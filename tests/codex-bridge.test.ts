import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { CodexOptions, ThreadEvent, ThreadOptions, TurnOptions } from '@openai/codex-sdk';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config.js';
import {
  buildCodexSandboxedEnv,
  CodexSdkRunner,
  reconcileOrphanJobs,
  type CodexClientLike,
} from '../src/core/codexRunner.js';
import { cancelActiveJob } from '../src/core/workspaceExec.js';
import { WorkspaceLockManager } from '../src/core/workspaceLock.js';
import { createRepositories } from '../src/db/repositories/index.js';
import { openDatabase } from '../src/db/sqlite.js';
import { runSubprocess } from '../src/utils/exec.js';

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  vi.unstubAllEnvs();
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('CodexSdkRunner bridge', () => {
  it('runs readonly -> persists threadId -> resumes with workspace-write escalation + pre-write checkpoint + env isolation', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');

    const nonGitSlug = 'non-git-ws';
    const nonGitDir = path.join(workspacesDir, nonGitSlug);
    fs.mkdirSync(nonGitDir, { recursive: true });

    const gitSlug = 'git-codex-ws';
    const gitDir = path.join(workspacesDir, gitSlug);
    fs.mkdirSync(gitDir, { recursive: true });
    await runSubprocess({ command: 'git', args: ['init'], cwd: gitDir });
    await runSubprocess({
      command: 'git',
      args: ['config', 'user.email', 'test@example.com'],
      cwd: gitDir,
    });
    await runSubprocess({
      command: 'git',
      args: ['config', 'user.name', 'Test User'],
      cwd: gitDir,
    });
    fs.writeFileSync(path.join(gitDir, 'index.ts'), 'export const x = 1;\n', 'utf8');
    await runSubprocess({ command: 'git', args: ['add', 'index.ts'], cwd: gitDir });
    await runSubprocess({ command: 'git', args: ['commit', '-m', 'init'], cwd: gitDir });

    vi.stubEnv('GH_TOKEN', 'ghp_must_never_leak_to_codex_12345');
    vi.stubEnv('CLOUDFLARE_API_TOKEN', 'cfut_must_never_leak_to_codex_12345');
    vi.stubEnv('ADMIN_PASSWORD_HASH', 'scrypt$must_never_leak_12345');
    vi.stubEnv('OAUTH_SIGNING_SECRET', 'oauth_secret_must_never_leak_12345');

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      CODEX_API_KEY: 'sk-codex-allowed-test-key-123456',
      CODEX_BASE_URL: 'https://codex-proxy.example.com/v1',
      NOTIFY_WEBHOOK_URL: 'https://hooks.slack.com/services/T00/B00/XXX',
    });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    const capturedCodexOptions: CodexOptions[] = [];
    const capturedCalls: Array<{
      kind: 'start' | 'resume';
      resumeId?: string;
      threadOptions?: ThreadOptions;
      turnOptions?: TurnOptions;
    }> = [];
    const webhookNotifications: unknown[] = [];

    const mockFactory = (codexOpts: CodexOptions): CodexClientLike => {
      capturedCodexOptions.push(codexOpts);
      return {
        startThread(threadOpts?: ThreadOptions) {
          capturedCalls.push({ kind: 'start', threadOptions: threadOpts });
          return {
            id: 'thread_ro_001',
            async runStreamed(_input: string, turnOpts?: TurnOptions) {
              capturedCalls[capturedCalls.length - 1]!.turnOptions = turnOpts;
              async function* gen(): AsyncGenerator<ThreadEvent> {
                yield { type: 'thread.started', thread_id: 'thread_ro_001' };
                yield { type: 'turn.started' };
                yield {
                  type: 'item.completed',
                  item: {
                    id: 'item_1',
                    type: 'command_execution',
                    command: 'git status',
                    aggregated_output: 'clean',
                    exit_code: 0,
                    status: 'completed',
                  },
                };
                yield {
                  type: 'item.completed',
                  item: {
                    id: 'item_2',
                    type: 'agent_message',
                    text: JSON.stringify({
                      summary: 'Analyzed non-git workspace',
                      files_touched: [],
                      verification_commands_run: ['git status'],
                      risks: [],
                      next_action_needed: 'Proceed to write phase',
                    }),
                  },
                };
                yield {
                  type: 'turn.completed',
                  usage: {
                    input_tokens: 1200,
                    cached_input_tokens: 200,
                    cache_write_input_tokens: 0,
                    output_tokens: 300,
                    reasoning_output_tokens: 50,
                  },
                };
              }
              return { events: gen() };
            },
          };
        },
        resumeThread(id: string, threadOpts?: ThreadOptions) {
          capturedCalls.push({ kind: 'resume', resumeId: id, threadOptions: threadOpts });
          return {
            id,
            async runStreamed(_input: string, turnOpts?: TurnOptions) {
              capturedCalls[capturedCalls.length - 1]!.turnOptions = turnOpts;
              async function* gen(): AsyncGenerator<ThreadEvent> {
                yield { type: 'turn.started' };
                yield {
                  type: 'item.completed',
                  item: {
                    id: 'item_3',
                    type: 'file_change',
                    changes: [{ path: 'index.ts', kind: 'update' }],
                    status: 'completed',
                  },
                };
                yield {
                  type: 'item.completed',
                  item: {
                    id: 'item_4',
                    type: 'agent_message',
                    text: JSON.stringify({
                      summary: 'Updated index.ts safely',
                      files_touched: ['index.ts'],
                      verification_commands_run: ['npm test'],
                      risks: [],
                      next_action_needed: 'none',
                    }),
                  },
                };
                yield {
                  type: 'turn.completed',
                  usage: {
                    input_tokens: 800,
                    cached_input_tokens: 400,
                    cache_write_input_tokens: 0,
                    output_tokens: 200,
                    reasoning_output_tokens: 20,
                  },
                };
              }
              return { events: gen() };
            },
          };
        },
      };
    };

    const runner = new CodexSdkRunner({
      config,
      jobRepo: repos.jobs,
      workspaceRepo: repos.workspaces,
      lockManager: lockMgr,
      codexFactory: mockFactory,
      webhookOptions: {
        fetchFn: (async (_url: string | URL | Request, init?: RequestInit) => {
          webhookNotifications.push(JSON.parse(String(init?.body ?? '{}')));
          return new Response('ok', { status: 200 });
        }) as typeof fetch,
      },
    });

    // Turn 1: readonly on non-git workspace
    const roResult = await runner.run({
      jobId: 'job_ro_1',
      workspaceSlug: nonGitSlug,
      workspaceDir: nonGitDir,
      mode: 'readonly',
      objective: 'Inspect the directory',
    });

    expect(roResult.status).toBe('completed');
    expect(roResult.threadId).toBe('thread_ro_001');
    expect(roResult.tokenUsage?.total_tokens).toBe(1500);
    expect(capturedCalls[0]?.kind).toBe('start');
    expect(capturedCalls[0]?.threadOptions?.sandboxMode).toBe('read-only');
    expect(capturedCalls[0]?.threadOptions?.skipGitRepoCheck).toBe(true);
    expect(capturedCalls[0]?.turnOptions?.outputSchema).toBeDefined();

    // Verify strict env isolation passed to Codex
    const passedEnv = capturedCodexOptions[0]?.env ?? {};
    expect(passedEnv.CODEX_API_KEY).toBe('sk-codex-allowed-test-key-123456');
    expect(passedEnv.CODEX_BASE_URL).toBe('https://codex-proxy.example.com/v1');
    expect(passedEnv.GH_TOKEN).toBeUndefined();
    expect(passedEnv.CLOUDFLARE_API_TOKEN).toBeUndefined();
    expect(passedEnv.ADMIN_PASSWORD_HASH).toBeUndefined();
    expect(passedEnv.OAUTH_SIGNING_SECRET).toBeUndefined();
    expect(passedEnv.NOTIFY_WEBHOOK_URL).toBeUndefined();

    // Check SQLite persistence for readonly job
    const roJob = repos.jobs.getJob('job_ro_1');
    expect(roJob?.status).toBe('completed');
    expect(roJob?.codex_thread_id).toBe('thread_ro_001');
    expect(roJob?.token_usage?.total_tokens).toBe(1500);
    expect(roJob?.events.length).toBeGreaterThanOrEqual(3);

    // Turn 2: resumeThread escalated to workspace-write on git repo
    const writeResult = await runner.run({
      jobId: 'job_wr_2',
      workspaceSlug: gitSlug,
      workspaceDir: gitDir,
      mode: 'write',
      resumeThreadId: roResult.threadId!,
      objective: 'Apply fix to index.ts',
      allowNetwork: false,
    });

    expect(writeResult.status).toBe('completed');
    expect(writeResult.threadId).toBe('thread_ro_001');
    expect(capturedCalls[1]?.kind).toBe('resume');
    expect(capturedCalls[1]?.resumeId).toBe('thread_ro_001');
    expect(capturedCalls[1]?.threadOptions?.sandboxMode).toBe('workspace-write');
    expect(capturedCalls[1]?.threadOptions?.skipGitRepoCheck).toBe(false);

    // Verify pre-write auto-checkpoint was created and linked in SQLite
    const wrJob = repos.jobs.getJob('job_wr_2');
    expect(wrJob?.checkpoint_id).toBeTruthy();
    const checkpoints = repos.workspaces.listCheckpoints(gitSlug);
    expect(checkpoints.some((c) => c.checkpoint_id === wrJob?.checkpoint_id)).toBe(true);
    expect(webhookNotifications.length).toBe(2);

    db.close();
  });

  it('caps rolling events to last 50, enforces token budget, and supports AbortController cancellation', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'codex-events';
    const wsDir = path.join(workspacesDir, slug);
    fs.mkdirSync(wsDir, { recursive: true });

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      CODEX_TOKEN_BUDGET: '1000',
    });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    // 1) Rolling 50-event cap + token budget guard
    const noisyRunner = new CodexSdkRunner({
      config,
      jobRepo: repos.jobs,
      lockManager: lockMgr,
      codexFactory: () => ({
        startThread() {
          return {
            id: 'thread_noisy',
            async runStreamed() {
              async function* gen(): AsyncGenerator<ThreadEvent> {
                yield { type: 'thread.started', thread_id: 'thread_noisy' };
                for (let i = 0; i < 65; i++) {
                  yield {
                    type: 'item.completed',
                    item: {
                      id: `cmd_${i}`,
                      type: 'command_execution',
                      command: `echo step-${i}`,
                      aggregated_output: '',
                      exit_code: 0,
                      status: 'completed',
                    },
                  };
                }
                yield {
                  type: 'turn.completed',
                  usage: {
                    input_tokens: 900,
                    cached_input_tokens: 0,
                    cache_write_input_tokens: 0,
                    output_tokens: 500,
                    reasoning_output_tokens: 0,
                  },
                };
              }
              return { events: gen() };
            },
          };
        },
        resumeThread() {
          throw new Error('unused');
        },
      }),
    });

    const budgetRes = await noisyRunner.run({
      jobId: 'job_budget_1',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'readonly',
      objective: 'Exceed budget',
    });

    expect(budgetRes.status).toBe('failed');
    expect(budgetRes.errorMessage).toContain('Token budget exceeded');
    const budgetJob = repos.jobs.getJob('job_budget_1');
    expect(budgetJob?.events.length).toBeLessThanOrEqual(50);

    // 2) AbortController / cancelActiveJob cancellation
    const slowRunner = new CodexSdkRunner({
      config,
      jobRepo: repos.jobs,
      lockManager: lockMgr,
      codexFactory: () => ({
        startThread() {
          return {
            id: 'thread_slow',
            async runStreamed(_input: string, turnOpts?: TurnOptions) {
              async function* gen(): AsyncGenerator<ThreadEvent> {
                yield { type: 'thread.started', thread_id: 'thread_slow' };
                while (!turnOpts?.signal?.aborted) {
                  await new Promise((r) => setTimeout(r, 30));
                }
              }
              return { events: gen() };
            },
          };
        },
        resumeThread() {
          throw new Error('unused');
        },
      }),
    });

    const runPromise = slowRunner.run({
      jobId: 'job_cancel_1',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'write',
      objective: 'Long task',
    });

    // Wait briefly until registered, then cancel via cancelActiveJob
    await new Promise((r) => setTimeout(r, 60));
    const cancelRes = await cancelActiveJob('job_cancel_1', repos.jobs);
    expect(cancelRes.cancelled).toBe(true);

    const cancelledResult = await runPromise;
    expect(cancelledResult.status).toBe('cancelled');
    expect(repos.jobs.getJob('job_cancel_1')?.status).toBe('cancelled');
    expect(lockMgr.getLockInfo(slug).hasActiveWriter).toBe(false);

    db.close();
  });

  it('reconciles orphaned running/queued jobs on startup crash recovery', () => {
    const db = openDatabase(':memory:');
    const repos = createRepositories(db);

    repos.jobs.createJob({
      job_id: 'orphan_running',
      workspace_slug: 'ws1',
      runner_type: 'codex_write',
      status: 'running',
      command_or_objective: 'Refactor module',
    });
    repos.jobs.createJob({
      job_id: 'orphan_queued',
      workspace_slug: 'ws1',
      runner_type: 'shell_task',
      status: 'queued',
      command_or_objective: 'npm test',
    });
    repos.jobs.createJob({
      job_id: 'already_done',
      workspace_slug: 'ws1',
      runner_type: 'codex_readonly',
      status: 'completed',
      command_or_objective: 'Inspect',
    });

    const count = reconcileOrphanJobs(repos.jobs);
    expect(count).toBe(2);
    expect(repos.jobs.getJob('orphan_running')?.status).toBe('failed');
    expect(repos.jobs.getJob('orphan_queued')?.status).toBe('failed');
    expect(repos.jobs.getJob('already_done')?.status).toBe('completed');

    db.close();
  });

  it('passes CODEX_HOME through buildCodexSandboxedEnv and cancelActiveJob awaits terminal cancelled status and lock release', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'codex-cancel-race';
    const wsDir = path.join(workspacesDir, slug);
    fs.mkdirSync(wsDir, { recursive: true });

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      CODEX_API_KEY: 'sk-codex-test-key-123456',
    });

    const codexEnv = buildCodexSandboxedEnv(config, {
      PATH: process.env.PATH,
      HOME: '/home/worker',
      CODEX_HOME: '/home/worker/.codex',
      GH_TOKEN: 'ghp_must_strip_123456',
    });
    expect(codexEnv.CODEX_HOME).toBe('/home/worker/.codex');
    expect(codexEnv.CODEX_API_KEY).toBe('sk-codex-test-key-123456');
    expect(codexEnv.GH_TOKEN).toBeUndefined();

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    // Hold write lock to force Codex job to queue on lock acquisition, then cancel via cancelActiveJob
    const blocker = await lockMgr.acquireWrite(slug, { holder: 'blocker' });

    const queuedRunner = new CodexSdkRunner({
      config,
      jobRepo: repos.jobs,
      lockManager: lockMgr,
      codexFactory: () => {
        throw new Error('Codex client must not be invoked when cancelled while waiting for lock');
      },
    });

    repos.jobs.createJob({
      job_id: 'job_queued_cancel',
      workspace_slug: slug,
      runner_type: 'codex_write',
      status: 'queued',
      command_or_objective: 'Queued task',
    });

    const runPromise = queuedRunner.run({
      jobId: 'job_queued_cancel',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'write',
      objective: 'Queued task',
    });

    // Yield one tick so run() registers active job and waits on acquireWrite
    await new Promise((r) => setTimeout(r, 20));
    const cancelRes = await cancelActiveJob('job_queued_cancel', repos.jobs);
    expect(cancelRes.cancelled).toBe(true);

    // Immediately after cancelActiveJob returns, DB status must already be cancelled and lock free
    expect(repos.jobs.getJob('job_queued_cancel')?.status).toBe('cancelled');
    expect(lockMgr.getLockInfo(slug).queuedCount).toBe(0);

    blocker.release();
    const res = await runPromise;
    expect(res.status).toBe('cancelled');
    expect(lockMgr.getLockInfo(slug).hasActiveWriter).toBe(false);

    db.close();
  });

  it('clamps caller tokenBudget to operator config cap and reconciles >500 orphan jobs in batches', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'codex-clamp';
    const wsDir = path.join(workspacesDir, slug);
    fs.mkdirSync(wsDir, { recursive: true });

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      CODEX_TOKEN_BUDGET: '1000',
      CODEX_MAX_DURATION_SEC: '30',
    });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    const runner = new CodexSdkRunner({
      config,
      jobRepo: repos.jobs,
      lockManager: lockMgr,
      codexFactory: () => ({
        startThread() {
          return {
            id: 'thread_clamp',
            async runStreamed() {
              async function* gen(): AsyncGenerator<ThreadEvent> {
                yield { type: 'thread.started', thread_id: 'thread_clamp' };
                yield {
                  type: 'turn.completed',
                  usage: {
                    input_tokens: 900,
                    cached_input_tokens: 0,
                    cache_write_input_tokens: 0,
                    output_tokens: 300,
                    reasoning_output_tokens: 0,
                  },
                };
              }
              return { events: gen() };
            },
          };
        },
        resumeThread() {
          throw new Error('unused');
        },
      }),
    });

    // Caller tries to raise tokenBudget to 999999 -> must be clamped to config.codexTokenBudget (1000)
    const clampedRes = await runner.run({
      jobId: 'job_clamp_1',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'readonly',
      objective: 'Try raising budget',
      tokenBudget: 999999,
      maxDurationSec: 9999,
    });

    expect(clampedRes.status).toBe('failed');
    expect(clampedRes.errorMessage).toContain('Token budget exceeded (1200 > 1000)');

    // Batch orphan reconciliation for >500 jobs
    const insertMany = db.transaction(() => {
      for (let i = 0; i < 520; i++) {
        repos.jobs.createJob({
          job_id: `orphan_batch_${i}`,
          workspace_slug: slug,
          runner_type: 'shell_task',
          status: i % 2 === 0 ? 'running' : 'queued',
          command_or_objective: `cmd-${i}`,
        });
      }
    });
    insertMany();

    const reconciled = reconcileOrphanJobs(repos.jobs);
    expect(reconciled).toBe(520);
    expect(repos.jobs.listJobs({ status: 'running', limit: 10 })).toEqual([]);
    expect(repos.jobs.listJobs({ status: 'queued', limit: 10 })).toEqual([]);

    db.close();
  });
});
