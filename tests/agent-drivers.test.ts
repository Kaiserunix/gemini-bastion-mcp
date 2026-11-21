import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config.js';
import {
  AgentRunnerRegistry,
  ClaudeCodeCliRunner,
  createAgentRunnerRegistry,
  GeminiCliRunner,
  OpenCodeCliRunner,
  RemoteSidecarAgentRunner,
  type SubprocessStarter,
} from '../src/core/agentDrivers/index.js';
import { cancelActiveJob } from '../src/core/workspaceExec.js';
import { WorkspaceLockManager } from '../src/core/workspaceLock.js';
import { createRepositories } from '../src/db/repositories/index.js';
import { openDatabase } from '../src/db/sqlite.js';
import { createRunnerSidecarServer } from '../src/runner/sidecarServer.js';
import type { AgentDriverName, AgentRunResult, AgentRunner } from '../src/types.js';
import { runSubprocess, type ExecResult, type SubprocessOptions } from '../src/utils/exec.js';

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

function createMockSubprocessStarter(
  jsonlLines: string[],
  capturedCalls: SubprocessOptions[],
  options: { delayMs?: number } = {},
): SubprocessStarter {
  return (subOpts: SubprocessOptions) => {
    capturedCalls.push(subOpts);
    let killed = false;

    const done = new Promise<ExecResult>((resolve) => {
      const startTime = Date.now();
      const emitAll = () => {
        if (killed) {
          resolve({
            exitCode: null,
            signal: 'SIGTERM',
            stdout: '',
            stderr: '',
            timedOut: false,
            aborted: true,
            truncated: false,
            durationMs: Date.now() - startTime,
          });
          return;
        }
        for (const line of jsonlLines) {
          subOpts.onStdout?.(`${line}\n`);
        }
        resolve({
          exitCode: 0,
          signal: null,
          stdout: jsonlLines.join('\n'),
          stderr: '',
          timedOut: false,
          aborted: false,
          truncated: false,
          durationMs: Date.now() - startTime,
        });
      };

      const timer = setTimeout(emitAll, options.delayMs ?? 10);
      timer.unref?.();

      subOpts.signal?.addEventListener(
        'abort',
        () => {
          killed = true;
          clearTimeout(timer);
          emitAll();
        },
        { once: true },
      );
    });

    return {
      pid: 99999,
      child: {} as never,
      done,
      kill: async () => {
        killed = true;
      },
      getOutputSnapshot: () => ({ stdout: '', stderr: '', truncated: false }),
    };
  };
}

describe('multi-agent drivers & isolated runner sidecar', () => {
  it('ClaudeCodeCliRunner builds exact readonly/write args, isolates env to ANTHROPIC_API_KEY, streams JSONL & creates write checkpoint', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'claude-ws';
    const wsDir = path.join(workspacesDir, slug);
    fs.mkdirSync(wsDir, { recursive: true });

    await runSubprocess({ command: 'git', args: ['init'], cwd: wsDir });
    await runSubprocess({ command: 'git', args: ['config', 'user.email', 't@e.com'], cwd: wsDir });
    await runSubprocess({ command: 'git', args: ['config', 'user.name', 'Test'], cwd: wsDir });
    fs.writeFileSync(path.join(wsDir, 'app.ts'), 'export const a = 1;\n', 'utf8');
    await runSubprocess({ command: 'git', args: ['add', 'app.ts'], cwd: wsDir });
    await runSubprocess({ command: 'git', args: ['commit', '-m', 'init'], cwd: wsDir });

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      ANTHROPIC_API_KEY: 'sk-ant-only-this-key-123456',
      GEMINI_API_KEY: 'AIzaSyMustNotLeakToClaude1234567890',
      OPENAI_API_KEY: 'sk-openai-must-not-leak-123456',
      GH_TOKEN: 'ghp_must_not_leak_1234567890',
      CLOUDFLARE_API_TOKEN: 'cfut_must_not_leak_1234567890',
      OPS_MCP_AUTH_TOKEN: 'ops-secret-must-not-leak-123456',
      AGENT_RUNNER_AUTH_TOKEN: 'runner-secret-must-not-leak-123456',
      OAUTH_SIGNING_SECRET: 'oauth-secret-must-not-leak-1234567890',
      ADMIN_PASSWORD_HASH: 'sha256$mustnotleak1234567890',
    });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();
    const captured: SubprocessOptions[] = [];

    const runner = new ClaudeCodeCliRunner({
      config,
      jobRepo: repos.jobs,
      workspaceRepo: repos.workspaces,
      lockManager: lockMgr,
      baseEnv: {
        PATH: process.env.PATH,
        HOME: '/home/worker',
        LANG: 'C.UTF-8',
        GH_TOKEN: config.ghToken,
        ADMIN_PASSWORD_HASH: config.adminPasswordHash,
      },
      subprocessStarter: createMockSubprocessStarter(
        [
          JSON.stringify({ type: 'system', subtype: 'init', session_id: 'claude_sess_01' }),
          JSON.stringify({
            type: 'assistant',
            session_id: 'claude_sess_01',
            message: {
              content: [
                { type: 'tool_use', name: 'Read' },
                { type: 'text', text: 'Inspected app.ts cleanly.' },
              ],
            },
          }),
          JSON.stringify({
            type: 'result',
            session_id: 'claude_sess_01',
            result: 'Final Claude report',
            usage: { input_tokens: 400, cache_read_input_tokens: 50, output_tokens: 100 },
          }),
        ],
        captured,
      ),
    });

    const roRes = await runner.run({
      jobId: 'job_claude_ro',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'readonly',
      objective: 'Audit app.ts',
      model: 'claude-sonnet-4-5',
    });

    expect(roRes.status).toBe('completed');
    expect(roRes.threadId).toBe('claude_sess_01');
    expect(roRes.finalReport).toBe('Final Claude report');
    expect(roRes.tokenUsage?.total_tokens).toBe(500);

    expect(captured[0]?.command).toBe('claude');
    expect(captured[0]?.shell).toBe(false);
    expect(captured[0]?.args).toEqual([
      '-p',
      '--output-format',
      'stream-json',
      '--verbose',
      '--permission-mode',
      'plan',
      '--model',
      'claude-sonnet-4-5',
      '--',
      'Audit app.ts',
    ]);
    expect(captured[0]?.bwrapIsolation?.allowNetwork).toBe(true);

    const passedEnv = captured[0]?.env ?? {};
    expect(passedEnv.ANTHROPIC_API_KEY).toBe('sk-ant-only-this-key-123456');
    expect(passedEnv.GEMINI_API_KEY).toBeUndefined();
    expect(passedEnv.OPENAI_API_KEY).toBeUndefined();
    expect(passedEnv.GH_TOKEN).toBeUndefined();
    expect(passedEnv.CLOUDFLARE_API_TOKEN).toBeUndefined();
    expect(passedEnv.OPS_MCP_AUTH_TOKEN).toBeUndefined();
    expect(passedEnv.AGENT_RUNNER_AUTH_TOKEN).toBeUndefined();
    expect(passedEnv.OAUTH_SIGNING_SECRET).toBeUndefined();
    expect(passedEnv.ADMIN_PASSWORD_HASH).toBeUndefined();

    // Write mode with resumeThreadId -> acceptEdits + --resume + pre-write checkpoint
    const wrRes = await runner.run({
      jobId: 'job_claude_wr',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'write',
      resumeThreadId: 'claude_sess_01',
      objective: 'Update app.ts',
    });

    expect(wrRes.status).toBe('completed');
    expect(captured[1]?.args).toContain('acceptEdits');
    expect(captured[1]?.args).toContain('--resume');
    expect(captured[1]?.args).toContain('claude_sess_01');
    const wrJob = repos.jobs.getJob('job_claude_wr');
    expect(wrJob?.runner_type).toBe('agent_write');
    expect(wrJob?.checkpoint_id).toBeTruthy();

    db.close();
  });

  it('GeminiCliRunner and OpenCodeCliRunner build exact args, isolate secrets, stream events, and support cancellation', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'multi-cli-ws';
    const wsDir = path.join(workspacesDir, slug);
    fs.mkdirSync(wsDir, { recursive: true });

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      GEMINI_API_KEY: 'AIzaSyOnlyGeminiKey1234567890123456',
      ANTHROPIC_API_KEY: 'sk-ant-key-for-opencode-123456',
      GH_TOKEN: 'ghp_must_never_leak_123456',
      OPS_MCP_AUTH_TOKEN: 'ops-must-never-leak-1234567890',
    });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    // 1. GeminiCliRunner
    const geminiCalls: SubprocessOptions[] = [];
    const geminiRunner = new GeminiCliRunner({
      config,
      jobRepo: repos.jobs,
      lockManager: lockMgr,
      subprocessStarter: createMockSubprocessStarter(
        [
          JSON.stringify({ type: 'init', session_id: 'gem_sess_42' }),
          JSON.stringify({ type: 'tool_use', tool_name: 'read_file' }),
          JSON.stringify({ type: 'message', role: 'assistant', content: 'Gemini partial' }),
          JSON.stringify({
            type: 'result',
            response: 'Gemini final summary',
            stats: { tokens: { input: 200, output: 80, total: 280 } },
          }),
        ],
        geminiCalls,
      ),
    });

    const gemRes = await geminiRunner.run({
      jobId: 'job_gem_1',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'write',
      resumeThreadId: 'gem_prev',
      model: 'gemini-2.5-pro',
      objective: 'Fix bug',
    });

    expect(gemRes.status).toBe('completed');
    expect(gemRes.threadId).toBe('gem_sess_42');
    expect(gemRes.finalReport).toBe('Gemini final summary');
    expect(gemRes.tokenUsage?.total_tokens).toBe(280);
    expect(geminiCalls[0]?.command).toBe('gemini');
    expect(geminiCalls[0]?.args).toEqual([
      '--prompt=Fix bug',
      '--output-format',
      'stream-json',
      '--approval-mode',
      'yolo',
      '--resume',
      'gem_prev',
      '-m',
      'gemini-2.5-pro',
    ]);
    expect(geminiCalls[0]?.env?.GEMINI_API_KEY).toBe('AIzaSyOnlyGeminiKey1234567890123456');
    expect(geminiCalls[0]?.env?.ANTHROPIC_API_KEY).toBeUndefined();
    expect(geminiCalls[0]?.env?.GH_TOKEN).toBeUndefined();
    expect(geminiCalls[0]?.env?.OPS_MCP_AUTH_TOKEN).toBeUndefined();

    // 2. OpenCodeCliRunner + cancellation
    const ocCalls: SubprocessOptions[] = [];
    const ocRunner = new OpenCodeCliRunner({
      config,
      jobRepo: repos.jobs,
      lockManager: lockMgr,
      subprocessStarter: createMockSubprocessStarter(
        [
          JSON.stringify({ type: 'step_start', sessionID: 'oc_sess_77' }),
          JSON.stringify({ type: 'text', part: { text: 'OpenCode done' } }),
          JSON.stringify({
            type: 'step_finish',
            part: { tokens: { input: 100, output: 50 } },
          }),
        ],
        ocCalls,
        { delayMs: 250 },
      ),
    });

    const ocRunPromise = ocRunner.run({
      jobId: 'job_oc_cancel',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'readonly',
      resumeThreadId: 'oc_prev',
      model: 'anthropic/claude-sonnet-4',
      objective: 'Check repo',
    });

    await new Promise((r) => setTimeout(r, 30));
    const cancelled = await cancelActiveJob('job_oc_cancel', repos.jobs);
    expect(cancelled.cancelled).toBe(true);

    const ocRes = await ocRunPromise;
    expect(ocRes.status).toBe('cancelled');
    expect(ocCalls[0]?.command).toBe('opencode');
    expect(ocCalls[0]?.args).toEqual([
      'run',
      '--format',
      'json',
      '--session',
      'oc_prev',
      '--model',
      'anthropic/claude-sonnet-4',
      '--',
      'Check repo',
    ]);
    expect(ocCalls[0]?.env?.ANTHROPIC_API_KEY).toBe('sk-ant-key-for-opencode-123456');
    expect(ocCalls[0]?.env?.GEMINI_API_KEY).toBe('AIzaSyOnlyGeminiKey1234567890123456');
    expect(ocCalls[0]?.env?.GH_TOKEN).toBeUndefined();
    expect(ocCalls[0]?.env?.OPS_MCP_AUTH_TOKEN).toBeUndefined();

    db.close();
  });

  it('AgentRunnerRegistry routes across all 4 drivers cleanly', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      DEFAULT_AGENT_DRIVER: 'gemini_cli',
    });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    const invoked: Array<{ name: string; driver?: AgentDriverName }> = [];
    const makeStub = (name: string): AgentRunner => ({
      name,
      async run(opts) {
        invoked.push({ name, driver: opts.driver });
        return {
          status: 'completed',
          threadId: `${name}_t1`,
          finalReport: `ok:${name}`,
          tokenUsage: null,
        };
      },
    });

    const registry = createAgentRunnerRegistry({
      config,
      jobRepo: repos.jobs,
      workspaceRepo: repos.workspaces,
      lockManager: lockMgr,
      runners: {
        codex: makeStub('codex'),
        claude_code: makeStub('claude_code'),
        gemini_cli: makeStub('gemini_cli'),
        opencode: makeStub('opencode'),
      },
    });

    // Uses defaultAgentDriver ('gemini_cli') when omitted
    const rDefault = await registry.run({
      jobId: 'j1',
      workspaceSlug: 'ws',
      workspaceDir: workspacesDir,
      mode: 'readonly',
      objective: 'hi',
    });
    expect(rDefault.finalReport).toBe('ok:gemini_cli');

    for (const driver of ['codex', 'claude_code', 'gemini_cli', 'opencode'] as const) {
      const res = await registry.run({
        jobId: `j_${driver}`,
        workspaceSlug: 'ws',
        workspaceDir: workspacesDir,
        mode: 'readonly',
        driver,
        objective: 'hi',
      });
      expect(res.finalReport).toBe(`ok:${driver}`);
    }

    expect(invoked.map((x) => x.name)).toEqual([
      'gemini_cli',
      'codex',
      'claude_code',
      'gemini_cli',
      'opencode',
    ]);
    db.close();
  });

  it('live createRunnerSidecarServer + RemoteSidecarAgentRunner enforces fail-closed auth, streams NDJSON events, and supports cancellation', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'sidecar-ws';
    const wsDir = path.join(workspacesDir, slug);
    fs.mkdirSync(wsDir, { recursive: true });

    // Fails closed if token missing or < 24 chars
    await expect(
      createRunnerSidecarServer({ authToken: 'short-token', workspacesDir, port: 0 }),
    ).rejects.toThrow(/AGENT_RUNNER_AUTH_TOKEN/);

    const sidecarToken = 'sidecar-bearer-token-at-least-32-chars-ok';
    const mockSidecarRunner: AgentRunner = {
      name: 'mock-sidecar-inner',
      async run(opts): Promise<AgentRunResult> {
        opts.onEvent?.({
          ts: Date.now(),
          type: 'tool_call',
          message: `running ${opts.driver} on ${opts.workspaceSlug}`,
        });
        if (opts.objective === 'hang') {
          await new Promise<void>((resolve) => {
            if (opts.signal?.aborted) {
              resolve();
              return;
            }
            opts.signal?.addEventListener('abort', () => resolve(), { once: true });
          });
          return {
            status: 'cancelled',
            threadId: 'sidecar_t_cancel',
            finalReport: '',
            tokenUsage: null,
            errorMessage: 'Cancelled inside sidecar',
          };
        }
        return {
          status: 'completed',
          threadId: 'sidecar_t_100',
          finalReport: 'Sidecar completed cleanly',
          tokenUsage: { input_tokens: 150, output_tokens: 50, total_tokens: 200 },
        };
      },
    };

    const serverHandle = await createRunnerSidecarServer({
      authToken: sidecarToken,
      workspacesDir,
      host: '127.0.0.1',
      port: 0,
      runner: mockSidecarRunner,
    });

    try {
      // /healthz without auth -> 200
      const hz = await fetch(`${serverHandle.url}/healthz`);
      expect(hz.status).toBe(200);
      expect(await hz.json()).toEqual({ ok: true, role: 'isolated-runner' });

      // /run without or with wrong auth -> 401
      const unauthRun = await fetch(`${serverHandle.url}/run`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jobId: 'x', workspaceSlug: slug, objective: 'hi' }),
      });
      expect(unauthRun.status).toBe(401);

      const wrongAuthCancel = await fetch(`${serverHandle.url}/cancel/x`, {
        method: 'POST',
        headers: { authorization: 'Bearer wrong-token' },
      });
      expect(wrongAuthCancel.status).toBe(401);

      // RemoteSidecarAgentRunner via AgentRunnerRegistry
      const config = loadConfig({
        DATA_DIR: dataDir,
        WORKSPACES_DIR: workspacesDir,
        AGENT_RUNNER_URL: serverHandle.url,
        AGENT_RUNNER_AUTH_TOKEN: sidecarToken,
      });
      const db = openDatabase(':memory:');
      const repos = createRepositories(db);
      const lockMgr = new WorkspaceLockManager();

      const registry = new AgentRunnerRegistry({
        config,
        jobRepo: repos.jobs,
        workspaceRepo: repos.workspaces,
        lockManager: lockMgr,
      });

      const okRes = await registry.run({
        jobId: 'job_remote_1',
        workspaceSlug: slug,
        workspaceDir: wsDir,
        mode: 'readonly',
        driver: 'claude_code',
        objective: 'Analyze codebase',
      });

      expect(okRes.status).toBe('completed');
      expect(okRes.threadId).toBe('sidecar_t_100');
      expect(okRes.finalReport).toBe('Sidecar completed cleanly');
      expect(okRes.tokenUsage?.total_tokens).toBe(200);

      const dbJob = repos.jobs.getJob('job_remote_1');
      expect(dbJob?.status).toBe('completed');
      expect(dbJob?.codex_thread_id).toBe('sidecar_t_100');
      expect(dbJob?.events.some((e) => e.message.includes('running claude_code'))).toBe(true);

      // Cancel running remote job via cancelActiveJob
      const remoteRunner = new RemoteSidecarAgentRunner({
        config,
        jobRepo: repos.jobs,
        workspaceRepo: repos.workspaces,
        lockManager: lockMgr,
      });
      const hangPromise = remoteRunner.run({
        jobId: 'job_remote_cancel',
        workspaceSlug: slug,
        workspaceDir: wsDir,
        mode: 'write',
        driver: 'codex',
        objective: 'hang',
      });

      await new Promise((r) => setTimeout(r, 80));
      const cancelOut = await cancelActiveJob('job_remote_cancel', repos.jobs);
      expect(cancelOut.cancelled).toBe(true);

      const hangRes = await hangPromise;
      expect(hangRes.status).toBe('cancelled');
      expect(repos.jobs.getJob('job_remote_cancel')?.status).toBe('cancelled');
      expect(lockMgr.getLockInfo(slug).hasActiveWriter).toBe(false);

      db.close();
    } finally {
      await serverHandle.close();
    }
  });

  it('rejects leading-dash CLI flags, safely passes leading-dash Gemini objective, and boots sidecar in production without OAuth secrets', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'flag-sec-ws';
    const wsDir = path.join(workspacesDir, slug);
    fs.mkdirSync(wsDir, { recursive: true });

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
    });
    const lockMgr = new WorkspaceLockManager();

    const claudeCalls: SubprocessOptions[] = [];
    const claudeRunner = new ClaudeCodeCliRunner({
      config,
      lockManager: lockMgr,
      subprocessStarter: createMockSubprocessStarter([], claudeCalls),
    });
    const badModel = await claudeRunner.run({
      jobId: 'j_bad_model',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'readonly',
      model: '--dangerously-skip-permissions',
      objective: 'hi',
    });
    expect(badModel.status).toBe('failed');
    expect(badModel.errorMessage).toContain('Invalid model');
    expect(claudeCalls.length).toBe(0);

    const ocCalls: SubprocessOptions[] = [];
    const ocRunner = new OpenCodeCliRunner({
      config,
      lockManager: lockMgr,
      subprocessStarter: createMockSubprocessStarter([], ocCalls),
    });
    const badSession = await ocRunner.run({
      jobId: 'j_bad_sess',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'readonly',
      resumeThreadId: '--evil-flag',
      objective: 'hi',
    });
    expect(badSession.status).toBe('failed');
    expect(badSession.errorMessage).toContain('Invalid resumeThreadId');
    expect(ocCalls.length).toBe(0);

    // GeminiCliRunner: rejects leading-dash model/resumeThreadId, safely formats leading-dash objective as --prompt=...
    const gemCalls: SubprocessOptions[] = [];
    const gemRunner = new GeminiCliRunner({
      config,
      lockManager: lockMgr,
      subprocessStarter: createMockSubprocessStarter([], gemCalls),
    });
    const badGemModel = await gemRunner.run({
      jobId: 'j_bad_gem_model',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'readonly',
      model: '-y',
      objective: 'hi',
    });
    expect(badGemModel.status).toBe('failed');
    expect(badGemModel.errorMessage).toContain('Invalid model');

    const safeDashObj = await gemRunner.run({
      jobId: 'j_safe_gem_obj',
      workspaceSlug: slug,
      workspaceDir: wsDir,
      mode: 'readonly',
      objective: '--yolo --delete-everything',
    });
    expect(safeDashObj.status).toBe('completed');
    expect(gemCalls[0]?.args?.[0]).toBe('--prompt=--yolo --delete-everything');

    // Production sidecar startup without OAUTH_SIGNING_SECRET / PUBLIC_DOMAIN
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('OAUTH_SIGNING_SECRET', '');
    vi.stubEnv('PUBLIC_DOMAIN', '');

    await expect(
      createRunnerSidecarServer({
        authToken: 'replace-with-random-production-secret',
        workspacesDir,
        host: '127.0.0.1',
        port: 0,
      }),
    ).rejects.toThrow(/placeholder AGENT_RUNNER_AUTH_TOKEN/);

    const prodToken = 'prod-isolated-runner-token-xyz-987654321';
    const prodServer = await createRunnerSidecarServer({
      authToken: prodToken,
      workspacesDir,
      host: '127.0.0.1',
      port: 0,
      runner: {
        name: 'stub',
        async run() {
          return {
            status: 'completed',
            threadId: null,
            finalReport: 'ok',
            tokenUsage: null,
          };
        },
      },
    });

    try {
      // 413 on >64KB request body
      const oversizedRes = await fetch(`${prodServer.url}/run`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${prodToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          jobId: 'j_big',
          workspaceSlug: slug,
          objective: 'A'.repeat(70 * 1024),
        }),
      });
      expect(oversizedRes.status).toBe(413);

      // 400 on malformed percent-encoding in /cancel/
      const badCancelRes = await fetch(`${prodServer.url}/cancel/%E0%A4%A`, {
        method: 'POST',
        headers: { authorization: `Bearer ${prodToken}` },
      });
      expect(badCancelRes.status).toBe(400);

      // 400 on path-traversal workspaceSlug
      const badSlugRes = await fetch(`${prodServer.url}/run`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${prodToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          jobId: 'j_trav',
          workspaceSlug: '../../etc',
          objective: 'read',
        }),
      });
      expect(badSlugRes.status).toBe(400);
    } finally {
      await prodServer.close();
    }
  });
});
