import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config.js';
import { cancelActiveJob, workspaceExec } from '../src/core/workspaceExec.js';
import { WorkspaceLockManager } from '../src/core/workspaceLock.js';
import { createRepositories } from '../src/db/repositories/index.js';
import { openDatabase } from '../src/db/sqlite.js';
import { buildBwrapArgs } from '../src/utils/exec.js';

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

describe('workspaceExec', () => {
  it('returns sync result immediately for fast commands and strips all gateway secrets from child env', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'exec-sync';
    fs.mkdirSync(path.join(workspacesDir, slug), { recursive: true });

    vi.stubEnv('GH_TOKEN', 'ghp_super_secret_gateway_token_12345');
    vi.stubEnv('CLOUDFLARE_API_TOKEN', 'cfut_secret_gateway_token_67890');
    vi.stubEnv('OPENAI_API_KEY', 'sk-secret-openai-key-1234567890');
    vi.stubEnv('CODEX_API_KEY', 'sk-secret-codex-key-1234567890');
    vi.stubEnv('ADMIN_PASSWORD_HASH', 'scrypt$secret_hash_value_12345');

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
    });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    const script = [
      'const keys = ["GH_TOKEN","CLOUDFLARE_API_TOKEN","OPENAI_API_KEY","CODEX_API_KEY","ADMIN_PASSWORD_HASH"];',
      'const leaked = keys.filter(k => process.env[k] !== undefined);',
      'console.log(JSON.stringify({ leaked, ci: process.env.CI }));',
    ].join(' ');

    const res = await workspaceExec({
      config,
      slug,
      command: process.execPath,
      args: ['-e', script],
      shell: false,
      waitMs: 5000,
      jobRepo: repos.jobs,
      lockManager: lockMgr,
    });

    expect(res.mode).toBe('sync');
    if (res.mode !== 'sync') throw new Error('Expected sync mode');

    expect(res.exitCode).toBe(0);
    const parsed = JSON.parse(res.stdout.trim()) as { leaked: string[]; ci: string };
    expect(parsed.leaked).toEqual([]);
    expect(parsed.ci).toBe('true');

    // Lock must be released after sync completion
    expect(lockMgr.getLockInfo(slug).hasActiveWriter).toBe(false);
    db.close();
  });

  it('auto-promotes slow command to async SQLite job, locks out concurrent writes with job_id, and completes', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'exec-async';
    fs.mkdirSync(path.join(workspacesDir, slug), { recursive: true });

    const webhookCalls: Array<{ url: string; body: unknown }> = [];
    const mockFetch = (async (url: string | URL | Request, init?: RequestInit) => {
      webhookCalls.push({
        url: String(url),
        body: JSON.parse(String(init?.body ?? '{}')),
      });
      return new Response('ok', { status: 200 });
    }) as typeof fetch;

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      NOTIFY_WEBHOOK_URL: 'https://example.com/webhook',
    });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    const script = [
      'console.log("step-1-started");',
      'setTimeout(() => { console.log("step-2-finished"); process.exit(0); }, 1100);',
    ].join(' ');

    const res = await workspaceExec({
      config,
      slug,
      command: process.execPath,
      args: ['-e', script],
      shell: false,
      waitMs: 500,
      jobRepo: repos.jobs,
      lockManager: lockMgr,
      webhookOptions: { fetchFn: mockFetch },
    });

    expect(res.mode).toBe('async_promoted');
    if (res.mode !== 'async_promoted') throw new Error('Expected async_promoted mode');

    const jobId = res.jobId;
    expect(jobId).toMatch(/^job_/);

    // While running, a concurrent write attempt must fast-fail reporting active job_id
    await expect(lockMgr.acquireWrite(slug)).rejects.toMatchObject({
      code: 'ACTIVE_JOB_LOCK',
      activeJobId: jobId,
    });

    // Wait for background process to finish
    let job = repos.jobs.getJob(jobId);
    const deadline = Date.now() + 5000;
    while (job && job.status === 'running' && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 50));
      job = repos.jobs.getJob(jobId);
    }

    expect(job?.status).toBe('completed');
    expect(job?.final_report_text).toContain('step-2-finished');
    expect(job?.events.length).toBeGreaterThanOrEqual(1);
    expect(lockMgr.getLockInfo(slug).hasActiveWriter).toBe(false);
    expect(webhookCalls.length).toBe(1);

    db.close();
  });

  it('cancels a promoted background shell job via cancelActiveJob and releases lock', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'exec-cancel';
    fs.mkdirSync(path.join(workspacesDir, slug), { recursive: true });

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
    });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    const script = 'console.log("working..."); setInterval(() => {}, 1000);';

    const res = await workspaceExec({
      config,
      slug,
      command: process.execPath,
      args: ['-e', script],
      shell: false,
      waitMs: 500,
      jobRepo: repos.jobs,
      lockManager: lockMgr,
    });

    expect(res.mode).toBe('async_promoted');
    if (res.mode !== 'async_promoted') throw new Error('Expected async_promoted mode');

    const cancelRes = await cancelActiveJob(res.jobId, repos.jobs);
    expect(cancelRes.cancelled).toBe(true);

    const job = repos.jobs.getJob(res.jobId);
    expect(job?.status).toBe('cancelled');
    expect(lockMgr.getLockInfo(slug).hasActiveWriter).toBe(false);

    db.close();
  });

  it('allows concurrent readonly commands and blocks cwd traversal', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'exec-ro';
    fs.mkdirSync(path.join(workspacesDir, slug, 'sub'), { recursive: true });

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
    });
    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    await expect(
      workspaceExec({
        config,
        slug,
        command: process.execPath,
        args: ['-e', 'console.log(1)'],
        shell: false,
        cwd: '../../outside',
        jobRepo: repos.jobs,
        lockManager: lockMgr,
      }),
    ).rejects.toThrow(/escapes workspace/);

    const [r1, r2] = await Promise.all([
      workspaceExec({
        config,
        slug,
        command: process.execPath,
        args: ['-e', 'console.log(process.cwd())'],
        shell: false,
        cwd: 'sub',
        readonly: true,
        jobRepo: repos.jobs,
        lockManager: lockMgr,
      }),
      workspaceExec({
        config,
        slug,
        command: process.execPath,
        args: ['-e', 'console.log("ok2")'],
        shell: false,
        readonly: true,
        jobRepo: repos.jobs,
        lockManager: lockMgr,
      }),
    ]);

    expect(r1.mode).toBe('sync');
    expect(r2.mode).toBe('sync');
    if (r1.mode === 'sync') {
      expect(path.basename(r1.stdout.trim())).toBe('sub');
    }

    db.close();
  });

  it('kills subprocess and releases workspace lock if DB write fails during async promotion', async () => {
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'exec-db-fail';
    fs.mkdirSync(path.join(workspacesDir, slug), { recursive: true });

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
    });
    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    const failingJobRepo = new Proxy(repos.jobs, {
      get(target, prop) {
        if (prop === 'createJob') {
          return () => {
            throw new Error('Simulated SQLite write failure');
          };
        }
        return Reflect.get(target, prop, target);
      },
    });

    await expect(
      workspaceExec({
        config,
        slug,
        command: process.execPath,
        args: ['-e', 'setInterval(() => {}, 1000);'],
        shell: false,
        waitMs: 500,
        jobRepo: failingJobRepo,
        lockManager: lockMgr,
      }),
    ).rejects.toThrow('Simulated SQLite write failure');

    expect(lockMgr.getLockInfo(slug).hasActiveWriter).toBe(false);
    db.close();
  });

  it('builds per-workspace bwrap isolation args hiding sibling workspaces and /data with --unshare-net by default', async () => {
    const restrictedArgs = buildBwrapArgs(
      {
        enabled: true,
        workspaceDir: '/workspaces/my-app',
        workspacesRoot: '/workspaces',
        dataDir: '/data',
        allowNetwork: false,
      },
      ['/bin/sh', '-c', 'echo hi'],
    );

    expect(restrictedArgs).toContain('--die-with-parent');
    expect(restrictedArgs).toContain('--unshare-net');
    expect(restrictedArgs.join(' ')).toContain('--tmpfs /workspaces');
    expect(restrictedArgs.join(' ')).toContain('--tmpfs /data');
    expect(restrictedArgs.join(' ')).toContain('--bind /workspaces/my-app /workspaces/my-app');
    expect(restrictedArgs.join(' ')).toContain('--chdir /workspaces/my-app');
    expect(restrictedArgs.slice(-4)).toEqual(['--', '/bin/sh', '-c', 'echo hi']);

    const networkArgs = buildBwrapArgs(
      {
        enabled: true,
        workspaceDir: '/workspaces/my-app',
        workspacesRoot: '/workspaces',
        dataDir: '/data',
        allowNetwork: true,
      },
      ['npm', 'test'],
    );
    expect(networkArgs).not.toContain('--unshare-net');
    expect(networkArgs.slice(-3)).toEqual(['--', 'npm', 'test']);

    // Verify workspaceExec accepts allowNetwork option cleanly
    const dataDir = makeTempDir('omni-data-');
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'exec-net';
    fs.mkdirSync(path.join(workspacesDir, slug), { recursive: true });

    const config = loadConfig({
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      SANDBOX_BWRAP_ISOLATION: 'false',
    });
    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const lockMgr = new WorkspaceLockManager();

    const syncRes = await workspaceExec({
      config,
      slug,
      command: process.execPath,
      args: ['-e', 'console.log("net-ok")'],
      shell: false,
      allowNetwork: true,
      waitMs: 5000,
      jobRepo: repos.jobs,
      lockManager: lockMgr,
    });
    expect(syncRes.mode).toBe('sync');
    if (syncRes.mode === 'sync') {
      expect(syncRes.stdout.trim()).toBe('net-ok');
    }

    db.close();
  });
});
