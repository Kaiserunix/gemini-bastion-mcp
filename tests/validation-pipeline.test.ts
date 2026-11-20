import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  applyPatch,
  CodePatchError,
  createOrOverwriteFiles,
  deleteFiles,
} from '../src/core/codePatcher.js';
import {
  createCheckpoint,
  detectWorkspaceStackAndPlaybook,
  readSafeBoundedWorkspaceFile,
  rollbackToCheckpoint,
  syncGitHubRepo,
} from '../src/core/gitSnapshot.js';
import {
  checkAntiPlaceholder,
  checkSyntax,
  runValidationPipeline,
  scanForSecrets,
} from '../src/core/validationPipeline.js';
import {
  resolveSafeWorkspacePath,
  WorkspaceLockError,
  WorkspaceLockManager,
  WorkspaceSandboxError,
} from '../src/core/workspaceLock.js';
import { createRepositories } from '../src/db/repositories/index.js';
import { openDatabase } from '../src/db/sqlite.js';
import { runSubprocess } from '../src/utils/exec.js';
import { SecretScrubber } from '../src/utils/secretScrubber.js';

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('validationPipeline & codePatcher & gitSnapshot & workspaceLock', () => {
  it('rejects lazy placeholder and merge conflict markers on code files while exempting .md/.txt/.json and opt-out', () => {
    const tsBad = [
      'export function alpha() {',
      '  // ... existing code',
      '  return 1;',
      '}',
    ].join('\n');
    expect(checkAntiPlaceholder('src/app.ts', tsBad).length).toBeGreaterThan(0);

    const pyBad = ['# ... rest unchanged', 'def run():', '    pass'].join('\n');
    expect(checkAntiPlaceholder('app.py', pyBad).length).toBeGreaterThan(0);

    const zhBad = ['/* ...保持不变 */', 'const x = 1;'].join('\n');
    expect(checkAntiPlaceholder('src/mod.js', zhBad).length).toBeGreaterThan(0);

    const conflictBad = ['<<<<<<< HEAD', 'const a = 1;', '=======', 'const a = 2;', '>>>>>>> main'].join('\n');
    expect(checkAntiPlaceholder('src/conflict.ts', conflictBad).length).toBe(3);

    // Exemptions: .md, .txt, .json
    expect(checkAntiPlaceholder('README.md', '// ... existing code\n=======')).toEqual([]);
    expect(checkAntiPlaceholder('notes.txt', '# ... rest unchanged')).toEqual([]);
    expect(checkAntiPlaceholder('data.json', '{"note": "// ... existing code"}')).toEqual([]);

    // Opt-out for test fixtures
    expect(
      checkAntiPlaceholder('tests/fixture.ts', tsBad, { allowPlaceholderMarkers: true }),
    ).toEqual([]);

    // Normal spread syntax / comments must NOT trigger false positives
    const cleanCode = [
      '// Spread items into array cleanly',
      'export function merge(a: number[], b: number[]) {',
      '  return [...a, ...b];',
      '}',
    ].join('\n');
    expect(checkAntiPlaceholder('src/clean.ts', cleanCode)).toEqual([]);
  });

  it('rejects hardcoded secrets via SecretScrubber and high-confidence key patterns', () => {
    const scrubber = new SecretScrubber({
      extraSecrets: ['super-secret-gateway-value-12345'],
    });

    const leak1 = 'const token = "ghp_1234567890abcdef1234567890abcdef";';
    expect(scanForSecrets('src/auth.ts', leak1, scrubber).length).toBeGreaterThan(0);

    const leak2 = 'const custom = "super-secret-gateway-value-12345";';
    expect(scanForSecrets('src/cfg.ts', leak2, scrubber).length).toBeGreaterThan(0);

    const leak3 = 'const awsKey = "AKIA1234567890ABCDEF";';
    expect(scanForSecrets('src/aws.ts', leak3, scrubber).length).toBeGreaterThan(0);

    const clean = 'const ok = process.env.API_KEY ?? "default";';
    expect(scanForSecrets('src/ok.ts', clean, scrubber)).toEqual([]);
  });

  it('reports exact line and column for TS and JSON syntax errors', async () => {
    const badTs = [
      'export const a = 1;',
      'export const broken = ;',
      'export const c = 3;',
    ].join('\n');
    const tsDiags = await checkSyntax('src/broken.ts', badTs);
    expect(tsDiags.length).toBeGreaterThan(0);
    expect(tsDiags[0]!.line).toBe(2);
    expect(tsDiags[0]!.column).toBeGreaterThan(0);

    const badJson = '{\n  "name": "ok",\n  "bad": ,\n}';
    const jsonDiags = await checkSyntax('package.json', badJson);
    expect(jsonDiags.length).toBe(1);
    expect(jsonDiags[0]!.line).toBe(3);
    expect(jsonDiags[0]!.column).toBeGreaterThan(0);
  });

  it('enforces multi-file atomic patch rollback when second file fails pre-validation or hunk match', async () => {
    const workspacesDir = makeTempDir('omni-ws-');
    const slug = 'repo-atomic';
    const wsRoot = path.join(workspacesDir, slug);
    fs.mkdirSync(path.join(wsRoot, 'src'), { recursive: true });
    fs.writeFileSync(path.join(wsRoot, 'src/a.ts'), 'export const a = 1;\n', 'utf8');
    fs.writeFileSync(path.join(wsRoot, 'src/b.ts'), 'export const b = 2;\n', 'utf8');

    // Case 1: 2nd file hunk does not match -> 1st file must remain untouched
    await expect(
      applyPatch({
        workspacesDir,
        slug,
        edits: [
          {
            path: 'src/a.ts',
            hunks: [{ search: 'export const a = 1;', replace: 'export const a = 10;' }],
          },
          {
            path: 'src/b.ts',
            hunks: [{ search: 'NON_EXISTENT_ANCHOR', replace: 'export const b = 20;' }],
          },
        ],
      }),
    ).rejects.toThrow(CodePatchError);

    expect(fs.readFileSync(path.join(wsRoot, 'src/a.ts'), 'utf8')).toBe('export const a = 1;\n');
    expect(fs.readFileSync(path.join(wsRoot, 'src/b.ts'), 'utf8')).toBe('export const b = 2;\n');

    // Case 2: 2nd file introduces TS syntax error -> post-write validation fails and rolls back BOTH files
    const res = await applyPatch({
      workspacesDir,
      slug,
      skipL1: true,
      rollbackOnValidationFailure: true,
      edits: [
        {
          path: 'src/a.ts',
          hunks: [{ search: 'export const a = 1;', replace: 'export const a = 42;' }],
        },
        {
          path: 'src/b.ts',
          hunks: [{ search: 'export const b = 2;', replace: 'export const b = (; // broken' }],
        },
      ],
    });

    expect(res.rolledBack).toBe(true);
    expect(res.validation?.passed).toBe(false);
    expect(fs.readFileSync(path.join(wsRoot, 'src/a.ts'), 'utf8')).toBe('export const a = 1;\n');
    expect(fs.readFileSync(path.join(wsRoot, 'src/b.ts'), 'utf8')).toBe('export const b = 2;\n');
  });

  it('disambiguates multiple identical hunks using line_hint and rejects ambiguous hunks without hint', async () => {
    const workspacesDir = makeTempDir('omni-hint-');
    const slug = 'hint-ws';
    const wsRoot = path.join(workspacesDir, slug);
    fs.mkdirSync(wsRoot, { recursive: true });

    const lines = [
      'function one() {',
      '  const value = 1;',
      '  return value;',
      '}',
      '',
      'function two() {',
      '  const value = 1;',
      '  return value;',
      '}',
      '',
    ];
    fs.writeFileSync(path.join(wsRoot, 'sample.ts'), lines.join('\n'), 'utf8');

    // Without line_hint -> ambiguous error
    await expect(
      applyPatch({
        workspacesDir,
        slug,
        skipL1: true,
        edits: [
          {
            path: 'sample.ts',
            hunks: [{ search: '  const value = 1;', replace: '  const value = 99;' }],
          },
        ],
      }),
    ).rejects.toThrow(/Ambiguous patch/);

    // With line_hint=7 -> updates function two() only
    const result = await applyPatch({
      workspacesDir,
      slug,
      skipL1: true,
      edits: [
        {
          path: 'sample.ts',
          hunks: [{ search: '  const value = 1;', replace: '  const value = 99;', line_hint: 7 }],
        },
      ],
    });

    expect(result.rolledBack).toBe(false);
    const updated = fs.readFileSync(path.join(wsRoot, 'sample.ts'), 'utf8');
    expect(updated).toContain('function one() {\n  const value = 1;');
    expect(updated).toContain('function two() {\n  const value = 99;');
    expect(result.diff).toContain('-  const value = 1;');
    expect(result.diff).toContain('+  const value = 99;');
  });

  it('creates temp-index git snapshot preserving staged .git/index and rolls back cleanly', async () => {
    const workspacesDir = makeTempDir('omni-git-');
    const slug = 'git-ws';
    const wsRoot = path.join(workspacesDir, slug);
    fs.mkdirSync(wsRoot, { recursive: true });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);

    await runSubprocess({ command: 'git', args: ['init'], cwd: wsRoot });
    await runSubprocess({
      command: 'git',
      args: ['config', 'core.autocrlf', 'false'],
      cwd: wsRoot,
    });
    await runSubprocess({
      command: 'git',
      args: ['config', 'user.email', 'test@example.com'],
      cwd: wsRoot,
    });
    await runSubprocess({
      command: 'git',
      args: ['config', 'user.name', 'Test User'],
      cwd: wsRoot,
    });

    fs.writeFileSync(path.join(wsRoot, 'tracked.txt'), 'v1\n', 'utf8');
    await runSubprocess({ command: 'git', args: ['add', 'tracked.txt'], cwd: wsRoot });
    await runSubprocess({ command: 'git', args: ['commit', '-m', 'init'], cwd: wsRoot });

    // Stage a specific change in real .git/index (must NOT be clobbered by snapshot!)
    fs.writeFileSync(path.join(wsRoot, 'tracked.txt'), 'v2-staged\n', 'utf8');
    await runSubprocess({ command: 'git', args: ['add', 'tracked.txt'], cwd: wsRoot });

    // Also add an unstaged + untracked file
    fs.writeFileSync(path.join(wsRoot, 'tracked.txt'), 'v3-working\n', 'utf8');
    fs.writeFileSync(path.join(wsRoot, 'untracked.txt'), 'keep-me-in-checkpoint\n', 'utf8');

    const cachedBefore = (
      await runSubprocess({ command: 'git', args: ['diff', '--cached'], cwd: wsRoot })
    ).stdout;

    const chk = await createCheckpoint({
      workspacesDir,
      slug,
      reason: 'before-risky-edit',
      workspaceRepo: repos.workspaces,
    });

    const cachedAfter = (
      await runSubprocess({ command: 'git', args: ['diff', '--cached'], cwd: wsRoot })
    ).stdout;

    // Real .git/index staged state was NOT touched
    expect(cachedAfter).toBe(cachedBefore);
    expect(cachedAfter).toContain('+v2-staged');
    expect(chk.gitRef).toBe(`refs/mcp-checkpoints/${chk.checkpointId}`);

    // Verify ref exists in git
    const refVerify = await runSubprocess({
      command: 'git',
      args: ['rev-parse', '--verify', chk.gitRef],
      cwd: wsRoot,
    });
    expect(refVerify.exitCode).toBe(0);
    expect(refVerify.stdout.trim()).toBe(chk.gitCommitSha);

    // Mutate worktree further & add extra garbage file
    fs.writeFileSync(path.join(wsRoot, 'tracked.txt'), 'v4-corrupted\n', 'utf8');
    fs.writeFileSync(path.join(wsRoot, 'garbage.txt'), 'delete-me-on-rollback\n', 'utf8');

    await rollbackToCheckpoint(slug, chk.checkpointId, {
      workspacesDir,
      workspaceRepo: repos.workspaces,
    });

    expect(fs.readFileSync(path.join(wsRoot, 'tracked.txt'), 'utf8')).toBe('v3-working\n');
    expect(fs.readFileSync(path.join(wsRoot, 'untracked.txt'), 'utf8')).toBe(
      'keep-me-in-checkpoint\n',
    );
    expect(fs.existsSync(path.join(wsRoot, 'garbage.txt'))).toBe(false);
    expect(fs.existsSync(path.join(wsRoot, '.git'))).toBe(true);

    db.close();
  });

  it('enforces sensitive file blacklist, path sandbox, and RW lock fast-fail with active job_id', async () => {
    const workspacesDir = makeTempDir('omni-sec-');
    const slug = 'sec-ws';
    const wsRoot = path.join(workspacesDir, slug);
    fs.mkdirSync(wsRoot, { recursive: true });

    expect(() =>
      resolveSafeWorkspacePath(workspacesDir, slug, '../../etc/passwd'),
    ).toThrow(WorkspaceSandboxError);
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, '.env')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, '.env.production')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, 'certs/tls.pem')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, 'keys/server.key')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, '.ssh/id_rsa')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, '.ssh/id_ed25519.pub')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, '.git/config')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, '.git/hooks/pre-commit')).toThrow(
      WorkspaceSandboxError,
    );

    const lockMgr = new WorkspaceLockManager(200);
    const r1 = await lockMgr.acquireRead(slug);
    const r2 = await lockMgr.acquireRead(slug);
    r1.release();
    r2.release();

    const w1 = await lockMgr.acquireWrite(slug, { holder: 'codex_write', jobId: 'job_bg_99' });
    await expect(lockMgr.acquireWrite(slug)).rejects.toMatchObject({
      name: 'WorkspaceLockError',
      code: 'ACTIVE_JOB_LOCK',
      activeJobId: 'job_bg_99',
    });
    w1.release();

    // Test createOrOverwriteFiles and deleteFiles + stack detection
    await createOrOverwriteFiles({
      workspacesDir,
      slug,
      lockManager: lockMgr,
      skipL1: true,
      files: [
        {
          path: 'package.json',
          content: JSON.stringify({
            name: 'demo',
            scripts: { test: 'vitest run' },
            devDependencies: { vitest: '^5.0.0', typescript: '^5.8.0' },
          }),
        },
        { path: 'AGENTS.md', content: '# Agent Playbook\nRun vitest before PR.' },
        { path: 'temp.ts', content: 'export const temp = 1;\n' },
      ],
    });

    const { stack, playbookText } = detectWorkspaceStackAndPlaybook(wsRoot);
    expect(stack.languages).toContain('typescript');
    expect(stack.testCommands).toContain('npm test');
    expect(playbookText).toContain('Run vitest before PR.');

    const pipelineRes = await runValidationPipeline({
      workspaceDir: wsRoot,
      changedFiles: ['temp.ts'],
      skipL1: true,
    });
    expect(pipelineRes.passed).toBe(true);
    expect(pipelineRes.steps.some((s) => s.level === 'L2')).toBe(true);

    const delRes = await deleteFiles({
      workspacesDir,
      slug,
      lockManager: lockMgr,
      paths: ['temp.ts'],
    });
    expect(delRes.filesTouched).toEqual(['temp.ts']);
    expect(fs.existsSync(path.join(wsRoot, 'temp.ts'))).toBe(false);
    // Avoid unused import warning for WorkspaceLockError
    expect(WorkspaceLockError).toBeDefined();
  });

  it('blocks NTFS trailing-dot/space sensitive bypasses, .dev.vars, symlink escapes, and unsafe git branch flags', async () => {
    const workspacesDir = makeTempDir('omni-reg-');
    const outsideDir = makeTempDir('omni-out-');
    const slug = 'reg-ws';
    const wsRoot = path.join(workspacesDir, slug);
    fs.mkdirSync(path.join(wsRoot, '.git', 'hooks'), { recursive: true });
    fs.writeFileSync(path.join(wsRoot, '.env'), 'SECRET=1\n', 'utf8');
    fs.writeFileSync(path.join(wsRoot, '.git', 'hooks', 'pre-commit'), '#!/bin/sh\n', 'utf8');

    // Trailing-dot / trailing-space Windows NTFS bypass attempts
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, 'keys/server.key.')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, 'keys/server.key . ')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, '.env.')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, 'id_rsa .')).toThrow(
      WorkspaceSandboxError,
    );

    // .dev.vars and .dev.vars.*
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, '.dev.vars')).toThrow(
      WorkspaceSandboxError,
    );
    expect(() => resolveSafeWorkspacePath(workspacesDir, slug, '.dev.vars.staging')).toThrow(
      WorkspaceSandboxError,
    );

    // Workspace-root symlink/junction escape check
    const escapedSlug = 'escaped-ws';
    fs.symlinkSync(outsideDir, path.join(workspacesDir, escapedSlug), 'junction');
    expect(() => resolveSafeWorkspacePath(workspacesDir, escapedSlug, 'file.txt')).toThrow(
      WorkspaceSandboxError,
    );

    // Internal directory junction pointing into .git/hooks -> blocked via realRelativePath
    fs.symlinkSync(
      path.join(wsRoot, '.git', 'hooks'),
      path.join(wsRoot, 'public-hooks'),
      'junction',
    );
    expect(() =>
      resolveSafeWorkspacePath(workspacesDir, slug, 'public-hooks/pre-commit'),
    ).toThrow(WorkspaceSandboxError);

    // Optional file symlink test (may require elevated privilege on some Windows hosts)
    try {
      fs.symlinkSync(path.join(wsRoot, '.env'), path.join(wsRoot, 'safe.txt'), 'file');
      expect(() => resolveSafeWorkspacePath(workspacesDir, slug, 'safe.txt')).toThrow(
        WorkspaceSandboxError,
      );
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EPERM') throw err;
    }

    // Reject git branch flag injection in syncGitHubRepo
    await expect(
      syncGitHubRepo({
        workspacesDir,
        slug,
        repo: 'owner/repo',
        branch: '--upload-pack=evil',
      }),
    ).rejects.toThrow(/Invalid git branch name/);
    await expect(
      syncGitHubRepo({
        workspacesDir,
        slug,
        repo: 'owner/repo',
        branch: 'main..evil',
      }),
    ).rejects.toThrow(/Invalid git branch name/);
  });

  it('rejects sibling workspace-root symlink aliasing, symlink playbooks, and rolls back on validation throw while preserving mode', async () => {
    const workspacesDir = makeTempDir('omni-stagea-');
    const outsideDir = makeTempDir('omni-outside-');
    const realSlug = 'real-ws';
    const realWs = path.join(workspacesDir, realSlug);
    fs.mkdirSync(realWs, { recursive: true });
    fs.writeFileSync(path.join(outsideDir, 'secret-playbook.md'), 'LEAKED\n', 'utf8');
    fs.writeFileSync(path.join(realWs, 'target.ts'), 'export const val = 1;\n', {
      encoding: 'utf8',
      mode: 0o755,
    });

    // Sibling workspace-root symlink/junction pointing inside workspacesDir must still be rejected
    const aliasSlug = 'alias-ws';
    fs.symlinkSync(realWs, path.join(workspacesDir, aliasSlug), 'junction');
    expect(() => resolveSafeWorkspacePath(workspacesDir, aliasSlug, 'target.ts')).toThrow(
      WorkspaceSandboxError,
    );

    // Bounded file reader rejects symlinks and truncates oversized files cleanly
    fs.writeFileSync(path.join(realWs, 'big.txt'), 'A'.repeat(2048), 'utf8');
    const bounded = readSafeBoundedWorkspaceFile(realWs, 'big.txt', 128);
    expect(bounded?.length).toBe(128);
    expect(readSafeBoundedWorkspaceFile(realWs, '../outside/secret-playbook.md')).toBeNull();

    try {
      fs.symlinkSync(
        path.join(outsideDir, 'secret-playbook.md'),
        path.join(realWs, 'AGENTS.md'),
        'file',
      );
      expect(readSafeBoundedWorkspaceFile(realWs, 'AGENTS.md')).toBeNull();
      const { playbookText } = detectWorkspaceStackAndPlaybook(realWs);
      expect(playbookText).toBeNull();
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EPERM') throw err;
    }

    // Case-insensitive lock key on win32/darwin
    if (process.platform === 'win32' || process.platform === 'darwin') {
      const caseMgr = new WorkspaceLockManager(100);
      const lease = await caseMgr.acquireWrite('CaseSlug', { jobId: 'job_case_1' });
      await expect(caseMgr.acquireWrite('caseslug')).rejects.toMatchObject({
        code: 'ACTIVE_JOB_LOCK',
        activeJobId: 'job_case_1',
      });
      lease.release();
    }

    // codePatcher preserves file mode (on POSIX) and rolls back if validationRunner throws unexpectedly
    const modeBefore = fs.statSync(path.join(realWs, 'target.ts')).mode & 0o777;
    await expect(
      applyPatch({
        workspacesDir,
        slug: realSlug,
        edits: [
          {
            path: 'target.ts',
            hunks: [{ search: 'export const val = 1;', replace: 'export const val = 2;' }],
          },
        ],
        validationRunner: async () => {
          throw new Error('Unexpected validator crash');
        },
      }),
    ).rejects.toThrow('Unexpected validator crash');

    expect(fs.readFileSync(path.join(realWs, 'target.ts'), 'utf8')).toBe(
      'export const val = 1;\n',
    );
    expect(fs.statSync(path.join(realWs, 'target.ts')).mode & 0o777).toBe(modeBefore);
  });
});
