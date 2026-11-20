import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { WorkspaceRepository } from '../db/repositories/workspaceRepo.js';
import type {
  CheckpointRecord,
  DetectedStack,
  ScrubberLike,
  WorkspaceRecord,
} from '../types.js';
import { buildSandboxedEnv, runSubprocess } from '../utils/exec.js';
import { createSecretScrubber } from '../utils/secretScrubber.js';
import { resolveWorkspaceRoot, validateWorkspaceSlug } from './workspaceLock.js';

export const MCP_CHECKPOINT_REF_PREFIX = 'refs/mcp-checkpoints/';

const GIT_IDENTITY_ENV: Record<string, string> = {
  GIT_AUTHOR_NAME: 'omni-mcp-gateway',
  GIT_AUTHOR_EMAIL: 'gateway@omni.local',
  GIT_COMMITTER_NAME: 'omni-mcp-gateway',
  GIT_COMMITTER_EMAIL: 'gateway@omni.local',
};

export interface CreateCheckpointOptions {
  workspacesDir: string;
  slug: string;
  reason: string;
  checkpointId?: string;
  workspaceRepo?: WorkspaceRepository;
  scrubber?: ScrubberLike;
}

export interface CheckpointCreationResult {
  checkpointId: string;
  workspaceSlug: string;
  gitCommitSha: string;
  gitRef: string;
  reason: string;
  createdAt: number;
  record?: CheckpointRecord;
}

export interface RollbackOptions {
  workspacesDir: string;
  workspaceRepo?: WorkspaceRepository;
  createSafetyCheckpoint?: boolean;
  scrubber?: ScrubberLike;
}

export interface RollbackResult {
  workspaceSlug: string;
  rolledBackTo: string;
  gitCommitSha: string;
  safetyCheckpointId?: string;
}

export interface SyncGitHubRepoOptions {
  workspacesDir: string;
  slug: string;
  repo: string;
  branch?: string;
  ghToken?: string;
  workspaceRepo?: WorkspaceRepository;
  scrubber?: ScrubberLike;
}

export interface SyncGitHubRepoResult {
  workspace: WorkspaceRecord;
  workspaceDir: string;
  action: 'cloned' | 'updated' | 'fetched_only_dirty';
  currentBranch: string;
  headSha: string;
  output: string;
}

export interface InitCfOpsWorkspaceOptions {
  workspacesDir: string;
  slug: string;
  workspaceRepo?: WorkspaceRepository;
}

export interface CfOpsContext {
  workspaceSlug: string;
  workspaceDir: string;
  hasWranglerConfig: boolean;
  wranglerConfigFile: string | null;
  workerName: string | null;
  compatibilityDate: string | null;
  mainEntry: string | null;
  bindings: {
    kvNamespaces: string[];
    d1Databases: string[];
    r2Buckets: string[];
    durableObjects: string[];
  };
  detectedStack: DetectedStack;
  playbookText: string | null;
}

async function runGit(
  cwd: string,
  args: string[],
  extraEnv: Record<string, string | undefined> = {},
  timeoutMs = 30000,
): Promise<{ stdout: string; stderr: string; exitCode: number | null }> {
  const env = buildSandboxedEnv({
    extraEnv: {
      ...GIT_IDENTITY_ENV,
      ...extraEnv,
    },
  });

  const nullHooksPath = process.platform === 'win32' ? 'NUL' : '/dev/null';
  const hardenedArgs = [
    '-c',
    `core.hooksPath=${nullHooksPath}`,
    '-c',
    'credential.helper=',
    ...args,
  ];

  const res = await runSubprocess({
    command: 'git',
    args: hardenedArgs,
    cwd,
    env,
    timeoutMs,
  });

  return {
    stdout: res.stdout.trim(),
    stderr: res.stderr.trim(),
    exitCode: res.exitCode,
  };
}

/**
 * Checks whether a directory is inside a git repository.
 */
export async function isGitRepository(workspaceDir: string): Promise<boolean> {
  if (!fs.existsSync(workspaceDir)) return false;
  const res = await runGit(workspaceDir, ['rev-parse', '--is-inside-work-tree']);
  return res.exitCode === 0 && res.stdout === 'true';
}

function ensureWorkspaceRow(
  workspaceRepo: WorkspaceRepository | undefined,
  slug: string,
  workspaceDir: string,
): void {
  if (!workspaceRepo) return;
  const existing = workspaceRepo.getWorkspace(slug);
  if (existing) return;

  const { stack, playbookText } = detectWorkspaceStackAndPlaybook(workspaceDir);
  workspaceRepo.upsertWorkspace({
    slug,
    repo_url: 'local',
    default_branch: 'main',
    detected_stack: stack,
    playbook_text: playbookText,
    last_synced_at: null,
  });
}

/**
 * Creates a zero-side-effect Git snapshot using a temporary `GIT_INDEX_FILE`
 * copied from `.git/index` so the workspace's real `.git/index` and `HEAD` remain untouched.
 */
export async function createCheckpoint(
  options: CreateCheckpointOptions,
): Promise<CheckpointCreationResult> {
  const validSlug = validateWorkspaceSlug(options.slug);
  const { realWorkspaceRoot } = resolveWorkspaceRoot(options.workspacesDir, validSlug);
  const scrubber = options.scrubber ?? createSecretScrubber();

  if (!fs.existsSync(realWorkspaceRoot)) {
    throw new Error(`Workspace directory does not exist: "${validSlug}"`);
  }

  const gitDirRes = await runGit(realWorkspaceRoot, ['rev-parse', '--git-dir']);
  if (gitDirRes.exitCode !== 0 || !gitDirRes.stdout) {
    throw new Error(`Workspace "${validSlug}" is not a git repository`);
  }

  const gitDir = path.isAbsolute(gitDirRes.stdout)
    ? gitDirRes.stdout
    : path.resolve(realWorkspaceRoot, gitDirRes.stdout);
  const realIndexPath = path.join(gitDir, 'index');
  const tmpIndexPath = path.join(os.tmpdir(), `omni-git-idx-${randomUUID()}`);

  try {
    if (fs.existsSync(realIndexPath)) {
      fs.copyFileSync(realIndexPath, tmpIndexPath);
    }

    const addRes = await runGit(realWorkspaceRoot, ['add', '-A'], {
      GIT_INDEX_FILE: tmpIndexPath,
    });
    if (addRes.exitCode !== 0) {
      throw new Error(
        `git add -A (temp index) failed: ${scrubber.scrub(addRes.stderr || addRes.stdout)}`,
      );
    }

    const treeRes = await runGit(realWorkspaceRoot, ['write-tree'], {
      GIT_INDEX_FILE: tmpIndexPath,
    });
    if (treeRes.exitCode !== 0 || !treeRes.stdout) {
      throw new Error(
        `git write-tree failed: ${scrubber.scrub(treeRes.stderr || treeRes.stdout)}`,
      );
    }
    const treeSha = treeRes.stdout;

    const headRes = await runGit(realWorkspaceRoot, ['rev-parse', '--verify', 'HEAD']);
    const commitArgs = ['commit-tree', treeSha];
    if (headRes.exitCode === 0 && headRes.stdout) {
      commitArgs.push('-p', headRes.stdout);
    }
    commitArgs.push('-m', `mcp-checkpoint: ${options.reason}`);

    const commitRes = await runGit(realWorkspaceRoot, commitArgs);
    if (commitRes.exitCode !== 0 || !commitRes.stdout) {
      throw new Error(
        `git commit-tree failed: ${scrubber.scrub(commitRes.stderr || commitRes.stdout)}`,
      );
    }
    const gitCommitSha = commitRes.stdout;

    const checkpointId = options.checkpointId ?? `chk_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const gitRef = `${MCP_CHECKPOINT_REF_PREFIX}${checkpointId}`;

    const refRes = await runGit(realWorkspaceRoot, ['update-ref', gitRef, gitCommitSha]);
    if (refRes.exitCode !== 0) {
      throw new Error(
        `git update-ref failed: ${scrubber.scrub(refRes.stderr || refRes.stdout)}`,
      );
    }

    const createdAt = Date.now();
    let record: CheckpointRecord | undefined;
    if (options.workspaceRepo) {
      ensureWorkspaceRow(options.workspaceRepo, validSlug, realWorkspaceRoot);
      record = options.workspaceRepo.createCheckpoint({
        checkpoint_id: checkpointId,
        workspace_slug: validSlug,
        git_commit_sha: gitCommitSha,
        git_ref: gitRef,
        reason: options.reason,
        created_at: createdAt,
      });
    }

    return {
      checkpointId,
      workspaceSlug: validSlug,
      gitCommitSha,
      gitRef,
      reason: options.reason,
      createdAt,
      record,
    };
  } finally {
    try {
      if (fs.existsSync(tmpIndexPath)) {
        fs.unlinkSync(tmpIndexPath);
      }
    } catch {
      // Best-effort temp cleanup
    }
  }
}

/**
 * Restores the workspace worktree cleanly from a checkpoint commit without losing `.git` metadata.
 */
export async function rollbackToCheckpoint(
  slug: string,
  checkpointId: string,
  options: RollbackOptions,
): Promise<RollbackResult> {
  const validSlug = validateWorkspaceSlug(slug);
  const { realWorkspaceRoot } = resolveWorkspaceRoot(options.workspacesDir, validSlug);
  const scrubber = options.scrubber ?? createSecretScrubber();

  if (!fs.existsSync(realWorkspaceRoot)) {
    throw new Error(`Workspace directory does not exist: "${validSlug}"`);
  }

  let commitSha: string | null = null;
  if (options.workspaceRepo) {
    const rec = options.workspaceRepo.getCheckpoint(checkpointId);
    if (rec) {
      if (rec.workspace_slug !== validSlug) {
        throw new Error(
          `Checkpoint "${checkpointId}" belongs to workspace "${rec.workspace_slug}", not "${validSlug}"`,
        );
      }
      commitSha = rec.git_commit_sha;
    }
  }

  if (!commitSha) {
    const refRes = await runGit(realWorkspaceRoot, [
      'rev-parse',
      '--verify',
      `${MCP_CHECKPOINT_REF_PREFIX}${checkpointId}`,
    ]);
    if (refRes.exitCode === 0 && refRes.stdout) {
      commitSha = refRes.stdout;
    }
  }

  if (!commitSha) {
    throw new Error(`Checkpoint "${checkpointId}" not found for workspace "${validSlug}"`);
  }

  let safetyCheckpointId: string | undefined;
  if (options.createSafetyCheckpoint !== false) {
    const safety = await createCheckpoint({
      workspacesDir: options.workspacesDir,
      slug: validSlug,
      reason: `pre-rollback:${checkpointId}`,
      workspaceRepo: options.workspaceRepo,
      scrubber,
    });
    safetyCheckpointId = safety.checkpointId;
  }

  const cleanRes = await runGit(realWorkspaceRoot, ['clean', '-fd']);
  if (cleanRes.exitCode !== 0) {
    throw new Error(`git clean failed during rollback: ${scrubber.scrub(cleanRes.stderr)}`);
  }

  const readTreeRes = await runGit(realWorkspaceRoot, ['read-tree', '--reset', '-u', commitSha]);
  if (readTreeRes.exitCode !== 0) {
    throw new Error(
      `git read-tree --reset -u failed during rollback: ${scrubber.scrub(readTreeRes.stderr)}`,
    );
  }

  return {
    workspaceSlug: validSlug,
    rolledBackTo: checkpointId,
    gitCommitSha: commitSha,
    safetyCheckpointId,
  };
}

function addUnique(list: string[], value: string): void {
  if (value && !list.includes(value)) {
    list.push(value);
  }
}

const DEFAULT_STACK_FILE_MAX_BYTES = 64 * 1024;

function isInsideRealDir(candidatePath: string, realRootDir: string): boolean {
  const a = process.platform === 'win32' ? candidatePath.toLowerCase() : candidatePath;
  const b = process.platform === 'win32' ? realRootDir.toLowerCase() : realRootDir;
  if (a === b) return true;
  const prefix = b.endsWith(path.sep) ? b : b + path.sep;
  return a.startsWith(prefix);
}

/**
 * Safely reads at most `maxBytes` from a workspace-relative regular file.
 * Rejects symlinks (`lstatSync`), verifies `realpathSync` containment inside `workspaceDir`,
 * and avoids unbounded memory reads on oversized files.
 */
export function readSafeBoundedWorkspaceFile(
  workspaceDir: string,
  relFile: string,
  maxBytes = DEFAULT_STACK_FILE_MAX_BYTES,
): string | null {
  try {
    const realRoot = fs.realpathSync(workspaceDir);
    const candidate = path.resolve(workspaceDir, relFile);
    if (!isInsideRealDir(candidate, path.resolve(workspaceDir))) {
      return null;
    }

    const stat = fs.lstatSync(candidate);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      return null;
    }

    const realTarget = fs.realpathSync(candidate);
    if (!isInsideRealDir(realTarget, realRoot)) {
      return null;
    }

    const fd = fs.openSync(realTarget, 'r');
    try {
      const toRead = Math.max(0, Math.min(stat.size, maxBytes));
      if (toRead === 0) return '';
      const buf = Buffer.allocUnsafe(toRead);
      let totalRead = 0;
      while (totalRead < toRead) {
        const bytesRead = fs.readSync(fd, buf, totalRead, toRead - totalRead, totalRead);
        if (bytesRead <= 0) break;
        totalRead += bytesRead;
      }
      return buf.subarray(0, totalRead).toString('utf8');
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return null;
  }
}

function readJsonSafe(
  workspaceDir: string,
  relFile: string,
  maxBytes = DEFAULT_STACK_FILE_MAX_BYTES,
): Record<string, unknown> | null {
  const raw = readSafeBoundedWorkspaceFile(workspaceDir, relFile, maxBytes);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Detects workspace languages, package managers, frameworks, verification commands,
 * and reads `AGENTS.md` / `CLAUDE.md` playbooks.
 */
export function detectWorkspaceStackAndPlaybook(workspaceDir: string): {
  stack: DetectedStack;
  playbookText: string | null;
} {
  const stack: DetectedStack = {
    languages: [],
    packageManagers: [],
    frameworks: [],
    testCommands: [],
    lintCommands: [],
    buildCommands: [],
    typecheckCommands: [],
    hasDockerfile: false,
    hasWrangler: false,
    playbookSources: [],
  };

  if (!fs.existsSync(workspaceDir)) {
    return { stack, playbookText: null };
  }

  const entries = new Set(fs.readdirSync(workspaceDir));

  // Node / TypeScript
  if (entries.has('package.json')) {
    addUnique(stack.languages, entries.has('tsconfig.json') ? 'typescript' : 'javascript');
    if (entries.has('pnpm-lock.yaml')) addUnique(stack.packageManagers, 'pnpm');
    else if (entries.has('yarn.lock')) addUnique(stack.packageManagers, 'yarn');
    else if (entries.has('bun.lockb') || entries.has('bun.lock')) {
      addUnique(stack.packageManagers, 'bun');
    } else {
      addUnique(stack.packageManagers, 'npm');
    }

    const pm = stack.packageManagers[0] ?? 'npm';
    const runPrefix = pm === 'npm' ? 'npm run' : pm;
    const pkg = readJsonSafe(workspaceDir, 'package.json');
    if (pkg) {
      const scripts = (pkg.scripts ?? {}) as Record<string, unknown>;
      if (typeof scripts.test === 'string') {
        addUnique(stack.testCommands, pm === 'npm' ? 'npm test' : `${pm} test`);
      }
      if (typeof scripts.lint === 'string') {
        addUnique(stack.lintCommands, `${runPrefix} lint`);
      }
      if (typeof scripts.build === 'string') {
        addUnique(stack.buildCommands, `${runPrefix} build`);
      }
      if (typeof scripts.typecheck === 'string') {
        addUnique(stack.typecheckCommands, `${runPrefix} typecheck`);
      }

      const deps = {
        ...((pkg.dependencies as Record<string, unknown> | undefined) ?? {}),
        ...((pkg.devDependencies as Record<string, unknown> | undefined) ?? {}),
      };
      for (const fw of ['hono', 'next', 'react', 'vite', 'vitest', 'jest', 'express', 'astro', 'wrangler']) {
        if (fw in deps) {
          addUnique(stack.frameworks, fw);
        }
      }
      if ('typescript' in deps) {
        addUnique(stack.languages, 'typescript');
        if (stack.typecheckCommands.length === 0 && entries.has('tsconfig.json')) {
          addUnique(stack.typecheckCommands, 'npx tsc --noEmit');
        }
      }
    }
  } else if (entries.has('tsconfig.json')) {
    addUnique(stack.languages, 'typescript');
    addUnique(stack.typecheckCommands, 'npx tsc --noEmit');
  }

  // Python
  if (
    entries.has('pyproject.toml') ||
    entries.has('pytest.ini') ||
    entries.has('requirements.txt')
  ) {
    addUnique(stack.languages, 'python');
    if (entries.has('uv.lock')) addUnique(stack.packageManagers, 'uv');
    else if (entries.has('poetry.lock')) addUnique(stack.packageManagers, 'poetry');
    else addUnique(stack.packageManagers, 'pip');

    if (entries.has('pytest.ini')) {
      addUnique(stack.frameworks, 'pytest');
      addUnique(stack.testCommands, 'pytest');
    } else if (entries.has('pyproject.toml')) {
      const pyproject = readSafeBoundedWorkspaceFile(workspaceDir, 'pyproject.toml');
      if (pyproject) {
        if (pyproject.includes('pytest')) {
          addUnique(stack.frameworks, 'pytest');
          addUnique(stack.testCommands, 'pytest');
        }
        if (pyproject.includes('ruff')) {
          addUnique(stack.lintCommands, 'ruff check .');
        }
        if (pyproject.includes('pyright')) {
          addUnique(stack.typecheckCommands, 'pyright');
        }
      }
    }
  }

  // Rust
  if (entries.has('Cargo.toml')) {
    addUnique(stack.languages, 'rust');
    addUnique(stack.packageManagers, 'cargo');
    addUnique(stack.testCommands, 'cargo test');
    addUnique(stack.lintCommands, 'cargo clippy');
    addUnique(stack.buildCommands, 'cargo build');
  }

  // Go
  if (entries.has('go.mod')) {
    addUnique(stack.languages, 'go');
    addUnique(stack.packageManagers, 'go');
    addUnique(stack.testCommands, 'go test ./...');
    addUnique(stack.lintCommands, 'go vet ./...');
    addUnique(stack.buildCommands, 'go build ./...');
  }

  // Makefile
  if (entries.has('Makefile')) {
    const makefile = readSafeBoundedWorkspaceFile(workspaceDir, 'Makefile');
    if (makefile) {
      if (/^test:/m.test(makefile)) addUnique(stack.testCommands, 'make test');
      if (/^lint:/m.test(makefile)) addUnique(stack.lintCommands, 'make lint');
      if (/^build:/m.test(makefile)) addUnique(stack.buildCommands, 'make build');
    }
  }

  // Dockerfile
  for (const entry of entries) {
    if (entry === 'Dockerfile' || entry.startsWith('Dockerfile.')) {
      stack.hasDockerfile = true;
      addUnique(stack.frameworks, 'docker');
      break;
    }
  }

  // Wrangler / Cloudflare
  if (entries.has('wrangler.toml') || entries.has('wrangler.jsonc')) {
    stack.hasWrangler = true;
    addUnique(stack.frameworks, 'cloudflare-workers');
  }

  // Playbooks: AGENTS.md / CLAUDE.md
  const playbookParts: string[] = [];
  for (const filename of ['AGENTS.md', 'AGENTS.override.md', 'CLAUDE.md']) {
    const raw = readSafeBoundedWorkspaceFile(workspaceDir, filename, 16384);
    if (raw !== null) {
      stack.playbookSources?.push(filename);
      const trimmed = raw.trim();
      if (trimmed) {
        playbookParts.push(`## ${filename}\n${trimmed}`);
      }
    }
  }

  const playbookText =
    playbookParts.length > 0 ? playbookParts.join('\n\n').slice(0, 16384) : null;

  return { stack, playbookText };
}

function normalizeGitHubRepoUrl(repo: string): string {
  const trimmed = repo.trim();
  if (/^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(trimmed)) {
    return `https://github.com/${trimmed}.git`;
  }
  const parsed = new URL(trimmed);
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(`Unsupported repository URL protocol: ${parsed.protocol}`);
  }
  return trimmed;
}

function buildGitAuthEnv(ghToken?: string): Record<string, string> {
  if (!ghToken) return {};
  const basic = Buffer.from(`x-access-token:${ghToken}`, 'utf8').toString('base64');
  return {
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
    GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${basic}`,
  };
}

function validateGitBranchName(branch: string): string {
  if (
    typeof branch !== 'string' ||
    branch.length === 0 ||
    branch.startsWith('-') ||
    branch.includes('..') ||
    branch.includes('@{') ||
    /[\s~^:?*[\]\\\x00-\x1f\x7f]/.test(branch)
  ) {
    throw new Error(`Invalid git branch name "${String(branch)}"`);
  }
  return branch;
}

/**
 * On POSIX, ensures cloned/updated workspace worktree directories and files are group-writable (`g+w`,
 * skipping symlinks) so the sandboxed `worker` UID can edit/build, while stripping group-write (`g-w`)
 * from `.git/config` and `.git/hooks/*`.
 */
function ensureWorkspaceGroupPermissions(workspaceRoot: string): void {
  if (process.platform === 'win32') return;

  const walk = (dirPath: string, relDir: string) => {
    let dirStat: fs.Stats;
    try {
      dirStat = fs.lstatSync(dirPath);
    } catch {
      return;
    }
    if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) return;

    const inRestrictedGitDir =
      relDir === '.git/hooks' || relDir.startsWith('.git/hooks/');
    try {
      const mode = dirStat.mode & 0o7777;
      if (inRestrictedGitDir) {
        if ((mode & 0o020) !== 0) {
          fs.chmodSync(dirPath, mode & ~0o020);
        }
      } else if ((mode & 0o020) === 0) {
        fs.chmodSync(dirPath, mode | 0o020);
      }
    } catch {
      // Best-effort permission adjustment
    }

    let entries: string[];
    try {
      entries = fs.readdirSync(dirPath);
    } catch {
      return;
    }

    for (const name of entries) {
      const full = path.join(dirPath, name);
      const rel = relDir ? `${relDir}/${name}` : name;
      let stat: fs.Stats;
      try {
        stat = fs.lstatSync(full);
      } catch {
        continue;
      }
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) {
        walk(full, rel);
      } else if (stat.isFile()) {
        const isProtectedGitFile =
          rel === '.git/config' || rel === '.git/hooks' || rel.startsWith('.git/hooks/');
        try {
          const mode = stat.mode & 0o7777;
          if (isProtectedGitFile) {
            if ((mode & 0o020) !== 0) {
              fs.chmodSync(full, mode & ~0o020);
            }
          } else if ((mode & 0o020) === 0) {
            fs.chmodSync(full, mode | 0o020);
          }
        } catch {
          // Best-effort permission adjustment
        }
      }
    }
  };

  walk(workspaceRoot, '');
}

/**
 * Clones or fast-forward syncs a GitHub repository into `{workspacesDir}/{slug}`,
 * detects stack and playbooks, and persists workspace metadata.
 */
export async function syncGitHubRepo(
  options: SyncGitHubRepoOptions,
): Promise<SyncGitHubRepoResult> {
  const validSlug = validateWorkspaceSlug(options.slug);
  const validBranch =
    options.branch !== undefined ? validateGitBranchName(options.branch) : undefined;
  const scrubber = options.scrubber ?? createSecretScrubber();
  if (options.ghToken && 'addSecret' in scrubber && typeof scrubber.addSecret === 'function') {
    (scrubber as { addSecret(val: string): void }).addSecret(options.ghToken);
  }

  const baseWorkspaces = path.resolve(options.workspacesDir);
  fs.mkdirSync(baseWorkspaces, { recursive: true });
  const { workspaceRoot } = resolveWorkspaceRoot(baseWorkspaces, validSlug);
  const repoUrl = normalizeGitHubRepoUrl(options.repo);
  const authEnv = buildGitAuthEnv(options.ghToken);

  let action: 'cloned' | 'updated' | 'fetched_only_dirty';
  let outputText = '';

  if (!fs.existsSync(path.join(workspaceRoot, '.git'))) {
    if (fs.existsSync(workspaceRoot) && fs.readdirSync(workspaceRoot).length > 0) {
      throw new Error(
        `Target workspace directory "${validSlug}" already exists and is not a git repository`,
      );
    }
    const cloneArgs = ['clone', '-c', 'core.sharedRepository=group'];
    if (validBranch) {
      cloneArgs.push('--branch', validBranch);
    }
    cloneArgs.push(repoUrl, workspaceRoot);

    const cloneRes = await runGit(baseWorkspaces, cloneArgs, authEnv, 120000);
    if (cloneRes.exitCode !== 0) {
      throw new Error(
        `git clone failed: ${scrubber.scrub(cloneRes.stderr || cloneRes.stdout)}`,
      );
    }
    action = 'cloned';
    outputText = scrubber.scrub([cloneRes.stdout, cloneRes.stderr].filter(Boolean).join('\n'));
  } else {
    const fetchRes = await runGit(
      workspaceRoot,
      ['-c', 'core.sharedRepository=group', 'fetch', '--prune', 'origin'],
      authEnv,
      60000,
    );
    if (fetchRes.exitCode !== 0) {
      throw new Error(
        `git fetch failed: ${scrubber.scrub(fetchRes.stderr || fetchRes.stdout)}`,
      );
    }

    const statusRes = await runGit(workspaceRoot, ['status', '--porcelain']);
    const isDirty = statusRes.stdout.length > 0;
    if (isDirty) {
      action = 'fetched_only_dirty';
      outputText = scrubber.scrub(
        `Fetched origin, skipped fast-forward because working tree has uncommitted changes.\n${fetchRes.stderr}`,
      );
    } else {
      const targetBranch =
        validBranch ??
        (await runGit(workspaceRoot, ['rev-parse', '--abbrev-ref', 'HEAD'])).stdout;
      if (validBranch) {
        const checkoutRes = await runGit(workspaceRoot, [
          '-c',
          'core.sharedRepository=group',
          'checkout',
          validBranch,
        ]);
        if (checkoutRes.exitCode !== 0) {
          throw new Error(
            `git checkout ${validBranch} failed: ${scrubber.scrub(checkoutRes.stderr)}`,
          );
        }
      }
      const pullRes = await runGit(
        workspaceRoot,
        ['-c', 'core.sharedRepository=group', 'pull', '--ff-only', 'origin', targetBranch || 'HEAD'],
        authEnv,
        60000,
      );
      if (pullRes.exitCode !== 0) {
        throw new Error(
          `git pull --ff-only failed: ${scrubber.scrub(pullRes.stderr || pullRes.stdout)}`,
        );
      }
      action = 'updated';
      outputText = scrubber.scrub([fetchRes.stdout, pullRes.stdout].filter(Boolean).join('\n'));
    }
  }

  ensureWorkspaceGroupPermissions(workspaceRoot);

  const branchRes = await runGit(workspaceRoot, ['rev-parse', '--abbrev-ref', 'HEAD']);
  const headRes = await runGit(workspaceRoot, ['rev-parse', 'HEAD']);
  const currentBranch = branchRes.stdout || validBranch || 'main';
  const headSha = headRes.stdout || '';

  const { stack, playbookText } = detectWorkspaceStackAndPlaybook(workspaceRoot);
  const now = Date.now();

  let workspace: WorkspaceRecord = {
    slug: validSlug,
    repo_url: repoUrl,
    default_branch: currentBranch,
    detected_stack: stack,
    playbook_text: playbookText,
    last_synced_at: now,
  };

  if (options.workspaceRepo) {
    workspace = options.workspaceRepo.upsertWorkspace(workspace);
  }

  return {
    workspace,
    workspaceDir: workspaceRoot,
    action,
    currentBranch,
    headSha,
    output: outputText,
  };
}

function extractTomlString(content: string, key: string): string | null {
  const re = new RegExp(`^\\s*${key}\\s*=\\s*["']([^"']+)["']`, 'm');
  const match = content.match(re);
  return match?.[1] ?? null;
}

function extractTomlBindings(content: string, section: string): string[] {
  const results: string[] = [];
  const blockRe = new RegExp(`\\[\\[${section}\\]\\][\\s\\S]*?(?=\\n\\[|$)`, 'g');
  const blocks = content.match(blockRe) ?? [];
  for (const block of blocks) {
    const binding = extractTomlString(block, 'binding');
    if (binding) results.push(binding);
  }
  return results;
}

/**
 * Inspects Cloudflare Worker/Pages operational context (`wrangler.toml` / `wrangler.jsonc`)
 * inside a workspace without reading sensitive `.dev.vars` or `.env*` files.
 */
export function initCfOpsWorkspace(options: InitCfOpsWorkspaceOptions): CfOpsContext {
  const validSlug = validateWorkspaceSlug(options.slug);
  const { workspaceRoot } = resolveWorkspaceRoot(options.workspacesDir, validSlug);
  if (!fs.existsSync(workspaceRoot)) {
    throw new Error(`Workspace "${validSlug}" does not exist`);
  }

  const { stack, playbookText } = detectWorkspaceStackAndPlaybook(workspaceRoot);

  let wranglerConfigFile: string | null = null;
  let workerName: string | null = null;
  let compatibilityDate: string | null = null;
  let mainEntry: string | null = null;
  const bindings = {
    kvNamespaces: [] as string[],
    d1Databases: [] as string[],
    r2Buckets: [] as string[],
    durableObjects: [] as string[],
  };

  const rawToml = readSafeBoundedWorkspaceFile(workspaceRoot, 'wrangler.toml');
  const rawJsonc =
    rawToml === null ? readSafeBoundedWorkspaceFile(workspaceRoot, 'wrangler.jsonc') : null;

  if (rawToml !== null) {
    wranglerConfigFile = 'wrangler.toml';
    workerName = extractTomlString(rawToml, 'name');
    compatibilityDate = extractTomlString(rawToml, 'compatibility_date');
    mainEntry = extractTomlString(rawToml, 'main');
    bindings.kvNamespaces = extractTomlBindings(rawToml, 'kv_namespaces');
    bindings.d1Databases = extractTomlBindings(rawToml, 'd1_databases');
    bindings.r2Buckets = extractTomlBindings(rawToml, 'r2_buckets');
    bindings.durableObjects = extractTomlBindings(rawToml, 'durable_objects\\.bindings');
  } else if (rawJsonc !== null) {
    wranglerConfigFile = 'wrangler.jsonc';
    const stripped = rawJsonc
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/^\s*\/\/.*$/gm, '');
    try {
      const parsed = JSON.parse(stripped) as Record<string, unknown>;
      workerName = typeof parsed.name === 'string' ? parsed.name : null;
      compatibilityDate =
        typeof parsed.compatibility_date === 'string' ? parsed.compatibility_date : null;
      mainEntry = typeof parsed.main === 'string' ? parsed.main : null;
      if (Array.isArray(parsed.kv_namespaces)) {
        bindings.kvNamespaces = parsed.kv_namespaces
          .map((x) => (x as { binding?: unknown }).binding)
          .filter((x): x is string => typeof x === 'string');
      }
      if (Array.isArray(parsed.d1_databases)) {
        bindings.d1Databases = parsed.d1_databases
          .map((x) => (x as { binding?: unknown }).binding)
          .filter((x): x is string => typeof x === 'string');
      }
      if (Array.isArray(parsed.r2_buckets)) {
        bindings.r2Buckets = parsed.r2_buckets
          .map((x) => (x as { binding?: unknown }).binding)
          .filter((x): x is string => typeof x === 'string');
      }
    } catch {
      // Malformed jsonc still returns file presence
    }
  }

  if (options.workspaceRepo) {
    const existing = options.workspaceRepo.getWorkspace(validSlug);
    options.workspaceRepo.upsertWorkspace({
      slug: validSlug,
      repo_url: existing?.repo_url ?? 'local',
      default_branch: existing?.default_branch ?? 'main',
      detected_stack: stack,
      playbook_text: playbookText,
      last_synced_at: existing?.last_synced_at ?? Date.now(),
    });
  }

  return {
    workspaceSlug: validSlug,
    workspaceDir: workspaceRoot,
    hasWranglerConfig: wranglerConfigFile !== null,
    wranglerConfigFile,
    workerName,
    compatibilityDate,
    mainEntry,
    bindings,
    detectedStack: stack,
    playbookText,
  };
}
