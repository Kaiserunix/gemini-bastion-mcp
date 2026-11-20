import fs from 'node:fs';
import path from 'node:path';

export const WORKSPACE_SLUG_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;

export class WorkspaceSandboxError extends Error {
  constructor(
    message: string,
    public readonly code:
      | 'INVALID_SLUG'
      | 'PATH_TRAVERSAL'
      | 'SENSITIVE_FILE'
      | 'SYMLINK_ESCAPE',
  ) {
    super(message);
    this.name = 'WorkspaceSandboxError';
  }
}

export class WorkspaceLockError extends Error {
  constructor(
    message: string,
    public readonly code: 'LOCK_TIMEOUT' | 'ACTIVE_JOB_LOCK',
    public readonly activeJobId?: string,
  ) {
    super(message);
    this.name = 'WorkspaceLockError';
  }
}

/**
 * Returns true if the given workspace slug matches `^[a-zA-Z0-9_-]{1,64}$`.
 */
export function isValidWorkspaceSlug(slug: string): boolean {
  return WORKSPACE_SLUG_REGEX.test(slug);
}

/**
 * Validates a workspace slug and returns it, throwing WorkspaceSandboxError on mismatch.
 */
export function validateWorkspaceSlug(slug: string): string {
  if (typeof slug !== 'string' || !WORKSPACE_SLUG_REGEX.test(slug)) {
    throw new WorkspaceSandboxError(
      `Invalid workspace slug "${String(slug)}": must match ${WORKSPACE_SLUG_REGEX.source}`,
      'INVALID_SLUG',
    );
  }
  return slug;
}

/**
 * Resolves the realpath of an existing path, or the realpath of its deepest existing
 * ancestor joined with the remaining non-existent path segments.
 * Rejects broken symlinks so dangling links cannot escape the sandbox.
 */
function resolveRealPathWithAncestor(targetPath: string): string {
  const resolved = path.resolve(targetPath);

  try {
    const stat = fs.lstatSync(resolved);
    try {
      return fs.realpathSync(resolved);
    } catch {
      if (stat.isSymbolicLink()) {
        throw new WorkspaceSandboxError(
          `Broken symlink rejected inside workspace: "${resolved}"`,
          'SYMLINK_ESCAPE',
        );
      }
      throw new WorkspaceSandboxError(
        `Unable to resolve real path for "${resolved}"`,
        'SYMLINK_ESCAPE',
      );
    }
  } catch (err) {
    if (err instanceof WorkspaceSandboxError) {
      throw err;
    }
    const nodeErr = err as NodeJS.ErrnoException;
    if (nodeErr.code !== 'ENOENT') {
      throw err;
    }
  }

  let current = path.dirname(resolved);
  while (true) {
    try {
      const stat = fs.lstatSync(current);
      let realAncestor: string;
      try {
        realAncestor = fs.realpathSync(current);
      } catch {
        if (stat.isSymbolicLink()) {
          throw new WorkspaceSandboxError(
            `Broken symlink ancestor rejected: "${current}"`,
            'SYMLINK_ESCAPE',
          );
        }
        throw new WorkspaceSandboxError(
          `Unable to resolve real path for ancestor "${current}"`,
          'SYMLINK_ESCAPE',
        );
      }
      const suffix = path.relative(current, resolved);
      return suffix ? path.join(realAncestor, suffix) : realAncestor;
    } catch (err) {
      if (err instanceof WorkspaceSandboxError) {
        throw err;
      }
      const nodeErr = err as NodeJS.ErrnoException;
      if (nodeErr.code !== 'ENOENT') {
        throw err;
      }
      const parent = path.dirname(current);
      if (parent === current) {
        return resolved;
      }
      current = parent;
    }
  }
}

function isWithinDirectory(candidatePath: string, rootDir: string): boolean {
  const normCandidate = process.platform === 'win32' ? candidatePath.toLowerCase() : candidatePath;
  const normRoot = process.platform === 'win32' ? rootDir.toLowerCase() : rootDir;
  if (normCandidate === normRoot) return true;
  const rootWithSep = normRoot.endsWith(path.sep) ? normRoot : normRoot + path.sep;
  return normCandidate.startsWith(rootWithSep);
}

/**
 * Checks whether a workspace-relative path hits the hard read/write sensitive file blacklist:
 * `.env`, `.env.*`, `.dev.vars`, `.dev.vars.*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `.git/hooks/*`, `.git/config`.
 * Strips Windows NTFS trailing dots/spaces per segment so `server.key.` or `.env.` cannot bypass checks.
 */
export function isSensitiveWorkspacePath(relPath: string): boolean {
  const normalized = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  if (!normalized || normalized === '.') return false;

  const lower = normalized.toLowerCase();
  const segments = lower
    .split('/')
    .filter((s) => s.length > 0 && s !== '.')
    .map((s) => (s === '..' ? s : s.replace(/[. ]+$/, '')))
    .filter((s) => s.length > 0);
  if (segments.length === 0) return false;

  const cleanRel = segments.join('/');
  if (cleanRel === '.git/config' || cleanRel === '.git/hooks' || cleanRel.startsWith('.git/hooks/')) {
    return true;
  }

  // Also block nested .git/config or .git/hooks/* if ever present
  for (let i = 0; i < segments.length - 1; i++) {
    if (segments[i] === '.git') {
      const next = segments[i + 1];
      if (next === 'config' || next === 'hooks') {
        return true;
      }
    }
  }

  const basename = segments[segments.length - 1]!;
  if (basename === '.env' || basename.startsWith('.env.')) {
    return true;
  }
  if (basename === '.dev.vars' || basename.startsWith('.dev.vars.')) {
    return true;
  }
  if (basename.endsWith('.pem') || basename.endsWith('.key')) {
    return true;
  }
  if (basename.startsWith('id_rsa') || basename.startsWith('id_ed25519')) {
    return true;
  }

  return false;
}

export interface ResolveWorkspacePathOptions {
  allowRoot?: boolean;
  checkSensitive?: boolean;
}

export interface ResolvedWorkspacePath {
  slug: string;
  workspaceRoot: string;
  realWorkspaceRoot: string;
  resolvedPath: string;
  realPath: string;
  relativePath: string;
}

/**
 * Resolves and validates the workspace root `{workspacesDir}/{slug}`,
 * ensuring the workspace directory itself is not a symlink escaping `workspacesDir`.
 */
export function resolveWorkspaceRoot(workspacesDir: string, slug: string): {
  slug: string;
  workspaceRoot: string;
  realWorkspaceRoot: string;
} {
  const validSlug = validateWorkspaceSlug(slug);
  const baseWorkspaces = path.resolve(workspacesDir);
  const realBaseWorkspaces = resolveRealPathWithAncestor(baseWorkspaces);
  const workspaceRoot = path.resolve(baseWorkspaces, validSlug);
  try {
    const stat = fs.lstatSync(workspaceRoot);
    if (stat.isSymbolicLink()) {
      throw new WorkspaceSandboxError(
        `Workspace root "${validSlug}" cannot be a symlink`,
        'SYMLINK_ESCAPE',
      );
    }
  } catch (err) {
    if (err instanceof WorkspaceSandboxError) throw err;
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
  const realWorkspaceRoot = resolveRealPathWithAncestor(workspaceRoot);
  if (!isWithinDirectory(realWorkspaceRoot, realBaseWorkspaces)) {
    throw new WorkspaceSandboxError(
      `Workspace root for "${validSlug}" escapes workspaces directory via symlink`,
      'SYMLINK_ESCAPE',
    );
  }
  return {
    slug: validSlug,
    workspaceRoot,
    realWorkspaceRoot,
  };
}

/**
 * Dual-check path sandbox:
 * 1) `path.resolve` containment check inside `{workspacesDir}/{slug}`
 * 2) `fs.realpath` (or deepest existing ancestor realpath for new files) containment check
 * 3) Hard read/write sensitive file blacklist enforcement on BOTH logical and real relative paths
 */
export function resolveSafeWorkspacePath(
  workspacesDir: string,
  slug: string,
  targetPath: string,
  options: ResolveWorkspacePathOptions = {},
): ResolvedWorkspacePath {
  const allowRoot = options.allowRoot ?? false;
  const checkSensitive = options.checkSensitive ?? true;

  if (typeof targetPath !== 'string' || targetPath.includes('\0')) {
    throw new WorkspaceSandboxError('Invalid path: null byte or non-string path', 'PATH_TRAVERSAL');
  }

  const { workspaceRoot, realWorkspaceRoot } = resolveWorkspaceRoot(workspacesDir, slug);
  const trimmed = targetPath.trim();
  const effectiveTarget = trimmed === '' ? '.' : trimmed;

  const resolvedPath = path.resolve(workspaceRoot, effectiveTarget);
  if (!isWithinDirectory(resolvedPath, workspaceRoot)) {
    throw new WorkspaceSandboxError(
      `Path "${targetPath}" escapes workspace "${slug}"`,
      'PATH_TRAVERSAL',
    );
  }

  const relativePath = path.relative(workspaceRoot, resolvedPath).replace(/\\/g, '/');
  if (!allowRoot && (relativePath === '' || relativePath === '.')) {
    throw new WorkspaceSandboxError(
      `Operation cannot target workspace root directly`,
      'PATH_TRAVERSAL',
    );
  }

  const realPath = resolveRealPathWithAncestor(resolvedPath);
  if (!isWithinDirectory(realPath, realWorkspaceRoot)) {
    throw new WorkspaceSandboxError(
      `Resolved real path for "${targetPath}" escapes workspace "${slug}" via symlink`,
      'SYMLINK_ESCAPE',
    );
  }

  const realRelativePath = path.relative(realWorkspaceRoot, realPath).replace(/\\/g, '/');
  if (
    checkSensitive &&
    (isSensitiveWorkspacePath(relativePath) || isSensitiveWorkspacePath(realRelativePath))
  ) {
    throw new WorkspaceSandboxError(
      `Access denied to sensitive workspace file "${relativePath}"`,
      'SENSITIVE_FILE',
    );
  }

  return {
    slug,
    workspaceRoot,
    realWorkspaceRoot,
    resolvedPath,
    realPath,
    relativePath: relativePath || '.',
  };
}

export interface WorkspaceLockLease {
  readonly slug: string;
  readonly mode: 'read' | 'write';
  setJobId(jobId: string): void;
  release(): void;
}

export interface AcquireLockOptions {
  timeoutMs?: number;
  holder?: string;
  jobId?: string;
  signal?: AbortSignal;
}

interface ActiveWriterState {
  token: symbol;
  holder?: string;
  jobId?: string;
  acquiredAt: number;
}

interface LockWaiter {
  kind: 'read' | 'write';
  holder?: string;
  jobId?: string;
  settled: boolean;
  timer: NodeJS.Timeout;
  grant: () => void;
  reject: (err: Error) => void;
}

interface WorkspaceLockState {
  activeReaders: number;
  activeWriter: ActiveWriterState | null;
  waiters: LockWaiter[];
}

export const DEFAULT_LOCK_TIMEOUT_MS = 5000;

/**
 * Async per-workspace Read-Write Lock manager:
 * - Concurrent readers
 * - Strictly exclusive writer with configurable wait timeout (default 5000ms)
 * - Fair FIFO queue to prevent writer starvation
 * - Fast-fail if an active background job holds the write lock (reporting active `job_id`)
 */
export class WorkspaceLockManager {
  private readonly locks = new Map<string, WorkspaceLockState>();
  private readonly defaultTimeoutMs: number;

  constructor(defaultTimeoutMs = DEFAULT_LOCK_TIMEOUT_MS) {
    this.defaultTimeoutMs = defaultTimeoutMs;
  }

  private normalizeKey(slug: string): string {
    return process.platform === 'win32' || process.platform === 'darwin'
      ? slug.toLowerCase()
      : slug;
  }

  private getState(slug: string): WorkspaceLockState {
    validateWorkspaceSlug(slug);
    const key = this.normalizeKey(slug);
    let state = this.locks.get(key);
    if (!state) {
      state = {
        activeReaders: 0,
        activeWriter: null,
        waiters: [],
      };
      this.locks.set(key, state);
    }
    return state;
  }

  private cleanupIfIdle(slug: string, state: WorkspaceLockState): void {
    if (state.activeReaders === 0 && !state.activeWriter && state.waiters.length === 0) {
      this.locks.delete(this.normalizeKey(slug));
    }
  }

  private dispatchWaiters(slug: string, state: WorkspaceLockState): void {
    while (state.waiters.length > 0) {
      const next = state.waiters[0]!;
      if (next.settled) {
        state.waiters.shift();
        continue;
      }

      if (next.kind === 'write') {
        if (state.activeWriter || state.activeReaders > 0) {
          break;
        }
        state.waiters.shift();
        next.settled = true;
        clearTimeout(next.timer);
        next.grant();
        break;
      } else {
        if (state.activeWriter) {
          break;
        }
        state.waiters.shift();
        next.settled = true;
        clearTimeout(next.timer);
        next.grant();
      }
    }

    this.cleanupIfIdle(slug, state);
  }

  getActiveWriteJobId(slug: string): string | null {
    validateWorkspaceSlug(slug);
    const state = this.locks.get(this.normalizeKey(slug));
    return state?.activeWriter?.jobId ?? null;
  }

  getLockInfo(slug: string): {
    activeReaders: number;
    hasActiveWriter: boolean;
    activeJobId: string | null;
    queuedCount: number;
  } {
    validateWorkspaceSlug(slug);
    const state = this.locks.get(this.normalizeKey(slug));
    if (!state) {
      return {
        activeReaders: 0,
        hasActiveWriter: false,
        activeJobId: null,
        queuedCount: 0,
      };
    }
    return {
      activeReaders: state.activeReaders,
      hasActiveWriter: state.activeWriter !== null,
      activeJobId: state.activeWriter?.jobId ?? null,
      queuedCount: state.waiters.length,
    };
  }

  async acquireRead(
    slug: string,
    options: AcquireLockOptions = {},
  ): Promise<WorkspaceLockLease> {
    const validSlug = validateWorkspaceSlug(slug);
    const state = this.getState(validSlug);
    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;

    const createReadLease = (): WorkspaceLockLease => {
      state.activeReaders += 1;
      let released = false;
      return {
        slug: validSlug,
        mode: 'read',
        setJobId: () => {
          // Read locks do not carry exclusive job ownership
        },
        release: () => {
          if (released) return;
          released = true;
          state.activeReaders = Math.max(0, state.activeReaders - 1);
          this.dispatchWaiters(validSlug, state);
        },
      };
    };

    if (options.signal?.aborted) {
      throw new WorkspaceLockError(
        `Read lock acquisition aborted for workspace "${validSlug}"`,
        'LOCK_TIMEOUT',
        state.activeWriter?.jobId,
      );
    }

    if (!state.activeWriter && state.waiters.length === 0) {
      return createReadLease();
    }

    return new Promise<WorkspaceLockLease>((resolve, reject) => {
      const cleanupSignal = () => {
        if (options.signal) {
          options.signal.removeEventListener('abort', onAbort);
        }
      };

      const onAbort = () => {
        if (waiter.settled) return;
        waiter.settled = true;
        clearTimeout(waiter.timer);
        const idx = state.waiters.indexOf(waiter);
        if (idx !== -1) state.waiters.splice(idx, 1);
        cleanupSignal();
        reject(
          new WorkspaceLockError(
            `Read lock acquisition aborted for workspace "${validSlug}"`,
            'LOCK_TIMEOUT',
            state.activeWriter?.jobId,
          ),
        );
        this.cleanupIfIdle(validSlug, state);
      };

      const waiter: LockWaiter = {
        kind: 'read',
        holder: options.holder,
        settled: false,
        timer: setTimeout(() => {
          if (waiter.settled) return;
          waiter.settled = true;
          cleanupSignal();
          const idx = state.waiters.indexOf(waiter);
          if (idx !== -1) state.waiters.splice(idx, 1);
          const activeJob = state.activeWriter?.jobId;
          const jobNote = activeJob ? ` (active job: ${activeJob})` : '';
          reject(
            new WorkspaceLockError(
              `Timed out after ${timeoutMs}ms waiting for read lock on workspace "${validSlug}"${jobNote}`,
              'LOCK_TIMEOUT',
              activeJob,
            ),
          );
          this.cleanupIfIdle(validSlug, state);
        }, timeoutMs),
        grant: () => {
          cleanupSignal();
          resolve(createReadLease());
        },
        reject: (err) => {
          cleanupSignal();
          reject(err);
        },
      };
      waiter.timer.unref?.();
      if (options.signal) {
        options.signal.addEventListener('abort', onAbort, { once: true });
      }
      state.waiters.push(waiter);
    });
  }

  async acquireWrite(
    slug: string,
    options: AcquireLockOptions = {},
  ): Promise<WorkspaceLockLease> {
    const validSlug = validateWorkspaceSlug(slug);
    const state = this.getState(validSlug);
    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;

    if (state.activeWriter?.jobId) {
      throw new WorkspaceLockError(
        `Workspace "${validSlug}" write lock is currently held by active background job "${state.activeWriter.jobId}"`,
        'ACTIVE_JOB_LOCK',
        state.activeWriter.jobId,
      );
    }

    const createWriteLease = (): WorkspaceLockLease => {
      const token = Symbol('write-lock');
      const writerState: ActiveWriterState = {
        token,
        holder: options.holder,
        jobId: options.jobId,
        acquiredAt: Date.now(),
      };
      state.activeWriter = writerState;
      let released = false;

      return {
        slug: validSlug,
        mode: 'write',
        setJobId: (jobId: string) => {
          if (!released && state.activeWriter?.token === token) {
            state.activeWriter.jobId = jobId;
          }
        },
        release: () => {
          if (released) return;
          released = true;
          if (state.activeWriter?.token === token) {
            state.activeWriter = null;
          }
          this.dispatchWaiters(validSlug, state);
        },
      };
    };

    if (options.signal?.aborted) {
      throw new WorkspaceLockError(
        `Write lock acquisition aborted for workspace "${validSlug}"`,
        'LOCK_TIMEOUT',
        state.activeWriter?.jobId,
      );
    }

    if (!state.activeWriter && state.activeReaders === 0) {
      return createWriteLease();
    }

    return new Promise<WorkspaceLockLease>((resolve, reject) => {
      const cleanupSignal = () => {
        if (options.signal) {
          options.signal.removeEventListener('abort', onAbort);
        }
      };

      const onAbort = () => {
        if (waiter.settled) return;
        waiter.settled = true;
        clearTimeout(waiter.timer);
        const idx = state.waiters.indexOf(waiter);
        if (idx !== -1) state.waiters.splice(idx, 1);
        cleanupSignal();
        reject(
          new WorkspaceLockError(
            `Write lock acquisition aborted for workspace "${validSlug}"`,
            'LOCK_TIMEOUT',
            state.activeWriter?.jobId,
          ),
        );
        this.cleanupIfIdle(validSlug, state);
      };

      const waiter: LockWaiter = {
        kind: 'write',
        holder: options.holder,
        jobId: options.jobId,
        settled: false,
        timer: setTimeout(() => {
          if (waiter.settled) return;
          waiter.settled = true;
          cleanupSignal();
          const idx = state.waiters.indexOf(waiter);
          if (idx !== -1) state.waiters.splice(idx, 1);
          const activeJob = state.activeWriter?.jobId;
          const jobNote = activeJob ? ` (active job: ${activeJob})` : '';
          reject(
            new WorkspaceLockError(
              `Timed out after ${timeoutMs}ms waiting for write lock on workspace "${validSlug}"${jobNote}`,
              'LOCK_TIMEOUT',
              activeJob,
            ),
          );
          this.cleanupIfIdle(validSlug, state);
        }, timeoutMs),
        grant: () => {
          cleanupSignal();
          resolve(createWriteLease());
        },
        reject: (err) => {
          cleanupSignal();
          reject(err);
        },
      };
      waiter.timer.unref?.();
      if (options.signal) {
        options.signal.addEventListener('abort', onAbort, { once: true });
      }
      state.waiters.push(waiter);
    });
  }

  async withReadLock<T>(
    slug: string,
    fn: (lease: WorkspaceLockLease) => Promise<T>,
    options: AcquireLockOptions = {},
  ): Promise<T> {
    const lease = await this.acquireRead(slug, options);
    try {
      return await fn(lease);
    } finally {
      lease.release();
    }
  }

  async withWriteLock<T>(
    slug: string,
    fn: (lease: WorkspaceLockLease) => Promise<T>,
    options: AcquireLockOptions = {},
  ): Promise<T> {
    const lease = await this.acquireWrite(slug, options);
    try {
      return await fn(lease);
    } finally {
      lease.release();
    }
  }
}

export const workspaceLockManager = new WorkspaceLockManager();
