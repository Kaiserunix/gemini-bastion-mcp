import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';

const IMMUTABLE_GATEWAY_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

function resolvePosixBinary(candidates: string[], fallback: string): string {
  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      // Ignore stat error and try next candidate
    }
  }
  return fallback;
}

const POSIX_ALLOWLIST = [
  'PATH',
  'HOME',
  'USER',
  'LOGNAME',
  'SHELL',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
  'TMPDIR',
  'TMP',
  'TEMP',
  'TERM',
  'XDG_CONFIG_HOME',
  'XDG_CACHE_HOME',
  'XDG_DATA_HOME',
  'MISE_DATA_DIR',
  'MISE_CACHE_DIR',
  'MISE_CONFIG_DIR',
  'UV_CACHE_DIR',
  'UV_PYTHON_INSTALL_DIR',
  'UV_TOOL_DIR',
  'UV_TOOL_BIN_DIR',
  'PIP_CACHE_DIR',
  'NPM_CONFIG_CACHE',
  'npm_config_cache',
  'NODE_ENV',
] as const;

const WINDOWS_ALLOWLIST = [
  'SystemRoot',
  'SYSTEMROOT',
  'COMSPEC',
  'ComSpec',
  'PATHEXT',
  'WINDIR',
  'windir',
  'USERPROFILE',
  'APPDATA',
  'LOCALAPPDATA',
  'ProgramFiles',
  'ProgramFiles(x86)',
  'CommonProgramFiles',
  'NUMBER_OF_PROCESSORS',
  'OS',
  'PROCESSOR_ARCHITECTURE',
] as const;

const FORBIDDEN_ENV_KEY_PATTERN =
  /(?:GH_TOKEN|GITHUB_TOKEN|CLOUDFLARE|OPENAI|CODEX_API|ANTHROPIC_API_KEY|GEMINI_API_KEY|OPS_MCP_AUTH_TOKEN|AGENT_RUNNER_AUTH_TOKEN|OAUTH|ADMIN_PASSWORD|NOTIFY_WEBHOOK|DOWNSTREAM_MCPS|API_KEY|AUTH_TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|CREDENTIAL)/i;

export const NON_INTERACTIVE_ENV_DEFAULTS: Record<string, string> = {
  CI: 'true',
  DEBIAN_FRONTEND: 'noninteractive',
  GIT_TERMINAL_PROMPT: '0',
  PAGER: 'cat',
  GIT_PAGER: 'cat',
  TERM: 'dumb',
  NO_COLOR: '1',
};

export interface BuildSandboxedEnvOptions {
  baseEnv?: Record<string, string | undefined>;
  extraEnv?: Record<string, string | undefined>;
  homeDir?: string;
}

/**
 * Builds a strict allowlisted environment for sandboxed workspace processes,
 * stripping all gateway secrets and enforcing non-interactive tool defaults.
 */
export function buildSandboxedEnv(options: BuildSandboxedEnvOptions = {}): Record<string, string> {
  const baseEnv = options.baseEnv ?? process.env;
  const result: Record<string, string> = {};

  const allowlist: readonly string[] =
    process.platform === 'win32'
      ? [...POSIX_ALLOWLIST, ...WINDOWS_ALLOWLIST]
      : POSIX_ALLOWLIST;

  for (const key of allowlist) {
    const val = baseEnv[key];
    if (val !== undefined && !FORBIDDEN_ENV_KEY_PATTERN.test(key)) {
      result[key] = val;
    }
  }

  if (options.homeDir) {
    result.HOME = options.homeDir;
    if (process.platform === 'win32') {
      result.USERPROFILE = options.homeDir;
    }
  }

  Object.assign(result, NON_INTERACTIVE_ENV_DEFAULTS);

  if (options.extraEnv) {
    for (const [key, val] of Object.entries(options.extraEnv)) {
      if (val === undefined) continue;
      if (FORBIDDEN_ENV_KEY_PATTERN.test(key)) {
        throw new Error(`Refusing to pass forbidden secret env variable "${key}" into sandbox`);
      }
      result[key] = val;
    }
  }

  return result;
}

export interface BwrapIsolationOptions {
  enabled: boolean;
  strict?: boolean;
  workspaceDir: string;
  workspacesRoot: string;
  chdir?: string;
  dataDir?: string;
  allowNetwork?: boolean;
  bwrapBinary?: string;
}

export interface SubprocessOptions {
  command: string;
  args?: string[];
  shell?: boolean;
  cwd: string;
  env?: Record<string, string>;
  timeoutMs?: number;
  maxOutputBytes?: number;
  signal?: AbortSignal;
  uid?: number;
  gid?: number;
  bwrapIsolation?: BwrapIsolationOptions;
  stdinData?: string;
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
}

export type ExecOptions = SubprocessOptions;

export interface ExecResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  aborted: boolean;
  truncated: boolean;
  durationMs: number;
}

export interface SubprocessHandle {
  readonly pid: number | undefined;
  readonly child: ChildProcess;
  readonly done: Promise<ExecResult>;
  kill(reason?: 'timeout' | 'abort' | 'manual'): Promise<void>;
  getOutputSnapshot(): { stdout: string; stderr: string; truncated: boolean };
}

async function runSudoKill(
  sudoUid: number,
  signalName: 'TERM' | 'KILL',
  targetPid: number,
): Promise<boolean> {
  const sudoBin = resolvePosixBinary(['/usr/bin/sudo'], 'sudo');
  const killBin = resolvePosixBinary(['/bin/kill', '/usr/bin/kill'], 'kill');
  const sudoEnv = { PATH: IMMUTABLE_GATEWAY_PATH };

  return new Promise<boolean>((resolve) => {
    const killer = spawn(
      sudoBin,
      ['-n', '-u', `#${sudoUid}`, killBin, `-${signalName}`, '--', `-${targetPid}`],
      {
        env: sudoEnv,
        stdio: 'ignore',
        windowsHide: true,
      },
    );
    killer.on('error', () => resolve(false));
    killer.on('exit', (code) => {
      if (code === 0) {
        resolve(true);
        return;
      }
      // Fallback: target direct PID if not a process group leader
      const fallback = spawn(
        sudoBin,
        ['-n', '-u', `#${sudoUid}`, killBin, `-${signalName}`, String(targetPid)],
        {
          env: sudoEnv,
          stdio: 'ignore',
          windowsHide: true,
        },
      );
      fallback.on('error', () => resolve(false));
      fallback.on('exit', (c2) => resolve(c2 === 0));
    });
  });
}

export interface KillProcessTreeOptions {
  sudoUid?: number;
}

/**
 * Terminates a process and its entire process group cross-platform.
 * On POSIX uses negative-PID SIGTERM followed by SIGKILL after graceMs,
 * with `sudo -n -u #<sudoUid> kill` fallback on EPERM for sandboxed children.
 * On Windows falls back to `taskkill /PID <pid> /T /F`.
 */
export async function killProcessTree(
  pid: number | undefined,
  graceMs = 1500,
  options: KillProcessTreeOptions = {},
): Promise<void> {
  if (!pid || pid <= 0) return;

  if (process.platform === 'win32') {
    await new Promise<void>((resolve) => {
      const killer = spawn('taskkill', ['/PID', String(pid), '/T', '/F'], {
        stdio: 'ignore',
        windowsHide: true,
      });
      killer.on('error', () => {
        try {
          process.kill(pid, 'SIGKILL');
        } catch {
          // Process already exited
        }
        resolve();
      });
      killer.on('exit', () => resolve());
    });
    return;
  }

  const { sudoUid } = options;

  const sendGroupSignal = async (sig: 'SIGTERM' | 'SIGKILL', signalName: 'TERM' | 'KILL'): Promise<boolean> => {
    try {
      process.kill(-pid, sig);
      return true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code;
      if (code === 'EPERM' && sudoUid !== undefined) {
        if (await runSudoKill(sudoUid, signalName, pid)) {
          return true;
        }
      }
      try {
        process.kill(pid, sig);
        return true;
      } catch (err2) {
        const code2 = (err2 as NodeJS.ErrnoException)?.code;
        if (code2 === 'EPERM' && sudoUid !== undefined) {
          return runSudoKill(sudoUid, signalName, pid);
        }
        return false;
      }
    }
  };

  if (!(await sendGroupSignal('SIGTERM', 'TERM'))) {
    return;
  }

  await new Promise<void>((resolve) => {
    const timer = setTimeout(() => {
      void sendGroupSignal('SIGKILL', 'KILL').finally(() => resolve());
    }, graceMs);
    timer.unref?.();
  });
}

const bwrapProbeSyncCache = new Map<string, boolean>();
const bwrapProbePromiseCache = new Map<string, Promise<boolean>>();
let warnedBwrapFallback = false;

function normalizeMountPath(target: string): string {
  const normalized = target.replace(/\\/g, '/').replace(/\/+$/, '');
  return normalized.length === 0 ? '/' : normalized;
}

function isSameOrParentMount(candidate: string, target: string): boolean {
  const a = normalizeMountPath(candidate);
  const b = normalizeMountPath(target);
  if (a === b) return true;
  if (a === '/') return true;
  return b.startsWith(`${a}/`);
}

/**
 * Pure helper building argv for bubblewrap (`bwrap`) per-workspace filesystem and network isolation.
 * Safe to unit-test on any OS.
 */
export function buildBwrapArgs(
  options: BwrapIsolationOptions,
  innerCommandArgs: string[],
): string[] {
  const workspacesRoot = normalizeMountPath(options.workspacesRoot);
  const workspaceDir = normalizeMountPath(options.workspaceDir);
  const dataDir = options.dataDir ? normalizeMountPath(options.dataDir) : undefined;

  const args: string[] = [
    '--die-with-parent',
    '--ro-bind',
    '/',
    '/',
    '--dev',
    '/dev',
    '--proc',
    '/proc',
    '--tmpfs',
    '/tmp',
    '--tmpfs',
    workspacesRoot,
  ];

  if (
    dataDir &&
    dataDir !== '/tmp' &&
    !dataDir.startsWith('/tmp/') &&
    !isSameOrParentMount(dataDir, workspaceDir)
  ) {
    args.push('--tmpfs', dataDir);
  }

  const rawChdir = options.chdir ? normalizeMountPath(options.chdir) : undefined;
  const chdir = rawChdir && isSameOrParentMount(workspaceDir, rawChdir) ? rawChdir : workspaceDir;

  args.push('--bind', workspaceDir, workspaceDir);
  args.push('--chdir', chdir);

  if (!options.allowNetwork) {
    args.push('--unshare-net');
  }

  args.push('--', ...innerCommandArgs);
  return args;
}

function buildBwrapProbeCommand(
  bwrapBinary?: string,
  uid?: number,
  gid?: number,
): { cmd: string; args: string[]; env: Record<string, string>; cacheKey: string } {
  const bwrapBin = bwrapBinary ?? resolvePosixBinary(['/usr/bin/bwrap', '/bin/bwrap'], 'bwrap');
  const trueBin = resolvePosixBinary(['/bin/true', '/usr/bin/true'], '/bin/true');
  const probeArgs = ['--ro-bind', '/', '/', '--tmpfs', '/tmp', '--unshare-net', '--', trueBin];
  const cacheKey = `${bwrapBin}:${uid ?? ''}:${gid ?? ''}`;

  const currentUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  const currentGid = typeof process.getgid === 'function' ? process.getgid() : undefined;
  const needsPrivilegeSwitch =
    uid !== undefined &&
    currentUid !== undefined &&
    currentUid !== 0 &&
    (uid !== currentUid || (gid !== undefined && currentGid !== undefined && gid !== currentGid));

  if (needsPrivilegeSwitch) {
    const sudoBin = resolvePosixBinary(['/usr/bin/sudo'], 'sudo');
    const sudoArgs = ['-n', '-H', '-u', `#${uid}`];
    if (gid !== undefined) {
      sudoArgs.push('-g', `#${gid}`);
    }
    sudoArgs.push('--', bwrapBin, ...probeArgs);
    return { cmd: sudoBin, args: sudoArgs, env: { PATH: IMMUTABLE_GATEWAY_PATH }, cacheKey };
  }

  return { cmd: bwrapBin, args: probeArgs, env: { PATH: IMMUTABLE_GATEWAY_PATH }, cacheKey };
}

function probeBwrapSupportSync(bwrapBinary?: string, uid?: number, gid?: number): boolean {
  if (process.platform !== 'linux') return false;
  const { cmd, args, env, cacheKey } = buildBwrapProbeCommand(bwrapBinary, uid, gid);
  const cached = bwrapProbeSyncCache.get(cacheKey);
  if (cached !== undefined) return cached;

  try {
    const res = spawnSync(cmd, args, {
      env,
      stdio: 'ignore',
      timeout: 3000,
      windowsHide: true,
    });
    const ok = res.status === 0 && !res.error;
    bwrapProbeSyncCache.set(cacheKey, ok);
    return ok;
  } catch {
    bwrapProbeSyncCache.set(cacheKey, false);
    return false;
  }
}

/**
 * Probes whether bubblewrap (`bwrap`) can create user/mount/network namespaces on this Linux host.
 * Result is cached per binary + uid + gid; always returns `false` on non-Linux platforms.
 */
export async function probeBwrapSupport(
  bwrapBinary?: string,
  uid?: number,
  gid?: number,
): Promise<boolean> {
  if (process.platform !== 'linux') return false;
  const { cmd, args, env, cacheKey } = buildBwrapProbeCommand(bwrapBinary, uid, gid);

  const syncCached = bwrapProbeSyncCache.get(cacheKey);
  if (syncCached !== undefined) return syncCached;

  const existing = bwrapProbePromiseCache.get(cacheKey);
  if (existing) return existing;

  const probePromise = new Promise<boolean>((resolve) => {
    try {
      const child = spawn(cmd, args, {
        env,
        stdio: 'ignore',
        windowsHide: true,
      });
      const timer = setTimeout(() => {
        try {
          child.kill('SIGKILL');
        } catch {
          // ignore
        }
        bwrapProbeSyncCache.set(cacheKey, false);
        resolve(false);
      }, 3000);
      timer.unref?.();

      child.on('error', () => {
        clearTimeout(timer);
        bwrapProbeSyncCache.set(cacheKey, false);
        resolve(false);
      });
      child.on('exit', (code) => {
        clearTimeout(timer);
        const ok = code === 0;
        bwrapProbeSyncCache.set(cacheKey, ok);
        resolve(ok);
      });
    } catch {
      bwrapProbeSyncCache.set(cacheKey, false);
      resolve(false);
    }
  });

  bwrapProbePromiseCache.set(cacheKey, probePromise);
  return probePromise;
}

/**
 * Clears the cached bwrap namespace probe results (intended for tests).
 */
export function resetBwrapProbeCache(): void {
  bwrapProbeSyncCache.clear();
  bwrapProbePromiseCache.clear();
  warnedBwrapFallback = false;
}

/**
 * Starts a non-interactive subprocess with output capping, AbortSignal, and optional timeout.
 * Suitable for both bounded command execution and background-promoted shell jobs.
 */
export function startSubprocess(options: SubprocessOptions): SubprocessHandle {
  const startedAt = Date.now();
  const maxOutputBytes = options.maxOutputBytes ?? 1024 * 1024;
  const env = options.env ?? buildSandboxedEnv();

  let spawnCommand = options.command;
  let spawnArgs = options.args ?? [];
  let useShell = options.shell ?? false;
  let usedSudo = false;

  if (options.bwrapIsolation?.enabled) {
    const bwrap = options.bwrapIsolation;
    const bwrapSupported =
      process.platform === 'linux' &&
      probeBwrapSupportSync(bwrap.bwrapBinary, options.uid, options.gid);

    if (bwrapSupported) {
      const bwrapBin = bwrap.bwrapBinary ?? resolvePosixBinary(['/usr/bin/bwrap', '/bin/bwrap'], 'bwrap');
      const shBin = resolvePosixBinary(['/bin/sh', '/usr/bin/sh'], '/bin/sh');
      const innerCommandArgs = useShell
        ? [shBin, '-c', spawnArgs.length > 0 ? [spawnCommand, ...spawnArgs].join(' ') : spawnCommand]
        : [spawnCommand, ...spawnArgs];

      let effectiveDataDir: string | undefined;
      if (bwrap.dataDir) {
        try {
          if (fs.existsSync(bwrap.dataDir)) {
            effectiveDataDir = bwrap.dataDir;
          }
        } catch {
          effectiveDataDir = undefined;
        }
      }

      spawnArgs = buildBwrapArgs(
        { ...bwrap, dataDir: effectiveDataDir, chdir: bwrap.chdir ?? options.cwd },
        innerCommandArgs,
      );
      spawnCommand = bwrapBin;
      useShell = false;
    } else if (bwrap.strict) {
      throw new Error(
        'Sandbox bwrap isolation is required (SANDBOX_STRICT_ISOLATION=true) but bubblewrap namespace creation is unavailable',
      );
    } else if (process.platform === 'linux' && !warnedBwrapFallback) {
      warnedBwrapFallback = true;
      console.warn('[exec] bwrap namespace isolation unavailable; falling back to UID-dropped execution');
    }
  }

  const spawnOpts: Parameters<typeof spawn>[2] = {
    cwd: options.cwd,
    env,
    shell: useShell,
    stdio: [options.stdinData !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
    windowsHide: true,
  };

  if (process.platform !== 'win32' && options.uid !== undefined) {
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
    const currentGid = typeof process.getgid === 'function' ? process.getgid() : undefined;
    const needsUidSwitch = currentUid !== undefined && options.uid !== currentUid;
    const needsGidSwitch =
      options.gid !== undefined && currentGid !== undefined && options.gid !== currentGid;

    if (currentUid === 0) {
      spawnOpts.uid = options.uid;
      if (options.gid !== undefined) spawnOpts.gid = options.gid;
    } else if (needsUidSwitch || needsGidSwitch) {
      // Non-root gateway cannot setuid(worker) directly; delegate privilege drop via sudo -H + env.
      // Omit -i and gateway's own HOME/USER/LOGNAME so sudo -H keeps the target UID's home/identity.
      // Resolve absolute system binaries and keep gateway's PATH immutable (no /opt/mise/shims).
      usedSudo = true;
      const sudoBin = resolvePosixBinary(['/usr/bin/sudo'], 'sudo');
      const envBin = resolvePosixBinary(['/usr/bin/env'], 'env');
      const shBin = resolvePosixBinary(['/bin/sh', '/usr/bin/sh'], '/bin/sh');

      const miseShimsDir = env.MISE_DATA_DIR
        ? `${env.MISE_DATA_DIR.replace(/\/+$/, '')}/shims`
        : '/opt/mise/shims';
      const baseWorkerPath = env.PATH ?? IMMUTABLE_GATEWAY_PATH;
      const workerPathParts = baseWorkerPath.split(':').filter(Boolean);
      const workerPath = workerPathParts.includes(miseShimsDir)
        ? baseWorkerPath
        : `${miseShimsDir}:${baseWorkerPath}`;

      const sudoArgs: string[] = ['-n', '-H', '-u', `#${options.uid}`];
      if (options.gid !== undefined) {
        sudoArgs.push('-g', `#${options.gid}`);
      }
      sudoArgs.push('--', envBin, `PATH=${workerPath}`);
      for (const [k, v] of Object.entries(env)) {
        if (k === 'PATH') continue;
        if (
          (k === 'HOME' && v === process.env.HOME) ||
          (k === 'USER' && v === process.env.USER) ||
          (k === 'LOGNAME' && v === process.env.LOGNAME)
        ) {
          continue;
        }
        sudoArgs.push(`${k}=${v}`);
      }
      if (useShell) {
        const shellCmd =
          spawnArgs.length > 0 ? [spawnCommand, ...spawnArgs].join(' ') : spawnCommand;
        sudoArgs.push(shBin, '-c', shellCmd);
      } else {
        sudoArgs.push(spawnCommand, ...spawnArgs);
      }

      spawnCommand = sudoBin;
      spawnArgs = sudoArgs;
      useShell = false;
      spawnOpts.shell = false;
      spawnOpts.env = {
        PATH: IMMUTABLE_GATEWAY_PATH,
        ...(env.LANG ? { LANG: env.LANG } : {}),
      };
    }
  }

  const child = spawn(spawnCommand, spawnArgs, spawnOpts);

  let totalBytes = 0;
  let truncated = false;
  const stdoutChunks: Buffer[] = [];
  const stderrChunks: Buffer[] = [];
  let timedOut = false;
  let aborted = false;
  let settled = false;
  let killPromise: Promise<void> | null = null;

  const appendChunk = (target: Buffer[], chunk: Buffer, cb?: (text: string) => void) => {
    if (totalBytes >= maxOutputBytes) {
      truncated = true;
      return;
    }
    const remaining = maxOutputBytes - totalBytes;
    const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
    if (chunk.length > remaining) {
      truncated = true;
    }
    totalBytes += slice.length;
    target.push(slice);
    if (cb && slice.length > 0) {
      cb(slice.toString('utf8'));
    }
  };

  child.stdout?.on('data', (chunk: Buffer) => {
    appendChunk(stdoutChunks, chunk, options.onStdout);
  });

  child.stderr?.on('data', (chunk: Buffer) => {
    appendChunk(stderrChunks, chunk, options.onStderr);
  });

  if (options.stdinData !== undefined && child.stdin) {
    child.stdin.write(options.stdinData);
    child.stdin.end();
  }

  const kill = (reason: 'timeout' | 'abort' | 'manual' = 'manual'): Promise<void> => {
    if (reason === 'timeout') timedOut = true;
    if (reason === 'abort') aborted = true;
    if (settled) return Promise.resolve();
    if (!killPromise) {
      killPromise = killProcessTree(child.pid, 1500, usedSudo ? { sudoUid: options.uid } : undefined);
    }
    return killPromise;
  };

  let timeoutTimer: NodeJS.Timeout | undefined;
  if (options.timeoutMs !== undefined && options.timeoutMs > 0) {
    timeoutTimer = setTimeout(() => {
      void kill('timeout');
    }, options.timeoutMs);
    timeoutTimer.unref?.();
  }

  const onAbort = () => {
    void kill('abort');
  };

  if (options.signal) {
    if (options.signal.aborted) {
      void kill('abort');
    } else {
      options.signal.addEventListener('abort', onAbort, { once: true });
    }
  }

  const done = new Promise<ExecResult>((resolve) => {
    const finalize = (exitCode: number | null, signal: NodeJS.Signals | null, errMsg?: string) => {
      if (settled) return;
      settled = true;
      if (timeoutTimer) clearTimeout(timeoutTimer);
      if (options.signal) {
        options.signal.removeEventListener('abort', onAbort);
      }

      const stdout = Buffer.concat(stdoutChunks).toString('utf8');
      let stderr = Buffer.concat(stderrChunks).toString('utf8');
      if (errMsg) {
        stderr = stderr ? `${stderr}\n${errMsg}` : errMsg;
      }

      resolve({
        exitCode,
        signal,
        stdout,
        stderr,
        timedOut,
        aborted,
        truncated,
        durationMs: Date.now() - startedAt,
      });
    };

    child.on('error', (err) => {
      finalize(null, null, err.message);
    });

    child.on('close', (code, sig) => {
      finalize(code, sig);
    });
  });

  return {
    pid: child.pid,
    child,
    done,
    kill,
    getOutputSnapshot: () => ({
      stdout: Buffer.concat(stdoutChunks).toString('utf8'),
      stderr: Buffer.concat(stderrChunks).toString('utf8'),
      truncated,
    }),
  };
}

/**
 * Runs a subprocess to completion with timeout, maxOutputBytes, AbortSignal,
 * and automatic process-group cleanup.
 */
export async function runSubprocess(options: SubprocessOptions): Promise<ExecResult> {
  if (options.bwrapIsolation?.enabled && process.platform === 'linux') {
    await probeBwrapSupport(options.bwrapIsolation.bwrapBinary, options.uid, options.gid);
  }
  const handle = startSubprocess(options);
  return handle.done;
}
