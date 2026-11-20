import { spawn, type ChildProcess } from 'node:child_process';
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
  /(?:GH_TOKEN|GITHUB_TOKEN|CLOUDFLARE|OPENAI|CODEX_API|OAUTH|ADMIN_PASSWORD|NOTIFY_WEBHOOK|DOWNSTREAM_MCPS|SECRET|PASSWORD|PASSWD|PRIVATE_KEY|CREDENTIAL)/i;

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
  stdinData?: string;
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
}

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
          spawnArgs.length > 0 ? [options.command, ...spawnArgs].join(' ') : options.command;
        sudoArgs.push(shBin, '-c', shellCmd);
      } else {
        sudoArgs.push(options.command, ...spawnArgs);
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
  const handle = startSubprocess(options);
  return handle.done;
}
