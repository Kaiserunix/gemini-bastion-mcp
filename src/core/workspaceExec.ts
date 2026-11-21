import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { JobRepository } from '../db/repositories/jobRepo.js';
import type { GatewayConfig, JobRunnerType, JobStatus, ScrubberLike } from '../types.js';
import {
  buildSandboxedEnv,
  probeBwrapSupport,
  startSubprocess,
  type ExecResult,
} from '../utils/exec.js';
import { createSecretScrubber } from '../utils/secretScrubber.js';
import { notifyJobFinished, type WebhookNotifyOptions } from './webhookNotifier.js';
import {
  resolveSafeWorkspacePath,
  workspaceLockManager,
  type WorkspaceLockLease,
  type WorkspaceLockManager,
} from './workspaceLock.js';

export interface ActiveJobHandle {
  jobId: string;
  workspaceSlug: string;
  runnerType: JobRunnerType;
  cancel: () => Promise<void>;
  done?: Promise<void>;
}

const activeJobs = new Map<string, ActiveJobHandle>();

export function registerActiveJob(handle: ActiveJobHandle): void {
  activeJobs.set(handle.jobId, handle);
}

export function unregisterActiveJob(jobId: string): void {
  activeJobs.delete(jobId);
}

export function getActiveJob(jobId: string): ActiveJobHandle | undefined {
  return activeJobs.get(jobId);
}

export function listActiveJobIds(): string[] {
  return Array.from(activeJobs.keys());
}

/**
 * Cancels a running background job (`shell_task`, `codex_readonly`, or `codex_write`)
 * via its AbortController and process-group termination.
 */
export async function cancelActiveJob(
  jobId: string,
  jobRepo?: JobRepository,
): Promise<{ cancelled: boolean; jobId: string; reason?: string }> {
  const handle = activeJobs.get(jobId);
  if (!handle) {
    const existing = jobRepo?.getJob(jobId);
    if (!existing) {
      return { cancelled: false, jobId, reason: 'Job not found' };
    }
    if (existing.status === 'running' || existing.status === 'queued') {
      jobRepo?.updateJob(jobId, {
        status: 'cancelled',
        error_message: 'Cancelled (no active in-memory handle)',
      });
      return { cancelled: true, jobId, reason: 'Marked stale job cancelled in database' };
    }
    return {
      cancelled: false,
      jobId,
      reason: `Job is already in terminal state "${existing.status}"`,
    };
  }

  await handle.cancel();
  if (handle.done) {
    await Promise.race([
      handle.done.catch(() => undefined),
      new Promise<void>((resolve) => {
        const t = setTimeout(resolve, 4000);
        t.unref?.();
      }),
    ]);
  }
  return { cancelled: true, jobId };
}

export interface WorkspaceExecOptions {
  config: Pick<
    GatewayConfig,
    | 'workspacesDir'
    | 'workspaceExecDefaultWaitMs'
    | 'workspaceExecMaxWaitMs'
    | 'sandboxUid'
    | 'sandboxGid'
    | 'notifyWebhookUrl'
  > &
    Partial<GatewayConfig>;
  slug: string;
  command: string;
  args?: string[];
  shell?: boolean;
  cwd?: string;
  readonly?: boolean;
  allowNetwork?: boolean;
  waitMs?: number;
  maxDurationSec?: number;
  lockTimeoutMs?: number;
  extraEnv?: Record<string, string | undefined>;
  jobRepo: JobRepository;
  lockManager?: WorkspaceLockManager;
  scrubber?: ScrubberLike;
  webhookOptions?: WebhookNotifyOptions;
}

export interface WorkspaceExecSyncResult {
  mode: 'sync';
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  aborted: boolean;
  truncated: boolean;
  durationMs: number;
}

export interface WorkspaceExecAsyncPromotedResult {
  mode: 'async_promoted';
  jobId: string;
  partialOutput: {
    stdout: string;
    stderr: string;
    truncated: boolean;
  };
}

export type WorkspaceExecResult = WorkspaceExecSyncResult | WorkspaceExecAsyncPromotedResult;

const MIN_WAIT_MS = 500;
const MAX_WAIT_MS = 15000;
const DEFAULT_WAIT_MS = 12000;
const DEFAULT_MAX_DURATION_SEC = 600;

function clampWaitMs(waitMs: number | undefined, defaultWait: number, maxWait: number): number {
  const effectiveMax = Math.min(MAX_WAIT_MS, Math.max(MIN_WAIT_MS, maxWait));
  const raw = waitMs ?? defaultWait ?? DEFAULT_WAIT_MS;
  return Math.max(MIN_WAIT_MS, Math.min(effectiveMax, Math.floor(raw)));
}

function formatShellFinalReport(res: ExecResult, scrubber: ScrubberLike): string {
  const parts: string[] = [
    `exitCode=${res.exitCode ?? 'null'} durationMs=${res.durationMs}`,
  ];
  if (res.stdout.trim()) {
    parts.push(`--- stdout ---\n${res.stdout.trim().slice(-8000)}`);
  }
  if (res.stderr.trim()) {
    parts.push(`--- stderr ---\n${res.stderr.trim().slice(-4000)}`);
  }
  return scrubber.scrub(parts.join('\n'));
}

function resolveFinalShellStatus(res: ExecResult, cancelledFlag: boolean): JobStatus {
  if (res.aborted || cancelledFlag) return 'cancelled';
  if (res.timedOut) return 'timed_out';
  if (res.exitCode === 0) return 'completed';
  return 'failed';
}

/**
 * Executes a shell command inside `{workspacesDir}/{slug}` with a strict sandboxed environment,
 * workspace RW locking, and automatic promotion to a background SQLite job if it exceeds `waitMs`.
 */
export async function workspaceExec(
  options: WorkspaceExecOptions,
): Promise<WorkspaceExecResult> {
  const lockMgr = options.lockManager ?? workspaceLockManager;
  const scrubber = options.scrubber ?? createSecretScrubber(options.config);
  const resolvedCwd = resolveSafeWorkspacePath(
    options.config.workspacesDir,
    options.slug,
    options.cwd ?? '.',
    { allowRoot: true, checkSensitive: true },
  );

  if (!fs.existsSync(resolvedCwd.realPath) || !fs.statSync(resolvedCwd.realPath).isDirectory()) {
    throw new Error(
      `Working directory does not exist in workspace "${options.slug}": "${resolvedCwd.relativePath}"`,
    );
  }

  const waitMs = clampWaitMs(
    options.waitMs,
    options.config.workspaceExecDefaultWaitMs ?? DEFAULT_WAIT_MS,
    options.config.workspaceExecMaxWaitMs ?? MAX_WAIT_MS,
  );
  const maxDurationMs = Math.max(
    waitMs,
    (options.maxDurationSec ?? DEFAULT_MAX_DURATION_SEC) * 1000,
  );

  const lease: WorkspaceLockLease = options.readonly
    ? await lockMgr.acquireRead(options.slug, {
        timeoutMs: options.lockTimeoutMs,
        holder: 'workspace_exec:readonly',
      })
    : await lockMgr.acquireWrite(options.slug, {
        timeoutMs: options.lockTimeoutMs,
        holder: 'workspace_exec',
      });

  const env = buildSandboxedEnv({
    extraEnv: options.extraEnv,
  });

  const abortController = new AbortController();
  let promotedJobId: string | null = null;
  let cancelledFlag = false;

  const stdoutBuffer: string[] = [];
  const stderrBuffer: string[] = [];
  let flushTimer: NodeJS.Timeout | undefined;

  const flushBufferedOutput = () => {
    if (!promotedJobId) return;
    if (stdoutBuffer.length > 0) {
      const msg = scrubber.scrub(stdoutBuffer.splice(0).join(''));
      if (msg) {
        options.jobRepo.appendEvent(
          promotedJobId,
          { ts: Date.now(), type: 'stdout', message: msg },
          50,
        );
      }
    }
    if (stderrBuffer.length > 0) {
      const msg = scrubber.scrub(stderrBuffer.splice(0).join(''));
      if (msg) {
        options.jobRepo.appendEvent(
          promotedJobId,
          { ts: Date.now(), type: 'stderr', message: msg },
          50,
        );
      }
    }
  };

  const scheduleFlush = () => {
    if (flushTimer || !promotedJobId) return;
    flushTimer = setTimeout(() => {
      flushTimer = undefined;
      flushBufferedOutput();
    }, 100);
    flushTimer.unref?.();
  };

  const bwrapEnabled = Boolean(options.config.sandboxBwrapIsolation);
  let realWorkspacesRoot = path.resolve(options.config.workspacesDir);
  try {
    realWorkspacesRoot = fs.realpathSync(realWorkspacesRoot);
  } catch {
    // Keep path.resolve fallback if directory doesn't exist yet
  }

  if (bwrapEnabled && process.platform === 'linux') {
    await probeBwrapSupport(undefined, options.config.sandboxUid, options.config.sandboxGid);
  }

  let handle;
  try {
    handle = startSubprocess({
      command: options.command,
      args: options.args,
      shell: options.shell ?? (options.args === undefined),
      cwd: resolvedCwd.realPath,
      env,
      timeoutMs: maxDurationMs,
      signal: abortController.signal,
      uid: options.config.sandboxUid,
      gid: options.config.sandboxGid,
      bwrapIsolation: {
        enabled: bwrapEnabled,
        strict: Boolean(options.config.sandboxStrictIsolation),
        workspaceDir: resolvedCwd.realWorkspaceRoot,
        workspacesRoot: realWorkspacesRoot,
        dataDir: options.config.dataDir,
        allowNetwork: Boolean(options.allowNetwork),
      },
      onStdout: (chunk) => {
        if (promotedJobId) {
          stdoutBuffer.push(chunk);
          scheduleFlush();
        }
      },
      onStderr: (chunk) => {
        if (promotedJobId) {
          stderrBuffer.push(chunk);
          scheduleFlush();
        }
      },
    });
  } catch (err) {
    lease.release();
    throw err;
  }

  let waitTimer: NodeJS.Timeout | undefined;
  const raceOutcome = await Promise.race<
    { kind: 'finished'; result: ExecResult } | { kind: 'wait_elapsed' }
  >([
    handle.done.then((result) => ({ kind: 'finished' as const, result })),
    new Promise<{ kind: 'wait_elapsed' }>((resolve) => {
      waitTimer = setTimeout(() => resolve({ kind: 'wait_elapsed' }), waitMs);
      waitTimer.unref?.();
    }),
  ]);

  if (waitTimer) {
    clearTimeout(waitTimer);
  }

  if (raceOutcome.kind === 'finished') {
    lease.release();
    const res = raceOutcome.result;
    return {
      mode: 'sync',
      exitCode: res.exitCode,
      signal: res.signal,
      stdout: scrubber.scrub(res.stdout),
      stderr: scrubber.scrub(res.stderr),
      timedOut: res.timedOut,
      aborted: res.aborted,
      truncated: res.truncated,
      durationMs: res.durationMs,
    };
  }

  // Auto-promote live process to background SQLite job
  const jobId = `job_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
  promotedJobId = jobId;
  lease.setJobId(jobId);

  const cmdSummary = options.args?.length
    ? `${options.command} ${options.args.join(' ')}`
    : options.command;

  const snapshot = handle.getOutputSnapshot();
  const scrubbedStdout = scrubber.scrub(snapshot.stdout);
  const scrubbedStderr = scrubber.scrub(snapshot.stderr);

  try {
    options.jobRepo.createJob({
      job_id: jobId,
      workspace_slug: options.slug,
      runner_type: 'shell_task',
      status: 'running',
      command_or_objective: scrubber.scrub(cmdSummary),
    });

    options.jobRepo.appendEvent(
      jobId,
      {
        ts: Date.now(),
        type: 'status',
        message: `Promoted to background shell_task after ${waitMs}ms`,
      },
      50,
    );

    if (scrubbedStdout) {
      options.jobRepo.appendEvent(
        jobId,
        { ts: Date.now(), type: 'stdout', message: scrubbedStdout.slice(-4000) },
        50,
      );
    }
    if (scrubbedStderr) {
      options.jobRepo.appendEvent(
        jobId,
        { ts: Date.now(), type: 'stderr', message: scrubbedStderr.slice(-4000) },
        50,
      );
    }
  } catch (err) {
    promotedJobId = null;
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = undefined;
    }
    unregisterActiveJob(jobId);
    await handle.kill('abort').catch(() => undefined);
    await Promise.race([
      handle.done.catch(() => undefined),
      new Promise<void>((r) => {
        const t = setTimeout(r, 2000);
        t.unref?.();
      }),
    ]);
    lease.release();
    throw err;
  }

  const backgroundDone = handle.done.then(async (res) => {
    try {
      if (flushTimer) {
        clearTimeout(flushTimer);
        flushTimer = undefined;
      }
      flushBufferedOutput();

      const status = resolveFinalShellStatus(res, cancelledFlag);
      const finalReport = formatShellFinalReport(res, scrubber);
      const errorMsg =
        status === 'completed'
          ? null
          : scrubber.scrub(
              status === 'cancelled'
                ? 'Job was cancelled'
                : status === 'timed_out'
                  ? `Command timed out after ${maxDurationMs}ms`
                  : res.stderr.trim() || `Command exited with code ${res.exitCode ?? 'null'}`,
            );

      const updated = options.jobRepo.updateJob(jobId, {
        status,
        final_report_text: finalReport,
        error_message: errorMsg,
      });

      options.jobRepo.appendEvent(
        jobId,
        {
          ts: Date.now(),
          type: 'status',
          message: `Job finished with status "${status}" (exitCode=${res.exitCode ?? 'null'})`,
        },
        50,
      );

      if (updated) {
        await notifyJobFinished(options.config, updated, {
          scrubber,
          ...options.webhookOptions,
        });
      }
    } finally {
      unregisterActiveJob(jobId);
      lease.release();
    }
  });

  registerActiveJob({
    jobId,
    workspaceSlug: options.slug,
    runnerType: 'shell_task',
    cancel: async () => {
      cancelledFlag = true;
      abortController.abort();
      await handle.kill('abort');
    },
    done: backgroundDone,
  });

  return {
    mode: 'async_promoted',
    jobId,
    partialOutput: {
      stdout: scrubbedStdout,
      stderr: scrubbedStderr,
      truncated: snapshot.truncated,
    },
  };
}
