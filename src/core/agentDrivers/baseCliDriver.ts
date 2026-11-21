import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { JobRepository } from '../../db/repositories/jobRepo.js';
import type { WorkspaceRepository } from '../../db/repositories/workspaceRepo.js';
import type {
  AgentDriverName,
  AgentRunOptions,
  AgentRunResult,
  GatewayConfig,
  JobEvent,
  JobStatus,
  ScrubberLike,
  TokenUsage,
} from '../../types.js';
import {
  probeBwrapSupport,
  startSubprocess,
  type ExecResult,
  type SubprocessHandle,
  type SubprocessOptions,
} from '../../utils/exec.js';
import { createSecretScrubber } from '../../utils/secretScrubber.js';
import { createCheckpoint, isGitRepository } from '../gitSnapshot.js';
import { notifyJobFinished, type WebhookNotifyOptions } from '../webhookNotifier.js';
import { registerActiveJob, unregisterActiveJob } from '../workspaceExec.js';
import {
  workspaceLockManager,
  type WorkspaceLockLease,
  type WorkspaceLockManager,
} from '../workspaceLock.js';

export type SubprocessStarter = (options: SubprocessOptions) => SubprocessHandle;

/**
 * Validates CLI flag argument values (`resumeThreadId`, `model`, etc.) to prevent flag injection.
 */
export function assertSafeCliFlagValue(name: string, val: string): string {
  if (
    typeof val !== 'string' ||
    val.length === 0 ||
    val.includes('\0') ||
    val.includes('\r') ||
    val.includes('\n') ||
    val.startsWith('-')
  ) {
    throw new Error(
      `Invalid ${name}: must be a non-empty single-line value not starting with "-"`,
    );
  }
  return val;
}

export interface CliDriverDeps {
  config: Pick<
    GatewayConfig,
    | 'workspacesDir'
    | 'dataDir'
    | 'codexMaxDurationSec'
    | 'codexTokenBudget'
    | 'sandboxUid'
    | 'sandboxGid'
    | 'sandboxBwrapIsolation'
    | 'sandboxStrictIsolation'
    | 'notifyWebhookUrl'
  > &
    Partial<GatewayConfig>;
  jobRepo?: JobRepository;
  workspaceRepo?: WorkspaceRepository;
  lockManager?: WorkspaceLockManager;
  scrubber?: ScrubberLike;
  subprocessStarter?: SubprocessStarter;
  webhookOptions?: WebhookNotifyOptions;
  baseEnv?: Record<string, string | undefined>;
  binaryOverride?: string;
}

export interface ParsedCliLineResult {
  threadId?: string;
  events?: Array<Omit<JobEvent, 'seq'>>;
  finalReportText?: string;
  tokenUsage?: TokenUsage;
  errorMessage?: string;
}

export interface CliDriverSpec {
  readonly driver: AgentDriverName;
  readonly runnerName: string;
  readonly defaultBinary: string;
  readonly allowNetwork?: boolean;
  buildArgs(options: AgentRunOptions): string[];
  buildEnv(
    config: CliDriverDeps['config'],
    baseEnv: Record<string, string | undefined>,
  ): Record<string, string>;
  parseJsonLine(
    parsed: Record<string, unknown>,
    scrubber: ScrubberLike,
  ): ParsedCliLineResult;
}

export async function runCliAgentDriver(
  spec: CliDriverSpec,
  deps: CliDriverDeps,
  options: AgentRunOptions,
): Promise<AgentRunResult> {
  const scrubber = deps.scrubber ?? createSecretScrubber(deps.config);
  const lockManager = deps.lockManager ?? workspaceLockManager;
  const starter = deps.subprocessStarter ?? startSubprocess;
  const baseEnv = deps.baseEnv ?? process.env;

  const jobId = options.jobId || `job_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
  const runnerType = options.mode === 'write' ? 'agent_write' : 'agent_readonly';
  const maxDurationSec =
    options.maxDurationSec !== undefined
      ? Math.max(1, Math.min(options.maxDurationSec, deps.config.codexMaxDurationSec))
      : deps.config.codexMaxDurationSec;
  const tokenBudget =
    options.tokenBudget !== undefined
      ? Math.max(1, Math.min(options.tokenBudget, deps.config.codexTokenBudget))
      : deps.config.codexTokenBudget;

  let lease: WorkspaceLockLease | null = null;
  let subprocessHandle: SubprocessHandle | undefined;
  let checkpointId: string | null = null;
  const internalAbort = new AbortController();
  let timedOut = false;
  let cancelled = false;
  let budgetExceeded = false;

  let resolveDone!: () => void;
  const donePromise = new Promise<void>((resolve) => {
    resolveDone = resolve;
  });

  const onExternalAbort = () => {
    cancelled = true;
    internalAbort.abort();
    if (subprocessHandle) {
      void subprocessHandle.kill('abort');
    }
  };
  if (options.signal) {
    if (options.signal.aborted) {
      cancelled = true;
      internalAbort.abort();
    } else {
      options.signal.addEventListener('abort', onExternalAbort, { once: true });
    }
  }

  const durationTimer = setTimeout(() => {
    timedOut = true;
    internalAbort.abort();
    if (subprocessHandle) {
      void subprocessHandle.kill('timeout');
    }
  }, maxDurationSec * 1000);
  durationTimer.unref?.();

  const emitEvent = (ev: Omit<JobEvent, 'seq'>) => {
    options.onEvent?.(ev);
    deps.jobRepo?.appendEvent(jobId, ev, 50);
  };

  registerActiveJob({
    jobId,
    workspaceSlug: options.workspaceSlug,
    runnerType,
    cancel: async () => {
      cancelled = true;
      internalAbort.abort();
      if (subprocessHandle) {
        await subprocessHandle.kill('abort');
      }
    },
    done: donePromise,
  });

  let threadId: string | null = options.resumeThreadId ?? null;
  let finalReport = '';
  let tokenUsage: TokenUsage | null = null;
  let streamError: string | undefined;

  try {
    lease =
      options.mode === 'write'
        ? await lockManager.acquireWrite(options.workspaceSlug, {
            holder: `${spec.driver}:write`,
            jobId,
            signal: internalAbort.signal,
          })
        : await lockManager.acquireRead(options.workspaceSlug, {
            holder: `${spec.driver}:readonly`,
            signal: internalAbort.signal,
          });

    if (deps.jobRepo) {
      const existing = deps.jobRepo.getJob(jobId);
      if (!existing) {
        deps.jobRepo.createJob({
          job_id: jobId,
          workspace_slug: options.workspaceSlug,
          runner_type: runnerType,
          status: 'running',
          command_or_objective: scrubber.scrub(options.objective),
          codex_thread_id: threadId,
        });
      } else {
        deps.jobRepo.updateJob(jobId, {
          status: 'running',
          codex_thread_id: threadId,
        });
      }
    }

    if (cancelled || internalAbort.signal.aborted) {
      const abortStatus: 'cancelled' | 'timed_out' = timedOut ? 'timed_out' : 'cancelled';
      const abortMsg =
        abortStatus === 'timed_out'
          ? `${spec.runnerName} timed out after ${maxDurationSec}s`
          : `${spec.runnerName} job was cancelled`;
      const updated = deps.jobRepo?.updateJob(jobId, {
        status: abortStatus,
        codex_thread_id: threadId,
        error_message: abortMsg,
      });
      if (updated) {
        await notifyJobFinished(deps.config, updated, { scrubber, ...deps.webhookOptions });
      }
      return {
        status: abortStatus,
        threadId,
        finalReport: '',
        tokenUsage: null,
        errorMessage: abortMsg,
      };
    }

    if (options.mode === 'write' && (await isGitRepository(options.workspaceDir))) {
      const chk = await createCheckpoint({
        workspacesDir: deps.config.workspacesDir,
        slug: options.workspaceSlug,
        reason: `pre-${spec.driver}-write:${jobId}`,
        workspaceRepo: deps.workspaceRepo,
        scrubber,
      });
      checkpointId = chk.checkpointId;
      deps.jobRepo?.updateJob(jobId, { checkpoint_id: checkpointId });
      emitEvent({
        ts: Date.now(),
        type: 'checkpoint',
        message: `Created pre-write checkpoint ${checkpointId}`,
        data: { checkpoint_id: checkpointId, git_commit_sha: chk.gitCommitSha },
      });
    }

    const bwrapEnabled = Boolean(deps.config.sandboxBwrapIsolation);
    let realWorkspacesRoot = path.resolve(deps.config.workspacesDir);
    let realWorkspaceDir = path.resolve(options.workspaceDir);
    try {
      realWorkspacesRoot = fs.realpathSync(realWorkspacesRoot);
    } catch {
      // Fallback to resolved path
    }
    try {
      realWorkspaceDir = fs.realpathSync(realWorkspaceDir);
    } catch {
      // Fallback to resolved path
    }

    if (bwrapEnabled && process.platform === 'linux') {
      await probeBwrapSupport(undefined, deps.config.sandboxUid, deps.config.sandboxGid);
    }

    const env = spec.buildEnv(deps.config, baseEnv);
    const args = spec.buildArgs(options);
    const command = deps.binaryOverride ?? spec.defaultBinary;

    let stdoutRemainder = '';
    const plainOutputLines: string[] = [];

    const processLine = (rawLine: string) => {
      const trimmed = rawLine.trim();
      if (!trimmed) return;

      let parsed: Record<string, unknown> | null = null;
      if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
        try {
          parsed = JSON.parse(trimmed) as Record<string, unknown>;
        } catch {
          parsed = null;
        }
      }

      if (!parsed) {
        const clean = scrubber.scrub(trimmed);
        plainOutputLines.push(clean);
        emitEvent({
          ts: Date.now(),
          type: 'stdout',
          message: clean.slice(0, 2000),
        });
        return;
      }

      const res = spec.parseJsonLine(parsed, scrubber);
      if (res.threadId && res.threadId !== threadId) {
        threadId = res.threadId;
        deps.jobRepo?.updateJob(jobId, { codex_thread_id: threadId });
      }
      if (res.events) {
        for (const ev of res.events) {
          emitEvent(ev);
        }
      }
      if (res.finalReportText !== undefined) {
        finalReport = scrubber.scrub(res.finalReportText);
      }
      if (res.errorMessage !== undefined) {
        streamError = scrubber.scrub(res.errorMessage);
      }
      if (res.tokenUsage) {
        tokenUsage = res.tokenUsage;
        deps.jobRepo?.updateJob(jobId, { token_usage: tokenUsage });
        if (tokenUsage.total_tokens > tokenBudget) {
          budgetExceeded = true;
          streamError = `Token budget exceeded (${tokenUsage.total_tokens} > ${tokenBudget})`;
          emitEvent({
            ts: Date.now(),
            type: 'error',
            message: streamError,
          });
          internalAbort.abort();
          if (subprocessHandle) {
            void subprocessHandle.kill('abort');
          }
        }
      }
    };

    subprocessHandle = starter({
      command,
      args,
      shell: false,
      cwd: realWorkspaceDir,
      env,
      timeoutMs: maxDurationSec * 1000,
      signal: internalAbort.signal,
      uid: deps.config.sandboxUid,
      gid: deps.config.sandboxGid,
      bwrapIsolation: {
        enabled: bwrapEnabled,
        strict: Boolean(deps.config.sandboxStrictIsolation),
        workspaceDir: realWorkspaceDir,
        workspacesRoot: realWorkspacesRoot,
        dataDir: deps.config.dataDir,
        allowNetwork: spec.allowNetwork ?? true,
      },
      onStdout: (chunk) => {
        stdoutRemainder += chunk;
        let idx = stdoutRemainder.indexOf('\n');
        while (idx !== -1) {
          const line = stdoutRemainder.slice(0, idx);
          stdoutRemainder = stdoutRemainder.slice(idx + 1);
          processLine(line);
          idx = stdoutRemainder.indexOf('\n');
        }
      },
      onStderr: (chunk) => {
        const clean = scrubber.scrub(chunk).trim();
        if (clean) {
          emitEvent({
            ts: Date.now(),
            type: 'stderr',
            message: clean.slice(0, 2000),
          });
        }
      },
    });

    if (cancelled || internalAbort.signal.aborted) {
      await subprocessHandle.kill('abort');
    }

    const execRes: ExecResult = await subprocessHandle.done;
    if (stdoutRemainder.trim()) {
      processLine(stdoutRemainder);
    }

    if (!finalReport && plainOutputLines.length > 0) {
      finalReport = plainOutputLines.join('\n').slice(-8000);
    }

    let finalStatus: JobStatus;
    if (cancelled) {
      finalStatus = 'cancelled';
      streamError = streamError ?? `${spec.runnerName} job was cancelled`;
    } else if (timedOut || execRes.timedOut) {
      finalStatus = 'timed_out';
      streamError = streamError ?? `${spec.runnerName} job timed out after ${maxDurationSec}s`;
    } else if (budgetExceeded || streamError || (execRes.exitCode !== 0 && execRes.exitCode !== null)) {
      finalStatus = 'failed';
      if (!streamError) {
        const errSnippet = scrubber.scrub(execRes.stderr.trim());
        streamError = errSnippet || `${spec.runnerName} exited with code ${execRes.exitCode ?? 'null'}`;
      }
    } else if (execRes.exitCode === null) {
      finalStatus = execRes.aborted ? 'cancelled' : 'failed';
      streamError = streamError ?? scrubber.scrub(execRes.stderr.trim() || `${spec.runnerName} failed to launch`);
    } else {
      finalStatus = 'completed';
    }

    const scrubbedReport = scrubber.scrub(finalReport);
    const scrubbedError = streamError ? scrubber.scrub(streamError) : undefined;

    const updated = deps.jobRepo?.updateJob(jobId, {
      status: finalStatus,
      codex_thread_id: threadId,
      checkpoint_id: checkpointId,
      token_usage: tokenUsage,
      final_report_text: scrubbedReport || null,
      error_message: scrubbedError ?? null,
    });

    if (updated) {
      await notifyJobFinished(deps.config, updated, { scrubber, ...deps.webhookOptions });
    }

    return {
      status: finalStatus,
      threadId,
      finalReport: scrubbedReport,
      tokenUsage,
      ...(scrubbedError ? { errorMessage: scrubbedError } : {}),
    };
  } catch (err) {
    const safeErr = scrubber.scrub(err instanceof Error ? err.message : String(err));
    const finalStatus: 'failed' | 'cancelled' | 'timed_out' = cancelled
      ? 'cancelled'
      : timedOut
        ? 'timed_out'
        : 'failed';

    emitEvent({
      ts: Date.now(),
      type: 'error',
      message: safeErr,
    });

    const updated = deps.jobRepo?.updateJob(jobId, {
      status: finalStatus,
      codex_thread_id: threadId,
      checkpoint_id: checkpointId,
      token_usage: tokenUsage,
      final_report_text: finalReport ? scrubber.scrub(finalReport) : null,
      error_message: safeErr,
    });

    if (updated) {
      await notifyJobFinished(deps.config, updated, { scrubber, ...deps.webhookOptions });
    }

    return {
      status: finalStatus,
      threadId,
      finalReport: scrubber.scrub(finalReport),
      tokenUsage,
      errorMessage: safeErr,
    };
  } finally {
    clearTimeout(durationTimer);
    if (options.signal) {
      options.signal.removeEventListener('abort', onExternalAbort);
    }
    unregisterActiveJob(jobId);
    lease?.release();
    resolveDone();
  }
}
