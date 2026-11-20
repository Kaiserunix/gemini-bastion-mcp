import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  Codex,
  type CodexOptions,
  type ThreadEvent,
  type ThreadOptions,
  type TurnOptions,
} from '@openai/codex-sdk';
import type { JobRepository } from '../db/repositories/jobRepo.js';
import type { WorkspaceRepository } from '../db/repositories/workspaceRepo.js';
import type {
  AgentRunOptions,
  AgentRunResult,
  AgentRunner,
  GatewayConfig,
  JobEvent,
  JobStatus,
  ScrubberLike,
  TokenUsage,
} from '../types.js';
import { buildSandboxedEnv } from '../utils/exec.js';
import { createSecretScrubber } from '../utils/secretScrubber.js';
import { createCheckpoint, isGitRepository } from './gitSnapshot.js';
import { notifyJobFinished, type WebhookNotifyOptions } from './webhookNotifier.js';
import {
  getActiveJob,
  registerActiveJob,
  unregisterActiveJob,
} from './workspaceExec.js';
import {
  workspaceLockManager,
  type WorkspaceLockLease,
  type WorkspaceLockManager,
} from './workspaceLock.js';

export const CODEX_OUTPUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: [
    'summary',
    'files_touched',
    'verification_commands_run',
    'risks',
    'next_action_needed',
  ],
  properties: {
    summary: { type: 'string' },
    files_touched: { type: 'array', items: { type: 'string' } },
    verification_commands_run: { type: 'array', items: { type: 'string' } },
    risks: { type: 'array', items: { type: 'string' } },
    next_action_needed: { type: 'string' },
  },
} as const;

export interface CodexThreadLike {
  readonly id: string | null;
  runStreamed(
    input: string,
    turnOptions?: TurnOptions,
  ): Promise<{ events: AsyncGenerator<ThreadEvent> }>;
}

export interface CodexClientLike {
  startThread(options?: ThreadOptions): CodexThreadLike;
  resumeThread(id: string, options?: ThreadOptions): CodexThreadLike;
}

export interface CodexRunnerDeps {
  config: Pick<
    GatewayConfig,
    | 'workspacesDir'
    | 'codexApiKey'
    | 'openaiApiKey'
    | 'codexBaseUrl'
    | 'codexDefaultModel'
    | 'codexReasoningEffort'
    | 'codexMaxDurationSec'
    | 'codexTokenBudget'
    | 'notifyWebhookUrl'
  > &
    Partial<GatewayConfig>;
  jobRepo?: JobRepository;
  workspaceRepo?: WorkspaceRepository;
  lockManager?: WorkspaceLockManager;
  scrubber?: ScrubberLike;
  codexFactory?: (options: CodexOptions) => CodexClientLike;
  webhookOptions?: WebhookNotifyOptions;
  baseEnv?: Record<string, string | undefined>;
}

export interface CodexRunOptions extends AgentRunOptions {
  allowNetwork?: boolean;
  autoCheckpoint?: boolean;
  configOverrides?: string[];
}

/**
 * Builds the strict env allowlist passed to `@openai/codex-sdk`.
 * Excludes all gateway secrets (`GH_TOKEN`, `CLOUDFLARE_*`, `ADMIN_PASSWORD_HASH`, `OAUTH_*`, etc.)
 * and passes only Codex/OpenAI API key and optional base URL when configured.
 */
export function buildCodexSandboxedEnv(
  config: Pick<GatewayConfig, 'codexApiKey' | 'openaiApiKey' | 'codexBaseUrl'>,
  baseEnv: Record<string, string | undefined> = process.env,
): Record<string, string> {
  const env = buildSandboxedEnv({ baseEnv });

  if (baseEnv.CODEX_HOME) {
    env.CODEX_HOME = baseEnv.CODEX_HOME;
  }

  if (config.codexApiKey) {
    env.CODEX_API_KEY = config.codexApiKey;
  } else if (config.openaiApiKey) {
    env.OPENAI_API_KEY = config.openaiApiKey;
  }

  if (config.codexBaseUrl) {
    env.CODEX_BASE_URL = config.codexBaseUrl;
    env.OPENAI_BASE_URL = config.codexBaseUrl;
  }

  return env;
}

function mapThreadEventToJobEvent(
  event: ThreadEvent,
  scrubber: ScrubberLike,
): { jobEvent: Omit<JobEvent, 'seq'> | null; agentMessageText?: string; errorMessage?: string } {
  const ts = Date.now();

  switch (event.type) {
    case 'thread.started':
      return {
        jobEvent: {
          ts,
          type: 'status',
          message: `Codex thread started: ${event.thread_id}`,
          data: { thread_id: event.thread_id },
        },
      };

    case 'turn.started':
      return {
        jobEvent: {
          ts,
          type: 'status',
          message: 'Codex turn started',
        },
      };

    case 'turn.completed': {
      const total = (event.usage.input_tokens ?? 0) + (event.usage.output_tokens ?? 0);
      return {
        jobEvent: {
          ts,
          type: 'token_usage',
          message: `Turn completed (input=${event.usage.input_tokens}, output=${event.usage.output_tokens}, total=${total})`,
          data: { ...event.usage },
        },
      };
    }

    case 'turn.failed': {
      const errMsg = scrubber.scrub(event.error.message);
      return {
        jobEvent: {
          ts,
          type: 'error',
          message: `Codex turn failed: ${errMsg}`,
        },
        errorMessage: errMsg,
      };
    }

    case 'error': {
      const errMsg = scrubber.scrub(event.message);
      return {
        jobEvent: {
          ts,
          type: 'error',
          message: `Codex stream error: ${errMsg}`,
        },
        errorMessage: errMsg,
      };
    }

    case 'item.started':
    case 'item.updated':
    case 'item.completed': {
      const item = event.item;
      if (item.type === 'agent_message') {
        const text = scrubber.scrub(item.text);
        if (event.type === 'item.completed') {
          return {
            jobEvent: {
              ts,
              type: 'agent_message',
              message: text.slice(0, 2000),
            },
            agentMessageText: text,
          };
        }
        return { jobEvent: null };
      }

      if (item.type === 'command_execution') {
        if (event.type === 'item.updated') return { jobEvent: null };
        return {
          jobEvent: {
            ts,
            type: 'tool_call',
            message: scrubber.scrub(`exec[${item.status}]: ${item.command}`),
            data: {
              item_type: item.type,
              status: item.status,
              ...(item.exit_code !== undefined ? { exit_code: item.exit_code } : {}),
            },
          },
        };
      }

      if (item.type === 'file_change') {
        const summary = item.changes.map((c) => `${c.kind}:${c.path}`).join(', ');
        return {
          jobEvent: {
            ts,
            type: 'tool_call',
            message: scrubber.scrub(`files[${item.status}]: ${summary}`),
          },
        };
      }

      if (item.type === 'mcp_tool_call') {
        if (event.type === 'item.updated') return { jobEvent: null };
        return {
          jobEvent: {
            ts,
            type: 'tool_call',
            message: scrubber.scrub(`mcp[${item.status}]: ${item.server}.${item.tool}`),
          },
        };
      }

      if (item.type === 'error') {
        const errMsg = scrubber.scrub(item.message);
        return {
          jobEvent: {
            ts,
            type: 'error',
            message: errMsg,
          },
        };
      }

      return { jobEvent: null };
    }

    default:
      return { jobEvent: null };
  }
}

/**
 * Thin AgentRunner implementation backed by `@openai/codex-sdk` (`Codex` / `startThread` / `resumeThread` / `runStreamed`).
 */
export class CodexSdkRunner implements AgentRunner {
  readonly name = 'codex-sdk';

  private readonly config: CodexRunnerDeps['config'];
  private readonly jobRepo?: JobRepository;
  private readonly workspaceRepo?: WorkspaceRepository;
  private readonly lockManager: WorkspaceLockManager;
  private readonly scrubber: ScrubberLike;
  private readonly codexFactory: (options: CodexOptions) => CodexClientLike;
  private readonly webhookOptions?: WebhookNotifyOptions;
  private readonly baseEnv?: Record<string, string | undefined>;

  constructor(deps: CodexRunnerDeps) {
    this.config = deps.config;
    this.jobRepo = deps.jobRepo;
    this.workspaceRepo = deps.workspaceRepo;
    this.lockManager = deps.lockManager ?? workspaceLockManager;
    this.scrubber = deps.scrubber ?? createSecretScrubber(deps.config);
    this.codexFactory = deps.codexFactory ?? ((opts) => new Codex(opts));
    this.webhookOptions = deps.webhookOptions;
    this.baseEnv = deps.baseEnv;
  }

  async run(options: CodexRunOptions): Promise<AgentRunResult> {
    const jobId = options.jobId || `job_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const runnerType = options.mode === 'write' ? 'codex_write' : 'codex_readonly';
    const maxDurationSec =
      options.maxDurationSec !== undefined
        ? Math.max(1, Math.min(options.maxDurationSec, this.config.codexMaxDurationSec))
        : this.config.codexMaxDurationSec;
    const tokenBudget =
      options.tokenBudget !== undefined
        ? Math.max(1, Math.min(options.tokenBudget, this.config.codexTokenBudget))
        : this.config.codexTokenBudget;

    let checkpointId: string | null = null;
    let lease: WorkspaceLockLease | null = null;
    const internalAbort = new AbortController();
    let timedOut = false;
    let budgetExceeded = false;
    let cancelled = false;

    let resolveDone!: () => void;
    const donePromise = new Promise<void>((resolve) => {
      resolveDone = resolve;
    });

    const onExternalAbort = () => {
      cancelled = true;
      internalAbort.abort();
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
    }, maxDurationSec * 1000);
    durationTimer.unref?.();

    const emitEvent = (ev: Omit<JobEvent, 'seq'>) => {
      options.onEvent?.(ev);
      this.jobRepo?.appendEvent(jobId, ev, 50);
    };

    registerActiveJob({
      jobId,
      workspaceSlug: options.workspaceSlug,
      runnerType,
      cancel: async () => {
        cancelled = true;
        internalAbort.abort();
      },
      done: donePromise,
    });

    let threadId: string | null = options.resumeThreadId ?? null;
    let finalReport = '';
    let cumulativeUsage: TokenUsage | null = null;
    let streamError: string | undefined;

    try {
      // 1. Acquire workspace lock (registered in activeJobs beforehand so queued cancel works)
      lease =
        options.mode === 'write'
          ? await this.lockManager.acquireWrite(options.workspaceSlug, {
              holder: 'codex_write',
              jobId,
              signal: internalAbort.signal,
            })
          : await this.lockManager.acquireRead(options.workspaceSlug, {
              holder: 'codex_readonly',
              signal: internalAbort.signal,
            });

      // 2. Ensure job row exists in SQLite
      if (this.jobRepo) {
        const existing = this.jobRepo.getJob(jobId);
        if (!existing) {
          this.jobRepo.createJob({
            job_id: jobId,
            workspace_slug: options.workspaceSlug,
            runner_type: runnerType,
            status: 'running',
            command_or_objective: this.scrubber.scrub(options.objective),
            codex_thread_id: threadId,
          });
        } else {
          this.jobRepo.updateJob(jobId, {
            status: 'running',
            codex_thread_id: threadId,
          });
        }
      }

      if (cancelled || internalAbort.signal.aborted) {
        const abortStatus: 'cancelled' | 'timed_out' = timedOut ? 'timed_out' : 'cancelled';
        const abortMsg =
          abortStatus === 'timed_out'
            ? `Codex job timed out after ${maxDurationSec}s`
            : 'Codex job was cancelled';
        const updatedJob = this.jobRepo?.updateJob(jobId, {
          status: abortStatus,
          codex_thread_id: threadId,
          error_message: abortMsg,
        });
        if (updatedJob) {
          await notifyJobFinished(this.config, updatedJob, {
            scrubber: this.scrubber,
            ...this.webhookOptions,
          });
        }
        return {
          status: abortStatus,
          threadId,
          finalReport: '',
          tokenUsage: null,
          errorMessage: abortMsg,
        };
      }

      // 3. Auto-checkpoint before codex_write when workspace is a git repo
      if (
        options.mode === 'write' &&
        options.autoCheckpoint !== false &&
        (await isGitRepository(options.workspaceDir))
      ) {
        const chk = await createCheckpoint({
          workspacesDir: this.config.workspacesDir,
          slug: options.workspaceSlug,
          reason: `pre-codex-write:${jobId}`,
          workspaceRepo: this.workspaceRepo,
          scrubber: this.scrubber,
        });
        checkpointId = chk.checkpointId;
        this.jobRepo?.updateJob(jobId, { checkpoint_id: checkpointId });
        emitEvent({
          ts: Date.now(),
          type: 'checkpoint',
          message: `Created pre-write checkpoint ${checkpointId}`,
          data: { checkpoint_id: checkpointId, git_commit_sha: chk.gitCommitSha },
        });
      }

      // 4. Construct Codex client with strict env allowlist
      const sandboxEnv = buildCodexSandboxedEnv(this.config, this.baseEnv);
      const codexOptions: CodexOptions = {
        env: sandboxEnv,
        ...(this.config.codexApiKey || this.config.openaiApiKey
          ? { apiKey: this.config.codexApiKey ?? this.config.openaiApiKey }
          : {}),
        ...(this.config.codexBaseUrl ? { baseUrl: this.config.codexBaseUrl } : {}),
        ...(options.configOverrides && options.configOverrides.length > 0
          ? { configOverrides: options.configOverrides }
          : {}),
      };

      const codex = this.codexFactory(codexOptions);
      const isGit = fs.existsSync(path.join(options.workspaceDir, '.git'));
      const threadOptions: ThreadOptions = {
        model: options.model ?? this.config.codexDefaultModel,
        modelReasoningEffort: options.reasoningEffort ?? this.config.codexReasoningEffort,
        sandboxMode: options.mode === 'write' ? 'workspace-write' : 'read-only',
        workingDirectory: options.workspaceDir,
        skipGitRepoCheck: !isGit,
        approvalPolicy: 'never',
        networkAccessEnabled: options.mode === 'write' ? Boolean(options.allowNetwork) : false,
      };

      const thread = options.resumeThreadId
        ? codex.resumeThread(options.resumeThreadId, threadOptions)
        : codex.startThread(threadOptions);

      const streamed = await thread.runStreamed(options.objective, {
        outputSchema: CODEX_OUTPUT_SCHEMA,
        signal: internalAbort.signal,
      });

      for await (const event of streamed.events) {
        if (internalAbort.signal.aborted) {
          break;
        }

        if (event.type === 'thread.started') {
          threadId = event.thread_id;
          this.jobRepo?.updateJob(jobId, { codex_thread_id: threadId });
        }

        const mapped = mapThreadEventToJobEvent(event, this.scrubber);
        if (mapped.jobEvent) {
          emitEvent(mapped.jobEvent);
        }
        if (mapped.agentMessageText !== undefined) {
          finalReport = mapped.agentMessageText;
        }
        if (mapped.errorMessage !== undefined) {
          streamError = mapped.errorMessage;
        }

        if (event.type === 'turn.completed') {
          const prev = cumulativeUsage as TokenUsage | null;
          const input = event.usage.input_tokens ?? 0;
          const cached = event.usage.cached_input_tokens ?? 0;
          const output = event.usage.output_tokens ?? 0;
          const nextUsage: TokenUsage = {
            input_tokens: (prev?.input_tokens ?? 0) + input,
            cached_input_tokens: (prev?.cached_input_tokens ?? 0) + cached,
            output_tokens: (prev?.output_tokens ?? 0) + output,
            total_tokens: (prev?.total_tokens ?? 0) + input + output,
          };
          cumulativeUsage = nextUsage;
          this.jobRepo?.updateJob(jobId, { token_usage: nextUsage });

          if (nextUsage.total_tokens > tokenBudget) {
            budgetExceeded = true;
            streamError = `Token budget exceeded (${nextUsage.total_tokens} > ${tokenBudget})`;
            emitEvent({
              ts: Date.now(),
              type: 'error',
              message: streamError,
            });
            internalAbort.abort();
            break;
          }
        }

        if (!threadId && thread.id) {
          threadId = thread.id;
          this.jobRepo?.updateJob(jobId, { codex_thread_id: threadId });
        }
      }

      if (!threadId && thread.id) {
        threadId = thread.id;
      }

      let finalStatus: JobStatus;
      if (cancelled) {
        finalStatus = 'cancelled';
        streamError = streamError ?? 'Codex job was cancelled';
      } else if (timedOut) {
        finalStatus = 'timed_out';
        streamError = streamError ?? `Codex job timed out after ${maxDurationSec}s`;
      } else if (budgetExceeded || streamError) {
        finalStatus = 'failed';
      } else {
        finalStatus = 'completed';
      }

      const scrubbedReport = this.scrubber.scrub(finalReport);
      const scrubbedError = streamError ? this.scrubber.scrub(streamError) : undefined;

      const updatedJob = this.jobRepo?.updateJob(jobId, {
        status: finalStatus,
        codex_thread_id: threadId,
        checkpoint_id: checkpointId,
        token_usage: cumulativeUsage,
        final_report_text: scrubbedReport || null,
        error_message: scrubbedError ?? null,
      });

      if (updatedJob) {
        await notifyJobFinished(this.config, updatedJob, {
          scrubber: this.scrubber,
          ...this.webhookOptions,
        });
      }

      return {
        status: finalStatus,
        threadId,
        finalReport: scrubbedReport,
        tokenUsage: cumulativeUsage,
        ...(scrubbedError ? { errorMessage: scrubbedError } : {}),
      };
    } catch (err) {
      const rawMsg = err instanceof Error ? err.message : String(err);
      const safeErr = this.scrubber.scrub(rawMsg);

      let finalStatus: 'failed' | 'cancelled' | 'timed_out' = 'failed';
      if (cancelled) finalStatus = 'cancelled';
      else if (timedOut) finalStatus = 'timed_out';

      emitEvent({
        ts: Date.now(),
        type: 'error',
        message: safeErr,
      });

      const updatedJob = this.jobRepo?.updateJob(jobId, {
        status: finalStatus,
        codex_thread_id: threadId,
        checkpoint_id: checkpointId,
        token_usage: cumulativeUsage,
        final_report_text: finalReport ? this.scrubber.scrub(finalReport) : null,
        error_message: safeErr,
      });

      if (updatedJob) {
        await notifyJobFinished(this.config, updatedJob, {
          scrubber: this.scrubber,
          ...this.webhookOptions,
        });
      }

      return {
        status: finalStatus,
        threadId,
        finalReport: this.scrubber.scrub(finalReport),
        tokenUsage: cumulativeUsage,
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
}

/**
 * Reconciles orphaned `queued` / `running` jobs on gateway startup (crash recovery)
 * in batches until zero orphans remain, marking them `failed` with a clear restart recovery message.
 */
export function reconcileOrphanJobs(jobRepo: JobRepository): number {
  let totalCount = 0;

  while (true) {
    const running = jobRepo.listJobs({ status: 'running', limit: 500 });
    const queued = jobRepo.listJobs({ status: 'queued', limit: 500 });
    const orphans = [...running, ...queued].filter((job) => !getActiveJob(job.job_id));
    if (orphans.length === 0) {
      break;
    }

    let batchCount = 0;
    for (const job of orphans) {
      jobRepo.updateJob(job.job_id, {
        status: 'failed',
        error_message:
          'Orphaned job reconciled on gateway startup (process restarted before completion)',
      });
      jobRepo.appendEvent(
        job.job_id,
        {
          ts: Date.now(),
          type: 'error',
          message: 'Orphaned job marked failed during startup crash recovery',
        },
        50,
      );
      batchCount += 1;
    }
    totalCount += batchCount;
    if (batchCount === 0) {
      break;
    }
  }

  return totalCount;
}
