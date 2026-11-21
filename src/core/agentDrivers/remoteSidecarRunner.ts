import { randomUUID } from 'node:crypto';
import type { JobRepository } from '../../db/repositories/jobRepo.js';
import type { WorkspaceRepository } from '../../db/repositories/workspaceRepo.js';
import type {
  AgentRunOptions,
  AgentRunResult,
  AgentRunner,
  GatewayConfig,
  JobEvent,
  JobStatus,
  ScrubberLike,
  TokenUsage,
} from '../../types.js';
import { createSecretScrubber } from '../../utils/secretScrubber.js';
import { createCheckpoint, isGitRepository } from '../gitSnapshot.js';
import { notifyJobFinished, type WebhookNotifyOptions } from '../webhookNotifier.js';
import { registerActiveJob, unregisterActiveJob } from '../workspaceExec.js';
import {
  workspaceLockManager,
  type WorkspaceLockLease,
  type WorkspaceLockManager,
} from '../workspaceLock.js';

export interface RemoteSidecarRunnerDeps {
  config: Pick<
    GatewayConfig,
    | 'workspacesDir'
    | 'agentRunnerUrl'
    | 'agentRunnerAuthToken'
    | 'defaultAgentDriver'
    | 'codexMaxDurationSec'
    | 'codexTokenBudget'
    | 'notifyWebhookUrl'
  > &
    Partial<GatewayConfig>;
  jobRepo?: JobRepository;
  workspaceRepo?: WorkspaceRepository;
  lockManager?: WorkspaceLockManager;
  scrubber?: ScrubberLike;
  fetchImpl?: typeof fetch;
  webhookOptions?: WebhookNotifyOptions;
}

type SidecarStreamPacket =
  | { type: 'event'; event: Omit<JobEvent, 'seq'> }
  | { type: 'thread'; threadId: string }
  | { type: 'token_usage'; tokenUsage: TokenUsage }
  | { type: 'result'; result: AgentRunResult };

/**
 * Delegates agent execution over authenticated HTTP NDJSON streaming to an isolated-runner sidecar.
 */
export class RemoteSidecarAgentRunner implements AgentRunner {
  readonly name = 'remote-sidecar';

  private readonly config: RemoteSidecarRunnerDeps['config'];
  private readonly jobRepo?: JobRepository;
  private readonly workspaceRepo?: WorkspaceRepository;
  private readonly lockManager: WorkspaceLockManager;
  private readonly scrubber: ScrubberLike;
  private readonly fetchImpl: typeof fetch;
  private readonly webhookOptions?: WebhookNotifyOptions;

  constructor(deps: RemoteSidecarRunnerDeps) {
    this.config = deps.config;
    this.jobRepo = deps.jobRepo;
    this.workspaceRepo = deps.workspaceRepo;
    this.lockManager = deps.lockManager ?? workspaceLockManager;
    this.scrubber = deps.scrubber ?? createSecretScrubber(deps.config);
    this.fetchImpl = deps.fetchImpl ?? fetch;
    this.webhookOptions = deps.webhookOptions;
  }

  async run(options: AgentRunOptions): Promise<AgentRunResult> {
    const baseUrl = this.config.agentRunnerUrl?.replace(/\/+$/, '');
    const authToken = this.config.agentRunnerAuthToken;
    if (!baseUrl) {
      throw new Error('RemoteSidecarAgentRunner requires config.agentRunnerUrl');
    }
    if (!authToken || authToken.length < 24) {
      throw new Error(
        'RemoteSidecarAgentRunner requires config.agentRunnerAuthToken (>= 24 chars)',
      );
    }

    const jobId = options.jobId || `job_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const driver = options.driver ?? this.config.defaultAgentDriver;
    const runnerType = options.mode === 'write' ? 'agent_write' : 'agent_readonly';
    const maxDurationSec =
      options.maxDurationSec !== undefined
        ? Math.max(1, Math.min(options.maxDurationSec, this.config.codexMaxDurationSec))
        : this.config.codexMaxDurationSec;
    const tokenBudget =
      options.tokenBudget !== undefined
        ? Math.max(1, Math.min(options.tokenBudget, this.config.codexTokenBudget))
        : this.config.codexTokenBudget;

    let lease: WorkspaceLockLease | null = null;
    let checkpointId: string | null = null;
    const internalAbort = new AbortController();
    let timedOut = false;
    let cancelled = false;

    let resolveDone!: () => void;
    const donePromise = new Promise<void>((resolve) => {
      resolveDone = resolve;
    });

    const sendRemoteCancel = async () => {
      try {
        await this.fetchImpl(`${baseUrl}/cancel/${encodeURIComponent(jobId)}`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${authToken}`,
          },
          signal: AbortSignal.timeout(3000),
        });
      } catch {
        // Best-effort remote cancel notification
      }
    };

    const onExternalAbort = () => {
      cancelled = true;
      internalAbort.abort();
      void sendRemoteCancel();
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
      void sendRemoteCancel();
    }, maxDurationSec * 1000);
    durationTimer.unref?.();

    const emitEvent = (ev: Omit<JobEvent, 'seq'>) => {
      const cleanEv: Omit<JobEvent, 'seq'> = {
        ...ev,
        message: this.scrubber.scrub(ev.message),
        ...(ev.data ? { data: this.scrubber.scrubObject(ev.data) } : {}),
      };
      options.onEvent?.(cleanEv);
      this.jobRepo?.appendEvent(jobId, cleanEv, 50);
    };

    registerActiveJob({
      jobId,
      workspaceSlug: options.workspaceSlug,
      runnerType,
      cancel: async () => {
        cancelled = true;
        internalAbort.abort();
        await sendRemoteCancel();
      },
      done: donePromise,
    });

    let threadId: string | null = options.resumeThreadId ?? null;
    let tokenUsage: TokenUsage | null = null;
    let remoteResult: AgentRunResult | null = null;

    try {
      lease =
        options.mode === 'write'
          ? await this.lockManager.acquireWrite(options.workspaceSlug, {
              holder: `sidecar:${driver}:write`,
              jobId,
              signal: internalAbort.signal,
            })
          : await this.lockManager.acquireRead(options.workspaceSlug, {
              holder: `sidecar:${driver}:readonly`,
              signal: internalAbort.signal,
            });

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
            ? `Sidecar agent timed out after ${maxDurationSec}s`
            : 'Sidecar agent job was cancelled';
        const updated = this.jobRepo?.updateJob(jobId, {
          status: abortStatus,
          codex_thread_id: threadId,
          error_message: abortMsg,
        });
        if (updated) {
          await notifyJobFinished(this.config, updated, {
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

      if (options.mode === 'write' && (await isGitRepository(options.workspaceDir))) {
        const chk = await createCheckpoint({
          workspacesDir: this.config.workspacesDir,
          slug: options.workspaceSlug,
          reason: `pre-sidecar-${driver}-write:${jobId}`,
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

      const response = await this.fetchImpl(`${baseUrl}/run`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          jobId,
          workspaceSlug: options.workspaceSlug,
          mode: options.mode,
          objective: options.objective,
          driver,
          resumeThreadId: options.resumeThreadId,
          model: options.model,
          reasoningEffort: options.reasoningEffort,
          maxDurationSec,
          tokenBudget,
        }),
        signal: internalAbort.signal,
      });

      if (!response.ok) {
        const errBody = this.scrubber.scrub(await response.text().catch(() => ''));
        throw new Error(
          `Isolated runner sidecar returned HTTP ${response.status}${errBody ? `: ${errBody.slice(0, 500)}` : ''}`,
        );
      }

      if (response.body) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        const handlePacketLine = (rawLine: string) => {
          const trimmed = rawLine.trim();
          if (!trimmed) return;
          let pkt: SidecarStreamPacket;
          try {
            pkt = JSON.parse(trimmed) as SidecarStreamPacket;
          } catch {
            return;
          }
          if (pkt.type === 'event' && pkt.event) {
            emitEvent(pkt.event);
          } else if (pkt.type === 'thread' && pkt.threadId) {
            threadId = pkt.threadId;
            this.jobRepo?.updateJob(jobId, { codex_thread_id: threadId });
          } else if (pkt.type === 'token_usage' && pkt.tokenUsage) {
            tokenUsage = pkt.tokenUsage;
            this.jobRepo?.updateJob(jobId, { token_usage: tokenUsage });
          } else if (pkt.type === 'result' && pkt.result) {
            remoteResult = pkt.result;
          }
        };

        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          let idx = buffer.indexOf('\n');
          while (idx !== -1) {
            const line = buffer.slice(0, idx);
            buffer = buffer.slice(idx + 1);
            handlePacketLine(line);
            idx = buffer.indexOf('\n');
          }
        }
        buffer += decoder.decode();
        if (buffer.trim()) {
          handlePacketLine(buffer);
        }
      }

      const finalResult: AgentRunResult = remoteResult ?? {
        status: cancelled ? 'cancelled' : timedOut ? 'timed_out' : 'failed',
        threadId,
        finalReport: '',
        tokenUsage,
        errorMessage: cancelled
          ? 'Sidecar agent job was cancelled'
          : timedOut
            ? `Sidecar agent timed out after ${maxDurationSec}s`
            : 'Sidecar stream ended without a terminal result',
      };

      const status: JobStatus = cancelled
        ? 'cancelled'
        : timedOut
          ? 'timed_out'
          : finalResult.status;

      const scrubbedReport = this.scrubber.scrub(finalResult.finalReport ?? '');
      const scrubbedError = finalResult.errorMessage
        ? this.scrubber.scrub(finalResult.errorMessage)
        : undefined;
      const finalThreadId = finalResult.threadId ?? threadId;
      const finalTokens = finalResult.tokenUsage ?? tokenUsage;

      const updated = this.jobRepo?.updateJob(jobId, {
        status,
        codex_thread_id: finalThreadId,
        checkpoint_id: checkpointId,
        token_usage: finalTokens,
        final_report_text: scrubbedReport || null,
        error_message: scrubbedError ?? null,
      });

      if (updated) {
        await notifyJobFinished(this.config, updated, {
          scrubber: this.scrubber,
          ...this.webhookOptions,
        });
      }

      return {
        status,
        threadId: finalThreadId,
        finalReport: scrubbedReport,
        tokenUsage: finalTokens,
        ...(scrubbedError ? { errorMessage: scrubbedError } : {}),
      };
    } catch (err) {
      const safeErr = this.scrubber.scrub(err instanceof Error ? err.message : String(err));
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

      const updated = this.jobRepo?.updateJob(jobId, {
        status: finalStatus,
        codex_thread_id: threadId,
        checkpoint_id: checkpointId,
        token_usage: tokenUsage,
        error_message: safeErr,
      });

      if (updated) {
        await notifyJobFinished(this.config, updated, {
          scrubber: this.scrubber,
          ...this.webhookOptions,
        });
      }

      return {
        status: finalStatus,
        threadId,
        finalReport: '',
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
}
