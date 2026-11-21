import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { notifyJobFinished } from '../../core/webhookNotifier.js';
import {
  cancelActiveJob,
  registerActiveJob,
  unregisterActiveJob,
} from '../../core/workspaceExec.js';
import { resolveWorkspaceRoot } from '../../core/workspaceLock.js';
import {
  buildSandboxedEnv,
  probeBwrapSupport,
  runSubprocess,
  startSubprocess,
  type SubprocessHandle,
} from '../../utils/exec.js';
import type { McpToolRegistry } from '../registry.js';
import {
  buildGuardOptions,
  getAgentRunner,
  getToolActor,
  getWorkspaceAdapter,
  type McpToolDeps,
} from './context.js';

function launchBackgroundShellTask(
  deps: McpToolDeps,
  params: {
    jobId: string;
    slug: string;
    workspaceDir: string;
    command: string;
    maxDurationSec?: number;
    allowNetwork?: boolean;
  },
): void {
  const { jobId, slug, workspaceDir, command } = params;
  const maxDurationMs = Math.max(1000, (params.maxDurationSec ?? 600) * 1000);
  const abortController = new AbortController();
  let cancelled = false;
  let subprocessHandle: SubprocessHandle | undefined;

  const done = (async () => {
    let lease;
    try {
      lease = await deps.lockManager.acquireWrite(slug, {
        holder: 'shell_task',
        jobId,
        signal: abortController.signal,
      });

      if (cancelled || abortController.signal.aborted) {
        const updated = deps.repos.jobs.updateJob(jobId, {
          status: 'cancelled',
          error_message: 'Shell task was cancelled before starting',
        });
        deps.repos.jobs.appendEvent(jobId, {
          ts: Date.now(),
          type: 'status',
          message: 'Cancelled before subprocess start',
        });
        if (updated) {
          await notifyJobFinished(deps.config, updated, { scrubber: deps.scrubber });
        }
        return;
      }

      const bwrapEnabled = Boolean(deps.config.sandboxBwrapIsolation);
      let realWorkspacesRoot = path.resolve(deps.config.workspacesDir);
      try {
        realWorkspacesRoot = fs.realpathSync(realWorkspacesRoot);
      } catch {
        // Keep path.resolve fallback if directory doesn't exist yet
      }

      if (bwrapEnabled && process.platform === 'linux') {
        await probeBwrapSupport(undefined, deps.config.sandboxUid, deps.config.sandboxGid);
      }

      if (cancelled || abortController.signal.aborted) {
        const updated = deps.repos.jobs.updateJob(jobId, {
          status: 'cancelled',
          error_message: 'Shell task was cancelled before starting',
        });
        if (updated) {
          await notifyJobFinished(deps.config, updated, { scrubber: deps.scrubber });
        }
        return;
      }

      deps.repos.jobs.updateJob(jobId, { status: 'running' });
      deps.repos.jobs.appendEvent(jobId, {
        ts: Date.now(),
        type: 'status',
        message: `Started background shell_task: ${deps.scrubber.scrub(command)}`,
      });

      subprocessHandle = startSubprocess({
        command,
        shell: true,
        cwd: workspaceDir,
        env: buildSandboxedEnv(),
        timeoutMs: maxDurationMs,
        signal: abortController.signal,
        uid: deps.config.sandboxUid,
        gid: deps.config.sandboxGid,
        bwrapIsolation: {
          enabled: bwrapEnabled,
          strict: Boolean(deps.config.sandboxStrictIsolation),
          workspaceDir,
          workspacesRoot: realWorkspacesRoot,
          dataDir: deps.config.dataDir,
          allowNetwork: Boolean(params.allowNetwork),
        },
        onStdout: (chunk) => {
          const clean = deps.scrubber.scrub(chunk).trim();
          if (clean) {
            deps.repos.jobs.appendEvent(jobId, {
              ts: Date.now(),
              type: 'stdout',
              message: clean.slice(0, 2000),
            });
          }
        },
        onStderr: (chunk) => {
          const clean = deps.scrubber.scrub(chunk).trim();
          if (clean) {
            deps.repos.jobs.appendEvent(jobId, {
              ts: Date.now(),
              type: 'stderr',
              message: clean.slice(0, 2000),
            });
          }
        },
      });

      if (cancelled || abortController.signal.aborted) {
        await subprocessHandle.kill('abort');
      }

      const res = await subprocessHandle.done;
      const finalStatus =
        res.aborted || cancelled
          ? 'cancelled'
          : res.timedOut
            ? 'timed_out'
            : res.exitCode === 0
              ? 'completed'
              : 'failed';

      const report = deps.scrubber.scrub(
        [
          `exitCode=${res.exitCode ?? 'null'} durationMs=${res.durationMs}`,
          res.stdout.trim() ? `--- stdout ---\n${res.stdout.trim().slice(-8000)}` : '',
          res.stderr.trim() ? `--- stderr ---\n${res.stderr.trim().slice(-4000)}` : '',
        ]
          .filter(Boolean)
          .join('\n'),
      );

      const errorMessage =
        finalStatus === 'completed'
          ? null
          : deps.scrubber.scrub(
              finalStatus === 'cancelled'
                ? 'Shell task was cancelled'
                : finalStatus === 'timed_out'
                  ? `Shell task timed out after ${maxDurationMs}ms`
                  : res.stderr.trim() || `Exited with code ${res.exitCode ?? 'null'}`,
            );

      const updated = deps.repos.jobs.updateJob(jobId, {
        status: finalStatus,
        final_report_text: report,
        error_message: errorMessage,
      });

      if (updated) {
        await notifyJobFinished(deps.config, updated, { scrubber: deps.scrubber });
      }
    } catch (err) {
      const msg = deps.scrubber.scrub(err instanceof Error ? err.message : String(err));
      const updated = deps.repos.jobs.updateJob(jobId, {
        status: cancelled ? 'cancelled' : 'failed',
        error_message: msg,
      });
      if (updated) {
        await notifyJobFinished(deps.config, updated, { scrubber: deps.scrubber });
      }
    } finally {
      unregisterActiveJob(jobId);
      lease?.release();
    }
  })();

  registerActiveJob({
    jobId,
    workspaceSlug: slug,
    runnerType: 'shell_task',
    cancel: async () => {
      cancelled = true;
      abortController.abort();
      if (subprocessHandle) {
        await subprocessHandle.kill('abort');
      }
    },
    done,
  });
}

export function registerExecRunnerTools(registry: McpToolRegistry, deps: McpToolDeps): void {
  const wsAdapter = getWorkspaceAdapter(deps);

  // 4. workspace_exec
  registry.register({
    name: 'workspace_exec',
    title: 'Execute Workspace Command',
    description:
      'Execute a shell command inside /workspaces/{slug} with strict secret stripping. Waits up to wait_ms (default 12s, max 15s) and auto-promotes longer commands to a background job_id.',
    inputSchema: {
      slug: z.string().min(1),
      command: z.string().min(1),
      args: z.array(z.string()).optional(),
      cwd: z.string().optional(),
      readonly: z.boolean().optional(),
      allow_network: z.boolean().optional().default(false),
      wait_ms: z.number().int().min(500).max(15000).optional(),
      max_duration_sec: z.number().int().min(1).max(3600).optional(),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
    guardDeps: (args) => ({
      ...buildGuardOptions(deps, `exec-${args.slug}`),
      requiredScope: 'write',
    }),
    handler: async (args) => {
      const clampedDurationSec =
        args.max_duration_sec !== undefined
          ? Math.min(args.max_duration_sec, deps.config.codexMaxDurationSec)
          : undefined;
      const res = await wsAdapter.workspaceExec({
        config: deps.config,
        slug: args.slug,
        command: args.command,
        args: args.args,
        cwd: args.cwd,
        readonly: args.readonly,
        allowNetwork: args.allow_network,
        waitMs: args.wait_ms,
        maxDurationSec: clampedDurationSec,
        jobRepo: deps.repos.jobs,
        lockManager: deps.lockManager,
        scrubber: deps.scrubber,
      });

      if (res.mode === 'sync') {
        return [
          `# workspace_exec (sync) @ ${args.slug}`,
          `ExitCode: ${res.exitCode ?? 'null'} | Duration: ${res.durationMs}ms | TimedOut: ${res.timedOut} | Truncated: ${res.truncated}`,
          res.stdout ? `## stdout\n${res.stdout}` : '',
          res.stderr ? `## stderr\n${res.stderr}` : '',
        ]
          .filter(Boolean)
          .join('\n\n');
      }

      return [
        `# workspace_exec (auto-promoted to background job)`,
        `job_id: ${res.jobId}`,
        `Use job_status(job_id="${res.jobId}") to monitor progress or cancel.`,
        res.partialOutput.stdout ? `## Partial stdout\n${res.partialOutput.stdout}` : '',
        res.partialOutput.stderr ? `## Partial stderr\n${res.partialOutput.stderr}` : '',
      ]
        .filter(Boolean)
        .join('\n\n');
    },
  });

  // 5. dispatch_runner
  registry.register({
    name: 'dispatch_runner',
    title: 'Dispatch Background Runner',
    description:
      'Start an asynchronous multi-driver AI agent (Codex SDK, Claude Code CLI, Gemini CLI, OpenCode CLI) in readonly or write mode (with auto-checkpoint) or a background shell_task, returning job_id immediately.',
    inputSchema: {
      runner_type: z
        .enum(['codex_readonly', 'codex_write', 'agent_readonly', 'agent_write', 'shell_task'])
        .optional(),
      mode: z
        .enum(['codex_readonly', 'codex_write', 'agent_readonly', 'agent_write', 'shell_task'])
        .optional(),
      agent_driver: z.enum(['codex', 'claude_code', 'gemini_cli', 'opencode']).optional(),
      slug: z.string().min(1),
      objective: z.string().min(1),
      resume_thread_id: z.string().optional(),
      model: z.string().optional(),
      reasoning_effort: z.enum(['minimal', 'low', 'medium', 'high', 'xhigh']).optional(),
      allow_network: z.boolean().optional(),
      max_duration_sec: z.number().int().min(10).max(3600).optional(),
      token_budget: z.number().int().min(1000).max(10000000).optional(),
      include_memory: z.boolean().optional().default(true),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
    guardDeps: (args) => ({
      ...buildGuardOptions(deps, `dispatch-${args.slug}`),
      requiredScope: 'write',
    }),
    handler: async (args, extra) => {
      const actor = getToolActor(deps, extra);
      const effectiveRunnerType = args.runner_type ?? args.mode;
      if (!effectiveRunnerType) {
        throw new Error('dispatch_runner requires "runner_type" (or "mode").');
      }
      const effectiveDriver = args.agent_driver ?? deps.config.defaultAgentDriver ?? 'codex';

      const { slug, realWorkspaceRoot } = resolveWorkspaceRoot(
        deps.config.workspacesDir,
        args.slug,
      );
      if (!fs.existsSync(realWorkspaceRoot)) {
        throw new Error(`Workspace "${slug}" does not exist.`);
      }

      const jobId = `job_${randomUUID().replace(/-/g, '').slice(0, 16)}`;
      deps.repos.jobs.createJob({
        job_id: jobId,
        workspace_slug: slug,
        runner_type: effectiveRunnerType,
        status: 'queued',
        command_or_objective: deps.scrubber.scrub(args.objective),
        codex_thread_id: args.resume_thread_id ?? null,
      });

      deps.repos.audit.record({
        actor,
        action: 'runner.dispatch',
        target: `${slug}:${jobId}`,
        status: 'success',
        details: {
          runner_type: effectiveRunnerType,
          ...(effectiveRunnerType !== 'shell_task' ? { driver: effectiveDriver } : {}),
        },
      });

      const effectiveMaxDurationSec = Math.min(
        args.max_duration_sec ?? deps.config.codexMaxDurationSec,
        deps.config.codexMaxDurationSec,
      );
      const effectiveTokenBudget = Math.min(
        args.token_budget ?? deps.config.codexTokenBudget,
        deps.config.codexTokenBudget,
      );

      let memoryInjected = false;
      if (effectiveRunnerType === 'shell_task') {
        launchBackgroundShellTask(deps, {
          jobId,
          slug,
          workspaceDir: realWorkspaceRoot,
          command: args.objective,
          maxDurationSec: effectiveMaxDurationSec,
          allowNetwork: args.allow_network ?? false,
        });
      } else {
        const runMode =
          effectiveRunnerType === 'codex_write' || effectiveRunnerType === 'agent_write'
            ? 'write'
            : 'readonly';
        const memoryContext =
          args.include_memory !== false
            ? deps.repos.memories.formatRecallContext(slug, 1800)
            : '';
        memoryInjected = memoryContext.length > 0;
        const effectiveObjective = memoryInjected
          ? `[Workspace Persistent Memory]\n${memoryContext}\n[/Workspace Persistent Memory]\n\n${args.objective}`
          : args.objective;

        const runOptions = {
          jobId,
          workspaceSlug: slug,
          workspaceDir: realWorkspaceRoot,
          mode: runMode as 'readonly' | 'write',
          objective: effectiveObjective,
          driver: effectiveDriver,
          resumeThreadId: args.resume_thread_id,
          model: args.model,
          reasoningEffort: args.reasoning_effort,
          ...(args.allow_network !== undefined ? { allowNetwork: args.allow_network } : {}),
          maxDurationSec: effectiveMaxDurationSec,
          tokenBudget: effectiveTokenBudget,
        };

        void getAgentRunner(deps)
          .run(runOptions)
          .catch((err) => {
            const msg = deps.scrubber.scrub(
              err instanceof Error ? err.message : String(err),
            );
            deps.repos.jobs.updateJob(jobId, {
              status: 'failed',
              error_message: msg,
            });
          });
      }

      return [
        `Dispatched ${effectiveRunnerType}${effectiveRunnerType === 'shell_task' ? '' : ` (driver=${effectiveDriver})`} job on workspace "${slug}".`,
        `job_id: ${jobId}`,
        `status: queued`,
        ...(memoryInjected ? ['memory_context: injected'] : []),
        `Poll with job_status(job_id="${jobId}").`,
      ].join('\n');
    },
  });

  // 6. job_status
  registry.register({
    name: 'job_status',
    title: 'Inspect or Cancel Job',
    description:
      'Check status, duration, token usage, codex_thread_id, recent events, workspace git status, and final report for a job, or cancel it with cancel=true.',
    inputSchema: {
      job_id: z.string().min(1),
      since_seq: z.number().int().min(0).optional(),
      cancel: z.boolean().optional(),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
    guardDeps: (args) => ({
      ...buildGuardOptions(deps, `job-${args.job_id}`),
      requiredScope: args.cancel ? 'write' : 'read',
    }),
    handler: async (args, extra) => {
      const actor = getToolActor(deps, extra);
      let cancelNote = '';

      if (args.cancel) {
        const cancelRes = await cancelActiveJob(args.job_id, deps.repos.jobs);
        deps.repos.audit.record({
          actor,
          action: 'job.cancel',
          target: args.job_id,
          status: cancelRes.cancelled ? 'success' : 'failure',
          details: { reason: cancelRes.reason },
        });
        cancelNote = `Cancel requested: cancelled=${cancelRes.cancelled}${cancelRes.reason ? ` (${cancelRes.reason})` : ''}`;
      }

      const job = deps.repos.jobs.getJob(args.job_id);
      if (!job) {
        throw new Error(`Job "${args.job_id}" not found.`);
      }

      const events =
        args.since_seq !== undefined
          ? job.events.filter((ev) => ev.seq > args.since_seq!)
          : job.events.slice(-20);

      let gitStatusText = '(unavailable)';
      try {
        const { realWorkspaceRoot } = resolveWorkspaceRoot(
          deps.config.workspacesDir,
          job.workspace_slug,
        );
        if (fs.existsSync(path.join(realWorkspaceRoot, '.git'))) {
          const st = await runSubprocess({
            command: 'git',
            args: ['status', '-sb'],
            cwd: realWorkspaceRoot,
            env: buildSandboxedEnv(),
            timeoutMs: 3000,
          });
          if (st.exitCode === 0) {
            gitStatusText = st.stdout.trim() || '(clean)';
          }
        }
      } catch {
        // Non-fatal
      }

      const durationMs = Math.max(0, job.updated_at - job.created_at);
      const eventLines = events.map((ev) => `[#${ev.seq} ${ev.type}] ${ev.message}`);

      return [
        `# Job ${job.job_id}`,
        cancelNote,
        `Workspace: ${job.workspace_slug} | Runner: ${job.runner_type} | Status: ${job.status}`,
        `Duration: ${durationMs}ms | Codex Thread: ${job.codex_thread_id ?? 'none'} | Checkpoint: ${job.checkpoint_id ?? 'none'}`,
        `Token Usage: ${job.token_usage ? JSON.stringify(job.token_usage) : 'none'}`,
        `Git Status: ${gitStatusText}`,
        '',
        `## Events (${events.length})`,
        eventLines.join('\n') || '(no events)',
        job.final_report_text ? `\n## Final Report\n${job.final_report_text}` : '',
        job.error_message ? `\n## Error\n${job.error_message}` : '',
      ]
        .filter((part) => part !== '')
        .join('\n');
    },
  });
}
