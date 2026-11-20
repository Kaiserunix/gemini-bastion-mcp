import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { notifyJobFinished } from '../../core/webhookNotifier.js';
import {
  cancelActiveJob,
  registerActiveJob,
  unregisterActiveJob,
  workspaceExec,
} from '../../core/workspaceExec.js';
import { resolveWorkspaceRoot } from '../../core/workspaceLock.js';
import { buildSandboxedEnv, runSubprocess, startSubprocess, type SubprocessHandle } from '../../utils/exec.js';
import { withMcpGuardrails } from '../outputGuard.js';
import { buildGuardOptions, getToolActor, type McpToolDeps } from './context.js';

function launchBackgroundShellTask(
  deps: McpToolDeps,
  params: {
    jobId: string;
    slug: string;
    workspaceDir: string;
    command: string;
    maxDurationSec?: number;
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

export function registerExecRunnerTools(server: McpServer, deps: McpToolDeps): void {
  // 4. workspace_exec
  server.registerTool(
    'workspace_exec',
    {
      title: 'Execute Workspace Command',
      description:
        'Execute a shell command inside /workspaces/{slug} with strict secret stripping. Waits up to wait_ms (default 12s, max 15s) and auto-promotes longer commands to a background job_id.',
      inputSchema: {
        slug: z.string().min(1),
        command: z.string().min(1),
        args: z.array(z.string()).optional(),
        cwd: z.string().optional(),
        readonly: z.boolean().optional(),
        wait_ms: z.number().int().min(500).max(15000).optional(),
        max_duration_sec: z.number().int().min(1).max(3600).optional(),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: false,
      },
    },
    withMcpGuardrails(
      async (args) => {
        const clampedDurationSec =
          args.max_duration_sec !== undefined
            ? Math.min(args.max_duration_sec, deps.config.codexMaxDurationSec)
            : undefined;
        const res = await workspaceExec({
          config: deps.config,
          slug: args.slug,
          command: args.command,
          args: args.args,
          cwd: args.cwd,
          readonly: args.readonly,
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
      (args) => ({
        ...buildGuardOptions(deps, `exec-${args.slug}`),
        requiredScope: 'write',
      }),
    ),
  );

  // 5. dispatch_runner
  server.registerTool(
    'dispatch_runner',
    {
      title: 'Dispatch Background Runner',
      description:
        'Start an asynchronous Codex SDK agent (codex_readonly or codex_write with auto-checkpoint) or background shell_task, returning job_id immediately.',
      inputSchema: {
        mode: z.enum(['codex_readonly', 'codex_write', 'shell_task']),
        slug: z.string().min(1),
        objective: z.string().min(1),
        resume_thread_id: z.string().optional(),
        model: z.string().optional(),
        reasoning_effort: z.enum(['minimal', 'low', 'medium', 'high', 'xhigh']).optional(),
        allow_network: z.boolean().optional(),
        max_duration_sec: z.number().int().min(10).max(3600).optional(),
        token_budget: z.number().int().min(1000).max(10000000).optional(),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        openWorldHint: false,
      },
    },
    withMcpGuardrails(
      async (args, extra) => {
        const actor = getToolActor(deps, extra);
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
          runner_type: args.mode,
          status: 'queued',
          command_or_objective: deps.scrubber.scrub(args.objective),
          codex_thread_id: args.resume_thread_id ?? null,
        });

        deps.repos.audit.record({
          actor,
          action: 'runner.dispatch',
          target: `${slug}:${jobId}`,
          status: 'success',
          details: { mode: args.mode },
        });

        const effectiveMaxDurationSec = Math.min(
          args.max_duration_sec ?? deps.config.codexMaxDurationSec,
          deps.config.codexMaxDurationSec,
        );
        const effectiveTokenBudget = Math.min(
          args.token_budget ?? deps.config.codexTokenBudget,
          deps.config.codexTokenBudget,
        );

        if (args.mode === 'shell_task') {
          launchBackgroundShellTask(deps, {
            jobId,
            slug,
            workspaceDir: realWorkspaceRoot,
            command: args.objective,
            maxDurationSec: effectiveMaxDurationSec,
          });
        } else {
          void deps.codexRunner
            .run({
              jobId,
              workspaceSlug: slug,
              workspaceDir: realWorkspaceRoot,
              mode: args.mode === 'codex_write' ? 'write' : 'readonly',
              objective: args.objective,
              resumeThreadId: args.resume_thread_id,
              model: args.model,
              reasoningEffort: args.reasoning_effort,
              allowNetwork: args.allow_network,
              maxDurationSec: effectiveMaxDurationSec,
              tokenBudget: effectiveTokenBudget,
            })
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
          `Dispatched ${args.mode} job on workspace "${slug}".`,
          `job_id: ${jobId}`,
          `status: queued`,
          `Poll with job_status(job_id="${jobId}").`,
        ].join('\n');
      },
      (args) => ({
        ...buildGuardOptions(deps, `dispatch-${args.slug}`),
        requiredScope: 'write',
      }),
    ),
  );

  // 6. job_status
  server.registerTool(
    'job_status',
    {
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
    },
    withMcpGuardrails(
      async (args, extra) => {
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
        const eventLines = events.map(
          (ev) => `[#${ev.seq} ${ev.type}] ${ev.message}`,
        );

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
      (args) => ({
        ...buildGuardOptions(deps, `job-${args.job_id}`),
        requiredScope: args.cancel ? 'write' : 'read',
      }),
    ),
  );
}
