import { z } from 'zod';
import type { StageCloudflarePlanInput } from '../../core/cloudflareService.js';
import { resolveSafeWorkspacePath, resolveWorkspaceRoot } from '../../core/workspaceLock.js';
import { buildSandboxedEnv, runSubprocess } from '../../utils/exec.js';
import type { McpToolRegistry } from '../registry.js';
import {
  buildGuardOptions,
  getToolActor,
  getWorkspaceAdapter,
  type McpToolDeps,
} from './context.js';

async function getChangedWorkspaceFiles(
  workspaceDir: string,
  baseBranch?: string,
): Promise<string[]> {
  const files = new Set<string>();

  const res = await runSubprocess({
    command: 'git',
    args: ['status', '--porcelain'],
    cwd: workspaceDir,
    env: buildSandboxedEnv(),
    timeoutMs: 5000,
  });
  if (res.exitCode === 0) {
    for (const rawLine of res.stdout.split(/\r?\n/)) {
      if (rawLine.length < 4) continue;
      let filePart = rawLine.slice(3).trim();
      const arrowIdx = filePart.indexOf(' -> ');
      if (arrowIdx !== -1) {
        filePart = filePart.slice(arrowIdx + 4).trim();
      }
      if (filePart.startsWith('"') && filePart.endsWith('"')) {
        filePart = filePart.slice(1, -1);
      }
      if (filePart) files.add(filePart);
    }
  }

  // Also include committed-but-unpushed branch diff files
  if (
    baseBranch !== undefined &&
    (baseBranch.startsWith('-') || !/^[A-Za-z0-9._/-]+$/.test(baseBranch) || baseBranch.includes('..'))
  ) {
    throw new Error(`Invalid base_branch "${baseBranch}": unsafe git ref characters.`);
  }
  const candidates = baseBranch
    ? [`${baseBranch}..HEAD`, `origin/${baseBranch}..HEAD`, '@{u}..HEAD']
    : ['@{u}..HEAD', 'origin/main..HEAD', 'main..HEAD'];

  for (const range of candidates) {
    const diffRes = await runSubprocess({
      command: 'git',
      args: ['diff', '--name-only', range, '--'],
      cwd: workspaceDir,
      env: buildSandboxedEnv(),
      timeoutMs: 5000,
    });
    if (diffRes.exitCode === 0) {
      for (const line of diffRes.stdout.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (trimmed) files.add(trimmed);
      }
      break;
    }
  }

  return Array.from(files);
}

export function registerInfraPublishTools(registry: McpToolRegistry, deps: McpToolDeps): void {
  const wsAdapter = getWorkspaceAdapter(deps);

  // 7. github_inspect
  registry.register({
    name: 'github_inspect',
    title: 'Inspect GitHub PR, Issue, or Actions',
    description:
      'Read-only GitHub inspection for Pull Requests (metadata, files, diff, checks, failed Actions logs), Issues + comments, or Actions workflow failures. External data is wrapped in untrusted boundaries.',
    inputSchema: {
      mode: z.enum(['pr', 'issue', 'workflow_failure']),
      repo: z.string().min(1),
      pr_number: z.number().int().positive().optional(),
      issue_number: z.number().int().positive().optional(),
      run_id: z.number().int().positive().optional(),
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
    guardDeps: (args) => ({
      ...buildGuardOptions(deps, `github-${args.mode}`, `github:${args.mode}:${args.repo}`),
      requiredScope: 'read',
    }),
    handler: async (args) => {
      if (args.mode === 'pr') {
        if (!args.pr_number) {
          throw new Error('github_inspect mode "pr" requires "pr_number".');
        }
        const res = await deps.githubService.inspectPr(args.repo, args.pr_number);
        return res.summaryText;
      }
      if (args.mode === 'issue') {
        if (!args.issue_number) {
          throw new Error('github_inspect mode "issue" requires "issue_number".');
        }
        const res = await deps.githubService.inspectIssue(args.repo, args.issue_number);
        return res.summaryText;
      }
      const res = await deps.githubService.inspectWorkflowFailure(args.repo, args.run_id);
      return res.summaryText;
    },
  });

  // 8. infra_inspect
  registry.register({
    name: 'infra_inspect',
    title: 'Inspect Infrastructure & Downstream MCPs',
    description:
      'Strictly read-only inspection of Cloudflare resources (zones, dns_records, workers, pages, kv_namespaces, d1_databases, waf_rules, worker_tail_logs) and Downstream MCP-2 servers (downstream_list, downstream_call for readonlyTools only).',
    inputSchema: {
      action: z.enum([
        'zones',
        'dns_records',
        'workers',
        'pages',
        'kv_namespaces',
        'd1_databases',
        'waf_rules',
        'worker_tail_logs',
        'downstream_list',
        'downstream_call',
      ]),
      account_id: z.string().optional(),
      zone_id: z.string().optional(),
      zone_name: z.string().optional(),
      name: z.string().optional(),
      type: z.string().optional(),
      script_name: z.string().optional(),
      project_name: z.string().optional(),
      namespace_id: z.string().optional(),
      database_id: z.string().optional(),
      phase: z.string().optional(),
      limit: z.number().int().min(1).max(200).optional(),
      server_name: z.string().optional(),
      tool_name: z.string().optional(),
      args: z.record(z.unknown()).optional(),
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
    guardDeps: (args) => ({
      ...buildGuardOptions(deps, `infra-${args.action}`),
      requiredScope: 'read',
    }),
    handler: async (args) => {
      if (args.action === 'downstream_list') {
        const servers = await deps.downstreamBridge.listDownstreamTools(args.server_name);
        if (servers.length === 0) {
          return 'No downstream MCP-2 servers configured.';
        }
        return JSON.stringify(servers, null, 2);
      }

      if (args.action === 'downstream_call') {
        if (!args.server_name || !args.tool_name) {
          throw new Error('downstream_call requires both "server_name" and "tool_name".');
        }
        const res = await deps.downstreamBridge.callReadonlyTool(
          args.server_name,
          args.tool_name,
          args.args ?? {},
        );
        return res.wrappedText;
      }

      const res = await deps.cloudflareService.inspectResource(args.action, {
        accountId: args.account_id,
        zoneId: args.zone_id,
        zoneName: args.zone_name,
        name: args.name,
        type: args.type,
        scriptName: args.script_name,
        projectName: args.project_name,
        namespaceId: args.namespace_id,
        databaseId: args.database_id,
        phase: args.phase,
        limit: args.limit,
      });
      return res.summaryText;
    },
  });

  // 9. stage_mutation_plan
  registry.register({
    name: 'stage_mutation_plan',
    title: 'Stage Infrastructure Mutation Plan',
    description:
      'Stage a Cloudflare mutation (DNS, WAF, D1, KV put/delete, Worker route create/update/delete) or a Downstream MCP-2 mutating tool call with pre-change rollback snapshot and 15-minute TTL. Performs zero external writes until publish_changes(action="execute_staged_plan") is called.',
    inputSchema: {
      target: z.enum(['cloudflare', 'downstream_mcp']),
      // Cloudflare fields
      mutation_type: z
        .enum([
          'dns_record_create',
          'dns_record_update',
          'dns_record_delete',
          'waf_rule_update',
          'd1_sql_mutation',
          'kv_put',
          'kv_delete',
          'worker_route_create',
          'worker_route_update',
          'worker_route_delete',
        ])
        .optional(),
      zone_id: z.string().optional(),
      record_id: z.string().optional(),
      record: z
        .object({
          type: z.string().min(1),
          name: z.string().min(1),
          content: z.string().min(1),
          ttl: z.number().int().min(1).optional(),
          proxied: z.boolean().optional(),
          priority: z.number().int().min(0).optional(),
          comment: z.string().optional(),
        })
        .optional(),
      ruleset_id: z.string().optional(),
      phase: z.string().optional(),
      description: z.string().optional(),
      rules: z.array(z.record(z.unknown())).optional(),
      account_id: z.string().optional(),
      database_id: z.string().optional(),
      sql: z.string().optional(),
      params: z.array(z.string()).optional(),
      rollback_sql: z.string().optional(),
      // Cloudflare KV fields
      namespace_id: z.string().optional(),
      key: z.string().optional(),
      value: z.string().optional(),
      expiration: z.number().int().positive().optional(),
      expiration_ttl: z.number().int().min(60).optional(),
      metadata: z.record(z.unknown()).optional(),
      // Cloudflare Worker route fields
      route_id: z.string().optional(),
      pattern: z.string().optional(),
      script: z.string().optional(),
      // Downstream MCP-2 fields
      server_name: z.string().optional(),
      tool_name: z.string().optional(),
      args: z.record(z.unknown()).optional(),
      reason: z.string().optional(),
      rollback_tool_name: z.string().optional(),
      rollback_args: z.record(z.unknown()).optional(),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
    guardDeps: (args) => ({
      ...buildGuardOptions(deps, `stage-${args.target}`),
      requiredScope: 'write',
    }),
    handler: async (args, extra) => {
      const actor = getToolActor(deps, extra);

      if (args.target === 'downstream_mcp') {
        if (!args.server_name || !args.tool_name || !args.reason) {
          throw new Error(
            'stage_mutation_plan for downstream_mcp requires "server_name", "tool_name", and "reason".',
          );
        }
        const rollbackSpec = args.rollback_tool_name
          ? { toolName: args.rollback_tool_name, args: args.rollback_args ?? {} }
          : undefined;
        const plan = deps.downstreamBridge.stageMutatingToolPlan(
          deps.repos.plans,
          args.server_name,
          args.tool_name,
          args.args ?? {},
          args.reason,
          rollbackSpec,
        );
        deps.repos.audit.record({
          actor,
          action: 'stage_mutation_plan.downstream_mcp',
          target: plan.plan_id,
          status: 'success',
          details: {
            server: args.server_name,
            tool: args.tool_name,
            has_rollback: plan.rollback_payload !== null,
          },
        });
        return [
          `# Staged Mutation Plan: ${plan.plan_id}`,
          `Target: ${plan.target_service}`,
          `Expires At: ${new Date(plan.expires_at).toISOString()} (15m TTL)`,
          `Has Rollback Snapshot: ${plan.rollback_payload !== null}`,
          '',
          plan.summary_diff_text,
          '',
          `To execute: publish_changes(action="execute_staged_plan", plan_id="${plan.plan_id}")`,
        ].join('\n');
      }

      if (!args.mutation_type) {
        throw new Error('stage_mutation_plan for cloudflare requires "mutation_type".');
      }

      let cfInput: StageCloudflarePlanInput;
      switch (args.mutation_type) {
        case 'dns_record_create':
          cfInput = {
            type: 'dns_record_create',
            zoneId: args.zone_id ?? '',
            record: args.record!,
          };
          break;
        case 'dns_record_update':
          cfInput = {
            type: 'dns_record_update',
            zoneId: args.zone_id ?? '',
            recordId: args.record_id ?? '',
            record: args.record!,
          };
          break;
        case 'dns_record_delete':
          cfInput = {
            type: 'dns_record_delete',
            zoneId: args.zone_id ?? '',
            recordId: args.record_id ?? '',
          };
          break;
        case 'waf_rule_update':
          cfInput = {
            type: 'waf_rule_update',
            zoneId: args.zone_id ?? '',
            rulesetId: args.ruleset_id,
            phase: args.phase,
            description: args.description,
            rules: args.rules ?? [],
          };
          break;
        case 'd1_sql_mutation':
          cfInput = {
            type: 'd1_sql_mutation',
            accountId: args.account_id,
            databaseId: args.database_id ?? '',
            sql: args.sql ?? '',
            params: args.params,
            rollbackSql: args.rollback_sql,
          };
          break;
        case 'kv_put':
          cfInput = {
            type: 'kv_put',
            accountId: args.account_id,
            namespaceId: args.namespace_id ?? '',
            key: args.key ?? '',
            value: args.value ?? '',
            expiration: args.expiration,
            expirationTtl: args.expiration_ttl,
            metadata: args.metadata,
          };
          break;
        case 'kv_delete':
          cfInput = {
            type: 'kv_delete',
            accountId: args.account_id,
            namespaceId: args.namespace_id ?? '',
            key: args.key ?? '',
          };
          break;
        case 'worker_route_create':
          cfInput = {
            type: 'worker_route_create',
            zoneId: args.zone_id ?? '',
            pattern: args.pattern ?? '',
            script: args.script,
          };
          break;
        case 'worker_route_update':
          cfInput = {
            type: 'worker_route_update',
            zoneId: args.zone_id ?? '',
            routeId: args.route_id ?? '',
            pattern: args.pattern ?? '',
            script: args.script,
          };
          break;
        case 'worker_route_delete':
          cfInput = {
            type: 'worker_route_delete',
            zoneId: args.zone_id ?? '',
            routeId: args.route_id ?? '',
          };
          break;
      }

      const plan = await deps.cloudflareService.stageCloudflarePlan(deps.repos.plans, cfInput);
      deps.repos.audit.record({
        actor,
        action: 'stage_mutation_plan.cloudflare',
        target: plan.plan_id,
        status: 'success',
        details: { mutation_type: args.mutation_type },
      });

      return [
        `# Staged Mutation Plan: ${plan.plan_id}`,
        `Target: ${plan.target_service}`,
        `Expires At: ${new Date(plan.expires_at).toISOString()} (15m TTL)`,
        `Has Rollback Snapshot: ${plan.rollback_payload !== null}`,
        '',
        plan.summary_diff_text,
        '',
        `To execute: publish_changes(action="execute_staged_plan", plan_id="${plan.plan_id}")`,
      ].join('\n');
    },
  });

  // 10. publish_changes (ONLY destructive / open-world mutation exit)
  registry.register({
    name: 'publish_changes',
    title: 'Publish External Changes',
    description:
      'Single controlled exit for external mutations: create/update GitHub PR (feature branch only, draft default), submit PR review with suggestions, post GitHub comment, deploy Cloudflare Worker/Pages, execute staged plan, or rollback executed plan.',
    inputSchema: {
      action: z.enum([
        'github_pr',
        'github_pr_review',
        'github_comment',
        'cloudflare_worker_deploy',
        'cloudflare_pages_deploy',
        'execute_staged_plan',
        'rollback_plan',
      ]),
      // GitHub PR / comment / review fields
      slug: z.string().optional(),
      repo: z.string().optional(),
      branch_name: z.string().optional(),
      base_branch: z.string().optional(),
      title: z.string().optional(),
      body: z.string().optional(),
      commit_message: z.string().optional(),
      draft: z.boolean().optional(),
      skip_validation: z.boolean().optional(),
      pr_number: z.number().int().positive().optional(),
      issue_number: z.number().int().positive().optional(),
      event: z.enum(['COMMENT', 'REQUEST_CHANGES', 'APPROVE']).optional(),
      comments: z
        .array(
          z.object({
            path: z.string().min(1),
            line: z.number().int().positive().optional(),
            side: z.enum(['LEFT', 'RIGHT']).optional(),
            start_line: z.number().int().positive().optional(),
            start_side: z.enum(['LEFT', 'RIGHT']).optional(),
            position: z.number().int().positive().optional(),
            body: z.string().optional(),
            suggestion: z.string().optional(),
          }),
        )
        .optional(),
      // Cloudflare deploy fields
      target: z.enum(['preview', 'production']).optional(),
      message: z.string().optional(),
      env: z.string().optional(),
      config_path: z.string().optional(),
      project_name: z.string().optional(),
      directory: z.string().optional(),
      branch: z.string().optional(),
      // Staged plan fields
      plan_id: z.string().optional(),
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: true,
    },
    guardDeps: (args) => ({
      ...buildGuardOptions(deps, `publish-${args.action}`),
      requiredScope: 'write',
    }),
    handler: async (args, extra) => {
      const actor = getToolActor(deps, extra);

      switch (args.action) {
        case 'github_pr': {
          if (!args.slug || !args.repo || !args.branch_name || !args.title) {
            throw new Error(
              'github_pr requires "slug", "repo", "branch_name", and "title".',
            );
          }
          const { slug, realWorkspaceRoot } = resolveWorkspaceRoot(
            deps.config.workspacesDir,
            args.slug,
          );

          return deps.lockManager.withWriteLock(slug, async () => {
            if (!args.skip_validation) {
              const changed = await getChangedWorkspaceFiles(realWorkspaceRoot, args.base_branch);
              if (changed.length > 0) {
                const validation = await wsAdapter.runValidationPipeline({
                  workspaceDir: realWorkspaceRoot,
                  changedFiles: changed,
                  scrubber: deps.scrubber,
                  skipL2: true,
                });
                if (!validation.passed) {
                  deps.repos.audit.record({
                    actor,
                    action: 'publish_changes.github_pr',
                    target: `${args.repo}:${args.branch_name}`,
                    status: 'denied',
                    details: { reason: 'validation_failed', summary: validation.summary },
                  });
                  throw new Error(`Pre-publish validation failed: ${validation.summary}`);
                }
              }
            }

            const res = await deps.githubService.createOrUpdatePr({
              workspacePath: realWorkspaceRoot,
              repo: args.repo!,
              branchName: args.branch_name!,
              baseBranch: args.base_branch,
              title: args.title!,
              body: args.body,
              commitMessage: args.commit_message,
              draft: args.draft,
            });

            deps.repos.audit.record({
              actor,
              action: 'publish_changes.github_pr',
              target: `${res.repo}#${res.prNumber}`,
              status: 'success',
              details: {
                branch: res.branchName,
                base: res.baseBranch,
                draft: res.draft,
                updated: res.updated,
              },
            });
            await deps.notifyWebhook?.('publish_changes.github_pr', {
              summary: `${res.updated ? 'Updated' : 'Created'} PR ${res.repo}#${res.prNumber} (${res.branchName} -> ${res.baseBranch})`,
              url: res.url,
            });

            return JSON.stringify(res, null, 2);
          });
        }

        case 'github_pr_review': {
          if (!args.repo || !args.pr_number || !args.event) {
            throw new Error('github_pr_review requires "repo", "pr_number", and "event".');
          }
          const res = await deps.githubService.submitPrReview(args.repo, args.pr_number, {
            event: args.event,
            body: args.body,
            comments: args.comments,
          });
          deps.repos.audit.record({
            actor,
            action: 'publish_changes.github_pr_review',
            target: `${res.repo}#${res.prNumber}`,
            status: 'success',
            details: { review_id: res.reviewId, event: args.event, comments: res.commentCount },
          });
          await deps.notifyWebhook?.('publish_changes.github_pr_review', {
            summary: `Submitted ${args.event} review on ${res.repo}#${res.prNumber}`,
            url: res.htmlUrl,
          });
          return JSON.stringify(res, null, 2);
        }

        case 'github_comment': {
          if (!args.repo || !args.issue_number || !args.body) {
            throw new Error('github_comment requires "repo", "issue_number", and "body".');
          }
          const res = await deps.githubService.postIssueOrPrComment(
            args.repo,
            args.issue_number,
            args.body,
          );
          deps.repos.audit.record({
            actor,
            action: 'publish_changes.github_comment',
            target: `${res.repo}#${res.issueNumber}`,
            status: 'success',
            details: { comment_id: res.commentId },
          });
          await deps.notifyWebhook?.('publish_changes.github_comment', {
            summary: `Posted comment on ${res.repo}#${res.issueNumber}`,
            url: res.htmlUrl,
          });
          return JSON.stringify(res, null, 2);
        }

        case 'cloudflare_worker_deploy': {
          if (!args.slug) {
            throw new Error('cloudflare_worker_deploy requires "slug".');
          }
          const { slug, realWorkspaceRoot } = resolveWorkspaceRoot(
            deps.config.workspacesDir,
            args.slug,
          );
          const safeConfigPath = args.config_path
            ? resolveSafeWorkspacePath(deps.config.workspacesDir, slug, args.config_path, {
                allowRoot: false,
                checkSensitive: true,
              }).relativePath
            : undefined;
          const res = await deps.lockManager.withReadLock(slug, () =>
            deps.cloudflareService.deployWorker(realWorkspaceRoot, {
              target: args.target ?? 'preview',
              message: args.message,
              env: args.env,
              configPath: safeConfigPath,
            }),
          );
          deps.repos.audit.record({
            actor,
            action: 'publish_changes.cloudflare_worker_deploy',
            target: slug,
            status: 'success',
            details: { target: res.target, url: res.deploymentUrl },
          });
          await deps.notifyWebhook?.('publish_changes.cloudflare_worker_deploy', {
            summary: `Deployed Cloudflare Worker (${res.target}) for ${slug}`,
            url: res.deploymentUrl,
          });
          return JSON.stringify(res, null, 2);
        }

        case 'cloudflare_pages_deploy': {
          if (!args.slug || !args.project_name || !args.directory) {
            throw new Error(
              'cloudflare_pages_deploy requires "slug", "project_name", and "directory".',
            );
          }
          const { slug, realWorkspaceRoot } = resolveWorkspaceRoot(
            deps.config.workspacesDir,
            args.slug,
          );
          const safeDir = resolveSafeWorkspacePath(
            deps.config.workspacesDir,
            slug,
            args.directory,
            { allowRoot: true, checkSensitive: true },
          ).relativePath;
          const res = await deps.lockManager.withReadLock(slug, () =>
            deps.cloudflareService.deployPages(realWorkspaceRoot, {
              projectName: args.project_name!,
              directory: safeDir,
              branch: args.branch,
              commitMessage: args.commit_message,
            }),
          );
          deps.repos.audit.record({
            actor,
            action: 'publish_changes.cloudflare_pages_deploy',
            target: `${slug}:${args.project_name}`,
            status: 'success',
            details: { url: res.deploymentUrl },
          });
          await deps.notifyWebhook?.('publish_changes.cloudflare_pages_deploy', {
            summary: `Deployed Cloudflare Pages "${args.project_name}" for ${slug}`,
            url: res.deploymentUrl,
          });
          return JSON.stringify(res, null, 2);
        }

        case 'execute_staged_plan': {
          if (!args.plan_id) {
            throw new Error('execute_staged_plan requires "plan_id".');
          }
          const existing = deps.repos.plans.getPlan(args.plan_id);
          let result: unknown;

          if (deps.planGate) {
            result = await deps.planGate.executePlan(args.plan_id, actor);
          } else {
            const isDownstream = existing?.target_service.startsWith('downstream_mcp:') ?? false;
            result = isDownstream
              ? await deps.downstreamBridge.executeStagedDownstreamPlan(
                  deps.repos.plans,
                  deps.repos.audit,
                  args.plan_id,
                  actor,
                )
              : await deps.cloudflareService.executeStagedCloudflarePlan(
                  deps.repos.plans,
                  deps.repos.audit,
                  args.plan_id,
                  actor,
                );
          }

          await deps.notifyWebhook?.('publish_changes.execute_staged_plan', {
            summary: `Executed staged plan ${args.plan_id} (${existing?.target_service ?? 'unknown'})`,
          });
          return JSON.stringify(result, null, 2);
        }

        case 'rollback_plan': {
          if (!args.plan_id) {
            throw new Error('rollback_plan requires "plan_id".');
          }
          const existing = deps.repos.plans.getPlan(args.plan_id);
          let res: unknown;

          if (deps.planGate) {
            res = await deps.planGate.rollbackPlan(args.plan_id, actor);
          } else {
            const isDownstream = existing?.target_service.startsWith('downstream_mcp:') ?? false;
            if (isDownstream && deps.downstreamBridge.rollbackExecutedDownstreamPlan) {
              res = await deps.downstreamBridge.rollbackExecutedDownstreamPlan(
                deps.repos.plans,
                deps.repos.audit,
                args.plan_id,
                actor,
              );
            } else {
              res = await deps.cloudflareService.rollbackExecutedPlan(
                deps.repos.plans,
                deps.repos.audit,
                args.plan_id,
                actor,
              );
            }
          }

          await deps.notifyWebhook?.('publish_changes.rollback_plan', {
            summary: `Rolled back executed plan ${args.plan_id}`,
          });
          return JSON.stringify(res, null, 2);
        }
      }
    },
  });
}
