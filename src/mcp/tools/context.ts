import type { CloudflareService } from '../../core/cloudflareService.js';
import type { CodexSdkRunner } from '../../core/codexRunner.js';
import type { DownstreamMcpBridge } from '../../core/downstreamMcpBridge.js';
import type { GitHubService } from '../../core/githubService.js';
import type { WorkspaceLockManager } from '../../core/workspaceLock.js';
import type { GatewayDatabase } from '../../db/sqlite.js';
import type { Repositories } from '../../db/repositories/index.js';
import type { AuditEventPublisher } from '../../security/auditSink.js';
import type { PolicyEvaluatorPort } from '../../security/policyEvaluator.js';
import type { GatewayConfig, ScrubberLike } from '../../types.js';
import type { GuardTextOutputOptions } from '../outputGuard.js';

export interface McpToolDeps {
  config: GatewayConfig;
  db: GatewayDatabase;
  repos: Repositories;
  scrubber: ScrubberLike;
  lockManager: WorkspaceLockManager;
  githubService: GitHubService;
  cloudflareService: CloudflareService;
  downstreamBridge: DownstreamMcpBridge;
  codexRunner: CodexSdkRunner;
  actor?: string;
  policyEvaluator?: PolicyEvaluatorPort;
  auditPublisher?: AuditEventPublisher;
  notifyWebhook?: (event: string, payload: Record<string, unknown>) => Promise<void>;
}

const GUARD_LABEL_TOOL_PREFIXES: ReadonlyArray<readonly [string, string]> = [
  ['workspace-', 'workspace_manage'],
  ['explore-', 'code_explore'],
  ['patch-', 'code_patch'],
  ['exec-', 'workspace_exec'],
  ['dispatch-', 'dispatch_runner'],
  ['job-', 'job_status'],
  ['github-', 'github_inspect'],
  ['infra-', 'infra_inspect'],
  ['stage-', 'stage_mutation_plan'],
  ['publish-', 'publish_changes'],
];

export function inferToolNameFromGuardLabel(label: string): string | undefined {
  for (const [prefix, toolName] of GUARD_LABEL_TOOL_PREFIXES) {
    if (label.startsWith(prefix)) {
      return toolName;
    }
  }
  return undefined;
}

export function buildGuardOptions(
  deps: McpToolDeps,
  label: string,
  untrustedSource?: string,
  toolName?: string,
): GuardTextOutputOptions {
  return {
    scrubber: deps.scrubber,
    artifactsDir: deps.config.artifactsDir,
    workspacesDir: deps.config.workspacesDir,
    label,
    toolName: toolName ?? inferToolNameFromGuardLabel(label),
    defaultActor: deps.actor,
    defaultBranchResolver: (slug: string) => deps.repos.workspaces.getWorkspace(slug)?.default_branch,
    policyEvaluator: deps.policyEvaluator,
    maxBytes: deps.config.inlineOutputMaxBytes ?? 60_000,
    untrustedSource,
  };
}

export function getToolActor(deps: McpToolDeps, extra?: { authInfo?: { clientId?: string } }): string {
  return extra?.authInfo?.clientId ?? deps.actor ?? 'mcp-operator';
}
