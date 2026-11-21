import type { WorkspaceLockManager } from '../../core/workspaceLock.js';
import type { GatewayDatabase } from '../../db/sqlite.js';
import type { Repositories } from '../../db/repositories/index.js';
import {
  defaultApprovalGatePolicy,
  type ApprovalGatePolicy,
  type MutationPlanGate,
} from '../../policy/index.js';
import type { GatewayConfig, ScrubberLike } from '../../types.js';
import {
  defaultWorkspaceToolAdapter,
  type AgentRunnerAdapter,
  type CloudflareToolAdapter,
  type DownstreamMcpToolAdapter,
  type GitHubToolAdapter,
  type WorkspaceToolAdapter,
} from '../adapters/index.js';
import type { GuardTextOutputOptions } from '../outputGuard.js';

export interface McpToolDeps {
  config: GatewayConfig;
  db: GatewayDatabase;
  repos: Repositories;
  scrubber: ScrubberLike;
  lockManager: WorkspaceLockManager;
  githubService: GitHubToolAdapter;
  cloudflareService: CloudflareToolAdapter;
  downstreamBridge: DownstreamMcpToolAdapter;
  codexRunner: AgentRunnerAdapter;
  workspaceAdapter?: WorkspaceToolAdapter;
  approvalPolicy?: ApprovalGatePolicy;
  planGate?: MutationPlanGate;
  actor?: string;
  notifyWebhook?: (event: string, payload: Record<string, unknown>) => Promise<void>;
}

export function getWorkspaceAdapter(deps: McpToolDeps): WorkspaceToolAdapter {
  return deps.workspaceAdapter ?? defaultWorkspaceToolAdapter;
}

export function getApprovalPolicy(deps: McpToolDeps): ApprovalGatePolicy {
  return deps.approvalPolicy ?? defaultApprovalGatePolicy;
}

export function buildGuardOptions(
  deps: McpToolDeps,
  label: string,
  untrustedSource?: string,
): GuardTextOutputOptions {
  return {
    scrubber: deps.scrubber,
    artifactsDir: deps.config.artifactsDir,
    workspacesDir: deps.config.workspacesDir,
    label,
    maxBytes: deps.config.inlineOutputMaxBytes ?? 60_000,
    untrustedSource,
    policy: getApprovalPolicy(deps),
  };
}

export function getToolActor(deps: McpToolDeps, extra?: { authInfo?: { clientId?: string } }): string {
  return extra?.authInfo?.clientId ?? deps.actor ?? 'mcp-operator';
}
