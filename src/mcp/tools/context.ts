import type { CloudflareService } from '../../core/cloudflareService.js';
import type { DownstreamMcpBridge } from '../../core/downstreamMcpBridge.js';
import type { GitHubService } from '../../core/githubService.js';
import type { WorkspaceLockManager } from '../../core/workspaceLock.js';
import type { GatewayDatabase } from '../../db/sqlite.js';
import type { Repositories } from '../../db/repositories/index.js';
import type { AgentRunner, GatewayConfig, ScrubberLike } from '../../types.js';
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
  agentRunner: AgentRunner;
  actor?: string;
  notifyWebhook?: (event: string, payload: Record<string, unknown>) => Promise<void>;
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
    maxBytes: deps.config.inlineOutputMaxBytes ?? 60_000,
    untrustedSource,
    toolName: toolName ?? label,
    onToolUsage: (metric) => {
      deps.repos?.usage?.recordToolCall(metric);
    },
  };
}

export function getToolActor(deps: McpToolDeps, extra?: { authInfo?: { clientId?: string } }): string {
  return extra?.authInfo?.clientId ?? deps.actor ?? 'mcp-operator';
}
