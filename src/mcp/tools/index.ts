import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { McpToolDeps } from './context.js';
import { registerExecRunnerTools } from './execRunnerTools.js';
import { registerInfraPublishTools } from './infraPublishTools.js';
import { registerWorkspaceTools } from './workspaceTools.js';

export type { McpToolDeps } from './context.js';

export const MCP_TOOL_NAMES = [
  'workspace_manage',
  'code_explore',
  'code_patch',
  'workspace_exec',
  'dispatch_runner',
  'job_status',
  'github_inspect',
  'infra_inspect',
  'stage_mutation_plan',
  'publish_changes',
] as const;

/**
 * Registers the exact 10-tool omni-mcp-gateway contract on an McpServer instance.
 */
export function registerAllMcpTools(server: McpServer, deps: McpToolDeps): void {
  registerWorkspaceTools(server, deps);
  registerExecRunnerTools(server, deps);
  registerInfraPublishTools(server, deps);
}
