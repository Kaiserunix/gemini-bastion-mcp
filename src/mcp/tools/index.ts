import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { MCP_TOOL_NAMES, McpToolRegistry, type McpToolContractName } from '../registry.js';
import { getApprovalPolicy, type McpToolDeps } from './context.js';
import { registerExecRunnerTools } from './execRunnerTools.js';
import { registerInfraPublishTools } from './infraPublishTools.js';
import { registerWorkspaceTools } from './workspaceTools.js';

export type { McpToolDeps } from './context.js';
export { MCP_TOOL_NAMES, McpToolRegistry, type McpToolContractName };

/**
 * Builds the contract-enforcing McpToolRegistry populated with the exact 10
 * omni-mcp-gateway tools.
 */
export function createMcpToolRegistry(deps: McpToolDeps): McpToolRegistry {
  const registry = new McpToolRegistry({
    policy: getApprovalPolicy(deps),
    trustSandboxHints: deps.config.mcpTrustSandboxHints,
  });
  registerWorkspaceTools(registry, deps);
  registerExecRunnerTools(registry, deps);
  registerInfraPublishTools(registry, deps);
  return registry;
}

/**
 * Registers the exact 10-tool omni-mcp-gateway contract on an McpServer instance.
 */
export function registerAllMcpTools(server: McpServer, deps: McpToolDeps): void {
  const registry = createMcpToolRegistry(deps);
  registry.attachToServer(server, { requireCompleteContract: true });
}
