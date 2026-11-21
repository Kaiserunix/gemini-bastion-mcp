import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { z, ZodRawShape } from 'zod';
import {
  defaultApprovalGatePolicy,
  type ApprovalGatePolicy,
  type RequiredMcpScope,
} from '../policy/index.js';
import {
  withMcpGuardrails,
  type GuardTextOutputOptions,
  type McpHandlerExtraLike,
  type OutputGuardDeps,
} from './outputGuard.js';

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

export type McpToolContractName = (typeof MCP_TOOL_NAMES)[number];

const ALLOWED_TOOL_NAME_SET = new Set<string>(MCP_TOOL_NAMES);

export interface McpToolAnnotations {
  readOnlyHint: boolean;
  destructiveHint: boolean;
  openWorldHint: boolean;
}

export interface RegisteredMcpToolDefinition<TShape extends ZodRawShape = ZodRawShape> {
  readonly name: McpToolContractName;
  readonly title: string;
  readonly description: string;
  readonly inputSchema: TShape;
  readonly annotations: McpToolAnnotations;
  readonly guardDeps: OutputGuardDeps<z.infer<z.ZodObject<TShape>>, McpHandlerExtraLike>;
  readonly requiredScope?:
    | RequiredMcpScope
    | ((args: z.infer<z.ZodObject<TShape>>) => RequiredMcpScope);
  readonly handler: (
    args: z.infer<z.ZodObject<TShape>>,
    extra: McpHandlerExtraLike,
  ) => Promise<unknown> | unknown;
}

export interface McpToolRegistryOptions {
  policy?: ApprovalGatePolicy;
}

/**
 * Contract-enforcing MCP tool registry.
 *
 * Enforces mandatory architecture guardrails fail-closed:
 * 1. Only the exact 10 contract tools (`MCP_TOOL_NAMES`) may be registered.
 * 2. Duplicate tool registrations are rejected.
 * 3. Only `publish_changes` may declare `destructiveHint: true`.
 * 4. Every tool handler is uniformly wrapped with `withMcpGuardrails` + `ApprovalGatePolicy`.
 */
export class McpToolRegistry {
  private readonly definitions = new Map<McpToolContractName, RegisteredMcpToolDefinition<ZodRawShape>>();
  private readonly policy: ApprovalGatePolicy;

  constructor(options: McpToolRegistryOptions = {}) {
    this.policy = options.policy ?? defaultApprovalGatePolicy;
  }

  register<TShape extends ZodRawShape>(definition: RegisteredMcpToolDefinition<TShape>): this {
    if (!ALLOWED_TOOL_NAME_SET.has(definition.name)) {
      throw new Error(
        `Refusing to register non-contract MCP tool "${String(definition.name)}". Exact 10-tool surface is enforced.`,
      );
    }
    if (this.definitions.has(definition.name)) {
      throw new Error(`Duplicate MCP tool registration for "${definition.name}".`);
    }
    if (definition.name !== 'publish_changes' && definition.annotations.destructiveHint) {
      throw new Error(
        `Guardrail violation: only "publish_changes" may declare destructiveHint: true (got "${definition.name}").`,
      );
    }
    if (definition.name === 'publish_changes' && !definition.annotations.destructiveHint) {
      throw new Error('Guardrail violation: "publish_changes" must declare destructiveHint: true.');
    }

    this.definitions.set(
      definition.name,
      definition as unknown as RegisteredMcpToolDefinition<ZodRawShape>,
    );
    return this;
  }

  listRegisteredNames(): McpToolContractName[] {
    return Array.from(this.definitions.keys());
  }

  get(name: McpToolContractName): RegisteredMcpToolDefinition<ZodRawShape> | undefined {
    return this.definitions.get(name);
  }

  /**
   * Attaches all registered tools onto an `McpServer`, enforcing the complete 10-tool contract.
   */
  attachToServer(server: McpServer, options: { requireCompleteContract?: boolean } = {}): void {
    const requireComplete = options.requireCompleteContract ?? true;
    if (requireComplete) {
      const missing = MCP_TOOL_NAMES.filter((name) => !this.definitions.has(name));
      if (missing.length > 0) {
        throw new Error(
          `Incomplete MCP tool registry; missing contract tool(s): ${missing.join(', ')}`,
        );
      }
    }

    for (const def of this.definitions.values()) {
      const rawGuardDeps = def.guardDeps;
      const guardDepsWithPolicy: OutputGuardDeps<Record<string, unknown>, McpHandlerExtraLike> =
        typeof rawGuardDeps === 'function'
          ? (args, extra): GuardTextOutputOptions => ({
              ...rawGuardDeps(args, extra),
              policy: this.policy,
            })
          : { ...rawGuardDeps, policy: this.policy };

      server.registerTool(
        def.name,
        {
          title: def.title,
          description: def.description,
          inputSchema: def.inputSchema,
          annotations: def.annotations,
        },
        withMcpGuardrails(def.handler, guardDepsWithPolicy, def.requiredScope),
      );
    }
  }
}
