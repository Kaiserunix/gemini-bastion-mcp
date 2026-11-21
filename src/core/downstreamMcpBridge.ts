import crypto from 'node:crypto';
import fs from 'node:fs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { z } from 'zod';
import type { AuditLogger } from '../auth/store.js';
import { wrapUntrustedData } from '../mcp/outputGuard.js';
import {
  defaultApprovalGatePolicy,
  type ApprovalGatePolicy,
  type DownstreamToolClassification,
  type MutationTargetAdapter,
  type PlanStore,
} from '../policy/index.js';
import type {
  DownstreamMcpServerConfig,
  GatewayConfig,
  MutationPlanRecord,
  ScrubberLike,
} from '../types.js';
import { buildSandboxedEnv } from '../utils/exec.js';
import { SecretScrubber } from '../utils/secretScrubber.js';

export const DEFAULT_DOWNSTREAM_PLAN_TTL_MS = 15 * 60 * 1000;

export type { DownstreamToolClassification };

export class DownstreamPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DownstreamPolicyError';
  }
}

export interface DownstreamToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface DownstreamMcpClientLike {
  listTools(): Promise<{ tools: DownstreamToolDescriptor[] }>;
  callTool(params: {
    name: string;
    arguments?: Record<string, unknown>;
  }): Promise<{
    content: Array<{ type: string; text?: string; [key: string]: unknown }>;
    isError?: boolean;
  }>;
  close(): Promise<void>;
}

export type DownstreamClientFactory = (
  server: DownstreamMcpServerConfig,
) => Promise<DownstreamMcpClientLike> | DownstreamMcpClientLike;

export interface DownstreamMcpBridgeOptions {
  servers?: DownstreamMcpServerConfig[];
  downstreamMcpsJson?: string;
  downstreamMcpsFile?: string;
  planTtlMs?: number;
  scrubber?: ScrubberLike;
  policy?: ApprovalGatePolicy;
  clientFactory?: DownstreamClientFactory;
}

export interface ListedDownstreamTool extends DownstreamToolDescriptor {
  classification: 'readonly' | 'mutating';
}

export interface ListedDownstreamServer {
  id: string;
  transport: 'http' | 'stdio';
  description?: string;
  connected: boolean;
  error?: string;
  readonlyTools: ListedDownstreamTool[];
  mutatingTools: ListedDownstreamTool[];
}

export interface DownstreamCallResult {
  serverName: string;
  toolName: string;
  wrappedText: string;
  rawText: string;
}

export interface ExecuteDownstreamPlanResult {
  planId: string;
  serverName: string;
  toolName: string;
  status: 'executed';
  wrappedText: string;
}

export interface RollbackDownstreamPlanResult {
  planId: string;
  serverName: string;
  toolName: string;
  status: 'rolled_back';
  wrappedText: string;
}

export interface DownstreamRollbackSpec {
  toolName: string;
  args?: Record<string, unknown>;
}

const serverConfigSchema = z
  .object({
    id: z.string().min(1),
    transport: z.enum(['http', 'stdio']),
    url: z.string().url().optional(),
    headers: z.record(z.string()).optional(),
    command: z.string().min(1).optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string()).optional(),
    description: z.string().optional(),
    enabled: z.boolean().optional(),
    timeoutMs: z.number().int().positive().optional(),
    readonlyTools: z.array(z.string()).default([]),
    mutatingTools: z.array(z.string()).default([]),
    deniedTools: z.array(z.string()).default([]),
  })
  .superRefine((val, ctx) => {
    if (val.transport === 'http' && !val.url) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `Downstream server "${val.id}" with transport "http" requires "url".`,
      });
    }
    if (val.transport === 'stdio' && !val.command) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `Downstream server "${val.id}" with transport "stdio" requires "command".`,
      });
    }
  });

function parseServersPayload(raw: unknown): DownstreamMcpServerConfig[] {
  if (Array.isArray(raw)) {
    return z.array(serverConfigSchema).parse(raw);
  }
  if (raw && typeof raw === 'object') {
    const obj = raw as Record<string, unknown>;
    if (Array.isArray(obj.servers)) {
      return z.array(serverConfigSchema).parse(obj.servers);
    }
    // Support keyed map { "cf-ops": { transport: "http", ... } }
    const entries = Object.entries(obj).map(([id, cfg]) => ({
      id,
      ...(cfg as Record<string, unknown>),
    }));
    return z.array(serverConfigSchema).parse(entries);
  }
  throw new Error('DOWNSTREAM_MCPS config must be a JSON array, { servers: [...] }, or keyed object.');
}

/**
 * Loads downstream MCP-2 server configs from explicit array, JSON string, or file path.
 * Returns an empty array cleanly when unconfigured.
 */
export function loadDownstreamServerConfigs(opts: {
  servers?: DownstreamMcpServerConfig[];
  downstreamMcpsJson?: string;
  downstreamMcpsFile?: string;
}): DownstreamMcpServerConfig[] {
  const configs: DownstreamMcpServerConfig[] = [];

  if (opts.servers) {
    configs.push(...z.array(serverConfigSchema).parse(opts.servers));
  }
  if (opts.downstreamMcpsFile && opts.downstreamMcpsFile.trim().length > 0) {
    if (!fs.existsSync(opts.downstreamMcpsFile)) {
      throw new Error(`DOWNSTREAM_MCPS_FILE not found: ${opts.downstreamMcpsFile}`);
    }
    const rawText = fs.readFileSync(opts.downstreamMcpsFile, 'utf8');
    if (rawText.trim().length > 0) {
      configs.push(...parseServersPayload(JSON.parse(rawText)));
    }
  }
  if (opts.downstreamMcpsJson && opts.downstreamMcpsJson.trim().length > 0) {
    configs.push(...parseServersPayload(JSON.parse(opts.downstreamMcpsJson)));
  }

  return configs.filter((s) => s.enabled !== false);
}

/**
 * Classifies a tool under a server's strict policy lists.
 * deniedTools always wins; unlisted tools are default-denied.
 */
export function classifyDownstreamTool(
  server: DownstreamMcpServerConfig,
  toolName: string,
  policy: ApprovalGatePolicy = defaultApprovalGatePolicy,
): DownstreamToolClassification {
  return policy.classifyDownstreamTool(server, toolName);
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number | undefined, label: string): Promise<T> {
  if (!timeoutMs || timeoutMs <= 0) return promise;
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`${label} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref?.();
    promise.then(
      (val) => {
        clearTimeout(timer);
        resolve(val);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

function extractMcpToolText(result: {
  content: Array<{ type: string; text?: string; [key: string]: unknown }>;
}): string {
  if (!Array.isArray(result.content) || result.content.length === 0) {
    return '';
  }
  return result.content
    .map((block) => {
      if (block.type === 'text' && typeof block.text === 'string') {
        return block.text;
      }
      return JSON.stringify(block);
    })
    .join('\n');
}

async function defaultClientFactory(
  server: DownstreamMcpServerConfig,
): Promise<DownstreamMcpClientLike> {
  const client = new Client({
    name: 'omni-mcp-gateway-federation',
    version: '1.0.0',
  });

  if (server.transport === 'http') {
    const transport = new StreamableHTTPClientTransport(new URL(server.url!), {
      requestInit: server.headers ? { headers: server.headers } : undefined,
    });
    await client.connect(transport);
  } else {
    const env = {
      ...buildSandboxedEnv(),
      ...(server.env ?? {}),
    };
    const transport = new StdioClientTransport({
      command: server.command!,
      args: server.args ?? [],
      env,
    });
    await client.connect(transport);
  }

  return client as unknown as DownstreamMcpClientLike;
}

/**
 * MCP-1 -> MCP-2 Federation Client (Policy Facade).
 * Enforces strict readonly / mutating / denied / default-deny tool classification,
 * two-phase staging for mutating tools, and untrusted boundary wrapping.
 */
export class DownstreamMcpBridge {
  private readonly servers = new Map<string, DownstreamMcpServerConfig>();
  private readonly clients = new Map<string, DownstreamMcpClientLike>();
  private readonly connectingClients = new Map<string, Promise<DownstreamMcpClientLike>>();
  private readonly toolCache = new Map<string, DownstreamToolDescriptor[]>();
  private readonly planTtlMs: number;
  private readonly scrubber: ScrubberLike;
  private readonly policy: ApprovalGatePolicy;
  private readonly clientFactory: DownstreamClientFactory;

  constructor(options: DownstreamMcpBridgeOptions = {}) {
    const loaded = loadDownstreamServerConfigs(options);
    for (const srv of loaded) {
      this.servers.set(srv.id, srv);
    }
    this.planTtlMs = options.planTtlMs ?? DEFAULT_DOWNSTREAM_PLAN_TTL_MS;
    this.scrubber = options.scrubber ?? new SecretScrubber();
    this.policy = options.policy ?? defaultApprovalGatePolicy;
    this.clientFactory = options.clientFactory ?? defaultClientFactory;
  }

  static fromConfig(
    config: Pick<
      GatewayConfig,
      'downstreamMcpsJson' | 'downstreamMcpsFile' | 'mutationPlanTtlSec'
    >,
    scrubber?: ScrubberLike,
    clientFactory?: DownstreamClientFactory,
    policy?: ApprovalGatePolicy,
  ): DownstreamMcpBridge {
    return new DownstreamMcpBridge({
      downstreamMcpsJson: config.downstreamMcpsJson,
      downstreamMcpsFile: config.downstreamMcpsFile,
      planTtlMs: config.mutationPlanTtlSec * 1000,
      scrubber,
      clientFactory,
      policy,
    });
  }

  getConfiguredServers(): DownstreamMcpServerConfig[] {
    return Array.from(this.servers.values());
  }

  private getServerOrThrow(serverName: string): DownstreamMcpServerConfig {
    const srv = this.servers.get(serverName);
    if (!srv) {
      throw new DownstreamPolicyError(
        `Downstream MCP server "${serverName}" is not configured or is disabled.`,
      );
    }
    return srv;
  }

  private async getOrConnectClient(server: DownstreamMcpServerConfig): Promise<DownstreamMcpClientLike> {
    const existing = this.clients.get(server.id);
    if (existing) return existing;

    const inFlight = this.connectingClients.get(server.id);
    if (inFlight) return inFlight;

    const rawConnectPromise = Promise.resolve(this.clientFactory(server));
    let timedOutOrFailed = false;

    const trackedPromise = withTimeout(
      rawConnectPromise,
      server.timeoutMs,
      `Connecting to downstream MCP "${server.id}"`,
    )
      .then((client) => {
        this.clients.set(server.id, client);
        return client;
      })
      .catch((err) => {
        timedOutOrFailed = true;
        // If rawConnectPromise resolves late after timeout, close it cleanly so sockets/subprocesses don't leak
        rawConnectPromise.then(
          (lateClient) => lateClient.close().catch(() => undefined),
          () => undefined,
        );
        throw err;
      })
      .finally(() => {
        if (this.connectingClients.get(server.id) === trackedPromise) {
          this.connectingClients.delete(server.id);
        }
        if (timedOutOrFailed) {
          this.toolCache.delete(server.id);
        }
      });

    this.connectingClients.set(server.id, trackedPromise);
    return trackedPromise;
  }

  private async evictClient(
    serverId: string,
    failedClient?: DownstreamMcpClientLike,
  ): Promise<void> {
    const current = this.clients.get(serverId);
    if (!current) return;
    if (failedClient && current !== failedClient) {
      return;
    }
    this.clients.delete(serverId);
    this.toolCache.delete(serverId);
    await current.close().catch(() => undefined);
  }

  private async withClientCall<T>(
    server: DownstreamMcpServerConfig,
    label: string,
    fn: (client: DownstreamMcpClientLike) => Promise<T>,
  ): Promise<T> {
    const client = await this.getOrConnectClient(server);
    try {
      return await withTimeout(fn(client), server.timeoutMs, label);
    } catch (err) {
      await this.evictClient(server.id, client);
      throw err;
    }
  }

  /**
   * Lists configured downstream servers and their allowed `readonly` and `mutating` tools.
   * Denied and unlisted tools are never exposed as callable.
   */
  async listDownstreamTools(serverName?: string): Promise<ListedDownstreamServer[]> {
    const targets = serverName
      ? [this.getServerOrThrow(serverName)]
      : Array.from(this.servers.values());

    const results: ListedDownstreamServer[] = [];

    for (const server of targets) {
      let remoteTools = this.toolCache.get(server.id);
      let connected = Boolean(remoteTools);
      let errorMsg: string | undefined;

      if (!remoteTools) {
        try {
          const listed = await this.withClientCall(
            server,
            `listTools on downstream MCP "${server.id}"`,
            (client) => client.listTools(),
          );
          remoteTools = listed.tools ?? [];
          this.toolCache.set(server.id, remoteTools);
          connected = true;
        } catch (err) {
          connected = false;
          errorMsg = this.scrubber.scrub(err instanceof Error ? err.message : String(err));
          remoteTools = [];
        }
      }

      const remoteMap = new Map<string, DownstreamToolDescriptor>();
      for (const tool of remoteTools) {
        remoteMap.set(tool.name, tool);
      }

      const readonlyTools: ListedDownstreamTool[] = [];
      for (const name of server.readonlyTools) {
        if (this.policy.classifyDownstreamTool(server, name) !== 'readonly') continue;
        const meta = remoteMap.get(name);
        readonlyTools.push({
          name,
          description: meta?.description
            ? this.scrubber.scrub(meta.description)
            : undefined,
          inputSchema: meta?.inputSchema,
          classification: 'readonly',
        });
      }

      const mutatingTools: ListedDownstreamTool[] = [];
      for (const name of server.mutatingTools) {
        if (this.policy.classifyDownstreamTool(server, name) !== 'mutating') continue;
        const meta = remoteMap.get(name);
        mutatingTools.push({
          name,
          description: meta?.description
            ? this.scrubber.scrub(meta.description)
            : undefined,
          inputSchema: meta?.inputSchema,
          classification: 'mutating',
        });
      }

      results.push({
        id: server.id,
        transport: server.transport,
        description: server.description,
        connected,
        ...(errorMsg ? { error: errorMsg } : {}),
        readonlyTools,
        mutatingTools,
      });
    }

    return results;
  }

  /**
   * Invokes a downstream MCP-2 tool ONLY if classified in `readonlyTools`.
   * Rejects `mutatingTools`, `deniedTools`, and unlisted tools.
   */
  async callReadonlyTool(
    serverName: string,
    toolName: string,
    args: Record<string, unknown> = {},
  ): Promise<DownstreamCallResult> {
    const server = this.getServerOrThrow(serverName);
    const decision = this.policy.evaluateDownstreamTool(server, toolName, 'inspect');
    if (!decision.allowed) {
      throw new DownstreamPolicyError(decision.reason);
    }

    const res = await this.withClientCall(
      server,
      `callTool "${toolName}" on downstream MCP "${serverName}"`,
      (client) => client.callTool({ name: toolName, arguments: args }),
    );
    const rawText = this.scrubber.scrub(extractMcpToolText(res));

    if (res.isError) {
      throw new Error(`Downstream tool "${serverName}:${toolName}" returned error: ${rawText}`);
    }

    const wrappedText = wrapUntrustedData(`downstream_mcp:${serverName}:${toolName}`, rawText);
    return {
      serverName,
      toolName,
      rawText,
      wrappedText,
    };
  }

  /**
   * Stages a mutating downstream MCP-2 tool call in `mutation_plans` with 15-minute TTL.
   * Rejects `deniedTools`, `readonlyTools`, and unlisted tools.
   * Optionally attaches a policy-validated mutating rollback tool payload.
   */
  stageMutatingToolPlan(
    planRepo: PlanStore,
    serverName: string,
    toolName: string,
    args: Record<string, unknown>,
    reason: string,
    rollback?: DownstreamRollbackSpec,
  ): MutationPlanRecord {
    const server = this.getServerOrThrow(serverName);
    const decision = this.policy.evaluateDownstreamTool(server, toolName, 'stage');
    if (!decision.allowed) {
      throw new DownstreamPolicyError(decision.reason);
    }

    let rollbackPayload: Record<string, unknown> | null = null;
    if (rollback) {
      const rbDecision = this.policy.evaluateDownstreamTool(server, rollback.toolName, 'stage');
      if (!rbDecision.allowed) {
        throw new DownstreamPolicyError(
          `Rollback tool rejected by policy: ${rbDecision.reason}`,
        );
      }
      rollbackPayload = {
        serverName,
        toolName: rollback.toolName,
        args: rollback.args ?? {},
      };
    }

    const cleanReason = reason.trim();
    if (!cleanReason) {
      throw new Error('A non-empty reason is required when staging a downstream mutating tool.');
    }

    const now = Date.now();
    const planId = `mcp-plan-${now}-${crypto.randomBytes(4).toString('hex')}`;
    const scrubbedArgs = this.scrubber.scrubObject(args);

    const summaryLines = [
      `Downstream MCP-2 Mutation Plan (${serverName} -> ${toolName}):`,
      `Reason: ${this.scrubber.scrub(cleanReason)}`,
      `+ Tool: ${serverName}:${toolName}`,
      `+ Arguments: ${JSON.stringify(scrubbedArgs, null, 2)}`,
    ];
    if (rollback) {
      summaryLines.push(
        `  Rollback Tool: ${serverName}:${rollback.toolName}`,
        `  Rollback Arguments: ${JSON.stringify(this.scrubber.scrubObject(rollback.args ?? {}), null, 2)}`,
      );
    }
    const summaryDiffText = summaryLines.join('\n');

    return planRepo.createPlan({
      plan_id: planId,
      target_service: `downstream_mcp:${serverName}`,
      summary_diff_text: summaryDiffText,
      payload: {
        serverName,
        toolName,
        args,
        reason: cleanReason,
      },
      rollback_payload: rollbackPayload,
      status: 'staged',
      expires_at: now + this.planTtlMs,
      created_at: now,
    });
  }

  private async invokeDownstreamPayload(
    serverName: string,
    toolName: string,
    args: Record<string, unknown>,
    operationLabel: string,
  ): Promise<string> {
    const server = this.getServerOrThrow(serverName);
    const decision = this.policy.evaluateDownstreamTool(server, toolName, 'execute');
    if (!decision.allowed) {
      throw new DownstreamPolicyError(decision.reason);
    }

    const res = await this.withClientCall(
      server,
      `${operationLabel} "${toolName}" on "${serverName}"`,
      (client) => client.callTool({ name: toolName, arguments: args }),
    );
    const rawText = this.scrubber.scrub(extractMcpToolText(res));

    if (res.isError) {
      throw new Error(`Downstream tool "${serverName}:${toolName}" returned error: ${rawText}`);
    }

    return wrapUntrustedData(`downstream_mcp:${serverName}:${toolName}`, rawText);
  }

  /**
   * Returns a typed `MutationTargetAdapter` for wiring into `MutationPlanGate`.
   */
  asMutationTargetAdapter(): MutationTargetAdapter {
    return {
      targetPrefix: 'downstream_mcp:',
      auditActionPrefix: 'downstream_mcp',
      matchesTargetService: (targetService: string) => targetService.startsWith('downstream_mcp:'),
      executeStagedPayload: async (plan: MutationPlanRecord) => {
        const payload = plan.payload;
        const serverName = String(payload.serverName ?? '');
        const toolName = String(payload.toolName ?? '');
        const args = (payload.args ?? {}) as Record<string, unknown>;
        const reason = String(payload.reason ?? '');
        const wrappedText = await this.invokeDownstreamPayload(
          serverName,
          toolName,
          args,
          'executeStagedDownstreamPlan',
        );
        return {
          result: {
            planId: plan.plan_id,
            serverName,
            toolName,
            status: 'executed',
            wrappedText,
          },
          auditTarget: `${serverName}:${toolName}`,
          auditDetails: { plan_id: plan.plan_id, reason: this.scrubber.scrub(reason) },
        };
      },
      rollbackExecutedPayload: async (plan: MutationPlanRecord) => {
        if (!plan.rollback_payload) {
          throw new Error(`Plan "${plan.plan_id}" has no rollback_payload stored.`);
        }
        const rb = plan.rollback_payload;
        const serverName = String(rb.serverName ?? '');
        const toolName = String(rb.toolName ?? '');
        const args = (rb.args ?? {}) as Record<string, unknown>;
        const wrappedText = await this.invokeDownstreamPayload(
          serverName,
          toolName,
          args,
          'rollbackExecutedDownstreamPlan',
        );
        return {
          result: {
            planId: plan.plan_id,
            serverName,
            toolName,
            status: 'rolled_back',
            wrappedText,
          },
          auditTarget: `${serverName}:${toolName}`,
          auditDetails: { plan_id: plan.plan_id, rollbackTool: toolName },
        };
      },
    };
  }

  /**
   * Executes a previously staged downstream MCP-2 mutation plan after verifying
   * non-expired `staged` status, policy classification, and recording an audit entry.
   */
  async executeStagedDownstreamPlan(
    planRepo: PlanStore,
    auditRepo: AuditLogger,
    planId: string,
    actor = 'system',
  ): Promise<ExecuteDownstreamPlanResult> {
    const preview = planRepo.getPlan(planId);
    const preDecision = this.policy.evaluatePlanExecution(preview, {
      expectedTargetPrefix: 'downstream_mcp:',
    });
    if (!preDecision.allowed && preDecision.code === 'PLAN_TARGET_MISMATCH') {
      auditRepo.record({
        actor,
        action: 'downstream_mcp.execute_plan',
        target: planId,
        status: 'denied',
        details: { error: `Wrong target_service: ${preview?.target_service ?? 'unknown'}` },
      });
      throw new Error(
        `Plan "${planId}" targets "${preview?.target_service ?? 'unknown'}", not a downstream MCP server.`,
      );
    }

    const claim = planRepo.claimForExecution(planId);

    if (!claim.ok) {
      const reasonMsg =
        claim.reason === 'not_found'
          ? `Mutation plan "${planId}" not found.`
          : claim.reason === 'expired'
            ? `Mutation plan "${planId}" has expired (15-minute TTL exceeded).`
            : `Mutation plan "${planId}" cannot be executed in status "${claim.plan?.status ?? 'unknown'}".`;

      auditRepo.record({
        actor,
        action: 'downstream_mcp.execute_plan',
        target: planId,
        status: 'denied',
        details: { reason: claim.reason },
      });
      throw new Error(reasonMsg);
    }

    const plan = claim.plan;
    if (!plan.target_service.startsWith('downstream_mcp:')) {
      planRepo.updatePlanStatus(planId, 'staged');
      auditRepo.record({
        actor,
        action: 'downstream_mcp.execute_plan',
        target: planId,
        status: 'denied',
        details: { error: `Wrong target_service: ${plan.target_service}` },
      });
      throw new Error(
        `Plan "${planId}" targets "${plan.target_service}", not a downstream MCP server.`,
      );
    }

    const payload = plan.payload;
    const serverName = String(payload.serverName ?? '');
    const toolName = String(payload.toolName ?? '');
    const args = (payload.args ?? {}) as Record<string, unknown>;
    const reason = String(payload.reason ?? '');

    try {
      const wrappedText = await this.invokeDownstreamPayload(
        serverName,
        toolName,
        args,
        'executeStagedDownstreamPlan',
      );
      planRepo.updatePlanStatus(planId, 'executed', Date.now());
      auditRepo.record({
        actor,
        action: 'downstream_mcp.execute_plan',
        target: `${serverName}:${toolName}`,
        status: 'success',
        details: { plan_id: planId, reason: this.scrubber.scrub(reason) },
      });

      return {
        planId,
        serverName,
        toolName,
        status: 'executed',
        wrappedText,
      };
    } catch (err) {
      const msg = this.scrubber.scrub(err instanceof Error ? err.message : String(err));
      planRepo.updatePlanStatus(planId, 'failed');
      auditRepo.record({
        actor,
        action: 'downstream_mcp.execute_plan',
        target: `${serverName}:${toolName}`,
        status: 'failure',
        details: { plan_id: planId, error: msg },
      });
      throw err instanceof DownstreamPolicyError
        ? err
        : new Error(`Failed executing downstream MCP plan "${planId}": ${msg}`);
    }
  }

  /**
   * Executes the stored rollback tool payload for an executed downstream MCP-2 plan
   * without corrupting plans that do not define a rollback tool.
   */
  async rollbackExecutedDownstreamPlan(
    planRepo: PlanStore,
    auditRepo: AuditLogger,
    planId: string,
    actor = 'system',
  ): Promise<RollbackDownstreamPlanResult> {
    const preview = planRepo.getPlan(planId);
    const preDecision = this.policy.evaluatePlanRollback(preview, {
      expectedTargetPrefix: 'downstream_mcp:',
    });
    if (
      !preDecision.allowed &&
      (preDecision.code === 'PLAN_TARGET_MISMATCH' || preDecision.code === 'PLAN_NO_ROLLBACK')
    ) {
      auditRepo.record({
        actor,
        action: 'downstream_mcp.rollback_plan',
        target: planId,
        status: 'denied',
        details: { code: preDecision.code, reason: preDecision.reason },
      });
      throw new Error(preDecision.reason);
    }

    const claim = planRepo.claimForRollback(planId);
    if (!claim.ok) {
      const reasonMsg =
        claim.reason === 'not_found'
          ? `Mutation plan "${planId}" not found.`
          : `Plan "${planId}" cannot be rolled back from status "${claim.plan?.status ?? 'unknown'}" (must be "executed").`;
      auditRepo.record({
        actor,
        action: 'downstream_mcp.rollback_plan',
        target: planId,
        status: 'denied',
        details: { reason: claim.reason },
      });
      throw new Error(reasonMsg);
    }

    const plan = claim.plan;
    if (!plan.target_service.startsWith('downstream_mcp:') || !plan.rollback_payload) {
      planRepo.updatePlanStatus(planId, 'executed');
      throw new Error(`Plan "${planId}" cannot be rolled back as a downstream MCP plan.`);
    }

    const rb = plan.rollback_payload;
    const serverName = String(rb.serverName ?? '');
    const toolName = String(rb.toolName ?? '');
    const args = (rb.args ?? {}) as Record<string, unknown>;

    try {
      const wrappedText = await this.invokeDownstreamPayload(
        serverName,
        toolName,
        args,
        'rollbackExecutedDownstreamPlan',
      );
      planRepo.updatePlanStatus(planId, 'rolled_back');
      auditRepo.record({
        actor,
        action: 'downstream_mcp.rollback_plan',
        target: `${serverName}:${toolName}`,
        status: 'success',
        details: { plan_id: planId, rollbackTool: toolName },
      });

      return {
        planId,
        serverName,
        toolName,
        status: 'rolled_back',
        wrappedText,
      };
    } catch (err) {
      const msg = this.scrubber.scrub(err instanceof Error ? err.message : String(err));
      planRepo.updatePlanStatus(planId, 'failed');
      auditRepo.record({
        actor,
        action: 'downstream_mcp.rollback_plan',
        target: `${serverName}:${toolName}`,
        status: 'failure',
        details: { plan_id: planId, error: msg },
      });
      throw err instanceof DownstreamPolicyError
        ? err
        : new Error(`Failed rolling back downstream MCP plan "${planId}": ${msg}`);
    }
  }

  /**
   * Gracefully closes all connected downstream MCP clients/transports.
   */
  async closeAll(): Promise<void> {
    const entries = Array.from(this.clients.entries());
    this.clients.clear();
    this.toolCache.clear();
    await Promise.allSettled(entries.map(([, client]) => client.close()));
  }
}
