import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Cloudflare from 'cloudflare';
import { z } from 'zod';
import type { AuditLogger } from '../auth/store.js';
import { wrapUntrustedData } from '../mcp/outputGuard.js';
import {
  defaultApprovalGatePolicy,
  type ApprovalGatePolicy,
  type MutationTargetAdapter,
  type PlanStore,
} from '../policy/index.js';
import type { GatewayConfig, MutationPlanRecord, ScrubberLike } from '../types.js';
import { buildSandboxedEnv, runSubprocess, type ExecResult } from '../utils/exec.js';
import { SecretScrubber } from '../utils/secretScrubber.js';
import { isSensitiveWorkspacePath } from './workspaceLock.js';

export const DEFAULT_PLAN_TTL_MS = 15 * 60 * 1000;

export type CloudflareResourceType =
  | 'zones'
  | 'dns_records'
  | 'workers'
  | 'pages'
  | 'kv_namespaces'
  | 'd1_databases'
  | 'waf_rules'
  | 'worker_tail_logs';

export interface InspectCloudflareParams {
  accountId?: string;
  zoneId?: string;
  zoneName?: string;
  name?: string;
  type?: string;
  scriptName?: string;
  projectName?: string;
  namespaceId?: string;
  databaseId?: string;
  phase?: string;
  limit?: number;
}

export interface InspectCloudflareResult {
  resource: CloudflareResourceType;
  data: unknown;
  summaryText: string;
}

export interface CloudflareClientLike {
  zones: {
    list(query?: Record<string, unknown>): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
    get(params: { zone_id: string }): Promise<Record<string, unknown>>;
  };
  dns: {
    records: {
      list(params: Record<string, unknown>): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
      get(dnsRecordID: string, params: { zone_id: string }): Promise<Record<string, unknown>>;
      create(params: Record<string, unknown>): Promise<Record<string, unknown>>;
      update(dnsRecordID: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
      delete(dnsRecordID: string, params: { zone_id: string }): Promise<unknown>;
    };
  };
  workers: {
    scripts: {
      list(params: { account_id: string }): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
      tail: {
        get(scriptName: string, params: { account_id: string }): Promise<unknown>;
      };
    };
    routes?: {
      list(params: { zone_id: string }): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
      get(routeID: string, params: { zone_id: string }): Promise<Record<string, unknown>>;
      create(params: {
        zone_id: string;
        pattern: string;
        script?: string;
      }): Promise<Record<string, unknown>>;
      update(
        routeID: string,
        params: { zone_id: string; pattern: string; script?: string },
      ): Promise<Record<string, unknown>>;
      delete(routeID: string, params: { zone_id: string }): Promise<unknown>;
    };
  };
  pages: {
    projects: {
      list(params: { account_id: string }): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
      get(projectName: string, params: { account_id: string }): Promise<Record<string, unknown>>;
      deployments: {
        list(
          projectName: string,
          params: { account_id: string; per_page?: number },
        ): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
      };
    };
  };
  kv: {
    namespaces: {
      list(params: { account_id: string }): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
      keys: {
        list(
          namespaceID: string,
          params: { account_id: string },
        ): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
      };
      values?: {
        get(
          keyName: string,
          params: { account_id: string; namespace_id: string },
        ): Promise<Response | string | { text(): Promise<string> }>;
        update(
          keyName: string,
          params: {
            account_id: string;
            namespace_id: string;
            value: string;
            expiration?: number;
            expiration_ttl?: number;
            metadata?: unknown;
          },
        ): Promise<unknown>;
        delete(
          keyName: string,
          params: { account_id: string; namespace_id: string },
        ): Promise<unknown>;
      };
    };
  };
  d1: {
    database: {
      list(params: { account_id: string }): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
      get(databaseID: string, params: { account_id: string }): Promise<Record<string, unknown>>;
      query(
        databaseID: string,
        params: { account_id: string; sql: string; params?: string[] },
      ): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
    };
  };
  rulesets: {
    list(params: Record<string, unknown>): AsyncIterable<Record<string, unknown>> | Promise<unknown>;
    get(rulesetID: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
    update(rulesetID: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
    phases: {
      get(phase: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
      update(phase: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
    };
  };
}

export type WranglerRunner = (
  args: string[],
  cwd: string,
  env: Record<string, string>,
) => Promise<ExecResult>;

export interface CloudflareServiceOptions {
  apiToken?: string;
  readonlyApiToken?: string;
  accountId?: string;
  planTtlMs?: number;
  scrubber?: ScrubberLike;
  policy?: ApprovalGatePolicy;
  readClient?: CloudflareClientLike;
  writeClient?: CloudflareClientLike;
  clientFactory?: (token: string, mode: 'read' | 'write') => CloudflareClientLike;
  wranglerRunner?: WranglerRunner;
}

const dnsRecordFieldsSchema = z.object({
  type: z.string().min(1),
  name: z.string().min(1),
  content: z.string().min(1),
  ttl: z.number().int().min(1).optional(),
  proxied: z.boolean().optional(),
  priority: z.number().int().min(0).optional(),
  comment: z.string().optional(),
});

const stagePlanInputSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('dns_record_create'),
    zoneId: z.string().min(1),
    record: dnsRecordFieldsSchema,
  }),
  z.object({
    type: z.literal('dns_record_update'),
    zoneId: z.string().min(1),
    recordId: z.string().min(1),
    record: dnsRecordFieldsSchema,
  }),
  z.object({
    type: z.literal('dns_record_delete'),
    zoneId: z.string().min(1),
    recordId: z.string().min(1),
  }),
  z.object({
    type: z.literal('waf_rule_update'),
    zoneId: z.string().min(1),
    rulesetId: z.string().min(1).optional(),
    phase: z.string().min(1).default('http_request_firewall_custom'),
    description: z.string().optional(),
    rules: z.array(z.record(z.unknown())),
  }),
  z.object({
    type: z.literal('d1_sql_mutation'),
    accountId: z.string().min(1).optional(),
    databaseId: z.string().min(1),
    sql: z.string().min(1),
    params: z.array(z.string()).optional(),
    rollbackSql: z.string().min(1).optional(),
  }),
  z.object({
    type: z.literal('kv_put'),
    accountId: z.string().min(1).optional(),
    namespaceId: z.string().min(1),
    key: z.string().min(1),
    value: z.string(),
    expiration: z.number().int().positive().optional(),
    expirationTtl: z.number().int().min(60).optional(),
    metadata: z.record(z.unknown()).optional(),
  }),
  z.object({
    type: z.literal('kv_delete'),
    accountId: z.string().min(1).optional(),
    namespaceId: z.string().min(1),
    key: z.string().min(1),
  }),
  z.object({
    type: z.literal('worker_route_create'),
    zoneId: z.string().min(1),
    pattern: z.string().min(1),
    script: z.string().min(1).optional(),
  }),
  z.object({
    type: z.literal('worker_route_update'),
    zoneId: z.string().min(1),
    routeId: z.string().min(1),
    pattern: z.string().min(1),
    script: z.string().min(1).optional(),
  }),
  z.object({
    type: z.literal('worker_route_delete'),
    zoneId: z.string().min(1),
    routeId: z.string().min(1),
  }),
]);

export type StageCloudflarePlanInput = z.input<typeof stagePlanInputSchema>;

export interface DeployWorkerOptions {
  target?: 'preview' | 'production';
  message?: string;
  env?: string;
  configPath?: string;
}

export interface DeployWorkerResult {
  target: 'preview' | 'production';
  command: string;
  exitCode: number | null;
  deploymentUrl: string | null;
  output: string;
}

export interface DeployPagesOptions {
  projectName: string;
  directory: string;
  branch?: string;
  commitMessage?: string;
}

export interface DeployPagesResult {
  projectName: string;
  directory: string;
  command: string;
  exitCode: number | null;
  deploymentUrl: string | null;
  output: string;
}

export interface ExecutePlanResult {
  planId: string;
  status: 'executed';
  result: unknown;
}

export interface RollbackPlanResult {
  planId: string;
  status: 'rolled_back';
  result: unknown;
}

async function collectItems(
  source: AsyncIterable<Record<string, unknown>> | Promise<unknown>,
  limit = 100,
): Promise<Array<Record<string, unknown>>> {
  if (
    source &&
    typeof source === 'object' &&
    Symbol.asyncIterator in source &&
    typeof (source as AsyncIterable<Record<string, unknown>>)[Symbol.asyncIterator] === 'function'
  ) {
    const items: Array<Record<string, unknown>> = [];
    for await (const item of source as AsyncIterable<Record<string, unknown>>) {
      items.push(item);
      if (items.length >= limit) break;
    }
    return items;
  }

  const resolved = await source;
  if (Array.isArray(resolved)) {
    return (resolved as Array<Record<string, unknown>>).slice(0, limit);
  }
  if (resolved && typeof resolved === 'object') {
    const obj = resolved as Record<string, unknown>;
    if (Array.isArray(obj.result)) {
      return (obj.result as Array<Record<string, unknown>>).slice(0, limit);
    }
    return [obj];
  }
  return [];
}

function assertSafeWranglerFlagValue(name: string, value: string): string {
  if (value.includes('\0') || /[\r\n]/.test(value)) {
    throw new Error(`Invalid ${name}: contains null byte or newline.`);
  }
  if (value.trim().startsWith('-')) {
    throw new Error(`Invalid ${name} "${value}": must not start with "-".`);
  }
  return value;
}

function assertWorkspaceRelativeSubpath(
  workspacePath: string,
  targetPath: string,
  options: { allowRoot: boolean; fieldName: string },
): string {
  if (!targetPath || targetPath.includes('\0')) {
    throw new Error(`Invalid ${options.fieldName}: empty or contains null byte.`);
  }
  const trimmed = targetPath.trim();
  if (trimmed.startsWith('-')) {
    throw new Error(`Invalid ${options.fieldName} "${targetPath}": must not start with "-".`);
  }
  if (path.isAbsolute(trimmed)) {
    // Allow only if resolved path is strictly inside workspacePath
    const resolvedWs = path.resolve(workspacePath);
    const resolvedTarget = path.resolve(trimmed);
    const normWs = process.platform === 'win32' ? resolvedWs.toLowerCase() : resolvedWs;
    const normTarget = process.platform === 'win32' ? resolvedTarget.toLowerCase() : resolvedTarget;
    if (normTarget !== normWs && !normTarget.startsWith(normWs + path.sep)) {
      throw new Error(
        `Invalid ${options.fieldName} "${targetPath}": path escapes workspace directory.`,
      );
    }
  }

  const resolvedWs = path.resolve(workspacePath);
  const resolvedTarget = path.resolve(resolvedWs, trimmed || '.');
  const normWs = process.platform === 'win32' ? resolvedWs.toLowerCase() : resolvedWs;
  const normTarget = process.platform === 'win32' ? resolvedTarget.toLowerCase() : resolvedTarget;
  if (normTarget !== normWs && !normTarget.startsWith(normWs + path.sep)) {
    throw new Error(
      `Invalid ${options.fieldName} "${targetPath}": path escapes workspace directory.`,
    );
  }

  const rel = path.relative(resolvedWs, resolvedTarget).replace(/\\/g, '/') || '.';
  if (!options.allowRoot && rel === '.') {
    throw new Error(`Invalid ${options.fieldName}: cannot target workspace root directly.`);
  }
  if (isSensitiveWorkspacePath(rel)) {
    throw new Error(`Invalid ${options.fieldName}: access to sensitive path "${rel}" denied.`);
  }

  if (fs.existsSync(resolvedWs)) {
    const realWs = fs.realpathSync(resolvedWs);
    let targetStat: fs.Stats | null = null;
    try {
      targetStat = fs.lstatSync(resolvedTarget);
    } catch (err) {
      const nodeErr = err as NodeJS.ErrnoException;
      if (nodeErr.code !== 'ENOENT') {
        throw err;
      }
    }

    if (targetStat) {
      let realTarget: string;
      try {
        realTarget = fs.realpathSync(resolvedTarget);
      } catch {
        throw new Error(
          `Invalid ${options.fieldName} "${targetPath}": broken symlink rejected.`,
        );
      }
      const normRealWs = process.platform === 'win32' ? realWs.toLowerCase() : realWs;
      const normRealTarget = process.platform === 'win32' ? realTarget.toLowerCase() : realTarget;
      if (normRealTarget !== normRealWs && !normRealTarget.startsWith(normRealWs + path.sep)) {
        throw new Error(
          `Invalid ${options.fieldName} "${targetPath}": symlink resolves outside workspace.`,
        );
      }
      const realRel = path.relative(realWs, realTarget).replace(/\\/g, '/') || '.';
      if (isSensitiveWorkspacePath(realRel)) {
        throw new Error(
          `Invalid ${options.fieldName}: symlink target "${realRel}" is a sensitive path.`,
        );
      }
    }
  }

  return rel;
}

function redactTailUrls(value: unknown, seen = new WeakSet<object>()): unknown {
  if (typeof value === 'string') {
    return value.replace(/\bwss?:\/\/[^\s"'<>]+/gi, '[REDACTED_TAIL_URL]');
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (seen.has(value as object)) {
    return value;
  }
  seen.add(value as object);
  if (Array.isArray(value)) {
    return value.map((item) => redactTailUrls(item, seen));
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (/^(?:url|websocket_url|ws_url|tail_url)$/i.test(k)) {
      out[k] = '[REDACTED_TAIL_URL]';
    } else {
      out[k] = redactTailUrls(v, seen);
    }
  }
  return out;
}

function resolveTrustedWranglerBinary(): string {
  if (process.platform !== 'win32' && fs.existsSync('/usr/local/bin/wrangler')) {
    return '/usr/local/bin/wrangler';
  }
  return 'wrangler';
}

function extractWranglerUrl(output: string): string | null {
  const match = /https:\/\/[A-Za-z0-9._-]+\.(?:workers\.dev|pages\.dev)(?:\/[^\s]*)?/i.exec(output);
  return match ? match[0] : null;
}

function pickDnsFields(record: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {
    type: record.type,
    name: record.name,
    content: record.content,
  };
  if (record.ttl !== undefined) out.ttl = record.ttl;
  if (record.proxied !== undefined) out.proxied = record.proxied;
  if (record.priority !== undefined) out.priority = record.priority;
  if (record.comment !== undefined && record.comment !== null) out.comment = record.comment;
  return out;
}

function isCloudflareNotFoundError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const record = err as { status?: unknown; statusCode?: unknown; message?: unknown };
  if (record.status === 404 || record.statusCode === 404) return true;
  if (typeof record.message === 'string' && /\b404\b|not found/i.test(record.message)) return true;
  return false;
}

async function readKvValueText(
  client: CloudflareClientLike,
  accountId: string,
  namespaceId: string,
  key: string,
): Promise<{ exists: boolean; value: string | null }> {
  const valuesApi = client.kv.namespaces.values;
  if (!valuesApi) {
    throw new Error('Cloudflare client does not support KV values API.');
  }
  try {
    const raw = await valuesApi.get(key, { account_id: accountId, namespace_id: namespaceId });
    if (typeof raw === 'string') {
      return { exists: true, value: raw };
    }
    if (raw && typeof raw === 'object' && 'status' in raw && (raw as Response).status === 404) {
      return { exists: false, value: null };
    }
    if (raw && typeof raw === 'object' && 'text' in raw && typeof raw.text === 'function') {
      return { exists: true, value: await raw.text() };
    }
    return { exists: true, value: String(raw ?? '') };
  } catch (err) {
    if (isCloudflareNotFoundError(err)) {
      return { exists: false, value: null };
    }
    throw err;
  }
}

function summarizeKvValue(value: string, scrubber: ScrubberLike): string {
  const byteLen = Buffer.byteLength(value, 'utf8');
  const scrubbed = scrubber.scrub(value);
  const singleLine = scrubbed.replace(/[\r\n]+/g, ' ');
  const preview = singleLine.length > 80 ? `${singleLine.slice(0, 80)}...` : singleLine;
  return `${byteLen} bytes ("${preview}")`;
}

/**
 * Cloudflare platform service with read/write token separation,
 * read-only resource inspection, two-phase staged mutations with rollback snapshots,
 * and controlled Wrangler deployment.
 */
export class CloudflareService {
  private readonly writeToken?: string;
  private readonly readToken?: string;
  private readonly defaultAccountId?: string;
  private readonly planTtlMs: number;
  private readonly scrubber: ScrubberLike;
  private readonly policy: ApprovalGatePolicy;
  private readonly readClientOverride?: CloudflareClientLike;
  private readonly writeClientOverride?: CloudflareClientLike;
  private readonly clientFactory?: (token: string, mode: 'read' | 'write') => CloudflareClientLike;
  private readonly wranglerRunner?: WranglerRunner;

  private cachedReadClient?: CloudflareClientLike;
  private cachedWriteClient?: CloudflareClientLike;

  constructor(options: CloudflareServiceOptions = {}) {
    this.writeToken = options.apiToken;
    this.readToken = options.readonlyApiToken ?? options.apiToken;
    this.defaultAccountId = options.accountId;
    this.planTtlMs = options.planTtlMs ?? DEFAULT_PLAN_TTL_MS;
    this.scrubber =
      options.scrubber ??
      new SecretScrubber({
        extraSecrets: [options.apiToken, options.readonlyApiToken].filter(
          (v): v is string => Boolean(v),
        ),
      });
    this.policy = options.policy ?? defaultApprovalGatePolicy;
    this.readClientOverride = options.readClient;
    this.writeClientOverride = options.writeClient;
    this.clientFactory = options.clientFactory;
    this.wranglerRunner = options.wranglerRunner;
  }

  static fromConfig(
    config: Pick<
      GatewayConfig,
      'cloudflareApiToken' | 'cloudflareReadonlyApiToken' | 'cloudflareAccountId' | 'mutationPlanTtlSec'
    >,
    scrubber?: ScrubberLike,
    policy?: ApprovalGatePolicy,
  ): CloudflareService {
    return new CloudflareService({
      apiToken: config.cloudflareApiToken,
      readonlyApiToken: config.cloudflareReadonlyApiToken,
      accountId: config.cloudflareAccountId,
      planTtlMs: config.mutationPlanTtlSec * 1000,
      scrubber,
      policy,
    });
  }

  private getReadClient(): CloudflareClientLike {
    if (this.readClientOverride) return this.readClientOverride;
    if (this.cachedReadClient) return this.cachedReadClient;
    if (!this.readToken) {
      throw new Error(
        'Cloudflare read operation requires CLOUDFLARE_READONLY_API_TOKEN or CLOUDFLARE_API_TOKEN.',
      );
    }
    this.cachedReadClient = this.clientFactory
      ? this.clientFactory(this.readToken, 'read')
      : (new Cloudflare({ apiToken: this.readToken }) as unknown as CloudflareClientLike);
    return this.cachedReadClient;
  }

  private getWriteClient(): CloudflareClientLike {
    if (this.writeClientOverride) return this.writeClientOverride;
    if (this.cachedWriteClient) return this.cachedWriteClient;
    if (!this.writeToken) {
      throw new Error(
        'Cloudflare write operation requires CLOUDFLARE_API_TOKEN (readonly token cannot perform writes).',
      );
    }
    this.cachedWriteClient = this.clientFactory
      ? this.clientFactory(this.writeToken, 'write')
      : (new Cloudflare({ apiToken: this.writeToken }) as unknown as CloudflareClientLike);
    return this.cachedWriteClient;
  }

  private requireWriteToken(): string {
    if (!this.writeToken) {
      throw new Error(
        'Cloudflare deployment/write operation requires CLOUDFLARE_API_TOKEN (readonly token cannot perform writes).',
      );
    }
    return this.writeToken;
  }

  private requireAccountId(override?: string): string {
    const accountId = override ?? this.defaultAccountId;
    if (!accountId) {
      throw new Error('Cloudflare accountId is required (pass accountId or configure CLOUDFLARE_ACCOUNT_ID).');
    }
    return accountId;
  }

  private async resolveZoneId(
    client: CloudflareClientLike,
    params: { zoneId?: string; zoneName?: string },
  ): Promise<string> {
    if (params.zoneId) return params.zoneId;
    if (params.zoneName) {
      const zones = await collectItems(client.zones.list({ name: params.zoneName }), 5);
      const match = zones.find((z) => String(z.name ?? '') === params.zoneName) ?? zones[0];
      if (match?.id) return String(match.id);
      throw new Error(`Cloudflare zone not found for name "${params.zoneName}".`);
    }
    throw new Error('Either zoneId or zoneName is required for this Cloudflare resource.');
  }

  private async runWrangler(args: string[], cwd: string): Promise<ExecResult> {
    const token = this.requireWriteToken();
    const env = buildSandboxedEnv();
    delete env.NODE_OPTIONS;
    env.CLOUDFLARE_API_TOKEN = token;
    if (this.defaultAccountId) {
      env.CLOUDFLARE_ACCOUNT_ID = this.defaultAccountId;
    }

    if (this.wranglerRunner) {
      return this.wranglerRunner(args, cwd, env);
    }

    return runSubprocess({
      command: resolveTrustedWranglerBinary(),
      args,
      cwd,
      env,
      timeoutMs: 120_000,
    });
  }

  /**
   * Read-only Cloudflare resource inspection using readonly token (with fallback to primary token).
   */
  async inspectResource(
    resource: CloudflareResourceType,
    params: InspectCloudflareParams = {},
  ): Promise<InspectCloudflareResult> {
    const client = this.getReadClient();
    const limit = params.limit ?? 50;

    switch (resource) {
      case 'zones': {
        if (params.zoneId) {
          const zone = await client.zones.get({ zone_id: params.zoneId });
          const clean = this.scrubber.scrubObject(zone);
          return {
            resource,
            data: clean,
            summaryText: `Cloudflare Zone ${String(clean.name ?? params.zoneId)} (${String(clean.id ?? params.zoneId)}): status=${String(clean.status ?? 'unknown')}`,
          };
        }
        const query: Record<string, unknown> = {};
        if (params.name) query.name = params.name;
        const zones = this.scrubber.scrubObject(await collectItems(client.zones.list(query), limit));
        const lines = zones.map(
          (z) => `- ${String(z.name ?? '')} (id=${String(z.id ?? '')}, status=${String(z.status ?? '')})`,
        );
        return {
          resource,
          data: zones,
          summaryText: `# Cloudflare Zones (${zones.length})\n${lines.join('\n') || '(none)'}`,
        };
      }

      case 'dns_records': {
        const zoneId = await this.resolveZoneId(client, params);
        const query: Record<string, unknown> = { zone_id: zoneId };
        if (params.name) query.name = params.name;
        if (params.type) query.type = params.type;
        const records = this.scrubber.scrubObject(
          await collectItems(client.dns.records.list(query), limit),
        );
        const lines = records.map(
          (r) =>
            `- [${String(r.type ?? '')}] ${String(r.name ?? '')} -> ${String(r.content ?? '')} (id=${String(r.id ?? '')}, proxied=${String(r.proxied ?? false)}, ttl=${String(r.ttl ?? 'auto')})`,
        );
        return {
          resource,
          data: records,
          summaryText: `# DNS Records for zone ${zoneId} (${records.length})\n${lines.join('\n') || '(none)'}`,
        };
      }

      case 'workers': {
        const accountId = this.requireAccountId(params.accountId);
        const scripts = this.scrubber.scrubObject(
          await collectItems(client.workers.scripts.list({ account_id: accountId }), limit),
        );
        const lines = scripts.map(
          (s) => `- ${String(s.id ?? s.name ?? 'unknown')} (modified=${String(s.modified_on ?? '')})`,
        );
        return {
          resource,
          data: scripts,
          summaryText: `# Cloudflare Workers (${scripts.length})\n${lines.join('\n') || '(none)'}`,
        };
      }

      case 'pages': {
        const accountId = this.requireAccountId(params.accountId);
        if (params.projectName) {
          const [project, deployments] = await Promise.all([
            client.pages.projects.get(params.projectName, { account_id: accountId }),
            collectItems(
              client.pages.projects.deployments.list(params.projectName, {
                account_id: accountId,
                per_page: Math.min(limit, 10),
              }),
              Math.min(limit, 10),
            ),
          ]);
          const data = this.scrubber.scrubObject({ project, recentDeployments: deployments });
          const depLines = deployments.map((d) => {
            const stage = (d.latest_stage ?? {}) as Record<string, unknown>;
            return `  - ${String(d.id ?? '')} env=${String(d.environment ?? '')} url=${String(d.url ?? '')} status=${String(stage.status ?? '')}`;
          });
          return {
            resource,
            data,
            summaryText: [
              `# Cloudflare Pages Project: ${params.projectName}`,
              `Subdomain: ${String(project.subdomain ?? '')} | Production branch: ${String(project.production_branch ?? '')}`,
              `## Recent Deployments (${deployments.length})`,
              depLines.join('\n') || '(none)',
            ].join('\n'),
          };
        }

        const projects = await collectItems(
          client.pages.projects.list({ account_id: accountId }),
          limit,
        );
        const projectsWithDeployments: Array<{
          project: Record<string, unknown>;
          recentDeployments: Array<Record<string, unknown>>;
        }> = [];
        for (const proj of projects.slice(0, 5)) {
          const projName = String(proj.name ?? '');
          let deployments: Array<Record<string, unknown>> = [];
          if (projName) {
            try {
              deployments = await collectItems(
                client.pages.projects.deployments.list(projName, {
                  account_id: accountId,
                  per_page: 5,
                }),
                5,
              );
            } catch {
              deployments = [];
            }
          }
          projectsWithDeployments.push({ project: proj, recentDeployments: deployments });
        }

        const clean = this.scrubber.scrubObject(projectsWithDeployments);
        const lines = clean.map((entry) => {
          const p = entry.project;
          const latest = entry.recentDeployments[0];
          const latestDesc = latest
            ? `latest=${String(latest.url ?? latest.id ?? '')}`
            : 'no deployments';
          return `- ${String(p.name ?? '')} (subdomain=${String(p.subdomain ?? '')}, ${latestDesc})`;
        });
        return {
          resource,
          data: clean,
          summaryText: `# Cloudflare Pages Projects (${projects.length})\n${lines.join('\n') || '(none)'}`,
        };
      }

      case 'kv_namespaces': {
        const accountId = this.requireAccountId(params.accountId);
        if (params.namespaceId) {
          const keys = this.scrubber.scrubObject(
            await collectItems(
              client.kv.namespaces.keys.list(params.namespaceId, { account_id: accountId }),
              limit,
            ),
          );
          const lines = keys.map((k) => `- ${String(k.name ?? '')}`);
          return {
            resource,
            data: keys,
            summaryText: `# KV Keys in ${params.namespaceId} (${keys.length})\n${lines.join('\n') || '(none)'}`,
          };
        }

        const namespaces = this.scrubber.scrubObject(
          await collectItems(client.kv.namespaces.list({ account_id: accountId }), limit),
        );
        const lines = namespaces.map(
          (ns) => `- ${String(ns.title ?? '')} (id=${String(ns.id ?? '')})`,
        );
        return {
          resource,
          data: namespaces,
          summaryText: `# Cloudflare KV Namespaces (${namespaces.length})\n${lines.join('\n') || '(none)'}`,
        };
      }

      case 'd1_databases': {
        const accountId = this.requireAccountId(params.accountId);
        if (params.databaseId) {
          const db = this.scrubber.scrubObject(
            await client.d1.database.get(params.databaseId, { account_id: accountId }),
          );
          return {
            resource,
            data: db,
            summaryText: `# D1 Database ${String(db.name ?? params.databaseId)} (uuid=${String(db.uuid ?? params.databaseId)})`,
          };
        }

        const dbs = this.scrubber.scrubObject(
          await collectItems(client.d1.database.list({ account_id: accountId }), limit),
        );
        const lines = dbs.map(
          (d) => `- ${String(d.name ?? '')} (uuid=${String(d.uuid ?? d.id ?? '')})`,
        );
        return {
          resource,
          data: dbs,
          summaryText: `# Cloudflare D1 Databases (${dbs.length})\n${lines.join('\n') || '(none)'}`,
        };
      }

      case 'waf_rules': {
        const zoneId = await this.resolveZoneId(client, params);
        const rulesets = this.scrubber.scrubObject(
          await collectItems(client.rulesets.list({ zone_id: zoneId }), limit),
        );
        let customPhase: Record<string, unknown> | null = null;
        try {
          customPhase = this.scrubber.scrubObject(
            await client.rulesets.phases.get(params.phase ?? 'http_request_firewall_custom', {
              zone_id: zoneId,
            }),
          );
        } catch {
          customPhase = null;
        }
        const lines = rulesets.map(
          (rs) => `- ${String(rs.name ?? rs.id ?? '')} (id=${String(rs.id ?? '')}, phase=${String(rs.phase ?? '')}, kind=${String(rs.kind ?? '')})`,
        );
        return {
          resource,
          data: { rulesets, customPhase },
          summaryText: `# Cloudflare WAF Rulesets for zone ${zoneId} (${rulesets.length})\n${lines.join('\n') || '(none)'}`,
        };
      }

      case 'worker_tail_logs': {
        const accountId = this.requireAccountId(params.accountId);
        if (!params.scriptName) {
          throw new Error('scriptName is required for worker_tail_logs inspection.');
        }
        const tailInfo = await client.workers.scripts.tail.get(params.scriptName, {
          account_id: accountId,
        });
        const scrubbedTail = this.scrubber.scrubObject(redactTailUrls(tailInfo));
        const cleanRaw = this.scrubber.scrub(JSON.stringify(scrubbedTail, null, 2));
        const wrapped = wrapUntrustedData(
          `cloudflare:worker_tail_logs:${params.scriptName}`,
          cleanRaw,
        );
        return {
          resource,
          data: scrubbedTail,
          summaryText: `# Worker Tail Sessions Metadata (${params.scriptName})\n${wrapped}`,
        };
      }
    }
  }

  /**
   * Two-phase Mutation Plan Staging:
   * Validates DNS/WAF/D1/KV/Worker-route mutation inputs, queries remote pre-change state to build
   * `rollback_payload_json`, generates `summary_diff_text`, and persists a 15-minute TTL plan.
   */
  async stageCloudflarePlan(
    planRepo: PlanStore,
    rawInput: StageCloudflarePlanInput,
  ): Promise<MutationPlanRecord> {
    const input = stagePlanInputSchema.parse(rawInput);
    const client = this.getReadClient();
    const now = Date.now();
    const expiresAt = now + this.planTtlMs;
    const planId = `cf-plan-${now}-${crypto.randomBytes(4).toString('hex')}`;

    let summaryDiffText = '';
    let payload: Record<string, unknown> = {};
    let rollbackPayload: Record<string, unknown> | null = null;

    switch (input.type) {
      case 'dns_record_create': {
        const existing = await collectItems(
          client.dns.records.list({
            zone_id: input.zoneId,
            name: input.record.name,
            type: input.record.type,
          }),
          10,
        );
        summaryDiffText = [
          `Cloudflare DNS CREATE in zone ${input.zoneId}:`,
          `  Existing matching (${input.record.type} ${input.record.name}): ${existing.length} record(s)`,
          `+ ${input.record.type} ${input.record.name} -> ${input.record.content} (ttl=${input.record.ttl ?? 'auto'}, proxied=${input.record.proxied ?? false})`,
        ].join('\n');
        payload = {
          type: 'dns_record_create',
          zoneId: input.zoneId,
          record: input.record,
        };
        rollbackPayload = {
          action: 'dns_record_delete_created',
          zoneId: input.zoneId,
          name: input.record.name,
          type: input.record.type,
          content: input.record.content,
        };
        break;
      }

      case 'dns_record_update': {
        const existing = await client.dns.records.get(input.recordId, {
          zone_id: input.zoneId,
        });
        if (!existing || !existing.id) {
          throw new Error(`DNS record ${input.recordId} not found in zone ${input.zoneId}.`);
        }
        const prev = pickDnsFields(existing);
        summaryDiffText = [
          `Cloudflare DNS UPDATE in zone ${input.zoneId} (record=${input.recordId}):`,
          `- ${String(prev.type)} ${String(prev.name)} -> ${String(prev.content)} (ttl=${String(prev.ttl ?? 'auto')}, proxied=${String(prev.proxied ?? false)})`,
          `+ ${input.record.type} ${input.record.name} -> ${input.record.content} (ttl=${input.record.ttl ?? 'auto'}, proxied=${input.record.proxied ?? false})`,
        ].join('\n');
        payload = {
          type: 'dns_record_update',
          zoneId: input.zoneId,
          recordId: input.recordId,
          record: input.record,
        };
        rollbackPayload = {
          action: 'dns_record_update',
          zoneId: input.zoneId,
          recordId: input.recordId,
          record: prev,
        };
        break;
      }

      case 'dns_record_delete': {
        const existing = await client.dns.records.get(input.recordId, {
          zone_id: input.zoneId,
        });
        if (!existing || !existing.id) {
          throw new Error(`DNS record ${input.recordId} not found in zone ${input.zoneId}.`);
        }
        const prev = pickDnsFields(existing);
        summaryDiffText = [
          `Cloudflare DNS DELETE in zone ${input.zoneId} (record=${input.recordId}):`,
          `- ${String(prev.type)} ${String(prev.name)} -> ${String(prev.content)} (ttl=${String(prev.ttl ?? 'auto')}, proxied=${String(prev.proxied ?? false)})`,
        ].join('\n');
        payload = {
          type: 'dns_record_delete',
          zoneId: input.zoneId,
          recordId: input.recordId,
        };
        rollbackPayload = {
          action: 'dns_record_create',
          zoneId: input.zoneId,
          record: prev,
        };
        break;
      }

      case 'waf_rule_update': {
        const current = input.rulesetId
          ? await client.rulesets.get(input.rulesetId, { zone_id: input.zoneId })
          : await client.rulesets.phases.get(input.phase, { zone_id: input.zoneId });

        const prevRules = Array.isArray(current.rules)
          ? (current.rules as Array<Record<string, unknown>>)
          : [];
        const resolvedRulesetId = current.id ? String(current.id) : input.rulesetId;
        const resolvedPhase = current.phase ? String(current.phase) : input.phase;

        summaryDiffText = [
          `Cloudflare WAF UPDATE in zone ${input.zoneId} (phase=${resolvedPhase}${resolvedRulesetId ? `, ruleset=${resolvedRulesetId}` : ''}):`,
          `- Previous rule count: ${prevRules.length}`,
          `+ New rule count: ${input.rules.length}`,
        ].join('\n');

        payload = {
          type: 'waf_rule_update',
          zoneId: input.zoneId,
          rulesetId: resolvedRulesetId,
          phase: resolvedPhase,
          description: input.description,
          rules: input.rules,
        };
        rollbackPayload = {
          action: 'waf_rule_update',
          zoneId: input.zoneId,
          rulesetId: resolvedRulesetId,
          phase: resolvedPhase,
          description: current.description ?? undefined,
          rules: prevRules,
        };
        break;
      }

      case 'd1_sql_mutation': {
        const accountId = this.requireAccountId(input.accountId);
        const dbMeta = await client.d1.database.get(input.databaseId, { account_id: accountId });
        summaryDiffText = [
          `Cloudflare D1 SQL MUTATION on database ${String(dbMeta.name ?? input.databaseId)} (${input.databaseId}):`,
          `+ SQL: ${input.sql}`,
          input.rollbackSql
            ? `  Rollback SQL: ${input.rollbackSql}`
            : '  Rollback SQL: (not provided)',
        ].join('\n');

        payload = {
          type: 'd1_sql_mutation',
          accountId,
          databaseId: input.databaseId,
          sql: input.sql,
          params: input.params,
        };
        rollbackPayload = input.rollbackSql
          ? {
              action: 'd1_sql_mutation',
              accountId,
              databaseId: input.databaseId,
              sql: input.rollbackSql,
            }
          : null;
        break;
      }

      case 'kv_put': {
        const accountId = this.requireAccountId(input.accountId);
        const existing = await readKvValueText(client, accountId, input.namespaceId, input.key);
        summaryDiffText = [
          `Cloudflare KV PUT in namespace ${input.namespaceId} (key=${input.key}):`,
          existing.exists && existing.value !== null
            ? `- Previous value: ${summarizeKvValue(existing.value, this.scrubber)}`
            : '  Previous value: (key does not exist)',
          `+ New value: ${summarizeKvValue(input.value, this.scrubber)}${
            input.expirationTtl !== undefined ? ` (ttl=${input.expirationTtl}s)` : ''
          }${input.expiration !== undefined ? ` (expiration=${input.expiration})` : ''}`,
        ].join('\n');

        payload = {
          type: 'kv_put',
          accountId,
          namespaceId: input.namespaceId,
          key: input.key,
          value: input.value,
          ...(input.expiration !== undefined ? { expiration: input.expiration } : {}),
          ...(input.expirationTtl !== undefined ? { expirationTtl: input.expirationTtl } : {}),
          ...(input.metadata !== undefined ? { metadata: input.metadata } : {}),
        };
        rollbackPayload =
          existing.exists && existing.value !== null
            ? {
                action: 'kv_put',
                accountId,
                namespaceId: input.namespaceId,
                key: input.key,
                value: existing.value,
              }
            : {
                action: 'kv_delete',
                accountId,
                namespaceId: input.namespaceId,
                key: input.key,
              };
        break;
      }

      case 'kv_delete': {
        const accountId = this.requireAccountId(input.accountId);
        const existing = await readKvValueText(client, accountId, input.namespaceId, input.key);
        if (!existing.exists || existing.value === null) {
          throw new Error(
            `KV key "${input.key}" not found in namespace ${input.namespaceId}.`,
          );
        }
        summaryDiffText = [
          `Cloudflare KV DELETE in namespace ${input.namespaceId} (key=${input.key}):`,
          `- Existing value: ${summarizeKvValue(existing.value, this.scrubber)}`,
        ].join('\n');

        payload = {
          type: 'kv_delete',
          accountId,
          namespaceId: input.namespaceId,
          key: input.key,
        };
        rollbackPayload = {
          action: 'kv_put',
          accountId,
          namespaceId: input.namespaceId,
          key: input.key,
          value: existing.value,
        };
        break;
      }

      case 'worker_route_create': {
        const routesApi = client.workers.routes;
        if (!routesApi) {
          throw new Error('Cloudflare client does not support Worker routes API.');
        }
        const existing = await collectItems(routesApi.list({ zone_id: input.zoneId }), 50);
        const conflictCount = existing.filter(
          (r) => String(r.pattern ?? '') === input.pattern,
        ).length;
        summaryDiffText = [
          `Cloudflare Worker Route CREATE in zone ${input.zoneId}:`,
          `  Existing routes matching pattern: ${conflictCount}`,
          `+ pattern=${input.pattern} -> script=${input.script ?? '(disabled/none)'}`,
        ].join('\n');
        payload = {
          type: 'worker_route_create',
          zoneId: input.zoneId,
          pattern: input.pattern,
          ...(input.script !== undefined ? { script: input.script } : {}),
        };
        rollbackPayload = {
          action: 'worker_route_delete_created',
          zoneId: input.zoneId,
          pattern: input.pattern,
          ...(input.script !== undefined ? { script: input.script } : {}),
        };
        break;
      }

      case 'worker_route_update': {
        const routesApi = client.workers.routes;
        if (!routesApi) {
          throw new Error('Cloudflare client does not support Worker routes API.');
        }
        const existing = await routesApi.get(input.routeId, { zone_id: input.zoneId });
        if (!existing || !existing.id) {
          throw new Error(`Worker route ${input.routeId} not found in zone ${input.zoneId}.`);
        }
        const prevPattern = String(existing.pattern ?? '');
        const prevScript =
          typeof existing.script === 'string' && existing.script.length > 0
            ? existing.script
            : undefined;
        summaryDiffText = [
          `Cloudflare Worker Route UPDATE in zone ${input.zoneId} (route=${input.routeId}):`,
          `- pattern=${prevPattern} -> script=${prevScript ?? '(disabled/none)'}`,
          `+ pattern=${input.pattern} -> script=${input.script ?? '(disabled/none)'}`,
        ].join('\n');
        payload = {
          type: 'worker_route_update',
          zoneId: input.zoneId,
          routeId: input.routeId,
          pattern: input.pattern,
          ...(input.script !== undefined ? { script: input.script } : {}),
        };
        rollbackPayload = {
          action: 'worker_route_update',
          zoneId: input.zoneId,
          routeId: input.routeId,
          pattern: prevPattern,
          ...(prevScript !== undefined ? { script: prevScript } : {}),
        };
        break;
      }

      case 'worker_route_delete': {
        const routesApi = client.workers.routes;
        if (!routesApi) {
          throw new Error('Cloudflare client does not support Worker routes API.');
        }
        const existing = await routesApi.get(input.routeId, { zone_id: input.zoneId });
        if (!existing || !existing.id) {
          throw new Error(`Worker route ${input.routeId} not found in zone ${input.zoneId}.`);
        }
        const prevPattern = String(existing.pattern ?? '');
        const prevScript =
          typeof existing.script === 'string' && existing.script.length > 0
            ? existing.script
            : undefined;
        summaryDiffText = [
          `Cloudflare Worker Route DELETE in zone ${input.zoneId} (route=${input.routeId}):`,
          `- pattern=${prevPattern} -> script=${prevScript ?? '(disabled/none)'}`,
        ].join('\n');
        payload = {
          type: 'worker_route_delete',
          zoneId: input.zoneId,
          routeId: input.routeId,
        };
        rollbackPayload = {
          action: 'worker_route_create',
          zoneId: input.zoneId,
          pattern: prevPattern,
          ...(prevScript !== undefined ? { script: prevScript } : {}),
        };
        break;
      }
    }

    return planRepo.createPlan({
      plan_id: planId,
      target_service: 'cloudflare',
      summary_diff_text: this.scrubber.scrub(summaryDiffText),
      payload,
      rollback_payload: rollbackPayload,
      status: 'staged',
      expires_at: expiresAt,
      created_at: now,
    });
  }

  /**
   * Controlled Worker deployment (used ONLY by publish_changes).
   * Runs `wrangler versions upload` by default (preview) or `wrangler deploy` when target === 'production'.
   */
  async deployWorker(
    workspacePath: string,
    opts: DeployWorkerOptions = {},
  ): Promise<DeployWorkerResult> {
    const target: 'preview' | 'production' = opts.target ?? 'preview';
    const args: string[] =
      target === 'production' ? ['deploy'] : ['versions', 'upload'];

    if (opts.message) {
      args.push('--message', assertSafeWranglerFlagValue('message', opts.message));
    }
    if (opts.env) {
      args.push('--env', assertSafeWranglerFlagValue('env', opts.env));
    }
    if (opts.configPath) {
      const safeConfigPath = assertWorkspaceRelativeSubpath(workspacePath, opts.configPath, {
        allowRoot: false,
        fieldName: 'configPath',
      });
      args.push('--config', safeConfigPath);
    }

    const res = await this.runWrangler(args, workspacePath);
    const combined = this.scrubber.scrub([res.stdout, res.stderr].filter(Boolean).join('\n'));
    if (res.exitCode !== 0) {
      throw new Error(`wrangler ${args.join(' ')} failed (exit ${res.exitCode}): ${combined}`);
    }

    return {
      target,
      command: `wrangler ${args.join(' ')}`,
      exitCode: res.exitCode,
      deploymentUrl: extractWranglerUrl(combined),
      output: combined,
    };
  }

  /**
   * Controlled Pages deployment (used ONLY by publish_changes).
   */
  async deployPages(
    workspacePath: string,
    opts: DeployPagesOptions,
  ): Promise<DeployPagesResult> {
    if (!opts.projectName.trim() || !opts.directory.trim()) {
      throw new Error('deployPages requires non-empty projectName and directory.');
    }

    const safeProjectName = assertSafeWranglerFlagValue('projectName', opts.projectName.trim());
    const safeDirectory = assertWorkspaceRelativeSubpath(workspacePath, opts.directory, {
      allowRoot: true,
      fieldName: 'directory',
    });

    const args = ['pages', 'deploy', safeDirectory, '--project-name', safeProjectName];
    if (opts.branch) {
      args.push('--branch', assertSafeWranglerFlagValue('branch', opts.branch));
    }
    if (opts.commitMessage) {
      args.push(
        '--commit-message',
        assertSafeWranglerFlagValue('commitMessage', opts.commitMessage),
      );
    }

    const res = await this.runWrangler(args, workspacePath);
    const combined = this.scrubber.scrub([res.stdout, res.stderr].filter(Boolean).join('\n'));
    if (res.exitCode !== 0) {
      throw new Error(`wrangler ${args.join(' ')} failed (exit ${res.exitCode}): ${combined}`);
    }

    return {
      projectName: safeProjectName,
      directory: safeDirectory,
      command: `wrangler ${args.join(' ')}`,
      exitCode: res.exitCode,
      deploymentUrl: extractWranglerUrl(combined),
      output: combined,
    };
  }

  private async executePayloadWithClient(
    client: CloudflareClientLike,
    plan: MutationPlanRecord,
  ): Promise<{
    type: string;
    apiResult: unknown;
    updatedRollbackPayload?: Record<string, unknown> | null;
  }> {
    const payload = plan.payload;
    const type = String(payload.type ?? '');
    let apiResult: unknown;
    let updatedRollbackPayload: Record<string, unknown> | null | undefined;

    switch (type) {
      case 'dns_record_create': {
        const rec = payload.record as Record<string, unknown>;
        const created = await client.dns.records.create({
          zone_id: String(payload.zoneId),
          ...rec,
        });
        apiResult = created;
        if (created && typeof created === 'object' && 'id' in created && created.id) {
          updatedRollbackPayload = {
            ...(plan.rollback_payload ?? {}),
            action: 'dns_record_delete_created',
            zoneId: String(payload.zoneId),
            recordId: String(created.id),
          };
        }
        break;
      }
      case 'dns_record_update': {
        const rec = payload.record as Record<string, unknown>;
        apiResult = await client.dns.records.update(String(payload.recordId), {
          zone_id: String(payload.zoneId),
          ...rec,
        });
        break;
      }
      case 'dns_record_delete': {
        apiResult = await client.dns.records.delete(String(payload.recordId), {
          zone_id: String(payload.zoneId),
        });
        break;
      }
      case 'waf_rule_update': {
        const zoneId = String(payload.zoneId);
        const rules = payload.rules as Array<Record<string, unknown>>;
        const description = payload.description ? String(payload.description) : undefined;
        if (payload.rulesetId) {
          apiResult = await client.rulesets.update(String(payload.rulesetId), {
            zone_id: zoneId,
            ...(description ? { description } : {}),
            rules,
          });
        } else {
          apiResult = await client.rulesets.phases.update(
            String(payload.phase ?? 'http_request_firewall_custom'),
            {
              zone_id: zoneId,
              ...(description ? { description } : {}),
              rules,
            },
          );
        }
        break;
      }
      case 'd1_sql_mutation': {
        apiResult = await collectItems(
          client.d1.database.query(String(payload.databaseId), {
            account_id: String(payload.accountId),
            sql: String(payload.sql),
            params: Array.isArray(payload.params) ? (payload.params as string[]) : undefined,
          }),
        );
        break;
      }
      case 'kv_put': {
        const valuesApi = client.kv.namespaces.values;
        if (!valuesApi) {
          throw new Error('Cloudflare client does not support KV values API.');
        }
        apiResult = await valuesApi.update(String(payload.key), {
          account_id: String(payload.accountId),
          namespace_id: String(payload.namespaceId),
          value: String(payload.value ?? ''),
          ...(typeof payload.expiration === 'number' ? { expiration: payload.expiration } : {}),
          ...(typeof payload.expirationTtl === 'number'
            ? { expiration_ttl: payload.expirationTtl }
            : {}),
          ...(payload.metadata !== undefined ? { metadata: payload.metadata } : {}),
        });
        break;
      }
      case 'kv_delete': {
        const valuesApi = client.kv.namespaces.values;
        if (!valuesApi) {
          throw new Error('Cloudflare client does not support KV values API.');
        }
        apiResult = await valuesApi.delete(String(payload.key), {
          account_id: String(payload.accountId),
          namespace_id: String(payload.namespaceId),
        });
        break;
      }
      case 'worker_route_create': {
        const routesApi = client.workers.routes;
        if (!routesApi) {
          throw new Error('Cloudflare client does not support Worker routes API.');
        }
        const created = await routesApi.create({
          zone_id: String(payload.zoneId),
          pattern: String(payload.pattern),
          ...(typeof payload.script === 'string' ? { script: payload.script } : {}),
        });
        apiResult = created;
        if (created && typeof created === 'object' && 'id' in created && created.id) {
          updatedRollbackPayload = {
            ...(plan.rollback_payload ?? {}),
            action: 'worker_route_delete_created',
            zoneId: String(payload.zoneId),
            routeId: String(created.id),
          };
        }
        break;
      }
      case 'worker_route_update': {
        const routesApi = client.workers.routes;
        if (!routesApi) {
          throw new Error('Cloudflare client does not support Worker routes API.');
        }
        apiResult = await routesApi.update(String(payload.routeId), {
          zone_id: String(payload.zoneId),
          pattern: String(payload.pattern),
          ...(typeof payload.script === 'string' ? { script: payload.script } : {}),
        });
        break;
      }
      case 'worker_route_delete': {
        const routesApi = client.workers.routes;
        if (!routesApi) {
          throw new Error('Cloudflare client does not support Worker routes API.');
        }
        apiResult = await routesApi.delete(String(payload.routeId), {
          zone_id: String(payload.zoneId),
        });
        break;
      }
      default:
        throw new Error(`Unsupported Cloudflare mutation payload type: "${type}"`);
    }

    return { type, apiResult, updatedRollbackPayload };
  }

  private async rollbackPayloadWithClient(
    client: CloudflareClientLike,
    rb: Record<string, unknown>,
  ): Promise<{ action: string; apiResult: unknown }> {
    const action = String(rb.action ?? '');
    let apiResult: unknown;

    switch (action) {
      case 'dns_record_update': {
        const rec = rb.record as Record<string, unknown>;
        apiResult = await client.dns.records.update(String(rb.recordId), {
          zone_id: String(rb.zoneId),
          ...rec,
        });
        break;
      }
      case 'dns_record_create': {
        const rec = rb.record as Record<string, unknown>;
        apiResult = await client.dns.records.create({
          zone_id: String(rb.zoneId),
          ...rec,
        });
        break;
      }
      case 'dns_record_delete_created': {
        const zoneId = String(rb.zoneId);
        if (typeof rb.recordId === 'string' && rb.recordId.length > 0) {
          apiResult = await client.dns.records.delete(rb.recordId, { zone_id: zoneId });
          break;
        }
        const records = await collectItems(
          client.dns.records.list({
            zone_id: zoneId,
            name: rb.name,
            type: rb.type,
          }),
          20,
        );
        const match = records.find(
          (r) =>
            String(r.name ?? '') === String(rb.name) &&
            String(r.type ?? '') === String(rb.type) &&
            String(r.content ?? '') === String(rb.content),
        );
        if (!match?.id) {
          throw new Error(
            `Unable to locate created DNS record (${String(rb.type)} ${String(rb.name)}) for rollback deletion.`,
          );
        }
        apiResult = await client.dns.records.delete(String(match.id), { zone_id: zoneId });
        break;
      }
      case 'waf_rule_update': {
        const zoneId = String(rb.zoneId);
        const rules = rb.rules as Array<Record<string, unknown>>;
        const description = rb.description ? String(rb.description) : undefined;
        if (rb.rulesetId) {
          apiResult = await client.rulesets.update(String(rb.rulesetId), {
            zone_id: zoneId,
            ...(description ? { description } : {}),
            rules,
          });
        } else {
          apiResult = await client.rulesets.phases.update(
            String(rb.phase ?? 'http_request_firewall_custom'),
            {
              zone_id: zoneId,
              ...(description ? { description } : {}),
              rules,
            },
          );
        }
        break;
      }
      case 'd1_sql_mutation': {
        apiResult = await collectItems(
          client.d1.database.query(String(rb.databaseId), {
            account_id: String(rb.accountId),
            sql: String(rb.sql),
          }),
        );
        break;
      }
      case 'kv_put': {
        const valuesApi = client.kv.namespaces.values;
        if (!valuesApi) {
          throw new Error('Cloudflare client does not support KV values API.');
        }
        apiResult = await valuesApi.update(String(rb.key), {
          account_id: String(rb.accountId),
          namespace_id: String(rb.namespaceId),
          value: String(rb.value ?? ''),
        });
        break;
      }
      case 'kv_delete': {
        const valuesApi = client.kv.namespaces.values;
        if (!valuesApi) {
          throw new Error('Cloudflare client does not support KV values API.');
        }
        apiResult = await valuesApi.delete(String(rb.key), {
          account_id: String(rb.accountId),
          namespace_id: String(rb.namespaceId),
        });
        break;
      }
      case 'worker_route_create': {
        const routesApi = client.workers.routes;
        if (!routesApi) {
          throw new Error('Cloudflare client does not support Worker routes API.');
        }
        apiResult = await routesApi.create({
          zone_id: String(rb.zoneId),
          pattern: String(rb.pattern),
          ...(typeof rb.script === 'string' ? { script: rb.script } : {}),
        });
        break;
      }
      case 'worker_route_update': {
        const routesApi = client.workers.routes;
        if (!routesApi) {
          throw new Error('Cloudflare client does not support Worker routes API.');
        }
        apiResult = await routesApi.update(String(rb.routeId), {
          zone_id: String(rb.zoneId),
          pattern: String(rb.pattern),
          ...(typeof rb.script === 'string' ? { script: rb.script } : {}),
        });
        break;
      }
      case 'worker_route_delete_created': {
        const routesApi = client.workers.routes;
        if (!routesApi) {
          throw new Error('Cloudflare client does not support Worker routes API.');
        }
        const zoneId = String(rb.zoneId);
        if (typeof rb.routeId === 'string' && rb.routeId.length > 0) {
          apiResult = await routesApi.delete(rb.routeId, { zone_id: zoneId });
          break;
        }
        const routes = await collectItems(routesApi.list({ zone_id: zoneId }), 50);
        const match = routes.find((r) => String(r.pattern ?? '') === String(rb.pattern));
        if (!match?.id) {
          throw new Error(
            `Unable to locate created Worker route (${String(rb.pattern)}) for rollback deletion.`,
          );
        }
        apiResult = await routesApi.delete(String(match.id), { zone_id: zoneId });
        break;
      }
      default:
        throw new Error(`Unsupported rollback action: "${action}"`);
    }

    return { action, apiResult };
  }

  /**
   * Returns a typed `MutationTargetAdapter` for wiring into `MutationPlanGate`.
   */
  asMutationTargetAdapter(): MutationTargetAdapter {
    return {
      targetPrefix: 'cloudflare',
      auditActionPrefix: 'cloudflare',
      matchesTargetService: (targetService: string) => targetService === 'cloudflare',
      executeStagedPayload: async (plan: MutationPlanRecord) => {
        const client = this.getWriteClient();
        const { type, apiResult, updatedRollbackPayload } = await this.executePayloadWithClient(
          client,
          plan,
        );
        return {
          result: this.scrubber.scrubObject(apiResult),
          auditTarget: plan.plan_id,
          auditDetails: { type },
          updatedRollbackPayload,
        };
      },
      rollbackExecutedPayload: async (plan: MutationPlanRecord) => {
        const client = this.getWriteClient();
        if (!plan.rollback_payload) {
          throw new Error(`Plan "${plan.plan_id}" has no rollback_payload stored.`);
        }
        const { action, apiResult } = await this.rollbackPayloadWithClient(
          client,
          plan.rollback_payload,
        );
        return {
          result: this.scrubber.scrubObject(apiResult),
          auditTarget: plan.plan_id,
          auditDetails: { rollbackAction: action },
        };
      },
    };
  }

  /**
   * Executes a previously staged Cloudflare mutation plan.
   * Rejects missing, wrong-target, already-executed, or expired plan_id atomically
   * without corrupting non-Cloudflare plans.
   */
  async executeStagedCloudflarePlan(
    planRepo: PlanStore,
    auditRepo: AuditLogger,
    planId: string,
    actor = 'system',
  ): Promise<ExecutePlanResult> {
    const client = this.getWriteClient();

    const preview = planRepo.getPlan(planId);
    const preDecision = this.policy.evaluatePlanExecution(preview, {
      expectedTargetPrefix: 'cloudflare',
    });
    if (!preDecision.allowed && preDecision.code === 'PLAN_TARGET_MISMATCH') {
      auditRepo.record({
        actor,
        action: 'cloudflare.execute_plan',
        target: planId,
        status: 'denied',
        details: { error: `Wrong target_service: ${preview?.target_service ?? 'unknown'}` },
      });
      throw new Error(preDecision.reason);
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
        action: 'cloudflare.execute_plan',
        target: planId,
        status: 'denied',
        details: { reason: claim.reason },
      });
      throw new Error(reasonMsg);
    }

    const plan = claim.plan;
    if (plan.target_service !== 'cloudflare') {
      planRepo.updatePlanStatus(planId, 'staged');
      auditRepo.record({
        actor,
        action: 'cloudflare.execute_plan',
        target: planId,
        status: 'denied',
        details: { error: `Wrong target_service: ${plan.target_service}` },
      });
      throw new Error(
        `Plan "${planId}" targets "${plan.target_service}", not "cloudflare".`,
      );
    }

    try {
      const { type, apiResult, updatedRollbackPayload } = await this.executePayloadWithClient(
        client,
        plan,
      );
      if (updatedRollbackPayload !== undefined) {
        planRepo.updatePlanRollbackPayload(planId, updatedRollbackPayload);
      }

      const cleanResult = this.scrubber.scrubObject(apiResult);
      planRepo.updatePlanStatus(planId, 'executed', Date.now());
      auditRepo.record({
        actor,
        action: 'cloudflare.execute_plan',
        target: planId,
        status: 'success',
        details: { type },
      });

      return {
        planId,
        status: 'executed',
        result: cleanResult,
      };
    } catch (err) {
      const msg = this.scrubber.scrub(err instanceof Error ? err.message : String(err));
      planRepo.updatePlanStatus(planId, 'failed');
      auditRepo.record({
        actor,
        action: 'cloudflare.execute_plan',
        target: planId,
        status: 'failure',
        details: { error: msg },
      });
      throw new Error(`Failed executing Cloudflare plan "${planId}": ${msg}`);
    }
  }

  /**
   * Executes the stored `rollback_payload_json` for an already-executed Cloudflare plan
   * and marks it `rolled_back` with an audit log record.
   */
  async rollbackExecutedPlan(
    planRepo: PlanStore,
    auditRepo: AuditLogger,
    planId: string,
    actor = 'system',
  ): Promise<RollbackPlanResult> {
    const client = this.getWriteClient();

    const preview = planRepo.getPlan(planId);
    const preDecision = this.policy.evaluatePlanRollback(preview, {
      expectedTargetPrefix: 'cloudflare',
    });
    if (
      !preDecision.allowed &&
      (preDecision.code === 'PLAN_TARGET_MISMATCH' || preDecision.code === 'PLAN_NO_ROLLBACK')
    ) {
      auditRepo.record({
        actor,
        action: 'cloudflare.rollback_plan',
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
        action: 'cloudflare.rollback_plan',
        target: planId,
        status: 'denied',
        details: { reason: claim.reason },
      });
      throw new Error(reasonMsg);
    }

    const plan = claim.plan;
    if (plan.target_service !== 'cloudflare') {
      planRepo.updatePlanStatus(planId, 'executed');
      auditRepo.record({
        actor,
        action: 'cloudflare.rollback_plan',
        target: planId,
        status: 'denied',
        details: { error: `Wrong target_service: ${plan.target_service}` },
      });
      throw new Error(`Plan "${planId}" targets "${plan.target_service}", not "cloudflare".`);
    }
    if (!plan.rollback_payload) {
      planRepo.updatePlanStatus(planId, 'executed');
      auditRepo.record({
        actor,
        action: 'cloudflare.rollback_plan',
        target: planId,
        status: 'denied',
        details: { error: 'Missing rollback_payload' },
      });
      throw new Error(`Plan "${planId}" has no rollback_payload stored.`);
    }

    const rb = plan.rollback_payload;
    const action = String(rb.action ?? '');

    try {
      const { apiResult } = await this.rollbackPayloadWithClient(client, rb);

      planRepo.updatePlanStatus(planId, 'rolled_back');
      auditRepo.record({
        actor,
        action: 'cloudflare.rollback_plan',
        target: planId,
        status: 'success',
        details: { rollbackAction: action },
      });

      return {
        planId,
        status: 'rolled_back',
        result: this.scrubber.scrubObject(apiResult),
      };
    } catch (err) {
      const msg = this.scrubber.scrub(err instanceof Error ? err.message : String(err));
      planRepo.updatePlanStatus(planId, 'failed');
      auditRepo.record({
        actor,
        action: 'cloudflare.rollback_plan',
        target: planId,
        status: 'failure',
        details: { error: msg, rollbackAction: action },
      });
      throw new Error(`Failed rolling back Cloudflare plan "${planId}": ${msg}`);
    }
  }
}
