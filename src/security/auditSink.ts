import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { AuditLogRecord, ScrubberLike } from '../types.js';
import { SecretScrubber } from '../utils/secretScrubber.js';

export const GENESIS_AUDIT_HASH = '0'.repeat(64);

export type AuditCategory =
  | 'auth'
  | 'admin'
  | 'mcp_tool'
  | 'workspace'
  | 'runner'
  | 'mutation'
  | 'policy'
  | 'resilience'
  | 'system';

export type AuditSeverity = 'info' | 'warn' | 'high' | 'critical';

export type AuditStatus = 'success' | 'failure' | 'denied' | string;

export interface StructuredAuditInput {
  actor: string;
  action: string;
  target: string;
  status: AuditStatus;
  category?: AuditCategory;
  severity?: AuditSeverity;
  correlationId?: string;
  clientId?: string;
  ip?: string;
  details?: Record<string, unknown>;
  created_at?: number;
}

export interface StructuredAuditEvent {
  schema_version: 'bastion.audit.v1';
  event_id: string;
  seq: number;
  created_at: number;
  iso_time: string;
  actor: string;
  action: string;
  target: string;
  status: AuditStatus;
  category: AuditCategory;
  severity: AuditSeverity;
  correlation_id?: string;
  client_id?: string;
  ip?: string;
  details: Record<string, unknown>;
  prev_hash: string;
  entry_hash: string;
}

/**
 * Narrow decoupled port for structured audit-log consumers (SQLite, NDJSON file, memory buffer, SIEM/webhook).
 */
export interface AuditSink {
  readonly name: string;
  write(event: StructuredAuditEvent): void | Promise<void>;
  flush?(): Promise<void>;
  close?(): Promise<void>;
}

/**
 * Narrow port that callers (middleware, policy evaluator, MCP tools, auth/admin routes) depend on
 * without coupling to SQLite or filesystem storage.
 */
export interface AuditEventPublisher {
  emit(input: StructuredAuditInput): StructuredAuditEvent;
  flush(): Promise<void>;
  close(): Promise<void>;
}

export interface AuditChainVerificationResult {
  valid: boolean;
  checkedCount: number;
  brokenAtIndex?: number;
  reason?: string;
}

function canonicalizeJsonValue(value: unknown): unknown {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalizeJsonValue);
  }
  const obj = value as Record<string, unknown>;
  const sortedKeys = Object.keys(obj).sort();
  const out: Record<string, unknown> = {};
  for (const k of sortedKeys) {
    const v = obj[k];
    if (v !== undefined) {
      out[k] = canonicalizeJsonValue(v);
    }
  }
  return out;
}

export function computeAuditEntryHash(
  prevHash: string,
  payload: Omit<StructuredAuditEvent, 'entry_hash'>,
): string {
  const canonical = JSON.stringify(canonicalizeJsonValue(payload));
  return crypto.createHash('sha256').update(`${prevHash}|${canonical}`, 'utf8').digest('hex');
}

/**
 * Verifies cryptographic SHA-256 hash chain continuity and payload integrity across structured audit events.
 */
export function verifyAuditChain(
  events: readonly StructuredAuditEvent[],
  expectedInitialPrevHash = GENESIS_AUDIT_HASH,
): AuditChainVerificationResult {
  let expectedPrev = expectedInitialPrevHash;

  for (let i = 0; i < events.length; i++) {
    const ev = events[i]!;
    if (i > 0 && ev.seq <= events[i - 1]!.seq) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtIndex: i,
        reason: `Non-monotonic sequence number at index ${i}: ${ev.seq} <= ${events[i - 1]!.seq}`,
      };
    }

    if (ev.prev_hash !== expectedPrev) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtIndex: i,
        reason: `prev_hash mismatch at index ${i}: expected ${expectedPrev}, got ${ev.prev_hash}`,
      };
    }

    const { entry_hash, ...rest } = ev;
    const recomputed = computeAuditEntryHash(ev.prev_hash, rest);
    if (entry_hash !== recomputed) {
      return {
        valid: false,
        checkedCount: i,
        brokenAtIndex: i,
        reason: `entry_hash tampered at index ${i}: expected ${recomputed}, got ${entry_hash}`,
      };
    }

    expectedPrev = entry_hash;
  }

  return {
    valid: true,
    checkedCount: events.length,
  };
}

export function inferAuditCategory(action: string): AuditCategory {
  const lower = action.toLowerCase();
  if (lower.startsWith('admin')) return 'admin';
  if (lower.startsWith('policy')) return 'policy';
  if (
    lower.startsWith('ratelimit') ||
    lower.startsWith('rate_limit') ||
    lower.startsWith('circuit_breaker') ||
    lower.startsWith('resilience')
  ) {
    return 'resilience';
  }
  if (
    lower.startsWith('oauth') ||
    lower.startsWith('dcr') ||
    lower.startsWith('token') ||
    lower.startsWith('authorize') ||
    lower.startsWith('idp') ||
    lower.startsWith('auth')
  ) {
    return 'auth';
  }
  if (
    lower.startsWith('publish_changes') ||
    lower.startsWith('stage_mutation_plan') ||
    lower.endsWith('.execute_plan') ||
    lower.includes('rollback_plan')
  ) {
    return 'mutation';
  }
  if (
    lower.startsWith('workspace.') ||
    lower.startsWith('workspace_manage') ||
    lower.startsWith('code_patch') ||
    lower.startsWith('code_explore')
  ) {
    return 'workspace';
  }
  if (
    lower.startsWith('runner.') ||
    lower.startsWith('job.') ||
    lower.startsWith('codex') ||
    lower.startsWith('workspace_exec') ||
    lower.startsWith('dispatch_runner') ||
    lower.startsWith('job_status')
  ) {
    return 'runner';
  }
  if (
    lower.startsWith('mcp.') ||
    lower.startsWith('tool.') ||
    lower.startsWith('github_inspect') ||
    lower.startsWith('infra_inspect')
  ) {
    return 'mcp_tool';
  }
  return 'system';
}

export function inferAuditSeverity(
  action: string,
  status: AuditStatus,
  category: AuditCategory,
): AuditSeverity {
  const lower = action.toLowerCase();
  if (
    lower.includes('theft') ||
    lower.includes('family_revoked') ||
    lower.includes('tamper') ||
    lower.includes('escape')
  ) {
    return 'critical';
  }

  if (status === 'denied') {
    if (category === 'policy' || category === 'mutation' || category === 'auth') {
      return 'high';
    }
    return 'warn';
  }

  if (status === 'failure') {
    if (category === 'mutation' || category === 'resilience') {
      return 'high';
    }
    return 'warn';
  }

  return 'info';
}

function resolveRealPathWithAncestor(targetPath: string): string {
  const resolved = path.resolve(targetPath);
  if (fs.existsSync(resolved)) {
    return fs.realpathSync(resolved);
  }
  let current = path.dirname(resolved);
  while (true) {
    if (fs.existsSync(current)) {
      const realAncestor = fs.realpathSync(current);
      const suffix = path.relative(current, resolved);
      return suffix ? path.join(realAncestor, suffix) : realAncestor;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return resolved;
    }
    current = parent;
  }
}

export function assertAuditPathOutsideWorkspaces(filePath: string, workspacesDir?: string): string {
  const resolvedFile = path.resolve(filePath);
  if (workspacesDir) {
    const realTarget = resolveRealPathWithAncestor(resolvedFile);
    const realWorkspaces = resolveRealPathWithAncestor(workspacesDir);
    const normTarget = process.platform === 'win32' ? realTarget.toLowerCase() : realTarget;
    const normWorkspaces =
      process.platform === 'win32' ? realWorkspaces.toLowerCase() : realWorkspaces;
    if (normTarget === normWorkspaces || normTarget.startsWith(normWorkspaces + path.sep)) {
      throw new Error(
        `Refusing to place structured audit log inside workspaces directory: ${realTarget}`,
      );
    }
  }
  return resolvedFile;
}

// ============================================================================
// Concrete Pluggable Audit Sinks
// ============================================================================

export interface AuditQueryFilter {
  actor?: string;
  action?: string;
  actionPrefix?: string;
  target?: string;
  status?: AuditStatus;
  category?: AuditCategory;
  severity?: AuditSeverity;
  correlationId?: string;
  clientId?: string;
  since?: number;
  until?: number;
  limit?: number;
  offset?: number;
}

/**
 * Bounded in-memory ring-buffer sink for diagnostics, admin telemetry, and deterministic tests.
 */
export class MemoryAuditSink implements AuditSink {
  readonly name: string;
  private readonly maxEntries: number;
  private readonly entries: StructuredAuditEvent[] = [];

  constructor(options: { name?: string; maxEntries?: number } = {}) {
    this.name = options.name ?? 'memory';
    this.maxEntries = Math.max(1, options.maxEntries ?? 1000);
  }

  write(event: StructuredAuditEvent): void {
    if (this.entries.length >= this.maxEntries) {
      this.entries.shift();
    }
    this.entries.push(event);
  }

  /**
   * Returns events in chronological insertion order (oldest -> newest) for hash-chain verification.
   */
  getEvents(): StructuredAuditEvent[] {
    return [...this.entries];
  }

  /**
   * Queries events in reverse-chronological order (newest -> oldest) matching AuditRepository semantics.
   */
  query(filter: AuditQueryFilter = {}): StructuredAuditEvent[] {
    const matched: StructuredAuditEvent[] = [];
    for (let i = this.entries.length - 1; i >= 0; i--) {
      const ev = this.entries[i]!;
      if (filter.actor !== undefined && ev.actor !== filter.actor) continue;
      if (filter.action !== undefined && ev.action !== filter.action) continue;
      if (filter.actionPrefix !== undefined && !ev.action.startsWith(filter.actionPrefix)) continue;
      if (filter.target !== undefined && ev.target !== filter.target) continue;
      if (filter.status !== undefined && ev.status !== filter.status) continue;
      if (filter.category !== undefined && ev.category !== filter.category) continue;
      if (filter.severity !== undefined && ev.severity !== filter.severity) continue;
      if (filter.correlationId !== undefined && ev.correlation_id !== filter.correlationId) continue;
      if (filter.clientId !== undefined && ev.client_id !== filter.clientId) continue;
      if (filter.since !== undefined && ev.created_at < filter.since) continue;
      if (filter.until !== undefined && ev.created_at > filter.until) continue;
      matched.push(ev);
    }

    const offset = Math.max(0, filter.offset ?? 0);
    const limit = Math.max(1, filter.limit ?? 100);
    return matched.slice(offset, offset + limit);
  }

  size(): number {
    return this.entries.length;
  }

  clear(): void {
    this.entries.length = 0;
  }
}

export interface JsonlFileAuditSinkOptions {
  filePath: string;
  workspacesDir?: string;
  maxFileBytes?: number;
  maxRotatedFiles?: number;
  name?: string;
}

/**
 * Append-only NDJSON (JSON Lines) structured audit sink with size-based file rotation
 * and strict containment checks forbidding placement inside `/workspaces`.
 */
export class JsonlFileAuditSink implements AuditSink {
  readonly name: string;
  private readonly filePath: string;
  private readonly maxFileBytes: number;
  private readonly maxRotatedFiles: number;

  constructor(options: JsonlFileAuditSinkOptions) {
    this.name = options.name ?? 'jsonl-file';
    this.filePath = assertAuditPathOutsideWorkspaces(options.filePath, options.workspacesDir);
    this.maxFileBytes = Math.max(4096, options.maxFileBytes ?? 10 * 1024 * 1024);
    this.maxRotatedFiles = Math.max(1, options.maxRotatedFiles ?? 3);

    const dir = path.dirname(this.filePath);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  getFilePath(): string {
    return this.filePath;
  }

  write(event: StructuredAuditEvent): void {
    const line = `${JSON.stringify(event)}\n`;
    const lineBytes = Buffer.byteLength(line, 'utf8');
    this.rotateIfNeeded(lineBytes);
    fs.appendFileSync(this.filePath, line, { encoding: 'utf8', mode: 0o600 });
  }

  readEvents(): StructuredAuditEvent[] {
    if (!fs.existsSync(this.filePath)) {
      return [];
    }
    const raw = fs.readFileSync(this.filePath, 'utf8');
    return raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as StructuredAuditEvent);
  }

  private rotateIfNeeded(incomingBytes: number): void {
    if (!fs.existsSync(this.filePath)) return;
    let currentSize = 0;
    try {
      currentSize = fs.statSync(this.filePath).size;
    } catch {
      return;
    }

    if (currentSize + incomingBytes <= this.maxFileBytes) {
      return;
    }

    for (let idx = this.maxRotatedFiles; idx >= 1; idx--) {
      const src = idx === 1 ? this.filePath : `${this.filePath}.${idx - 1}`;
      const dst = `${this.filePath}.${idx}`;
      if (fs.existsSync(src)) {
        if (idx === this.maxRotatedFiles && fs.existsSync(dst)) {
          fs.rmSync(dst, { force: true });
        }
        fs.renameSync(src, dst);
      }
    }
  }
}

export interface CallbackAuditSinkOptions {
  name?: string;
  filter?: (event: StructuredAuditEvent) => boolean;
  onEvent: (event: StructuredAuditEvent) => void | Promise<void>;
  onClose?: () => void | Promise<void>;
}

/**
 * Pluggable observer sink for async webhook alerts, SIEM shipping, or custom structured log streams.
 */
export class CallbackAuditSink implements AuditSink {
  readonly name: string;
  private readonly filter?: (event: StructuredAuditEvent) => boolean;
  private readonly onEvent: (event: StructuredAuditEvent) => void | Promise<void>;
  private readonly onClose?: () => void | Promise<void>;

  constructor(options: CallbackAuditSinkOptions) {
    this.name = options.name ?? 'callback';
    this.filter = options.filter;
    this.onEvent = options.onEvent;
    this.onClose = options.onClose;
  }

  write(event: StructuredAuditEvent): void | Promise<void> {
    if (this.filter && !this.filter(event)) {
      return;
    }
    return this.onEvent(event);
  }

  async close(): Promise<void> {
    if (this.onClose) {
      await this.onClose();
    }
  }
}

export interface AuditRecordWriter {
  record(input: {
    actor: string;
    action: string;
    target: string;
    status: string;
    details?: Record<string, unknown>;
    created_at?: number;
  }): AuditLogRecord;
  recordDirect?(input: {
    actor: string;
    action: string;
    target: string;
    status: string;
    details?: Record<string, unknown>;
    created_at?: number;
  }): AuditLogRecord;
  isForwardingToPublisher?(): boolean;
}

/**
 * Adapter sink persisting structured audit events into an AuditRecordWriter (such as SQLite AuditRepository).
 */
export class SqliteAuditSink implements AuditSink {
  readonly name: string;

  constructor(
    private readonly writer: AuditRecordWriter,
    options: { name?: string } = {},
  ) {
    this.name = options.name ?? 'sqlite';
  }

  write(event: StructuredAuditEvent): void {
    if (this.writer.isForwardingToPublisher?.()) {
      return;
    }
    const payload = {
      actor: event.actor,
      action: event.action,
      target: event.target,
      status: event.status,
      created_at: event.created_at,
      details: {
        ...event.details,
        _audit: {
          event_id: event.event_id,
          seq: event.seq,
          category: event.category,
          severity: event.severity,
          ...(event.correlation_id ? { correlation_id: event.correlation_id } : {}),
          ...(event.client_id ? { client_id: event.client_id } : {}),
          ...(event.ip ? { ip: event.ip } : {}),
          prev_hash: event.prev_hash,
          entry_hash: event.entry_hash,
        },
      },
    };
    if (this.writer.recordDirect) {
      this.writer.recordDirect(payload);
    } else {
      this.writer.record(payload);
    }
  }
}

// ============================================================================
// StructuredAuditLogger (Composite Scrubbing + Hash-Chaining Fan-Out Hub)
// ============================================================================

export interface StructuredAuditLoggerOptions {
  sinks?: AuditSink[];
  scrubber?: ScrubberLike;
  nowFn?: () => number;
  initialPrevHash?: string;
  onSinkError?: (sinkName: string, error: unknown, event: StructuredAuditEvent) => void;
}

/**
 * Decoupled structured audit-log coordinator:
 * 1. Scrubs all fields & nested details with `SecretScrubber` BEFORE hashing or fan-out.
 * 2. Enriches events with `event_id`, monotonic `seq`, `category`, `severity`, and ISO timestamp.
 * 3. Chains every entry with a tamper-evident SHA-256 `prev_hash` -> `entry_hash`.
 * 4. Isolates failures across synchronous and asynchronous `AuditSink` targets.
 */
export class StructuredAuditLogger implements AuditEventPublisher {
  private readonly sinks: AuditSink[] = [];
  private readonly scrubber: ScrubberLike;
  private readonly nowFn: () => number;
  private readonly onSinkError?: (
    sinkName: string,
    error: unknown,
    event: StructuredAuditEvent,
  ) => void;
  private readonly pendingWrites = new Set<Promise<void>>();
  private seq = 0;
  private lastHash: string;
  private closed = false;

  constructor(options: StructuredAuditLoggerOptions = {}) {
    this.scrubber = options.scrubber ?? new SecretScrubber();
    this.nowFn = options.nowFn ?? Date.now;
    this.lastHash = options.initialPrevHash ?? GENESIS_AUDIT_HASH;
    this.onSinkError = options.onSinkError;
    if (options.sinks) {
      this.sinks.push(...options.sinks);
    }
  }

  addSink(sink: AuditSink): void {
    this.sinks.push(sink);
  }

  removeSink(name: string): boolean {
    const idx = this.sinks.findIndex((s) => s.name === name);
    if (idx === -1) return false;
    this.sinks.splice(idx, 1);
    return true;
  }

  getSinks(): readonly AuditSink[] {
    return this.sinks;
  }

  getLastHash(): string {
    return this.lastHash;
  }

  emit(input: StructuredAuditInput): StructuredAuditEvent {
    const createdAt = input.created_at ?? this.nowFn();
    const actor = this.scrubber.scrub(input.actor || 'unknown');
    const action = this.scrubber.scrub(input.action || 'unknown');
    const target = this.scrubber.scrub(input.target || 'unknown');
    const status = this.scrubber.scrub(input.status || 'unknown');
    const category = input.category ?? inferAuditCategory(action);
    const severity = input.severity ?? inferAuditSeverity(action, status, category);
    const scrubbedDetails = this.scrubber.scrubObject(input.details ?? {});
    const correlationId = input.correlationId
      ? this.scrubber.scrub(input.correlationId)
      : undefined;
    const clientId = input.clientId ? this.scrubber.scrub(input.clientId) : undefined;
    const ip = input.ip ? this.scrubber.scrub(input.ip) : undefined;

    this.seq += 1;
    const seq = this.seq;
    const prevHash = this.lastHash;
    const eventId = `aud_${createdAt}_${crypto.randomBytes(6).toString('hex')}`;

    const withoutHash: Omit<StructuredAuditEvent, 'entry_hash'> = {
      schema_version: 'bastion.audit.v1',
      event_id: eventId,
      seq,
      created_at: createdAt,
      iso_time: new Date(createdAt).toISOString(),
      actor,
      action,
      target,
      status,
      category,
      severity,
      ...(correlationId ? { correlation_id: correlationId } : {}),
      ...(clientId ? { client_id: clientId } : {}),
      ...(ip ? { ip } : {}),
      details: scrubbedDetails,
      prev_hash: prevHash,
    };

    const entryHash = computeAuditEntryHash(prevHash, withoutHash);
    this.lastHash = entryHash;

    const event: StructuredAuditEvent = {
      ...withoutHash,
      entry_hash: entryHash,
    };

    if (this.closed) {
      return event;
    }

    for (const sink of this.sinks) {
      try {
        const maybePromise = sink.write(event);
        if (maybePromise && typeof (maybePromise as Promise<void>).then === 'function') {
          const tracked = Promise.resolve(maybePromise)
            .catch((err) => {
              this.onSinkError?.(sink.name, err, event);
            })
            .finally(() => {
              this.pendingWrites.delete(tracked);
            });
          this.pendingWrites.add(tracked);
        }
      } catch (err) {
        this.onSinkError?.(sink.name, err, event);
      }
    }

    return event;
  }

  async flush(): Promise<void> {
    if (this.pendingWrites.size > 0) {
      await Promise.allSettled(Array.from(this.pendingWrites));
    }
    await Promise.allSettled(
      this.sinks.map((sink) => (sink.flush ? sink.flush() : Promise.resolve())),
    );
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.flush();
    await Promise.allSettled(
      this.sinks.map((sink) => (sink.close ? sink.close() : Promise.resolve())),
    );
  }
}
