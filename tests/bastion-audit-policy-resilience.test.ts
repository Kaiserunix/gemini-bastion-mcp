import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Hono } from 'hono';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createGatewayApp, type GatewayAppInstance } from '../src/app.js';
import { computeS256Challenge, hashPasswordScrypt } from '../src/auth/index.js';
import { loadConfig } from '../src/config.js';
import {
  CloudflareService,
  type CloudflareClientLike,
} from '../src/core/cloudflareService.js';
import { createRepositories } from '../src/db/repositories/index.js';
import { openDatabase, type GatewayDatabase } from '../src/db/sqlite.js';
import {
  CallbackAuditSink,
  CircuitBreaker,
  CircuitBreakerRegistry,
  CircuitOpenError,
  GENESIS_AUDIT_HASH,
  JsonlFileAuditSink,
  MemoryAuditSink,
  PolicyEvaluator,
  SlidingWindowRateLimiter,
  SqliteAuditSink,
  StructuredAuditLogger,
  TokenBucketRateLimiter,
  createBastionPolicyEvaluator,
  createResilienceMiddleware,
  extractToolPolicyContext,
  inferAuditCategory,
  inferAuditSeverity,
  loadPolicyRulesFromSources,
  verifyAuditChain,
  type StructuredAuditEvent,
} from '../src/security/index.js';
import { REDACTED_PLACEHOLDER, SecretScrubber } from '../src/utils/secretScrubber.js';

const tempDirs: string[] = [];
const openDbs: GatewayDatabase[] = [];
const gateways: GatewayAppInstance[] = [];

function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

function extractHiddenInput(html: string, name: string): string {
  const regex = new RegExp(`name="${name}"\\s+value="([^"]+)"`, 'i');
  const match = regex.exec(html);
  if (!match?.[1]) {
    throw new Error(`Could not extract hidden input "${name}"`);
  }
  return match[1];
}

afterEach(async () => {
  for (const gw of gateways.splice(0)) {
    await gw.shutdown();
  }
  for (const db of openDbs.splice(0)) {
    try {
      db.close();
    } catch {
      // ignore
    }
  }
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// 1. Structured Audit-Log Sink Suite
// ============================================================================

describe('StructuredAuditLogger & Pluggable AuditSinks', () => {
  it('scrubs secrets before computing SHA-256 hash chain and verifies tamper detection', () => {
    const memorySink = new MemoryAuditSink({ maxEntries: 50 });
    const scrubber = new SecretScrubber({
      extraSecrets: ['custom_gateway_signing_secret_98765'],
    });
    let now = 1_700_000_000_000;
    const logger = new StructuredAuditLogger({
      sinks: [memorySink],
      scrubber,
      nowFn: () => {
        now += 1000;
        return now;
      },
    });

    const ev1 = logger.emit({
      actor: 'client_alpha',
      action: 'oauth.token_issued',
      target: 'Bearer super_secret_bearer_token_value',
      status: 'success',
      correlationId: 'req-001',
      details: {
        gh_pat: 'ghp_abcdefghijklmnopqrstuvwxyz123456',
        openai_key: 'sk-proj-abcdefghijklmnopqrstuvwxyz123456',
        nested: {
          signing: 'custom_gateway_signing_secret_98765',
        },
      },
    });

    const ev2 = logger.emit({
      actor: 'client_alpha',
      action: 'policy.denied',
      target: 'publish_changes:github_pr',
      status: 'denied',
      correlationId: 'req-002',
      details: { branch: 'main' },
    });

    const ev3 = logger.emit({
      actor: 'admin',
      action: 'oauth.token_theft_family_revoked',
      target: 'fam_123',
      status: 'denied',
      details: { reason: 'reused_refresh_token_outside_grace' },
    });

    expect(ev1.prev_hash).toBe(GENESIS_AUDIT_HASH);
    expect(ev2.prev_hash).toBe(ev1.entry_hash);
    expect(ev3.prev_hash).toBe(ev2.entry_hash);
    expect(ev1.category).toBe('auth');
    expect(ev2.category).toBe('policy');
    expect(ev2.severity).toBe('high');
    expect(ev3.severity).toBe('critical');

    const serialized = JSON.stringify(memorySink.getEvents());
    expect(serialized).not.toContain('super_secret_bearer_token_value');
    expect(serialized).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz123456');
    expect(serialized).not.toContain('sk-proj-abcdefghijklmnopqrstuvwxyz123456');
    expect(serialized).not.toContain('custom_gateway_signing_secret_98765');
    expect(serialized).toContain(REDACTED_PLACEHOLDER);

    const chainOk = verifyAuditChain(memorySink.getEvents());
    expect(chainOk).toEqual({ valid: true, checkedCount: 3 });

    // Tamper with middle record details -> hash verification catches exact index
    const tamperedPayload = memorySink.getEvents().map((e) => ({
      ...e,
      details: { ...e.details },
    }));
    tamperedPayload[1]!.details.branch = 'feature/innocent';
    const chainTampered = verifyAuditChain(tamperedPayload);
    expect(chainTampered.valid).toBe(false);
    expect(chainTampered.brokenAtIndex).toBe(1);
    expect(chainTampered.reason).toContain('entry_hash tampered');

    // Drop middle record -> prev_hash continuity check catches tampering
    const dropped = [memorySink.getEvents()[0]!, memorySink.getEvents()[2]!];
    const chainDropped = verifyAuditChain(dropped);
    expect(chainDropped.valid).toBe(false);
    expect(chainDropped.brokenAtIndex).toBe(1);
    expect(chainDropped.reason).toContain('prev_hash mismatch');
  });

  it('supports JsonlFileAuditSink rotation and rejects paths inside WORKSPACES_DIR', () => {
    const baseDir = makeTempDir('bastion-audit-jsonl-');
    const workspacesDir = path.join(baseDir, 'workspaces');
    const auditDir = path.join(baseDir, 'data', 'audit');
    fs.mkdirSync(workspacesDir, { recursive: true });

    expect(
      () =>
        new JsonlFileAuditSink({
          filePath: path.join(workspacesDir, 'demo', 'audit.jsonl'),
          workspacesDir,
        }),
    ).toThrow(/inside workspaces directory/);

    expect(() =>
      loadConfig({
        DATA_DIR: path.join(baseDir, 'data'),
        WORKSPACES_DIR: workspacesDir,
        AUDIT_LOG_FILE_PATH: path.join(workspacesDir, 'leaked-audit.jsonl'),
      }),
    ).toThrow(/AUDIT_LOG_FILE_PATH/);

    const filePath = path.join(auditDir, 'bastion-audit.jsonl');
    const fileSink = new JsonlFileAuditSink({
      filePath,
      workspacesDir,
      maxFileBytes: 4096, // minimum 4KB rotation threshold
      maxRotatedFiles: 2,
    });
    const logger = new StructuredAuditLogger({ sinks: [fileSink] });

    for (let i = 0; i < 25; i++) {
      logger.emit({
        actor: 'client-rotator',
        action: 'workspace_manage.sync_github',
        target: `repo-${i}`,
        status: 'success',
        details: { padding: 'X'.repeat(250), index: i },
      });
    }

    expect(fs.existsSync(filePath)).toBe(true);
    expect(fs.existsSync(`${filePath}.1`)).toBe(true);
    expect(fs.existsSync(`${filePath}.2`)).toBe(true);
    expect(fs.existsSync(`${filePath}.3`)).toBe(false);

    const activeEvents = fileSink.readEvents();
    expect(activeEvents.length).toBeGreaterThan(0);
    expect(activeEvents[activeEvents.length - 1]!.target).toBe('repo-24');
  });

  it('isolates failing sync/async sinks, awaits flush/close, and bridges AuditRepository without duplicates', async () => {
    const db = openDatabase(':memory:');
    openDbs.push(db);
    const scrubber = new SecretScrubber({ extraSecrets: ['db_audit_secret_token_777'] });
    const repos = createRepositories(db, { scrubber });

    const memorySink = new MemoryAuditSink({ maxEntries: 100 });
    const asyncDelivered: StructuredAuditEvent[] = [];
    const sinkErrors: Array<{ sinkName: string; message: string }> = [];

    const brokenSyncSink = new CallbackAuditSink({
      name: 'broken-sync',
      onEvent: () => {
        throw new Error('disk full');
      },
    });
    const brokenAsyncSink = new CallbackAuditSink({
      name: 'broken-async',
      onEvent: async () => {
        await new Promise((r) => setTimeout(r, 10));
        throw new Error('siem timeout');
      },
    });
    const healthyAsyncSink = new CallbackAuditSink({
      name: 'healthy-siem',
      filter: (ev) => ev.status === 'denied' || ev.action.startsWith('admin'),
      onEvent: async (ev) => {
        await new Promise((r) => setTimeout(r, 15));
        asyncDelivered.push(ev);
      },
    });

    const logger = new StructuredAuditLogger({
      sinks: [
        new SqliteAuditSink(repos.audit),
        memorySink,
        brokenSyncSink,
        brokenAsyncSink,
        healthyAsyncSink,
      ],
      scrubber,
      onSinkError: (sinkName, err) => {
        sinkErrors.push({
          sinkName,
          message: err instanceof Error ? err.message : String(err),
        });
      },
    });
    repos.audit.configure({ scrubber, publisher: logger });

    // Direction 1: Legacy repository call -> writes 1 scrubbed SQLite row + emits 1 structured event
    repos.audit.record({
      actor: 'admin',
      action: 'admin_login',
      target: 'admin_console',
      status: 'success',
      details: { leaked: 'db_audit_secret_token_777' },
    });

    // Direction 2: Direct StructuredAuditLogger call -> writes 1 SQLite row + emits 1 structured event
    logger.emit({
      actor: 'client-x',
      action: 'policy.denied',
      target: 'code_patch',
      status: 'denied',
      details: { token: 'db_audit_secret_token_777' },
    });

    await logger.flush();

    const sqliteRows = repos.audit.list({ limit: 20 });
    expect(sqliteRows).toHaveLength(2);
    expect(JSON.stringify(sqliteRows)).not.toContain('db_audit_secret_token_777');
    expect(JSON.stringify(sqliteRows)).toContain(REDACTED_PLACEHOLDER);

    expect(memorySink.size()).toBe(2);
    expect(verifyAuditChain(memorySink.getEvents()).valid).toBe(true);
    expect(asyncDelivered).toHaveLength(2);
    expect(sinkErrors.map((e) => e.sinkName)).toContain('broken-sync');
    expect(sinkErrors.map((e) => e.sinkName)).toContain('broken-async');

    // Verify rich MemoryAuditSink query filters & category/severity helpers
    expect(memorySink.query({ category: 'policy', status: 'denied' })).toHaveLength(1);
    expect(memorySink.query({ actionPrefix: 'admin_' })).toHaveLength(1);
    expect(inferAuditCategory('publish_changes.github_pr')).toBe('mutation');
    expect(inferAuditCategory('dispatch_runner')).toBe('runner');
    expect(inferAuditCategory('github_inspect')).toBe('mcp_tool');
    expect(inferAuditSeverity('publish_changes.github_pr', 'failure', 'mutation')).toBe('high');

    await logger.close();
  });
});

// ============================================================================
// 2. Rate-Limiter & Circuit-Breaker Middleware Suite
// ============================================================================

describe('Rate Limiters, Circuit Breaker & Hono Resilience Middleware', () => {
  it('enforces TokenBucketRateLimiter burst, continuous refill, weighted cost, and LRU bucket cap', () => {
    let now = 1_000_000;
    const bucket = new TokenBucketRateLimiter({
      capacity: 4,
      refillRatePerSec: 2, // 1 token per 500ms
      maxBuckets: 16,
      nowFn: () => now,
    });

    expect(bucket.consume('client-1', 2).allowed).toBe(true);
    expect(bucket.peek('client-1').remaining).toBe(2);
    expect(bucket.consume('client-1', 2).allowed).toBe(true);

    const denied = bucket.consume('client-1', 1);
    expect(denied.allowed).toBe(false);
    expect(denied.remaining).toBe(0);
    expect(denied.retryAfterSec).toBe(1);

    // Advance 500ms -> 1 token refilled
    now += 500;
    expect(bucket.consume('client-1', 1).allowed).toBe(true);
    expect(bucket.consume('client-1', 1).allowed).toBe(false);

    // Flood > maxBuckets keys without unbounded growth
    for (let i = 0; i < 40; i++) {
      expect(bucket.consume(`ephemeral-${i}`, 1).allowed).toBe(true);
    }

    bucket.reset('client-1');
    expect(bucket.consume('client-1', 4).allowed).toBe(true);
  });

  it('prevents fixed-window boundary double-burst spikes in SlidingWindowRateLimiter', () => {
    let now = 59_000; // 1 second before 60_000ms window boundary
    const limiter = new SlidingWindowRateLimiter({
      maxRequests: 10,
      windowMs: 60_000,
      nowFn: () => now,
    });

    for (let i = 0; i < 10; i++) {
      expect(limiter.consume('ip:1.2.3.4').allowed).toBe(true);
    }
    expect(limiter.consume('ip:1.2.3.4').allowed).toBe(false);

    // Cross into next window by 6 seconds (90% overlap with previous window => prevWeight = 0.9 => effective = 9)
    now = 66_000;
    expect(limiter.consume('ip:1.2.3.4').allowed).toBe(true); // 9 + 1 <= 10
    const burstBlocked = limiter.consume('ip:1.2.3.4'); // 9 + 2 > 10 -> blocked!
    expect(burstBlocked.allowed).toBe(false);
    expect(burstBlocked.retryAfterSec).toBeGreaterThan(0);

    // At 126_000ms (into window #2), the 1 accepted request from window #1 still carries 0.9 weight -> 9 allowed, 10th blocked;
    // at 180_000ms (2 full windows past window #1), all 10 are completely clear.
    now = 126_000;
    expect(limiter.peek('ip:1.2.3.4').remaining).toBe(9);
    now = 180_000;
    expect(limiter.consume('ip:1.2.3.4', 10).allowed).toBe(true);
  });

  it('drives CircuitBreaker through closed -> open -> half_open (probe concurrency cap) -> open -> closed', async () => {
    let now = 10_000;
    const transitions: string[] = [];
    const breaker = new CircuitBreaker({
      name: 'cloudflare:api',
      failureThreshold: 3,
      failureWindowMs: 10_000,
      resetTimeoutMs: 5_000,
      halfOpenMaxCalls: 1,
      halfOpenSuccessThreshold: 2,
      isFailure: (err) => !(err instanceof Error && err.message.startsWith('400:')),
      nowFn: () => now,
      onStateChange: (t) => transitions.push(`${t.from}->${t.to}`),
    });

    // Non-infra 400 error is ignored by custom isFailure predicate
    await expect(
      breaker.execute(async () => {
        throw new Error('400: bad client param');
      }),
    ).rejects.toThrow('400:');
    expect(breaker.getSnapshot().consecutiveFailures).toBe(0);

    // Old failure outside failureWindowMs gets pruned
    await expect(
      breaker.execute(async () => {
        throw new Error('502 upstream timeout');
      }),
    ).rejects.toThrow('502');
    now += 15_000; // > 10_000ms failureWindowMs
    expect(breaker.getSnapshot().consecutiveFailures).toBe(0);

    // 3 failures inside window trip circuit to open
    for (let i = 0; i < 3; i++) {
      now += 100;
      await expect(
        breaker.execute(async () => {
          throw new Error(`503 failure #${i + 1}`);
        }),
      ).rejects.toThrow('503');
    }
    expect(breaker.getState()).toBe('open');

    // Fast-fails while open without calling downstream fn
    const spy = vi.fn(async () => 'ok');
    await expect(breaker.execute(spy)).rejects.toThrow(CircuitOpenError);
    expect(spy).not.toHaveBeenCalled();
    expect(breaker.getSnapshot().totalRejected).toBe(1);

    // Advance past cooldown -> half_open
    now += 5_500;
    expect(breaker.getState()).toBe('half_open');

    // Concurrent calls during half_open: 1st acquires probe, 2nd fast-fails while 1st is in flight
    let resolveProbe!: (val: string) => void;
    const firstProbePromise = breaker.execute(
      () =>
        new Promise<string>((resolve) => {
          resolveProbe = resolve;
        }),
    );
    await expect(breaker.execute(async () => 'concurrent-extra')).rejects.toThrow(CircuitOpenError);
    resolveProbe('probe-1-ok');
    expect(await firstProbePromise).toBe('probe-1-ok');
    expect(breaker.getState()).toBe('half_open'); // needs 2 successes (halfOpenSuccessThreshold=2)

    // If 2nd probe fails, circuit immediately re-opens!
    await expect(
      breaker.execute(async () => {
        throw new Error('504 gateway timeout');
      }),
    ).rejects.toThrow('504');
    expect(breaker.getState()).toBe('open');

    // Wait cooldown again and pass 2 consecutive half_open probes -> closes circuit!
    now += 5_500;
    expect(await breaker.execute(async () => 'recover-1')).toBe('recover-1');
    expect(breaker.getState()).toBe('half_open');
    expect(await breaker.execute(async () => 'recover-2')).toBe('recover-2');
    expect(breaker.getState()).toBe('closed');

    expect(transitions).toEqual([
      'closed->open',
      'open->half_open',
      'half_open->open',
      'open->half_open',
      'half_open->closed',
    ]);
  });

  it('enforces Hono createResilienceMiddleware in JSON-RPC mode with audit logging', async () => {
    let now = 50_000;
    const memAudit = new MemoryAuditSink();
    const auditLogger = new StructuredAuditLogger({
      sinks: [memAudit],
      nowFn: () => now,
    });
    const limiter = new TokenBucketRateLimiter({
      capacity: 3,
      refillRatePerSec: 1,
      nowFn: () => now,
    });
    const registry = new CircuitBreakerRegistry({
      defaults: {
        failureThreshold: 2,
        resetTimeoutMs: 10_000,
        nowFn: () => now,
      },
      auditPublisher: auditLogger,
    });

    let shouldFail500 = false;
    const app = new Hono();
    app.use(
      '/mcp',
      createResilienceMiddleware({
        limiter,
        breaker: registry,
        circuitName: 'mcp:test',
        responseFormat: 'jsonrpc',
        auditPublisher: auditLogger,
      }),
    );
    app.post('/mcp', (c) => {
      if (shouldFail500) {
        return c.json({ jsonrpc: '2.0', error: { code: -32603, message: 'boom' }, id: 1 }, 500);
      }
      return c.json({ jsonrpc: '2.0', result: { ok: true }, id: 1 }, 200);
    });

    // 1. Trigger 2 HTTP 500s -> trips circuit breaker to open
    shouldFail500 = true;
    const r1 = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '203.0.113.10' },
    });
    expect(r1.status).toBe(500);
    expect(r1.headers.get('x-ratelimit-limit')).toBe('3');
    expect(r1.headers.get('x-ratelimit-remaining')).toBe('2');

    const r2 = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '203.0.113.10' },
    });
    expect(r2.status).toBe(500);
    expect(r2.headers.get('x-circuit-state')).toBe('open');

    // 2. 3rd request hits open circuit -> 503 JSON-RPC -32006
    shouldFail500 = false;
    const r3 = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '203.0.113.10' },
    });
    expect(r3.status).toBe(503);
    expect(r3.headers.get('retry-after')).toBeTruthy();
    expect(await r3.json()).toMatchObject({
      jsonrpc: '2.0',
      error: { code: -32006 },
    });

    // 3. Exhaust rate limiter on 4th immediate request -> 429 JSON-RPC -32005
    const r4 = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '203.0.113.10' },
    });
    expect(r4.status).toBe(429);
    expect(await r4.json()).toMatchObject({
      jsonrpc: '2.0',
      error: { code: -32005 },
    });

    // 4. Advance past cooldown & refill -> recovers cleanly!
    now += 11_000;
    const r5 = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { 'cf-connecting-ip': '203.0.113.10' },
    });
    expect(r5.status).toBe(200);
    expect(r5.headers.get('x-circuit-state')).toBe('closed');

    const actions = memAudit.getEvents().map((e) => e.action);
    expect(actions).toContain('circuit_breaker.open');
    expect(actions).toContain('circuit_breaker.rejected');
    expect(actions).toContain('rate_limit.exceeded');
    expect(actions).toContain('circuit_breaker.half_open');
    expect(actions).toContain('circuit_breaker.closed');
  });

  it('isolates rate-limit buckets per OAuth clientId, enforces trustCfConnectingIp=false, and supports REST format + registry snapshots', async () => {
    const limiter = new SlidingWindowRateLimiter({ maxRequests: 1, windowMs: 60_000 });
    const registry = new CircuitBreakerRegistry({
      defaults: { failureThreshold: 1, resetTimeoutMs: 30_000 },
    });

    const app = new Hono<{ Variables: { oauthAuth?: { clientId: string; scope: string; resource: string | null; tokenFamilyId: string } } }>();
    app.use('/api/*', async (c, next) => {
      const cid = c.req.header('x-test-client');
      if (cid) {
        c.set('oauthAuth', {
          clientId: cid,
          scope: 'mcp:tools',
          resource: 'https://mcp.example.com/mcp',
          tokenFamilyId: 'fam-1',
        });
      }
      await next();
    });
    app.use(
      '/api/*',
      createResilienceMiddleware({
        limiter,
        breaker: registry,
        circuitName: 'rest:api',
        trustCfConnectingIp: false,
        responseFormat: 'rest',
      }),
    );
    app.get('/api/ping', (c) => c.json({ pong: true }, 200));
    app.get('/api/fail', (c) => c.json({ error: 'upstream_down' }, 502));

    // Client A uses its 1 allowed request -> 2nd request from Client A is 429, while Client B still succeeds!
    const a1 = await app.request('https://mcp.example.com/api/ping', {
      headers: { 'x-test-client': 'client-a' },
    });
    expect(a1.status).toBe(200);
    const a2 = await app.request('https://mcp.example.com/api/ping', {
      headers: { 'x-test-client': 'client-a' },
    });
    expect(a2.status).toBe(429);
    expect(await a2.json()).toMatchObject({ error: 'rate_limit_exceeded' });

    const b1 = await app.request('https://mcp.example.com/api/ping', {
      headers: { 'x-test-client': 'client-b' },
    });
    expect(b1.status).toBe(200);

    // Unauthenticated requests with trustCfConnectingIp=false ignore spoofed CF-Connecting-IP and share 'direct' bucket
    const spoof1 = await app.request('https://mcp.example.com/api/ping', {
      headers: { 'cf-connecting-ip': '198.51.100.1' },
    });
    expect(spoof1.status).toBe(200);
    const spoof2 = await app.request('https://mcp.example.com/api/ping', {
      headers: { 'cf-connecting-ip': '198.51.100.99' },
    });
    expect(spoof2.status).toBe(429);

    // Trip REST circuit breaker and inspect snapshots + resetAll()
    const c1 = await app.request('https://mcp.example.com/api/fail', {
      headers: { 'x-test-client': 'client-c' },
    });
    expect(c1.status).toBe(502);
    expect(registry.listSnapshots()[0]?.state).toBe('open');

    const d1 = await app.request('https://mcp.example.com/api/ping', {
      headers: { 'x-test-client': 'client-d' },
    });
    expect(d1.status).toBe(503);
    expect(await d1.json()).toMatchObject({ error: 'circuit_open', circuit: 'rest:api' });

    registry.resetAll();
    expect(registry.listSnapshots()[0]?.state).toBe('closed');
  });
});

// ============================================================================
// 3. Policy-Rule Evaluator & End-to-End Bastion Gateway Integration Suite
// ============================================================================

describe('PolicyEvaluator & Gateway End-to-End Security Enforcement', () => {
  it('enforces built-in Bastion guardrails, custom JSON/file rules, deny-overrides, and fail-closed predicate faults', () => {
    const policyDir = makeTempDir('bastion-policy-');
    const policyFilePath = path.join(policyDir, 'policy.json');
    fs.writeFileSync(
      policyFilePath,
      JSON.stringify({
        rules: [
          {
            id: 'org:deny-prod-worker-deploy',
            priority: 500,
            effect: 'deny',
            reason: 'Production Worker promotion is locked during freeze window.',
            match: {
              tools: ['publish_changes'],
              actions: ['cloudflare_worker_deploy'],
              deployTargets: ['production'],
            },
          },
          {
            id: 'org:guest-client-workspace-jail',
            priority: 400,
            effect: 'deny',
            reason: 'Guest client may only access sandbox-* workspaces.',
            match: {
              clientIds: ['guest-client'],
              notWorkspaces: ['sandbox-*'],
            },
          },
        ],
      }),
      'utf8',
    );

    const memAudit = new MemoryAuditSink();
    const auditLogger = new StructuredAuditLogger({ sinks: [memAudit] });
    const evaluator = createBastionPolicyEvaluator({
      policyFile: policyFilePath,
      auditPublisher: auditLogger,
    });

    // 1. Unknown tool -> fail-closed default deny
    const unknownDecision = evaluator.evaluate({
      actor: 'op',
      scopes: ['mcp:tools'],
      toolName: 'rogue_eleventh_tool',
    });
    expect(unknownDecision.allowed).toBe(false);
    expect(unknownDecision.defaultApplied).toBe(true);

    // 2. Protected branch push blocked (`refs/heads/main` and custom `defaultBranch`)
    const mainPushCtx = extractToolPolicyContext(
      'publish_changes',
      {
        action: 'github_pr',
        slug: 'app',
        repo: 'Kaiserunix/gemini-bastion-mcp',
        branch_name: 'refs/heads/main',
        title: 'Direct push attempt',
      },
      { authInfo: { clientId: 'dev-client', scopes: ['mcp:tools'] } },
    );
    const mainDecision = evaluator.evaluate(mainPushCtx);
    expect(mainDecision.allowed).toBe(false);
    expect(mainDecision.matchedRuleId).toBe('builtin:no-protected-branch-push');

    const customDefaultCtx = extractToolPolicyContext(
      'publish_changes',
      {
        action: 'github_pr',
        slug: 'app',
        repo: 'Kaiserunix/gemini-bastion-mcp',
        branch_name: 'trunk',
        title: 'Push to custom default',
      },
      { authInfo: { clientId: 'dev-client', scopes: ['mcp:tools'] } },
    );
    customDefaultCtx.defaultBranch = 'trunk';
    expect(evaluator.evaluate(customDefaultCtx).allowed).toBe(false);

    // Cloudflare Pages deploy with `--branch main` metadata IS allowed
    const pagesMainCtx = extractToolPolicyContext(
      'publish_changes',
      {
        action: 'cloudflare_pages_deploy',
        slug: 'app',
        project_name: 'docs',
        directory: 'dist',
        branch: 'main',
      },
      { authInfo: { clientId: 'dev-client', scopes: ['mcp:tools'] } },
    );
    expect(evaluator.evaluate(pagesMainCtx).allowed).toBe(true);

    // 3. Deprecated `codex mcp-server` CLI blocked
    const legacyCodexCtx = extractToolPolicyContext(
      'workspace_exec',
      {
        slug: 'app',
        command: 'npx codex mcp-server --stdio',
      },
      { authInfo: { clientId: 'dev-client', scopes: ['mcp:tools'] } },
    );
    const legacyDecision = evaluator.evaluate(legacyCodexCtx);
    expect(legacyDecision.allowed).toBe(false);
    expect(legacyDecision.matchedRuleId).toBe('builtin:forbid-legacy-codex-mcp-cli');

    // 4. Custom file rules: prod deploy denied, preview deploy allowed!
    const prodDeployCtx = extractToolPolicyContext(
      'publish_changes',
      {
        action: 'cloudflare_worker_deploy',
        slug: 'app',
        target: 'production',
      },
      { authInfo: { clientId: 'dev-client', scopes: ['mcp:tools'] } },
    );
    expect(evaluator.evaluate(prodDeployCtx)).toMatchObject({
      allowed: false,
      matchedRuleId: 'org:deny-prod-worker-deploy',
    });

    const previewDeployCtx = extractToolPolicyContext(
      'publish_changes',
      {
        action: 'cloudflare_worker_deploy',
        slug: 'app',
        target: 'preview',
      },
      { authInfo: { clientId: 'dev-client', scopes: ['mcp:tools'] } },
    );
    expect(evaluator.evaluate(previewDeployCtx).allowed).toBe(true);

    // 5. Guest client workspace jail
    const guestProdWs = extractToolPolicyContext(
      'code_explore',
      { mode: 'pack', slug: 'prod-core' },
      { authInfo: { clientId: 'guest-client', scopes: ['mcp:read'] } },
    );
    expect(evaluator.evaluate(guestProdWs)).toMatchObject({
      allowed: false,
      matchedRuleId: 'org:guest-client-workspace-jail',
    });

    const guestSandboxWs = extractToolPolicyContext(
      'code_explore',
      { mode: 'pack', slug: 'sandbox-lab' },
      { authInfo: { clientId: 'guest-client', scopes: ['mcp:read'] } },
    );
    expect(evaluator.evaluate(guestSandboxWs).allowed).toBe(true);

    // 6. Require staged plan_id on execute_staged_plan
    const missingPlanCtx = extractToolPolicyContext(
      'publish_changes',
      { action: 'execute_staged_plan' },
      { authInfo: { clientId: 'dev-client', scopes: ['mcp:tools'] } },
    );
    expect(evaluator.evaluate(missingPlanCtx)).toMatchObject({
      allowed: false,
      effect: 'require_staged_plan',
      matchedRuleId: 'builtin:require-staged-plan-id',
    });

    // 7. Faulty predicate fails closed instead of failing open
    const faultyEvaluator = new PolicyEvaluator({
      defaultEffect: 'allow',
      rules: [
        {
          id: 'buggy-rule',
          effect: 'allow',
          predicate: () => {
            throw new Error('unexpected null pointer in custom predicate');
          },
        },
      ],
      auditPublisher: auditLogger,
    });
    const faultDecision = faultyEvaluator.evaluate({
      actor: 'op',
      toolName: 'workspace_exec',
    });
    expect(faultDecision.allowed).toBe(false);
    expect(faultDecision.matchedRuleId).toBe('system:evaluator-error-fail-closed');

    // Reject malformed policy schema
    expect(() =>
      loadPolicyRulesFromSources({
        policyJson: JSON.stringify([{ id: 'bad', effect: 'invalid_effect' }]),
      }),
    ).toThrow();

    expect(memAudit.query({ category: 'policy', status: 'denied' }).length).toBeGreaterThanOrEqual(6);
  });

  it('supports first-applicable combining, requireExplicitScopes, repo/downstream/regex matchers, and auditAllows', () => {
    const memAudit = new MemoryAuditSink();
    const auditLogger = new StructuredAuditLogger({ sinks: [memAudit] });

    const evaluator = new PolicyEvaluator({
      combiningAlgorithm: 'first-applicable',
      defaultEffect: 'deny',
      requireExplicitScopes: true,
      auditPublisher: auditLogger,
      auditAllows: true,
      rules: [
        {
          id: 'rule-deny-dangerous-rm',
          priority: 200,
          effect: 'deny',
          reason: 'Destructive root rm -rf blocked.',
          match: {
            tools: ['workspace_exec'],
            commandRegexes: ['rm\\s+-rf\\s+/'],
          },
        },
        {
          id: 'rule-allow-kaiserunix-pr',
          priority: 100,
          effect: 'allow',
          match: {
            tools: ['github_inspect'],
            repos: ['Kaiserunix/*'],
          },
        },
        {
          id: 'rule-deny-downstream-admin',
          priority: 150,
          effect: 'deny',
          match: {
            tools: ['infra_inspect'],
            downstreamServers: ['ops-*'],
            downstreamTools: ['drop_*'],
          },
        },
      ],
    });

    // Missing scopes rejected immediately when requireExplicitScopes=true
    expect(
      evaluator.evaluate({
        actor: 'op',
        toolName: 'github_inspect',
        repo: 'Kaiserunix/gemini-bastion-mcp',
      }),
    ).toMatchObject({
      allowed: false,
      matchedRuleId: 'system:missing-explicit-scopes',
    });

    // Allowed Kaiserunix repo inspect emits policy.allowed when auditAllows=true
    expect(
      evaluator.evaluate({
        actor: 'op',
        scopes: ['mcp:read'],
        toolName: 'github_inspect',
        repo: 'Kaiserunix/gemini-bastion-mcp',
      }),
    ).toMatchObject({
      allowed: true,
      matchedRuleId: 'rule-allow-kaiserunix-pr',
    });

    // Regex command matcher blocks destructive rm -rf /
    expect(
      evaluator.evaluate({
        actor: 'op',
        scopes: ['mcp:tools'],
        toolName: 'workspace_exec',
        command: 'sudo rm -rf / --no-preserve-root',
      }),
    ).toMatchObject({
      allowed: false,
      matchedRuleId: 'rule-deny-dangerous-rm',
    });

    // Downstream server/tool wildcard matcher
    expect(
      evaluator.evaluate({
        actor: 'op',
        scopes: ['mcp:read'],
        toolName: 'infra_inspect',
        downstreamServer: 'ops-db',
        downstreamTool: 'drop_schema',
      }),
    ).toMatchObject({
      allowed: false,
      matchedRuleId: 'rule-deny-downstream-admin',
    });

    expect(memAudit.query({ action: 'policy.allowed' })).toHaveLength(1);
  });

  it('integrates PolicyEvaluator, RateLimiter, and JsonlFileAuditSink end-to-end inside createGatewayApp', async () => {
    const rootDir = makeTempDir('bastion-gw-e2e-');
    const dataDir = path.join(rootDir, 'data');
    const workspacesDir = path.join(rootDir, 'workspaces');
    const auditFilePath = path.join(dataDir, 'audit', 'gateway-events.jsonl');
    const adminPassword = 'bastion-audit-test-pw';

    const config = loadConfig({
      NODE_ENV: 'test',
      PUBLIC_DOMAIN: 'https://mcp.example.com',
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      DATABASE_PATH: ':memory:',
      AUDIT_LOG_FILE_PATH: auditFilePath,
      ADMIN_PASSWORD_HASH: hashPasswordScrypt(adminPassword),
      OAUTH_SIGNING_SECRET: 'audit-e2e-signing-secret-at-least-32-chars-0000',
      MCP_RATE_LIMIT_MAX_REQUESTS: '5',
      MCP_RATE_LIMIT_WINDOW_MS: '60000',
      SECURITY_POLICY_JSON: JSON.stringify([
        {
          id: 'e2e:block-prod-deploy',
          priority: 600,
          effect: 'deny',
          reason: 'Production deploy blocked by operator policy.',
          match: {
            tools: ['publish_changes'],
            actions: ['cloudflare_worker_deploy'],
            deployTargets: ['production'],
          },
        },
      ]),
    });

    const mockCfStub = {} as unknown as CloudflareClientLike;
    const cloudflareService = new CloudflareService({
      apiToken: 'cf_test_secret_token_value_12345',
      accountId: 'acct-1',
      readClient: mockCfStub,
      writeClient: mockCfStub,
    });

    const gateway = createGatewayApp({
      config,
      dbPath: ':memory:',
      cloudflareService,
    });
    gateways.push(gateway);

    // Complete OAuth 2.1 DCR + PKCE flow to mint Bearer token
    const dcrRes = await gateway.app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Bastion Policy Client',
        redirect_uris: ['https://gemini.google.com/oauth/callback'],
      }),
    });
    const { client_id: clientId } = (await dcrRes.json()) as { client_id: string };

    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = computeS256Challenge(verifier);
    const authUrl = new URL('https://mcp.example.com/oauth/authorize');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', 'https://gemini.google.com/oauth/callback');
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('scope', 'mcp:tools');
    authUrl.searchParams.set('resource', 'https://mcp.example.com/mcp');

    const getAuth = await gateway.app.request(authUrl.toString());
    const authHtml = await getAuth.text();
    const postAuth = await gateway.app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        auth_req_id: extractHiddenInput(authHtml, 'auth_req_id'),
        csrf_token: extractHiddenInput(authHtml, 'csrf_token'),
        password: adminPassword,
        decision: 'approve',
      }).toString(),
    });
    const code = new URL(postAuth.headers.get('location')!).searchParams.get('code')!;
    const tokRes = await gateway.app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://gemini.google.com/oauth/callback',
        client_id: clientId,
        code_verifier: verifier,
        resource: 'https://mcp.example.com/mcp',
      }).toString(),
    });
    const { access_token: accessToken } = (await tokRes.json()) as { access_token: string };

    // Request #1: Allowed workspace list call (verifies X-RateLimit-* & X-Circuit-State headers)
    const okRpc = await gateway.app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessToken}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-11-25',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'workspace_manage', arguments: { action: 'list' } },
      }),
    });
    expect(okRpc.status).toBe(200);
    expect(okRpc.headers.get('x-ratelimit-limit')).toBe('5');
    expect(okRpc.headers.get('x-circuit-state')).toBe('closed');

    // Request #2: Blocked by custom SECURITY_POLICY_JSON (`e2e:block-prod-deploy`)
    const blockedRpc = await gateway.app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessToken}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-11-25',
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/call',
        params: {
          name: 'publish_changes',
          arguments: {
            action: 'cloudflare_worker_deploy',
            slug: 'demo-ws',
            target: 'production',
          },
        },
      }),
    });
    expect(blockedRpc.status).toBe(200);
    const blockedJson = (await blockedRpc.json()) as {
      result: { isError?: boolean; content: Array<{ text: string }> };
    };
    expect(blockedJson.result.isError).toBe(true);
    expect(blockedJson.result.content[0]!.text).toContain('e2e:block-prod-deploy');
    expect(blockedJson.result.content[0]!.text).toContain('Production deploy blocked');

    // Requests #3, #4, #5 consume remaining window budget; Request #6 returns HTTP 429 JSON-RPC -32005!
    for (let id = 3; id <= 5; id++) {
      const res = await gateway.app.request('https://mcp.example.com/mcp', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${accessToken}`,
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'mcp-protocol-version': '2025-11-25',
        },
        body: JSON.stringify({ jsonrpc: '2.0', id, method: 'tools/list', params: {} }),
      });
      expect(res.status).toBe(200);
    }

    const rateLimitedRes = await gateway.app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessToken}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-11-25',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 6, method: 'tools/list', params: {} }),
    });
    expect(rateLimitedRes.status).toBe(429);
    expect(rateLimitedRes.headers.get('retry-after')).toBeTruthy();

    await gateway.auditLogger.flush();

    // Verify NDJSON audit file contains unbroken cryptographic hash chain covering DCR, OAuth, Policy denial, and Rate Limit!
    const rawLines = fs
      .readFileSync(auditFilePath, 'utf8')
      .trim()
      .split(/\r?\n/)
      .map((l) => JSON.parse(l) as StructuredAuditEvent);
    expect(rawLines.length).toBeGreaterThanOrEqual(5);
    expect(verifyAuditChain(rawLines)).toEqual({
      valid: true,
      checkedCount: rawLines.length,
    });
    expect(rawLines.some((e) => e.action === 'policy.denied')).toBe(true);
    expect(rawLines.some((e) => e.action === 'rate_limit.exceeded')).toBe(true);

    // SQLite audit_logs table also holds synced records
    const sqlAuditActions = gateway.repos.audit.list({ limit: 50 }).map((r) => r.action);
    expect(sqlAuditActions).toContain('policy.denied');
    expect(sqlAuditActions).toContain('rate_limit.exceeded');
  });
});
