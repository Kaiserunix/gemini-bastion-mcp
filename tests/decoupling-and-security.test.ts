import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { Hono } from 'hono';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createGatewayApp } from '../src/app.js';
import {
  computeS256Challenge,
  createAuthApp,
  createBearerMiddleware,
  generateRandomToken,
  hashPasswordScrypt,
  InMemoryOAuthStore,
  SignedCookieAdminSessionManager,
  type AuditLogger,
  type RateLimiter,
} from '../src/auth/index.js';
import { loadConfig } from '../src/config.js';
import {
  CloudflareService,
  type CloudflareClientLike,
} from '../src/core/cloudflareService.js';
import {
  DownstreamMcpBridge,
  DownstreamPolicyError,
  type DownstreamMcpClientLike,
} from '../src/core/downstreamMcpBridge.js';
import { GitHubService, ProtectedBranchError } from '../src/core/githubService.js';
import { WorkspaceLockManager } from '../src/core/workspaceLock.js';
import { createRepositories } from '../src/db/repositories/index.js';
import { openDatabase } from '../src/db/sqlite.js';
import type {
  AgentRunnerAdapter,
  CloudflareToolAdapter,
  DownstreamMcpToolAdapter,
  GitHubToolAdapter,
  WorkspaceToolAdapter,
} from '../src/mcp/adapters/index.js';
import { withMcpGuardrails } from '../src/mcp/outputGuard.js';
import { McpToolRegistry } from '../src/mcp/registry.js';
import { createMcpHttpHandler } from '../src/mcp/server.js';
import { createMcpToolRegistry, type McpToolDeps } from '../src/mcp/tools/index.js';
import {
  ApprovalGatePolicyError,
  DefaultApprovalGatePolicy,
  InMemoryPlanStore,
  MutationPlanGate,
} from '../src/policy/index.js';
import type { AuditLogRecord, GatewayConfig } from '../src/types.js';
import { SecretScrubber } from '../src/utils/secretScrubber.js';

const tempDirs: string[] = [];

function makeTempDir(prefix: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      // Ignore transient cleanup lock on Windows
    }
  }
});

function createTestConfig(overrides: Record<string, string | undefined> = {}): GatewayConfig {
  const root = makeTempDir('bastion-decouple-');
  const adminPassword = 'decouple-test-password-123';
  return loadConfig({
    NODE_ENV: 'test',
    PUBLIC_DOMAIN: 'https://mcp.example.com',
    ADMIN_PASSWORD_HASH: hashPasswordScrypt(adminPassword),
    OAUTH_SIGNING_SECRET: 'decouple-signing-secret-0123456789abcdef',
    DATA_DIR: path.join(root, 'data'),
    WORKSPACES_DIR: path.join(root, 'workspaces'),
    ARTIFACTS_DIR: path.join(root, 'data', 'artifacts'),
    ...overrides,
  });
}

function createMemoryAuditLogger(): AuditLogger & { entries: AuditLogRecord[] } {
  const entries: AuditLogRecord[] = [];
  return {
    entries,
    record(input) {
      const rec: AuditLogRecord = {
        id: entries.length + 1,
        actor: input.actor,
        action: input.action,
        target: input.target,
        status: input.status,
        details: input.details ?? {},
        created_at: input.created_at ?? Date.now(),
      };
      entries.push(rec);
      return rec;
    },
  };
}

function createMockCloudflareClient() {
  const dnsRecords = new Map<string, Record<string, unknown>>();
  const kvValues = new Map<string, string>();
  const workerRoutes = new Map<string, { id: string; pattern: string; script?: string }>();
  let nextDnsId = 1;
  let nextRouteId = 1;

  const dnsListSpy = vi.fn(async () => Array.from(dnsRecords.values()));
  const dnsDeleteSpy = vi.fn(async (id: string) => {
    dnsRecords.delete(id);
    return { id };
  });

  const client: CloudflareClientLike = {
    zones: {
      list: async () => [],
    },
    dns: {
      records: {
        list: dnsListSpy,
        get: async (id) => {
          const rec = dnsRecords.get(id);
          if (!rec) throw Object.assign(new Error('404 Not Found'), { status: 404 });
          return rec;
        },
        create: async (params) => {
          const id = `dns-${nextDnsId++}`;
          const rec = { id, ...params };
          dnsRecords.set(id, rec);
          return rec;
        },
        update: async (id, params) => {
          const rec = { id, ...params };
          dnsRecords.set(id, rec);
          return rec;
        },
        delete: dnsDeleteSpy,
      },
    },
    workers: {
      scripts: {
        list: async () => [],
      },
      routes: {
        list: async () => Array.from(workerRoutes.values()),
        get: async (id) => {
          const route = workerRoutes.get(id);
          if (!route) throw Object.assign(new Error('404 Route Not Found'), { status: 404 });
          return route;
        },
        create: async (params) => {
          const id = `route-${nextRouteId++}`;
          const route = { id, pattern: params.pattern, script: params.script };
          workerRoutes.set(id, route);
          return route;
        },
        update: async (id, params) => {
          const route = { id, pattern: params.pattern, script: params.script };
          workerRoutes.set(id, route);
          return route;
        },
        delete: async (id) => {
          workerRoutes.delete(id);
          return { id };
        },
      },
    },
    pages: {
      projects: {
        list: async () => [],
        deployments: {
          list: async () => [],
        },
      },
    },
    kv: {
      namespaces: {
        list: async () => [],
        keys: {
          list: async () => Array.from(kvValues.keys()).map((name) => ({ name })),
        },
        values: {
          get: async (keyName) => {
            if (!kvValues.has(keyName)) {
              throw Object.assign(new Error('404 Key not found'), { status: 404 });
            }
            const val = kvValues.get(keyName)!;
            return { text: async () => val };
          },
          update: async (keyName, params) => {
            kvValues.set(keyName, params.value);
            return { success: true };
          },
          delete: async (keyName) => {
            kvValues.delete(keyName);
            return { success: true };
          },
        },
      },
    },
    d1: {
      database: {
        list: async () => [],
        get: async (id) => ({ uuid: id }),
        query: async () => [],
      },
    },
    rulesets: {
      list: async () => [],
      get: async (id) => ({ id, rules: [] }),
      update: async (id, params) => ({ id, ...params }),
      phases: {
        get: async (phase) => ({ id: `rs-${phase}`, phase, rules: [] }),
        update: async (phase, params) => ({ id: `rs-${phase}`, phase, ...params }),
      },
    },
  };

  return { client, dnsRecords, kvValues, workerRoutes, dnsListSpy, dnsDeleteSpy };
}

async function runAuthorizeAndExchange(params: {
  app: Hono;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  scope?: string;
  password?: string;
  useBasicAuth?: boolean;
}) {
  const verifier = generateRandomToken(32);
  const challenge = computeS256Challenge(verifier);
  const authUrl = new URL('https://mcp.example.com/oauth/authorize');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', params.clientId);
  authUrl.searchParams.set('redirect_uri', params.redirectUri);
  authUrl.searchParams.set('code_challenge', challenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');
  authUrl.searchParams.set('state', 'st-123');
  authUrl.searchParams.set('resource', 'https://mcp.example.com/mcp');
  if (params.scope) {
    authUrl.searchParams.set('scope', params.scope);
  }

  const getRes = await params.app.request(authUrl.toString());
  expect(getRes.status).toBe(200);
  const html = await getRes.text();
  const authReqId = /name="auth_req_id"\s+value="([^"]+)"/.exec(html)?.[1];
  const csrf = /name="csrf_token"\s+value="([^"]+)"/.exec(html)?.[1];
  expect(authReqId).toBeTruthy();
  expect(csrf).toBeTruthy();
  const cookie = getRes.headers.get('set-cookie')?.split(';')[0] ?? '';

  const form = new URLSearchParams({
    auth_req_id: authReqId!,
    csrf_token: csrf!,
    password: params.password ?? 'decouple-test-password-123',
    decision: 'approve',
  });

  const postRes = await params.app.request('https://mcp.example.com/oauth/authorize', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: cookie,
    },
    body: form.toString(),
  });
  expect(postRes.status).toBe(302);
  const loc = new URL(postRes.headers.get('location')!);
  const code = loc.searchParams.get('code')!;
  expect(code).toBeTruthy();

  const tokenForm = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: params.redirectUri,
    code_verifier: verifier,
    resource: 'https://mcp.example.com/mcp',
  });
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };
  if (params.useBasicAuth && params.clientSecret) {
    const basic = Buffer.from(
      `${encodeURIComponent(params.clientId)}:${encodeURIComponent(params.clientSecret)}`,
      'utf8',
    ).toString('base64');
    headers.Authorization = `Basic ${basic}`;
  } else {
    tokenForm.set('client_id', params.clientId);
    if (params.clientSecret) {
      tokenForm.set('client_secret', params.clientSecret);
    }
  }

  const tokenRes = await params.app.request('https://mcp.example.com/oauth/token', {
    method: 'POST',
    headers,
    body: tokenForm.toString(),
  });
  const tokenJson = (await tokenRes.json()) as Record<string, unknown>;
  return { code, verifier, tokenRes, tokenJson };
}

describe('Decoupled OAuth Store, Session Manager & OAuth 2.1 Security Edge Cases', () => {
  it('runs complete OAuth 2.1 DCR -> PKCE -> Bearer -> Refresh -> Revoke with InMemoryOAuthStore (zero SQLite)', async () => {
    const config = createTestConfig();
    const oauthStore = new InMemoryOAuthStore();
    const auditLogger = createMemoryAuditLogger();
    const rateCalls: string[] = [];
    const customLimiter: RateLimiter = {
      consume(key) {
        rateCalls.push(key);
        return { allowed: true, remaining: 99, retryAfterSec: 0 };
      },
      reset() {},
    };
    const sessionManager = new SignedCookieAdminSessionManager(config, { ttlMs: 60_000 });

    // Verify SignedCookieAdminSessionManager standalone lifecycle
    const issued = sessionManager.issue(1_000_000, 'operator-1');
    expect(sessionManager.verify(issued.token, 1_030_000)?.sub).toBe('operator-1');
    expect(sessionManager.verify(`${issued.token}tamper`, 1_030_000)).toBeNull();
    expect(sessionManager.verify(issued.token, 1_070_000)).toBeNull();

    const app = new Hono();
    app.route(
      '/',
      createAuthApp({
        config,
        oauthStore,
        auditLogger,
        sessionManager,
        rateLimiter: customLimiter,
      }),
    );
    app.use('/mcp', createBearerMiddleware({ config, oauthStore }));
    app.post('/mcp', (c) => c.json({ ok: true, auth: c.get('oauthAuth') }));

    // Unauthenticated /mcp returns 401 with Cache-Control: no-store
    const unauthRes = await app.request('https://mcp.example.com/mcp', { method: 'POST' });
    expect(unauthRes.status).toBe(401);
    expect(unauthRes.headers.get('cache-control')).toBe('no-store');

    // Default redirect allowlist accepts Claude.ai and ChatGPT.com (HTTPS only)
    const dcrRes = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Multi-Client Test',
        redirect_uris: [
          'https://claude.ai/api/mcp/auth_callback',
          'https://chatgpt.com/connector_platform_oauth_redirect',
        ],
      }),
    });
    expect(dcrRes.status).toBe(201);
    const { client_id: clientId } = (await dcrRes.json()) as { client_id: string };

    // Reject HTTP claude.ai and arbitrary domains
    const badHttpRes = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['http://claude.ai/api/mcp/auth_callback'],
      }),
    });
    expect(badHttpRes.status).toBe(400);

    const { tokenRes, tokenJson } = await runAuthorizeAndExchange({
      app,
      clientId,
      redirectUri: 'https://claude.ai/api/mcp/auth_callback',
      scope: 'mcp:tools mcp:read',
    });
    expect(tokenRes.status).toBe(200);
    expect(rateCalls.length).toBeGreaterThan(0);

    const accessToken = String(tokenJson.access_token);
    const refreshToken = String(tokenJson.refresh_token);

    // Bearer access works via InMemoryOAuthStore
    const okMcp = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    expect(okMcp.status).toBe(200);

    // OAuth 2.1 §4.3.1: Refresh token down-scoping succeeds (mcp:tools mcp:read -> mcp:read)
    const downScopeRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: clientId,
        scope: 'mcp:read',
      }).toString(),
    });
    expect(downScopeRes.status).toBe(200);
    const downScoped = (await downScopeRes.json()) as {
      access_token: string;
      refresh_token: string;
      scope: string;
    };
    expect(downScoped.scope).toBe('mcp:read');

    // OAuth 2.1 §4.3.1: Attempting to escalate narrowed refresh token back to mcp:tools fails closed
    const escalateRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: downScoped.refresh_token,
        client_id: clientId,
        scope: 'mcp:tools',
      }).toString(),
    });
    expect(escalateRes.status).toBe(400);
    expect(((await escalateRes.json()) as { error: string }).error).toBe('invalid_scope');

    // Revoke refresh token revokes entire family in InMemoryOAuthStore
    const revokeRes = await app.request('https://mcp.example.com/oauth/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: downScoped.refresh_token,
        client_id: clientId,
      }).toString(),
    });
    expect(revokeRes.status).toBe(200);

    const afterRevoke = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { Authorization: `Bearer ${downScoped.access_token}` },
    });
    expect(afterRevoke.status).toBe(401);
    expect(auditLogger.entries.some((e) => e.action === 'oauth_token_revoke')).toBe(true);
  });

  it('enforces OAuth 2.1 §4.1.2 code replay family revocation and RFC 6749 §2.3 Basic Auth hardening', async () => {
    const config = createTestConfig();
    const oauthStore = new InMemoryOAuthStore();
    const auditLogger = createMemoryAuditLogger();

    const app = new Hono();
    app.route('/', createAuthApp({ config, oauthStore, auditLogger }));
    app.use('/mcp', createBearerMiddleware({ config, oauthStore }));
    app.post('/mcp', (c) => c.json({ ok: true }));

    // Register confidential client
    const dcrRes = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'],
        token_endpoint_auth_method: 'client_secret_post',
      }),
    });
    expect(dcrRes.status).toBe(201);
    const { client_id: clientId, client_secret: clientSecret } = (await dcrRes.json()) as {
      client_id: string;
      client_secret: string;
    };

    // Malformed Basic Authorization headers fail closed with 401 invalid_client
    for (const badHeader of ['Basic !!!not-b64!!!', `Basic ${Buffer.from('no-colon').toString('base64')}`, `Basic ${Buffer.from('cid:%ZZ').toString('base64')}`]) {
      const badBasicRes = await app.request('https://mcp.example.com/oauth/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: badHeader,
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: 'dummy',
          redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
          code_verifier: 'x'.repeat(43),
        }).toString(),
      });
      expect(badBasicRes.status).toBe(401);
      expect(((await badBasicRes.json()) as { error: string }).error).toBe('invalid_client');
    }

    // Conflicting Basic header and body client_id fails closed with 400 invalid_request
    const validBasic = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
    const conflictRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: validBasic,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: 'dummy',
        client_id: 'other-client',
        redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
        code_verifier: 'x'.repeat(43),
      }).toString(),
    });
    expect(conflictRes.status).toBe(400);
    expect(((await conflictRes.json()) as { error: string }).error).toBe('invalid_request');

    // Valid Basic Auth exchange succeeds
    const { code, verifier, tokenRes, tokenJson } = await runAuthorizeAndExchange({
      app,
      clientId,
      clientSecret,
      redirectUri: 'https://chatgpt.com/connector_platform_oauth_redirect',
      useBasicAuth: true,
    });
    expect(tokenRes.status).toBe(200);
    const accessToken = String(tokenJson.access_token);
    const refreshToken = String(tokenJson.refresh_token);

    // Token works before replay
    expect(
      (
        await app.request('https://mcp.example.com/mcp', {
          method: 'POST',
          headers: { Authorization: `Bearer ${accessToken}` },
        })
      ).status,
    ).toBe(200);

    // Replaying authorization code revokes entire issued token family (access + refresh)
    const replayRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: validBasic,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://chatgpt.com/connector_platform_oauth_redirect',
        code_verifier: verifier,
      }).toString(),
    });
    expect(replayRes.status).toBe(400);

    // Access token is now revoked (401)
    expect(
      (
        await app.request('https://mcp.example.com/mcp', {
          method: 'POST',
          headers: { Authorization: `Bearer ${accessToken}` },
        })
      ).status,
    ).toBe(401);

    // Refresh token is also revoked (400 invalid_grant)
    const refreshAfterReplay = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: validBasic,
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      }).toString(),
    });
    expect(refreshAfterReplay.status).toBe(400);
    expect(auditLogger.entries.some((e) => e.action === 'oauth_code_replay')).toBe(true);
  });
});

describe('Approval-Gate Policy Engine, MutationPlanGate, Cloudflare KV/Routes & Downstream Rollback', () => {
  it('enforces fail-closed scope, protected-branch, and downstream tool policies', async () => {
    const policy = new DefaultApprovalGatePolicy({
      protectedBranches: ['main', 'master', 'staging'],
    });

    // Scope policy
    expect(policy.evaluateScope(['mcp:tools'], 'write').allowed).toBe(true);
    expect(policy.evaluateScope(['mcp:read'], 'read').allowed).toBe(true);
    expect(policy.evaluateScope(['mcp:read'], 'write').allowed).toBe(false);
    expect(policy.evaluateScope([], 'read').allowed).toBe(false);

    // Protected branch policy (also verified via GitHubService)
    expect(policy.evaluateProtectedBranch('main').allowed).toBe(false);
    expect(policy.evaluateProtectedBranch('staging').allowed).toBe(false);
    expect(policy.evaluateProtectedBranch('release', 'release').allowed).toBe(false);
    expect(policy.evaluateProtectedBranch('--bad-flag').allowed).toBe(false);
    expect(policy.evaluateProtectedBranch('feat/decoupled-policy').allowed).toBe(true);

    const gh = new GitHubService({ policy });
    await expect(
      gh.createOrUpdatePr({
        workspacePath: makeTempDir('gh-pol-'),
        repo: 'owner/repo',
        branchName: 'staging',
        title: 'Blocked',
      }),
    ).rejects.toThrow(ProtectedBranchError);

    // Downstream tool classification: denied overrides readonly/mutating; unlisted fails closed
    const serverConfig = {
      id: 'ops',
      transport: 'http' as const,
      url: 'http://ops.internal/mcp',
      enabled: true,
      timeoutMs: 10_000,
      readonlyTools: ['status', 'conflict_tool'],
      mutatingTools: ['deploy', 'conflict_tool'],
      deniedTools: ['conflict_tool', 'drop_db'],
    };
    expect(policy.classifyDownstreamTool(serverConfig, 'conflict_tool')).toBe('denied');
    expect(policy.classifyDownstreamTool(serverConfig, 'unknown_tool')).toBe('unlisted');
    expect(policy.evaluateDownstreamTool(serverConfig, 'status', 'inspect').allowed).toBe(true);
    expect(policy.evaluateDownstreamTool(serverConfig, 'status', 'stage').allowed).toBe(false);
    expect(policy.evaluateDownstreamTool(serverConfig, 'deploy', 'inspect').allowed).toBe(false);
    expect(policy.evaluateDownstreamTool(serverConfig, 'deploy', 'stage').allowed).toBe(true);
    expect(policy.evaluateDownstreamTool(serverConfig, 'unknown_tool', 'inspect').allowed).toBe(false);
  });

  it('stages, executes, and rolls back Cloudflare KV (put/delete), Worker Routes (create/update/delete), and DNS exact-ID via MutationPlanGate (zero SQLite)', async () => {
    const { client, kvValues, workerRoutes, dnsRecords, dnsListSpy, dnsDeleteSpy } =
      createMockCloudflareClient();
    const secretVal = 'cf-super-secret-kv-value-99999';
    const scrubber = new SecretScrubber({ extraSecrets: [secretVal] });
    const planStore = new InMemoryPlanStore();
    const auditLogger = createMemoryAuditLogger();
    const policy = new DefaultApprovalGatePolicy();

    const cf = new CloudflareService({
      accountId: 'acc-1',
      readClient: client,
      writeClient: client,
      scrubber,
      policy,
    });
    const gate = new MutationPlanGate({
      planStore,
      auditLogger,
      policy,
      scrubber,
      adapters: [cf.asMutationTargetAdapter()],
    });

    // 1. KV Put (new key -> rollback deletes key) + secret scrubbing in diff
    const kvNewPlan = await cf.stageCloudflarePlan(planStore, {
      type: 'kv_put',
      namespaceId: 'ns-1',
      key: 'feature:flag',
      value: `token=${secretVal}`,
    });
    expect(kvNewPlan.summary_diff_text).not.toContain(secretVal);
    expect(kvNewPlan.summary_diff_text).toContain('[REDACTED_SECRET]');

    const kvNewExec = await gate.executePlan(kvNewPlan.plan_id, 'tester');
    expect(kvNewExec.status).toBe('executed');
    expect(kvValues.get('feature:flag')).toBe(`token=${secretVal}`);

    const kvNewRb = await gate.rollbackPlan(kvNewPlan.plan_id, 'tester');
    expect(kvNewRb.status).toBe('rolled_back');
    expect(kvValues.has('feature:flag')).toBe(false);

    // 2. KV Put (existing key -> rollback restores previous value)
    kvValues.set('config:mode', 'v1-old');
    const kvUpdatePlan = await cf.stageCloudflarePlan(planStore, {
      type: 'kv_put',
      namespaceId: 'ns-1',
      key: 'config:mode',
      value: 'v2-new',
    });
    await gate.executePlan(kvUpdatePlan.plan_id, 'tester');
    expect(kvValues.get('config:mode')).toBe('v2-new');
    await gate.rollbackPlan(kvUpdatePlan.plan_id, 'tester');
    expect(kvValues.get('config:mode')).toBe('v1-old');

    // 3. KV Delete (captures previous value -> rollback restores; missing key fails staging)
    await expect(
      cf.stageCloudflarePlan(planStore, {
        type: 'kv_delete',
        namespaceId: 'ns-1',
        key: 'does-not-exist',
      }),
    ).rejects.toThrow(/not found/i);

    const kvDelPlan = await cf.stageCloudflarePlan(planStore, {
      type: 'kv_delete',
      namespaceId: 'ns-1',
      key: 'config:mode',
    });
    await gate.executePlan(kvDelPlan.plan_id, 'tester');
    expect(kvValues.has('config:mode')).toBe(false);
    await gate.rollbackPlan(kvDelPlan.plan_id, 'tester');
    expect(kvValues.get('config:mode')).toBe('v1-old');

    // 4. Worker Route Create -> persists created routeId -> exact-ID delete on rollback
    const routeCreatePlan = await cf.stageCloudflarePlan(planStore, {
      type: 'worker_route_create',
      zoneId: 'zone-1',
      pattern: 'api.example.com/*',
      script: 'api-worker',
    });
    await gate.executePlan(routeCreatePlan.plan_id, 'tester');
    expect(workerRoutes.size).toBe(1);
    const createdRouteId = Array.from(workerRoutes.keys())[0]!;
    const afterCreateStored = planStore.getPlan(routeCreatePlan.plan_id)!;
    expect((afterCreateStored.rollback_payload as { routeId?: string })?.routeId).toBe(
      createdRouteId,
    );
    await gate.rollbackPlan(routeCreatePlan.plan_id, 'tester');
    expect(workerRoutes.size).toBe(0);

    // 5. Worker Route Update & Delete with full snapshot rollback
    workerRoutes.set('route-fixed', {
      id: 'route-fixed',
      pattern: 'old.example.com/*',
      script: 'old-worker',
    });
    const routeUpdatePlan = await cf.stageCloudflarePlan(planStore, {
      type: 'worker_route_update',
      zoneId: 'zone-1',
      routeId: 'route-fixed',
      pattern: 'new.example.com/*',
      script: 'new-worker',
    });
    await gate.executePlan(routeUpdatePlan.plan_id, 'tester');
    expect(workerRoutes.get('route-fixed')?.script).toBe('new-worker');
    await gate.rollbackPlan(routeUpdatePlan.plan_id, 'tester');
    expect(workerRoutes.get('route-fixed')).toEqual({
      id: 'route-fixed',
      pattern: 'old.example.com/*',
      script: 'old-worker',
    });

    const routeDeletePlan = await cf.stageCloudflarePlan(planStore, {
      type: 'worker_route_delete',
      zoneId: 'zone-1',
      routeId: 'route-fixed',
    });
    await gate.executePlan(routeDeletePlan.plan_id, 'tester');
    expect(workerRoutes.has('route-fixed')).toBe(false);
    await gate.rollbackPlan(routeDeletePlan.plan_id, 'tester');
    expect(Array.from(workerRoutes.values())[0]).toMatchObject({
      pattern: 'old.example.com/*',
      script: 'old-worker',
    });

    // 6. DNS Record Create persists created recordId -> exact-ID delete on rollback (no list scan during rollback)
    const dnsPlan = await cf.stageCloudflarePlan(planStore, {
      type: 'dns_record_create',
      zoneId: 'zone-1',
      record: { type: 'A', name: 'exact.example.com', content: '203.0.113.10' },
    });
    await gate.executePlan(dnsPlan.plan_id, 'tester');
    expect(dnsRecords.size).toBe(1);
    const createdDnsId = Array.from(dnsRecords.keys())[0]!;
    dnsListSpy.mockClear();
    await gate.rollbackPlan(dnsPlan.plan_id, 'tester');
    expect(dnsRecords.size).toBe(0);
    expect(dnsDeleteSpy).toHaveBeenCalledWith(createdDnsId, { zone_id: 'zone-1' });
    expect(dnsListSpy).not.toHaveBeenCalled();
  });

  it('supports Downstream MCP-2 rollback and preserves plan state on target/rollback mismatch', async () => {
    const planStore = new InMemoryPlanStore();
    const auditLogger = createMemoryAuditLogger();
    const policy = new DefaultApprovalGatePolicy();
    const scrubber = new SecretScrubber();
    const calledTools: Array<{ name: string; args: Record<string, unknown> }> = [];

    const mockClient: DownstreamMcpClientLike = {
      listTools: async () => ({
        tools: [{ name: 'db_migrate' }, { name: 'db_rollback' }, { name: 'db_status' }],
      }),
      callTool: async ({ name, arguments: toolArgs }) => {
        calledTools.push({ name, args: toolArgs });
        return { content: [{ type: 'text', text: `ran ${name}` }] };
      },
      close: async () => {},
    };

    const bridge = new DownstreamMcpBridge({
      servers: [
        {
          id: 'ops',
          transport: 'http',
          url: 'http://ops.internal/mcp',
          readonlyTools: ['db_status'],
          mutatingTools: ['db_migrate', 'db_rollback'],
          deniedTools: ['drop_all'],
        },
      ],
      clientFactory: async () => mockClient,
      policy,
      scrubber,
    });

    // Rejects readonly or denied rollback tool at stage time
    expect(() =>
      bridge.stageMutatingToolPlan(
        planStore,
        'ops',
        'db_migrate',
        { rev: 2 },
        'migrate',
        { toolName: 'db_status', args: {} },
      ),
    ).toThrow(DownstreamPolicyError);

    expect(() =>
      bridge.stageMutatingToolPlan(
        planStore,
        'ops',
        'db_migrate',
        { rev: 2 },
        'migrate',
        { toolName: 'drop_all', args: {} },
      ),
    ).toThrow(DownstreamPolicyError);

    // Stage plan WITHOUT rollback, execute, and verify failed rollback does NOT corrupt 'executed' status
    const noRbPlan = bridge.stageMutatingToolPlan(planStore, 'ops', 'db_migrate', { rev: 1 }, 'no-rb');
    const gate = new MutationPlanGate({
      planStore,
      auditLogger,
      policy,
      scrubber,
      adapters: [bridge.asMutationTargetAdapter()],
    });
    await gate.executePlan(noRbPlan.plan_id, 'tester');
    expect(planStore.getPlan(noRbPlan.plan_id)?.status).toBe('executed');
    await expect(gate.rollbackPlan(noRbPlan.plan_id, 'tester')).rejects.toThrow(
      ApprovalGatePolicyError,
    );
    expect(planStore.getPlan(noRbPlan.plan_id)?.status).toBe('executed');

    // Stage plan WITH rollback, execute, and roll back cleanly via MutationPlanGate
    const withRbPlan = bridge.stageMutatingToolPlan(
      planStore,
      'ops',
      'db_migrate',
      { rev: 2 },
      'upgrade with rollback',
      { toolName: 'db_rollback', args: { toRev: 1 } },
    );
    const execRes = await gate.executePlan(withRbPlan.plan_id, 'tester');
    expect(execRes.status).toBe('executed');
    const rbRes = await gate.rollbackPlan(withRbPlan.plan_id, 'tester');
    expect(rbRes.status).toBe('rolled_back');
    expect(calledTools.slice(-2)).toEqual([
      { name: 'db_migrate', args: { rev: 2 } },
      { name: 'db_rollback', args: { toRev: 1 } },
    ]);

    // Target mismatch on unregistered gate must NOT corrupt staged plan status
    const cfOnlyGate = new MutationPlanGate({
      planStore,
      auditLogger,
      policy,
      scrubber,
      adapters: [],
    });
    const stagedPlan = bridge.stageMutatingToolPlan(planStore, 'ops', 'db_migrate', { rev: 3 }, 'test');
    await expect(cfOnlyGate.executePlan(stagedPlan.plan_id, 'tester')).rejects.toThrow(
      ApprovalGatePolicyError,
    );
    expect(planStore.getPlan(stagedPlan.plan_id)?.status).toBe('staged');
  });
});

describe('Contract-Enforcing McpToolRegistry, Adapter Decoupling & Streamable HTTP Edge Cases', () => {
  it('enforces exact 10-tool contract, single destructiveHint rule, and fail-closed scopes', async () => {
    const registry = new McpToolRegistry();
    const scrubber = new SecretScrubber();
    const baseGuard = {
      scrubber,
      artifactsDir: makeTempDir('reg-art-'),
      label: 'test',
    };

    // Rejects non-contract tool name
    expect(() =>
      registry.register({
        name: 'ad_hoc_tool' as unknown as 'workspace_manage',
        title: 'Bad',
        description: 'Bad',
        inputSchema: {},
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
        guardDeps: baseGuard,
        handler: async () => 'nope',
      }),
    ).toThrow(/non-contract/i);

    // Rejects destructiveHint: true on non-publish_changes
    expect(() =>
      registry.register({
        name: 'workspace_manage',
        title: 'WS',
        description: 'WS',
        inputSchema: {},
        annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
        guardDeps: baseGuard,
        handler: async () => 'nope',
      }),
    ).toThrow(/destructiveHint/i);

    // Rejects destructiveHint: false on publish_changes
    expect(() =>
      registry.register({
        name: 'publish_changes',
        title: 'Pub',
        description: 'Pub',
        inputSchema: {},
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
        guardDeps: baseGuard,
        handler: async () => 'nope',
      }),
    ).toThrow(/destructiveHint/i);

    // Register valid tool, then reject duplicate and incomplete attachToServer
    registry.register({
      name: 'workspace_manage',
      title: 'WS',
      description: 'WS',
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
      guardDeps: baseGuard,
      handler: async () => 'ok',
    });
    expect(() =>
      registry.register({
        name: 'workspace_manage',
        title: 'WS',
        description: 'WS',
        inputSchema: {},
        annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
        guardDeps: baseGuard,
        handler: async () => 'ok',
      }),
    ).toThrow(/Duplicate/i);

    const server = new McpServer({ name: 'test', version: '1.0.0' });
    expect(() => registry.attachToServer(server)).toThrow(/Incomplete MCP tool registry/i);

    // Fail-closed scope guard when authInfo has empty or insufficient scopes
    const guarded = withMcpGuardrails(
      async () => 'secret-write-result',
      { ...baseGuard, requiredScope: 'write' },
    );
    const emptyScopesRes = await guarded({}, { authInfo: { clientId: 'c1', scopes: [] } });
    expect(emptyScopesRes.isError).toBe(true);
    expect(emptyScopesRes.content[0]?.text).toContain('insufficient_scope');

    const readOnlyRes = await guarded({}, { authInfo: { clientId: 'c1', scopes: ['mcp:read'] } });
    expect(readOnlyRes.isError).toBe(true);
    expect(readOnlyRes.content[0]?.text).toContain('insufficient_scope');

    const writeRes = await guarded({}, { authInfo: { clientId: 'c1', scopes: ['mcp:write'] } });
    expect(writeRes.isError).toBeUndefined();
    expect(writeRes.content[0]?.text).toBe('secret-write-result');
  });

  it('supports pure mock adapter injection, code_patch old_text/new_text alias, ast lang injection defense, and base_branch injection defense', async () => {
    const config = createTestConfig();
    fs.mkdirSync(path.join(config.workspacesDir, 'demo'), { recursive: true });
    fs.mkdirSync(config.artifactsDir, { recursive: true });

    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const scrubber = new SecretScrubber();
    const applyPatchSpy = vi.fn(async () => ({
      action: 'patch' as const,
      workspaceSlug: 'demo',
      filesTouched: ['src/a.ts'],
      diff: '--- a/src/a.ts\n+++ b/src/a.ts',
      validation: null,
      checkpointId: null,
      rolledBack: false,
    }));

    const mockWorkspaceAdapter: WorkspaceToolAdapter = {
      syncGitHubRepo: vi.fn(),
      initCfOpsWorkspace: vi.fn(),
      rollbackToCheckpoint: vi.fn(),
      applyPatch: applyPatchSpy as unknown as WorkspaceToolAdapter['applyPatch'],
      createOrOverwriteFiles: vi.fn(),
      deleteFiles: vi.fn(),
      workspaceExec: vi.fn(),
      runValidationPipeline: vi.fn(),
    };
    const mockGithub: GitHubToolAdapter = {
      inspectPr: vi.fn(),
      inspectIssue: vi.fn(),
      inspectWorkflowFailure: vi.fn(),
      createOrUpdatePr: vi.fn(),
      submitPrReview: vi.fn(),
      postIssueOrPrComment: vi.fn(),
    };
    const mockCf: CloudflareToolAdapter = {
      inspectResource: vi.fn(),
      stageCloudflarePlan: vi.fn(),
      executeStagedCloudflarePlan: vi.fn(),
      rollbackExecutedPlan: vi.fn(),
      deployWorker: vi.fn(),
      deployPages: vi.fn(),
    };
    const mockDownstream: DownstreamMcpToolAdapter = {
      listDownstreamTools: vi.fn(),
      callReadonlyTool: vi.fn(),
      stageMutatingToolPlan: vi.fn(),
      executeStagedDownstreamPlan: vi.fn(),
      rollbackExecutedDownstreamPlan: vi.fn(),
      closeAll: vi.fn(),
    };
    const mockRunner: AgentRunnerAdapter = {
      name: 'mock-runner',
      run: vi.fn(),
    };

    const deps: McpToolDeps = {
      config,
      db,
      repos,
      scrubber,
      lockManager: new WorkspaceLockManager(),
      githubService: mockGithub,
      cloudflareService: mockCf,
      downstreamBridge: mockDownstream,
      codexRunner: mockRunner,
      workspaceAdapter: mockWorkspaceAdapter,
    };

    const registry = createMcpToolRegistry(deps);
    expect(registry.listRegisteredNames()).toHaveLength(10);

    // 1. code_patch accepts old_text / new_text aliases (DESIGN.md §7.3)
    const patchDef = registry.get('code_patch')!;
    await patchDef.handler(
      {
        action: 'patch',
        slug: 'demo',
        edits: [
          {
            path: 'src/a.ts',
            hunks: [{ old_text: 'foo', new_text: 'bar' }],
          },
        ],
      },
      {},
    );
    expect(applyPatchSpy).toHaveBeenCalledTimes(1);
    const passedInput = (applyPatchSpy.mock.calls[0] as unknown as [{ edits: Array<{ path: string; hunks: Array<{ search: string; replace: string }> }> }])[0];
    expect(passedInput.edits[0]!.hunks[0]).toMatchObject({ search: 'foo', replace: 'bar' });

    // 2. code_explore(mode="ast") blocks flag injection in lang
    const exploreDef = registry.get('code_explore')!;
    await expect(
      exploreDef.handler(
        {
          slug: 'demo',
          mode: 'ast',
          query: 'console.log($A)',
          lang: '--inspect=0.0.0.0:9229',
        },
        {},
      ),
    ).rejects.toThrow(/Invalid ast lang/i);

    // 3. publish_changes(action="github_pr") blocks git flag injection in base_branch before running git diff
    const publishDef = registry.get('publish_changes')!;
    await expect(
      publishDef.handler(
        {
          action: 'github_pr',
          slug: 'demo',
          repo: 'owner/repo',
          branch_name: 'feat/safe',
          base_branch: '--output=/tmp/pwned',
          title: 'Test',
        },
        {},
      ),
    ).rejects.toThrow(/Invalid base_branch/i);

    db.close();
  });

  it('enforces bounded POST /mcp body ceiling (413) and defensive headers alongside Claude/ChatGPT Origin allowlist', async () => {
    const root = makeTempDir('bastion-http-limit-');
    const gw = createGatewayApp({
      env: {
        NODE_ENV: 'test',
        PUBLIC_DOMAIN: 'https://mcp.example.com',
        ADMIN_PASSWORD_HASH: hashPasswordScrypt('pw-123456'),
        OAUTH_SIGNING_SECRET: 'http-limit-secret-0123456789abcdef',
        DATA_DIR: path.join(root, 'data'),
        WORKSPACES_DIR: path.join(root, 'workspaces'),
        ARTIFACTS_DIR: path.join(root, 'data', 'artifacts'),
      },
      dbPath: ':memory:',
      mcpMaxBodyBytes: 256,
    });

    try {
      const dcr = await gw.app.request('https://mcp.example.com/oauth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
        }),
      });
      const { client_id: clientId } = (await dcr.json()) as { client_id: string };
      const { tokenJson } = await runAuthorizeAndExchange({
        app: gw.app,
        clientId,
        redirectUri: 'https://claude.ai/api/mcp/auth_callback',
        password: 'pw-123456',
      });
      const accessToken = String(tokenJson.access_token);

      // Oversized POST /mcp body rejected with 413 JSON-RPC error + defensive headers
      const bigBody = JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: { pad: 'x'.repeat(1024) },
      });
      const tooBigRes = await gw.app.request('https://mcp.example.com/mcp', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Origin: 'https://claude.ai',
        },
        body: bigBody,
      });
      expect(tooBigRes.status).toBe(413);
      expect(tooBigRes.headers.get('cache-control')).toBe('no-store');
      expect(tooBigRes.headers.get('x-content-type-options')).toBe('nosniff');

      // Disallowed Origin rejected with 403
      const badOriginRes = await gw.app.request('https://mcp.example.com/mcp', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Origin: 'https://evil.example.com',
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
      });
      expect(badOriginRes.status).toBe(403);

      // Allowed ChatGPT Origin + small valid request succeeds with defensive headers
      const okRes = await gw.app.request('https://mcp.example.com/mcp', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          Origin: 'https://chatgpt.com',
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }),
      });
      expect(okRes.status).toBe(200);
      expect(okRes.headers.get('cache-control')).toBe('no-store');
      expect(okRes.headers.get('x-content-type-options')).toBe('nosniff');
    } finally {
      await gw.shutdown();
    }
  });

  it('keeps createMcpHttpHandler directly usable with custom options', async () => {
    const config = createTestConfig();
    const db = openDatabase(':memory:');
    const repos = createRepositories(db);
    const handler = createMcpHttpHandler(
      {
        config,
        db,
        repos,
        scrubber: new SecretScrubber(),
        lockManager: new WorkspaceLockManager(),
        githubService: new GitHubService(),
        cloudflareService: new CloudflareService(),
        downstreamBridge: new DownstreamMcpBridge(),
        codexRunner: { name: 'mock', run: vi.fn() },
      },
      { maxBodyBytes: 64 },
    );

    const app = new Hono();
    app.all('/mcp', handler);
    const res = await app.request('https://mcp.example.com/mcp', { method: 'GET' });
    expect(res.status).toBe(405);
    expect(res.headers.get('allow')).toBe('POST');
    db.close();
  });
});
