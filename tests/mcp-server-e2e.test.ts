import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createGatewayApp, type GatewayAppInstance } from '../src/app.js';
import { computeS256Challenge, hashPasswordScrypt } from '../src/auth/index.js';
import { loadConfig } from '../src/config.js';
import {
  CloudflareService,
  type CloudflareClientLike,
} from '../src/core/cloudflareService.js';
import {
  DownstreamMcpBridge,
  type DownstreamMcpClientLike,
} from '../src/core/downstreamMcpBridge.js';
import type { AgentRunOptions, AgentRunner } from '../src/types.js';

const tempDirs: string[] = [];
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

function createMockCloudflareClient(): {
  client: CloudflareClientLike;
  spies: Record<string, ReturnType<typeof vi.fn>>;
} {
  const spies = {
    zonesList: vi.fn(async () => ({
      result: [{ id: 'zone-e2e', name: 'e2e.example.com', status: 'active' }],
    })),
    zonesGet: vi.fn(async () => ({ id: 'zone-e2e', name: 'e2e.example.com', status: 'active' })),
    dnsList: vi.fn(async () => ({
      result: [
        {
          id: 'rec-1',
          type: 'A',
          name: 'api.e2e.example.com',
          content: '10.0.0.1',
          ttl: 300,
          proxied: true,
        },
      ],
    })),
    dnsGet: vi.fn(async () => ({
      id: 'rec-1',
      type: 'A',
      name: 'api.e2e.example.com',
      content: '10.0.0.1',
      ttl: 300,
      proxied: true,
    })),
    dnsCreate: vi.fn(async (params: Record<string, unknown>) => ({ id: 'rec-new', ...params })),
    dnsUpdate: vi.fn(async (id: string, params: Record<string, unknown>) => ({ id, ...params })),
    dnsDelete: vi.fn(async (id: string) => ({ id })),
    workersList: vi.fn(async () => ({ result: [] })),
    workersTailGet: vi.fn(async () => ({ tails: [] })),
    pagesList: vi.fn(async () => ({ result: [] })),
    pagesGet: vi.fn(async () => ({})),
    pagesDeploymentsList: vi.fn(async () => ({ result: [] })),
    kvList: vi.fn(async () => ({ result: [] })),
    kvKeysList: vi.fn(async () => ({ result: [] })),
    d1List: vi.fn(async () => ({ result: [] })),
    d1Get: vi.fn(async () => ({})),
    d1Query: vi.fn(async () => ({ result: [] })),
    rulesetsList: vi.fn(async () => ({ result: [] })),
    rulesetsGet: vi.fn(async () => ({})),
    rulesetsUpdate: vi.fn(async () => ({})),
    rulesetsPhasesGet: vi.fn(async () => ({})),
    rulesetsPhasesUpdate: vi.fn(async () => ({})),
  };

  const client: CloudflareClientLike = {
    zones: { list: spies.zonesList, get: spies.zonesGet },
    dns: {
      records: {
        list: spies.dnsList,
        get: spies.dnsGet,
        create: spies.dnsCreate,
        update: spies.dnsUpdate,
        delete: spies.dnsDelete,
      },
    },
    workers: { scripts: { list: spies.workersList, tail: { get: spies.workersTailGet } } },
    pages: {
      projects: {
        list: spies.pagesList,
        get: spies.pagesGet,
        deployments: { list: spies.pagesDeploymentsList },
      },
    },
    kv: { namespaces: { list: spies.kvList, keys: { list: spies.kvKeysList } } },
    d1: { database: { list: spies.d1List, get: spies.d1Get, query: spies.d1Query } },
    rulesets: {
      list: spies.rulesetsList,
      get: spies.rulesetsGet,
      update: spies.rulesetsUpdate,
      phases: { get: spies.rulesetsPhasesGet, update: spies.rulesetsPhasesUpdate },
    },
  };

  return { client, spies };
}

async function mcpRpc(
  gateway: GatewayAppInstance,
  token: string,
  method: string,
  params: Record<string, unknown> = {},
  id = 1,
): Promise<Record<string, unknown>> {
  const res = await gateway.app.request('https://mcp.example.com/mcp', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${token}`,
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2025-11-25',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id,
      method,
      params,
    }),
  });
  expect(res.status).toBe(200);
  const ct = res.headers.get('content-type') ?? '';
  expect(ct).toContain('application/json');
  return (await res.json()) as Record<string, unknown>;
}

async function callMcpTool(
  gateway: GatewayAppInstance,
  token: string,
  name: string,
  args: Record<string, unknown>,
  id = 10,
): Promise<{ content: Array<{ type: string; text: string }>; isError?: boolean }> {
  const rpc = await mcpRpc(
    gateway,
    token,
    'tools/call',
    { name, arguments: args },
    id,
  );
  if (rpc.error) {
    throw new Error(`JSON-RPC error calling ${name}: ${JSON.stringify(rpc.error)}`);
  }
  return rpc.result as { content: Array<{ type: string; text: string }>; isError?: boolean };
}

function initGitWorkspace(workspacesDir: string, slug: string): string {
  const wsDir = path.join(workspacesDir, slug);
  fs.mkdirSync(path.join(wsDir, 'src'), { recursive: true });
  fs.writeFileSync(
    path.join(wsDir, 'package.json'),
    JSON.stringify({ name: slug, version: '1.0.0' }, null, 2),
    'utf8',
  );
  fs.writeFileSync(
    path.join(wsDir, 'src', 'hello.ts'),
    'export function greet(name: string): string {\n  return `Hello, ${name}`;\n}\n',
    'utf8',
  );
  fs.writeFileSync(
    path.join(wsDir, 'wrangler.toml'),
    'name = "demo-worker"\ncompatibility_date = "2026-01-01"\nmain = "src/hello.ts"\n',
    'utf8',
  );
  fs.writeFileSync(path.join(wsDir, '.env'), 'SECRET_SHOULD_NOT_BE_READ=topsecret1234\n', 'utf8');

  execFileSync('git', ['init'], { cwd: wsDir, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.email', 'test@omni.local'], { cwd: wsDir, stdio: 'ignore' });
  execFileSync('git', ['config', 'user.name', 'Omni Test'], { cwd: wsDir, stdio: 'ignore' });
  execFileSync('git', ['add', 'package.json', 'src/hello.ts', 'wrangler.toml'], {
    cwd: wsDir,
    stdio: 'ignore',
  });
  execFileSync('git', ['commit', '-m', 'Initial commit'], { cwd: wsDir, stdio: 'ignore' });
  return wsDir;
}

afterEach(async () => {
  for (const gw of gateways.splice(0)) {
    await gw.shutdown();
  }
  for (const dir of tempDirs.splice(0)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

describe('MCP Gateway E2E (OAuth + Stateless Streamable HTTP + 10 Tools)', () => {
  it('completes OAuth DCR+PKCE, enforces 401/405 transport rules, exposes exact 10 tools & annotations, and runs end-to-end tool flows', async () => {
    const rootDir = makeTempDir('omni-e2e-');
    const dataDir = path.join(rootDir, 'data');
    const workspacesDir = path.join(rootDir, 'workspaces');
    const artifactsDir = path.join(dataDir, 'artifacts');
    const adminPassword = 'e2e-operator-password-123';

    const config = loadConfig({
      NODE_ENV: 'test',
      PORT: '8787',
      PUBLIC_DOMAIN: 'https://mcp.example.com',
      DATA_DIR: dataDir,
      WORKSPACES_DIR: workspacesDir,
      ARTIFACTS_DIR: artifactsDir,
      DATABASE_PATH: ':memory:',
      ADMIN_PASSWORD_HASH: hashPasswordScrypt(adminPassword),
      OAUTH_SIGNING_SECRET: 'e2e-signing-secret-at-least-32-bytes-long-9999',
      GH_TOKEN: 'ghp_e2e_secret_token_never_leak_123456',
      CLOUDFLARE_API_TOKEN: 'cf_e2e_write_token_never_leak_123456',
      CLOUDFLARE_ACCOUNT_ID: 'acct-e2e',
    });

    const { client: cfReadClient } = createMockCloudflareClient();
    const { client: cfWriteClient, spies: cfWriteSpies } = createMockCloudflareClient();
    const cloudflareService = new CloudflareService({
      apiToken: config.cloudflareApiToken,
      accountId: config.cloudflareAccountId,
      readClient: cfReadClient,
      writeClient: cfWriteClient,
    });

    const downstreamCallSpy = vi.fn(
      async ({ name, arguments: args }: { name: string; arguments?: Record<string, unknown> }) => ({
        content: [{ type: 'text', text: `Downstream OK: ${name} ${JSON.stringify(args ?? {})}` }],
      }),
    );
    const downstreamClient: DownstreamMcpClientLike = {
      listTools: async () => ({
        tools: [
          { name: 'db_inspect', description: 'Read-only DB stats' },
          { name: 'db_migrate', description: 'Run DB migration' },
          { name: 'db_wipe', description: 'Denied destructive wipe' },
        ],
      }),
      callTool: downstreamCallSpy,
      close: async () => {},
    };
    const downstreamBridge = new DownstreamMcpBridge({
      servers: [
        {
          id: 'db-sidecar',
          transport: 'http',
          url: 'http://db-sidecar:3000/mcp',
          readonlyTools: ['db_inspect'],
          mutatingTools: ['db_migrate'],
          deniedTools: ['db_wipe'],
        },
      ],
      clientFactory: async () => downstreamClient,
    });

    const agentRunSpy = vi.fn(async (opts: AgentRunOptions) => ({
      status: 'completed' as const,
      threadId: `thread-${opts.driver ?? 'codex'}`,
      finalReport: `Completed ${opts.driver ?? 'codex'} (${opts.mode})`,
      tokenUsage: { input_tokens: 10, output_tokens: 20, total_tokens: 30 },
    }));
    const mockAgentRunner: AgentRunner = {
      name: 'mock-agent-registry',
      run: agentRunSpy,
    };

    const gateway = createGatewayApp({
      config,
      dbPath: ':memory:',
      cloudflareService,
      downstreamBridge,
      agentRunner: mockAgentRunner,
    });
    gateways.push(gateway);

    // 1. Healthcheck
    const healthRes = await gateway.app.request('https://mcp.example.com/healthz');
    expect(healthRes.status).toBe(200);
    expect(await healthRes.json()).toMatchObject({ ok: true, db: 'ready' });

    // 2. Unauthenticated /mcp -> 401 + WWW-Authenticate
    const unauthRes = await gateway.app.request('https://mcp.example.com/mcp', { method: 'POST' });
    expect(unauthRes.status).toBe(401);
    expect(unauthRes.headers.get('www-authenticate')).toBe(
      'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"',
    );

    // 3. OAuth 2.1 DCR -> PKCE S256 authorize -> token
    const dcrRes = await gateway.app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Gemini Connected App E2E',
        redirect_uris: ['https://gemini.google.com/oauth/callback'],
      }),
    });
    expect(dcrRes.status).toBe(201);
    const dcrBody = (await dcrRes.json()) as { client_id: string };
    expect(dcrBody.client_id).toBeTruthy();

    const verifier = crypto.randomBytes(32).toString('base64url');
    const challenge = computeS256Challenge(verifier);
    const state = 'state-' + 'x'.repeat(128);
    const resource = 'https://mcp.example.com/mcp';

    const authGetUrl = new URL('https://mcp.example.com/oauth/authorize');
    authGetUrl.searchParams.set('response_type', 'code');
    authGetUrl.searchParams.set('client_id', dcrBody.client_id);
    authGetUrl.searchParams.set('redirect_uri', 'https://gemini.google.com/oauth/callback');
    authGetUrl.searchParams.set('code_challenge', challenge);
    authGetUrl.searchParams.set('code_challenge_method', 'S256');
    authGetUrl.searchParams.set('state', state);
    authGetUrl.searchParams.set('scope', 'mcp:tools');
    authGetUrl.searchParams.set('resource', resource);

    const authGetRes = await gateway.app.request(authGetUrl.toString());
    expect(authGetRes.status).toBe(200);
    const authHtml = await authGetRes.text();
    const authReqId = extractHiddenInput(authHtml, 'auth_req_id');
    const csrfToken = extractHiddenInput(authHtml, 'csrf_token');

    const authPostBody = new URLSearchParams({
      auth_req_id: authReqId,
      csrf_token: csrfToken,
      password: adminPassword,
      decision: 'approve',
    });
    const authPostRes = await gateway.app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: authPostBody.toString(),
    });
    expect(authPostRes.status).toBe(302);
    const redirectLocation = new URL(authPostRes.headers.get('location')!);
    expect(redirectLocation.searchParams.get('state')).toBe(state);
    const code = redirectLocation.searchParams.get('code')!;
    expect(code).toBeTruthy();

    const tokenRes = await gateway.app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://gemini.google.com/oauth/callback',
        client_id: dcrBody.client_id,
        code_verifier: verifier,
        resource,
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const tokenJson = (await tokenRes.json()) as { access_token: string };
    const accessToken = tokenJson.access_token;
    expect(accessToken).toBeTruthy();

    // 4. GET /mcp and DELETE /mcp -> 405 Method Not Allowed
    const getMcpRes = await gateway.app.request('https://mcp.example.com/mcp', {
      method: 'GET',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(getMcpRes.status).toBe(405);
    expect(getMcpRes.headers.get('allow')).toBe('POST');

    const delMcpRes = await gateway.app.request('https://mcp.example.com/mcp', {
      method: 'DELETE',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(delMcpRes.status).toBe(405);

    // 5. POST /mcp initialize + tools/list asserting exact 10 tools & annotations
    const initRpc = await mcpRpc(gateway, accessToken, 'initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'e2e-client', version: '1.0.0' },
    });
    expect(initRpc.result).toMatchObject({
      protocolVersion: '2025-11-25',
      serverInfo: { name: 'gemini-bastion-mcp' },
    });

    const listRpc = await mcpRpc(gateway, accessToken, 'tools/list', {}, 2);
    const tools = ((listRpc.result as { tools: Array<Record<string, unknown>> }).tools ?? []).sort(
      (a, b) => String(a.name).localeCompare(String(b.name)),
    );
    expect(tools).toHaveLength(10);

    const byName = new Map(tools.map((t) => [String(t.name), t]));
    expect(Array.from(byName.keys()).sort()).toEqual(
      [
        'code_explore',
        'code_patch',
        'dispatch_runner',
        'github_inspect',
        'infra_inspect',
        'job_status',
        'publish_changes',
        'stage_mutation_plan',
        'workspace_exec',
        'workspace_manage',
      ].sort(),
    );

    // ONLY publish_changes has destructiveHint: true
    for (const [name, tool] of byName.entries()) {
      const ann = (tool.annotations ?? {}) as Record<string, unknown>;
      if (name === 'publish_changes') {
        expect(ann.destructiveHint).toBe(true);
        expect(ann.openWorldHint).toBe(true);
        expect(ann.readOnlyHint).toBe(false);
      } else {
        expect(ann.destructiveHint).toBe(false);
      }
    }
    expect((byName.get('github_inspect')!.annotations as Record<string, unknown>).openWorldHint).toBe(true);
    expect((byName.get('infra_inspect')!.annotations as Record<string, unknown>).openWorldHint).toBe(true);
    expect((byName.get('code_explore')!.annotations as Record<string, unknown>).readOnlyHint).toBe(true);
    expect((byName.get('job_status')!.annotations as Record<string, unknown>).readOnlyHint).toBe(false);

    // 5b. Disallowed browser Origin -> 403 on /mcp; allowed Origin -> 200
    const badOriginRes = await gateway.app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessToken}`,
        origin: 'https://evil.example.com',
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-11-25',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'tools/list', params: {} }),
    });
    expect(badOriginRes.status).toBe(403);

    const okOriginRes = await gateway.app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${accessToken}`,
        origin: 'https://gemini.google.com',
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-11-25',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 100, method: 'tools/list', params: {} }),
    });
    expect(okOriginRes.status).toBe(200);

    // 6. Real workspace_manage + code_patch + code_explore (including read_artifact) + workspace_exec
    initGitWorkspace(workspacesDir, 'demo-repo');

    const cfOpsRes = await callMcpTool(gateway, accessToken, 'workspace_manage', {
      action: 'init_cf_ops',
      slug: 'demo-repo',
    });
    expect(cfOpsRes.isError).toBeUndefined();
    expect(cfOpsRes.content[0].text).toContain('"workerName": "demo-worker"');

    const listWsRes = await callMcpTool(gateway, accessToken, 'workspace_manage', {
      action: 'list',
    });
    expect(listWsRes.content[0].text).toContain('demo-repo');

    const patchRes = await callMcpTool(gateway, accessToken, 'code_patch', {
      action: 'patch',
      slug: 'demo-repo',
      edits: [
        {
          path: 'src/hello.ts',
          hunks: [
            {
              search: 'return `Hello, ${name}`;',
              replace: 'return `Hi, ${name}!`;',
            },
          ],
        },
      ],
      skip_l1: true,
    });
    expect(patchRes.isError).toBeUndefined();
    expect(patchRes.content[0].text).toContain('Checkpoint: chk_');

    // Verify search & read_lines work and .env is blocked
    const searchRes = await callMcpTool(gateway, accessToken, 'code_explore', {
      mode: 'search',
      slug: 'demo-repo',
      query: 'Hi, \\$\\{name\\}',
    });
    expect(searchRes.content[0].text).toContain('src/hello.ts');

    const envReadRes = await callMcpTool(gateway, accessToken, 'code_explore', {
      mode: 'read_lines',
      slug: 'demo-repo',
      path: '.env',
    });
    expect(envReadRes.isError).toBe(true);
    expect(envReadRes.content[0].text).toContain('sensitive workspace file');

    // Create oversized file (>60KB) and trigger code_explore truncation -> read_artifact
    const bigContent = Array.from({ length: 1500 }, (_, i) => `export const line_${i} = "${'X'.repeat(40)}";`).join('\n');
    await callMcpTool(gateway, accessToken, 'code_patch', {
      action: 'create_or_overwrite',
      slug: 'demo-repo',
      files: [{ path: 'src/big.ts', content: bigContent }],
      skip_validation: true,
    });

    const bigRead = await callMcpTool(gateway, accessToken, 'code_explore', {
      mode: 'read_lines',
      slug: 'demo-repo',
      path: 'src/big.ts',
      start_line: 1,
      end_line: 1500,
    });
    expect(bigRead.content[0].text).toContain('code_explore(mode="read_artifact"');
    const artifactMatch = /artifact_id="([a-zA-Z0-9_-]+)"/.exec(bigRead.content[0].text);
    expect(artifactMatch?.[1]).toBeTruthy();

    const artifactSlice = await callMcpTool(gateway, accessToken, 'code_explore', {
      mode: 'read_artifact',
      artifact_id: artifactMatch![1],
      offset: 25000,
      limit: 500,
    });
    expect(artifactSlice.isError).toBeUndefined();
    expect(artifactSlice.content[0].text).toContain(`# Artifact: ${artifactMatch![1]}`);
    expect(artifactSlice.content[0].text).toContain('Offset: 25000');

    // workspace_exec verifies secret isolation (process.env does NOT contain GH_TOKEN or CLOUDFLARE_API_TOKEN) and allow_network param
    const execRes = await callMcpTool(gateway, accessToken, 'workspace_exec', {
      slug: 'demo-repo',
      command: `node -e "console.log('GH=' + Boolean(process.env.GH_TOKEN) + ',CF=' + Boolean(process.env.CLOUDFLARE_API_TOKEN))"`,
      allow_network: true,
    });
    expect(execRes.isError).toBeUndefined();
    expect(execRes.content[0].text).toContain('GH=false,CF=false');

    // 7. Stage & Execute Cloudflare mutation plan + Rollback
    const cfStage = await callMcpTool(gateway, accessToken, 'stage_mutation_plan', {
      target: 'cloudflare',
      mutation_type: 'dns_record_update',
      zone_id: 'zone-e2e',
      record_id: 'rec-1',
      record: {
        type: 'A',
        name: 'api.e2e.example.com',
        content: '10.0.0.2',
        ttl: 120,
        proxied: false,
      },
    });
    expect(cfStage.isError).toBeUndefined();
    const cfPlanMatch = /cf-plan-[0-9]+-[a-f0-9]+/.exec(cfStage.content[0].text);
    expect(cfPlanMatch?.[0]).toBeTruthy();
    const cfPlanId = cfPlanMatch![0];

    const cfExec = await callMcpTool(gateway, accessToken, 'publish_changes', {
      action: 'execute_staged_plan',
      plan_id: cfPlanId,
    });
    expect(cfExec.isError).toBeUndefined();
    expect(cfExec.content[0].text).toContain('"status": "executed"');
    expect(cfWriteSpies.dnsUpdate).toHaveBeenCalledTimes(1);

    const cfRollback = await callMcpTool(gateway, accessToken, 'publish_changes', {
      action: 'rollback_plan',
      plan_id: cfPlanId,
    });
    expect(cfRollback.isError).toBeUndefined();
    expect(cfRollback.content[0].text).toContain('"status": "rolled_back"');
    expect(cfWriteSpies.dnsUpdate).toHaveBeenCalledTimes(2);

    // 8. Downstream MCP-2 policy enforcement + Stage & Execute
    const dsList = await callMcpTool(gateway, accessToken, 'infra_inspect', {
      action: 'downstream_list',
    });
    expect(dsList.content[0].text).toContain('db_inspect');
    expect(dsList.content[0].text).toContain('db_migrate');
    expect(dsList.content[0].text).not.toContain('db_wipe');

    const dsDeniedCall = await callMcpTool(gateway, accessToken, 'infra_inspect', {
      action: 'downstream_call',
      server_name: 'db-sidecar',
      tool_name: 'db_migrate',
      args: {},
    });
    expect(dsDeniedCall.isError).toBe(true);
    expect(dsDeniedCall.content[0].text).toContain('stage_mutation_plan');

    const dsStage = await callMcpTool(gateway, accessToken, 'stage_mutation_plan', {
      target: 'downstream_mcp',
      server_name: 'db-sidecar',
      tool_name: 'db_migrate',
      args: { target: 'v2' },
      reason: 'Add index on sessions',
    });
    expect(dsStage.isError).toBeUndefined();
    const mcpPlanMatch = /mcp-plan-[0-9]+-[a-f0-9]+/.exec(dsStage.content[0].text);
    expect(mcpPlanMatch?.[0]).toBeTruthy();

    const dsExec = await callMcpTool(gateway, accessToken, 'publish_changes', {
      action: 'execute_staged_plan',
      plan_id: mcpPlanMatch![0],
    });
    expect(dsExec.isError).toBeUndefined();
    expect(dsExec.content[0].text).toContain('Downstream OK: db_migrate');
    expect(downstreamCallSpy).toHaveBeenCalledWith({
      name: 'db_migrate',
      arguments: { target: 'v2' },
    });

    // 9. Security regressions: search glob override, git_diff flag injection, Pages/Worker path escape, shell_task immediate cancel
    const envGlobSearch = await callMcpTool(gateway, accessToken, 'code_explore', {
      mode: 'search',
      slug: 'demo-repo',
      query: 'SECRET_SHOULD_NOT_BE_READ',
      glob: '.env',
    });
    expect(envGlobSearch.content[0].text).not.toContain('topsecret1234');

    const badGitDiff = await callMcpTool(gateway, accessToken, 'code_explore', {
      mode: 'git_diff',
      slug: 'demo-repo',
      base_ref: '--output=/tmp/pwned',
    });
    expect(badGitDiff.isError).toBe(true);
    expect(badGitDiff.content[0].text).toContain('Invalid git base_ref');

    const badPagesDeploy = await callMcpTool(gateway, accessToken, 'publish_changes', {
      action: 'cloudflare_pages_deploy',
      slug: 'demo-repo',
      project_name: 'demo',
      directory: '/data',
    });
    expect(badPagesDeploy.isError).toBe(true);
    expect(badPagesDeploy.content[0].text).toContain('escapes workspace');

    const badWorkerConfig = await callMcpTool(gateway, accessToken, 'publish_changes', {
      action: 'cloudflare_worker_deploy',
      slug: 'demo-repo',
      config_path: '../../etc/passwd',
    });
    expect(badWorkerConfig.isError).toBe(true);
    expect(badWorkerConfig.content[0].text).toContain('escapes workspace');

    const dispatchRes = await callMcpTool(gateway, accessToken, 'dispatch_runner', {
      mode: 'shell_task',
      slug: 'demo-repo',
      objective: 'node -e "setTimeout(() => {}, 30000)"',
    });
    expect(dispatchRes.isError).toBeUndefined();
    const jobMatch = /job_id:\s*(job_[a-f0-9]+)/.exec(dispatchRes.content[0].text);
    expect(jobMatch?.[1]).toBeTruthy();

    const cancelStatus = await callMcpTool(gateway, accessToken, 'job_status', {
      job_id: jobMatch![1],
      cancel: true,
    });
    expect(cancelStatus.isError).toBeUndefined();
    expect(cancelStatus.content[0].text).toContain('Status: cancelled');

    // 9b. Multi-driver dispatch_runner (runner_type: "agent_readonly", agent_driver: "claude_code")
    const agentDispatchRes = await callMcpTool(gateway, accessToken, 'dispatch_runner', {
      runner_type: 'agent_readonly',
      agent_driver: 'claude_code',
      slug: 'demo-repo',
      objective: 'Summarize repository architecture',
    });
    expect(agentDispatchRes.isError).toBeUndefined();
    expect(agentDispatchRes.content[0].text).toContain('driver=claude_code');
    expect(agentRunSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        workspaceSlug: 'demo-repo',
        mode: 'readonly',
        driver: 'claude_code',
        objective: 'Summarize repository architecture',
      }),
    );

    // 10. Public GET / Gateway Portal (HTML & JSON content negotiation, zero private data leakage)
    const landingHtmlRes = await gateway.app.request('https://mcp.example.com/', {
      headers: { accept: 'text/html' },
    });
    expect(landingHtmlRes.status).toBe(200);
    expect(landingHtmlRes.headers.get('content-security-policy')).toContain("script-src 'sha256-");
    const landingHtml = await landingHtmlRes.text();
    expect(landingHtml).toContain('GeminiBastionMCP');
    expect(landingHtml).toContain('v0.2.0');
    expect(landingHtml).toContain('Claude.ai');
    expect(landingHtml).toContain('ChatGPT');
    expect(landingHtml).toContain('bwrap');
    expect(landingHtml).toContain('https://mcp.example.com/mcp');
    expect(landingHtml).toContain('publish_changes');
    expect(landingHtml).not.toContain('onclick=');
    expect(landingHtml).not.toContain('demo-repo');
    expect(landingHtml).not.toContain(dcrBody.client_id);
    expect(landingHtml).not.toContain('ghp_');

    const landingJsonRes = await gateway.app.request('https://mcp.example.com/', {
      headers: { accept: 'application/json' },
    });
    expect(landingJsonRes.status).toBe(200);
    const landingJson = (await landingJsonRes.json()) as Record<string, unknown>;
    expect(landingJson).toMatchObject({
      service: 'gemini-bastion-mcp',
      brand: 'GeminiBastionMCP',
      version: '0.2.0',
      status: 'online',
      dbReady: true,
      mcpEndpoint: 'https://mcp.example.com/mcp',
      oauthMetadata: 'https://mcp.example.com/.well-known/oauth-authorization-server',
      protectedResourceMetadata: 'https://mcp.example.com/.well-known/oauth-protected-resource',
      adminUrl: '/admin',
      toolsCount: 10,
    });
    expect(JSON.stringify(landingJson)).not.toContain('demo-repo');
    expect(JSON.stringify(landingJson)).not.toContain(dcrBody.client_id);

    // 11. OAuth scope enforcement: mcp:read token allows read tools and blocks write tools (insufficient_scope)
    const roVerifier = crypto.randomBytes(32).toString('base64url');
    const roChallenge = computeS256Challenge(roVerifier);
    const roAuthUrl = new URL('https://mcp.example.com/oauth/authorize');
    roAuthUrl.searchParams.set('response_type', 'code');
    roAuthUrl.searchParams.set('client_id', dcrBody.client_id);
    roAuthUrl.searchParams.set('redirect_uri', 'https://gemini.google.com/oauth/callback');
    roAuthUrl.searchParams.set('code_challenge', roChallenge);
    roAuthUrl.searchParams.set('code_challenge_method', 'S256');
    roAuthUrl.searchParams.set('scope', 'mcp:read');
    roAuthUrl.searchParams.set('resource', resource);

    const roGet = await gateway.app.request(roAuthUrl.toString());
    const roHtml = await roGet.text();
    const roPost = await gateway.app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        auth_req_id: extractHiddenInput(roHtml, 'auth_req_id'),
        csrf_token: extractHiddenInput(roHtml, 'csrf_token'),
        password: adminPassword,
        decision: 'approve',
      }).toString(),
    });
    const roCode = new URL(roPost.headers.get('location')!).searchParams.get('code')!;
    const roTokRes = await gateway.app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: roCode,
        redirect_uri: 'https://gemini.google.com/oauth/callback',
        client_id: dcrBody.client_id,
        code_verifier: roVerifier,
        resource,
      }).toString(),
    });
    const roToken = ((await roTokRes.json()) as { access_token: string }).access_token;

    const roReadOk = await callMcpTool(gateway, roToken, 'workspace_manage', { action: 'list' }, 201);
    expect(roReadOk.isError).toBeUndefined();

    const roWriteBlocked = await callMcpTool(
      gateway,
      roToken,
      'code_patch',
      {
        action: 'create_or_overwrite',
        slug: 'demo-repo',
        files: [{ path: 'src/x.ts', content: 'export const x = 1;\n' }],
      },
      202,
    );
    expect(roWriteBlocked.isError).toBe(true);
    expect(roWriteBlocked.content[0].text).toContain('insufficient_scope');

    const roCancelBlocked = await callMcpTool(
      gateway,
      roToken,
      'job_status',
      { job_id: jobMatch![1], cancel: true },
      203,
    );
    expect(roCancelBlocked.isError).toBe(true);
    expect(roCancelBlocked.content[0].text).toContain('insufficient_scope');
  });
});
