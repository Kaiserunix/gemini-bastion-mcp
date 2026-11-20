import crypto from 'node:crypto';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAdminApp } from '../src/admin/index.js';
import {
  computeS256Challenge,
  createAuthApp,
  createBearerMiddleware,
  ensureStaticClient,
  hashPasswordScrypt,
  hashToken,
  verifyPassword,
} from '../src/auth/index.js';
import { loadConfig } from '../src/config.js';
import { createRepositories, type Repositories } from '../src/db/repositories/index.js';
import { openDatabase, type GatewayDatabase } from '../src/db/sqlite.js';
import type { GatewayConfig } from '../src/types.js';

function createPkcePair(): { verifier: string; challenge: string } {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = computeS256Challenge(verifier);
  return { verifier, challenge };
}

function extractHiddenInput(html: string, name: string): string {
  const regex = new RegExp(`name="${name}"\\s+value="([^"]+)"`, 'i');
  const match = regex.exec(html);
  if (!match || !match[1]) {
    throw new Error(`Could not extract hidden input "${name}" from HTML`);
  }
  return match[1];
}

function extractCookieValue(setCookieHeaders: string[], name: string): string | undefined {
  for (const header of setCookieHeaders) {
    const firstPart = header.split(';')[0] ?? '';
    const eqIdx = firstPart.indexOf('=');
    if (eqIdx > 0 && firstPart.slice(0, eqIdx).trim() === name) {
      return firstPart.slice(eqIdx + 1).trim();
    }
  }
  return undefined;
}

function makeTestConfig(overrides: Record<string, string | undefined> = {}): GatewayConfig {
  const passwordHash = hashPasswordScrypt('super-secret-operator-pw');
  return loadConfig({
    NODE_ENV: 'test',
    PUBLIC_DOMAIN: 'https://mcp.example.com',
    TRUST_CF_CONNECTING_IP: 'true',
    DATA_DIR: '/tmp/omni-test-data',
    WORKSPACES_DIR: '/tmp/omni-test-workspaces',
    ADMIN_PASSWORD_HASH: passwordHash,
    OAUTH_SIGNING_SECRET: 'test-signing-secret-at-least-32-bytes-long-123456',
    OAUTH_ACCESS_TOKEN_TTL_SEC: '3600',
    OAUTH_REFRESH_TOKEN_TTL_SEC: '2592000',
    OAUTH_REFRESH_GRACE_SEC: '60',
    ...overrides,
  });
}

describe('OAuth 2.1 Gemini Compatibility & Admin PWA', () => {
  let db: GatewayDatabase;
  let repos: Repositories;
  let config: GatewayConfig;
  let app: Hono;
  let cancelJobMock: ReturnType<typeof vi.fn<(jobId: string) => Promise<boolean>>>;
  let rollbackMock: ReturnType<typeof vi.fn<(slug: string, checkpointId: string) => Promise<void>>>;

  beforeEach(() => {
    db = openDatabase(':memory:');
    repos = createRepositories(db);
    config = makeTestConfig();
    cancelJobMock = vi.fn(async () => true);
    rollbackMock = vi.fn(async () => undefined);

    app = new Hono();
    app.route('/', createAuthApp({ config, db, repos, rateLimitMaxAttempts: 5, rateLimitWindowMs: 60_000 }));
    app.route(
      '/admin',
      createAdminApp({
        config,
        repos,
        cancelJob: cancelJobMock,
        rollbackCheckpoint: rollbackMock,
        rateLimitMaxAttempts: 5,
        rateLimitWindowMs: 60_000,
        ssePollIntervalMs: 50,
      }),
    );
    app.use('/mcp', createBearerMiddleware({ config, repos }));
    app.all('/mcp', (c) => c.json({ ok: true, auth: c.get('oauthAuth') }));
  });

  afterEach(() => {
    vi.useRealTimers();
    db.close();
  });

  it('returns 401 with exact RFC 9728 WWW-Authenticate header on unauthenticated /mcp', async () => {
    const res = await app.request('https://mcp.example.com/mcp', { method: 'POST' });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe(
      'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"',
    );
  });

  it('serves RFC 9728 protected-resource and RFC 8414 authorization-server discovery endpoints', async () => {
    const prRes = await app.request('https://mcp.example.com/.well-known/oauth-protected-resource');
    expect(prRes.status).toBe(200);
    const prJson = (await prRes.json()) as Record<string, unknown>;
    expect(prJson).toMatchObject({
      resource: 'https://mcp.example.com/mcp',
      authorization_servers: ['https://mcp.example.com'],
      bearer_methods_supported: ['header'],
    });

    const prMcpRes = await app.request(
      'https://mcp.example.com/.well-known/oauth-protected-resource/mcp',
    );
    expect(prMcpRes.status).toBe(200);
    expect(await prMcpRes.json()).toEqual(prJson);

    const asRes = await app.request(
      'https://mcp.example.com/.well-known/oauth-authorization-server',
    );
    expect(asRes.status).toBe(200);
    const asJson = (await asRes.json()) as Record<string, unknown>;
    expect(asJson).toMatchObject({
      issuer: 'https://mcp.example.com',
      authorization_endpoint: 'https://mcp.example.com/oauth/authorize',
      token_endpoint: 'https://mcp.example.com/oauth/token',
      revocation_endpoint: 'https://mcp.example.com/oauth/revoke',
      registration_endpoint: 'https://mcp.example.com/oauth/register',
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
      code_challenge_methods_supported: ['S256'],
    });
  });

  it('supports DCR with 6 Google redirect URIs, up to 16 URIs, vertexaisearch, and rejects 17 or evil URIs', async () => {
    const gemini6Uris = [
      'https://oauth-redirect.googleusercontent.com/r/gemini-prod-1',
      'https://oauth-redirect.googleusercontent.com/a/gemini-prod-2',
      'https://oauth-redirect-sandbox.googleusercontent.com/r/sandbox',
      'https://oauth-redirect-test.googleusercontent.com/a/test',
      'https://vertexaisearch.cloud.google.com/oauth-redirect',
      'http://localhost:8080/callback',
    ];

    const reg6 = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Gemini Connected App',
        redirect_uris: gemini6Uris,
        token_endpoint_auth_method: 'none',
      }),
    });
    expect(reg6.status).toBe(201);
    const reg6Body = (await reg6.json()) as Record<string, unknown>;
    expect(reg6Body.redirect_uris).toEqual(gemini6Uris);
    expect(reg6Body.token_endpoint_auth_method).toBe('none');
    expect(reg6Body.client_secret).toBeUndefined();

    const sixteenUris = Array.from(
      { length: 16 },
      (_, i) => `https://oauth-redirect.googleusercontent.com/r/app-${i}`,
    );
    const reg16 = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: sixteenUris }),
    });
    expect(reg16.status).toBe(201);

    const seventeenUris = [
      ...sixteenUris,
      'https://oauth-redirect.googleusercontent.com/r/app-16',
    ];
    const reg17 = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: seventeenUris }),
    });
    expect(reg17.status).toBe(400);

    const evilReg = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://evil.example.com/steal-code'],
      }),
    });
    expect(evilReg.status).toBe(400);

    const badGooglePathReg = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://oauth-redirect.googleusercontent.com/other/path'],
      }),
    });
    expect(badGooglePathReg.status).toBe(400);

    const loopbackIpReg = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['http://127.0.0.1:43210/oauth/cb'],
      }),
    });
    expect(loopbackIpReg.status).toBe(201);
  });

  it('completes full PKCE S256 flow preserving 2600-char state across wrong-password retry', async () => {
    const redirectUri = 'https://oauth-redirect.googleusercontent.com/r/gemini-app';
    const dcrRes = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Gemini',
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: 'none',
      }),
    });
    const { client_id: clientId } = (await dcrRes.json()) as { client_id: string };

    const { verifier, challenge } = createPkcePair();
    const rawState = 'st_' + 'AbCd0123+/=?&_'.repeat(185) + '_END';
    expect(rawState.length).toBeGreaterThanOrEqual(2590);

    const authUrl = new URL('https://mcp.example.com/oauth/authorize');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('resource', 'https://mcp.example.com/mcp');
    authUrl.searchParams.set('state', rawState);

    const getAuth = await app.request(authUrl.toString());
    expect(getAuth.status).toBe(200);
    const csp = getAuth.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('form-action');
    const html1 = await getAuth.text();
    const authReqId = extractHiddenInput(html1, 'auth_req_id');
    const csrf1 = extractHiddenInput(html1, 'csrf_token');

    // Retry 1: wrong password -> 401 re-render, preserving auth_req_id & 2600-char state in DB
    const badPost = await app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CF-Connecting-IP': '203.0.113.10',
      },
      body: new URLSearchParams({
        auth_req_id: authReqId,
        csrf_token: csrf1,
        password: 'wrong-password',
        decision: 'approve',
      }).toString(),
    });
    expect(badPost.status).toBe(401);
    const html2 = await badPost.text();
    const authReqId2 = extractHiddenInput(html2, 'auth_req_id');
    const csrf2 = extractHiddenInput(html2, 'csrf_token');
    expect(authReqId2).toBe(authReqId);

    // Retry 2: valid password -> 302 redirect preserving exact 2600-char state byte-for-byte
    const goodPost = await app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CF-Connecting-IP': '203.0.113.10',
      },
      body: new URLSearchParams({
        auth_req_id: authReqId2,
        csrf_token: csrf2,
        password: 'super-secret-operator-pw',
        decision: 'approve',
      }).toString(),
    });
    expect(goodPost.status).toBe(302);
    const location = goodPost.headers.get('location');
    expect(location).toBeTruthy();

    const callbackUrl = new URL(location!);
    expect(callbackUrl.origin + callbackUrl.pathname).toBe(redirectUri);
    expect(callbackUrl.searchParams.get('state')).toBe(rawState);
    const code = callbackUrl.searchParams.get('code');
    expect(code).toBeTruthy();

    // Exchange code via form-urlencoded without Basic auth
    const tokenRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
        resource: 'https://mcp.example.com/mcp',
      }).toString(),
    });
    expect(tokenRes.status).toBe(200);
    const tokenBody = (await tokenRes.json()) as {
      access_token: string;
      refresh_token: string;
      token_type: string;
    };
    expect(tokenBody.token_type).toBe('Bearer');
    expect(tokenBody.access_token).toBeTruthy();
    expect(tokenBody.refresh_token).toBeTruthy();

    // Single-use code replay rejected
    const replayCodeRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: code!,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      }).toString(),
    });
    expect(replayCodeRes.status).toBe(400);

    // Access /mcp with issued Bearer token
    const mcpRes = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tokenBody.access_token}` },
    });
    expect(mcpRes.status).toBe(200);
    const mcpJson = (await mcpRes.json()) as { ok: boolean; auth: { clientId: string } };
    expect(mcpJson.ok).toBe(true);
    expect(mcpJson.auth.clientId).toBe(clientId);
  });

  it('enforces RFC 8707 resource indicators across /authorize, /token, and /mcp middleware', async () => {
    const redirectUri = 'https://oauth-redirect.googleusercontent.com/r/res-check';
    const dcrRes = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [redirectUri] }),
    });
    const { client_id: clientId } = (await dcrRes.json()) as { client_id: string };
    const { verifier, challenge } = createPkcePair();

    // Mismatched resource on /authorize redirects with error=invalid_target
    const badAuthUrl = new URL('https://mcp.example.com/oauth/authorize');
    badAuthUrl.searchParams.set('response_type', 'code');
    badAuthUrl.searchParams.set('client_id', clientId);
    badAuthUrl.searchParams.set('redirect_uri', redirectUri);
    badAuthUrl.searchParams.set('code_challenge', challenge);
    badAuthUrl.searchParams.set('code_challenge_method', 'S256');
    badAuthUrl.searchParams.set('resource', 'https://other-server.example.com/mcp');
    badAuthUrl.searchParams.set('state', 's1');

    const badAuthRes = await app.request(badAuthUrl.toString());
    expect(badAuthRes.status).toBe(302);
    const errRedirect = new URL(badAuthRes.headers.get('location')!);
    expect(errRedirect.searchParams.get('error')).toBe('invalid_target');
    expect(errRedirect.searchParams.get('state')).toBe('s1');

    // Valid resource on /authorize -> mismatched resource on /token fails
    const goodAuthUrl = new URL('https://mcp.example.com/oauth/authorize');
    goodAuthUrl.searchParams.set('response_type', 'code');
    goodAuthUrl.searchParams.set('client_id', clientId);
    goodAuthUrl.searchParams.set('redirect_uri', redirectUri);
    goodAuthUrl.searchParams.set('code_challenge', challenge);
    goodAuthUrl.searchParams.set('code_challenge_method', 'S256');
    goodAuthUrl.searchParams.set('resource', 'https://mcp.example.com/mcp');

    const getRes = await app.request(goodAuthUrl.toString());
    const html = await getRes.text();
    const postRes = await app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        auth_req_id: extractHiddenInput(html, 'auth_req_id'),
        csrf_token: extractHiddenInput(html, 'csrf_token'),
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    const code = new URL(postRes.headers.get('location')!).searchParams.get('code')!;

    const mismatchedTokenRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
        resource: 'https://mcp.example.com',
      }).toString(),
    });
    expect(mismatchedTokenRes.status).toBe(400);
    expect(((await mismatchedTokenRes.json()) as { error: string }).error).toBe('invalid_target');

    // Token stored with foreign resource audience is rejected by /mcp middleware
    const foreignToken = 'foreign_audience_token_123456';
    repos.oauth.createToken({
      token_hash: hashToken(foreignToken),
      token_type: 'access',
      client_id: clientId,
      scope: 'mcp:tools',
      resource: 'https://foreign.example.com/mcp',
      token_family_id: 'fam_foreign',
      expires_at: Date.now() + 60_000,
      grace_expires_at: null,
    });
    const mcpReject = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { Authorization: `Bearer ${foreignToken}` },
    });
    expect(mcpReject.status).toBe(401);
    expect(mcpReject.headers.get('www-authenticate')).toBe(
      'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"',
    );
  });

  it('supports client_secret_post DCR clients and static fallback client', async () => {
    // 1. client_secret_post via DCR
    const redirectUri = 'https://vertexaisearch.cloud.google.com/oauth-redirect';
    const dcrRes = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Confidential Vertex Client',
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: 'client_secret_post',
      }),
    });
    expect(dcrRes.status).toBe(201);
    const dcrBody = (await dcrRes.json()) as {
      client_id: string;
      client_secret: string;
      token_endpoint_auth_method: string;
    };
    expect(dcrBody.token_endpoint_auth_method).toBe('client_secret_post');
    expect(dcrBody.client_secret).toBeTruthy();

    const { verifier, challenge } = createPkcePair();
    const authUrl = new URL('https://mcp.example.com/oauth/authorize');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', dcrBody.client_id);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const getAuth = await app.request(authUrl.toString());
    const html = await getAuth.text();
    const postAuth = await app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        auth_req_id: extractHiddenInput(html, 'auth_req_id'),
        csrf_token: extractHiddenInput(html, 'csrf_token'),
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    const code = new URL(postAuth.headers.get('location')!).searchParams.get('code')!;

    // Missing client_secret -> 401 invalid_client
    const missingSecretRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: dcrBody.client_id,
        code_verifier: verifier,
      }).toString(),
    });
    expect(missingSecretRes.status).toBe(401);

    // Valid client_secret_post -> 200
    const okTokenRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: dcrBody.client_id,
        client_secret: dcrBody.client_secret,
        code_verifier: verifier,
      }).toString(),
    });
    expect(okTokenRes.status).toBe(200);

    // 2. Static fallback client
    const staticCfg = makeTestConfig({
      OAUTH_STATIC_CLIENT_ID: 'gemini-static-id',
      OAUTH_STATIC_CLIENT_SECRET: 'gemini-static-secret',
    });
    const staticClient = ensureStaticClient(staticCfg, repos.oauth);
    expect(staticClient).not.toBeNull();
    expect(staticClient!.is_static).toBe(true);

    const staticApp = createAuthApp({ config: staticCfg, db, repos });
    const staticRedirect = 'https://oauth-redirect.googleusercontent.com/r/static-connector';
    const staticPkce = createPkcePair();
    const sUrl = new URL('https://mcp.example.com/oauth/authorize');
    sUrl.searchParams.set('response_type', 'code');
    sUrl.searchParams.set('client_id', 'gemini-static-id');
    sUrl.searchParams.set('redirect_uri', staticRedirect);
    sUrl.searchParams.set('code_challenge', staticPkce.challenge);
    sUrl.searchParams.set('code_challenge_method', 'S256');

    const sGet = await staticApp.request(sUrl.toString());
    expect(sGet.status).toBe(200);
    const sHtml = await sGet.text();
    const sPost = await staticApp.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        auth_req_id: extractHiddenInput(sHtml, 'auth_req_id'),
        csrf_token: extractHiddenInput(sHtml, 'csrf_token'),
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    expect(sPost.status).toBe(302);
    const sCode = new URL(sPost.headers.get('location')!).searchParams.get('code')!;

    const sTokRes = await staticApp.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: sCode,
        redirect_uri: staticRedirect,
        client_id: 'gemini-static-id',
        client_secret: 'gemini-static-secret',
        code_verifier: staticPkce.verifier,
      }).toString(),
    });
    expect(sTokRes.status).toBe(200);
  });

  it('rotates refresh tokens with 60s concurrent grace leeway and revokes family on replay outside grace', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

    const redirectUri = 'https://oauth-redirect.googleusercontent.com/r/grace-test';
    const reg = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [redirectUri] }),
    });
    const { client_id: clientId } = (await reg.json()) as { client_id: string };
    const { verifier, challenge } = createPkcePair();

    const authUrl = new URL('https://mcp.example.com/oauth/authorize');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const getAuth = await app.request(authUrl.toString());
    const html = await getAuth.text();
    const postAuth = await app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        auth_req_id: extractHiddenInput(html, 'auth_req_id'),
        csrf_token: extractHiddenInput(html, 'csrf_token'),
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    const code = new URL(postAuth.headers.get('location')!).searchParams.get('code')!;

    const tok1Res = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      }).toString(),
    });
    const tok1 = (await tok1Res.json()) as { access_token: string; refresh_token: string };

    // Initial refresh at t=0 -> rotates and opens 60s grace window on tok1.refresh_token
    const refresh1Res = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tok1.refresh_token,
        client_id: clientId,
      }).toString(),
    });
    expect(refresh1Res.status).toBe(200);
    const tok2 = (await refresh1Res.json()) as { access_token: string; refresh_token: string };
    expect(tok2.refresh_token).not.toBe(tok1.refresh_token);

    // Concurrent retry of tok1.refresh_token at t=+15s (inside 60s grace) -> succeeds!
    vi.advanceTimersByTime(15_000);
    const concurrentRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tok1.refresh_token,
        client_id: clientId,
      }).toString(),
    });
    expect(concurrentRes.status).toBe(200);
    const tok3 = (await concurrentRes.json()) as { access_token: string; refresh_token: string };

    // Replay of tok1.refresh_token at t=+61s (outside 60s grace) -> 400 + revokes ENTIRE family!
    vi.advanceTimersByTime(46_000);
    const replayRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tok1.refresh_token,
        client_id: clientId,
      }).toString(),
    });
    expect(replayRes.status).toBe(400);
    expect(((await replayRes.json()) as { error: string }).error).toBe('invalid_grant');

    // Verify tok2.refresh_token, tok3.refresh_token, and tok3.access_token are all revoked
    const tok2After = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tok2.refresh_token,
        client_id: clientId,
      }).toString(),
    });
    expect(tok2After.status).toBe(400);

    const mcpAfter = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tok3.access_token}` },
    });
    expect(mcpAfter.status).toBe(401);
  });

  it('supports /oauth/revoke and per-IP rate limiting respecting CF-Connecting-IP', async () => {
    const redirectUri = 'https://oauth-redirect.googleusercontent.com/r/revoke-rl';
    const reg = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [redirectUri] }),
    });
    const { client_id: clientId } = (await reg.json()) as { client_id: string };
    const { verifier, challenge } = createPkcePair();

    const authUrl = new URL('https://mcp.example.com/oauth/authorize');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    const getAuth = await app.request(authUrl.toString());
    const html = await getAuth.text();
    const authReqId = extractHiddenInput(html, 'auth_req_id');
    const csrf = extractHiddenInput(html, 'csrf_token');

    // Exhaust rate limit (5 attempts) for IP 198.51.100.1
    for (let i = 0; i < 5; i++) {
      const r = await app.request('https://mcp.example.com/oauth/authorize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'CF-Connecting-IP': '198.51.100.1',
        },
        body: new URLSearchParams({
          auth_req_id: authReqId,
          csrf_token: csrf,
          password: 'wrong',
        }).toString(),
      });
      expect(r.status).toBe(401);
    }

    const blocked = await app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CF-Connecting-IP': '198.51.100.1',
      },
      body: new URLSearchParams({
        auth_req_id: authReqId,
        csrf_token: csrf,
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    expect(blocked.status).toBe(429);

    // Different CF-Connecting-IP is NOT locked out!
    const otherUser = await app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CF-Connecting-IP': '198.51.100.2',
      },
      body: new URLSearchParams({
        auth_req_id: authReqId,
        csrf_token: csrf,
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    expect(otherUser.status).toBe(302);
    const code = new URL(otherUser.headers.get('location')!).searchParams.get('code')!;

    const tokRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      }).toString(),
    });
    const tok = (await tokRes.json()) as { access_token: string; refresh_token: string };

    // Verify CF-Connecting-IP is ignored when trustCfConnectingIp is false
    const untrustedCfg = makeTestConfig({ TRUST_CF_CONNECTING_IP: 'false' });
    const untrustedApp = createAuthApp({
      config: untrustedCfg,
      db,
      repos,
      rateLimitMaxAttempts: 2,
      rateLimitWindowMs: 60_000,
    });
    const uGet = await untrustedApp.request(authUrl.toString());
    const uHtml = await uGet.text();
    const uReqId = extractHiddenInput(uHtml, 'auth_req_id');
    const uCsrf = extractHiddenInput(uHtml, 'csrf_token');
    for (let i = 0; i < 2; i++) {
      await untrustedApp.request('https://mcp.example.com/oauth/authorize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'CF-Connecting-IP': `10.0.0.${i + 1}`,
        },
        body: new URLSearchParams({
          auth_req_id: uReqId,
          csrf_token: uCsrf,
          password: 'wrong',
        }).toString(),
      });
    }
    const untrustedBlocked = await untrustedApp.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CF-Connecting-IP': '10.0.0.99',
      },
      body: new URLSearchParams({
        auth_req_id: uReqId,
        csrf_token: uCsrf,
        password: 'wrong',
      }).toString(),
    });
    expect(untrustedBlocked.status).toBe(429);

    const revokeRes = await app.request('https://mcp.example.com/oauth/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: tok.refresh_token,
        client_id: clientId,
      }).toString(),
    });
    expect(revokeRes.status).toBe(200);

    const mcpDenied = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { Authorization: `Bearer ${tok.access_token}` },
    });
    expect(mcpDenied.status).toBe(401);
  });

  it('verifies scrypt$, scrypt:, sha256$, sha256:, and plain$ password formats appropriately', () => {
    const scrypt = hashPasswordScrypt('pw-scrypt');
    expect(verifyPassword('pw-scrypt', scrypt, 'production')).toBe(true);
    expect(verifyPassword('wrong', scrypt, 'production')).toBe(false);

    const scryptColon = hashPasswordScrypt('pw-scrypt-colon', undefined, ':');
    expect(scryptColon.startsWith('scrypt:')).toBe(true);
    expect(verifyPassword('pw-scrypt-colon', scryptColon, 'production')).toBe(true);
    expect(verifyPassword('wrong', scryptColon, 'production')).toBe(false);

    const shaHex = crypto.createHash('sha256').update('pw-sha', 'utf8').digest('hex');
    const sha = `sha256$${shaHex}`;
    expect(verifyPassword('pw-sha', sha, 'production')).toBe(true);
    expect(verifyPassword('wrong', sha, 'production')).toBe(false);

    const shaColon = `sha256:${shaHex}`;
    expect(verifyPassword('pw-sha', shaColon, 'production')).toBe(true);
    expect(verifyPassword('wrong', shaColon, 'production')).toBe(false);

    expect(verifyPassword('pw-plain', 'plain$pw-plain', 'development')).toBe(true);
    expect(verifyPassword('pw-plain', 'pw-plain', 'test')).toBe(true);
    expect(verifyPassword('argon2:fake', 'argon2:fake', 'development')).toBe(false);
    expect(verifyPassword('pw-plain', 'plain$pw-plain', 'production')).toBe(false);
    expect(verifyPassword('pw-plain', 'pw-plain', 'production')).toBe(false);
  });

  it('handles Admin PWA login, manifest, audit API, job/workspace actions, OAuth admin API, and SSE stream', async () => {
    // Unauthenticated checks
    const unauthDash = await app.request('https://mcp.example.com/admin');
    expect(unauthDash.status).toBe(302);
    expect(unauthDash.headers.get('location')).toBe('/admin/login');

    const unauthApi = await app.request('https://mcp.example.com/admin/api/audit');
    expect(unauthApi.status).toBe(401);

    // PWA Manifest
    const manifestRes = await app.request('https://mcp.example.com/admin/manifest.webmanifest');
    expect(manifestRes.status).toBe(200);
    expect(manifestRes.headers.get('content-type')).toContain('application/manifest+json');
    const manifest = (await manifestRes.json()) as {
      name: string;
      short_name: string;
      start_url: string;
      display: string;
    };
    expect(manifest.name).toBe('GeminiBastionMCP');
    expect(manifest.short_name).toBe('GeminiBastion');
    expect(manifest.start_url).toBe('/admin');
    expect(manifest.display).toBe('standalone');

    // Login flow with CSRF
    const loginGet = await app.request('https://mcp.example.com/admin/login');
    expect(loginGet.status).toBe(200);
    const loginHtml = await loginGet.text();
    const loginCsrf = extractHiddenInput(loginHtml, 'csrf_token');
    const loginSetCookies = loginGet.headers.getSetCookie();
    const csrfCookie = extractCookieValue(loginSetCookies, 'gb_admin_csrf');
    expect(csrfCookie).toBe(loginCsrf);

    const loginPost = await app.request('https://mcp.example.com/admin/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie}`,
      },
      body: new URLSearchParams({
        csrf_token: loginCsrf,
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    expect(loginPost.status).toBe(302);
    expect(loginPost.headers.get('location')).toBe('/admin');
    const sessionCookie = extractCookieValue(loginPost.headers.getSetCookie(), 'gb_admin_session');
    expect(sessionCookie).toBeTruthy();

    // Dashboard HTML + extract API CSRF token
    const dashRes = await app.request('https://mcp.example.com/admin', {
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
    });
    expect(dashRes.status).toBe(200);
    const dashHtml = await dashRes.text();
    expect(dashHtml).toContain('GeminiBastionMCP Admin');
    expect(dashHtml).toContain('data-action="copy-mcp"');
    expect(dashHtml).toContain('data-url="https://mcp.example.com/mcp"');
    expect(dashHtml).toContain('kpiActiveJobs');
    expect(dashHtml).toContain('kpiStagedPlans');
    expect(dashHtml).toContain('kpiWorkspaces');
    expect(dashHtml).toContain('kpiOauthSessions');
    expect(dashHtml).toContain('window.confirm');
    expect(dashHtml).toContain('toggle-log');
    expect(dashHtml).not.toContain('onclick=');
    const metaMatch = /meta name="csrf-token" content="([^"]+)"/.exec(dashHtml);
    expect(metaMatch?.[1]).toBeTruthy();
    const apiCsrf = metaMatch![1]!;

    // Seed workspace, checkpoint, job, mutation plan, and OAuth token
    repos.workspaces.upsertWorkspace({
      slug: 'demo-repo',
      repo_url: 'https://github.com/acme/demo',
      default_branch: 'main',
      detected_stack: {
        languages: ['typescript'],
        packageManagers: ['npm'],
        frameworks: ['hono'],
        testCommands: ['npm test'],
        lintCommands: [],
        buildCommands: ['npm run build'],
        typecheckCommands: ['npm run typecheck'],
      },
    });
    repos.workspaces.createCheckpoint({
      checkpoint_id: 'cp-1',
      workspace_slug: 'demo-repo',
      git_commit_sha: 'abc1234',
      git_ref: 'refs/omni-checkpoints/cp-1',
      reason: 'pre-patch',
    });
    repos.jobs.createJob({
      job_id: 'job-1',
      workspace_slug: 'demo-repo',
      runner_type: 'shell_task',
      status: 'running',
      command_or_objective: 'npm test',
    });
    repos.plans.createPlan({
      plan_id: 'plan-1',
      target_service: 'cloudflare',
      summary_diff_text: '+ DNS A record test.example.com -> 1.2.3.4',
      payload: { action: 'create_dns' },
      expires_at: Date.now() + 60_000,
    });

    // KPI Summary API
    const summaryRes = await app.request('https://mcp.example.com/admin/api/summary', {
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
    });
    expect(summaryRes.status).toBe(200);
    const summaryData = (await summaryRes.json()) as {
      activeJobs: number;
      stagedPlans: number;
      workspaces: number;
      oauthSessions: number;
    };
    expect(summaryData.activeJobs).toBe(1);
    expect(summaryData.stagedPlans).toBe(1);
    expect(summaryData.workspaces).toBe(1);

    // Audit API
    const auditRes = await app.request('https://mcp.example.com/admin/api/audit', {
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
    });
    expect(auditRes.status).toBe(200);
    const auditData = (await auditRes.json()) as { logs: Array<{ action: string }> };
    expect(auditData.logs.some((l) => l.action === 'admin_login')).toBe(true);

    // Plans API
    const plansRes = await app.request('https://mcp.example.com/admin/api/plans', {
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
    });
    expect(plansRes.status).toBe(200);
    expect(((await plansRes.json()) as { plans: Array<{ plan_id: string }> }).plans[0]?.plan_id).toBe(
      'plan-1',
    );

    // Job Cancel callback (requires CSRF header)
    const cancelNoCsrf = await app.request('https://mcp.example.com/admin/api/jobs/job-1/cancel', {
      method: 'POST',
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
    });
    expect(cancelNoCsrf.status).toBe(403);

    const cancelOk = await app.request('https://mcp.example.com/admin/api/jobs/job-1/cancel', {
      method: 'POST',
      headers: {
        Cookie: `gb_admin_session=${sessionCookie}`,
        'X-CSRF-Token': apiCsrf,
      },
    });
    expect(cancelOk.status).toBe(200);
    expect(cancelJobMock).toHaveBeenCalledWith('job-1');

    // Workspace Rollback callback
    const rollbackRes = await app.request(
      'https://mcp.example.com/admin/api/workspaces/demo-repo/rollback',
      {
        method: 'POST',
        headers: {
          Cookie: `gb_admin_session=${sessionCookie}`,
          'X-CSRF-Token': apiCsrf,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ checkpoint_id: 'cp-1' }),
      },
    );
    expect(rollbackRes.status).toBe(200);
    expect(rollbackMock).toHaveBeenCalledWith('demo-repo', 'cp-1');

    // OAuth Admin API: list clients & active tokens, revoke token, delete client
    const dcrAdminReg = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Admin Test Client',
        redirect_uris: ['http://localhost:9000/cb'],
      }),
    });
    const { client_id: adminTestClientId } = (await dcrAdminReg.json()) as { client_id: string };
    const seededAccessToken = 'admin_seeded_access_token_123456';
    const seededTokenHash = hashToken(seededAccessToken);
    repos.oauth.createToken({
      token_hash: seededTokenHash,
      token_type: 'access',
      client_id: adminTestClientId,
      scope: 'mcp:tools',
      resource: 'https://mcp.example.com/mcp',
      token_family_id: 'fam_admin_test',
      expires_at: Date.now() + 60_000,
      grace_expires_at: null,
    });

    const oauthListRes = await app.request('https://mcp.example.com/admin/api/oauth', {
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
    });
    expect(oauthListRes.status).toBe(200);
    const oauthListData = (await oauthListRes.json()) as {
      clients: Array<{ client_id: string }>;
      activeTokens: Array<{ token_hash: string }>;
    };
    expect(oauthListData.clients.some((c) => c.client_id === adminTestClientId)).toBe(true);
    expect(oauthListData.activeTokens.some((t) => t.token_hash === seededTokenHash)).toBe(true);

    const adminRevokeRes = await app.request(
      `https://mcp.example.com/admin/api/oauth/tokens/${seededTokenHash}/revoke`,
      {
        method: 'POST',
        headers: {
          Cookie: `gb_admin_session=${sessionCookie}`,
          'X-CSRF-Token': apiCsrf,
        },
      },
    );
    expect(adminRevokeRes.status).toBe(200);
    expect(repos.oauth.getTokenByHash(seededTokenHash)?.revoked).toBe(true);

    const adminDeleteClientRes = await app.request(
      `https://mcp.example.com/admin/api/oauth/clients/${adminTestClientId}`,
      {
        method: 'DELETE',
        headers: {
          Cookie: `gb_admin_session=${sessionCookie}`,
          'X-CSRF-Token': apiCsrf,
        },
      },
    );
    expect(adminDeleteClientRes.status).toBe(200);
    expect(repos.oauth.getClient(adminTestClientId)).toBeNull();

    // SSE live jobs stream
    const ac = new AbortController();
    const sseRes = await app.request('https://mcp.example.com/admin/api/jobs/stream', {
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
      signal: ac.signal,
    });
    expect(sseRes.status).toBe(200);
    expect(sseRes.headers.get('content-type')).toContain('text/event-stream');
    const reader = sseRes.body!.getReader();
    const chunk = await reader.read();
    const text = new TextDecoder().decode(chunk.value);
    expect(text).toContain('event: jobs');
    expect(text).toContain('job-1');
    ac.abort();
    await reader.cancel().catch(() => undefined);
  });

  it('rejects redirect URI bypass vectors (fragment, userinfo, wildcard, encoded traversal) and requires auth for confidential /oauth/revoke', async () => {
    const bypassCandidates = [
      'https://oauth-redirect.googleusercontent.com/r/foo#',
      'https://@oauth-redirect.googleusercontent.com/r/foo',
      'https://user:pass@oauth-redirect.googleusercontent.com/r/foo',
      'https://oauth-redirect.googleusercontent.com/r/*',
      'https://oauth-redirect.googleusercontent.com/r/%2e%2e/evil',
      'https://oauth-redirect.googleusercontent.com/r/..%2fadmin',
      'https://vertexaisearch.cloud.google.com/oauth-redirect/%2e%2e/admin',
      'https://oauth-redirect.googleusercontent.com/r/foo bar',
    ];

    for (const candidate of bypassCandidates) {
      const regRes = await app.request('https://mcp.example.com/oauth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ redirect_uris: [candidate] }),
      });
      expect(regRes.status, `Expected 400 for ${candidate}`).toBe(400);
    }

    // Static client also rejects literal wildcard pattern on /oauth/authorize
    const staticCfg = makeTestConfig({
      OAUTH_STATIC_CLIENT_ID: 'static-client-sec',
      OAUTH_STATIC_CLIENT_SECRET: 'static-secret-sec',
    });
    const staticApp = createAuthApp({ config: staticCfg, db, repos });
    const { challenge } = createPkcePair();
    const wildcardAuth = new URL('https://mcp.example.com/oauth/authorize');
    wildcardAuth.searchParams.set('response_type', 'code');
    wildcardAuth.searchParams.set('client_id', 'static-client-sec');
    wildcardAuth.searchParams.set('redirect_uri', 'https://oauth-redirect.googleusercontent.com/r/*');
    wildcardAuth.searchParams.set('code_challenge', challenge);
    wildcardAuth.searchParams.set('code_challenge_method', 'S256');
    const wildcardRes = await staticApp.request(wildcardAuth.toString());
    expect(wildcardRes.status).toBe(400);

    // Confidential client /oauth/revoke requires client_secret even when client_id is omitted
    const confReg = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        redirect_uris: ['https://oauth-redirect.googleusercontent.com/r/conf-revoke'],
        token_endpoint_auth_method: 'client_secret_post',
      }),
    });
    expect(confReg.status).toBe(201);
    const confBody = (await confReg.json()) as { client_id: string; client_secret: string };
    const confToken = 'confidential_client_token_123456';
    const confHash = hashToken(confToken);
    repos.oauth.createToken({
      token_hash: confHash,
      token_type: 'access',
      client_id: confBody.client_id,
      scope: 'mcp:tools',
      resource: 'https://mcp.example.com/mcp',
      token_family_id: 'fam_conf_revoke',
      expires_at: Date.now() + 60_000,
      grace_expires_at: null,
    });

    // Revoke WITHOUT client_id or client_secret -> 401 and token stays active
    const unauthRevoke = await app.request('https://mcp.example.com/oauth/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: confToken }).toString(),
    });
    expect(unauthRevoke.status).toBe(401);
    expect(repos.oauth.getTokenByHash(confHash)?.revoked).toBe(false);

    // Revoke WITH valid client_secret -> 200 and token revoked
    const authRevoke = await app.request('https://mcp.example.com/oauth/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        token: confToken,
        client_id: confBody.client_id,
        client_secret: confBody.client_secret,
      }).toString(),
    });
    expect(authRevoke.status).toBe(200);
    expect(repos.oauth.getTokenByHash(confHash)?.revoked).toBe(true);

    // Admin dashboard HTML uses delegated click handler with zero inline onclick= handlers
    const loginGet = await app.request('https://mcp.example.com/admin/login');
    const loginCsrf = extractHiddenInput(await loginGet.text(), 'csrf_token');
    const csrfCookie = extractCookieValue(loginGet.headers.getSetCookie(), 'gb_admin_csrf');
    const loginPost = await app.request('https://mcp.example.com/admin/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie}`,
      },
      body: new URLSearchParams({
        csrf_token: loginCsrf,
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    const sessionCookie = extractCookieValue(loginPost.headers.getSetCookie(), 'gb_admin_session');
    const dashHtml = await (
      await app.request('https://mcp.example.com/admin', {
        headers: { Cookie: `gb_admin_session=${sessionCookie}` },
      })
    ).text();
    expect(dashHtml).not.toContain('onclick=');
    expect(dashHtml).toContain('data-action');
  });

  it('enforces scope validation (invalid_scope), 413 body limits, stale static client retirement, expired-ancestor replay family revocation, default resource binding, and SQL KPI/SSE session expiry', async () => {
    // 1. Scope validation on /oauth/authorize
    const redirectUri = 'https://oauth-redirect.googleusercontent.com/r/stage-b';
    const reg = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [redirectUri] }),
    });
    const { client_id: clientId } = (await reg.json()) as { client_id: string };
    const { verifier, challenge } = createPkcePair();

    const badScopeUrl = new URL('https://mcp.example.com/oauth/authorize');
    badScopeUrl.searchParams.set('response_type', 'code');
    badScopeUrl.searchParams.set('client_id', clientId);
    badScopeUrl.searchParams.set('redirect_uri', redirectUri);
    badScopeUrl.searchParams.set('code_challenge', challenge);
    badScopeUrl.searchParams.set('code_challenge_method', 'S256');
    badScopeUrl.searchParams.set('scope', 'mcp:read admin:superuser');
    badScopeUrl.searchParams.set('state', 'scope_s1');

    const badScopeRes = await app.request(badScopeUrl.toString());
    expect(badScopeRes.status).toBe(302);
    const badScopeLoc = new URL(badScopeRes.headers.get('location')!);
    expect(badScopeLoc.searchParams.get('error')).toBe('invalid_scope');
    expect(badScopeLoc.searchParams.get('state')).toBe('scope_s1');

    // 2. 413 body limit (> 64KB) across auth & admin POST endpoints
    const oversized = 'x'.repeat(70_000);
    for (const url of [
      'https://mcp.example.com/oauth/register',
      'https://mcp.example.com/oauth/authorize',
      'https://mcp.example.com/oauth/token',
      'https://mcp.example.com/oauth/revoke',
      'https://mcp.example.com/admin/login',
    ]) {
      const r413 = await app.request(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `data=${oversized}`,
      });
      expect(r413.status, `Expected 413 for ${url}`).toBe(413);
    }

    // 3. Stale static client retirement
    const staticCfg1 = makeTestConfig({
      OAUTH_STATIC_CLIENT_ID: 'old-static-id',
      OAUTH_STATIC_CLIENT_SECRET: 'old-static-secret',
    });
    ensureStaticClient(staticCfg1, repos.oauth);
    const oldStaticTok = 'old_static_access_token_123456';
    repos.oauth.createToken({
      token_hash: hashToken(oldStaticTok),
      token_type: 'access',
      client_id: 'old-static-id',
      scope: 'mcp:tools',
      resource: 'https://mcp.example.com/mcp',
      token_family_id: 'fam_old_static',
      expires_at: Date.now() + 60_000,
      grace_expires_at: null,
    });
    const staticCfg2 = makeTestConfig({
      OAUTH_STATIC_CLIENT_ID: 'new-static-id',
      OAUTH_STATIC_CLIENT_SECRET: 'new-static-secret',
    });
    ensureStaticClient(staticCfg2, repos.oauth);
    expect(repos.oauth.getClient('old-static-id')).toBeNull();
    expect(repos.oauth.getTokenByHash(hashToken(oldStaticTok))).toBeNull();
    const oldStaticMcp = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { Authorization: `Bearer ${oldStaticTok}` },
    });
    expect(oldStaticMcp.status).toBe(401);
    expect(repos.oauth.getClient('new-static-id')).not.toBeNull();
    // Calling with no static client ID retires new-static-id too
    ensureStaticClient(makeTestConfig(), repos.oauth);
    expect(repos.oauth.getClient('new-static-id')).toBeNull();

    // 4. Default concrete resource binding when resource is omitted + rejecting null-resource token
    const omitResUrl = new URL('https://mcp.example.com/oauth/authorize');
    omitResUrl.searchParams.set('response_type', 'code');
    omitResUrl.searchParams.set('client_id', clientId);
    omitResUrl.searchParams.set('redirect_uri', redirectUri);
    omitResUrl.searchParams.set('code_challenge', challenge);
    omitResUrl.searchParams.set('code_challenge_method', 'S256');
    omitResUrl.searchParams.set('scope', 'mcp:read');

    const getAuth = await app.request(omitResUrl.toString());
    expect(getAuth.status).toBe(200);
    const html = await getAuth.text();
    const postAuth = await app.request('https://mcp.example.com/oauth/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        auth_req_id: extractHiddenInput(html, 'auth_req_id'),
        csrf_token: extractHiddenInput(html, 'csrf_token'),
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    const code = new URL(postAuth.headers.get('location')!).searchParams.get('code')!;

    const tokRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: verifier,
      }).toString(),
    });
    expect(tokRes.status).toBe(200);
    const tokJson = (await tokRes.json()) as { access_token: string; refresh_token: string };
    expect(repos.oauth.getTokenByHash(hashToken(tokJson.access_token))?.resource).toBe(
      'https://mcp.example.com/mcp',
    );

    const nullResourceToken = 'null_resource_legacy_token_123';
    repos.oauth.createToken({
      token_hash: hashToken(nullResourceToken),
      token_type: 'access',
      client_id: clientId,
      scope: 'mcp:tools',
      resource: null,
      token_family_id: 'fam_null_res',
      expires_at: Date.now() + 60_000,
      grace_expires_at: null,
    });
    const nullResMcp = await app.request('https://mcp.example.com/mcp', {
      method: 'POST',
      headers: { Authorization: `Bearer ${nullResourceToken}` },
    });
    expect(nullResMcp.status).toBe(401);

    // 5. Expired-but-already-rotated ancestor refresh token replay still revokes active family
    vi.useFakeTimers();
    const t0 = Date.now();
    vi.setSystemTime(t0);
    const rotatedRes = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokJson.refresh_token,
        client_id: clientId,
      }).toString(),
    });
    expect(rotatedRes.status).toBe(200);
    const rotatedJson = (await rotatedRes.json()) as { access_token: string; refresh_token: string };

    // Force-expire the old ancestor refresh token while keeping its family active
    db.prepare('UPDATE oauth_tokens SET expires_at = ? WHERE token_hash = ?').run(
      t0 + 120_000,
      hashToken(tokJson.refresh_token),
    );
    vi.advanceTimersByTime(180_000); // > grace (60s) AND > ancestor expires_at (120s)
    const expiredAncestorReplay = await app.request('https://mcp.example.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokJson.refresh_token,
        client_id: clientId,
      }).toString(),
    });
    expect(expiredAncestorReplay.status).toBe(400);
    expect(repos.oauth.getTokenByHash(hashToken(rotatedJson.refresh_token))?.revoked).toBe(true);
    expect(repos.oauth.getTokenByHash(hashToken(rotatedJson.access_token))?.revoked).toBe(true);

    // 6. SQL aggregate KPI counts when > 30 jobs exist + SSE activeJobs & session expiry
    vi.useRealTimers();
    for (let i = 0; i < 35; i++) {
      repos.jobs.createJob({
        job_id: `bulk-job-${i}`,
        workspace_slug: 'demo-repo',
        runner_type: 'shell_task',
        status: i < 32 ? 'running' : 'completed',
        command_or_objective: `echo ${i}`,
      });
    }
    const loginGet = await app.request('https://mcp.example.com/admin/login');
    const loginCsrf = extractHiddenInput(await loginGet.text(), 'csrf_token');
    const csrfCookie = extractCookieValue(loginGet.headers.getSetCookie(), 'gb_admin_csrf');
    const loginPost = await app.request('https://mcp.example.com/admin/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie}`,
      },
      body: new URLSearchParams({
        csrf_token: loginCsrf,
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    const sessionCookie = extractCookieValue(loginPost.headers.getSetCookie(), 'gb_admin_session');

    const summaryRes = await app.request('https://mcp.example.com/admin/api/summary', {
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
    });
    expect(summaryRes.status).toBe(200);
    expect(((await summaryRes.json()) as { activeJobs: number }).activeJobs).toBe(32);

    const ac = new AbortController();
    const sseRes = await app.request('https://mcp.example.com/admin/api/jobs/stream', {
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
      signal: ac.signal,
    });
    const reader = sseRes.body!.getReader();
    const chunkText = new TextDecoder().decode((await reader.read()).value);
    expect(chunkText).toContain('"activeJobs":32');
    ac.abort();
    await reader.cancel().catch(() => undefined);

    // 7. SSE stream closes cleanly when session.exp passes
    vi.useFakeTimers();
    const tSessionStart = Date.now();
    vi.setSystemTime(tSessionStart);
    const loginGet2 = await app.request('https://mcp.example.com/admin/login');
    const loginCsrf2 = extractHiddenInput(await loginGet2.text(), 'csrf_token');
    const csrfCookie2 = extractCookieValue(loginGet2.headers.getSetCookie(), 'gb_admin_csrf');
    const loginPost2 = await app.request('https://mcp.example.com/admin/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie2}`,
      },
      body: new URLSearchParams({
        csrf_token: loginCsrf2,
        password: 'super-secret-operator-pw',
      }).toString(),
    });
    const expSessionCookie = extractCookieValue(loginPost2.headers.getSetCookie(), 'gb_admin_session');
    const sseExpRes = await app.request('https://mcp.example.com/admin/api/jobs/stream', {
      headers: { Cookie: `gb_admin_session=${expSessionCookie}` },
    });
    const expReader = sseExpRes.body!.getReader();
    const firstChunk = await expReader.read();
    expect(firstChunk.done).toBe(false);
    vi.setSystemTime(tSessionStart + 12 * 60 * 60 * 1000 + 1000);
    await vi.advanceTimersByTimeAsync(100);
    const afterExp = await expReader.read();
    expect(afterExp.done).toBe(true);
  });
});
