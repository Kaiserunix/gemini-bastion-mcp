import crypto from 'node:crypto';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAdminApp } from '../src/admin/index.js';
import {
  computeS256Challenge,
  createAuthApp,
  createBearerMiddleware,
  hashPasswordScrypt,
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

function extractHiddenInput(html: string, name: string, formAction?: string): string {
  let scope = html;
  if (formAction) {
    const idx = html.indexOf(`action="${formAction}"`);
    if (idx === -1) throw new Error(`Form with action="${formAction}" not found`);
    scope = html.slice(idx, html.indexOf('</form>', idx));
  }
  const regex = new RegExp(`name="${name}"\\s+value="([^"]+)"`, 'i');
  const match = regex.exec(scope);
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

function makeIdpConfig(overrides: Record<string, string | undefined> = {}): GatewayConfig {
  return loadConfig({
    NODE_ENV: 'test',
    PUBLIC_DOMAIN: 'https://mcp.example.com',
    TRUST_CF_CONNECTING_IP: 'true',
    DATA_DIR: '/tmp/omni-idp-test-data',
    WORKSPACES_DIR: '/tmp/omni-idp-test-workspaces',
    ADMIN_PASSWORD_HASH: hashPasswordScrypt('operator-pass-123'),
    OAUTH_SIGNING_SECRET: 'test-signing-secret-at-least-32-bytes-long-123456',
    GOOGLE_OAUTH_CLIENT_ID: 'google-client-id-123',
    GOOGLE_OAUTH_CLIENT_SECRET: 'google-client-secret-xyz',
    GOOGLE_OAUTH_ALLOWED_EMAILS: 'owner@example.com',
    GITHUB_OAUTH_CLIENT_ID: 'github-client-id-456',
    GITHUB_OAUTH_CLIENT_SECRET: 'github-client-secret-abc',
    GITHUB_OAUTH_ALLOWED_USERS: 'octo-owner',
    ...overrides,
  });
}

describe('Upstream Operator OAuth (Google & GitHub IdP)', () => {
  let db: GatewayDatabase;
  let repos: Repositories;
  let config: GatewayConfig;
  let mockFetch: ReturnType<typeof vi.fn<typeof fetch>>;
  let app: Hono;

  function setupApp(cfg: GatewayConfig) {
    app = new Hono();
    app.route(
      '/',
      createAuthApp({
        config: cfg,
        db,
        repos,
        upstreamFetch: mockFetch,
      }),
    );
    app.route('/admin', createAdminApp({ config: cfg, repos }));
    app.use('/mcp', createBearerMiddleware({ config: cfg, repos }));
    app.all('/mcp', (c) => c.json({ ok: true, auth: c.get('oauthAuth') }));
  }

  beforeEach(() => {
    db = openDatabase(':memory:');
    repos = createRepositories(db);
    config = makeIdpConfig();
    mockFetch = vi.fn<typeof fetch>();
    setupApp(config);
  });

  afterEach(() => {
    db.close();
  });

  it('logs into /admin via Google OAuth for allowlisted verified email and rejects unverified or unauthorized emails', async () => {
    const loginGet = await app.request('https://mcp.example.com/admin/login');
    expect(loginGet.status).toBe(200);
    const loginCsp = loginGet.headers.get('content-security-policy') ?? '';
    expect(loginCsp).not.toContain('form-action');
    const loginHtml = await loginGet.text();
    expect(loginHtml).toContain('Sign in with Google');
    expect(loginHtml).toContain('Sign in with GitHub');

    const csrfToken = extractHiddenInput(loginHtml, 'csrf_token', '/auth/idp/google/start');
    const csrfCookie = extractCookieValue(loginGet.headers.getSetCookie(), 'gb_admin_csrf');
    expect(csrfCookie).toBe(csrfToken);

    const startRes = await app.request('https://mcp.example.com/auth/idp/google/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie}`,
      },
      body: new URLSearchParams({
        purpose: 'admin',
        csrf_token: csrfToken,
      }).toString(),
    });
    expect(startRes.status).toBe(302);
    const googleAuthUrl = new URL(startRes.headers.get('location')!);
    expect(googleAuthUrl.origin + googleAuthUrl.pathname).toBe(
      'https://accounts.google.com/o/oauth2/v2/auth',
    );
    expect(googleAuthUrl.searchParams.get('redirect_uri')).toBe(
      'https://mcp.example.com/auth/idp/google/callback',
    );
    expect(googleAuthUrl.searchParams.get('code_challenge_method')).toBe('S256');
    const upstreamCookie = extractCookieValue(startRes.headers.getSetCookie(), 'gb_upstream_oauth');
    expect(upstreamCookie).toBeTruthy();
    const state = googleAuthUrl.searchParams.get('state')!;

    // Case 1: allowlisted + verified -> 302 /admin with gb_admin_session cookie
    mockFetch
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: 'g-access-1' }), { status: 200 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ email: 'Owner@Example.com', email_verified: true }),
          { status: 200 },
        ),
      );

    const cbOk = await app.request(
      `https://mcp.example.com/auth/idp/google/callback?code=g-code-1&state=${encodeURIComponent(state)}`,
      {
        headers: { Cookie: `gb_upstream_oauth=${upstreamCookie}` },
      },
    );
    expect(cbOk.status).toBe(302);
    expect(cbOk.headers.get('location')).toBe('/admin');
    const sessionCookie = extractCookieValue(cbOk.headers.getSetCookie(), 'gb_admin_session');
    expect(sessionCookie).toBeTruthy();

    const dashRes = await app.request('https://mcp.example.com/admin', {
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
    });
    expect(dashRes.status).toBe(200);

    // Also verify /admin/api/oauth reports upstream provider status without leaking secrets
    const oauthApiRes = await app.request('https://mcp.example.com/admin/api/oauth', {
      headers: { Cookie: `gb_admin_session=${sessionCookie}` },
    });
    expect(oauthApiRes.status).toBe(200);
    const oauthApiJson = (await oauthApiRes.json()) as {
      upstreamProviders: {
        google: { enabled: boolean; allowedCount: number; callbackUrl: string };
        github: { enabled: boolean; allowedCount: number; callbackUrl: string };
      };
    };
    expect(oauthApiJson.upstreamProviders.google).toEqual({
      enabled: true,
      allowedCount: 1,
      callbackUrl: 'https://mcp.example.com/auth/idp/google/callback',
    });
    expect(JSON.stringify(oauthApiJson)).not.toContain('google-client-secret-xyz');

    // Case 2: email_verified: false -> 403
    const start2 = await app.request('https://mcp.example.com/auth/idp/google/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie}`,
      },
      body: new URLSearchParams({ purpose: 'admin', csrf_token: csrfToken }).toString(),
    });
    const state2 = new URL(start2.headers.get('location')!).searchParams.get('state')!;
    const cookie2 = extractCookieValue(start2.headers.getSetCookie(), 'gb_upstream_oauth')!;

    mockFetch
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: 'g-access-2' }), { status: 200 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ email: 'owner@example.com', email_verified: false }),
          { status: 200 },
        ),
      );
    const cbUnverified = await app.request(
      `https://mcp.example.com/auth/idp/google/callback?code=g-code-2&state=${encodeURIComponent(state2)}`,
      { headers: { Cookie: `gb_upstream_oauth=${cookie2}` } },
    );
    expect(cbUnverified.status).toBe(403);

    // Case 3: non-allowlisted email -> 403
    const start3 = await app.request('https://mcp.example.com/auth/idp/google/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie}`,
      },
      body: new URLSearchParams({ purpose: 'admin', csrf_token: csrfToken }).toString(),
    });
    const state3 = new URL(start3.headers.get('location')!).searchParams.get('state')!;
    const cookie3 = extractCookieValue(start3.headers.getSetCookie(), 'gb_upstream_oauth')!;

    mockFetch
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: 'g-access-3' }), { status: 200 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ email: 'intruder@example.com', email_verified: true }),
          { status: 200 },
        ),
      );
    const cbStranger = await app.request(
      `https://mcp.example.com/auth/idp/google/callback?code=g-code-3&state=${encodeURIComponent(state3)}`,
      { headers: { Cookie: `gb_upstream_oauth=${cookie3}` } },
    );
    expect(cbStranger.status).toBe(403);
  });

  it('logs into /admin via GitHub OAuth and enforces dual user+id allowlist when both are configured', async () => {
    const dualCfg = makeIdpConfig({
      GITHUB_OAUTH_ALLOWED_USERS: 'octo-owner',
      GITHUB_OAUTH_ALLOWED_IDS: '998877',
    });
    setupApp(dualCfg);

    const loginGet = await app.request('https://mcp.example.com/admin/login');
    const csrfToken = extractHiddenInput(await loginGet.text(), 'csrf_token', '/auth/idp/github/start');
    const csrfCookie = extractCookieValue(loginGet.headers.getSetCookie(), 'gb_admin_csrf')!;

    // Attempt 1: matching login, wrong numeric ID -> 403
    const s1 = await app.request('https://mcp.example.com/auth/idp/github/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie}`,
      },
      body: new URLSearchParams({ purpose: 'admin', csrf_token: csrfToken }).toString(),
    });
    expect(s1.status).toBe(302);
    const ghUrl = new URL(s1.headers.get('location')!);
    expect(ghUrl.origin + ghUrl.pathname).toBe('https://github.com/login/oauth/authorize');
    const st1 = ghUrl.searchParams.get('state')!;
    const ck1 = extractCookieValue(s1.headers.getSetCookie(), 'gb_upstream_oauth')!;

    mockFetch
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: 'gh-tok-1' }), { status: 200 }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: 111111, login: 'octo-owner' }), { status: 200 }),
      );
    const cbMismatchId = await app.request(
      `https://mcp.example.com/auth/idp/github/callback?code=gh-c1&state=${encodeURIComponent(st1)}`,
      { headers: { Cookie: `gb_upstream_oauth=${ck1}` } },
    );
    expect(cbMismatchId.status).toBe(403);

    // Attempt 2: both login and ID match -> 302 /admin
    const s2 = await app.request('https://mcp.example.com/auth/idp/github/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie}`,
      },
      body: new URLSearchParams({ purpose: 'admin', csrf_token: csrfToken }).toString(),
    });
    const st2 = new URL(s2.headers.get('location')!).searchParams.get('state')!;
    const ck2 = extractCookieValue(s2.headers.getSetCookie(), 'gb_upstream_oauth')!;

    mockFetch
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: 'gh-tok-2' }), { status: 200 }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ id: 998877, login: 'Octo-Owner' }), { status: 200 }),
      );
    const cbOk = await app.request(
      `https://mcp.example.com/auth/idp/github/callback?code=gh-c2&state=${encodeURIComponent(st2)}`,
      { headers: { Cookie: `gb_upstream_oauth=${ck2}` } },
    );
    expect(cbOk.status).toBe(302);
    expect(cbOk.headers.get('location')).toBe('/admin');
    expect(extractCookieValue(cbOk.headers.getSetCookie(), 'gb_admin_session')).toBeTruthy();
  });

  it('completes MCP /oauth/authorize consent via Google and GitHub preserving 2600-char state byte-for-byte', async () => {
    const redirectUri = 'https://oauth-redirect.googleusercontent.com/r/idp-mcp';
    const dcrRes = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Gemini IdP Test',
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: 'none',
      }),
    });
    const { client_id: clientId } = (await dcrRes.json()) as { client_id: string };

    for (const provider of ['google', 'github'] as const) {
      const { verifier, challenge } = createPkcePair();
      const rawState = `${provider}_` + 'ZyXw9876+/=?&_'.repeat(186) + '_END';
      expect(rawState.length).toBeGreaterThanOrEqual(2600);

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
      const html = await getAuth.text();
      expect(html).toContain('Approve with Google');
      expect(html).toContain('Approve with GitHub');

      const bindCookie = extractCookieValue(getAuth.headers.getSetCookie(), 'gb_mcp_auth_bind');
      expect(bindCookie).toBeTruthy();

      const action = `/auth/idp/${provider}/start`;
      const authReqId = extractHiddenInput(html, 'auth_req_id', action);
      const csrfToken = extractHiddenInput(html, 'csrf_token', action);

      const startRes = await app.request(`https://mcp.example.com${action}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Cookie: `gb_mcp_auth_bind=${bindCookie}`,
        },
        body: new URLSearchParams({
          purpose: 'mcp_authorize',
          auth_req_id: authReqId,
          csrf_token: csrfToken,
        }).toString(),
      });
      expect(startRes.status).toBe(302);
      const upState = new URL(startRes.headers.get('location')!).searchParams.get('state')!;
      const upCookie = extractCookieValue(startRes.headers.getSetCookie(), 'gb_upstream_oauth')!;

      if (provider === 'google') {
        mockFetch
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ access_token: 'g-mcp-tok' }), { status: 200 }),
          )
          .mockResolvedValueOnce(
            new Response(
              JSON.stringify({ email: 'owner@example.com', email_verified: true }),
              { status: 200 },
            ),
          );
      } else {
        mockFetch
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ access_token: 'gh-mcp-tok' }), { status: 200 }),
          )
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ id: 42, login: 'octo-owner' }), { status: 200 }),
          );
      }

      const cbRes = await app.request(
        `https://mcp.example.com/auth/idp/${provider}/callback?code=up-code&state=${encodeURIComponent(upState)}`,
        { headers: { Cookie: `gb_upstream_oauth=${upCookie}` } },
      );
      expect(cbRes.status).toBe(302);

      const callbackUrl = new URL(cbRes.headers.get('location')!);
      expect(callbackUrl.origin + callbackUrl.pathname).toBe(redirectUri);
      expect(callbackUrl.searchParams.get('state')).toBe(rawState);
      const mcpCode = callbackUrl.searchParams.get('code')!;
      expect(mcpCode).toBeTruthy();

      const tokRes = await app.request('https://mcp.example.com/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: mcpCode,
          redirect_uri: redirectUri,
          client_id: clientId,
          code_verifier: verifier,
          resource: 'https://mcp.example.com/mcp',
        }).toString(),
      });
      expect(tokRes.status).toBe(200);
      const tokJson = (await tokRes.json()) as { access_token: string };

      const mcpRes = await app.request('https://mcp.example.com/mcp', {
        method: 'POST',
        headers: { Authorization: `Bearer ${tokJson.access_token}` },
      });
      expect(mcpRes.status).toBe(200);
    }
  });

  it('defends against Login CSRF, Session Fixation, missing/mismatched binding cookies, state replay, and missing prod allowlists', async () => {
    // 1. Login CSRF: missing or wrong csrf_token / cookie -> 403
    const loginGet = await app.request('https://mcp.example.com/admin/login');
    const csrfToken = extractHiddenInput(await loginGet.text(), 'csrf_token', '/auth/idp/google/start');
    const csrfCookie = extractCookieValue(loginGet.headers.getSetCookie(), 'gb_admin_csrf')!;

    const missingCookieCsrf = await app.request('https://mcp.example.com/auth/idp/google/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ purpose: 'admin', csrf_token: csrfToken }).toString(),
    });
    expect(missingCookieCsrf.status).toBe(403);

    const wrongBodyCsrf = await app.request('https://mcp.example.com/auth/idp/google/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie}`,
      },
      body: new URLSearchParams({ purpose: 'admin', csrf_token: 'attacker-csrf' }).toString(),
    });
    expect(wrongBodyCsrf.status).toBe(403);

    // 2. Authorization Session Fixation: missing gb_mcp_auth_bind cookie -> 403
    const redirectUri = 'https://oauth-redirect.googleusercontent.com/r/fixation-test';
    const dcrRes = await app.request('https://mcp.example.com/oauth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [redirectUri] }),
    });
    const { client_id: clientId } = (await dcrRes.json()) as { client_id: string };
    const { challenge } = createPkcePair();

    const authUrl = new URL('https://mcp.example.com/oauth/authorize');
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('code_challenge', challenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    const getAuth = await app.request(authUrl.toString());
    const authHtml = await getAuth.text();
    const authReqId = extractHiddenInput(authHtml, 'auth_req_id', '/auth/idp/google/start');
    const authCsrf = extractHiddenInput(authHtml, 'csrf_token', '/auth/idp/google/start');

    const fixationAttempt = await app.request('https://mcp.example.com/auth/idp/google/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        purpose: 'mcp_authorize',
        auth_req_id: authReqId,
        csrf_token: authCsrf,
      }).toString(),
    });
    expect(fixationAttempt.status).toBe(403);

    // 3. Mismatched / missing gb_upstream_oauth cookie on callback + replay of consumed state
    const validStart = await app.request('https://mcp.example.com/auth/idp/google/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${csrfCookie}`,
      },
      body: new URLSearchParams({ purpose: 'admin', csrf_token: csrfToken }).toString(),
    });
    const validState = new URL(validStart.headers.get('location')!).searchParams.get('state')!;
    const validCookie = extractCookieValue(validStart.headers.getSetCookie(), 'gb_upstream_oauth')!;

    const wrongBindCb = await app.request(
      `https://mcp.example.com/auth/idp/google/callback?code=c1&state=${encodeURIComponent(validState)}`,
      { headers: { Cookie: 'gb_upstream_oauth=wrong-nonce' } },
    );
    expect(wrongBindCb.status).toBe(403);

    mockFetch
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: 'g-once' }), { status: 200 }),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ email: 'owner@example.com', email_verified: true }),
          { status: 200 },
        ),
      );
    const firstCb = await app.request(
      `https://mcp.example.com/auth/idp/google/callback?code=c1&state=${encodeURIComponent(validState)}`,
      { headers: { Cookie: `gb_upstream_oauth=${validCookie}` } },
    );
    expect(firstCb.status).toBe(302);

    // Replay same state + cookie -> 403
    const replayCb = await app.request(
      `https://mcp.example.com/auth/idp/google/callback?code=c1&state=${encodeURIComponent(validState)}`,
      { headers: { Cookie: `gb_upstream_oauth=${validCookie}` } },
    );
    expect(replayCb.status).toBe(403);

    // 3b. Reflected error query parameter is NOT echoed into HTML and oversized error is sanitized in audit_logs
    const spoofedErrCb = await app.request(
      'https://mcp.example.com/auth/idp/google/callback?error=Visit%20evil.com%20now',
    );
    expect(spoofedErrCb.status).toBe(403);
    const spoofedHtml = await spoofedErrCb.text();
    expect(spoofedHtml).not.toContain('Visit evil.com now');
    expect(spoofedHtml).toContain('Sign-in was cancelled or denied by the upstream provider.');
    const errLogs = repos.audit.list({ action: 'idp_callback_error', limit: 5 });
    expect(errLogs[0]?.details.error).toBe('upstream_error');

    // 3c. Admin login 413 keeps CSRF cookie in sync with rendered form
    const oversizedAdminLogin = await app.request('https://mcp.example.com/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `password=${'p'.repeat(70_000)}`,
    });
    expect(oversizedAdminLogin.status).toBe(413);
    const errFormHtml = await oversizedAdminLogin.text();
    const errFormCsrf = extractHiddenInput(errFormHtml, 'csrf_token');
    const errFormCookie = extractCookieValue(
      oversizedAdminLogin.headers.getSetCookie(),
      'gb_admin_csrf',
    );
    expect(errFormCookie).toBe(errFormCsrf);

    // 3d. GitHub ID-only allowlist without login records github:<id> actor (not "github:")
    const idOnlyCfg = makeIdpConfig({
      GITHUB_OAUTH_ALLOWED_USERS: '',
      GITHUB_OAUTH_ALLOWED_IDS: '998877',
    });
    setupApp(idOnlyCfg);
    const idLoginGet = await app.request('https://mcp.example.com/admin/login');
    const idCsrf = extractHiddenInput(await idLoginGet.text(), 'csrf_token', '/auth/idp/github/start');
    const idCsrfCookie = extractCookieValue(idLoginGet.headers.getSetCookie(), 'gb_admin_csrf')!;
    const idStart = await app.request('https://mcp.example.com/auth/idp/github/start', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Cookie: `gb_admin_csrf=${idCsrfCookie}`,
      },
      body: new URLSearchParams({ purpose: 'admin', csrf_token: idCsrf }).toString(),
    });
    const idState = new URL(idStart.headers.get('location')!).searchParams.get('state')!;
    const idUpCookie = extractCookieValue(idStart.headers.getSetCookie(), 'gb_upstream_oauth')!;
    mockFetch
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ access_token: 'gh-id-only' }), { status: 200 }),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 998877 }), { status: 200 }));
    const idCb = await app.request(
      `https://mcp.example.com/auth/idp/github/callback?code=c-id&state=${encodeURIComponent(idState)}`,
      { headers: { Cookie: `gb_upstream_oauth=${idUpCookie}` } },
    );
    expect(idCb.status).toBe(302);
    const oauthLoginLogs = repos.audit.list({ action: 'admin.login.oauth', limit: 5 });
    expect(oauthLoginLogs[0]?.actor).toBe('github:998877');
    setupApp(config);

    // 4. Disabled provider -> 404 & oversized start body -> 413
    const oversizedRes = await app.request('https://mcp.example.com/auth/idp/google/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `purpose=admin&csrf_token=${'a'.repeat(70_000)}`,
    });
    expect(oversizedRes.status).toBe(413);

    const disabledCfg = makeIdpConfig({
      GOOGLE_OAUTH_ALLOWED_EMAILS: '',
      GITHUB_OAUTH_ALLOWED_USERS: '',
    });
    setupApp(disabledCfg);
    const disabledStart = await app.request('https://mcp.example.com/auth/idp/google/start', {
      method: 'POST',
      body: new URLSearchParams({ purpose: 'admin', csrf_token: 'x' }).toString(),
    });
    expect(disabledStart.status).toBe(404);

    // 5. Fail-closed production startup when IdP credentials lack allowlist
    expect(() =>
      loadConfig({
        NODE_ENV: 'production',
        PUBLIC_DOMAIN: 'https://mcp.example.com',
        DATA_DIR: '/tmp/omni-prod-data',
        WORKSPACES_DIR: '/tmp/omni-prod-ws',
        OAUTH_SIGNING_SECRET: 'prod-signing-secret-with-plenty-of-entropy-123456',
        GOOGLE_OAUTH_CLIENT_ID: 'gid',
        GOOGLE_OAUTH_CLIENT_SECRET: 'gsec',
      }),
    ).toThrow(/GOOGLE_OAUTH_ALLOWED_EMAILS/);

    expect(() =>
      loadConfig({
        NODE_ENV: 'production',
        PUBLIC_DOMAIN: 'https://mcp.example.com',
        DATA_DIR: '/tmp/omni-prod-data',
        WORKSPACES_DIR: '/tmp/omni-prod-ws',
        OAUTH_SIGNING_SECRET: 'prod-signing-secret-with-plenty-of-entropy-123456',
        GITHUB_OAUTH_CLIENT_ID: 'ghid',
        GITHUB_OAUTH_CLIENT_SECRET: 'ghsec',
      }),
    ).toThrow(/GITHUB_OAUTH_ALLOWED_USERS/);
  });
});
