import { Hono } from 'hono';
import type { Context } from 'hono';
import { isGitHubOAuthEnabled, isGoogleOAuthEnabled } from '../config.js';
import type { GatewayConfig, OAuthAuthRequest, OAuthClient } from '../types.js';
import { clearMcpAuthBindCookie, setMcpAuthBindCookie } from './cookies.js';
import {
  constantTimeEqual,
  generateRandomToken,
  hashToken,
  verifyPassword,
} from './crypto.js';
import { isAllowedRedirectUri } from './dcr.js';
import { DEFAULT_SCOPES_SUPPORTED, getCanonicalResource, isValidResource } from './discovery.js';
import { getClientIp, IpRateLimiter, readLimitedBodyText } from './rateLimit.js';
import type { AuditLogger, OAuthStore, RateLimiter } from './store.js';

export const MAX_STATE_BYTES = 8192;
export const AUTH_REQUEST_TTL_MS = 10 * 60 * 1000;
export const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

const PKCE_CHALLENGE_REGEX = /^[A-Za-z0-9\-_]{43,128}$/;

export interface AuthorizeDeps {
  config: GatewayConfig;
  oauthStore?: Pick<
    OAuthStore,
    'getClient' | 'createAuthRequest' | 'getAuthRequest' | 'consumeAuthRequest' | 'createCode'
  >;
  oauthRepo?: Pick<
    OAuthStore,
    'getClient' | 'createAuthRequest' | 'getAuthRequest' | 'consumeAuthRequest' | 'createCode'
  >;
  auditRepo?: AuditLogger;
  auditLogger?: AuditLogger;
  rateLimiter?: RateLimiter;
  getRateLimiter?: RateLimiter;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function setSecurityHeaders(c: Context): void {
  c.header(
    'Content-Security-Policy',
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
  );
  c.header('X-Frame-Options', 'DENY');
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('Cache-Control', 'no-store');
}

function renderErrorHtml(title: string, message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} — GeminiBastionMCP</title>
  <style>
    body { margin:0; font-family: system-ui, -apple-system, sans-serif; background:#0b1020; color:#e5e7eb; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:16px; }
    .card { max-width:440px; width:100%; background:#131a2e; border:1px solid #26314f; border-radius:14px; padding:24px; box-shadow:0 12px 32px rgba(0,0,0,0.45); }
    h1 { margin:0 0 8px; font-size:1.2rem; color:#f87171; }
    p { margin:0; font-size:0.95rem; line-height:1.5; color:#cbd5e1; }
  </style>
</head>
<body>
  <main class="card">
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
  </main>
</body>
</html>`;
}

function renderConsentHtml(params: {
  clientName: string;
  authReq: OAuthAuthRequest;
  errorMessage?: string;
  actionPath?: string;
  googleEnabled?: boolean;
  githubEnabled?: boolean;
}): string {
  const {
    clientName,
    authReq,
    errorMessage,
    actionPath = '/oauth/authorize',
    googleEnabled = false,
    githubEnabled = false,
  } = params;
  const redirectOrigin = (() => {
    try {
      return new URL(authReq.redirect_uri).origin;
    } catch {
      return authReq.redirect_uri;
    }
  })();

  const idpButtons: string[] = [];
  if (googleEnabled) {
    idpButtons.push(`<form method="POST" action="/auth/idp/google/start">
        <input type="hidden" name="purpose" value="mcp_authorize" />
        <input type="hidden" name="auth_req_id" value="${escapeHtml(authReq.auth_req_id)}" />
        <input type="hidden" name="csrf_token" value="${escapeHtml(authReq.csrf_token)}" />
        <button class="btn-idp btn-google" type="submit">Approve with Google</button>
      </form>`);
  }
  if (githubEnabled) {
    idpButtons.push(`<form method="POST" action="/auth/idp/github/start">
        <input type="hidden" name="purpose" value="mcp_authorize" />
        <input type="hidden" name="auth_req_id" value="${escapeHtml(authReq.auth_req_id)}" />
        <input type="hidden" name="csrf_token" value="${escapeHtml(authReq.csrf_token)}" />
        <button class="btn-idp btn-github" type="submit">Approve with GitHub</button>
      </form>`);
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize Access — GeminiBastionMCP</title>
  <style>
    * { box-sizing: border-box; }
    body { margin:0; font-family: system-ui, -apple-system, sans-serif; background:#0b1020; color:#e5e7eb; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:16px; }
    .card { max-width:460px; width:100%; background:#131a2e; border:1px solid #26314f; border-radius:16px; padding:24px; box-shadow:0 14px 36px rgba(0,0,0,0.45); }
    .badge { display:inline-block; font-size:0.75rem; font-weight:600; letter-spacing:0.04em; text-transform:uppercase; color:#93c5fd; background:#1e293b; border:1px solid #334155; padding:4px 10px; border-radius:999px; margin-bottom:12px; }
    h1 { margin:0 0 8px; font-size:1.25rem; color:#f8fafc; }
    .sub { margin:0 0 18px; font-size:0.9rem; color:#94a3b8; line-height:1.45; }
    .meta { background:#0d1324; border:1px solid #1e293b; border-radius:10px; padding:12px 14px; margin-bottom:18px; font-size:0.85rem; }
    .meta-row { display:flex; justify-content:space-between; gap:12px; padding:4px 0; }
    .meta-k { color:#94a3b8; }
    .meta-v { color:#e2e8f0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break:break-all; text-align:right; }
    .err { background:#3f151b; border:1px solid #991b1b; color:#fecaca; padding:10px 12px; border-radius:8px; font-size:0.88rem; margin-bottom:16px; }
    label { display:block; font-size:0.85rem; font-weight:600; color:#cbd5e1; margin-bottom:6px; }
    input[type="password"] { width:100%; padding:11px 12px; border-radius:10px; border:1px solid #334155; background:#0b1020; color:#f8fafc; font-size:1rem; margin-bottom:16px; }
    input[type="password"]:focus { outline:2px solid #3b82f6; border-color:transparent; }
    .actions { display:flex; gap:10px; }
    button { flex:1; padding:11px 14px; border-radius:10px; font-size:0.95rem; font-weight:600; cursor:pointer; border:none; }
    .btn-primary { background:#2563eb; color:#fff; }
    .btn-primary:hover { background:#1d4ed8; }
    .btn-secondary { background:#1e293b; color:#cbd5e1; border:1px solid #334155; }
    .divider { display:flex; align-items:center; gap:10px; margin:18px 0 14px; color:#64748b; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.06em; }
    .divider::before, .divider::after { content:''; flex:1; height:1px; background:#26314f; }
    .idp-stack { display:flex; flex-direction:column; gap:10px; }
    .btn-idp { width:100%; padding:10px 14px; border-radius:10px; font-size:0.92rem; font-weight:600; cursor:pointer; border:1px solid #334155; background:#0f172a; color:#f8fafc; }
    .btn-idp:hover { border-color:#3b82f6; background:#172554; }
  </style>
</head>
<body>
  <main class="card">
    <span class="badge">OAuth 2.1 + PKCE</span>
    <h1>Authorize ${escapeHtml(clientName)}</h1>
    <p class="sub">Approve MCP gateway access using your operator password${idpButtons.length > 0 ? ' or a verified upstream provider' : ''}.</p>
    <div class="meta">
      <div class="meta-row"><span class="meta-k">Client ID</span><span class="meta-v">${escapeHtml(authReq.client_id)}</span></div>
      <div class="meta-row"><span class="meta-k">Redirect Origin</span><span class="meta-v">${escapeHtml(redirectOrigin)}</span></div>
      <div class="meta-row"><span class="meta-k">Scope</span><span class="meta-v">${escapeHtml(authReq.scope)}</span></div>
      ${authReq.resource ? `<div class="meta-row"><span class="meta-k">Resource</span><span class="meta-v">${escapeHtml(authReq.resource)}</span></div>` : ''}
    </div>
    ${errorMessage ? `<div class="err" role="alert">${escapeHtml(errorMessage)}</div>` : ''}
    <form method="POST" action="${escapeHtml(actionPath)}">
      <input type="hidden" name="auth_req_id" value="${escapeHtml(authReq.auth_req_id)}" />
      <input type="hidden" name="csrf_token" value="${escapeHtml(authReq.csrf_token)}" />
      <label for="password">Operator Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus />
      <div class="actions">
        <button class="btn-secondary" type="submit" name="decision" value="deny" formnovalidate>Deny</button>
        <button class="btn-primary" type="submit" name="decision" value="approve">Authorize</button>
      </div>
    </form>
    ${idpButtons.length > 0 ? `<div class="divider">or</div><div class="idp-stack">${idpButtons.join('')}</div>` : ''}
  </main>
</body>
</html>`;
}

function isRedirectUriValidForClient(
  redirectUri: string,
  client: OAuthClient,
  config: GatewayConfig,
): boolean {
  if (client.is_static) {
    return isAllowedRedirectUri(redirectUri, config.oauthAllowedRedirectHosts);
  }
  return (
    client.redirect_uris.includes(redirectUri) &&
    isAllowedRedirectUri(redirectUri, config.oauthAllowedRedirectHosts)
  );
}

function redirectWithOAuthError(
  c: Context,
  redirectUri: string,
  error: string,
  description: string,
  state: string | null,
): Response {
  const target = new URL(redirectUri);
  target.searchParams.set('error', error);
  target.searchParams.set('error_description', description);
  if (state !== null) {
    target.searchParams.set('state', state);
  }
  c.header('Cache-Control', 'no-store');
  return c.redirect(target.toString(), 302);
}

/**
 * Mounts `GET /oauth/authorize` and `POST /oauth/authorize`.
 */
export function createAuthorizeRoutes(deps: AuthorizeDeps): Hono {
  const { config } = deps;
  const oauthRepo = deps.oauthStore ?? deps.oauthRepo;
  if (!oauthRepo) {
    throw new Error('createAuthorizeRoutes requires oauthStore or oauthRepo');
  }
  const auditRepo = deps.auditLogger ?? deps.auditRepo;
  const rateLimiter = deps.rateLimiter ?? new IpRateLimiter(10, 60_000);
  const getRateLimiter = deps.getRateLimiter ?? new IpRateLimiter(60, 60_000);
  const allowedScopes = new Set<string>(DEFAULT_SCOPES_SUPPORTED);
  const app = new Hono();

  app.get('/oauth/authorize', (c) => {
    setSecurityHeaders(c);

    const ip = getClientIp(c, config.trustCfConnectingIp);
    const getRate = getRateLimiter.consume(`authorize-get:${ip}`);
    if (!getRate.allowed) {
      c.header('Retry-After', String(getRate.retryAfterSec));
      return c.html(
        renderErrorHtml('Too Many Requests', 'Rate limit exceeded. Please wait before retrying.'),
        429,
      );
    }

    const clientId = c.req.query('client_id')?.trim();
    const redirectUri = c.req.query('redirect_uri');
    const responseType = c.req.query('response_type');
    const rawState = c.req.query('state');
    const codeChallenge = c.req.query('code_challenge');
    const codeChallengeMethod = c.req.query('code_challenge_method');
    const rawScope = c.req.query('scope');
    const rawResource = c.req.query('resource');

    if (!clientId) {
      return c.html(renderErrorHtml('Invalid Request', 'Missing client_id parameter.'), 400);
    }

    const client = oauthRepo.getClient(clientId);
    if (!client) {
      return c.html(renderErrorHtml('Unknown Client', 'The specified client_id is not registered.'), 400);
    }

    if (!redirectUri || !isRedirectUriValidForClient(redirectUri, client, config)) {
      return c.html(
        renderErrorHtml('Invalid Redirect URI', 'The redirect_uri is missing or not allowed for this client.'),
        400,
      );
    }

    if (rawState !== undefined && Buffer.byteLength(rawState, 'utf8') > MAX_STATE_BYTES) {
      return redirectWithOAuthError(
        c,
        redirectUri,
        'invalid_request',
        `state must not exceed ${MAX_STATE_BYTES} bytes`,
        null,
      );
    }
    const state = rawState !== undefined ? rawState : null;

    if (responseType !== 'code') {
      return redirectWithOAuthError(
        c,
        redirectUri,
        'unsupported_response_type',
        'Only response_type=code is supported',
        state,
      );
    }

    if (codeChallengeMethod !== 'S256' || !codeChallenge || !PKCE_CHALLENGE_REGEX.test(codeChallenge)) {
      return redirectWithOAuthError(
        c,
        redirectUri,
        'invalid_request',
        'PKCE with code_challenge_method=S256 is required',
        state,
      );
    }

    let scope = 'mcp:tools';
    if (rawScope !== undefined && rawScope.trim().length > 0) {
      const tokens = rawScope.trim().split(/\s+/);
      if (tokens.some((tok) => !allowedScopes.has(tok))) {
        return redirectWithOAuthError(
          c,
          redirectUri,
          'invalid_scope',
          `Unsupported scope; supported scopes: ${DEFAULT_SCOPES_SUPPORTED.join(' ')}`,
          state,
        );
      }
      scope = Array.from(new Set(tokens)).join(' ');
    }

    let resource: string;
    if (rawResource !== undefined && rawResource.trim().length > 0) {
      if (!isValidResource(rawResource, config.publicDomain)) {
        return redirectWithOAuthError(
          c,
          redirectUri,
          'invalid_target',
          'Requested resource does not match this gateway',
          state,
        );
      }
      resource = rawResource;
    } else {
      resource = getCanonicalResource(config.publicDomain);
    }

    const authReq = oauthRepo.createAuthRequest({
      auth_req_id: generateRandomToken(24),
      client_id: client.client_id,
      redirect_uri: redirectUri,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      scope,
      resource,
      csrf_token: generateRandomToken(24),
      expires_at: Date.now() + AUTH_REQUEST_TTL_MS,
    });

    setMcpAuthBindCookie(c, config, hashToken(authReq.auth_req_id));

    return c.html(
      renderConsentHtml({
        clientName: client.client_name,
        authReq,
        googleEnabled: isGoogleOAuthEnabled(config),
        githubEnabled: isGitHubOAuthEnabled(config),
      }),
      200,
    );
  });

  app.post('/oauth/authorize', async (c) => {
    setSecurityHeaders(c);

    const ip = getClientIp(c, config.trustCfConnectingIp);
    const rate = rateLimiter.consume(`authorize:${ip}`);
    if (!rate.allowed) {
      c.header('Retry-After', String(rate.retryAfterSec));
      return c.html(
        renderErrorHtml('Too Many Requests', 'Rate limit exceeded. Please wait before retrying.'),
        429,
      );
    }

    const bodyRead = await readLimitedBodyText(c);
    if (!bodyRead.ok) {
      return c.html(
        renderErrorHtml('Payload Too Large', 'Request body exceeds 64KB limit.'),
        413,
      );
    }

    let authReqId = '';
    let submittedCsrf = '';
    let password = '';
    let decision = 'approve';

    const contentType = c.req.header('content-type') ?? '';
    if (contentType.includes('application/json')) {
      try {
        const json = JSON.parse(bodyRead.text) as Record<string, unknown>;
        authReqId = typeof json.auth_req_id === 'string' ? json.auth_req_id : '';
        submittedCsrf = typeof json.csrf_token === 'string' ? json.csrf_token : '';
        password = typeof json.password === 'string' ? json.password : '';
        decision = typeof json.decision === 'string' ? json.decision : 'approve';
      } catch {
        return c.html(renderErrorHtml('Bad Request', 'Malformed JSON body.'), 400);
      }
    } else {
      const form = new URLSearchParams(bodyRead.text);
      authReqId = form.get('auth_req_id') ?? '';
      submittedCsrf = form.get('csrf_token') ?? '';
      password = form.get('password') ?? '';
      decision = form.get('decision') ?? 'approve';
    }

    if (!authReqId) {
      return c.html(renderErrorHtml('Invalid Request', 'Missing authorization request ID.'), 400);
    }

    const authReq = oauthRepo.getAuthRequest(authReqId);
    if (!authReq || authReq.used || authReq.expires_at <= Date.now()) {
      return c.html(
        renderErrorHtml('Request Expired', 'This authorization request has expired or was already used.'),
        400,
      );
    }

    if (!submittedCsrf || !constantTimeEqual(submittedCsrf, authReq.csrf_token)) {
      return c.html(renderErrorHtml('Forbidden', 'Invalid CSRF token.'), 403);
    }

    if (decision === 'deny') {
      oauthRepo.consumeAuthRequest(authReq.auth_req_id);
      clearMcpAuthBindCookie(c);
      auditRepo?.record({
        actor: 'admin',
        action: 'oauth_authorize',
        target: authReq.client_id,
        status: 'denied',
        details: { ip },
      });
      return redirectWithOAuthError(
        c,
        authReq.redirect_uri,
        'access_denied',
        'Operator denied authorization',
        authReq.state,
      );
    }

    const client = oauthRepo.getClient(authReq.client_id);
    if (!client) {
      return c.html(renderErrorHtml('Unknown Client', 'Client no longer exists.'), 400);
    }

    const passwordOk = verifyPassword(password, config.adminPasswordHash, config.nodeEnv);
    if (!passwordOk) {
      auditRepo?.record({
        actor: 'admin',
        action: 'oauth_authorize',
        target: authReq.client_id,
        status: 'failure',
        details: { reason: 'invalid_password', ip },
      });
      return c.html(
        renderConsentHtml({
          clientName: client.client_name,
          authReq,
          errorMessage: 'Invalid operator password. Please try again.',
          googleEnabled: isGoogleOAuthEnabled(config),
          githubEnabled: isGitHubOAuthEnabled(config),
        }),
        401,
      );
    }

    const consumed = oauthRepo.consumeAuthRequest(authReq.auth_req_id);
    if (!consumed) {
      return c.html(
        renderErrorHtml('Request Expired', 'This authorization request has expired or was already used.'),
        400,
      );
    }
    clearMcpAuthBindCookie(c);

    const code = generateRandomToken(32);
    oauthRepo.createCode({
      code,
      client_id: consumed.client_id,
      redirect_uri: consumed.redirect_uri,
      code_challenge: consumed.code_challenge,
      scope: consumed.scope,
      resource: consumed.resource,
      expires_at: Date.now() + AUTH_CODE_TTL_MS,
    });

    auditRepo?.record({
      actor: 'admin',
      action: 'oauth_authorize',
      target: consumed.client_id,
      status: 'success',
      details: {
        scope: consumed.scope,
        resource: consumed.resource,
        ip,
      },
    });

    const redirectUrl = new URL(consumed.redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (consumed.state !== null) {
      redirectUrl.searchParams.set('state', consumed.state);
    }

    c.header('Cache-Control', 'no-store');
    return c.redirect(redirectUrl.toString(), 302);
  });

  return app;
}
