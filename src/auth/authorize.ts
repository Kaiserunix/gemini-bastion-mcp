import { Hono } from 'hono';
import type { Context } from 'hono';
import { isGitHubOAuthEnabled, isGoogleOAuthEnabled } from '../config.js';
import type { AuditRepository } from '../db/repositories/auditRepo.js';
import type { OAuthRepository } from '../db/repositories/oauthRepo.js';
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

export const MAX_STATE_BYTES = 8192;
export const AUTH_REQUEST_TTL_MS = 10 * 60 * 1000;
export const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

const PKCE_CHALLENGE_REGEX = /^[A-Za-z0-9\-_]{43,128}$/;

export interface AuthorizeDeps {
  config: GatewayConfig;
  oauthRepo: OAuthRepository;
  auditRepo?: AuditRepository;
  rateLimiter?: IpRateLimiter;
  getRateLimiter?: IpRateLimiter;
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

const EDITORIAL_THEME_CSS = `
    :root {
      --bg: #FBFBFB;
      --surface: #FFFFFF;
      --subtle: #F4F4F5;
      --border: #E4E4E7;
      --border-strong: #D4D4D8;
      --ink: #111113;
      --ink-2: #52525B;
      --muted: #71717A;
      --cta-bg: #111113;
      --cta-fg: #FFFFFF;
      --cta-hover: #27272A;
      --crimson: #B91C1C;
      --crimson-bg: #FEF2F2;
      --crimson-bd: #FECACA;
      --shadow: 0 1px 2px rgba(17,17,19,0.04), 0 8px 24px rgba(17,17,19,0.03);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #09090B;
        --surface: #111113;
        --subtle: #18181B;
        --border: #27272A;
        --border-strong: #3F3F46;
        --ink: #FAFAFA;
        --ink-2: #A1A1AA;
        --muted: #71717A;
        --cta-bg: #FAFAFA;
        --cta-fg: #09090B;
        --cta-hover: #E4E4E7;
        --crimson: #F87171;
        --crimson-bg: rgba(185,28,28,0.16);
        --crimson-bd: rgba(248,113,113,0.3);
        --shadow: 0 1px 2px rgba(0,0,0,0.4);
      }
    }
`;

const BASTION_MARK_SVG = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 2.5L20 6.5V13.2C20 17.6 16.5 20.8 12 22C7.5 20.8 4 17.6 4 13.2V6.5L12 2.5Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
  <path d="M9 12.2L11.1 14.3L15.3 9.9" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

const GOOGLE_MONO_SVG = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M21.35 12.23c0-.72-.06-1.41-.18-2.08H12v3.94h5.26a4.5 4.5 0 0 1-1.95 2.95v2.45h3.16c1.85-1.7 2.88-4.21 2.88-7.26Z" fill="currentColor" opacity="0.85"/>
  <path d="M12 21.75c2.63 0 4.84-.87 6.45-2.36l-3.16-2.45c-.87.58-1.99.93-3.29.93-2.53 0-4.68-1.71-5.45-4.01H3.29v2.52A9.75 9.75 0 0 0 12 21.75Z" fill="currentColor" opacity="0.7"/>
  <path d="M6.55 13.86A5.86 5.86 0 0 1 6.24 12c0-.64.11-1.27.31-1.86V7.62H3.29A9.75 9.75 0 0 0 2.25 12c0 1.57.38 3.06 1.04 4.38l3.26-2.52Z" fill="currentColor" opacity="0.55"/>
  <path d="M12 6.13c1.43 0 2.71.49 3.72 1.46l2.79-2.79C16.83 3.24 14.62 2.25 12 2.25a9.75 9.75 0 0 0-8.71 5.37l3.26 2.52c.77-2.3 2.92-4.01 5.45-4.01Z" fill="currentColor"/>
</svg>`;

const GITHUB_MONO_SVG = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
  <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.475 2 2 6.475 2 12a9.994 9.994 0 0 0 6.838 9.488c.5.087.687-.213.687-.475 0-.238-.012-1.025-.012-1.863-2.513.463-3.163-.612-3.363-1.175-.112-.287-.6-1.175-1.025-1.412-.35-.188-.85-.65-.012-.663.787-.012 1.35.725 1.537 1.025.9 1.513 2.338 1.088 2.913.825.087-.65.35-1.087.637-1.337-2.225-.25-4.55-1.113-4.55-4.938 0-1.087.388-1.987 1.025-2.687-.1-.25-.45-1.275.1-2.65 0 0 .838-.263 2.75 1.025a9.28 9.28 0 0 1 2.5-.338c.85 0 1.7.113 2.5.338 1.912-1.3 2.75-1.025 2.75-1.025.55 1.375.2 2.4.1 2.65.637.7 1.025 1.587 1.025 2.687 0 3.838-2.337 4.688-4.562 4.938.362.312.675.912.675 1.85 0 1.337-.013 2.412-.013 2.75 0 .262.188.574.688.474A10.016 10.016 0 0 0 22 12c0-5.525-4.475-10-10-10Z"/>
</svg>`;

function renderErrorHtml(title: string, message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} — GeminiBastionMCP</title>
  <style>
    ${EDITORIAL_THEME_CSS}
    * { box-sizing: border-box; }
    body { margin:0; font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif; background:var(--bg); color:var(--ink); display:flex; align-items:center; justify-content:center; min-height:100vh; padding:20px; -webkit-font-smoothing:antialiased; }
    .card { max-width:400px; width:100%; background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:32px; box-shadow:var(--shadow); }
    .mark { display:inline-flex; align-items:center; gap:8px; font-size:0.8125rem; font-weight:600; color:var(--ink); margin-bottom:20px; }
    h1 { margin:0 0 8px; font-size:1.125rem; font-weight:600; letter-spacing:-0.02em; color:var(--crimson); }
    p { margin:0; font-size:0.875rem; line-height:1.55; color:var(--ink-2); }
  </style>
</head>
<body>
  <main class="card">
    <div class="mark">${BASTION_MARK_SVG}<span>GeminiBastionMCP</span></div>
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
        <button class="btn-idp" type="submit">${GOOGLE_MONO_SVG}<span>Approve with Google</span></button>
      </form>`);
  }
  if (githubEnabled) {
    idpButtons.push(`<form method="POST" action="/auth/idp/github/start">
        <input type="hidden" name="purpose" value="mcp_authorize" />
        <input type="hidden" name="auth_req_id" value="${escapeHtml(authReq.auth_req_id)}" />
        <input type="hidden" name="csrf_token" value="${escapeHtml(authReq.csrf_token)}" />
        <button class="btn-idp" type="submit">${GITHUB_MONO_SVG}<span>Approve with GitHub</span></button>
      </form>`);
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authorize Access — GeminiBastionMCP</title>
  <style>
    ${EDITORIAL_THEME_CSS}
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif;
      background: var(--bg);
      color: var(--ink);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
      -webkit-font-smoothing: antialiased;
    }
    .card {
      max-width: 400px;
      width: 100%;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 32px;
      box-shadow: var(--shadow);
    }
    .top-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 20px;
    }
    .mark {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 0.8125rem;
      font-weight: 600;
      letter-spacing: -0.01em;
      color: var(--ink);
    }
    .badge {
      font-size: 0.6875rem;
      font-weight: 500;
      color: var(--muted);
      background: var(--subtle);
      border: 1px solid var(--border);
      padding: 2px 8px;
      border-radius: 999px;
    }
    h1 {
      margin: 0 0 6px;
      font-size: 1.25rem;
      font-weight: 600;
      letter-spacing: -0.02em;
      color: var(--ink);
    }
    .sub {
      margin: 0 0 18px;
      font-size: 0.875rem;
      color: var(--ink-2);
      line-height: 1.5;
    }
    .meta {
      background: var(--subtle);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 18px;
      overflow: hidden;
    }
    .meta-row {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 12px;
      padding: 8px 12px;
      font-size: 0.8125rem;
      border-bottom: 1px solid var(--border);
    }
    .meta-row:last-child { border-bottom: none; }
    .meta-k { color: var(--muted); flex-shrink: 0; }
    .meta-v {
      color: var(--ink);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.75rem;
      word-break: break-all;
      text-align: right;
    }
    .err {
      background: var(--crimson-bg);
      border: 1px solid var(--crimson-bd);
      color: var(--crimson);
      padding: 10px 12px;
      border-radius: 8px;
      font-size: 0.8125rem;
      line-height: 1.45;
      margin-bottom: 16px;
    }
    label {
      display: block;
      font-size: 0.8125rem;
      font-weight: 500;
      color: var(--ink-2);
      margin-bottom: 6px;
    }
    input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--ink);
      font-size: 0.9375rem;
      margin-bottom: 14px;
    }
    input[type="password"]:focus {
      outline: none;
      border-color: var(--ink);
    }
    .actions { display: flex; gap: 8px; }
    button {
      flex: 1;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      border: 1px solid transparent;
    }
    .btn-primary { background: var(--cta-bg); color: var(--cta-fg); }
    .btn-primary:hover { background: var(--cta-hover); }
    .btn-secondary {
      background: var(--surface);
      color: var(--ink-2);
      border-color: var(--border);
    }
    .btn-secondary:hover { background: var(--subtle); color: var(--ink); }
    .divider {
      display: flex;
      align-items: center;
      gap: 12px;
      margin: 18px 0;
      color: var(--muted);
      font-size: 0.75rem;
    }
    .divider::before, .divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }
    .idp-stack { display: flex; flex-direction: column; gap: 8px; }
    .btn-idp {
      width: 100%;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--ink);
    }
    .btn-idp:hover { background: var(--subtle); border-color: var(--border-strong); }
  </style>
</head>
<body>
  <main class="card">
    <div class="top-bar">
      <div class="mark">${BASTION_MARK_SVG}<span>GeminiBastionMCP</span></div>
      <span class="badge">OAuth 2.1 · PKCE</span>
    </div>
    <h1>Authorize ${escapeHtml(clientName)}</h1>
    <p class="sub">Approve MCP gateway access using your operator password${idpButtons.length > 0 ? ' or a verified upstream account' : ''}.</p>
    <div class="meta">
      <div class="meta-row"><span class="meta-k">Client ID</span><span class="meta-v">${escapeHtml(authReq.client_id)}</span></div>
      <div class="meta-row"><span class="meta-k">Redirect</span><span class="meta-v">${escapeHtml(redirectOrigin)}</span></div>
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
  const { config, oauthRepo, auditRepo } = deps;
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
