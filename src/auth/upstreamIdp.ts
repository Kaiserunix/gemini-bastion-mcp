import { Hono } from 'hono';
import type { Context } from 'hono';
import { isGitHubOAuthEnabled, isGoogleOAuthEnabled } from '../config.js';
import type { GatewayConfig, UpstreamOAuthProvider, UpstreamOAuthPurpose } from '../types.js';
import {
  clearAdminCsrfCookie,
  clearMcpAuthBindCookie,
  clearUpstreamOAuthCookie,
  issueAdminSessionCookie,
  readAdminCsrfCookie,
  readMcpAuthBindCookie,
  readUpstreamOAuthCookie,
  setUpstreamOAuthCookie,
} from './cookies.js';
import {
  computeS256Challenge,
  constantTimeEqual,
  generateRandomToken,
  hashToken,
} from './crypto.js';
import { getClientIp, IpRateLimiter, readLimitedBodyText } from './rateLimit.js';
import type { AdminSessionManager, AuditLogger, OAuthStore, RateLimiter } from './store.js';

const UPSTREAM_STATE_TTL_MS = 10 * 60 * 1000;
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;
const UPSTREAM_FETCH_TIMEOUT_MS = 10_000;

export interface UpstreamIdpDeps {
  config: GatewayConfig;
  oauthStore?: Pick<
    OAuthStore,
    | 'getAuthRequest'
    | 'consumeAuthRequest'
    | 'createUpstreamState'
    | 'consumeUpstreamState'
    | 'createCode'
  >;
  oauthRepo?: Pick<
    OAuthStore,
    | 'getAuthRequest'
    | 'consumeAuthRequest'
    | 'createUpstreamState'
    | 'consumeUpstreamState'
    | 'createCode'
  >;
  auditRepo?: AuditLogger;
  auditLogger?: AuditLogger;
  sessionManager?: AdminSessionManager;
  upstreamFetch?: typeof fetch;
  startRateLimiter?: RateLimiter;
  callbackRateLimiter?: RateLimiter;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function setIdpSecurityHeaders(c: Context): void {
  c.header(
    'Content-Security-Policy',
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
  );
  c.header('X-Frame-Options', 'DENY');
  c.header('X-Content-Type-Options', 'nosniff');
  c.header('Cache-Control', 'no-store');
}

function renderIdpErrorHtml(title: string, message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)} — GeminiBastionMCP</title>
  <style>
    :root {
      --bg: #FBFBFB;
      --surface: #FFFFFF;
      --border: #E4E4E7;
      --ink: #111113;
      --ink-2: #52525B;
      --crimson: #B91C1C;
      --shadow: 0 1px 2px rgba(17,17,19,0.04), 0 8px 24px rgba(17,17,19,0.03);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #09090B;
        --surface: #111113;
        --border: #27272A;
        --ink: #FAFAFA;
        --ink-2: #A1A1AA;
        --crimson: #F87171;
        --shadow: 0 1px 2px rgba(0,0,0,0.4);
      }
    }
    * { box-sizing: border-box; }
    body { margin:0; font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif; background:var(--bg); color:var(--ink); display:flex; align-items:center; justify-content:center; min-height:100vh; padding:20px; -webkit-font-smoothing:antialiased; }
    .card { max-width:400px; width:100%; background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:32px; box-shadow:var(--shadow); }
    .mark { display:inline-flex; align-items:center; gap:8px; font-size:0.8125rem; font-weight:600; color:var(--ink); margin-bottom:20px; }
    h1 { margin:0 0 8px; font-size:1.125rem; font-weight:600; letter-spacing:-0.02em; color:var(--crimson); }
    p { margin:0 0 20px; font-size:0.875rem; line-height:1.55; color:var(--ink-2); }
    a { display:inline-block; color:var(--ink); text-decoration:none; font-size:0.8125rem; font-weight:500; border:1px solid var(--border); padding:8px 12px; border-radius:8px; }
    a:hover { text-decoration:underline; }
  </style>
</head>
<body>
  <main class="card">
    <div class="mark"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 2.5L20 6.5V13.2C20 17.6 16.5 20.8 12 22C7.5 20.8 4 17.6 4 13.2V6.5L12 2.5Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M9 12.2L11.1 14.3L15.3 9.9" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg><span>GeminiBastionMCP</span></div>
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
    <a href="/admin/login">Return to Sign In</a>
  </main>
</body>
</html>`;
}

function parseProvider(raw: string | undefined): UpstreamOAuthProvider | null {
  if (raw === 'google' || raw === 'github') return raw;
  return null;
}

function isProviderEnabled(provider: UpstreamOAuthProvider, config: GatewayConfig): boolean {
  return provider === 'google' ? isGoogleOAuthEnabled(config) : isGitHubOAuthEnabled(config);
}

function getCallbackUrl(config: GatewayConfig, provider: UpstreamOAuthProvider): string {
  const base = config.publicDomain.replace(/\/+$/, '');
  return `${base}/auth/idp/${provider}/callback`;
}

/**
 * Mounts upstream operator IdP routes:
 * - `POST /auth/idp/:provider/start`
 * - `GET /auth/idp/:provider/callback`
 */
export function createUpstreamIdpRoutes(deps: UpstreamIdpDeps): Hono {
  const { config, sessionManager } = deps;
  const oauthRepo = deps.oauthStore ?? deps.oauthRepo;
  if (!oauthRepo) {
    throw new Error('createUpstreamIdpRoutes requires oauthStore or oauthRepo');
  }
  const auditRepo = deps.auditLogger ?? deps.auditRepo;
  const fetcher = deps.upstreamFetch ?? fetch;
  const startRateLimiter = deps.startRateLimiter ?? new IpRateLimiter(20, 60_000);
  const callbackRateLimiter = deps.callbackRateLimiter ?? new IpRateLimiter(30, 60_000);
  const app = new Hono();

  app.post('/auth/idp/:provider/start', async (c) => {
    setIdpSecurityHeaders(c);

    const provider = parseProvider(c.req.param('provider'));
    if (!provider || !isProviderEnabled(provider, config)) {
      return c.html(
        renderIdpErrorHtml('Provider Unavailable', 'The requested sign-in provider is not enabled.'),
        404,
      );
    }

    const ip = getClientIp(c, config.trustCfConnectingIp);
    const rate = startRateLimiter.consume(`idp-start:${ip}`);
    if (!rate.allowed) {
      c.header('Retry-After', String(rate.retryAfterSec));
      return c.html(
        renderIdpErrorHtml('Too Many Requests', 'Rate limit exceeded. Please wait before retrying.'),
        429,
      );
    }

    const bodyRead = await readLimitedBodyText(c);
    if (!bodyRead.ok) {
      return c.html(
        renderIdpErrorHtml('Payload Too Large', 'Request body exceeds 64KB limit.'),
        413,
      );
    }

    let purposeRaw = '';
    let submittedCsrf = '';
    let authReqId = '';

    const contentType = (c.req.header('content-type') ?? '').toLowerCase();
    if (contentType.includes('application/json')) {
      try {
        const json = JSON.parse(bodyRead.text) as Record<string, unknown>;
        purposeRaw = typeof json.purpose === 'string' ? json.purpose : '';
        submittedCsrf = typeof json.csrf_token === 'string' ? json.csrf_token : '';
        authReqId = typeof json.auth_req_id === 'string' ? json.auth_req_id : '';
      } catch {
        return c.html(renderIdpErrorHtml('Bad Request', 'Malformed JSON body.'), 400);
      }
    } else {
      const form = new URLSearchParams(bodyRead.text);
      purposeRaw = form.get('purpose') ?? '';
      submittedCsrf = form.get('csrf_token') ?? '';
      authReqId = form.get('auth_req_id') ?? '';
    }

    if (purposeRaw !== 'admin' && purposeRaw !== 'mcp_authorize') {
      return c.html(renderIdpErrorHtml('Invalid Request', 'Invalid upstream login purpose.'), 400);
    }
    const purpose: UpstreamOAuthPurpose = purposeRaw;

    if (purpose === 'admin') {
      const cookieCsrf = readAdminCsrfCookie(c);
      if (!cookieCsrf || !submittedCsrf || !constantTimeEqual(submittedCsrf, cookieCsrf)) {
        return c.html(renderIdpErrorHtml('Forbidden', 'Invalid login CSRF token.'), 403);
      }
    } else {
      if (!authReqId || !submittedCsrf) {
        return c.html(
          renderIdpErrorHtml('Invalid Request', 'Missing authorization request binding.'),
          400,
        );
      }

      const authReq = oauthRepo.getAuthRequest(authReqId);
      if (!authReq || authReq.used || authReq.expires_at <= Date.now()) {
        return c.html(
          renderIdpErrorHtml(
            'Request Expired',
            'This authorization request has expired or was already used.',
          ),
          400,
        );
      }

      if (!constantTimeEqual(submittedCsrf, authReq.csrf_token)) {
        return c.html(renderIdpErrorHtml('Forbidden', 'Invalid CSRF token.'), 403);
      }

      const bindCookie = readMcpAuthBindCookie(c);
      const expectedBind = hashToken(authReqId);
      if (!bindCookie || !constantTimeEqual(bindCookie, expectedBind)) {
        return c.html(
          renderIdpErrorHtml('Forbidden', 'Missing or invalid authorization session binding.'),
          403,
        );
      }
    }

    const state = generateRandomToken(32);
    const codeVerifier = generateRandomToken(32);
    const codeChallenge = computeS256Challenge(codeVerifier);
    const bindingNonce = generateRandomToken(32);
    const bindingHash = hashToken(bindingNonce);
    const now = Date.now();

    oauthRepo.createUpstreamState({
      state,
      provider,
      purpose,
      auth_req_id: purpose === 'mcp_authorize' ? authReqId : null,
      code_verifier: codeVerifier,
      binding_hash: bindingHash,
      expires_at: now + UPSTREAM_STATE_TTL_MS,
      created_at: now,
    });

    setUpstreamOAuthCookie(c, config, bindingNonce);

    const callbackUrl = getCallbackUrl(config, provider);
    if (provider === 'google') {
      const target = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      target.searchParams.set('client_id', config.googleOAuthClientId!);
      target.searchParams.set('redirect_uri', callbackUrl);
      target.searchParams.set('response_type', 'code');
      target.searchParams.set('scope', 'openid email profile');
      target.searchParams.set('state', state);
      target.searchParams.set('code_challenge', codeChallenge);
      target.searchParams.set('code_challenge_method', 'S256');
      target.searchParams.set('prompt', 'select_account');
      return c.redirect(target.toString(), 302);
    }

    const target = new URL('https://github.com/login/oauth/authorize');
    target.searchParams.set('client_id', config.githubOAuthClientId!);
    target.searchParams.set('redirect_uri', callbackUrl);
    target.searchParams.set('scope', 'read:user');
    target.searchParams.set('state', state);
    target.searchParams.set('code_challenge', codeChallenge);
    target.searchParams.set('code_challenge_method', 'S256');
    target.searchParams.set('allow_signup', 'false');
    return c.redirect(target.toString(), 302);
  });

  app.get('/auth/idp/:provider/callback', async (c) => {
    setIdpSecurityHeaders(c);

    const bindingNonce = readUpstreamOAuthCookie(c);
    clearUpstreamOAuthCookie(c);

    const provider = parseProvider(c.req.param('provider'));
    if (!provider || !isProviderEnabled(provider, config)) {
      return c.html(
        renderIdpErrorHtml('Provider Unavailable', 'The requested sign-in provider is not enabled.'),
        404,
      );
    }

    const ip = getClientIp(c, config.trustCfConnectingIp);
    const rate = callbackRateLimiter.consume(`idp-cb:${ip}`);
    if (!rate.allowed) {
      c.header('Retry-After', String(rate.retryAfterSec));
      return c.html(
        renderIdpErrorHtml('Too Many Requests', 'Rate limit exceeded. Please wait before retrying.'),
        429,
      );
    }

    const rawUpstreamError = c.req.query('error');
    if (rawUpstreamError) {
      const sanitizedError = /^[A-Za-z0-9_.-]{1,64}$/.test(rawUpstreamError)
        ? rawUpstreamError
        : 'upstream_error';
      auditRepo?.record({
        actor: `idp:${provider}`,
        action: 'idp_callback_error',
        target: provider,
        status: 'failure',
        details: { error: sanitizedError, ip },
      });
      return c.html(
        renderIdpErrorHtml(
          'Sign-In Cancelled',
          'Sign-in was cancelled or denied by the upstream provider.',
        ),
        403,
      );
    }

    const code = c.req.query('code');
    const state = c.req.query('state');
    if (!code || !state || !bindingNonce) {
      return c.html(
        renderIdpErrorHtml('Invalid Callback', 'Missing OAuth callback code, state, or session binding.'),
        403,
      );
    }

    const upstreamState = oauthRepo.consumeUpstreamState(state, provider, hashToken(bindingNonce));
    if (!upstreamState) {
      auditRepo?.record({
        actor: `idp:${provider}`,
        action: 'idp_state_rejected',
        target: provider,
        status: 'denied',
        details: { ip },
      });
      return c.html(
        renderIdpErrorHtml('Forbidden', 'Upstream OAuth state is invalid, expired, or already used.'),
        403,
      );
    }

    const callbackUrl = getCallbackUrl(config, provider);
    let actor = '';

    try {
      if (provider === 'google') {
        const tokenRes = await fetcher('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json',
          },
          body: new URLSearchParams({
            code,
            client_id: config.googleOAuthClientId!,
            client_secret: config.googleOAuthClientSecret!,
            redirect_uri: callbackUrl,
            grant_type: 'authorization_code',
            code_verifier: upstreamState.code_verifier,
          }).toString(),
          signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
        });

        if (!tokenRes.ok) {
          throw new Error(`Google token exchange failed with status ${tokenRes.status}`);
        }
        const tokenJson = (await tokenRes.json()) as { access_token?: unknown };
        if (typeof tokenJson.access_token !== 'string' || !tokenJson.access_token) {
          throw new Error('Google token response missing access_token');
        }

        const userRes = await fetcher('https://openidconnect.googleapis.com/v1/userinfo', {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${tokenJson.access_token}`,
            Accept: 'application/json',
          },
          signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
        });
        if (!userRes.ok) {
          throw new Error(`Google userinfo failed with status ${userRes.status}`);
        }
        const userJson = (await userRes.json()) as {
          email?: unknown;
          email_verified?: unknown;
        };

        const normalizedEmail =
          typeof userJson.email === 'string' ? userJson.email.trim().toLowerCase() : '';
        const emailVerified = userJson.email_verified === true;
        const allowed =
          emailVerified &&
          normalizedEmail.length > 0 &&
          config.googleOAuthAllowedEmails.includes(normalizedEmail);

        if (!allowed) {
          auditRepo?.record({
            actor: `google:${normalizedEmail || 'unknown'}`,
            action: 'idp_allowlist_denied',
            target: upstreamState.purpose,
            status: 'denied',
            details: { provider: 'google', email_verified: emailVerified, ip },
          });
          return c.html(
            renderIdpErrorHtml(
              'Access Denied',
              'Your Google account is not authorized for this gateway.',
            ),
            403,
          );
        }

        actor = `google:${normalizedEmail}`;
      } else {
        const tokenRes = await fetcher('https://github.com/login/oauth/access_token', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Accept: 'application/json',
          },
          body: new URLSearchParams({
            client_id: config.githubOAuthClientId!,
            client_secret: config.githubOAuthClientSecret!,
            code,
            redirect_uri: callbackUrl,
            code_verifier: upstreamState.code_verifier,
          }).toString(),
          signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
        });

        if (!tokenRes.ok) {
          throw new Error(`GitHub token exchange failed with status ${tokenRes.status}`);
        }
        const tokenJson = (await tokenRes.json()) as { access_token?: unknown };
        if (typeof tokenJson.access_token !== 'string' || !tokenJson.access_token) {
          throw new Error('GitHub token response missing access_token');
        }

        const userRes = await fetcher('https://api.github.com/user', {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${tokenJson.access_token}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'GeminiBastionMCP',
          },
          signal: AbortSignal.timeout(UPSTREAM_FETCH_TIMEOUT_MS),
        });
        if (!userRes.ok) {
          throw new Error(`GitHub user fetch failed with status ${userRes.status}`);
        }
        const userJson = (await userRes.json()) as { id?: unknown; login?: unknown };

        const normalizedLogin =
          typeof userJson.login === 'string' ? userJson.login.trim().toLowerCase() : '';
        const normalizedId =
          typeof userJson.id === 'number' || typeof userJson.id === 'string'
            ? String(userJson.id).trim()
            : '';

        const hasUsers = config.githubOAuthAllowedUsers.length > 0;
        const hasIds = config.githubOAuthAllowedIds.length > 0;
        const userMatch =
          normalizedLogin.length > 0 && config.githubOAuthAllowedUsers.includes(normalizedLogin);
        const idMatch =
          normalizedId.length > 0 && config.githubOAuthAllowedIds.includes(normalizedId);

        const allowed =
          (hasUsers || hasIds) &&
          (hasUsers && hasIds ? userMatch && idMatch : hasUsers ? userMatch : idMatch);

        if (!allowed) {
          auditRepo?.record({
            actor: `github:${normalizedLogin || normalizedId || 'unknown'}`,
            action: 'idp_allowlist_denied',
            target: upstreamState.purpose,
            status: 'denied',
            details: { provider: 'github', github_id: normalizedId, ip },
          });
          return c.html(
            renderIdpErrorHtml(
              'Access Denied',
              'Your GitHub account is not authorized for this gateway.',
            ),
            403,
          );
        }

        actor = `github:${normalizedLogin || normalizedId}`;
      }
    } catch (err) {
      auditRepo?.record({
        actor: `idp:${provider}`,
        action: 'idp_exchange_error',
        target: upstreamState.purpose,
        status: 'failure',
        details: {
          provider,
          error: err instanceof Error ? err.message : 'Upstream exchange error',
          ip,
        },
      });
      return c.html(
        renderIdpErrorHtml(
          'Upstream Sign-In Failed',
          'Could not verify identity with the upstream provider. Please try again.',
        ),
        502,
      );
    }

    if (upstreamState.purpose === 'admin') {
      issueAdminSessionCookie(c, config, Date.now(), sessionManager);
      clearAdminCsrfCookie(c);
      auditRepo?.record({
        actor,
        action: 'admin.login.oauth',
        target: 'admin_console',
        status: 'success',
        details: { provider, ip },
      });
      return c.redirect('/admin', 302);
    }

    // purpose === 'mcp_authorize'
    if (!upstreamState.auth_req_id) {
      return c.html(
        renderIdpErrorHtml('Invalid Request', 'Missing linked MCP authorization request.'),
        400,
      );
    }

    const authReq = oauthRepo.consumeAuthRequest(upstreamState.auth_req_id);
    if (!authReq) {
      return c.html(
        renderIdpErrorHtml(
          'Request Expired',
          'This authorization request has expired or was already used.',
        ),
        400,
      );
    }

    clearMcpAuthBindCookie(c);

    const mcpCode = generateRandomToken(32);
    oauthRepo.createCode({
      code: mcpCode,
      client_id: authReq.client_id,
      redirect_uri: authReq.redirect_uri,
      code_challenge: authReq.code_challenge,
      scope: authReq.scope,
      resource: authReq.resource,
      expires_at: Date.now() + AUTH_CODE_TTL_MS,
    });

    auditRepo?.record({
      actor,
      action: 'oauth.authorize.approved',
      target: authReq.client_id,
      status: 'success',
      details: {
        provider,
        scope: authReq.scope,
        resource: authReq.resource,
        ip,
      },
    });

    const redirectUrl = new URL(authReq.redirect_uri);
    redirectUrl.searchParams.set('code', mcpCode);
    if (authReq.state !== null) {
      redirectUrl.searchParams.set('state', authReq.state);
    }

    return c.redirect(redirectUrl.toString(), 302);
  });

  return app;
}
