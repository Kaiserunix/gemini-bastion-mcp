import { Hono } from 'hono';
import type { GatewayConfig, OAuthClient } from '../types.js';
import { generateId, generateRandomToken, hashToken } from './crypto.js';
import { getClientIp, IpRateLimiter, readLimitedBodyText } from './rateLimit.js';
import type { AuditLogger, OAuthStore, RateLimiter } from './store.js';

export const MAX_DCR_REDIRECT_URIS = 16;
export const MAX_DYNAMIC_CLIENTS = 500;

export const STATIC_GOOGLE_REDIRECT_PATTERNS = [
  'https://oauth-redirect.googleusercontent.com/r/*',
  'https://oauth-redirect.googleusercontent.com/a/*',
  'https://oauth-redirect-sandbox.googleusercontent.com/*',
  'https://oauth-redirect-test.googleusercontent.com/*',
  'https://vertexaisearch.cloud.google.com/oauth-redirect',
] as const;

/**
 * Validates whether a redirect URI is permitted by the strict Gemini/Google, loopback,
 * and `OAUTH_ALLOWED_REDIRECT_HOSTS` allowlist.
 */
export function isAllowedRedirectUri(uri: string, allowedHosts: string[]): boolean {
  if (!uri || uri.includes('#') || uri.includes('*') || uri.includes('\\')) {
    return false;
  }
  if (/[\s\x00-\x1f\x7f]/.test(uri)) {
    return false;
  }

  const schemeEnd = uri.indexOf('://');
  if (schemeEnd <= 0) {
    return false;
  }
  const afterScheme = uri.slice(schemeEnd + 3);
  const authorityEnd = afterScheme.search(/[/?#]/);
  const authority = authorityEnd === -1 ? afterScheme : afterScheme.slice(0, authorityEnd);
  if (!authority || authority.includes('@')) {
    return false;
  }

  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  if (parsed.hash !== '' || parsed.username !== '' || parsed.password !== '') {
    return false;
  }

  const protocol = parsed.protocol.toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  if (!hostname || hostname.includes('%')) {
    return false;
  }

  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return protocol === 'http:' || protocol === 'https:';
  }

  if (protocol !== 'https:') {
    return false;
  }

  const rawPathAndQuery = authorityEnd === -1 ? '' : afterScheme.slice(authorityEnd);
  const queryStart = rawPathAndQuery.indexOf('?');
  const rawPath = queryStart === -1 ? rawPathAndQuery : rawPathAndQuery.slice(0, queryStart);
  const hasEncodedTraversal = /%2e|%2f|%5c/i.test(rawPath) || rawPath.includes('..');

  if (hostname === 'oauth-redirect.googleusercontent.com') {
    if (hasEncodedTraversal) {
      return false;
    }
    return parsed.pathname.startsWith('/r/') || parsed.pathname.startsWith('/a/');
  }

  if (
    hostname === 'oauth-redirect-sandbox.googleusercontent.com' ||
    hostname === 'oauth-redirect-test.googleusercontent.com'
  ) {
    return true;
  }

  if (hostname === 'vertexaisearch.cloud.google.com') {
    if (hasEncodedTraversal) {
      return false;
    }
    return (
      parsed.pathname === '/oauth-redirect' || parsed.pathname.startsWith('/oauth-redirect/')
    );
  }

  const normalizedHosts = allowedHosts.map((h) => h.trim().toLowerCase());
  return normalizedHosts.includes(hostname);
}

/**
 * Upserts the pre-configured static fallback OAuth client (`OAUTH_STATIC_CLIENT_ID`) on startup,
 * and retires any stale static clients whose ID no longer matches config.
 */
export function ensureStaticClient(
  config: GatewayConfig,
  oauthStore: Pick<OAuthStore, 'retireStaleStaticClients' | 'upsertStaticClient'>,
): OAuthClient | null {
  oauthStore.retireStaleStaticClients(config.oauthStaticClientId);

  if (!config.oauthStaticClientId) {
    return null;
  }

  const secretHash = config.oauthStaticClientSecret
    ? hashToken(config.oauthStaticClientSecret)
    : null;

  return oauthStore.upsertStaticClient({
    client_id: config.oauthStaticClientId,
    client_secret_hash: secretHash,
    client_name: 'Static Fallback Client',
    redirect_uris: [...STATIC_GOOGLE_REDIRECT_PATTERNS],
  });
}

export interface DcrDeps {
  config: GatewayConfig;
  oauthStore?: Pick<OAuthStore, 'listClients' | 'createClient'>;
  oauthRepo?: Pick<OAuthStore, 'listClients' | 'createClient'>;
  auditRepo?: AuditLogger;
  auditLogger?: AuditLogger;
  registerRateLimiter?: RateLimiter;
  maxDynamicClients?: number;
}

/**
 * Mounts RFC 7591 Dynamic Client Registration (`POST /oauth/register`).
 */
export function createDcrRoutes(deps: DcrDeps): Hono {
  const { config } = deps;
  const oauthRepo = deps.oauthStore ?? deps.oauthRepo;
  if (!oauthRepo) {
    throw new Error('createDcrRoutes requires oauthStore or oauthRepo');
  }
  const auditRepo = deps.auditLogger ?? deps.auditRepo;
  const registerRateLimiter = deps.registerRateLimiter ?? new IpRateLimiter(20, 60_000);
  const maxDynamicClients = deps.maxDynamicClients ?? MAX_DYNAMIC_CLIENTS;
  const app = new Hono();

  app.post('/oauth/register', async (c) => {
    const ip = getClientIp(c, config.trustCfConnectingIp);
    const rate = registerRateLimiter.consume(`register:${ip}`);
    if (!rate.allowed) {
      c.header('Retry-After', String(rate.retryAfterSec));
      return c.json(
        { error: 'too_many_requests', error_description: 'Dynamic client registration rate limit exceeded' },
        429,
      );
    }

    const bodyRead = await readLimitedBodyText(c);
    if (!bodyRead.ok) {
      return c.json(
        { error: 'invalid_request', error_description: 'Request body exceeds 64KB limit' },
        413,
      );
    }

    let body: unknown;
    try {
      body = JSON.parse(bodyRead.text);
    } catch {
      return c.json(
        { error: 'invalid_client_metadata', error_description: 'Request body must be valid JSON' },
        400,
      );
    }

    const existingDynamicCount = oauthRepo.listClients().filter((client) => !client.is_static).length;
    if (existingDynamicCount >= maxDynamicClients) {
      return c.json(
        {
          error: 'too_many_requests',
          error_description: 'Maximum dynamic client registration capacity reached',
        },
        429,
      );
    }

    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return c.json(
        { error: 'invalid_client_metadata', error_description: 'Metadata must be a JSON object' },
        400,
      );
    }

    const payload = body as Record<string, unknown>;

    if (!Array.isArray(payload.redirect_uris) || payload.redirect_uris.length === 0) {
      return c.json(
        {
          error: 'invalid_redirect_uri',
          error_description: 'redirect_uris must be a non-empty array of URIs',
        },
        400,
      );
    }

    if (payload.redirect_uris.length > MAX_DCR_REDIRECT_URIS) {
      return c.json(
        {
          error: 'invalid_redirect_uri',
          error_description: `At most ${MAX_DCR_REDIRECT_URIS} redirect_uris are allowed per client`,
        },
        400,
      );
    }

    const redirectUris: string[] = [];
    for (const item of payload.redirect_uris) {
      if (typeof item !== 'string' || !isAllowedRedirectUri(item, config.oauthAllowedRedirectHosts)) {
        return c.json(
          {
            error: 'invalid_redirect_uri',
            error_description: `Disallowed or invalid redirect_uri: ${String(item)}`,
          },
          400,
        );
      }
      redirectUris.push(item);
    }

    const authMethodRaw = payload.token_endpoint_auth_method ?? 'none';
    if (authMethodRaw !== 'none' && authMethodRaw !== 'client_secret_post') {
      return c.json(
        {
          error: 'invalid_client_metadata',
          error_description:
            'Unsupported token_endpoint_auth_method; supported values are "none" and "client_secret_post"',
        },
        400,
      );
    }
    const authMethod = authMethodRaw;

    if (payload.grant_types !== undefined) {
      if (
        !Array.isArray(payload.grant_types) ||
        payload.grant_types.some((g) => g !== 'authorization_code' && g !== 'refresh_token')
      ) {
        return c.json(
          {
            error: 'invalid_client_metadata',
            error_description: 'Unsupported grant_types; allowed: authorization_code, refresh_token',
          },
          400,
        );
      }
    }

    if (payload.response_types !== undefined) {
      if (!Array.isArray(payload.response_types) || payload.response_types.some((r) => r !== 'code')) {
        return c.json(
          {
            error: 'invalid_client_metadata',
            error_description: 'Unsupported response_types; allowed: code',
          },
          400,
        );
      }
    }

    const clientName =
      typeof payload.client_name === 'string' && payload.client_name.trim().length > 0
        ? payload.client_name.trim().slice(0, 200)
        : 'MCP OAuth Client';

    const clientId = generateId('dcr', 16);
    const clientSecret = authMethod === 'client_secret_post' ? generateRandomToken(32) : undefined;
    const clientSecretHash = clientSecret ? hashToken(clientSecret) : null;
    const createdAt = Date.now();

    oauthRepo.createClient({
      client_id: clientId,
      client_secret_hash: clientSecretHash,
      client_name: clientName,
      redirect_uris: redirectUris,
      is_static: false,
      created_at: createdAt,
    });

    auditRepo?.record({
      actor: 'oauth_dcr',
      action: 'oauth_client_register',
      target: clientId,
      status: 'success',
      details: {
        client_name: clientName,
        redirect_uri_count: redirectUris.length,
        token_endpoint_auth_method: authMethod,
      },
      created_at: createdAt,
    });

    const responseBody: Record<string, unknown> = {
      client_id: clientId,
      client_id_issued_at: Math.floor(createdAt / 1000),
      client_name: clientName,
      redirect_uris: redirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: authMethod,
    };

    if (clientSecret) {
      responseBody.client_secret = clientSecret;
      responseBody.client_secret_expires_at = 0;
    }

    return c.json(responseBody, 201, {
      'Cache-Control': 'no-store',
    });
  });

  return app;
}
