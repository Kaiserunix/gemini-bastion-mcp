import type { MiddlewareHandler } from 'hono';
import type { GatewayConfig } from '../types.js';
import { hashToken } from './crypto.js';
import { isValidResource } from './discovery.js';
import type { OAuthStore } from './store.js';

export interface OAuthAuthContext {
  clientId: string;
  scope: string;
  resource: string | null;
  tokenFamilyId: string;
}

export interface BearerMiddlewareDeps {
  config: GatewayConfig;
  oauthStore?: Pick<OAuthStore, 'getTokenByHash'>;
  oauthRepo?: Pick<OAuthStore, 'getTokenByHash'>;
}

/**
 * Builds the exact RFC 9728 `WWW-Authenticate` header required by MCP OAuth 2.1 clients.
 */
export function buildWwwAuthenticateHeader(publicDomain: string): string {
  const base = publicDomain.replace(/\/+$/, '');
  return `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource"`;
}

/**
 * Hono Bearer authentication middleware for `/mcp`.
 * Validates token presence, SHA-256 hash lookup, expiration, revocation, and RFC 8707 resource audience.
 */
export function createBearerMiddleware(deps: BearerMiddlewareDeps): MiddlewareHandler {
  const { config } = deps;
  const oauthStore = deps.oauthStore ?? deps.oauthRepo;
  if (!oauthStore) {
    throw new Error('createBearerMiddleware requires oauthStore or oauthRepo');
  }
  const wwwAuth = buildWwwAuthenticateHeader(config.publicDomain);

  return async (c, next) => {
    const authHeader = c.req.header('authorization');
    if (!authHeader) {
      c.header('WWW-Authenticate', wwwAuth);
      c.header('Cache-Control', 'no-store');
      return c.json({ error: 'unauthorized', error_description: 'Missing Authorization header' }, 401);
    }

    const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
    if (!match || !match[1]) {
      c.header('WWW-Authenticate', wwwAuth);
      c.header('Cache-Control', 'no-store');
      return c.json({ error: 'unauthorized', error_description: 'Invalid Bearer token format' }, 401);
    }

    const rawToken = match[1].trim();
    const tokenRecord = oauthStore.getTokenByHash(hashToken(rawToken));
    const now = Date.now();

    if (
      !tokenRecord ||
      tokenRecord.token_type !== 'access' ||
      tokenRecord.revoked ||
      tokenRecord.expires_at <= now
    ) {
      c.header('WWW-Authenticate', wwwAuth);
      c.header('Cache-Control', 'no-store');
      return c.json(
        { error: 'invalid_token', error_description: 'Access token is invalid, expired, or revoked' },
        401,
      );
    }

    if (tokenRecord.resource === null || !isValidResource(tokenRecord.resource, config.publicDomain)) {
      c.header('WWW-Authenticate', wwwAuth);
      c.header('Cache-Control', 'no-store');
      return c.json(
        { error: 'invalid_token', error_description: 'Token resource audience mismatch' },
        401,
      );
    }

    const authContext: OAuthAuthContext = {
      clientId: tokenRecord.client_id,
      scope: tokenRecord.scope,
      resource: tokenRecord.resource,
      tokenFamilyId: tokenRecord.token_family_id,
    };
    c.set('oauthAuth', authContext);

    await next();
  };
}
