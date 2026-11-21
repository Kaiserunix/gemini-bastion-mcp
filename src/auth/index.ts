import { Hono } from 'hono';
import type { GatewayDatabase } from '../db/sqlite.js';
import type { GatewayConfig } from '../types.js';
import { createAuthorizeRoutes } from './authorize.js';
import { createDcrRoutes, ensureStaticClient, isAllowedRedirectUri } from './dcr.js';
import { createDiscoveryRoutes, getCanonicalResource, isValidResource } from './discovery.js';
import {
  buildWwwAuthenticateHeader,
  createBearerMiddleware as buildBearerMiddleware,
  type BearerMiddlewareDeps,
  type OAuthAuthContext,
} from './middleware.js';
import { IpRateLimiter, MAX_AUTH_BODY_BYTES, getClientIp, readLimitedBodyText } from './rateLimit.js';
import {
  DEFAULT_ADMIN_SESSION_TTL_MS,
  InMemoryOAuthStore,
  SignedCookieAdminSessionManager,
  type AdminSessionManager,
  type AuditLogger,
  type OAuthStore,
  type RateLimiter,
} from './store.js';
import { createTokenRoutes } from './token.js';
import { createUpstreamIdpRoutes } from './upstreamIdp.js';

export interface AuthDeps {
  config: GatewayConfig;
  db?: GatewayDatabase;
  oauthStore?: OAuthStore;
  auditLogger?: AuditLogger;
  sessionManager?: AdminSessionManager;
  repos?: { oauth: OAuthStore; audit?: AuditLogger };
  upstreamFetch?: typeof fetch;
  rateLimiter?: RateLimiter;
  rateLimitMaxAttempts?: number;
  rateLimitWindowMs?: number;
}

/**
 * Creates the Hono sub-app mounting OAuth 2.1 discovery, DCR, authorize, token, and revoke routes.
 */
export function createAuthApp(deps: AuthDeps): Hono {
  const { config, db } = deps;
  const oauthStore = deps.oauthStore ?? deps.repos?.oauth;
  if (!oauthStore) {
    throw new Error('createAuthApp requires oauthStore or repos.oauth');
  }
  const auditLogger = deps.auditLogger ?? deps.repos?.audit;
  const app = new Hono();

  ensureStaticClient(config, oauthStore);

  const authorizeRateLimiter =
    deps.rateLimiter ??
    new IpRateLimiter(
      deps.rateLimitMaxAttempts ?? 10,
      deps.rateLimitWindowMs ?? 60_000,
    );

  app.route('/', createDiscoveryRoutes(config));
  app.route(
    '/',
    createDcrRoutes({
      config,
      oauthStore,
      auditLogger,
    }),
  );
  app.route(
    '/',
    createAuthorizeRoutes({
      config,
      oauthStore,
      auditLogger,
      rateLimiter: authorizeRateLimiter,
    }),
  );
  app.route(
    '/',
    createTokenRoutes({
      config,
      db,
      oauthStore,
      auditLogger,
    }),
  );
  app.route(
    '/',
    createUpstreamIdpRoutes({
      config,
      oauthStore,
      auditLogger,
      sessionManager: deps.sessionManager,
      upstreamFetch: deps.upstreamFetch,
    }),
  );

  return app;
}

/**
 * Creates the `/mcp` OAuth 2.1 Bearer token validation middleware from AuthDeps or BearerMiddlewareDeps.
 */
export function createBearerMiddleware(
  deps: {
    config: GatewayConfig;
    oauthStore?: Pick<OAuthStore, 'getTokenByHash'>;
    oauthRepo?: Pick<OAuthStore, 'getTokenByHash'>;
    repos?: { oauth: Pick<OAuthStore, 'getTokenByHash'> };
  },
) {
  const oauthStore = deps.oauthStore ?? deps.oauthRepo ?? deps.repos?.oauth;
  if (!oauthStore) {
    throw new Error('createBearerMiddleware requires oauthStore, oauthRepo, or repos.oauth');
  }
  return buildBearerMiddleware({
    config: deps.config,
    oauthStore,
  });
}

export type {
  BearerMiddlewareDeps,
  OAuthStore,
  AuditLogger,
  RateLimiter,
  AdminSessionManager,
};

export {
  ensureStaticClient,
  isAllowedRedirectUri,
  isValidResource,
  getCanonicalResource,
  buildWwwAuthenticateHeader,
  IpRateLimiter,
  InMemoryOAuthStore,
  SignedCookieAdminSessionManager,
  DEFAULT_ADMIN_SESSION_TTL_MS,
  MAX_AUTH_BODY_BYTES,
  getClientIp,
  readLimitedBodyText,
};
export type { OAuthAuthContext };
export {
  ADMIN_SESSION_COOKIE_NAME,
  ADMIN_CSRF_COOKIE_NAME,
  MCP_AUTH_BIND_COOKIE_NAME,
  UPSTREAM_OAUTH_COOKIE_NAME,
  issueAdminSessionCookie,
  readAdminSessionCookie,
  clearAdminSessionCookie,
  setAdminCsrfCookie,
  readAdminCsrfCookie,
  clearAdminCsrfCookie,
  setMcpAuthBindCookie,
  readMcpAuthBindCookie,
  clearMcpAuthBindCookie,
  setUpstreamOAuthCookie,
  readUpstreamOAuthCookie,
  clearUpstreamOAuthCookie,
} from './cookies.js';
export {
  hashToken,
  hashPasswordScrypt,
  verifyPassword,
  computeS256Challenge,
  verifyPkceS256,
  generateRandomToken,
  generateRandomHex,
  signSessionCookie,
  verifySessionCookie,
  resolveSigningSecret,
} from './crypto.js';
