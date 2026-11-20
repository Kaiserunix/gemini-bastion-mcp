import { Hono } from 'hono';
import type { OAuthRepository } from '../db/repositories/oauthRepo.js';
import type { Repositories } from '../db/repositories/index.js';
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
import { createTokenRoutes } from './token.js';

export interface AuthDeps {
  config: GatewayConfig;
  db?: GatewayDatabase;
  repos: Pick<Repositories, 'oauth' | 'audit'>;
  rateLimitMaxAttempts?: number;
  rateLimitWindowMs?: number;
}

/**
 * Creates the Hono sub-app mounting OAuth 2.1 discovery, DCR, authorize, token, and revoke routes.
 */
export function createAuthApp(deps: AuthDeps): Hono {
  const { config, db, repos } = deps;
  const app = new Hono();

  ensureStaticClient(config, repos.oauth);

  const authorizeRateLimiter = new IpRateLimiter(
    deps.rateLimitMaxAttempts ?? 10,
    deps.rateLimitWindowMs ?? 60_000,
  );

  app.route('/', createDiscoveryRoutes(config));
  app.route(
    '/',
    createDcrRoutes({
      config,
      oauthRepo: repos.oauth,
      auditRepo: repos.audit,
    }),
  );
  app.route(
    '/',
    createAuthorizeRoutes({
      config,
      oauthRepo: repos.oauth,
      auditRepo: repos.audit,
      rateLimiter: authorizeRateLimiter,
    }),
  );
  app.route(
    '/',
    createTokenRoutes({
      config,
      db,
      oauthRepo: repos.oauth,
      auditRepo: repos.audit,
    }),
  );

  return app;
}

/**
 * Creates the `/mcp` OAuth 2.1 Bearer token validation middleware from AuthDeps or BearerMiddlewareDeps.
 */
export function createBearerMiddleware(
  deps: Pick<AuthDeps, 'config'> & ({ repos: Pick<Repositories, 'oauth'> } | { oauthRepo: OAuthRepository }),
) {
  const oauthRepo = 'oauthRepo' in deps ? deps.oauthRepo : deps.repos.oauth;
  return buildBearerMiddleware({
    config: deps.config,
    oauthRepo,
  });
}

export type { BearerMiddlewareDeps };

export {
  ensureStaticClient,
  isAllowedRedirectUri,
  isValidResource,
  getCanonicalResource,
  buildWwwAuthenticateHeader,
  IpRateLimiter,
  MAX_AUTH_BODY_BYTES,
  getClientIp,
  readLimitedBodyText,
};
export type { OAuthAuthContext };
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
