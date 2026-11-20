import { Hono } from 'hono';
import type { Context } from 'hono';
import type { AuditRepository } from '../db/repositories/auditRepo.js';
import type { OAuthRepository } from '../db/repositories/oauthRepo.js';
import type { GatewayDatabase } from '../db/sqlite.js';
import type { GatewayConfig, OAuthClient } from '../types.js';
import {
  constantTimeEqual,
  generateRandomHex,
  generateRandomToken,
  hashToken,
  verifyPkceS256,
} from './crypto.js';
import { getCanonicalResource, isValidResource } from './discovery.js';
import { getClientIp, IpRateLimiter, readLimitedBodyText } from './rateLimit.js';

export interface TokenDeps {
  config: GatewayConfig;
  db?: GatewayDatabase;
  oauthRepo: OAuthRepository;
  auditRepo?: AuditRepository;
  tokenRateLimiter?: IpRateLimiter;
  revokeRateLimiter?: IpRateLimiter;
}

type ParamMap = Record<string, string | undefined>;

type ParseParamsResult =
  | { ok: true; params: ParamMap }
  | { ok: false; status: 400 | 413 };

async function parseTokenParams(c: Context): Promise<ParseParamsResult> {
  const bodyRead = await readLimitedBodyText(c);
  if (!bodyRead.ok) {
    return { ok: false, status: 413 };
  }

  const rawText = bodyRead.text;
  const contentType = (c.req.header('content-type') ?? '').toLowerCase();

  if (contentType.includes('application/json')) {
    try {
      const json = JSON.parse(rawText) as unknown;
      if (!json || typeof json !== 'object' || Array.isArray(json)) {
        return { ok: false, status: 400 };
      }
      const out: ParamMap = {};
      for (const [k, v] of Object.entries(json as Record<string, unknown>)) {
        if (typeof v === 'string') out[k] = v;
      }
      return { ok: true, params: out };
    } catch {
      return { ok: false, status: 400 };
    }
  }

  if (!rawText) return { ok: true, params: {} };

  // Fallback to JSON if caller sent JSON without Content-Type header
  const trimmed = rawText.trim();
  if (trimmed.startsWith('{')) {
    try {
      const json = JSON.parse(trimmed) as unknown;
      if (json && typeof json === 'object' && !Array.isArray(json)) {
        const out: ParamMap = {};
        for (const [k, v] of Object.entries(json as Record<string, unknown>)) {
          if (typeof v === 'string') out[k] = v;
        }
        return { ok: true, params: out };
      }
    } catch {
      // Fall through to URLSearchParams parsing
    }
  }

  const search = new URLSearchParams(rawText);
  const out: ParamMap = {};
  for (const [k, v] of search.entries()) {
    out[k] = v;
  }
  return { ok: true, params: out };
}

function extractClientCredentials(c: Context, params: ParamMap): {
  clientId?: string;
  clientSecret?: string;
} {
  let clientId = params.client_id;
  let clientSecret = params.client_secret;

  const authHeader = c.req.header('authorization');
  if (!clientId && authHeader && authHeader.toLowerCase().startsWith('basic ')) {
    try {
      const decoded = Buffer.from(authHeader.slice(6).trim(), 'base64').toString('utf8');
      const colonIdx = decoded.indexOf(':');
      if (colonIdx > 0) {
        clientId = decodeURIComponent(decoded.slice(0, colonIdx));
        clientSecret = decodeURIComponent(decoded.slice(colonIdx + 1));
      }
    } catch {
      // Ignore malformed Basic header
    }
  }

  return { clientId, clientSecret };
}

function authenticateClient(
  client: OAuthClient | null,
  providedSecret: string | undefined,
): boolean {
  if (!client) return false;
  if (client.client_secret_hash === null) {
    return true;
  }
  if (!providedSecret) return false;
  return constantTimeEqual(hashToken(providedSecret), client.client_secret_hash);
}

function oauthError(
  c: Context,
  status: 400 | 401 | 413 | 429,
  error: string,
  description: string,
): Response {
  return c.json(
    {
      error,
      error_description: description,
    },
    status,
    {
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
    },
  );
}

/**
 * Mounts `POST /oauth/token` and `POST /oauth/revoke`.
 */
export function createTokenRoutes(deps: TokenDeps): Hono {
  const { config, db, oauthRepo, auditRepo } = deps;
  const tokenRateLimiter = deps.tokenRateLimiter ?? new IpRateLimiter(120, 60_000);
  const revokeRateLimiter = deps.revokeRateLimiter ?? new IpRateLimiter(60, 60_000);
  const canonicalResource = getCanonicalResource(config.publicDomain);
  const app = new Hono();

  const runTx = <T>(fn: () => T): T => (db ? db.transaction(fn)() : fn());

  app.post('/oauth/token', async (c) => {
    const ip = getClientIp(c, config.trustCfConnectingIp);
    const rate = tokenRateLimiter.consume(`token:${ip}`);
    if (!rate.allowed) {
      c.header('Retry-After', String(rate.retryAfterSec));
      return oauthError(c, 429, 'too_many_requests', 'Token rate limit exceeded');
    }

    const parsed = await parseTokenParams(c);
    if (!parsed.ok) {
      return oauthError(
        c,
        parsed.status,
        'invalid_request',
        parsed.status === 413 ? 'Request body exceeds 64KB limit' : 'Malformed request body',
      );
    }

    const params = parsed.params;
    const grantType = params.grant_type;
    if (grantType !== 'authorization_code' && grantType !== 'refresh_token') {
      return oauthError(
        c,
        400,
        'unsupported_grant_type',
        'Supported grant_type values are authorization_code and refresh_token',
      );
    }

    const { clientId, clientSecret } = extractClientCredentials(c, params);

    if (grantType === 'authorization_code') {
      const code = params.code;
      const redirectUri = params.redirect_uri;
      const codeVerifier = params.code_verifier;
      const requestedResource = params.resource;

      if (!clientId || !code || !redirectUri || !codeVerifier) {
        return oauthError(
          c,
          400,
          'invalid_request',
          'Missing required parameters: code, redirect_uri, client_id, code_verifier',
        );
      }

      const client = oauthRepo.getClient(clientId);
      if (!client) {
        return oauthError(c, 401, 'invalid_client', 'Unknown client_id');
      }
      if (!authenticateClient(client, clientSecret)) {
        return oauthError(c, 401, 'invalid_client', 'Client authentication failed');
      }

      type AuthCodeIssueResult =
        | { ok: true; accessToken: string; refreshToken: string; scope: string }
        | { ok: false; status: 400; error: string; description: string };

      const issueResult = runTx((): AuthCodeIssueResult => {
        const now = Date.now();
        const authCode = oauthRepo.getCode(code);
        if (!authCode || authCode.used || authCode.expires_at <= now) {
          return {
            ok: false,
            status: 400,
            error: 'invalid_grant',
            description: 'Authorization code is invalid, expired, or already used',
          };
        }

        if (authCode.client_id !== client.client_id) {
          return {
            ok: false,
            status: 400,
            error: 'invalid_grant',
            description: 'Authorization code was not issued to this client',
          };
        }

        if (authCode.redirect_uri !== redirectUri) {
          return {
            ok: false,
            status: 400,
            error: 'invalid_grant',
            description: 'redirect_uri mismatch',
          };
        }

        if (!verifyPkceS256(codeVerifier, authCode.code_challenge)) {
          return {
            ok: false,
            status: 400,
            error: 'invalid_grant',
            description: 'PKCE code_verifier verification failed',
          };
        }

        let effectiveResource = authCode.resource ?? canonicalResource;
        if (requestedResource !== undefined && requestedResource.length > 0) {
          if (authCode.resource !== null && requestedResource !== authCode.resource) {
            return {
              ok: false,
              status: 400,
              error: 'invalid_target',
              description: 'Token request resource does not match authorization request resource',
            };
          }
          if (!isValidResource(requestedResource, config.publicDomain)) {
            return {
              ok: false,
              status: 400,
              error: 'invalid_target',
              description: 'Requested resource is not valid for this server',
            };
          }
          effectiveResource = requestedResource;
        }

        const consumed = oauthRepo.consumeCode(code, now);
        if (!consumed) {
          return {
            ok: false,
            status: 400,
            error: 'invalid_grant',
            description: 'Authorization code is invalid, expired, or already used',
          };
        }

        const familyId = generateRandomHex(16);
        const accessToken = generateRandomToken(32);
        const refreshToken = generateRandomToken(32);

        oauthRepo.createToken({
          token_hash: hashToken(accessToken),
          token_type: 'access',
          client_id: client.client_id,
          scope: consumed.scope,
          resource: effectiveResource,
          token_family_id: familyId,
          expires_at: now + config.oauthAccessTokenTtlSec * 1000,
          grace_expires_at: null,
          created_at: now,
        });

        oauthRepo.createToken({
          token_hash: hashToken(refreshToken),
          token_type: 'refresh',
          client_id: client.client_id,
          scope: consumed.scope,
          resource: effectiveResource,
          token_family_id: familyId,
          expires_at: now + config.oauthRefreshTokenTtlSec * 1000,
          grace_expires_at: null,
          created_at: now,
        });

        auditRepo?.record({
          actor: client.client_id,
          action: 'oauth_token_issue',
          target: familyId,
          status: 'success',
          details: {
            grant_type: 'authorization_code',
            scope: consumed.scope,
            resource: effectiveResource,
          },
          created_at: now,
        });

        return {
          ok: true,
          accessToken,
          refreshToken,
          scope: consumed.scope,
        };
      });

      if (!issueResult.ok) {
        return oauthError(c, issueResult.status, issueResult.error, issueResult.description);
      }

      return c.json(
        {
          access_token: issueResult.accessToken,
          token_type: 'Bearer',
          expires_in: config.oauthAccessTokenTtlSec,
          refresh_token: issueResult.refreshToken,
          scope: issueResult.scope,
        },
        200,
        {
          'Cache-Control': 'no-store',
          Pragma: 'no-cache',
        },
      );
    }

    // grant_type === 'refresh_token'
    const rawRefreshToken = params.refresh_token;
    const requestedResource = params.resource;
    if (!rawRefreshToken) {
      return oauthError(c, 400, 'invalid_request', 'Missing refresh_token');
    }

    type RefreshResult =
      | {
          ok: true;
          accessToken: string;
          refreshToken: string;
          scope: string;
        }
      | {
          ok: false;
          status: 400 | 401;
          error: string;
          description: string;
        };

    const result = runTx((): RefreshResult => {
      const now = Date.now();
      const tokenHash = hashToken(rawRefreshToken);
      const tokenRecord = oauthRepo.getTokenByHash(tokenHash);

      if (!tokenRecord || tokenRecord.token_type !== 'refresh') {
        return {
          ok: false,
          status: 400,
          error: 'invalid_grant',
          description: 'Invalid refresh token',
        };
      }

      if (clientId && tokenRecord.client_id !== clientId) {
        return {
          ok: false,
          status: 400,
          error: 'invalid_grant',
          description: 'Refresh token does not belong to client_id',
        };
      }

      const client = oauthRepo.getClient(clientId ?? tokenRecord.client_id);
      if (!client) {
        return {
          ok: false,
          status: 401,
          error: 'invalid_client',
          description: 'Client no longer exists',
        };
      }

      if (client.client_secret_hash !== null) {
        if (!clientId || !authenticateClient(client, clientSecret)) {
          return {
            ok: false,
            status: 401,
            error: 'invalid_client',
            description: 'Client authentication failed',
          };
        }
      }

      // Check replay / revocation BEFORE expiration so an expired-but-already-rotated
      // ancestor token replay still revokes the active token_family_id.
      if (tokenRecord.revoked) {
        oauthRepo.revokeTokenFamily(tokenRecord.token_family_id);
        auditRepo?.record({
          actor: client.client_id,
          action: 'oauth_refresh_replay',
          target: tokenRecord.token_family_id,
          status: 'denied',
          details: { reason: 'revoked_token_reused' },
          created_at: now,
        });
        return {
          ok: false,
          status: 400,
          error: 'invalid_grant',
          description: 'Refresh token was revoked',
        };
      }

      if (tokenRecord.grace_expires_at !== null && now > tokenRecord.grace_expires_at) {
        oauthRepo.revokeTokenFamily(tokenRecord.token_family_id);
        auditRepo?.record({
          actor: client.client_id,
          action: 'oauth_refresh_replay',
          target: tokenRecord.token_family_id,
          status: 'denied',
          details: { reason: 'replay_outside_grace_window' },
          created_at: now,
        });
        return {
          ok: false,
          status: 400,
          error: 'invalid_grant',
          description: 'Refresh token reuse detected outside grace window; token family revoked',
        };
      }

      if (tokenRecord.expires_at <= now) {
        return {
          ok: false,
          status: 400,
          error: 'invalid_grant',
          description: 'Refresh token expired',
        };
      }

      let effectiveResource = tokenRecord.resource ?? canonicalResource;
      if (requestedResource !== undefined && requestedResource.length > 0) {
        if (tokenRecord.resource !== null && requestedResource !== tokenRecord.resource) {
          return {
            ok: false,
            status: 400,
            error: 'invalid_target',
            description: 'Requested resource does not match token resource',
          };
        }
        if (!isValidResource(requestedResource, config.publicDomain)) {
          return {
            ok: false,
            status: 400,
            error: 'invalid_target',
            description: 'Requested resource is not valid for this server',
          };
        }
        effectiveResource = requestedResource;
      }

      if (tokenRecord.grace_expires_at === null) {
        oauthRepo.setRefreshTokenGrace(
          tokenRecord.token_hash,
          now + config.oauthRefreshGraceSec * 1000,
        );
      }

      const nextAccessToken = generateRandomToken(32);
      const nextRefreshToken = generateRandomToken(32);

      oauthRepo.createToken({
        token_hash: hashToken(nextAccessToken),
        token_type: 'access',
        client_id: client.client_id,
        scope: tokenRecord.scope,
        resource: effectiveResource,
        token_family_id: tokenRecord.token_family_id,
        expires_at: now + config.oauthAccessTokenTtlSec * 1000,
        grace_expires_at: null,
        created_at: now,
      });

      oauthRepo.createToken({
        token_hash: hashToken(nextRefreshToken),
        token_type: 'refresh',
        client_id: client.client_id,
        scope: tokenRecord.scope,
        resource: effectiveResource,
        token_family_id: tokenRecord.token_family_id,
        expires_at: now + config.oauthRefreshTokenTtlSec * 1000,
        grace_expires_at: null,
        created_at: now,
      });

      auditRepo?.record({
        actor: client.client_id,
        action: 'oauth_token_refresh',
        target: tokenRecord.token_family_id,
        status: 'success',
        details: {
          within_grace: tokenRecord.grace_expires_at !== null,
          resource: effectiveResource,
        },
        created_at: now,
      });

      return {
        ok: true,
        accessToken: nextAccessToken,
        refreshToken: nextRefreshToken,
        scope: tokenRecord.scope,
      };
    });

    if (!result.ok) {
      return oauthError(c, result.status, result.error, result.description);
    }

    return c.json(
      {
        access_token: result.accessToken,
        token_type: 'Bearer',
        expires_in: config.oauthAccessTokenTtlSec,
        refresh_token: result.refreshToken,
        scope: result.scope,
      },
      200,
      {
        'Cache-Control': 'no-store',
        Pragma: 'no-cache',
      },
    );
  });

  app.post('/oauth/revoke', async (c) => {
    const ip = getClientIp(c, config.trustCfConnectingIp);
    const rate = revokeRateLimiter.consume(`revoke:${ip}`);
    if (!rate.allowed) {
      c.header('Retry-After', String(rate.retryAfterSec));
      return oauthError(c, 429, 'too_many_requests', 'Revocation rate limit exceeded');
    }

    const parsed = await parseTokenParams(c);
    if (!parsed.ok) {
      return oauthError(
        c,
        parsed.status,
        'invalid_request',
        parsed.status === 413 ? 'Request body exceeds 64KB limit' : 'Malformed request body',
      );
    }

    const params = parsed.params;
    const token = params.token;
    if (!token) {
      return oauthError(c, 400, 'invalid_request', 'Missing token parameter');
    }

    const { clientId, clientSecret } = extractClientCredentials(c, params);
    if (clientId) {
      const client = oauthRepo.getClient(clientId);
      if (client && client.client_secret_hash !== null && !authenticateClient(client, clientSecret)) {
        return oauthError(c, 401, 'invalid_client', 'Client authentication failed');
      }
    }

    const tokenRecord = oauthRepo.getTokenByHash(hashToken(token));
    if (tokenRecord) {
      const ownerClient = oauthRepo.getClient(tokenRecord.client_id);
      if (ownerClient && ownerClient.client_secret_hash !== null) {
        if (
          (clientId && clientId !== ownerClient.client_id) ||
          !authenticateClient(ownerClient, clientSecret)
        ) {
          return oauthError(c, 401, 'invalid_client', 'Client authentication required to revoke token');
        }
      }

      if (!clientId || tokenRecord.client_id === clientId) {
        if (tokenRecord.token_type === 'refresh') {
          oauthRepo.revokeTokenFamily(tokenRecord.token_family_id);
        } else {
          oauthRepo.revokeToken(tokenRecord.token_hash);
        }

        auditRepo?.record({
          actor: clientId ?? tokenRecord.client_id,
          action: 'oauth_token_revoke',
          target: tokenRecord.token_family_id,
          status: 'success',
          details: { token_type: tokenRecord.token_type },
        });
      }
    }

    return c.json({ revoked: true }, 200, {
      'Cache-Control': 'no-store',
    });
  });

  return app;
}
