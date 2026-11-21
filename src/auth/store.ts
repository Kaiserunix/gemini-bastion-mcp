import { timingSafeEqual } from 'node:crypto';
import type {
  AuditLogRecord,
  GatewayConfig,
  OAuthAuthRequest,
  OAuthClient,
  OAuthCode,
  OAuthToken,
  OAuthUpstreamState,
  UpstreamOAuthProvider,
} from '../types.js';
import {
  generateRandomToken,
  resolveSigningSecret,
  signSessionCookie,
  verifySessionCookie,
  type AdminSessionPayload,
} from './crypto.js';
import type { RateLimitResult } from './rateLimit.js';

export const DEFAULT_ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000;

/**
 * Storage-agnostic typed contract for OAuth 2.1 clients, authorization requests,
 * authorization codes, rotated token families, and upstream IdP states.
 */
export interface OAuthStore {
  createClient(input: {
    client_id: string;
    client_secret_hash?: string | null;
    client_name: string;
    redirect_uris: string[];
    is_static?: boolean;
    created_at?: number;
  }): OAuthClient;
  upsertStaticClient(input: {
    client_id: string;
    client_secret_hash?: string | null;
    client_name: string;
    redirect_uris: string[];
  }): OAuthClient;
  getClient(clientId: string): OAuthClient | null;
  listClients(): OAuthClient[];
  deleteClient(clientId: string): boolean;
  retireStaleStaticClients(keepClientId?: string): number;

  createAuthRequest(input: Omit<OAuthAuthRequest, 'used'> & { used?: boolean }): OAuthAuthRequest;
  getAuthRequest(authReqId: string): OAuthAuthRequest | null;
  consumeAuthRequest(authReqId: string, now?: number): OAuthAuthRequest | null;

  createCode(
    input: Omit<OAuthCode, 'used' | 'issued_family_id'> & {
      used?: boolean;
      issued_family_id?: string | null;
    },
  ): OAuthCode;
  getCode(code: string): OAuthCode | null;
  consumeCode(code: string, now?: number): OAuthCode | null;
  setCodeIssuedFamily(code: string, familyId: string): void;

  createToken(
    input: Omit<OAuthToken, 'revoked' | 'created_at'> & {
      revoked?: boolean;
      created_at?: number;
    },
  ): OAuthToken;
  getTokenByHash(tokenHash: string): OAuthToken | null;
  setRefreshTokenGrace(tokenHash: string, graceExpiresAt: number): void;
  revokeToken(tokenHash: string): void;
  revokeTokenFamily(familyId: string): number;
  revokeClientTokens(clientId: string): number;
  listActiveTokens(now?: number): OAuthToken[];

  createUpstreamState(
    input: Omit<OAuthUpstreamState, 'used' | 'created_at'> & {
      used?: boolean;
      created_at?: number;
    },
  ): OAuthUpstreamState;
  consumeUpstreamState(
    state: string,
    provider: UpstreamOAuthProvider,
    bindingHash: string,
    now?: number,
  ): OAuthUpstreamState | null;

  purgeExpired(now?: number): {
    authRequests: number;
    codes: number;
    tokens: number;
    upstreamStates: number;
  };

  runInTransaction<T>(fn: () => T): T;
}

/**
 * Narrow typed audit-log recorder decoupled from concrete SQLite repositories.
 */
export interface AuditLogger {
  record(input: {
    actor: string;
    action: string;
    target: string;
    status: string;
    details?: Record<string, unknown>;
    created_at?: number;
  }): AuditLogRecord;
}

/**
 * Typed rate-limiter contract for auth and admin endpoints.
 */
export interface RateLimiter {
  consume(key: string, now?: number): RateLimitResult;
  reset(key?: string): void;
}

/**
 * Typed admin session token issuer & verifier decoupled from HTTP cookie I/O.
 */
export interface AdminSessionManager {
  readonly ttlMs: number;
  issue(now?: number, subject?: string): { token: string; payload: AdminSessionPayload };
  verify(rawToken: string | undefined, now?: number): AdminSessionPayload | null;
}

/**
 * Default HMAC-SHA256 signed session manager backed by `OAUTH_SIGNING_SECRET`
 * (or an ephemeral per-config secret in non-production dev/test).
 */
export class SignedCookieAdminSessionManager implements AdminSessionManager {
  readonly ttlMs: number;

  constructor(
    private readonly config: GatewayConfig,
    options: { ttlMs?: number } = {},
  ) {
    this.ttlMs = options.ttlMs ?? DEFAULT_ADMIN_SESSION_TTL_MS;
  }

  issue(now = Date.now(), subject = 'admin'): { token: string; payload: AdminSessionPayload } {
    const signingSecret = resolveSigningSecret(this.config);
    const payload: AdminSessionPayload = {
      sub: subject,
      csrf: generateRandomToken(24),
      iat: now,
      exp: now + this.ttlMs,
    };
    const token = signSessionCookie(payload, signingSecret);
    return { token, payload };
  }

  verify(rawToken: string | undefined, now = Date.now()): AdminSessionPayload | null {
    return verifySessionCookie(rawToken, resolveSigningSecret(this.config), now);
  }
}

function timingSafeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

/**
 * Full in-memory `OAuthStore` implementation with parity to `OAuthRepository`
 * (including ON DELETE CASCADE cleanup and replay-safe refresh family preservation).
 * Enables zero-SQLite unit tests and pluggable alternative storage backends.
 */
export class InMemoryOAuthStore implements OAuthStore {
  private readonly clients = new Map<string, OAuthClient>();
  private readonly authRequests = new Map<string, OAuthAuthRequest>();
  private readonly codes = new Map<string, OAuthCode>();
  private readonly tokens = new Map<string, OAuthToken>();
  private readonly upstreamStates = new Map<string, OAuthUpstreamState>();

  createClient(input: {
    client_id: string;
    client_secret_hash?: string | null;
    client_name: string;
    redirect_uris: string[];
    is_static?: boolean;
    created_at?: number;
  }): OAuthClient {
    if (this.clients.has(input.client_id)) {
      throw new Error(`OAuth client already exists: ${input.client_id}`);
    }
    const record: OAuthClient = {
      client_id: input.client_id,
      client_secret_hash: input.client_secret_hash ?? null,
      client_name: input.client_name,
      redirect_uris: [...input.redirect_uris],
      is_static: Boolean(input.is_static),
      created_at: input.created_at ?? Date.now(),
    };
    this.clients.set(record.client_id, record);
    return { ...record, redirect_uris: [...record.redirect_uris] };
  }

  upsertStaticClient(input: {
    client_id: string;
    client_secret_hash?: string | null;
    client_name: string;
    redirect_uris: string[];
  }): OAuthClient {
    const existing = this.clients.get(input.client_id);
    const record: OAuthClient = {
      client_id: input.client_id,
      client_secret_hash: input.client_secret_hash ?? null,
      client_name: input.client_name,
      redirect_uris: [...input.redirect_uris],
      is_static: true,
      created_at: existing?.created_at ?? Date.now(),
    };
    this.clients.set(record.client_id, record);
    return { ...record, redirect_uris: [...record.redirect_uris] };
  }

  getClient(clientId: string): OAuthClient | null {
    const found = this.clients.get(clientId);
    return found ? { ...found, redirect_uris: [...found.redirect_uris] } : null;
  }

  listClients(): OAuthClient[] {
    return Array.from(this.clients.values())
      .sort((a, b) => b.created_at - a.created_at)
      .map((c) => ({ ...c, redirect_uris: [...c.redirect_uris] }));
  }

  deleteClient(clientId: string): boolean {
    const existed = this.clients.delete(clientId);
    if (!existed) return false;
    // Mirror SQLite ON DELETE CASCADE behavior
    for (const [id, req] of this.authRequests) {
      if (req.client_id === clientId) this.authRequests.delete(id);
    }
    for (const [code, rec] of this.codes) {
      if (rec.client_id === clientId) this.codes.delete(code);
    }
    for (const [hash, tok] of this.tokens) {
      if (tok.client_id === clientId) this.tokens.delete(hash);
    }
    return true;
  }

  retireStaleStaticClients(keepClientId?: string): number {
    let deleted = 0;
    for (const client of Array.from(this.clients.values())) {
      if (!client.is_static) continue;
      if (keepClientId !== undefined && client.client_id === keepClientId) continue;
      this.revokeClientTokens(client.client_id);
      if (this.deleteClient(client.client_id)) {
        deleted += 1;
      }
    }
    return deleted;
  }

  createAuthRequest(input: Omit<OAuthAuthRequest, 'used'> & { used?: boolean }): OAuthAuthRequest {
    if (!this.clients.has(input.client_id)) {
      throw new Error(`Foreign key violation: unknown client_id "${input.client_id}"`);
    }
    const record: OAuthAuthRequest = {
      ...input,
      used: Boolean(input.used),
    };
    this.authRequests.set(record.auth_req_id, record);
    return { ...record };
  }

  getAuthRequest(authReqId: string): OAuthAuthRequest | null {
    const found = this.authRequests.get(authReqId);
    return found ? { ...found } : null;
  }

  consumeAuthRequest(authReqId: string, now = Date.now()): OAuthAuthRequest | null {
    const found = this.authRequests.get(authReqId);
    if (!found || found.used || found.expires_at <= now) {
      return null;
    }
    found.used = true;
    return { ...found };
  }

  createCode(
    input: Omit<OAuthCode, 'used' | 'issued_family_id'> & {
      used?: boolean;
      issued_family_id?: string | null;
    },
  ): OAuthCode {
    if (!this.clients.has(input.client_id)) {
      throw new Error(`Foreign key violation: unknown client_id "${input.client_id}"`);
    }
    const record: OAuthCode = {
      ...input,
      used: Boolean(input.used),
      issued_family_id: input.issued_family_id ?? null,
    };
    this.codes.set(record.code, record);
    return { ...record };
  }

  getCode(code: string): OAuthCode | null {
    const found = this.codes.get(code);
    return found ? { ...found } : null;
  }

  consumeCode(code: string, now = Date.now()): OAuthCode | null {
    const found = this.codes.get(code);
    if (!found || found.used || found.expires_at <= now) {
      return null;
    }
    found.used = true;
    return { ...found };
  }

  setCodeIssuedFamily(code: string, familyId: string): void {
    const found = this.codes.get(code);
    if (found) {
      found.issued_family_id = familyId;
    }
  }

  createToken(
    input: Omit<OAuthToken, 'revoked' | 'created_at'> & {
      revoked?: boolean;
      created_at?: number;
    },
  ): OAuthToken {
    if (!this.clients.has(input.client_id)) {
      throw new Error(`Foreign key violation: unknown client_id "${input.client_id}"`);
    }
    const record: OAuthToken = {
      token_hash: input.token_hash,
      token_type: input.token_type,
      client_id: input.client_id,
      scope: input.scope,
      resource: input.resource,
      token_family_id: input.token_family_id,
      expires_at: input.expires_at,
      grace_expires_at: input.grace_expires_at ?? null,
      revoked: Boolean(input.revoked),
      created_at: input.created_at ?? Date.now(),
    };
    this.tokens.set(record.token_hash, record);
    return { ...record };
  }

  getTokenByHash(tokenHash: string): OAuthToken | null {
    const found = this.tokens.get(tokenHash);
    return found ? { ...found } : null;
  }

  setRefreshTokenGrace(tokenHash: string, graceExpiresAt: number): void {
    const found = this.tokens.get(tokenHash);
    if (found) {
      found.grace_expires_at = graceExpiresAt;
    }
  }

  revokeToken(tokenHash: string): void {
    const found = this.tokens.get(tokenHash);
    if (found) {
      found.revoked = true;
    }
  }

  revokeTokenFamily(familyId: string): number {
    let changes = 0;
    for (const tok of this.tokens.values()) {
      if (tok.token_family_id === familyId) {
        tok.revoked = true;
        changes += 1;
      }
    }
    return changes;
  }

  revokeClientTokens(clientId: string): number {
    let changes = 0;
    for (const tok of this.tokens.values()) {
      if (tok.client_id === clientId) {
        tok.revoked = true;
        changes += 1;
      }
    }
    return changes;
  }

  listActiveTokens(now = Date.now()): OAuthToken[] {
    return Array.from(this.tokens.values())
      .filter((tok) => !tok.revoked && tok.expires_at > now)
      .sort((a, b) => b.created_at - a.created_at)
      .map((tok) => ({ ...tok }));
  }

  createUpstreamState(
    input: Omit<OAuthUpstreamState, 'used' | 'created_at'> & {
      used?: boolean;
      created_at?: number;
    },
  ): OAuthUpstreamState {
    const record: OAuthUpstreamState = {
      state: input.state,
      provider: input.provider,
      purpose: input.purpose,
      auth_req_id: input.auth_req_id,
      code_verifier: input.code_verifier,
      binding_hash: input.binding_hash,
      expires_at: input.expires_at,
      used: Boolean(input.used),
      created_at: input.created_at ?? Date.now(),
    };
    this.upstreamStates.set(record.state, record);
    return { ...record };
  }

  consumeUpstreamState(
    state: string,
    provider: UpstreamOAuthProvider,
    bindingHash: string,
    now = Date.now(),
  ): OAuthUpstreamState | null {
    const found = this.upstreamStates.get(state);
    if (
      !found ||
      found.used ||
      found.provider !== provider ||
      !timingSafeStringEqual(found.binding_hash, bindingHash) ||
      found.expires_at <= now
    ) {
      return null;
    }
    found.used = true;
    return { ...found };
  }

  purgeExpired(now = Date.now()): {
    authRequests: number;
    codes: number;
    tokens: number;
    upstreamStates: number;
  } {
    let authRequests = 0;
    for (const [id, req] of this.authRequests) {
      if (req.expires_at <= now) {
        this.authRequests.delete(id);
        authRequests += 1;
      }
    }

    let codes = 0;
    for (const [code, rec] of this.codes) {
      if (rec.expires_at <= now) {
        this.codes.delete(code);
        codes += 1;
      }
    }

    let tokens = 0;
    for (const [hash, tok] of this.tokens) {
      if (tok.token_type === 'access' && tok.expires_at <= now) {
        this.tokens.delete(hash);
        tokens += 1;
      }
    }

    const activeFamilies = new Set<string>();
    for (const tok of this.tokens.values()) {
      if (tok.expires_at > now) {
        activeFamilies.add(tok.token_family_id);
      }
    }
    for (const [hash, tok] of this.tokens) {
      if (tok.token_type === 'refresh' && !activeFamilies.has(tok.token_family_id)) {
        this.tokens.delete(hash);
        tokens += 1;
      }
    }

    let upstreamStates = 0;
    for (const [state, rec] of this.upstreamStates) {
      if (rec.expires_at <= now || rec.used) {
        this.upstreamStates.delete(state);
        upstreamStates += 1;
      }
    }

    return { authRequests, codes, tokens, upstreamStates };
  }

  runInTransaction<T>(fn: () => T): T {
    return fn();
  }
}
