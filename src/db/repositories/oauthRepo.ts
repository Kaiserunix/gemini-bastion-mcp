import { timingSafeEqual } from 'node:crypto';
import type { GatewayDatabase } from '../sqlite.js';
import type {
  OAuthAuthRequest,
  OAuthClient,
  OAuthCode,
  OAuthToken,
  OAuthTokenType,
  OAuthUpstreamState,
  UpstreamOAuthProvider,
  UpstreamOAuthPurpose,
} from '../../types.js';

interface OAuthClientRow {
  client_id: string;
  client_secret_hash: string | null;
  client_name: string;
  redirect_uris_json: string;
  is_static: number;
  created_at: number;
}

interface OAuthAuthRequestRow {
  auth_req_id: string;
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
  resource: string | null;
  csrf_token: string;
  expires_at: number;
  used: number;
}

interface OAuthCodeRow {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scope: string;
  resource: string | null;
  expires_at: number;
  used: number;
}

interface OAuthTokenRow {
  token_hash: string;
  token_type: string;
  client_id: string;
  scope: string;
  resource: string | null;
  token_family_id: string;
  expires_at: number;
  grace_expires_at: number | null;
  revoked: number;
  created_at: number;
}

interface OAuthUpstreamStateRow {
  state: string;
  provider: string;
  purpose: string;
  auth_req_id: string | null;
  code_verifier: string;
  binding_hash: string;
  expires_at: number;
  used: number;
  created_at: number;
}

function mapClient(row: OAuthClientRow): OAuthClient {
  return {
    client_id: row.client_id,
    client_secret_hash: row.client_secret_hash,
    client_name: row.client_name,
    redirect_uris: JSON.parse(row.redirect_uris_json) as string[],
    is_static: row.is_static === 1,
    created_at: row.created_at,
  };
}

function mapAuthRequest(row: OAuthAuthRequestRow): OAuthAuthRequest {
  return {
    auth_req_id: row.auth_req_id,
    client_id: row.client_id,
    redirect_uri: row.redirect_uri,
    state: row.state,
    code_challenge: row.code_challenge,
    code_challenge_method: row.code_challenge_method as 'S256',
    scope: row.scope,
    resource: row.resource,
    csrf_token: row.csrf_token,
    expires_at: row.expires_at,
    used: row.used === 1,
  };
}

function mapCode(row: OAuthCodeRow): OAuthCode {
  return {
    code: row.code,
    client_id: row.client_id,
    redirect_uri: row.redirect_uri,
    code_challenge: row.code_challenge,
    scope: row.scope,
    resource: row.resource,
    expires_at: row.expires_at,
    used: row.used === 1,
  };
}

function mapToken(row: OAuthTokenRow): OAuthToken {
  return {
    token_hash: row.token_hash,
    token_type: row.token_type as OAuthTokenType,
    client_id: row.client_id,
    scope: row.scope,
    resource: row.resource,
    token_family_id: row.token_family_id,
    expires_at: row.expires_at,
    grace_expires_at: row.grace_expires_at,
    revoked: row.revoked === 1,
    created_at: row.created_at,
  };
}

function timingSafeStringEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

function mapUpstreamState(row: OAuthUpstreamStateRow): OAuthUpstreamState {
  return {
    state: row.state,
    provider: row.provider as UpstreamOAuthProvider,
    purpose: row.purpose as UpstreamOAuthPurpose,
    auth_req_id: row.auth_req_id,
    code_verifier: row.code_verifier,
    binding_hash: row.binding_hash,
    expires_at: row.expires_at,
    used: row.used === 1,
    created_at: row.created_at,
  };
}

export class OAuthRepository {
  constructor(private readonly db: GatewayDatabase) {}

  createClient(input: {
    client_id: string;
    client_secret_hash?: string | null;
    client_name: string;
    redirect_uris: string[];
    is_static?: boolean;
    created_at?: number;
  }): OAuthClient {
    const createdAt = input.created_at ?? Date.now();
    const isStatic = input.is_static ? 1 : 0;
    this.db
      .prepare(
        `INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris_json, is_static, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.client_id,
        input.client_secret_hash ?? null,
        input.client_name,
        JSON.stringify(input.redirect_uris),
        isStatic,
        createdAt,
      );

    return {
      client_id: input.client_id,
      client_secret_hash: input.client_secret_hash ?? null,
      client_name: input.client_name,
      redirect_uris: [...input.redirect_uris],
      is_static: Boolean(input.is_static),
      created_at: createdAt,
    };
  }

  upsertStaticClient(input: {
    client_id: string;
    client_secret_hash?: string | null;
    client_name: string;
    redirect_uris: string[];
  }): OAuthClient {
    const existing = this.getClient(input.client_id);
    const createdAt = existing?.created_at ?? Date.now();
    this.db
      .prepare(
        `INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris_json, is_static, created_at)
         VALUES (?, ?, ?, ?, 1, ?)
         ON CONFLICT(client_id) DO UPDATE SET
           client_secret_hash = excluded.client_secret_hash,
           client_name = excluded.client_name,
           redirect_uris_json = excluded.redirect_uris_json,
           is_static = 1`,
      )
      .run(
        input.client_id,
        input.client_secret_hash ?? null,
        input.client_name,
        JSON.stringify(input.redirect_uris),
        createdAt,
      );

    return {
      client_id: input.client_id,
      client_secret_hash: input.client_secret_hash ?? null,
      client_name: input.client_name,
      redirect_uris: [...input.redirect_uris],
      is_static: true,
      created_at: createdAt,
    };
  }

  getClient(clientId: string): OAuthClient | null {
    const row = this.db
      .prepare('SELECT * FROM oauth_clients WHERE client_id = ?')
      .get(clientId) as OAuthClientRow | undefined;
    return row ? mapClient(row) : null;
  }

  listClients(): OAuthClient[] {
    const rows = this.db
      .prepare('SELECT * FROM oauth_clients ORDER BY created_at DESC')
      .all() as OAuthClientRow[];
    return rows.map(mapClient);
  }

  deleteClient(clientId: string): boolean {
    const info = this.db.prepare('DELETE FROM oauth_clients WHERE client_id = ?').run(clientId);
    return info.changes > 0;
  }

  /**
   * Revokes tokens and deletes any static clients other than `keepClientId`
   * (or all static clients when `keepClientId` is omitted).
   */
  retireStaleStaticClients(keepClientId?: string): number {
    return this.db.transaction(() => {
      const staleRows = (
        keepClientId !== undefined
          ? this.db
              .prepare('SELECT client_id FROM oauth_clients WHERE is_static = 1 AND client_id != ?')
              .all(keepClientId)
          : this.db.prepare('SELECT client_id FROM oauth_clients WHERE is_static = 1').all()
      ) as Array<{ client_id: string }>;

      let deleted = 0;
      const revokeTokensStmt = this.db.prepare(
        'UPDATE oauth_tokens SET revoked = 1 WHERE client_id = ?',
      );
      const deleteClientStmt = this.db.prepare(
        'DELETE FROM oauth_clients WHERE client_id = ? AND is_static = 1',
      );

      for (const row of staleRows) {
        revokeTokensStmt.run(row.client_id);
        deleted += deleteClientStmt.run(row.client_id).changes;
      }
      return deleted;
    })();
  }

  createAuthRequest(input: Omit<OAuthAuthRequest, 'used'> & { used?: boolean }): OAuthAuthRequest {
    const used = input.used ? 1 : 0;
    this.db
      .prepare(
        `INSERT INTO oauth_auth_requests
         (auth_req_id, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope, resource, csrf_token, expires_at, used)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.auth_req_id,
        input.client_id,
        input.redirect_uri,
        input.state,
        input.code_challenge,
        input.code_challenge_method,
        input.scope,
        input.resource,
        input.csrf_token,
        input.expires_at,
        used,
      );

    return {
      ...input,
      used: Boolean(input.used),
    };
  }

  getAuthRequest(authReqId: string): OAuthAuthRequest | null {
    const row = this.db
      .prepare('SELECT * FROM oauth_auth_requests WHERE auth_req_id = ?')
      .get(authReqId) as OAuthAuthRequestRow | undefined;
    return row ? mapAuthRequest(row) : null;
  }

  consumeAuthRequest(authReqId: string, now = Date.now()): OAuthAuthRequest | null {
    return this.db.transaction(() => {
      const row = this.db
        .prepare('SELECT * FROM oauth_auth_requests WHERE auth_req_id = ?')
        .get(authReqId) as OAuthAuthRequestRow | undefined;
      if (!row || row.used !== 0 || row.expires_at <= now) {
        return null;
      }
      const res = this.db
        .prepare('UPDATE oauth_auth_requests SET used = 1 WHERE auth_req_id = ? AND used = 0')
        .run(authReqId);
      if (res.changes === 0) return null;
      return mapAuthRequest({ ...row, used: 1 });
    })();
  }

  createCode(input: Omit<OAuthCode, 'used'> & { used?: boolean }): OAuthCode {
    const used = input.used ? 1 : 0;
    this.db
      .prepare(
        `INSERT INTO oauth_codes
         (code, client_id, redirect_uri, code_challenge, scope, resource, expires_at, used)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.code,
        input.client_id,
        input.redirect_uri,
        input.code_challenge,
        input.scope,
        input.resource,
        input.expires_at,
        used,
      );

    return {
      ...input,
      used: Boolean(input.used),
    };
  }

  getCode(code: string): OAuthCode | null {
    const row = this.db
      .prepare('SELECT * FROM oauth_codes WHERE code = ?')
      .get(code) as OAuthCodeRow | undefined;
    return row ? mapCode(row) : null;
  }

  consumeCode(code: string, now = Date.now()): OAuthCode | null {
    return this.db.transaction(() => {
      const row = this.db
        .prepare('SELECT * FROM oauth_codes WHERE code = ?')
        .get(code) as OAuthCodeRow | undefined;
      if (!row || row.used !== 0 || row.expires_at <= now) {
        return null;
      }
      const res = this.db
        .prepare('UPDATE oauth_codes SET used = 1 WHERE code = ? AND used = 0')
        .run(code);
      if (res.changes === 0) return null;
      return mapCode({ ...row, used: 1 });
    })();
  }

  createToken(
    input: Omit<OAuthToken, 'revoked' | 'created_at'> & { revoked?: boolean; created_at?: number },
  ): OAuthToken {
    const createdAt = input.created_at ?? Date.now();
    const revoked = input.revoked ? 1 : 0;
    this.db
      .prepare(
        `INSERT INTO oauth_tokens
         (token_hash, token_type, client_id, scope, resource, token_family_id, expires_at, grace_expires_at, revoked, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.token_hash,
        input.token_type,
        input.client_id,
        input.scope,
        input.resource,
        input.token_family_id,
        input.expires_at,
        input.grace_expires_at ?? null,
        revoked,
        createdAt,
      );

    return {
      token_hash: input.token_hash,
      token_type: input.token_type,
      client_id: input.client_id,
      scope: input.scope,
      resource: input.resource,
      token_family_id: input.token_family_id,
      expires_at: input.expires_at,
      grace_expires_at: input.grace_expires_at ?? null,
      revoked: Boolean(input.revoked),
      created_at: createdAt,
    };
  }

  getTokenByHash(tokenHash: string): OAuthToken | null {
    const row = this.db
      .prepare('SELECT * FROM oauth_tokens WHERE token_hash = ?')
      .get(tokenHash) as OAuthTokenRow | undefined;
    return row ? mapToken(row) : null;
  }

  setRefreshTokenGrace(tokenHash: string, graceExpiresAt: number): void {
    this.db
      .prepare('UPDATE oauth_tokens SET grace_expires_at = ? WHERE token_hash = ?')
      .run(graceExpiresAt, tokenHash);
  }

  revokeToken(tokenHash: string): void {
    this.db.prepare('UPDATE oauth_tokens SET revoked = 1 WHERE token_hash = ?').run(tokenHash);
  }

  revokeTokenFamily(familyId: string): number {
    const info = this.db
      .prepare('UPDATE oauth_tokens SET revoked = 1 WHERE token_family_id = ?')
      .run(familyId);
    return info.changes;
  }

  revokeClientTokens(clientId: string): number {
    const info = this.db
      .prepare('UPDATE oauth_tokens SET revoked = 1 WHERE client_id = ?')
      .run(clientId);
    return info.changes;
  }

  listActiveTokens(now = Date.now()): OAuthToken[] {
    const rows = this.db
      .prepare(
        'SELECT * FROM oauth_tokens WHERE revoked = 0 AND expires_at > ? ORDER BY created_at DESC',
      )
      .all(now) as OAuthTokenRow[];
    return rows.map(mapToken);
  }

  createUpstreamState(
    input: Omit<OAuthUpstreamState, 'used' | 'created_at'> & {
      used?: boolean;
      created_at?: number;
    },
  ): OAuthUpstreamState {
    const createdAt = input.created_at ?? Date.now();
    const used = input.used ? 1 : 0;
    this.db
      .prepare(
        `INSERT INTO oauth_upstream_states
         (state, provider, purpose, auth_req_id, code_verifier, binding_hash, expires_at, used, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.state,
        input.provider,
        input.purpose,
        input.auth_req_id,
        input.code_verifier,
        input.binding_hash,
        input.expires_at,
        used,
        createdAt,
      );

    return {
      state: input.state,
      provider: input.provider,
      purpose: input.purpose,
      auth_req_id: input.auth_req_id,
      code_verifier: input.code_verifier,
      binding_hash: input.binding_hash,
      expires_at: input.expires_at,
      used: Boolean(input.used),
      created_at: createdAt,
    };
  }

  consumeUpstreamState(
    state: string,
    provider: UpstreamOAuthProvider,
    bindingHash: string,
    now = Date.now(),
  ): OAuthUpstreamState | null {
    return this.db.transaction(() => {
      const row = this.db
        .prepare('SELECT * FROM oauth_upstream_states WHERE state = ?')
        .get(state) as OAuthUpstreamStateRow | undefined;
      if (
        !row ||
        row.used !== 0 ||
        row.provider !== provider ||
        !timingSafeStringEqual(row.binding_hash, bindingHash) ||
        row.expires_at <= now
      ) {
        return null;
      }

      const res = this.db
        .prepare('UPDATE oauth_upstream_states SET used = 1 WHERE state = ? AND used = 0')
        .run(state);
      if (res.changes === 0) return null;

      return mapUpstreamState({ ...row, used: 1 });
    })();
  }

  purgeExpired(
    now = Date.now(),
  ): { authRequests: number; codes: number; tokens: number; upstreamStates: number } {
    return this.db.transaction(() => {
      const authRequests = this.db
        .prepare('DELETE FROM oauth_auth_requests WHERE expires_at <= ?')
        .run(now).changes;
      const codes = this.db.prepare('DELETE FROM oauth_codes WHERE expires_at <= ?').run(now).changes;
      const expiredAccess = this.db
        .prepare("DELETE FROM oauth_tokens WHERE token_type = 'access' AND expires_at <= ?")
        .run(now).changes;
      // Preserve refresh tokens in families that still have at least one unexpired token so replay detection remains intact.
      const expiredRefresh = this.db
        .prepare(
          `DELETE FROM oauth_tokens
           WHERE token_type = 'refresh'
             AND NOT EXISTS (
               SELECT 1
               FROM oauth_tokens AS active_family
               WHERE active_family.token_family_id = oauth_tokens.token_family_id
                 AND active_family.expires_at > ?
             )`,
        )
        .run(now).changes;
      const upstreamStates = this.db
        .prepare('DELETE FROM oauth_upstream_states WHERE expires_at <= ? OR used = 1')
        .run(now).changes;
      return {
        authRequests,
        codes,
        tokens: expiredAccess + expiredRefresh,
        upstreamStates,
      };
    })();
  }
}
