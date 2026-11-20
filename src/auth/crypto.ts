import crypto from 'node:crypto';
import type { GatewayConfig, NodeEnv } from '../types.js';

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 32;

const PKCE_VERIFIER_REGEX = /^[A-Za-z0-9\-._~]{43,128}$/;

export interface AdminSessionPayload {
  sub: string;
  csrf: string;
  iat: number;
  exp: number;
}

/**
 * Generates a URL-safe base64 random token of `byteLength` cryptographically random bytes.
 */
export function generateRandomToken(byteLength = 32): string {
  return crypto.randomBytes(byteLength).toString('base64url');
}

/**
 * Generates a lowercase hexadecimal random string of `byteLength` bytes.
 */
export function generateRandomHex(byteLength = 16): string {
  return crypto.randomBytes(byteLength).toString('hex');
}

/**
 * Generates a prefixed random identifier (e.g. `dcr_...`).
 */
export function generateId(prefix = '', byteLength = 16): string {
  const hex = generateRandomHex(byteLength);
  return prefix ? `${prefix}_${hex}` : hex;
}

/**
 * Computes the SHA-256 hex digest of an opaque token or secret for DB storage/lookup.
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Computes the RFC 7636 PKCE S256 code challenge for a given code verifier.
 */
export function computeS256Challenge(codeVerifier: string): string {
  return crypto.createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
}

/**
 * Performs a constant-time equality check between two UTF-8 strings.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  const hashA = crypto.createHash('sha256').update(bufA).digest();
  const hashB = crypto.createHash('sha256').update(bufB).digest();
  const hashesMatch = crypto.timingSafeEqual(hashA, hashB);
  return bufA.length === bufB.length && hashesMatch;
}

/**
 * Verifies a PKCE S256 `code_verifier` against an expected `code_challenge`.
 */
export function verifyPkceS256(codeVerifier: string, expectedChallenge: string): boolean {
  if (!PKCE_VERIFIER_REGEX.test(codeVerifier)) {
    return false;
  }
  if (!expectedChallenge || expectedChallenge.length < 43) {
    return false;
  }
  const computed = computeS256Challenge(codeVerifier);
  return constantTimeEqual(computed, expectedChallenge);
}

/**
 * Hashes a password using scrypt in `scrypt$<salt>$<hex>` (default) or
 * Docker-Compose-safe `scrypt:<salt>:<hex>` format.
 */
export function hashPasswordScrypt(
  password: string,
  saltHex = generateRandomHex(16),
  separator: '$' | ':' = '$',
): string {
  const derived = crypto.scryptSync(password, saltHex, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });
  return `scrypt${separator}${saltHex}${separator}${derived.toString('hex')}`;
}

/**
 * Verifies a candidate password against a stored `ADMIN_PASSWORD_HASH` in constant time.
 * Supports:
 * - `scrypt$<salt>$<hex>` and `scrypt:<salt>:<hex>` (Docker-Compose-safe)
 * - `sha256$<hex>` and `sha256:<hex>` (Docker-Compose-safe)
 * - `plain$<plaintext>` (or unprefixed plain string in non-production dev/test environments)
 */
export function verifyPassword(
  password: string,
  storedHash: string | undefined,
  nodeEnv: NodeEnv = 'development',
): boolean {
  if (!storedHash || storedHash.length === 0 || password.length === 0) {
    return false;
  }

  const scryptSeparator = storedHash.startsWith('scrypt$')
    ? '$'
    : storedHash.startsWith('scrypt:')
      ? ':'
      : null;

  if (scryptSeparator) {
    const parts = storedHash.split(scryptSeparator);
    if (parts.length !== 3) return false;
    const [, salt, expectedHex] = parts;
    if (!salt || !expectedHex || expectedHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(expectedHex)) {
      return false;
    }
    const keyLen = expectedHex.length / 2;
    const derived = crypto.scryptSync(password, salt, keyLen, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
    });
    const expectedBuf = Buffer.from(expectedHex, 'hex');
    if (derived.length !== expectedBuf.length) return false;
    return crypto.timingSafeEqual(derived, expectedBuf);
  }

  const shaPrefix = storedHash.startsWith('sha256$')
    ? 'sha256$'
    : storedHash.startsWith('sha256:')
      ? 'sha256:'
      : null;

  if (shaPrefix) {
    const expectedHex = storedHash.slice(shaPrefix.length).toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(expectedHex)) return false;
    const computedHex = crypto.createHash('sha256').update(password, 'utf8').digest('hex');
    return constantTimeEqual(computedHex, expectedHex);
  }

  if (storedHash.startsWith('plain$')) {
    if (nodeEnv === 'production') return false;
    const expectedPlain = storedHash.slice('plain$'.length);
    if (expectedPlain.length === 0) return false;
    return constantTimeEqual(password, expectedPlain);
  }

  // Unprefixed fallback only allowed in non-production if it does not use an unknown `$` or `scheme:` prefix
  if (nodeEnv !== 'production' && !storedHash.includes('$') && !/^[a-z0-9_-]+:/i.test(storedHash)) {
    return constantTimeEqual(password, storedHash);
  }

  return false;
}

const fallbackEphemeralSecrets = new WeakMap<GatewayConfig, string>();

/**
 * Resolves a non-empty HMAC signing secret from config, falling back to an ephemeral
 * per-config-instance secret in dev/test when `OAUTH_SIGNING_SECRET` is unset.
 */
export function resolveSigningSecret(config: GatewayConfig): string {
  if (config.oauthSigningSecret && config.oauthSigningSecret.length > 0) {
    return config.oauthSigningSecret;
  }
  let ephemeral = fallbackEphemeralSecrets.get(config);
  if (!ephemeral) {
    ephemeral = generateRandomToken(32);
    fallbackEphemeralSecrets.set(config, ephemeral);
  }
  return ephemeral;
}

/**
 * Signs an admin session payload into `<base64url-payload>.<base64url-hmac>` format.
 */
export function signSessionCookie(payload: AdminSessionPayload, secret: string): string {
  if (!secret) {
    throw new Error('Signing secret must not be empty');
  }
  const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signature = crypto
    .createHmac('sha256', secret)
    .update(encodedPayload, 'utf8')
    .digest('base64url');
  return `${encodedPayload}.${signature}`;
}

/**
 * Verifies an HMAC-signed admin session cookie and checks its expiration timestamp.
 */
export function verifySessionCookie(
  cookieValue: string | undefined,
  secret: string,
  now = Date.now(),
): AdminSessionPayload | null {
  if (!cookieValue || !secret) return null;
  const dotIdx = cookieValue.indexOf('.');
  if (dotIdx <= 0 || dotIdx === cookieValue.length - 1) return null;

  const encodedPayload = cookieValue.slice(0, dotIdx);
  const providedSig = cookieValue.slice(dotIdx + 1);
  if (providedSig.includes('.')) return null;

  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(encodedPayload, 'utf8')
    .digest('base64url');

  if (!constantTimeEqual(providedSig, expectedSig)) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8')) as unknown;
    if (!parsed || typeof parsed !== 'object') return null;
    const record = parsed as Record<string, unknown>;
    if (
      typeof record.sub !== 'string' ||
      typeof record.csrf !== 'string' ||
      typeof record.iat !== 'number' ||
      typeof record.exp !== 'number'
    ) {
      return null;
    }
    if (record.exp <= now) return null;
    return {
      sub: record.sub,
      csrf: record.csrf,
      iat: record.iat,
      exp: record.exp,
    };
  } catch {
    return null;
  }
}
