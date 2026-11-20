import type { Context } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import type { GatewayConfig } from '../types.js';
import {
  generateRandomToken,
  resolveSigningSecret,
  signSessionCookie,
  verifySessionCookie,
  type AdminSessionPayload,
} from './crypto.js';

export const ADMIN_SESSION_COOKIE_NAME = 'gb_admin_session';
export const ADMIN_CSRF_COOKIE_NAME = 'gb_admin_csrf';
export const MCP_AUTH_BIND_COOKIE_NAME = 'gb_mcp_auth_bind';
export const UPSTREAM_OAUTH_COOKIE_NAME = 'gb_upstream_oauth';

export const ADMIN_SESSION_TTL_MS = 12 * 60 * 60 * 1000;
export const SHORT_AUTH_COOKIE_MAX_AGE_SEC = 600;

function isHttpsDomain(config: GatewayConfig): boolean {
  return config.publicDomain.toLowerCase().startsWith('https://');
}

export function issueAdminSessionCookie(
  c: Context,
  config: GatewayConfig,
  now = Date.now(),
): AdminSessionPayload {
  const signingSecret = resolveSigningSecret(config);
  const payload: AdminSessionPayload = {
    sub: 'admin',
    csrf: generateRandomToken(24),
    iat: now,
    exp: now + ADMIN_SESSION_TTL_MS,
  };
  const signedCookie = signSessionCookie(payload, signingSecret);

  setCookie(c, ADMIN_SESSION_COOKIE_NAME, signedCookie, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: isHttpsDomain(config),
    path: '/admin',
    maxAge: Math.floor(ADMIN_SESSION_TTL_MS / 1000),
  });

  return payload;
}

export function readAdminSessionCookie(
  c: Context,
  config: GatewayConfig,
  now = Date.now(),
): AdminSessionPayload | null {
  const raw = getCookie(c, ADMIN_SESSION_COOKIE_NAME);
  return verifySessionCookie(raw, resolveSigningSecret(config), now);
}

export function clearAdminSessionCookie(c: Context): void {
  deleteCookie(c, ADMIN_SESSION_COOKIE_NAME, { path: '/admin' });
}

export function setAdminCsrfCookie(c: Context, config: GatewayConfig, csrfToken: string): void {
  setCookie(c, ADMIN_CSRF_COOKIE_NAME, csrfToken, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: isHttpsDomain(config),
    path: '/',
    maxAge: SHORT_AUTH_COOKIE_MAX_AGE_SEC,
  });
}

export function readAdminCsrfCookie(c: Context): string | undefined {
  return getCookie(c, ADMIN_CSRF_COOKIE_NAME);
}

export function clearAdminCsrfCookie(c: Context): void {
  deleteCookie(c, ADMIN_CSRF_COOKIE_NAME, { path: '/' });
}

export function setMcpAuthBindCookie(c: Context, config: GatewayConfig, bindingHash: string): void {
  setCookie(c, MCP_AUTH_BIND_COOKIE_NAME, bindingHash, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: isHttpsDomain(config),
    path: '/',
    maxAge: SHORT_AUTH_COOKIE_MAX_AGE_SEC,
  });
}

export function readMcpAuthBindCookie(c: Context): string | undefined {
  return getCookie(c, MCP_AUTH_BIND_COOKIE_NAME);
}

export function clearMcpAuthBindCookie(c: Context): void {
  deleteCookie(c, MCP_AUTH_BIND_COOKIE_NAME, { path: '/' });
}

export function setUpstreamOAuthCookie(
  c: Context,
  config: GatewayConfig,
  bindingNonce: string,
): void {
  setCookie(c, UPSTREAM_OAUTH_COOKIE_NAME, bindingNonce, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: isHttpsDomain(config),
    path: '/auth/idp',
    maxAge: SHORT_AUTH_COOKIE_MAX_AGE_SEC,
  });
}

export function readUpstreamOAuthCookie(c: Context): string | undefined {
  return getCookie(c, UPSTREAM_OAUTH_COOKIE_NAME);
}

export function clearUpstreamOAuthCookie(c: Context): void {
  deleteCookie(c, UPSTREAM_OAUTH_COOKIE_NAME, { path: '/auth/idp' });
}
