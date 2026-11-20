import { Hono } from 'hono';
import type { GatewayConfig } from '../types.js';

export const DEFAULT_SCOPES_SUPPORTED = ['mcp:tools', 'mcp:read', 'mcp:write'] as const;

/**
 * Returns the canonical RFC 8707 MCP resource URI for the gateway (`https://{PUBLIC_DOMAIN}/mcp`).
 */
export function getCanonicalResource(publicDomain: string): string {
  return `${publicDomain.replace(/\/+$/, '')}/mcp`;
}

/**
 * Validates an RFC 8707 `resource` parameter against the gateway's configured `PUBLIC_DOMAIN`.
 */
export function isValidResource(resource: string, publicDomain: string): boolean {
  const normalizedBase = publicDomain.replace(/\/+$/, '');
  return resource === normalizedBase || resource === `${normalizedBase}/mcp`;
}

/**
 * Builds RFC 9728 OAuth Protected Resource Metadata payload.
 */
export function buildProtectedResourceMetadata(config: GatewayConfig): Record<string, unknown> {
  const base = config.publicDomain.replace(/\/+$/, '');
  return {
    resource: `${base}/mcp`,
    authorization_servers: [base],
    bearer_methods_supported: ['header'],
    scopes_supported: [...DEFAULT_SCOPES_SUPPORTED],
  };
}

/**
 * Builds RFC 8414 OAuth Authorization Server Metadata payload.
 */
export function buildAuthorizationServerMetadata(config: GatewayConfig): Record<string, unknown> {
  const base = config.publicDomain.replace(/\/+$/, '');
  return {
    issuer: base,
    authorization_endpoint: `${base}/oauth/authorize`,
    token_endpoint: `${base}/oauth/token`,
    revocation_endpoint: `${base}/oauth/revoke`,
    registration_endpoint: `${base}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: [...DEFAULT_SCOPES_SUPPORTED],
  };
}

/**
 * Mounts RFC 9728 and RFC 8414 `.well-known` OAuth discovery endpoints.
 */
export function createDiscoveryRoutes(config: GatewayConfig): Hono {
  const app = new Hono();

  app.get('/.well-known/oauth-protected-resource', (c) => {
    return c.json(buildProtectedResourceMetadata(config), 200, {
      'Cache-Control': 'no-store',
    });
  });

  app.get('/.well-known/oauth-protected-resource/mcp', (c) => {
    return c.json(buildProtectedResourceMetadata(config), 200, {
      'Cache-Control': 'no-store',
    });
  });

  app.get('/.well-known/oauth-authorization-server', (c) => {
    return c.json(buildAuthorizationServerMetadata(config), 200, {
      'Cache-Control': 'no-store',
    });
  });

  return app;
}
