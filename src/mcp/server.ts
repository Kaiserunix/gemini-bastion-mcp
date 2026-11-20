import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import type { Context } from 'hono';
import type { OAuthAuthContext } from '../auth/middleware.js';
import { registerAllMcpTools, type McpToolDeps } from './tools/index.js';

export interface McpServerOptions {
  name?: string;
  version?: string;
  enableJsonResponse?: boolean;
}

/**
 * Creates and configures a fresh McpServer instance with all 10 tools registered.
 */
export function createMcpServer(
  deps: McpToolDeps,
  options: McpServerOptions = {},
): McpServer {
  const server = new McpServer({
    name: options.name ?? 'gemini-bastion-mcp',
    version: options.version ?? '1.0.0',
  });

  registerAllMcpTools(server, deps);
  return server;
}

const STATIC_ALLOWED_MCP_ORIGINS = new Set([
  'https://gemini.google.com',
  'https://aistudio.google.com',
  'https://claude.ai',
  'https://chatgpt.com',
]);

export function isAllowedMcpOrigin(
  originHeader: string,
  deps: Pick<McpToolDeps, 'config'>,
): boolean {
  let parsed: URL;
  try {
    parsed = new URL(originHeader);
  } catch {
    return false;
  }

  if (parsed.origin === 'null') {
    return false;
  }

  try {
    const publicOrigin = new URL(deps.config.publicDomain).origin;
    if (parsed.origin === publicOrigin) {
      return true;
    }
  } catch {
    // ignore malformed publicDomain
  }

  if (STATIC_ALLOWED_MCP_ORIGINS.has(parsed.origin)) {
    return true;
  }

  const hostname = parsed.hostname.toLowerCase();
  const isLoopback = hostname === 'localhost' || hostname === '127.0.0.1';
  if (parsed.protocol !== 'https:' && !(isLoopback && parsed.protocol === 'http:')) {
    return false;
  }

  return deps.config.oauthAllowedRedirectHosts.some(
    (allowed) => allowed.toLowerCase() === hostname,
  );
}

/**
 * Creates a stateless Streamable HTTP Hono handler for `/mcp`:
 * - Enforces Origin allowlist when `Origin` header is present (403 on disallowed browser Origins)
 * - POST /mcp -> WebStandardStreamableHTTPServerTransport (sessionIdGenerator: undefined)
 * - GET /mcp and DELETE /mcp -> 405 Method Not Allowed (no legacy HTTP+SSE)
 */
export function createMcpHttpHandler(
  deps: McpToolDeps,
  options: McpServerOptions = {},
): (c: Context) => Promise<Response> {
  const enableJsonResponse = options.enableJsonResponse ?? true;

  return async (c: Context): Promise<Response> => {
    const originHeader = c.req.header('origin');
    if (originHeader !== undefined && !isAllowedMcpOrigin(originHeader, deps)) {
      return c.json(
        {
          jsonrpc: '2.0',
          error: {
            code: -32000,
            message: 'Origin not allowed for /mcp endpoint.',
          },
          id: null,
        },
        403,
      );
    }

    const method = c.req.method.toUpperCase();

    if (method === 'GET' || method === 'DELETE') {
      return c.json(
        {
          jsonrpc: '2.0',
          error: {
            code: -32000,
            message: `Method ${method} not allowed in stateless Streamable HTTP mode.`,
          },
          id: null,
        },
        405,
        { Allow: 'POST' },
      );
    }

    if (method !== 'POST') {
      return c.json(
        {
          jsonrpc: '2.0',
          error: {
            code: -32000,
            message: `Unsupported HTTP method: ${method}`,
          },
          id: null,
        },
        405,
        { Allow: 'POST' },
      );
    }

    const oauthAuth = c.get('oauthAuth') as OAuthAuthContext | undefined;
    const server = createMcpServer(deps, options);
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse,
    });

    await server.connect(transport);

    try {
      const response = await transport.handleRequest(c.req.raw, {
        ...(oauthAuth
          ? {
              authInfo: {
                token: '',
                clientId: oauthAuth.clientId,
                scopes: oauthAuth.scope.split(/\s+/).filter(Boolean),
              },
            }
          : {}),
      });
      return response;
    } finally {
      if (enableJsonResponse) {
        await Promise.allSettled([transport.close(), server.close()]);
      }
    }
  };
}
