import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import type { Context } from 'hono';
import type { OAuthAuthContext } from '../auth/middleware.js';
import { registerAllMcpTools, type McpToolDeps } from './tools/index.js';

export const DEFAULT_MAX_MCP_BODY_BYTES = 10 * 1024 * 1024;

export interface McpServerOptions {
  name?: string;
  version?: string;
  enableJsonResponse?: boolean;
  maxBodyBytes?: number;
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

async function readBoundedMcpRequest(
  rawReq: Request,
  maxBytes: number,
): Promise<{ ok: true; request: Request } | { ok: false }> {
  const declaredHeader = rawReq.headers.get('content-length');
  if (declaredHeader !== null) {
    const declared = Number(declaredHeader);
    if (Number.isFinite(declared) && declared > maxBytes) {
      return { ok: false };
    }
  }

  if (!rawReq.body) {
    return { ok: true, request: rawReq };
  }

  const reader = rawReq.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return { ok: false };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const merged = Buffer.concat(
    chunks.map((chunk) => Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength)),
  );
  const headers = new Headers(rawReq.headers);
  headers.set('content-length', String(merged.byteLength));
  const reconstructed = new Request(rawReq.url, {
    method: rawReq.method,
    headers,
    body: merged,
  });
  return { ok: true, request: reconstructed };
}

/**
 * Creates a stateless Streamable HTTP Hono handler for `/mcp`:
 * - Enforces Origin allowlist when `Origin` header is present (403 on disallowed browser Origins)
 * - Enforces bounded request body size ceiling (413 Payload Too Large)
 * - POST /mcp -> WebStandardStreamableHTTPServerTransport (sessionIdGenerator: undefined)
 * - GET /mcp and DELETE /mcp -> 405 Method Not Allowed (no legacy HTTP+SSE)
 */
export function createMcpHttpHandler(
  deps: McpToolDeps,
  options: McpServerOptions = {},
): (c: Context) => Promise<Response> {
  const enableJsonResponse = options.enableJsonResponse ?? true;
  const maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_MCP_BODY_BYTES;

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
        {
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        },
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
        {
          Allow: 'POST',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        },
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
        {
          Allow: 'POST',
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        },
      );
    }

    const bounded = await readBoundedMcpRequest(c.req.raw, maxBodyBytes);
    if (!bounded.ok) {
      return c.json(
        {
          jsonrpc: '2.0',
          error: {
            code: -32000,
            message: `Request body exceeds maximum allowed size (${maxBodyBytes} bytes).`,
          },
          id: null,
        },
        413,
        {
          'Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        },
      );
    }

    const oauthAuth = c.get('oauthAuth') as OAuthAuthContext | undefined;
    const server = createMcpServer(deps, options);
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse,
    });

    await server.connect(transport);

    let shouldClose = enableJsonResponse;
    try {
      const response = await transport.handleRequest(bounded.request, {
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
      const headers = new Headers(response.headers);
      if (!headers.has('cache-control')) {
        headers.set('cache-control', 'no-store');
      }
      if (!headers.has('x-content-type-options')) {
        headers.set('x-content-type-options', 'nosniff');
      }
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    } catch (err) {
      shouldClose = true;
      throw err;
    } finally {
      if (shouldClose) {
        await Promise.allSettled([transport.close(), server.close()]);
      }
    }
  };
}
