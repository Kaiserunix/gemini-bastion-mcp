import crypto from 'node:crypto';
import http from 'node:http';

const LISTEN_HOST = process.env.OPS_PROXY_HOST || '0.0.0.0';
const LISTEN_PORT = Number(process.env.OPS_PROXY_PORT || '9000');
const UPSTREAM_HOST = process.env.OPS_UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number(process.env.OPS_UPSTREAM_PORT || '9001');
const AUTH_TOKEN = process.env.OPS_MCP_AUTH_TOKEN || '';

if (AUTH_TOKEN.length < 24) {
  console.error('ERROR: OPS_MCP_AUTH_TOKEN must be set and at least 24 characters long (fail-closed).');
  process.exit(1);
}

const EXPECTED_DIGEST = crypto.createHash('sha256').update(AUTH_TOKEN, 'utf8').digest();

function isAuthorized(authHeader) {
  if (typeof authHeader !== 'string') return false;
  const match = /^Bearer\s+(.+)$/i.exec(authHeader.trim());
  if (!match) return false;
  const providedDigest = crypto.createHash('sha256').update(match[1], 'utf8').digest();
  return crypto.timingSafeEqual(providedDigest, EXPECTED_DIGEST);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'ops-mcp-auth-proxy' }));
    return;
  }

  if (!isAuthorized(req.headers.authorization)) {
    res.writeHead(401, {
      'content-type': 'application/json',
      'www-authenticate': 'Bearer realm="ops-mcp"',
    });
    res.end(JSON.stringify({ error: 'unauthorized' }));
    return;
  }

  const headers = { ...req.headers };
  delete headers.authorization;
  headers.host = `${UPSTREAM_HOST}:${UPSTREAM_PORT}`;

  const upstreamReq = http.request(
    {
      hostname: UPSTREAM_HOST,
      port: UPSTREAM_PORT,
      path: req.url || '/',
      method: req.method,
      headers,
    },
    (upstreamRes) => {
      upstreamRes.on('error', (err) => {
        if (!res.destroyed) res.destroy(err);
      });
      res.writeHead(upstreamRes.statusCode || 502, upstreamRes.headers);
      upstreamRes.pipe(res);
    },
  );

  upstreamReq.on('error', (err) => {
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'upstream_unavailable', message: err.message }));
    } else if (!res.destroyed) {
      res.destroy(err);
    }
  });

  req.on('error', (err) => {
    if (!upstreamReq.destroyed) upstreamReq.destroy(err);
  });

  res.on('error', () => {
    if (!upstreamReq.destroyed) upstreamReq.destroy();
  });

  res.on('close', () => {
    if (!res.writableEnded && !upstreamReq.destroyed) {
      upstreamReq.destroy();
    }
  });

  req.pipe(upstreamReq);
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(`ops-mcp-auth-proxy listening on ${LISTEN_HOST}:${LISTEN_PORT} -> ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
});

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    server.close(() => process.exit(0));
  });
}
