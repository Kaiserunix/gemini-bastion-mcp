import crypto from 'node:crypto';

export interface PublicLandingPageInput {
  publicDomain: string;
  dbReady: boolean;
  uptimeSec: number;
}

export interface PublicGatewayStatusJson {
  service: 'gemini-bastion-mcp';
  brand: 'GeminiBastionMCP';
  version: '0.2.0';
  status: 'online' | 'degraded';
  dbReady: boolean;
  mcpEndpoint: string;
  oauthMetadata: string;
  protectedResourceMetadata: string;
  adminUrl: string;
  toolsCount: 10;
  uptimeSec: number;
}

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatUptime(uptimeSec: number): string {
  const secs = Math.max(0, Math.floor(uptimeSec));
  const days = Math.floor(secs / 86400);
  const hours = Math.floor((secs % 86400) / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${mins}m`;
  if (hours > 0) return `${hours}h ${mins}m`;
  if (mins > 0) return `${mins}m ${secs % 60}s`;
  return `${secs}s`;
}

const COPY_SCRIPT_BODY = `
(function () {
  var btn = document.getElementById('copy-mcp-btn');
  var input = document.getElementById('mcp-endpoint-input');
  var statusEl = document.getElementById('copy-status');
  if (!btn || !input) return;
  btn.addEventListener('click', function () {
    var value = input.value || input.textContent || '';
    var done = function () {
      btn.textContent = 'Copied';
      if (statusEl) statusEl.textContent = 'Copied /mcp URL to clipboard';
      setTimeout(function () {
        btn.textContent = 'Copy';
        if (statusEl) statusEl.textContent = '';
      }, 1800);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(done).catch(function () {
        input.select();
        document.execCommand('copy');
        done();
      });
    } else {
      input.select();
      document.execCommand('copy');
      done();
    }
  });
})();
`.trim();

export const LANDING_PAGE_SCRIPT_CSP_HASH =
  "'sha256-" + crypto.createHash('sha256').update(COPY_SCRIPT_BODY, 'utf8').digest('base64') + "'";

export const LANDING_PAGE_CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  `script-src ${LANDING_PAGE_SCRIPT_CSP_HASH}`,
  "img-src 'self' data:",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

/**
 * Builds the zero-leakage JSON status payload for `GET /` content negotiation.
 */
export function buildPublicGatewayStatusJson(
  input: PublicLandingPageInput,
): PublicGatewayStatusJson {
  const base = input.publicDomain.replace(/\/+$/, '');
  return {
    service: 'gemini-bastion-mcp',
    brand: 'GeminiBastionMCP',
    version: '0.2.0',
    status: input.dbReady ? 'online' : 'degraded',
    dbReady: input.dbReady,
    mcpEndpoint: `${base}/mcp`,
    oauthMetadata: `${base}/.well-known/oauth-authorization-server`,
    protectedResourceMetadata: `${base}/.well-known/oauth-protected-resource`,
    adminUrl: '/admin',
    toolsCount: 10,
    uptimeSec: Math.max(0, Math.floor(input.uptimeSec)),
  };
}

/**
 * Renders the zero-leakage Public Gateway Portal HTML for `GET /`.
 * Never queries or exposes private workspaces, repo URLs, jobs, OAuth clients/tokens, or secrets.
 */
export function renderPublicLandingPageHtml(input: PublicLandingPageInput): string {
  const status = buildPublicGatewayStatusJson(input);
  const safeEndpoint = escapeHtml(status.mcpEndpoint);
  const safeOAuthMeta = escapeHtml(status.oauthMetadata);
  const safeResourceMeta = escapeHtml(status.protectedResourceMetadata);
  const safeUptime = escapeHtml(formatUptime(status.uptimeSec));
  const statusLabel = status.dbReady ? 'ONLINE' : 'DEGRADED';
  const statusColor = status.dbReady ? '#22c55e' : '#f59e0b';
  const dbLabel = status.dbReady ? 'SQLite WAL Engine: Ready' : 'SQLite WAL Engine: Degraded';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GeminiBastionMCP v0.2.0 — Remote MCP Bastion for Web Gemini, Claude &amp; ChatGPT</title>
  <style>
    :root {
      --bg: #0b1020;
      --card: #131a2e;
      --card-2: #0f1628;
      --border: #233054;
      --text: #e6ecff;
      --muted: #93a3c8;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --green: #22c55e;
      --yellow: #f59e0b;
      --red: #ef4444;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: radial-gradient(circle at top right, #182347 0%, var(--bg) 52%);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
      line-height: 1.5;
      padding: 24px 16px 48px;
    }
    .wrap { max-width: 920px; margin: 0 auto; }
    .topbar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 24px;
      padding: 12px 16px;
      background: rgba(19, 26, 46, 0.85);
      border: 1px solid var(--border);
      border-radius: 14px;
    }
    .brand-row { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 1.05rem; }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      letter-spacing: 0.04em;
      padding: 4px 10px;
      border-radius: 999px;
      background: rgba(34, 197, 94, 0.14);
      border: 1px solid ${statusColor};
      color: ${statusColor};
    }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: ${statusColor}; }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      padding: 9px 15px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--accent);
      color: #fff;
      font-weight: 600;
      font-size: 0.9rem;
      text-decoration: none;
      cursor: pointer;
    }
    .btn:hover { background: var(--accent-hover); }
    .btn-ghost { background: var(--card-2); color: var(--text); }
    .btn-ghost:hover { border-color: var(--accent); background: #17213d; }
    .hero { margin-bottom: 20px; }
    .hero h1 { margin: 0 0 8px; font-size: clamp(1.5rem, 3.2vw, 2.1rem); letter-spacing: -0.02em; }
    .hero p { margin: 0; color: var(--muted); font-size: 0.98rem; }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 18px 20px;
      margin-bottom: 16px;
    }
    .card-title { margin: 0 0 10px; font-size: 0.95rem; font-weight: 700; color: #c7d5ff; text-transform: uppercase; letter-spacing: 0.05em; }
    .endpoint-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: stretch; }
    .endpoint-input {
      flex: 1 1 260px;
      min-width: 0;
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--card-2);
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.9rem;
    }
    .meta-list {
      margin: 12px 0 0;
      padding: 0;
      list-style: none;
      display: grid;
      gap: 6px;
      font-size: 0.86rem;
      color: var(--muted);
    }
    .meta-list a { color: #7db0ff; text-decoration: none; word-break: break-all; }
    .meta-list a:hover { text-decoration: underline; }
    .grid-3 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
    }
    .mini-card {
      background: var(--card-2);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px;
    }
    .mini-card h3 { margin: 0 0 6px; font-size: 0.95rem; color: var(--text); }
    .mini-card p { margin: 0; font-size: 0.85rem; color: var(--muted); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; color: #b9ccff; }
    .badges { display: flex; flex-wrap: wrap; gap: 8px; }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 5px 10px;
      border-radius: 999px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.8rem;
      background: var(--card-2);
      border: 1px solid var(--border);
    }
    .tier-1 { border-color: rgba(34, 197, 94, 0.45); color: #bdf7cf; }
    .tier-2 { border-color: rgba(245, 158, 11, 0.55); color: #fde68a; }
    .tier-3 { border-color: rgba(239, 68, 68, 0.65); color: #fecaca; }
    .cta { display: flex; justify-content: center; margin-top: 20px; }
    #copy-status { margin-top: 8px; min-height: 1.1em; font-size: 0.82rem; color: #86efac; }
  </style>
</head>
<body>
  <main class="wrap">
    <header class="topbar">
      <div class="brand-row">
        <span class="pill"><span class="dot"></span>${statusLabel}</span>
        <span>GeminiBastionMCP</span>
        <span class="mono">v0.2.0</span>
      </div>
      <a class="btn btn-ghost" href="/admin">Operator /admin &rarr;</a>
    </header>

    <section class="hero">
      <h1>Remote MCP 2025-11-25 &amp; OAuth 2.1 Bastion for Web Gemini, Claude.ai &amp; ChatGPT</h1>
      <p>Stateless Streamable HTTP &middot; PKCE (S256) &middot; Dynamic Client Registration &middot; Per-Workspace bwrap Jail &middot; 10 Tools, 1 Approval Gate</p>
    </section>

    <section class="card">
      <h2 class="card-title">MCP Streamable HTTP Endpoint</h2>
      <div class="endpoint-row">
        <input id="mcp-endpoint-input" class="endpoint-input" type="text" readonly value="${safeEndpoint}" aria-label="MCP Endpoint URL" />
        <button id="copy-mcp-btn" class="btn" type="button">Copy</button>
      </div>
      <div id="copy-status" aria-live="polite"></div>
      <ul class="meta-list">
        <li>OAuth 2.1 Metadata: <a href="/.well-known/oauth-authorization-server">${safeOAuthMeta}</a></li>
        <li>Protected Resource: <a href="/.well-known/oauth-protected-resource">${safeResourceMeta}</a></li>
        <li>${escapeHtml(dbLabel)} &middot; Uptime: ${safeUptime}</li>
      </ul>
    </section>

    <section class="card">
      <h2 class="card-title">Quick Connect — Web Gemini, Claude.ai &amp; ChatGPT</h2>
      <div class="grid-3">
        <article class="mini-card">
          <h3>Web Gemini (gemini.google.com)</h3>
          <p>Open <strong>Connected Apps</strong> &rarr; Add custom MCP &rarr; paste the <span class="mono">/mcp</span> URL above. OAuth 2.1 DCR + PKCE runs automatically.</p>
        </article>
        <article class="mini-card">
          <h3>Claude.ai &amp; ChatGPT</h3>
          <p>Add a <strong>Custom Connector</strong> pointing to the <span class="mono">/mcp</span> endpoint. Supports stateless Streamable HTTP and RFC 8707 resource binding.</p>
        </article>
        <article class="mini-card">
          <h3>Static OAuth &amp; SSO</h3>
          <p>Authorize: <span class="mono">/oauth/authorize</span><br />Token: <span class="mono">/oauth/token</span><br />DCR: <span class="mono">/oauth/register</span></p>
        </article>
      </div>
    </section>

    <section class="card">
      <h2 class="card-title">10-Tool Contract &amp; Multi-Agent Drivers</h2>
      <div class="badges" style="margin-bottom: 10px;">
        <span class="badge tier-1">&#x1F7E2; workspace_manage</span>
        <span class="badge tier-1">&#x1F7E2; code_explore</span>
        <span class="badge tier-1">&#x1F7E2; code_patch</span>
        <span class="badge tier-1">&#x1F7E2; workspace_exec</span>
        <span class="badge tier-1">&#x1F7E2; dispatch_runner</span>
        <span class="badge tier-1">&#x1F7E2; job_status</span>
        <span class="badge tier-1">&#x1F7E2; github_inspect</span>
        <span class="badge tier-1">&#x1F7E2; infra_inspect</span>
        <span class="badge tier-2">&#x1F7E1; stage_mutation_plan</span>
        <span class="badge tier-3">&#x1F534; publish_changes (Single External Write Gate)</span>
      </div>
      <div class="badges">
        <span class="badge">Drivers: Codex SDK / Claude Code / Gemini CLI / OpenCode</span>
        <span class="badge">Isolation: bwrap FS &amp; --unshare-net Jail</span>
        <span class="badge">Federation: Authenticated MCP-2 Proxy</span>
      </div>
    </section>

    <div class="cta">
      <a class="btn" href="/admin">Sign in to Operator Console (/admin)</a>
    </div>
  </main>
  <script>${COPY_SCRIPT_BODY}</script>
</body>
</html>`;
}
