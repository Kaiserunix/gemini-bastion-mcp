import crypto from 'node:crypto';

export interface PublicLandingPageInput {
  publicDomain: string;
  dbReady: boolean;
  uptimeSec: number;
}

export interface PublicGatewayStatusJson {
  service: 'gemini-bastion-mcp';
  brand: 'GeminiBastionMCP';
  version: '0.3.0';
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
      if (statusEl) statusEl.textContent = 'Copied /mcp endpoint URL to clipboard.';
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
    version: '0.3.0',
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
  const statusState = status.dbReady ? 'Operational' : 'Degraded';
  const dotClass = status.dbReady ? 'dot-sage' : 'dot-ochre';
  const dbLabel = status.dbReady ? 'SQLite WAL Ready' : 'SQLite WAL Degraded';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>GeminiBastionMCP v0.3.0 — OAuth 2.1 Streamable HTTP Gateway</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #FBFBFB;
      --surface: #FFFFFF;
      --subtle: #F4F4F5;
      --border: #E4E4E7;
      --ink: #111113;
      --secondary: #52525B;
      --muted: #71717A;
      --cta-bg: #111113;
      --cta-hover: #27272A;
      --cta-fg: #FFFFFF;
      --sage: #047857;
      --sage-bg: #ECFDF5;
      --ochre: #B45309;
      --ochre-bg: #FFFBEB;
      --crimson: #B91C1C;
      --crimson-bg: #FEF2F2;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #09090B;
        --surface: #111113;
        --subtle: #18181B;
        --border: #27272A;
        --ink: #FAFAFA;
        --secondary: #A1A1AA;
        --muted: #71717A;
        --cta-bg: #FAFAFA;
        --cta-hover: #E4E4E7;
        --cta-fg: #09090B;
        --sage: #10B981;
        --sage-bg: rgba(16, 185, 129, 0.12);
        --ochre: #F59E0B;
        --ochre-bg: rgba(245, 158, 11, 0.12);
        --crimson: #F87171;
        --crimson-bg: rgba(248, 113, 113, 0.12);
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--ink);
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "SF Pro Text", "Segoe UI", system-ui, sans-serif;
      -webkit-font-smoothing: antialiased;
      line-height: 1.55;
      padding: 40px 20px 64px;
    }
    .wrap {
      max-width: 680px;
      margin: 0 auto;
    }
    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 36px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
    }
    .brand-mark {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 28px;
      height: 28px;
      border-radius: 7px;
      background: var(--subtle);
      border: 1px solid var(--border);
      color: var(--ink);
      flex-shrink: 0;
    }
    .brand-name {
      font-size: 0.95rem;
      font-weight: 600;
      letter-spacing: -0.015em;
      color: var(--ink);
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 3px 9px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--surface);
      font-size: 0.75rem;
      font-weight: 500;
      color: var(--secondary);
      font-variant-numeric: tabular-nums;
    }
    .dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      flex-shrink: 0;
    }
    .dot-sage { background: var(--sage); }
    .dot-ochre { background: var(--ochre); }
    .nav-link {
      font-size: 0.85rem;
      font-weight: 500;
      color: var(--secondary);
      text-decoration: none;
      transition: color 0.15s ease;
    }
    .nav-link:hover { color: var(--ink); }
    .hero {
      margin-bottom: 28px;
    }
    .hero h1 {
      margin: 0 0 8px;
      font-size: clamp(1.5rem, 3vw, 1.85rem);
      font-weight: 600;
      letter-spacing: -0.025em;
      line-height: 1.25;
      color: var(--ink);
    }
    .hero p {
      margin: 0;
      font-size: 0.95rem;
      color: var(--secondary);
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px 22px;
      margin-bottom: 16px;
    }
    .section-label {
      margin: 0 0 12px;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.04em;
      text-transform: uppercase;
      color: var(--muted);
    }
    .endpoint-row {
      display: flex;
      gap: 8px;
      align-items: stretch;
    }
    .endpoint-input {
      flex: 1 1 auto;
      min-width: 0;
      padding: 9px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--subtle);
      color: var(--ink);
      font-family: "SF Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.84rem;
      outline: none;
    }
    .endpoint-input:focus { border-color: var(--ink); }
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 9px 16px;
      border-radius: 8px;
      border: 1px solid transparent;
      background: var(--cta-bg);
      color: var(--cta-fg);
      font-size: 0.84rem;
      font-weight: 500;
      cursor: pointer;
      white-space: nowrap;
      text-decoration: none;
      transition: background-color 0.15s ease;
    }
    .btn:hover { background: var(--cta-hover); }
    #copy-status {
      min-height: 1.15em;
      margin-top: 6px;
      font-size: 0.78rem;
      color: var(--sage);
    }
    .kv-list {
      margin: 12px 0 0;
      padding: 12px 0 0;
      border-top: 1px solid var(--border);
      display: grid;
      gap: 8px;
    }
    .kv-row {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 16px;
      flex-wrap: wrap;
      font-size: 0.82rem;
    }
    .kv-key { color: var(--muted); flex-shrink: 0; }
    .kv-val {
      font-family: "SF Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.78rem;
      color: var(--secondary);
      text-decoration: none;
      word-break: break-all;
      text-align: right;
    }
    .kv-val:hover { color: var(--ink); text-decoration: underline; }
    .kv-static {
      font-size: 0.8rem;
      color: var(--muted);
      font-variant-numeric: tabular-nums;
    }
    .connect-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }
    .connect-item {
      padding: 12px 14px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg);
    }
    .connect-item h3 {
      margin: 0 0 4px;
      font-size: 0.84rem;
      font-weight: 600;
      color: var(--ink);
    }
    .connect-item p {
      margin: 0;
      font-size: 0.79rem;
      line-height: 1.45;
      color: var(--secondary);
    }
    .mono-inline {
      font-family: "SF Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.76rem;
      color: var(--ink);
    }
    .tool-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 1px;
      background: var(--border);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .tool-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      padding: 9px 12px;
      background: var(--surface);
      font-size: 0.8rem;
    }
    .tool-name {
      font-family: "SF Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.79rem;
      color: var(--ink);
    }
    .tier-tag {
      font-size: 0.7rem;
      font-weight: 500;
      padding: 1px 7px;
      border-radius: 999px;
      border: 1px solid var(--border);
      color: var(--muted);
      background: var(--subtle);
      white-space: nowrap;
    }
    .tier-stage {
      color: var(--ochre);
      background: var(--ochre-bg);
      border-color: rgba(180, 83, 9, 0.25);
    }
    .tier-gate {
      color: var(--crimson);
      background: var(--crimson-bg);
      border-color: rgba(185, 28, 28, 0.25);
    }
    .cap-note {
      margin: 12px 0 0;
      font-size: 0.79rem;
      line-height: 1.5;
      color: var(--muted);
    }
    .footer {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 24px;
      padding-top: 18px;
      border-top: 1px solid var(--border);
      font-size: 0.8rem;
      color: var(--muted);
    }
    @media (max-width: 600px) {
      body { padding: 24px 16px 48px; }
      .connect-grid, .tool-grid { grid-template-columns: 1fr; }
      .endpoint-row { flex-direction: column; }
      .kv-val { text-align: left; }
    }
  </style>
</head>
<body>
  <main class="wrap">
    <header class="topbar">
      <div class="brand">
        <span class="brand-mark" aria-hidden="true">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 3l7 3v5c0 4.9-3 8.9-7 10-4-1.1-7-5.1-7-10V6l7-3z" />
            <path d="M9.5 12l1.8 1.8L15 10" />
          </svg>
        </span>
        <span class="brand-name">GeminiBastionMCP</span>
        <span class="status-pill"><span class="dot ${dotClass}"></span>${statusState} &middot; v0.3.0</span>
      </div>
      <a class="nav-link" href="/admin">Operator Console &rarr;</a>
    </header>

    <section class="hero">
      <h1>Remote MCP 2025-11-25 &amp; OAuth 2.1 Gateway</h1>
      <p>Self-hosted OAuth 2.1 Streamable HTTP gateway for Web Gemini, Claude.ai, and ChatGPT.</p>
    </section>

    <section class="card">
      <h2 class="section-label">MCP Streamable HTTP Endpoint</h2>
      <div class="endpoint-row">
        <input id="mcp-endpoint-input" class="endpoint-input" type="text" readonly value="${safeEndpoint}" aria-label="MCP Endpoint URL" />
        <button id="copy-mcp-btn" class="btn" type="button">Copy</button>
      </div>
      <div id="copy-status" aria-live="polite"></div>
      <div class="kv-list">
        <div class="kv-row">
          <span class="kv-key">OAuth Authorization Server</span>
          <a class="kv-val" href="/.well-known/oauth-authorization-server">${safeOAuthMeta}</a>
        </div>
        <div class="kv-row">
          <span class="kv-key">Protected Resource Metadata</span>
          <a class="kv-val" href="/.well-known/oauth-protected-resource">${safeResourceMeta}</a>
        </div>
        <div class="kv-row">
          <span class="kv-key">Runtime Health</span>
          <span class="kv-static">${escapeHtml(dbLabel)} &middot; Uptime ${safeUptime}</span>
        </div>
      </div>
    </section>

    <section class="card">
      <h2 class="section-label">Connect Client</h2>
      <div class="connect-grid">
        <article class="connect-item">
          <h3>Web Gemini</h3>
          <p>Open <strong>Connected Apps</strong> &rarr; Add custom MCP &rarr; paste the <span class="mono-inline">/mcp</span> URL. OAuth 2.1 DCR &amp; PKCE (S256) run automatically.</p>
        </article>
        <article class="connect-item">
          <h3>Claude.ai &amp; ChatGPT</h3>
          <p>Add a <strong>Custom Connector</strong> using the <span class="mono-inline">/mcp</span> endpoint with stateless Streamable HTTP and RFC 8707 resource binding.</p>
        </article>
        <article class="connect-item">
          <h3>Static OAuth</h3>
          <p><span class="mono-inline">/oauth/authorize</span><br /><span class="mono-inline">/oauth/token</span><br /><span class="mono-inline">/oauth/register</span></p>
        </article>
      </div>
    </section>

    <section class="card">
      <h2 class="section-label">10-Tool Surface &amp; Single Approval Gate</h2>
      <div class="tool-grid">
        <div class="tool-row"><span class="tool-name">workspace_manage</span><span class="tier-tag">Workspace</span></div>
        <div class="tool-row"><span class="tool-name">code_explore</span><span class="tier-tag">Read</span></div>
        <div class="tool-row"><span class="tool-name">code_patch</span><span class="tier-tag">Sandbox</span></div>
        <div class="tool-row"><span class="tool-name">workspace_exec</span><span class="tier-tag">Sandbox</span></div>
        <div class="tool-row"><span class="tool-name">dispatch_runner</span><span class="tier-tag">Drivers</span></div>
        <div class="tool-row"><span class="tool-name">job_status</span><span class="tier-tag">Read</span></div>
        <div class="tool-row"><span class="tool-name">github_inspect</span><span class="tier-tag">Read</span></div>
        <div class="tool-row"><span class="tool-name">infra_inspect</span><span class="tier-tag">Read</span></div>
        <div class="tool-row"><span class="tool-name">stage_mutation_plan</span><span class="tier-tag tier-stage">Stage</span></div>
        <div class="tool-row"><span class="tool-name">publish_changes</span><span class="tier-tag tier-gate">Approval Gate</span></div>
      </div>
      <p class="cap-note">
        Isolated via <span class="mono-inline">bwrap</span> filesystem &amp; network jails &middot; Multi-agent drivers (Codex SDK, Claude Code, Gemini CLI, OpenCode) &middot; Persistent Memory &middot; 4 MCP Prompts &middot; Read-Only CI Watchdog &middot; Authenticated MCP-2 Federation.
      </p>
    </section>

    <footer class="footer">
      <span>Zero private workspace or credential data is exposed on this page.</span>
      <a class="nav-link" href="/admin">Sign in to /admin &rarr;</a>
    </footer>
  </main>
  <script>${COPY_SCRIPT_BODY}</script>
</body>
</html>`;
}
