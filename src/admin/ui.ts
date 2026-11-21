function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export interface AdminKpiSummary {
  activeJobs: number;
  stagedPlans: number;
  workspaces: number;
  latestSyncAt: number | null;
  oauthSessions: number;
  memoriesCount: number;
}

const EDITORIAL_THEME_CSS = `
    :root {
      --bg: #FBFBFB;
      --surface: #FFFFFF;
      --subtle: #F4F4F5;
      --border: #E4E4E7;
      --border-strong: #D4D4D8;
      --ink: #111113;
      --ink-2: #52525B;
      --muted: #71717A;
      --cta-bg: #111113;
      --cta-fg: #FFFFFF;
      --cta-hover: #27272A;
      --sage: #047857;
      --sage-bg: #ECFDF5;
      --sage-bd: #A7F3D0;
      --ochre: #B45309;
      --ochre-bg: #FFFBEB;
      --ochre-bd: #FDE68A;
      --crimson: #B91C1C;
      --crimson-bg: #FEF2F2;
      --crimson-bd: #FECACA;
      --shadow: 0 1px 2px rgba(17,17,19,0.04), 0 8px 24px rgba(17,17,19,0.03);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #09090B;
        --surface: #111113;
        --subtle: #18181B;
        --border: #27272A;
        --border-strong: #3F3F46;
        --ink: #FAFAFA;
        --ink-2: #A1A1AA;
        --muted: #71717A;
        --cta-bg: #FAFAFA;
        --cta-fg: #09090B;
        --cta-hover: #E4E4E7;
        --sage: #34D399;
        --sage-bg: rgba(4,120,87,0.14);
        --sage-bd: rgba(52,211,153,0.28);
        --ochre: #FBBF24;
        --ochre-bg: rgba(180,83,9,0.14);
        --ochre-bd: rgba(251,191,36,0.28);
        --crimson: #F87171;
        --crimson-bg: rgba(185,28,28,0.16);
        --crimson-bd: rgba(248,113,113,0.3);
        --shadow: 0 1px 2px rgba(0,0,0,0.4);
      }
    }
`;

const BASTION_MARK_SVG = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M12 2.5L20 6.5V13.2C20 17.6 16.5 20.8 12 22C7.5 20.8 4 17.6 4 13.2V6.5L12 2.5Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>
  <path d="M9 12.2L11.1 14.3L15.3 9.9" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

const GOOGLE_MONO_SVG = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden="true">
  <path d="M21.35 12.23c0-.72-.06-1.41-.18-2.08H12v3.94h5.26a4.5 4.5 0 0 1-1.95 2.95v2.45h3.16c1.85-1.7 2.88-4.21 2.88-7.26Z" fill="currentColor" opacity="0.85"/>
  <path d="M12 21.75c2.63 0 4.84-.87 6.45-2.36l-3.16-2.45c-.87.58-1.99.93-3.29.93-2.53 0-4.68-1.71-5.45-4.01H3.29v2.52A9.75 9.75 0 0 0 12 21.75Z" fill="currentColor" opacity="0.7"/>
  <path d="M6.55 13.86A5.86 5.86 0 0 1 6.24 12c0-.64.11-1.27.31-1.86V7.62H3.29A9.75 9.75 0 0 0 2.25 12c0 1.57.38 3.06 1.04 4.38l3.26-2.52Z" fill="currentColor" opacity="0.55"/>
  <path d="M12 6.13c1.43 0 2.71.49 3.72 1.46l2.79-2.79C16.83 3.24 14.62 2.25 12 2.25a9.75 9.75 0 0 0-8.71 5.37l3.26 2.52c.77-2.3 2.92-4.01 5.45-4.01Z" fill="currentColor"/>
</svg>`;

const GITHUB_MONO_SVG = `<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
  <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.475 2 2 6.475 2 12a9.994 9.994 0 0 0 6.838 9.488c.5.087.687-.213.687-.475 0-.238-.012-1.025-.012-1.863-2.513.463-3.163-.612-3.363-1.175-.112-.287-.6-1.175-1.025-1.412-.35-.188-.85-.65-.012-.663.787-.012 1.35.725 1.537 1.025.9 1.513 2.338 1.088 2.913.825.087-.65.35-1.087.637-1.337-2.225-.25-4.55-1.113-4.55-4.938 0-1.087.388-1.987 1.025-2.687-.1-.25-.45-1.275.1-2.65 0 0 .838-.263 2.75 1.025a9.28 9.28 0 0 1 2.5-.338c.85 0 1.7.113 2.5.338 1.912-1.3 2.75-1.025 2.75-1.025.55 1.375.2 2.4.1 2.65.637.7 1.025 1.587 1.025 2.687 0 3.838-2.337 4.688-4.562 4.938.362.312.675.912.675 1.85 0 1.337-.013 2.412-.013 2.75 0 .262.188.574.688.474A10.016 10.016 0 0 0 22 12c0-5.525-4.475-10-10-10Z"/>
</svg>`;

export function renderAdminManifest(): Record<string, unknown> {
  return {
    name: 'GeminiBastionMCP',
    short_name: 'GeminiBastion',
    description:
      'Editorial operator cockpit for GeminiBastionMCP jobs, workspaces, OAuth sessions, staged plans, and audit logs.',
    start_url: '/admin',
    scope: '/admin',
    display: 'standalone',
    background_color: '#FBFBFB',
    theme_color: '#FBFBFB',
    icons: [
      {
        src: '/admin/icon.svg',
        sizes: 'any',
        type: 'image/svg+xml',
        purpose: 'any maskable',
      },
    ],
  };
}

export function renderAdminIconSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="28" fill="#111113"/>
  <path d="M64 26L98 42V68C98 86.5 83.2 100.2 64 106C44.8 100.2 30 86.5 30 68V42L64 26Z" fill="none" stroke="#FAFAFA" stroke-width="5.5" stroke-linejoin="round"/>
  <path d="M51 66L60 75L78 56" fill="none" stroke="#FAFAFA" stroke-width="5.5" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;
}

export function renderAdminServiceWorker(): string {
  return `const CACHE_NAME = 'gemini-bastion-admin-shell-v3';
const SHELL_URLS = ['/admin/manifest.webmanifest', '/admin/icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_URLS)).catch(() => undefined)
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.pathname.startsWith('/admin/api/') || event.request.method !== 'GET') {
    return;
  }
  if (SHELL_URLS.includes(url.pathname)) {
    event.respondWith(
      caches.match(event.request).then((cached) => cached || fetch(event.request))
    );
  }
});
`;
}

export function renderAdminLoginHtml(params: {
  csrfToken: string;
  errorMessage?: string;
  googleEnabled?: boolean;
  githubEnabled?: boolean;
}): string {
  const { csrfToken, errorMessage, googleEnabled = false, githubEnabled = false } = params;
  const idpForms: string[] = [];
  if (googleEnabled) {
    idpForms.push(`<form method="POST" action="/auth/idp/google/start">
        <input type="hidden" name="purpose" value="admin" />
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
        <button class="btn-idp" type="submit">${GOOGLE_MONO_SVG}<span>Sign in with Google</span></button>
      </form>`);
  }
  if (githubEnabled) {
    idpForms.push(`<form method="POST" action="/auth/idp/github/start">
        <input type="hidden" name="purpose" value="admin" />
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
        <button class="btn-idp" type="submit">${GITHUB_MONO_SVG}<span>Sign in with GitHub</span></button>
      </form>`);
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#FBFBFB" media="(prefers-color-scheme: light)" />
  <meta name="theme-color" content="#09090B" media="(prefers-color-scheme: dark)" />
  <link rel="manifest" href="/admin/manifest.webmanifest" />
  <link rel="icon" href="/admin/icon.svg" type="image/svg+xml" />
  <title>Admin Login — GeminiBastionMCP</title>
  <style>
    ${EDITORIAL_THEME_CSS}
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif;
      background: var(--bg);
      color: var(--ink);
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
      -webkit-font-smoothing: antialiased;
    }
    .card {
      max-width: 400px;
      width: 100%;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 32px;
      box-shadow: var(--shadow);
    }
    .mark {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 0.8125rem;
      font-weight: 600;
      letter-spacing: -0.01em;
      color: var(--ink);
      margin-bottom: 20px;
    }
    h1 {
      margin: 0 0 6px;
      font-size: 1.25rem;
      font-weight: 600;
      letter-spacing: -0.02em;
      color: var(--ink);
    }
    .sub {
      margin: 0 0 22px;
      font-size: 0.875rem;
      line-height: 1.5;
      color: var(--ink-2);
    }
    .err {
      background: var(--crimson-bg);
      border: 1px solid var(--crimson-bd);
      color: var(--crimson);
      padding: 10px 12px;
      border-radius: 8px;
      font-size: 0.8125rem;
      line-height: 1.45;
      margin-bottom: 16px;
    }
    label {
      display: block;
      font-size: 0.8125rem;
      font-weight: 500;
      color: var(--ink-2);
      margin-bottom: 6px;
    }
    input[type="password"] {
      width: 100%;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--ink);
      font-size: 0.9375rem;
      margin-bottom: 14px;
      transition: border-color 120ms ease;
    }
    input[type="password"]:focus {
      outline: none;
      border-color: var(--ink);
    }
    button {
      width: 100%;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      border: 1px solid transparent;
      background: var(--cta-bg);
      color: var(--cta-fg);
      transition: opacity 120ms ease, background-color 120ms ease;
    }
    button:hover { background: var(--cta-hover); }
    .divider {
      display: flex;
      align-items: center;
      gap: 12px;
      margin: 18px 0;
      color: var(--muted);
      font-size: 0.75rem;
    }
    .divider::before, .divider::after {
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }
    .idp-stack {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .btn-idp {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      background: var(--surface);
      border: 1px solid var(--border);
      color: var(--ink);
    }
    .btn-idp:hover {
      background: var(--subtle);
      border-color: var(--border-strong);
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="mark">${BASTION_MARK_SVG}<span>GeminiBastionMCP</span></div>
    <h1>Operator Console</h1>
    <p class="sub">Sign in with your operator password${idpForms.length > 0 ? ' or a verified upstream account' : ''}.</p>
    ${errorMessage ? `<div class="err" role="alert">${escapeHtml(errorMessage)}</div>` : ''}
    <form method="POST" action="/admin/login">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
      <label for="password">Operator Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus />
      <button type="submit">Continue</button>
    </form>
    ${idpForms.length > 0 ? `<div class="divider">or</div><div class="idp-stack">${idpForms.join('')}</div>` : ''}
  </main>
</body>
</html>`;
}

export function renderAdminDashboardHtml(params: {
  csrfToken: string;
  publicDomain: string;
  kpis?: AdminKpiSummary;
}): string {
  const { csrfToken, publicDomain } = params;
  const kpis: AdminKpiSummary = params.kpis ?? {
    activeJobs: 0,
    stagedPlans: 0,
    workspaces: 0,
    latestSyncAt: null,
    oauthSessions: 0,
    memoriesCount: 0,
  };
  const mcpEndpoint = `${publicDomain.replace(/\/+$/, '')}/mcp`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#FBFBFB" media="(prefers-color-scheme: light)" />
  <meta name="theme-color" content="#09090B" media="(prefers-color-scheme: dark)" />
  <meta name="csrf-token" content="${escapeHtml(csrfToken)}" />
  <link rel="manifest" href="/admin/manifest.webmanifest" />
  <link rel="icon" href="/admin/icon.svg" type="image/svg+xml" />
  <title>Admin Console — GeminiBastionMCP</title>
  <style>
    ${EDITORIAL_THEME_CSS}
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", system-ui, sans-serif;
      background: var(--bg);
      color: var(--ink);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }
    header {
      position: sticky;
      top: 0;
      z-index: 10;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 12px 20px;
    }
    .header-inner {
      max-width: 1080px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      flex-wrap: wrap;
    }
    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      min-width: 0;
    }
    .brand {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 600;
      font-size: 0.9375rem;
      letter-spacing: -0.01em;
    }
    .dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--ochre);
      display: inline-block;
      flex-shrink: 0;
    }
    .dot.live { background: var(--sage); }
    .copy-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      max-width: 100%;
      padding: 5px 10px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--subtle);
      color: var(--ink-2);
      font-size: 0.75rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      cursor: pointer;
    }
    .copy-pill:hover {
      border-color: var(--border-strong);
      color: var(--ink);
    }
    .copy-pill-tag {
      font-family: -apple-system, BlinkMacSystemFont, "Inter", system-ui, sans-serif;
      font-weight: 600;
      color: var(--ink);
    }
    .header-actions {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .kpi-wrap {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
    }
    .kpi-strip {
      max-width: 1080px;
      margin: 0 auto;
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }
    .kpi-card {
      padding: 16px 20px;
      border-right: 1px solid var(--border);
    }
    .kpi-card:last-child { border-right: none; }
    @media (max-width: 700px) {
      .kpi-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .kpi-card:nth-child(2n) { border-right: none; }
      .kpi-card:nth-child(-n+2) { border-bottom: 1px solid var(--border); }
    }
    .kpi-label {
      font-size: 0.75rem;
      font-weight: 500;
      color: var(--muted);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    .kpi-value {
      font-size: 1.5rem;
      font-weight: 600;
      letter-spacing: -0.02em;
      color: var(--ink);
      margin-top: 4px;
      font-variant-numeric: tabular-nums;
    }
    .kpi-sub {
      font-size: 0.75rem;
      color: var(--muted);
      margin-top: 2px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .pulse-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: var(--muted);
      display: inline-block;
    }
    .pulse-dot.active {
      background: var(--sage);
      animation: subtlePulse 2.2s ease-in-out infinite;
    }
    @keyframes subtlePulse {
      0%, 100% { opacity: 1; }
      50% { opacity: 0.4; }
    }
    .tabs-bar {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
    }
    .tabs {
      max-width: 1080px;
      margin: 0 auto;
      display: flex;
      gap: 4px;
      padding: 0 20px;
      overflow-x: auto;
    }
    .tab {
      background: transparent;
      color: var(--muted);
      border: none;
      border-bottom: 2px solid transparent;
      padding: 11px 12px;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      white-space: nowrap;
      transition: color 120ms ease;
    }
    .tab:hover { color: var(--ink); }
    .tab.active {
      color: var(--ink);
      border-bottom-color: var(--ink);
    }
    main {
      max-width: 1080px;
      margin: 0 auto;
      padding: 20px;
    }
    h3 {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      margin: 20px 0 10px;
    }
    h3:first-child { margin-top: 0; }
    .panel { display: none; }
    .panel.active { display: block; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 10px;
    }
    .row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 12px;
      flex-wrap: wrap;
    }
    .title {
      font-weight: 600;
      font-size: 0.9375rem;
      letter-spacing: -0.01em;
      word-break: break-word;
    }
    .meta {
      font-size: 0.75rem;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      margin-top: 4px;
      word-break: break-word;
    }
    .pill {
      display: inline-block;
      font-size: 0.6875rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: var(--subtle);
      color: var(--ink-2);
    }
    .pill.running, .pill.queued {
      color: var(--ink);
      border-color: var(--border-strong);
      background: var(--subtle);
    }
    .pill.completed, .pill.success, .pill.executed {
      color: var(--sage);
      border-color: var(--sage-bd);
      background: var(--sage-bg);
    }
    .pill.failed, .pill.denied, .pill.cancelled, .pill.timed_out {
      color: var(--crimson);
      border-color: var(--crimson-bd);
      background: var(--crimson-bg);
    }
    .pill.staged {
      color: var(--ochre);
      border-color: var(--ochre-bd);
      background: var(--ochre-bg);
    }
    pre {
      background: var(--subtle);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
      overflow-x: auto;
      font-size: 0.75rem;
      line-height: 1.5;
      color: var(--ink-2);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      margin: 12px 0 0;
      max-height: 180px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    pre.expanded { max-height: none; }
    .log-toolbar { display: flex; justify-content: flex-end; margin-top: 8px; }
    button.btn {
      padding: 6px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--ink);
      font-size: 0.8125rem;
      font-weight: 500;
      cursor: pointer;
    }
    button.btn:hover { background: var(--subtle); border-color: var(--border-strong); }
    button.btn-sm { padding: 4px 10px; font-size: 0.75rem; color: var(--ink-2); }
    button.btn-danger {
      background: var(--crimson-bg);
      border-color: var(--crimson-bd);
      color: var(--crimson);
    }
    button.btn-danger:hover { opacity: 0.9; }
    .empty {
      color: var(--muted);
      font-size: 0.875rem;
      padding: 28px 0;
      text-align: center;
    }
    select {
      background: var(--surface);
      color: var(--ink);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 6px 10px;
      font-size: 0.8125rem;
      max-width: 100%;
    }
    .usage-note {
      font-size: 0.8125rem;
      line-height: 1.5;
      color: var(--ink-2);
      margin: 0 0 14px;
    }
    .usage-metrics {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 12px;
    }
    .usage-metric {
      padding: 14px 16px;
      border-right: 1px solid var(--border);
    }
    .usage-metric:last-child { border-right: none; }
    @media (max-width: 700px) {
      .usage-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .usage-metric:nth-child(2n) { border-right: none; }
      .usage-metric:nth-child(-n+2) { border-bottom: 1px solid var(--border); }
    }
    .usage-bars {
      display: flex;
      align-items: flex-end;
      gap: 4px;
      height: 92px;
      padding-top: 8px;
    }
    .usage-bar-col {
      flex: 1;
      height: 100%;
      display: flex;
      align-items: flex-end;
    }
    .usage-bar {
      width: 100%;
      min-height: 3px;
      border-radius: 3px 3px 0 0;
      background: var(--ink);
      opacity: 0.82;
    }
    .usage-bar.zero {
      background: var(--border-strong);
      opacity: 0.55;
    }
    .usage-bar-axis {
      display: flex;
      justify-content: space-between;
      font-size: 0.7rem;
      color: var(--muted);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      margin-top: 6px;
    }
    .usage-table-wrap { overflow-x: auto; margin-top: 8px; }
    table.usage-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8125rem;
      font-variant-numeric: tabular-nums;
    }
    table.usage-table th, table.usage-table td {
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
    }
    table.usage-table th {
      font-size: 0.72rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--muted);
    }
    table.usage-table tr:last-child td { border-bottom: none; }
    table.usage-table td.num, table.usage-table th.num { text-align: right; }
    .marker-row {
      padding: 10px 0;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 12px;
      flex-wrap: wrap;
    }
    .marker-row:last-child { border-bottom: none; padding-bottom: 0; }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div class="brand-wrap">
        <div class="brand"><span id="sseDot" class="dot" title="SSE connection"></span>${BASTION_MARK_SVG}<span>GeminiBastionMCP Admin</span></div>
        <button class="copy-pill" type="button" data-action="copy-mcp" data-url="${escapeHtml(mcpEndpoint)}" title="Copy /mcp endpoint URL">
          <span class="copy-pill-tag">Copy /mcp</span>
          <span>${escapeHtml(mcpEndpoint)}</span>
        </button>
      </div>
      <div class="header-actions">
        <form method="POST" action="/admin/logout">
          <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
          <button class="btn" type="submit">Sign out</button>
        </form>
      </div>
    </div>
  </header>

  <div class="kpi-wrap">
    <section class="kpi-strip" aria-label="Gateway KPIs">
      <div class="kpi-card">
        <div class="kpi-label"><span id="kpiJobsPulse" class="pulse-dot${kpis.activeJobs > 0 ? ' active' : ''}"></span> Active Jobs</div>
        <div class="kpi-value" id="kpiActiveJobs">${kpis.activeJobs}</div>
        <div class="kpi-sub">running / queued</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Staged Plans</div>
        <div class="kpi-value" id="kpiStagedPlans">${kpis.stagedPlans}</div>
        <div class="kpi-sub">pending approval</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Workspaces</div>
        <div class="kpi-value" id="kpiWorkspaces">${kpis.workspaces}</div>
        <div class="kpi-sub" id="kpiLatestSync">${kpis.latestSyncAt ? escapeHtml(new Date(kpis.latestSyncAt).toLocaleString()) : 'no sync yet'}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">OAuth Sessions</div>
        <div class="kpi-value" id="kpiOauthSessions">${kpis.oauthSessions}</div>
        <div class="kpi-sub">active families</div>
      </div>
    </section>
  </div>

  <div class="tabs-bar">
    <nav class="tabs" role="tablist">
      <button class="tab active" data-tab="jobs">Jobs</button>
      <button class="tab" data-tab="workspaces">Workspaces</button>
      <button class="tab" data-tab="memory">Memory (<span id="tabMemoriesCount">${kpis.memoriesCount}</span>)</button>
      <button class="tab" data-tab="oauth">OAuth</button>
      <button class="tab" data-tab="usage">Usage</button>
      <button class="tab" data-tab="plans">Plans</button>
      <button class="tab" data-tab="audit">Audit</button>
    </nav>
  </div>

  <main>
    <section id="tab-jobs" class="panel active"><div id="jobsList" class="empty">Connecting live stream...</div></section>
    <section id="tab-workspaces" class="panel"><div id="workspacesList" class="empty">Loading workspaces...</div></section>
    <section id="tab-memory" class="panel"><div id="memoryList" class="empty">Loading workspace memories...</div></section>
    <section id="tab-oauth" class="panel"><div id="oauthList" class="empty">Loading OAuth state...</div></section>
    <section id="tab-usage" class="panel"><div id="usageView" class="empty">Loading usage metrics...</div></section>
    <section id="tab-plans" class="panel"><div id="plansList" class="empty">Loading mutation plans...</div></section>
    <section id="tab-audit" class="panel"><div id="auditList" class="empty">Loading audit logs...</div></section>
  </main>

  <script>
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const fmtTime = (ms) => ms ? new Date(ms).toLocaleString() : '-';
    const fmtNum = (n) => Number(n ?? 0).toLocaleString();
    const expandedLogs = new Set();

    async function apiFetch(path, opts = {}) {
      const headers = Object.assign({}, opts.headers || {}, { 'X-CSRF-Token': csrfToken });
      const res = await fetch(path, Object.assign({}, opts, { headers }));
      if (res.status === 401) { window.location.href = '/admin/login'; return null; }
      return res.json();
    }

    function updateKpiStrip(summary) {
      if (!summary) return;
      if (typeof summary.activeJobs === 'number') {
        document.getElementById('kpiActiveJobs').textContent = String(summary.activeJobs);
        const pulse = document.getElementById('kpiJobsPulse');
        if (summary.activeJobs > 0) pulse.classList.add('active');
        else pulse.classList.remove('active');
      }
      if (typeof summary.stagedPlans === 'number') {
        document.getElementById('kpiStagedPlans').textContent = String(summary.stagedPlans);
      }
      if (typeof summary.workspaces === 'number') {
        document.getElementById('kpiWorkspaces').textContent = String(summary.workspaces);
      }
      if ('latestSyncAt' in summary) {
        document.getElementById('kpiLatestSync').textContent = summary.latestSyncAt ? fmtTime(summary.latestSyncAt) : 'no sync yet';
      }
      if (typeof summary.oauthSessions === 'number') {
        document.getElementById('kpiOauthSessions').textContent = String(summary.oauthSessions);
      }
      if (typeof summary.memoriesCount === 'number') {
        const memBadge = document.getElementById('tabMemoriesCount');
        if (memBadge) memBadge.textContent = String(summary.memoriesCount);
      }
    }

    async function refreshSummary() {
      const summary = await apiFetch('/admin/api/summary');
      updateKpiStrip(summary);
    }

    document.querySelectorAll('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
        document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
        refreshTab(btn.dataset.tab);
      });
    });

    function renderJobs(jobs, activeJobsOverride) {
      const el = document.getElementById('jobsList');
      const activeCount = typeof activeJobsOverride === 'number'
        ? activeJobsOverride
        : (jobs || []).filter((j) => j.status === 'queued' || j.status === 'running').length;
      updateKpiStrip({ activeJobs: activeCount });
      if (!jobs || jobs.length === 0) { el.innerHTML = '<div class="empty">No jobs recorded.</div>'; return; }
      el.innerHTML = jobs.map((j) => {
        const active = j.status === 'queued' || j.status === 'running';
        const tokens = j.token_usage ? ('Tokens: ' + j.token_usage.total_tokens + ' (in ' + j.token_usage.input_tokens + ' / out ' + j.token_usage.output_tokens + ')') : 'Tokens: -';
        const tail = (j.events || []).slice(-6).map((e) => '[' + e.seq + ' ' + e.type + '] ' + e.message).join('\\n');
        const logText = j.command_or_objective + (tail ? '\\n---\\n' + tail : '') + (j.error_message ? '\\nERROR: ' + j.error_message : '');
        const isExpanded = expandedLogs.has(j.job_id);
        return '<div class="card">'
          + '<div class="row"><div><div class="title">' + esc(j.workspace_slug) + ' · ' + esc(j.runner_type) + '</div>'
          + '<div class="meta">' + esc(j.job_id) + ' · ' + esc(tokens) + ' · ' + esc(fmtTime(j.updated_at)) + '</div></div>'
          + '<div style="display:flex;gap:8px;align-items:center;"><span class="pill ' + esc(j.status) + '">' + esc(j.status) + '</span>'
          + (active ? '<button class="btn btn-danger" type="button" data-action="cancel-job" data-id="' + esc(j.job_id) + '">Kill</button>' : '')
          + '</div></div>'
          + '<pre class="' + (isExpanded ? 'expanded' : '') + '" data-job-log="' + esc(j.job_id) + '">' + esc(logText) + '</pre>'
          + '<div class="log-toolbar"><button class="btn btn-sm" type="button" data-action="toggle-log" data-id="' + esc(j.job_id) + '">' + (isExpanded ? 'Collapse' : 'Expand') + '</button></div>'
          + '</div>';
      }).join('');
    }

    async function cancelJob(id) {
      if (!id) return;
      if (typeof window.confirm === 'function' && !window.confirm('Kill active job ' + id + '?')) return;
      await apiFetch('/admin/api/jobs/' + encodeURIComponent(id) + '/cancel', { method: 'POST' });
      const data = await apiFetch('/admin/api/jobs');
      if (data) renderJobs(data.jobs, data.activeJobs);
      refreshSummary();
    }

    async function loadWorkspaces() {
      const data = await apiFetch('/admin/api/workspaces');
      if (!data) return;
      const el = document.getElementById('workspacesList');
      if (!data.workspaces.length) { el.innerHTML = '<div class="empty">No workspaces registered.</div>'; return; }
      el.innerHTML = data.workspaces.map((w) => {
        const cps = data.checkpointsByWorkspace[w.slug] || [];
        const options = cps.map((c) => '<option value="' + esc(c.checkpoint_id) + '">' + esc(c.checkpoint_id) + ' — ' + esc(c.reason) + '</option>').join('');
        return '<div class="card"><div class="row"><div><div class="title">' + esc(w.slug) + ' (' + esc(w.default_branch) + ')</div>'
          + '<div class="meta">' + esc(w.repo_url) + ' · Synced: ' + esc(fmtTime(w.last_synced_at)) + '</div></div>'
          + (cps.length ? '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;"><select data-ws-select="' + esc(w.slug) + '">' + options + '</select><button class="btn btn-danger" type="button" data-action="rollback-ws" data-slug="' + esc(w.slug) + '">Rollback</button></div>' : '<span class="meta">No checkpoints</span>')
          + '</div></div>';
      }).join('');
      refreshSummary();
    }

    async function rollbackWs(slug, btn) {
      if (!slug) return;
      const row = btn.closest('.row');
      const sel = row ? row.querySelector('select[data-ws-select]') : null;
      if (!sel || !sel.value) return;
      if (typeof window.confirm === 'function' && !window.confirm('Rollback workspace "' + slug + '" to checkpoint ' + sel.value + '?')) return;
      await apiFetch('/admin/api/workspaces/' + encodeURIComponent(slug) + '/rollback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ checkpoint_id: sel.value })
      });
      loadWorkspaces();
    }

    async function loadOAuth() {
      const data = await apiFetch('/admin/api/oauth');
      if (!data) return;
      const el = document.getElementById('oauthList');
      const up = data.upstreamProviders || {};
      const renderProvider = (label, info) => {
        if (!info) return '';
        const statusClass = info.enabled ? 'completed' : 'staged';
        const statusText = info.enabled ? 'Enabled' : 'Disabled';
        return '<div class="card"><div class="row"><div><div class="title">' + esc(label) + '</div>'
          + '<div class="meta">Allowlist entries: ' + esc(info.allowedCount) + ' · Callback: ' + esc(info.callbackUrl) + '</div></div>'
          + '<div style="display:flex;gap:8px;align-items:center;"><span class="pill ' + statusClass + '">' + statusText + '</span>'
          + '<button class="btn btn-sm" type="button" data-action="copy-text" data-copy="' + esc(info.callbackUrl) + '">Copy Callback</button>'
          + '</div></div></div>';
      };
      const idpHtml = '<h3>Upstream Operator Login (IdP)</h3>'
        + renderProvider('Google OAuth', up.google)
        + renderProvider('GitHub OAuth', up.github);
      const clientsHtml = data.clients.map((c) => '<div class="card"><div class="row"><div><div class="title">' + esc(c.client_name) + (c.is_static ? ' [STATIC]' : '') + '</div>'
        + '<div class="meta">' + esc(c.client_id) + ' · URIs: ' + esc(c.redirect_uris.length) + '</div></div>'
        + '<button class="btn btn-danger" type="button" data-action="delete-client" data-id="' + esc(c.client_id) + '">Delete Client</button></div></div>').join('') || '<div class="empty">No OAuth clients.</div>';
      const tokensHtml = data.activeTokens.map((t) => '<div class="card"><div class="row"><div><div class="title">' + esc(t.token_type) + ' · ' + esc(t.client_id) + '</div>'
        + '<div class="meta">Family: ' + esc(t.token_family_id) + ' · Resource: ' + esc(t.resource || '-') + ' · Expires: ' + esc(fmtTime(t.expires_at)) + '</div></div>'
        + '<button class="btn btn-danger" type="button" data-action="revoke-token" data-hash="' + esc(t.token_hash) + '">Revoke</button></div></div>').join('') || '<div class="empty">No active tokens.</div>';
      el.innerHTML = idpHtml + '<h3>Clients</h3>' + clientsHtml + '<h3>Active Tokens</h3>' + tokensHtml;
      refreshSummary();
    }

    async function deleteClient(id) {
      if (!id) return;
      if (typeof window.confirm === 'function' && !window.confirm('Delete OAuth client ' + id + ' and revoke all its tokens?')) return;
      await apiFetch('/admin/api/oauth/clients/' + encodeURIComponent(id), { method: 'DELETE' });
      loadOAuth();
    }

    async function revokeToken(hash) {
      if (!hash) return;
      if (typeof window.confirm === 'function' && !window.confirm('Revoke this OAuth token?')) return;
      await apiFetch('/admin/api/oauth/tokens/' + encodeURIComponent(hash) + '/revoke', { method: 'POST' });
      loadOAuth();
    }

    function toggleJobLog(id, btn) {
      if (!id) return;
      const pre = document.querySelector('pre[data-job-log="' + CSS.escape(id) + '"]');
      if (!pre) return;
      if (pre.classList.contains('expanded')) {
        pre.classList.remove('expanded');
        expandedLogs.delete(id);
        btn.textContent = 'Expand';
      } else {
        pre.classList.add('expanded');
        expandedLogs.add(id);
        btn.textContent = 'Collapse';
      }
    }

    async function copyMcpUrl(url, btn) {
      if (!url) return;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(url);
        }
      } catch {}
      const tag = btn.querySelector('.copy-pill-tag');
      if (tag) {
        const prev = tag.textContent;
        tag.textContent = 'Copied!';
        setTimeout(() => { tag.textContent = prev; }, 1600);
      }
    }

    async function copyPlainText(text, btn) {
      if (!text) return;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        }
      } catch {}
      const prev = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = prev; }, 1600);
    }

    document.body.addEventListener('click', (event) => {
      const btn = event.target && event.target.closest ? event.target.closest('button[data-action]') : null;
      if (!btn) return;
      const action = btn.getAttribute('data-action');
      if (action === 'copy-mcp') copyMcpUrl(btn.getAttribute('data-url'), btn);
      else if (action === 'copy-text') copyPlainText(btn.getAttribute('data-copy'), btn);
      else if (action === 'cancel-job') cancelJob(btn.getAttribute('data-id'));
      else if (action === 'rollback-ws') rollbackWs(btn.getAttribute('data-slug'), btn);
      else if (action === 'delete-client') deleteClient(btn.getAttribute('data-id'));
      else if (action === 'revoke-token') revokeToken(btn.getAttribute('data-hash'));
      else if (action === 'delete-memory') deleteMemory(btn.getAttribute('data-id'));
      else if (action === 'mark-limit') markQuotaLimit();
      else if (action === 'toggle-log') toggleJobLog(btn.getAttribute('data-id'), btn);
    });

    async function loadUsage() {
      const data = await apiFetch('/admin/api/usage');
      if (!data || !data.summary) return;
      const s = data.summary;
      const markers = data.limitMarkers || [];
      const el = document.getElementById('usageView');

      const hourly = s.hourly24h || [];
      const maxTok = hourly.reduce((m, b) => Math.max(m, b.estTotalTokens || 0), 0);
      const maxCalls = hourly.reduce((m, b) => Math.max(m, b.calls || 0), 0);
      const barsHtml = hourly.map((b) => {
        const val = maxTok > 0 ? (b.estTotalTokens || 0) : (b.calls || 0);
        const denom = maxTok > 0 ? maxTok : maxCalls;
        const pct = denom > 0 && val > 0 ? Math.max(6, Math.round((val / denom) * 100)) : 3;
        const hrLabel = new Date(b.hourStartMs).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const tip = hrLabel + ' · ' + b.calls + ' calls · ' + fmtNum(b.estTotalTokens) + ' est. tokens';
        return '<div class="usage-bar-col"><div class="usage-bar' + (val === 0 ? ' zero' : '') + '" style="height:' + pct + '%" title="' + esc(tip) + '"></div></div>';
      }).join('');

      const tools = s.byTool || [];
      const toolsHtml = tools.length
        ? '<div class="usage-table-wrap"><table class="usage-table"><thead><tr><th>Tool</th><th class="num">24h</th><th class="num">30d</th><th class="num">Est. Tokens</th><th class="num">Avg ms</th></tr></thead><tbody>'
          + tools.map((t) => '<tr><td><code>' + esc(t.toolName) + '</code></td><td class="num">' + esc(fmtNum(t.calls24h)) + '</td><td class="num">' + esc(fmtNum(t.calls30d)) + '</td><td class="num">' + esc(fmtNum(t.estTotalTokens30d)) + '</td><td class="num">' + esc(fmtNum(t.avgDurationMs30d)) + '</td></tr>').join('')
          + '</tbody></table></div>'
        : '<div class="empty">No MCP tool usage recorded yet.</div>';

      const markersHtml = markers.length
        ? markers.map((m) => {
            const d = m.details || {};
            const l1 = d.last1h || {};
            const l3 = d.last3h || {};
            const l24 = d.last24h || {};
            return '<div class="marker-row"><div><div class="title">' + esc(d.note || 'Web AI quota limit hit') + '</div>'
              + '<div class="meta">' + esc(fmtTime(m.created_at)) + '</div></div>'
              + '<div class="meta">1h: ' + esc(l1.calls ?? 0) + ' / ' + esc(fmtNum(l1.estTotalTokens ?? 0)) + ' tok · 3h: ' + esc(l3.calls ?? 0) + ' / ' + esc(fmtNum(l3.estTotalTokens ?? 0)) + ' tok · 24h: ' + esc(l24.calls ?? 0) + ' / ' + esc(fmtNum(l24.estTotalTokens ?? 0)) + ' tok</div></div>';
          }).join('')
        : '<div class="empty">No quota limit snapshots recorded yet.</div>';

      const ag = s.agentTokens && s.agentTokens.last30d ? s.agentTokens.last30d : { totalTokens: 0, inputTokens: 0, cachedInputTokens: 0, outputTokens: 0 };
      el.innerHTML = '<p class="usage-note">Server-side MCP throughput estimates (Google does not expose Web Gemini\\\'s internal chat/thinking token quota) + exact background Agent SDK token totals.</p>'
        + '<div class="usage-metrics">'
        + '<div class="usage-metric"><div class="kpi-label">Last 1h</div><div class="kpi-value">' + esc(fmtNum(s.last1h.calls)) + '</div><div class="kpi-sub">' + esc(fmtNum(s.last1h.estTotalTokens)) + ' est. tokens</div></div>'
        + '<div class="usage-metric"><div class="kpi-label">Last 24h</div><div class="kpi-value">' + esc(fmtNum(s.last24h.calls)) + '</div><div class="kpi-sub">' + esc(fmtNum(s.last24h.estTotalTokens)) + ' est. tokens</div></div>'
        + '<div class="usage-metric"><div class="kpi-label">Last 30d</div><div class="kpi-value">' + esc(fmtNum(s.last30d.calls)) + '</div><div class="kpi-sub">' + esc(fmtNum(s.last30d.estTotalTokens)) + ' est. tokens</div></div>'
        + '<div class="usage-metric"><div class="kpi-label">Agent SDK (30d)</div><div class="kpi-value">' + esc(fmtNum(ag.totalTokens)) + '</div><div class="kpi-sub">in ' + esc(fmtNum(ag.inputTokens)) + ' / cached ' + esc(fmtNum(ag.cachedInputTokens)) + ' / out ' + esc(fmtNum(ag.outputTokens)) + '</div></div>'
        + '</div>'
        + '<div class="card"><div class="row"><div class="title">24-Hour MCP Throughput</div><div class="meta">Hourly estimated tokens</div></div>'
        + '<div class="usage-bars">' + barsHtml + '</div>'
        + '<div class="usage-bar-axis"><span>-24h</span><span>-12h</span><span>Now</span></div></div>'
        + '<div class="card"><div class="title">Per-Tool Breakdown</div>' + toolsHtml + '</div>'
        + '<div class="card"><div class="row" style="align-items:center;"><div class="title">Empirical Limit Markers</div><button class="btn" type="button" data-action="mark-limit">Mark Quota Limit Hit</button></div>'
        + markersHtml + '</div>';
    }

    async function markQuotaLimit() {
      let note = 'Web AI quota limit hit';
      if (typeof window.prompt === 'function') {
        const entered = window.prompt('Optional note for this quota limit snapshot:', note);
        if (entered === null) return;
        if (entered.trim()) note = entered.trim();
      }
      await apiFetch('/admin/api/usage/mark-limit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note })
      });
      loadUsage();
    }

    async function loadMemories() {
      const data = await apiFetch('/admin/api/memories');
      if (!data) return;
      const el = document.getElementById('memoryList');
      if (!data.memories || !data.memories.length) { el.innerHTML = '<div class="empty">No persisted workspace memories.</div>'; refreshSummary(); return; }
      el.innerHTML = data.memories.map((m) => '<div class="card"><div class="row"><div><div class="title">' + esc(m.workspace_slug) + ' · ' + esc(m.key) + '</div>'
        + '<div class="meta">' + esc(m.memory_id) + ' · Updated: ' + esc(fmtTime(m.updated_at)) + '</div></div>'
        + '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">'
        + '<span class="pill running">' + esc(m.category) + '</span>'
        + (m.pinned ? '<span class="pill completed">PINNED</span>' : '')
        + '<button class="btn btn-danger" type="button" data-action="delete-memory" data-id="' + esc(m.memory_id) + '">Delete</button>'
        + '</div></div><pre>' + esc(m.content) + '</pre></div>').join('');
      refreshSummary();
    }

    async function deleteMemory(id) {
      if (!id) return;
      if (typeof window.confirm === 'function' && !window.confirm('Delete workspace memory ' + id + '?')) return;
      await apiFetch('/admin/api/memories/' + encodeURIComponent(id), { method: 'DELETE' });
      loadMemories();
    }

    async function loadPlans() {
      const data = await apiFetch('/admin/api/plans');
      if (!data) return;
      const el = document.getElementById('plansList');
      if (!data.plans.length) { el.innerHTML = '<div class="empty">No mutation plans.</div>'; return; }
      el.innerHTML = data.plans.map((p) => '<div class="card"><div class="row"><div><div class="title">' + esc(p.target_service) + ' · ' + esc(p.plan_id) + '</div>'
        + '<div class="meta">Created: ' + esc(fmtTime(p.created_at)) + ' · Expires: ' + esc(fmtTime(p.expires_at)) + '</div></div>'
        + '<span class="pill ' + esc(p.status) + '">' + esc(p.status) + '</span></div><pre>' + esc(p.summary_diff_text) + '</pre></div>').join('');
      refreshSummary();
    }

    async function loadAudit() {
      const data = await apiFetch('/admin/api/audit');
      if (!data) return;
      const el = document.getElementById('auditList');
      if (!data.logs.length) { el.innerHTML = '<div class="empty">No audit logs.</div>'; return; }
      el.innerHTML = data.logs.map((l) => '<div class="card"><div class="row"><div><div class="title">' + esc(l.action) + ' → ' + esc(l.target) + '</div>'
        + '<div class="meta">Actor: ' + esc(l.actor) + ' · ' + esc(fmtTime(l.created_at)) + '</div></div>'
        + '<span class="pill ' + esc(l.status) + '">' + esc(l.status) + '</span></div><pre>' + esc(JSON.stringify(l.details, null, 2)) + '</pre></div>').join('');
    }

    function refreshTab(tab) {
      if (tab === 'workspaces') loadWorkspaces();
      else if (tab === 'memory') loadMemories();
      else if (tab === 'oauth') loadOAuth();
      else if (tab === 'usage') loadUsage();
      else if (tab === 'plans') loadPlans();
      else if (tab === 'audit') loadAudit();
    }

    if (typeof EventSource !== 'undefined') {
      const es = new EventSource('/admin/api/jobs/stream');
      es.addEventListener('open', () => document.getElementById('sseDot').classList.add('live'));
      es.addEventListener('error', () => document.getElementById('sseDot').classList.remove('live'));
      es.addEventListener('jobs', (ev) => {
        try {
          const payload = JSON.parse(ev.data);
          renderJobs(payload.jobs, payload.activeJobs);
        } catch {}
      });
    }
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/admin/sw.js').catch(() => undefined);
    }
  </script>
</body>
</html>`;
}
