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
}

export function renderAdminManifest(): Record<string, unknown> {
  return {
    name: 'GeminiBastionMCP',
    short_name: 'GeminiBastion',
    description:
      'Mobile-first operator cockpit for GeminiBastionMCP jobs, workspaces, OAuth sessions, staged plans, and audit logs.',
    start_url: '/admin',
    scope: '/admin',
    display: 'standalone',
    background_color: '#0b1020',
    theme_color: '#131a2e',
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
  <rect width="128" height="128" rx="28" fill="#0b1020"/>
  <rect x="10" y="10" width="108" height="108" rx="22" fill="#131a2e" stroke="#3b82f6" stroke-width="4"/>
  <path d="M36 46l28-14 28 14v36L64 96 36 82z" fill="none" stroke="#60a5fa" stroke-width="6" stroke-linejoin="round"/>
  <circle cx="64" cy="64" r="10" fill="#3b82f6"/>
</svg>`;
}

export function renderAdminServiceWorker(): string {
  return `const CACHE_NAME = 'gemini-bastion-admin-shell-v2';
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
        <button class="btn-idp" type="submit">Sign in with Google</button>
      </form>`);
  }
  if (githubEnabled) {
    idpForms.push(`<form method="POST" action="/auth/idp/github/start">
        <input type="hidden" name="purpose" value="admin" />
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
        <button class="btn-idp" type="submit">Sign in with GitHub</button>
      </form>`);
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#131a2e" />
  <link rel="manifest" href="/admin/manifest.webmanifest" />
  <link rel="icon" href="/admin/icon.svg" type="image/svg+xml" />
  <title>Admin Login — GeminiBastionMCP</title>
  <style>
    * { box-sizing: border-box; }
    body { margin:0; font-family: system-ui, -apple-system, sans-serif; background:#0b1020; color:#e5e7eb; display:flex; align-items:center; justify-content:center; min-height:100vh; padding:16px; }
    .card { max-width:420px; width:100%; background:#131a2e; border:1px solid #26314f; border-radius:16px; padding:24px; box-shadow:0 16px 40px rgba(0,0,0,0.45); }
    .badge { display:inline-block; font-size:0.75rem; font-weight:600; text-transform:uppercase; letter-spacing:0.05em; color:#93c5fd; background:#1e293b; border:1px solid #334155; padding:4px 10px; border-radius:999px; margin-bottom:12px; }
    h1 { margin:0 0 8px; font-size:1.3rem; color:#f8fafc; }
    p { margin:0 0 18px; font-size:0.9rem; color:#94a3b8; }
    .err { background:#3f151b; border:1px solid #991b1b; color:#fecaca; padding:10px 12px; border-radius:8px; font-size:0.88rem; margin-bottom:16px; }
    label { display:block; font-size:0.85rem; font-weight:600; color:#cbd5e1; margin-bottom:6px; }
    input[type="password"] { width:100%; padding:11px 12px; border-radius:10px; border:1px solid #334155; background:#0b1020; color:#f8fafc; font-size:1rem; margin-bottom:16px; }
    input[type="password"]:focus { outline:2px solid #3b82f6; border-color:transparent; }
    button { width:100%; padding:11px 14px; border-radius:10px; font-size:0.95rem; font-weight:600; cursor:pointer; border:none; background:#2563eb; color:#fff; }
    button:hover { background:#1d4ed8; }
    .divider { display:flex; align-items:center; gap:10px; margin:18px 0 14px; color:#64748b; font-size:0.78rem; text-transform:uppercase; letter-spacing:0.06em; }
    .divider::before, .divider::after { content:''; flex:1; height:1px; background:#26314f; }
    .idp-stack { display:flex; flex-direction:column; gap:10px; }
    .btn-idp { background:#0f172a; border:1px solid #334155; color:#f8fafc; }
    .btn-idp:hover { background:#172554; border-color:#3b82f6; }
  </style>
</head>
<body>
  <main class="card">
    <span class="badge">GeminiBastionMCP</span>
    <h1>Operator Console</h1>
    <p>Sign in with your operator password${idpForms.length > 0 ? ' or a verified upstream account' : ''} to monitor jobs, OAuth sessions, staged plans, and audit logs.</p>
    ${errorMessage ? `<div class="err" role="alert">${escapeHtml(errorMessage)}</div>` : ''}
    <form method="POST" action="/admin/login">
      <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
      <label for="password">Operator Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required autofocus />
      <button type="submit">Sign In</button>
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
  };
  const mcpEndpoint = `${publicDomain.replace(/\/+$/, '')}/mcp`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="theme-color" content="#131a2e" />
  <meta name="csrf-token" content="${escapeHtml(csrfToken)}" />
  <link rel="manifest" href="/admin/manifest.webmanifest" />
  <link rel="icon" href="/admin/icon.svg" type="image/svg+xml" />
  <title>Admin Console — GeminiBastionMCP</title>
  <style>
    :root { --bg:#0b1020; --surface:#131a2e; --surface2:#0e1526; --border:#25304d; --text:#e2e8f0; --muted:#94a3b8; --accent:#3b82f6; --danger:#ef4444; --ok:#22c55e; --warn:#f59e0b; }
    * { box-sizing:border-box; }
    body { margin:0; font-family: system-ui, -apple-system, sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
    header { position:sticky; top:0; z-index:10; background:rgba(19,26,46,0.95); backdrop-filter:blur(8px); border-bottom:1px solid var(--border); padding:12px 16px; display:flex; align-items:center; justify-content:space-between; gap:10px; flex-wrap:wrap; }
    .brand-wrap { display:flex; flex-direction:column; gap:4px; min-width:0; }
    .brand { display:flex; align-items:center; gap:10px; font-weight:700; font-size:1rem; }
    .dot { width:10px; height:10px; border-radius:50%; background:var(--warn); display:inline-block; flex-shrink:0; }
    .dot.live { background:var(--ok); box-shadow:0 0 8px var(--ok); }
    .header-actions { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
    .copy-pill { display:inline-flex; align-items:center; gap:6px; max-width:100%; padding:5px 10px; border-radius:999px; border:1px solid #334155; background:#0d1528; color:#93c5fd; font-size:0.78rem; font-family: ui-monospace, monospace; cursor:pointer; }
    .copy-pill:hover { border-color:var(--accent); color:#dbeafe; }
    .copy-pill-tag { font-family: system-ui, -apple-system, sans-serif; font-weight:700; color:#60a5fa; text-transform:uppercase; font-size:0.68rem; }
    .kpi-strip { display:grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap:10px; padding:12px 16px; background:var(--surface2); border-bottom:1px solid var(--border); }
    @media (max-width: 680px) { .kpi-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
    .kpi-card { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:10px 12px; }
    .kpi-label { font-size:0.72rem; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted); display:flex; align-items:center; gap:6px; }
    .kpi-value { font-size:1.35rem; font-weight:700; color:#f8fafc; margin-top:4px; font-variant-numeric: tabular-nums; }
    .kpi-sub { font-size:0.72rem; color:var(--muted); margin-top:2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
    .pulse-dot { width:8px; height:8px; border-radius:50%; background:var(--muted); display:inline-block; }
    .pulse-dot.active { background:var(--ok); box-shadow:0 0 0 0 rgba(34,197,94,0.7); animation:pulseRing 1.6s infinite; }
    @keyframes pulseRing { 0% { box-shadow:0 0 0 0 rgba(34,197,94,0.7); } 70% { box-shadow:0 0 0 7px rgba(34,197,94,0); } 100% { box-shadow:0 0 0 0 rgba(34,197,94,0); } }
    .tabs { display:flex; gap:6px; padding:8px 16px 0; overflow-x:auto; border-bottom:1px solid var(--border); background:var(--surface2); }
    .tab { background:transparent; color:var(--muted); border:none; border-bottom:2px solid transparent; padding:10px 14px; font-size:0.9rem; font-weight:600; cursor:pointer; white-space:nowrap; }
    .tab.active { color:#fff; border-bottom-color:var(--accent); }
    main { max-width:1100px; margin:0 auto; padding:16px; }
    .panel { display:none; }
    .panel.active { display:block; }
    .card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:14px; margin-bottom:12px; }
    .row { display:flex; justify-content:space-between; align-items:flex-start; gap:10px; flex-wrap:wrap; }
    .title { font-weight:600; font-size:0.95rem; word-break:break-word; }
    .meta { font-size:0.8rem; color:var(--muted); font-family: ui-monospace, monospace; margin-top:4px; }
    .pill { display:inline-block; font-size:0.72rem; font-weight:700; text-transform:uppercase; padding:3px 8px; border-radius:999px; border:1px solid var(--border); background:var(--surface2); }
    .pill.running, .pill.queued { color:#93c5fd; border-color:#1d4ed8; }
    .pill.completed, .pill.success, .pill.executed { color:#86efac; border-color:#166534; }
    .pill.failed, .pill.denied, .pill.cancelled, .pill.timed_out { color:#fca5a5; border-color:#991b1b; }
    .pill.staged { color:#fde68a; border-color:#92400e; }
    pre { background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:10px; overflow-x:auto; font-size:0.78rem; color:#cbd5e1; margin:10px 0 0; max-height:180px; white-space:pre-wrap; word-break:break-word; }
    pre.expanded { max-height:none; }
    .log-toolbar { display:flex; justify-content:flex-end; margin-top:6px; }
    button.btn { padding:7px 12px; border-radius:8px; border:1px solid var(--border); background:#1e293b; color:#f8fafc; font-size:0.82rem; font-weight:600; cursor:pointer; }
    button.btn-sm { padding:4px 9px; font-size:0.74rem; }
    button.btn-danger { background:#7f1d1d; border-color:#b91c1c; color:#fecaca; }
    button.btn-primary { background:#1d4ed8; border-color:#2563eb; color:#fff; }
    .empty { color:var(--muted); font-size:0.9rem; padding:16px 0; text-align:center; }
    select { background:var(--bg); color:var(--text); border:1px solid var(--border); border-radius:8px; padding:6px 8px; font-size:0.82rem; max-width:100%; }
  </style>
</head>
<body>
  <header>
    <div class="brand-wrap">
      <div class="brand"><span id="sseDot" class="dot"></span> GeminiBastionMCP Admin</div>
      <button class="copy-pill" type="button" data-action="copy-mcp" data-url="${escapeHtml(mcpEndpoint)}" title="Copy /mcp endpoint URL">
        <span class="copy-pill-tag">Copy /mcp</span>
        <span>${escapeHtml(mcpEndpoint)}</span>
      </button>
    </div>
    <div class="header-actions">
      <form method="POST" action="/admin/logout">
        <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}" />
        <button class="btn" type="submit">Logout</button>
      </form>
    </div>
  </header>

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

  <nav class="tabs" role="tablist">
    <button class="tab active" data-tab="jobs">Jobs (Live)</button>
    <button class="tab" data-tab="workspaces">Workspaces</button>
    <button class="tab" data-tab="oauth">OAuth</button>
    <button class="tab" data-tab="plans">Mutation Plans</button>
    <button class="tab" data-tab="audit">Audit Logs</button>
  </nav>

  <main>
    <section id="tab-jobs" class="panel active"><div id="jobsList" class="empty">Connecting live stream...</div></section>
    <section id="tab-workspaces" class="panel"><div id="workspacesList" class="empty">Loading workspaces...</div></section>
    <section id="tab-oauth" class="panel"><div id="oauthList" class="empty">Loading OAuth state...</div></section>
    <section id="tab-plans" class="panel"><div id="plansList" class="empty">Loading mutation plans...</div></section>
    <section id="tab-audit" class="panel"><div id="auditList" class="empty">Loading audit logs...</div></section>
  </main>

  <script>
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const fmtTime = (ms) => ms ? new Date(ms).toLocaleString() : '-';
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
      else if (action === 'toggle-log') toggleJobLog(btn.getAttribute('data-id'), btn);
    });

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
      else if (tab === 'oauth') loadOAuth();
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
