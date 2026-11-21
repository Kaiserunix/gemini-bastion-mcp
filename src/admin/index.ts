import { Hono } from 'hono';
import type { Context } from 'hono';
import {
  clearAdminCsrfCookie,
  clearAdminSessionCookie,
  issueAdminSessionCookie,
  readAdminCsrfCookie,
  readAdminSessionCookie,
  setAdminCsrfCookie,
} from '../auth/cookies.js';
import {
  constantTimeEqual,
  generateRandomToken,
  verifyPassword,
  type AdminSessionPayload,
} from '../auth/crypto.js';
import { getClientIp, IpRateLimiter, readLimitedBodyText } from '../auth/rateLimit.js';
import {
  SignedCookieAdminSessionManager,
  type AdminSessionManager,
  type RateLimiter,
} from '../auth/store.js';
import { isGitHubOAuthEnabled, isGoogleOAuthEnabled } from '../config.js';
import type { Repositories } from '../db/repositories/index.js';
import { MEMORY_CATEGORIES } from '../db/repositories/memoryRepo.js';
import type { GatewayConfig, MemoryCategory, ScrubberLike } from '../types.js';
import { createSecretScrubber } from '../utils/secretScrubber.js';
import {
  renderAdminDashboardHtml,
  renderAdminIconSvg,
  renderAdminLoginHtml,
  renderAdminManifest,
  renderAdminServiceWorker,
  type AdminKpiSummary,
} from './ui.js';

export interface AdminCallbacks {
  cancelJob?: (jobId: string) => Promise<boolean>;
  rollbackCheckpoint?: (slug: string, checkpointId: string) => Promise<void>;
}

export interface AdminDeps extends AdminCallbacks {
  config: GatewayConfig;
  repos: Repositories;
  scrubber?: ScrubberLike;
  sessionManager?: AdminSessionManager;
  rateLimiter?: RateLimiter;
  rateLimitMaxAttempts?: number;
  rateLimitWindowMs?: number;
  ssePollIntervalMs?: number;
}

type AdminVariables = {
  adminSession: AdminSessionPayload;
};

function setAdminSecurityHeaders(
  c: Context,
  allowInlineScript = false,
  allowExternalFormRedirect = false,
): void {
  const scriptSrc = allowInlineScript ? "'unsafe-inline'" : "'self'";
  const formAction = allowExternalFormRedirect ? '' : " form-action 'self';";
  c.header(
    'Content-Security-Policy',
    `default-src 'self'; script-src ${scriptSrc}; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self';${formAction} frame-ancestors 'none'; base-uri 'none'`,
  );
  c.header('X-Frame-Options', 'DENY');
  c.header('X-Content-Type-Options', 'nosniff');
}

function parseLimit(raw: string | undefined, fallback = 50, max = 200): number {
  if (!raw) return fallback;
  const num = Number(raw);
  if (!Number.isInteger(num) || num <= 0) return fallback;
  return Math.min(num, max);
}

/**
 * Creates the lightweight mobile-friendly `/admin` PWA Hono sub-app.
 * Has zero direct dependency on `src/core/*`; operational mutations use injected callbacks.
 */
export function createAdminApp(deps: AdminDeps): Hono<{ Variables: AdminVariables }> {
  const { config, repos } = deps;
  const scrubber = deps.scrubber ?? createSecretScrubber(config);
  const sessionManager = deps.sessionManager ?? new SignedCookieAdminSessionManager(config);
  const googleEnabled = isGoogleOAuthEnabled(config);
  const githubEnabled = isGitHubOAuthEnabled(config);
  const loginRateLimiter =
    deps.rateLimiter ??
    new IpRateLimiter(
      deps.rateLimitMaxAttempts ?? 10,
      deps.rateLimitWindowMs ?? 60_000,
    );
  const ssePollIntervalMs = deps.ssePollIntervalMs ?? 1000;

  const app = new Hono<{ Variables: AdminVariables }>();

  app.get('/manifest.webmanifest', (c) => {
    c.header('Content-Type', 'application/manifest+json; charset=utf-8');
    c.header('Cache-Control', 'no-cache');
    return c.body(JSON.stringify(renderAdminManifest(), null, 2), 200);
  });

  app.get('/icon.svg', (c) => {
    c.header('Content-Type', 'image/svg+xml; charset=utf-8');
    c.header('Cache-Control', 'public, max-age=86400');
    return c.body(renderAdminIconSvg(), 200);
  });

  app.get('/sw.js', (c) => {
    c.header('Content-Type', 'application/javascript; charset=utf-8');
    c.header('Cache-Control', 'no-cache');
    return c.body(renderAdminServiceWorker(), 200);
  });

  app.get('/login', (c) => {
    setAdminSecurityHeaders(c, false, true);
    c.header('Cache-Control', 'no-store');

    const csrfToken = generateRandomToken(24);
    setAdminCsrfCookie(c, config, csrfToken);

    return c.html(
      renderAdminLoginHtml({
        csrfToken,
        googleEnabled,
        githubEnabled,
      }),
      200,
    );
  });

  app.post('/login', async (c) => {
    setAdminSecurityHeaders(c, false, true);
    c.header('Cache-Control', 'no-store');

    const ensureFormCsrf = (): string => {
      const existing = readAdminCsrfCookie(c);
      if (existing) return existing;
      const fresh = generateRandomToken(24);
      setAdminCsrfCookie(c, config, fresh);
      return fresh;
    };

    const ip = getClientIp(c, config.trustCfConnectingIp);
    const rate = loginRateLimiter.consume(`admin-login:${ip}`);
    if (!rate.allowed) {
      c.header('Retry-After', String(rate.retryAfterSec));
      return c.html(
        renderAdminLoginHtml({
          csrfToken: ensureFormCsrf(),
          errorMessage: 'Too many login attempts. Please wait before retrying.',
          googleEnabled,
          githubEnabled,
        }),
        429,
      );
    }

    const bodyRead = await readLimitedBodyText(c);
    if (!bodyRead.ok) {
      return c.html(
        renderAdminLoginHtml({
          csrfToken: ensureFormCsrf(),
          errorMessage: 'Request body exceeds 64KB limit.',
          googleEnabled,
          githubEnabled,
        }),
        413,
      );
    }

    let password = '';
    let submittedCsrf = '';
    const contentType = (c.req.header('content-type') ?? '').toLowerCase();
    if (contentType.includes('application/json')) {
      try {
        const json = JSON.parse(bodyRead.text) as Record<string, unknown>;
        password = typeof json.password === 'string' ? json.password : '';
        submittedCsrf = typeof json.csrf_token === 'string' ? json.csrf_token : '';
      } catch {
        return c.json({ error: 'invalid_json' }, 400);
      }
    } else {
      const form = new URLSearchParams(bodyRead.text);
      password = form.get('password') ?? '';
      submittedCsrf = form.get('csrf_token') ?? '';
    }

    const cookieCsrf = readAdminCsrfCookie(c);
    const headerCsrf = c.req.header('x-csrf-token') ?? '';
    const candidateCsrf = submittedCsrf || headerCsrf;

    if (!cookieCsrf || !candidateCsrf || !constantTimeEqual(candidateCsrf, cookieCsrf)) {
      const freshCsrf = generateRandomToken(24);
      setAdminCsrfCookie(c, config, freshCsrf);
      return c.html(
        renderAdminLoginHtml({
          csrfToken: freshCsrf,
          errorMessage: 'Invalid or expired CSRF token. Please try again.',
          googleEnabled,
          githubEnabled,
        }),
        403,
      );
    }

    const passwordOk = verifyPassword(password, config.adminPasswordHash, config.nodeEnv);
    if (!passwordOk) {
      repos.audit.record({
        actor: 'admin',
        action: 'admin_login',
        target: 'admin_console',
        status: 'failure',
        details: { ip, reason: 'invalid_password' },
      });

      return c.html(
        renderAdminLoginHtml({
          csrfToken: cookieCsrf,
          errorMessage: 'Invalid operator password.',
          googleEnabled,
          githubEnabled,
        }),
        401,
      );
    }

    const now = Date.now();
    const sessionPayload = issueAdminSessionCookie(c, config, now, sessionManager);
    clearAdminCsrfCookie(c);

    repos.audit.record({
      actor: 'admin',
      action: 'admin_login',
      target: 'admin_console',
      status: 'success',
      details: { ip },
      created_at: now,
    });

    const accept = c.req.header('accept') ?? '';
    if (accept.includes('application/json') || contentType.includes('application/json')) {
      return c.json({ ok: true, csrfToken: sessionPayload.csrf }, 200);
    }
    return c.redirect('/admin', 302);
  });

  app.post('/logout', async (c) => {
    const session = readAdminSessionCookie(c, config, Date.now(), sessionManager);

    if (session) {
      let submittedCsrf = c.req.header('x-csrf-token') ?? '';
      if (!submittedCsrf) {
        try {
          const body = await c.req.parseBody();
          submittedCsrf = typeof body.csrf_token === 'string' ? body.csrf_token : '';
        } catch {
          // ignore
        }
      }
      if (!submittedCsrf || !constantTimeEqual(submittedCsrf, session.csrf)) {
        return c.json({ error: 'invalid_csrf_token' }, 403);
      }
    }

    clearAdminSessionCookie(c);
    return c.redirect('/admin/login', 302);
  });

  const computeKpiSummary = (): AdminKpiSummary => {
    const now = Date.now();
    repos.plans.expireStalePlans(now);
    const activeJobs = repos.jobs.countActiveJobs();
    const stagedPlans = repos.plans.countActiveStagedPlans(now);
    const workspaces = repos.workspaces.listWorkspaces();
    const latestSyncAt = workspaces.reduce<number | null>(
      (max, w) => (w.last_synced_at !== null && (max === null || w.last_synced_at > max) ? w.last_synced_at : max),
      null,
    );
    const activeTokens = repos.oauth.listActiveTokens(now);
    const oauthSessions = new Set(activeTokens.map((t) => t.token_family_id)).size;
    const memoriesCount = repos.memories.countAll();
    return {
      activeJobs,
      stagedPlans,
      workspaces: workspaces.length,
      latestSyncAt,
      oauthSessions,
      memoriesCount,
    };
  };

  app.get('/', (c) => {
    const session = readAdminSessionCookie(c, config, Date.now(), sessionManager);
    if (!session) {
      return c.redirect('/admin/login', 302);
    }

    setAdminSecurityHeaders(c, true);
    c.header('Cache-Control', 'no-store');
    return c.html(
      renderAdminDashboardHtml({
        csrfToken: session.csrf,
        publicDomain: config.publicDomain,
        kpis: computeKpiSummary(),
      }),
      200,
    );
  });

  app.use('/api/*', async (c, next) => {
    const session = readAdminSessionCookie(c, config, Date.now(), sessionManager);
    if (!session) {
      return c.json({ error: 'unauthorized' }, 401);
    }
    c.set('adminSession', session);

    const method = c.req.method.toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const headerCsrf = c.req.header('x-csrf-token') ?? '';
      if (!headerCsrf || !constantTimeEqual(headerCsrf, session.csrf)) {
        return c.json({ error: 'invalid_csrf_token' }, 403);
      }
    }

    await next();
  });

  app.get('/api/summary', (c) => {
    return c.json(computeKpiSummary(), 200, { 'Cache-Control': 'no-store' });
  });

  app.get('/api/jobs', (c) => {
    const limit = parseLimit(c.req.query('limit'), 50, 200);
    const jobs = scrubber.scrubObject(repos.jobs.listJobs({ limit }));
    const activeJobs = repos.jobs.countActiveJobs();
    return c.json({ jobs, activeJobs }, 200, { 'Cache-Control': 'no-store' });
  });

  app.get('/api/jobs/stream', (c) => {
    const encoder = new TextEncoder();
    const signal = c.req.raw.signal;
    const session = c.get('adminSession');
    let timer: ReturnType<typeof setInterval> | undefined;

    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        let closed = false;
        let lastSignature = '';

        const cleanup = () => {
          if (closed) return;
          closed = true;
          if (timer) {
            clearInterval(timer);
            timer = undefined;
          }
        };

        const sendJobs = (force = false) => {
          if (closed) return;
          if (Date.now() >= session.exp) {
            cleanup();
            try {
              controller.close();
            } catch {
              // already closed
            }
            return;
          }

          try {
            const jobs = scrubber.scrubObject(repos.jobs.listJobs({ limit: 30 }));
            const activeJobs = repos.jobs.countActiveJobs();
            const signature = `${activeJobs}#${jobs.map((j) => `${j.job_id}:${j.status}:${j.updated_at}`).join('|')}`;
            if (force || signature !== lastSignature) {
              lastSignature = signature;
              controller.enqueue(
                encoder.encode(`event: jobs\ndata: ${JSON.stringify({ jobs, activeJobs })}\n\n`),
              );
            } else {
              controller.enqueue(encoder.encode(': keepalive\n\n'));
            }
          } catch {
            cleanup();
          }
        };

        sendJobs(true);
        if (!closed) {
          timer = setInterval(() => sendJobs(false), ssePollIntervalMs);
        }
        signal.addEventListener('abort', () => {
          cleanup();
          try {
            controller.close();
          } catch {
            // already closed
          }
        });
      },
      cancel() {
        if (timer) {
          clearInterval(timer);
          timer = undefined;
        }
      },
    });

    return new Response(stream, {
      status: 200,
      headers: {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
      },
    });
  });

  app.post('/api/jobs/:id/cancel', async (c) => {
    const jobId = c.req.param('id');
    const job = repos.jobs.getJob(jobId);
    if (!job) {
      return c.json({ error: 'job_not_found' }, 404);
    }

    let cancelled = false;
    if (deps.cancelJob) {
      cancelled = await deps.cancelJob(jobId);
    } else if (job.status === 'queued' || job.status === 'running') {
      repos.jobs.updateJob(jobId, {
        status: 'cancelled',
        error_message: 'Cancelled from Admin console',
      });
      cancelled = true;
    }

    repos.audit.record({
      actor: 'admin',
      action: 'admin_cancel_job',
      target: jobId,
      status: cancelled ? 'success' : 'failure',
      details: { previous_status: job.status },
    });

    return c.json({ ok: true, job_id: jobId, cancelled }, 200);
  });

  app.get('/api/workspaces', (c) => {
    const workspaces = repos.workspaces.listWorkspaces();
    const checkpointsByWorkspace: Record<string, ReturnType<typeof repos.workspaces.listCheckpoints>> = {};
    for (const ws of workspaces) {
      checkpointsByWorkspace[ws.slug] = repos.workspaces.listCheckpoints(ws.slug, 20);
    }
    return c.json(
      scrubber.scrubObject({ workspaces, checkpointsByWorkspace }),
      200,
      { 'Cache-Control': 'no-store' },
    );
  });

  app.post('/api/workspaces/:slug/rollback', async (c) => {
    const slug = c.req.param('slug');
    const workspace = repos.workspaces.getWorkspace(slug);
    if (!workspace) {
      return c.json({ error: 'workspace_not_found' }, 404);
    }

    let checkpointId = '';
    try {
      const body = (await c.req.json()) as Record<string, unknown>;
      checkpointId =
        typeof body.checkpoint_id === 'string'
          ? body.checkpoint_id
          : typeof body.checkpointId === 'string'
            ? body.checkpointId
            : '';
    } catch {
      return c.json({ error: 'invalid_json' }, 400);
    }

    if (!checkpointId) {
      return c.json({ error: 'missing_checkpoint_id' }, 400);
    }

    const checkpoint = repos.workspaces.getCheckpoint(checkpointId);
    if (!checkpoint || checkpoint.workspace_slug !== slug) {
      return c.json({ error: 'checkpoint_not_found' }, 404);
    }

    if (!deps.rollbackCheckpoint) {
      return c.json({ error: 'rollback_not_configured' }, 501);
    }

    await deps.rollbackCheckpoint(slug, checkpointId);

    repos.audit.record({
      actor: 'admin',
      action: 'admin_rollback_checkpoint',
      target: `${slug}:${checkpointId}`,
      status: 'success',
      details: { git_commit_sha: checkpoint.git_commit_sha },
    });

    return c.json({ ok: true, slug, checkpoint_id: checkpointId }, 200);
  });

  app.get('/api/oauth', (c) => {
    const publicBase = config.publicDomain.replace(/\/+$/, '');
    const upstreamProviders = {
      google: {
        enabled: googleEnabled,
        allowedCount: config.googleOAuthAllowedEmails.length,
        callbackUrl: `${publicBase}/auth/idp/google/callback`,
      },
      github: {
        enabled: githubEnabled,
        allowedCount:
          config.githubOAuthAllowedUsers.length + config.githubOAuthAllowedIds.length,
        callbackUrl: `${publicBase}/auth/idp/github/callback`,
      },
    };

    const clients = repos.oauth.listClients().map((client) => ({
      client_id: client.client_id,
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      is_static: client.is_static,
      has_secret: client.client_secret_hash !== null,
      created_at: client.created_at,
    }));

    const activeTokens = repos.oauth.listActiveTokens().map((tok) => ({
      token_hash: tok.token_hash,
      token_type: tok.token_type,
      client_id: tok.client_id,
      scope: tok.scope,
      resource: tok.resource,
      token_family_id: tok.token_family_id,
      expires_at: tok.expires_at,
      grace_expires_at: tok.grace_expires_at,
      created_at: tok.created_at,
    }));

    return c.json({ upstreamProviders, clients, activeTokens }, 200, {
      'Cache-Control': 'no-store',
    });
  });

  app.post('/api/oauth/tokens/:hash/revoke', (c) => {
    const tokenHash = c.req.param('hash');
    const token = repos.oauth.getTokenByHash(tokenHash);
    if (!token) {
      return c.json({ error: 'token_not_found' }, 404);
    }

    if (token.token_type === 'refresh') {
      repos.oauth.revokeTokenFamily(token.token_family_id);
    } else {
      repos.oauth.revokeToken(tokenHash);
    }

    repos.audit.record({
      actor: 'admin',
      action: 'admin_revoke_token',
      target: token.token_family_id,
      status: 'success',
      details: { token_hash: tokenHash, token_type: token.token_type, client_id: token.client_id },
    });

    return c.json({ ok: true, token_hash: tokenHash }, 200);
  });

  app.delete('/api/oauth/clients/:id', (c) => {
    const clientId = c.req.param('id');
    const client = repos.oauth.getClient(clientId);
    if (!client) {
      return c.json({ error: 'client_not_found' }, 404);
    }

    const revokedCount = repos.oauth.revokeClientTokens(clientId);
    const deleted = repos.oauth.deleteClient(clientId);

    repos.audit.record({
      actor: 'admin',
      action: 'admin_delete_client',
      target: clientId,
      status: deleted ? 'success' : 'failure',
      details: { revoked_tokens: revokedCount, client_name: client.client_name },
    });

    return c.json({ ok: deleted, client_id: clientId, revoked_tokens: revokedCount }, 200);
  });

  app.get('/api/plans', (c) => {
    repos.plans.expireStalePlans();
    const limit = parseLimit(c.req.query('limit'), 50, 200);
    const plans = scrubber.scrubObject(repos.plans.listPlans({ limit }));
    return c.json({ plans }, 200, { 'Cache-Control': 'no-store' });
  });

  app.get('/api/memories', (c) => {
    const workspaceSlug = c.req.query('workspace')?.trim() || undefined;
    const rawCategory = c.req.query('category')?.trim() || undefined;
    const limit = parseLimit(c.req.query('limit'), 100, 200);

    if (rawCategory && !MEMORY_CATEGORIES.includes(rawCategory as MemoryCategory)) {
      return c.json({ error: 'invalid_category' }, 400);
    }

    try {
      const memories = scrubber.scrubObject(
        repos.memories.listMemories({
          workspaceSlug,
          category: rawCategory as MemoryCategory | undefined,
          limit,
        }),
      );
      return c.json({ memories }, 200, { 'Cache-Control': 'no-store' });
    } catch {
      return c.json({ error: 'invalid_workspace' }, 400);
    }
  });

  app.delete('/api/memories/:id', (c) => {
    const memoryId = c.req.param('id');
    const existing = repos.memories.getMemoryById(memoryId);
    if (!existing) {
      return c.json({ error: 'memory_not_found' }, 404);
    }

    const deleted = repos.memories.deleteMemoryById(memoryId);
    repos.audit.record({
      actor: 'admin',
      action: 'admin.memory.delete',
      target: memoryId,
      status: deleted ? 'success' : 'failure',
      details: {
        workspace_slug: existing.workspace_slug,
        category: existing.category,
        key: existing.key,
      },
    });

    if (!deleted) {
      return c.json({ error: 'memory_not_found' }, 404);
    }
    return c.json({ ok: true, memory_id: memoryId }, 200);
  });

  app.get('/api/usage', (c) => {
    const summary = repos.usage.getUsageSummary();
    const limitMarkers = repos.audit
      .list({ action: 'usage.limit_marker', limit: 15 })
      .map((entry) =>
        scrubber.scrubObject({
          id: entry.id,
          created_at: entry.created_at,
          actor: entry.actor,
          target: entry.target,
          details: entry.details,
        }),
      );
    return c.json({ summary, limitMarkers }, 200, { 'Cache-Control': 'no-store' });
  });

  app.post('/api/usage/mark-limit', async (c) => {
    const bodyRead = await readLimitedBodyText(c);
    if (!bodyRead.ok) {
      return c.json({ error: 'payload_too_large' }, 413);
    }

    let rawNote = '';
    const trimmed = bodyRead.text.trim();
    if (trimmed.length > 0) {
      try {
        const parsed = JSON.parse(trimmed) as Record<string, unknown>;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return c.json({ error: 'invalid_json' }, 400);
        }
        if (typeof parsed.note === 'string') {
          rawNote = parsed.note;
        }
      } catch {
        return c.json({ error: 'invalid_json' }, 400);
      }
    }

    const sanitizedNote = rawNote
      .replace(/[\x00-\x1f\x7f]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 120);
    const note = scrubber.scrub(sanitizedNote || 'Web AI quota limit hit');
    const summary = repos.usage.getUsageSummary();

    const record = repos.audit.record({
      actor: 'admin',
      action: 'usage.limit_marker',
      target: 'gemini-web',
      status: 'ok',
      details: {
        note,
        last1h: {
          calls: summary.last1h.calls,
          estTotalTokens: summary.last1h.estTotalTokens,
        },
        last3h: {
          calls: summary.last3h.calls,
          estTotalTokens: summary.last3h.estTotalTokens,
        },
        last24h: {
          calls: summary.last24h.calls,
          estTotalTokens: summary.last24h.estTotalTokens,
        },
        agentTokens24h: summary.agentTokens.last24h.totalTokens,
      },
    });

    return c.json(
      {
        ok: true,
        marker: {
          id: record.id,
          created_at: record.created_at,
          actor: record.actor,
          target: record.target,
          details: record.details,
        },
      },
      200,
    );
  });

  app.get('/api/audit', (c) => {
    const limit = parseLimit(c.req.query('limit'), 100, 500);
    const offsetRaw = Number(c.req.query('offset') ?? '0');
    const offset = Number.isInteger(offsetRaw) && offsetRaw >= 0 ? offsetRaw : 0;

    const logs = scrubber.scrubObject(
      repos.audit.list({
        actor: c.req.query('actor') || undefined,
        action: c.req.query('action') || undefined,
        target: c.req.query('target') || undefined,
        status: c.req.query('status') || undefined,
        limit,
        offset,
      }),
    );

    return c.json({ logs }, 200, { 'Cache-Control': 'no-store' });
  });

  return app;
}
