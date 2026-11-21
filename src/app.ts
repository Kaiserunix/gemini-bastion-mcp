import fs from 'node:fs';
import { Hono } from 'hono';
import { createAdminApp } from './admin/index.js';
import {
  createAuthApp,
  createBearerMiddleware,
  ensureStaticClient,
  SignedCookieAdminSessionManager,
  type AdminSessionManager,
  type OAuthStore,
} from './auth/index.js';
import { loadConfig } from './config.js';
import { createAgentRunnerRegistry } from './core/agentDrivers/index.js';
import { CloudflareService } from './core/cloudflareService.js';
import { CodexSdkRunner, reconcileOrphanJobs } from './core/codexRunner.js';
import { DownstreamMcpBridge } from './core/downstreamMcpBridge.js';
import { GitHubService } from './core/githubService.js';
import { rollbackToCheckpoint } from './core/gitSnapshot.js';
import { createGitHubWebhookApp } from './core/watchdogService.js';
import { sendWebhookNotification } from './core/webhookNotifier.js';
import { cancelActiveJob, listActiveJobIds } from './core/workspaceExec.js';
import { WorkspaceLockManager, workspaceLockManager } from './core/workspaceLock.js';
import { createRepositories, type Repositories } from './db/repositories/index.js';
import { openDatabase, type GatewayDatabase } from './db/sqlite.js';
import {
  defaultWorkspaceToolAdapter,
  type WorkspaceToolAdapter,
} from './mcp/adapters/index.js';
import {
  buildPublicGatewayStatusJson,
  LANDING_PAGE_CSP,
  renderPublicLandingPageHtml,
} from './mcp/landingPage.js';
import { createMcpHttpHandler } from './mcp/server.js';
import type { McpToolDeps } from './mcp/tools/index.js';
import {
  DefaultApprovalGatePolicy,
  MutationPlanGate,
  type ApprovalGatePolicy,
  type MutationTargetAdapter,
} from './policy/index.js';
import {
  CircuitBreakerRegistry,
  JsonlFileAuditSink,
  MemoryAuditSink,
  SlidingWindowRateLimiter,
  SqliteAuditSink,
  StructuredAuditLogger,
  createBastionPolicyEvaluator,
  createResilienceMiddleware,
  type AuditSink,
  type PolicyEvaluatorPort,
  type PolicyRule,
  type RateLimiterPort,
} from './security/index.js';
import type { AgentRunner, GatewayConfig, ScrubberLike } from './types.js';
import { createSecretScrubber } from './utils/secretScrubber.js';

export interface CreateGatewayAppOptions {
  config?: GatewayConfig;
  env?: Record<string, string | undefined>;
  dbPath?: string;
  scrubber?: ScrubberLike;
  lockManager?: WorkspaceLockManager;
  oauthStore?: OAuthStore;
  sessionManager?: AdminSessionManager;
  approvalPolicy?: ApprovalGatePolicy;
  planGate?: MutationPlanGate;
  workspaceAdapter?: WorkspaceToolAdapter;
  githubService?: GitHubService;
  cloudflareService?: CloudflareService;
  downstreamBridge?: DownstreamMcpBridge;
  codexRunner?: CodexSdkRunner;
  agentRunner?: AgentRunner;
  rateLimitMaxAttempts?: number;
  rateLimitWindowMs?: number;
  mcpMaxBodyBytes?: number;
  auditLogger?: StructuredAuditLogger;
  auditSinks?: AuditSink[];
  mcpRateLimiter?: RateLimiterPort;
  mcpRateLimitMaxRequests?: number;
  mcpRateLimitWindowMs?: number;
  circuitBreakers?: CircuitBreakerRegistry;
  policyEvaluator?: PolicyEvaluatorPort;
  policyRules?: PolicyRule[];
}

export interface GatewayAppInstance {
  app: Hono;
  config: GatewayConfig;
  db: GatewayDatabase;
  repos: Repositories;
  oauthStore: OAuthStore;
  sessionManager: AdminSessionManager;
  approvalPolicy: ApprovalGatePolicy;
  planGate: MutationPlanGate;
  workspaceAdapter: WorkspaceToolAdapter;
  scrubber: ScrubberLike;
  lockManager: WorkspaceLockManager;
  githubService: GitHubService;
  cloudflareService: CloudflareService;
  downstreamBridge: DownstreamMcpBridge;
  codexRunner: CodexSdkRunner;
  agentRunner: AgentRunner;
  auditLogger: StructuredAuditLogger;
  mcpRateLimiter: RateLimiterPort;
  circuitBreakers: CircuitBreakerRegistry;
  policyEvaluator: PolicyEvaluatorPort;
  shutdown: () => Promise<void>;
}

/**
 * Assembles the full omni-mcp-gateway Hono application:
 * - SQLite WAL database + migrations + repositories
 * - OAuth 2.1 + DCR + PKCE + RFC 8707 routes
 * - /admin PWA with real job cancellation & checkpoint rollback callbacks
 * - Bearer-protected stateless Streamable HTTP /mcp endpoint (10 tools)
 * - Scrubbed global error handling and graceful shutdown
 */
export function createGatewayApp(
  options: CreateGatewayAppOptions = {},
): GatewayAppInstance {
  const startedAt = Date.now();
  const config = options.config ?? loadConfig(options.env ?? process.env);

  fs.mkdirSync(config.dataDir, { recursive: true });
  fs.mkdirSync(config.workspacesDir, { recursive: true });
  fs.mkdirSync(config.artifactsDir, { recursive: true });

  const db = openDatabase(options.dbPath ?? config.databasePath);
  const scrubber = options.scrubber ?? createSecretScrubber(config, options.env ?? process.env);
  const repos = createRepositories(db, { scrubber });
  const oauthStore: OAuthStore = options.oauthStore ?? repos.oauth;
  const sessionManager: AdminSessionManager =
    options.sessionManager ?? new SignedCookieAdminSessionManager(config);
  const approvalPolicy: ApprovalGatePolicy =
    options.approvalPolicy ?? new DefaultApprovalGatePolicy();
  const workspaceAdapter: WorkspaceToolAdapter =
    options.workspaceAdapter ?? defaultWorkspaceToolAdapter;
  const lockManager = options.lockManager ?? workspaceLockManager;

  const defaultSinks: AuditSink[] = [
    new SqliteAuditSink(repos.audit),
    new MemoryAuditSink({ maxEntries: 1000 }),
  ];
  if (config.auditLogFilePath) {
    defaultSinks.push(
      new JsonlFileAuditSink({
        filePath: config.auditLogFilePath,
        workspacesDir: config.workspacesDir,
      }),
    );
  }
  if (options.auditSinks) {
    defaultSinks.push(...options.auditSinks);
  }

  const auditLogger =
    options.auditLogger ??
    new StructuredAuditLogger({
      sinks: defaultSinks,
      scrubber,
    });
  repos.audit.configure({ scrubber, publisher: auditLogger });

  const mcpRateLimiter =
    options.mcpRateLimiter ??
    new SlidingWindowRateLimiter({
      maxRequests: options.mcpRateLimitMaxRequests ?? config.mcpRateLimitMaxRequests ?? 300,
      windowMs: options.mcpRateLimitWindowMs ?? config.mcpRateLimitWindowMs ?? 60_000,
    });

  const circuitBreakers =
    options.circuitBreakers ??
    new CircuitBreakerRegistry({
      defaults: {
        failureThreshold: config.circuitBreakerFailureThreshold ?? 5,
        resetTimeoutMs: config.circuitBreakerResetTimeoutMs ?? 30_000,
      },
      auditPublisher: auditLogger,
    });

  const policyEvaluator =
    options.policyEvaluator ??
    createBastionPolicyEvaluator({
      rules: options.policyRules,
      policyJson: config.securityPolicyJson,
      policyFile: config.securityPolicyFile,
      auditPublisher: auditLogger,
    });

  ensureStaticClient(config, oauthStore);
  reconcileOrphanJobs(repos.jobs);

  const githubService =
    options.githubService ??
    new GitHubService({
      token: config.ghToken,
      scrubber,
      policy: approvalPolicy,
    });

  const cloudflareService =
    options.cloudflareService ?? CloudflareService.fromConfig(config, scrubber, approvalPolicy);

  const downstreamBridge =
    options.downstreamBridge ??
    DownstreamMcpBridge.fromConfig(config, scrubber, undefined, approvalPolicy);

  const gateAdapters: MutationTargetAdapter[] = [];
  if (typeof cloudflareService.asMutationTargetAdapter === 'function') {
    gateAdapters.push(cloudflareService.asMutationTargetAdapter());
  }
  if (typeof downstreamBridge.asMutationTargetAdapter === 'function') {
    gateAdapters.push(downstreamBridge.asMutationTargetAdapter());
  }

  const planGate =
    options.planGate ??
    new MutationPlanGate({
      planStore: repos.plans,
      auditLogger: repos.audit,
      policy: approvalPolicy,
      scrubber,
      adapters: gateAdapters,
    });

  const codexRunner =
    options.codexRunner ??
    new CodexSdkRunner({
      config,
      jobRepo: repos.jobs,
      workspaceRepo: repos.workspaces,
      lockManager,
      scrubber,
    });

  const agentRunner =
    options.agentRunner ??
    createAgentRunnerRegistry({
      config,
      jobRepo: repos.jobs,
      workspaceRepo: repos.workspaces,
      lockManager,
      scrubber,
      codexRunner,
    });

  const notifyWebhook = async (event: string, payload: Record<string, unknown>) => {
    await sendWebhookNotification(config, event, payload, { scrubber });
  };

  const mcpDeps: McpToolDeps = {
    config,
    db,
    repos,
    scrubber,
    lockManager,
    githubService,
    cloudflareService,
    downstreamBridge,
    codexRunner,
    agentRunner,
    workspaceAdapter,
    approvalPolicy,
    planGate,
    policyEvaluator,
    auditPublisher: auditLogger,
    notifyWebhook,
  };

  const app = new Hono();

  app.get('/', (c) => {
    let dbReady = false;
    try {
      db.prepare('SELECT 1').get();
      dbReady = true;
    } catch {
      dbReady = false;
    }

    const uptimeSec = Math.floor((Date.now() - startedAt) / 1000);
    const accept = (c.req.header('accept') ?? '').toLowerCase();
    const wantsJson = accept.includes('application/json') && !accept.includes('text/html');

    c.header('Cache-Control', 'no-store');
    c.header('X-Content-Type-Options', 'nosniff');
    c.header('X-Frame-Options', 'DENY');

    if (wantsJson) {
      return c.json(
        buildPublicGatewayStatusJson({
          publicDomain: config.publicDomain,
          dbReady,
          uptimeSec,
        }),
        dbReady ? 200 : 503,
      );
    }

    c.header('Content-Security-Policy', LANDING_PAGE_CSP);
    return c.html(
      renderPublicLandingPageHtml({
        publicDomain: config.publicDomain,
        dbReady,
        uptimeSec,
      }),
      dbReady ? 200 : 503,
    );
  });

  app.get('/healthz', (c) => {
    try {
      db.prepare('SELECT 1').get();
      return c.json(
        {
          ok: true,
          service: 'gemini-bastion-mcp',
          db: 'ready',
          uptime_sec: Math.floor((Date.now() - startedAt) / 1000),
        },
        200,
      );
    } catch (err) {
      return c.json(
        {
          ok: false,
          service: 'gemini-bastion-mcp',
          db: 'error',
          message: scrubber.scrub(err instanceof Error ? err.message : String(err)),
        },
        503,
      );
    }
  });

  app.route(
    '/',
    createAuthApp({
      config,
      db,
      repos,
      oauthStore,
      auditLogger: repos.audit,
      sessionManager,
      rateLimitMaxAttempts: options.rateLimitMaxAttempts,
      rateLimitWindowMs: options.rateLimitWindowMs,
    }),
  );

  app.route(
    '/admin',
    createAdminApp({
      config,
      repos,
      scrubber,
      sessionManager,
      rateLimitMaxAttempts: options.rateLimitMaxAttempts,
      rateLimitWindowMs: options.rateLimitWindowMs,
      cancelJob: async (jobId: string) => {
        const res = await cancelActiveJob(jobId, repos.jobs);
        return res.cancelled;
      },
      rollbackCheckpoint: async (slug: string, checkpointId: string) => {
        await lockManager.withWriteLock(slug, () =>
          rollbackToCheckpoint(slug, checkpointId, {
            workspacesDir: config.workspacesDir,
            workspaceRepo: repos.workspaces,
            createSafetyCheckpoint: true,
            scrubber,
          }),
        );
      },
    }),
  );

  const bearerMiddleware = createBearerMiddleware({ config, repos, oauthStore });
  const mcpResilienceMiddleware = createResilienceMiddleware({
    limiter: mcpRateLimiter,
    breaker: circuitBreakers,
    circuitName: 'mcp:http',
    trustCfConnectingIp: config.trustCfConnectingIp,
    keyPrefix: 'mcp',
    responseFormat: 'jsonrpc',
    auditPublisher: auditLogger,
  });
  app.use('/mcp', bearerMiddleware);
  app.use('/mcp', mcpResilienceMiddleware);
  app.all('/mcp', createMcpHttpHandler(mcpDeps, { maxBodyBytes: options.mcpMaxBodyBytes }));

  app.route(
    '/webhooks/github',
    createGitHubWebhookApp({
      config,
      repos,
      scrubber,
      agentRunner,
      notifyWebhook,
      rateLimitMaxAttempts: options.rateLimitMaxAttempts,
      rateLimitWindowMs: options.rateLimitWindowMs,
    }),
  );

  app.onError((err, c) => {
    const safeMsg = scrubber.scrub(err instanceof Error ? err.message : String(err));
    return c.json(
      {
        error: 'internal_server_error',
        message: safeMsg,
      },
      500,
    );
  });

  app.notFound((c) => c.json({ error: 'not_found' }, 404));

  const cleanupIntervalMs = 15 * 60 * 1000;
  const cleanupTimer = setInterval(() => {
    try {
      oauthStore.purgeExpired();
      repos.plans.expireStalePlans();
      repos.usage.purgeOlderThan(Date.now() - 90 * 24 * 60 * 60 * 1000);
    } catch {
      // Non-fatal periodic cleanup
    }
  }, cleanupIntervalMs);
  cleanupTimer.unref?.();

  let closed = false;
  const shutdown = async () => {
    if (closed) return;
    closed = true;

    clearInterval(cleanupTimer);
    const activeIds = listActiveJobIds();
    await Promise.allSettled(activeIds.map((id) => cancelActiveJob(id, repos.jobs)));
    await downstreamBridge.closeAll();
    await auditLogger.close();
    try {
      db.close();
    } catch {
      // Ignore if already closed
    }
  };

  return {
    app,
    config,
    db,
    repos,
    oauthStore,
    sessionManager,
    approvalPolicy,
    planGate,
    workspaceAdapter,
    scrubber,
    lockManager,
    githubService,
    cloudflareService,
    downstreamBridge,
    codexRunner,
    agentRunner,
    auditLogger,
    mcpRateLimiter,
    circuitBreakers,
    policyEvaluator,
    shutdown,
  };
}
