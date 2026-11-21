import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import type {
  AgentDriverName,
  CodexReasoningEffort,
  GatewayConfig,
  LogLevel,
  NodeEnv,
} from './types.js';

const DEFAULT_ALLOWED_REDIRECT_HOSTS = [
  'gemini.google.com',
  'aistudio.google.com',
  'accounts.google.com',
  'localhost',
  '127.0.0.1',
];

function parseBooleanFlag(val: string | undefined, defaultValue: boolean): boolean {
  if (val === undefined || val.trim() === '') return defaultValue;
  const normalized = val.trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
  if (['false', '0', 'no', 'off'].includes(normalized)) return false;
  throw new Error(`Invalid boolean env value: "${val}"`);
}

function emptyToUndefined(val: string | undefined): string | undefined {
  if (val === undefined) return undefined;
  const trimmed = val.trim();
  return trimmed.length === 0 ? undefined : trimmed;
}

function parseCommaList(val: string | undefined, fallback: string[]): string[] {
  if (val === undefined || val.trim() === '') return [...fallback];
  return val
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter((item) => item.length > 0);
}

const optionalUrlSchema = z
  .string()
  .optional()
  .transform(emptyToUndefined)
  .refine((val) => {
    if (!val) return true;
    try {
      const parsed = new URL(val);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }, 'Must be a valid http:// or https:// URL');

const optionalIntSchema = z
  .string()
  .optional()
  .transform(emptyToUndefined)
  .transform((val) => {
    if (val === undefined) return undefined;
    const num = Number(val);
    if (!Number.isInteger(num) || num < 0) {
      throw new Error(`Invalid non-negative integer value: "${val}"`);
    }
    return num;
  });

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).optional(),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).optional(),
  PORT: z.coerce.number().int().min(1).max(65535).default(8787),
  PUBLIC_DOMAIN: z
    .string()
    .optional()
    .transform(emptyToUndefined)
    .transform((val) => {
      const raw = val ?? 'http://localhost:8787';
      let parsedUrl: URL;
      try {
        parsedUrl = new URL(raw);
      } catch {
        throw new Error('PUBLIC_DOMAIN must be a valid http:// or https:// URL');
      }
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        throw new Error('PUBLIC_DOMAIN must use http:// or https://');
      }
      if (parsedUrl.username !== '' || parsedUrl.password !== '') {
        throw new Error('PUBLIC_DOMAIN must not contain userinfo');
      }
      if (parsedUrl.search !== '' || parsedUrl.hash !== '') {
        throw new Error('PUBLIC_DOMAIN must not contain query parameters or fragments');
      }
      if (parsedUrl.pathname !== '/') {
        throw new Error('PUBLIC_DOMAIN must not contain a non-root path');
      }
      return parsedUrl.origin;
    }),
  TRUST_CF_CONNECTING_IP: z.string().optional(),

  DATA_DIR: z
    .string()
    .optional()
    .transform(emptyToUndefined)
    .transform((val) => val ?? '/data'),
  WORKSPACES_DIR: z
    .string()
    .optional()
    .transform(emptyToUndefined)
    .transform((val) => val ?? '/workspaces'),
  ARTIFACTS_DIR: z.string().optional().transform(emptyToUndefined),
  DATABASE_PATH: z.string().optional().transform(emptyToUndefined),

  ADMIN_PASSWORD_HASH: z.string().optional().transform(emptyToUndefined),

  OAUTH_SIGNING_SECRET: z
    .string()
    .optional()
    .transform(emptyToUndefined)
    .transform((val) => val ?? ''),
  OAUTH_STATIC_CLIENT_ID: z.string().optional().transform(emptyToUndefined),
  OAUTH_STATIC_CLIENT_SECRET: z.string().optional().transform(emptyToUndefined),
  OAUTH_ALLOWED_REDIRECT_HOSTS: z.string().optional(),
  OAUTH_ACCESS_TOKEN_TTL_SEC: z.coerce.number().int().min(60).max(86400).default(3600),
  OAUTH_REFRESH_TOKEN_TTL_SEC: z.coerce.number().int().min(300).max(31536000).default(2592000),
  OAUTH_REFRESH_GRACE_SEC: z.coerce.number().int().min(0).max(300).default(60),

  GOOGLE_OAUTH_CLIENT_ID: z.string().optional().transform(emptyToUndefined),
  GOOGLE_OAUTH_CLIENT_SECRET: z.string().optional().transform(emptyToUndefined),
  GOOGLE_OAUTH_ALLOWED_EMAILS: z.string().optional(),
  GITHUB_OAUTH_CLIENT_ID: z.string().optional().transform(emptyToUndefined),
  GITHUB_OAUTH_CLIENT_SECRET: z.string().optional().transform(emptyToUndefined),
  GITHUB_OAUTH_ALLOWED_USERS: z.string().optional(),
  GITHUB_OAUTH_ALLOWED_IDS: z.string().optional(),

  GH_TOKEN: z.string().optional().transform(emptyToUndefined),
  CLOUDFLARE_API_TOKEN: z.string().optional().transform(emptyToUndefined),
  CLOUDFLARE_READONLY_API_TOKEN: z.string().optional().transform(emptyToUndefined),
  CLOUDFLARE_ACCOUNT_ID: z.string().optional().transform(emptyToUndefined),

  OPENAI_API_KEY: z.string().optional().transform(emptyToUndefined),
  CODEX_API_KEY: z.string().optional().transform(emptyToUndefined),
  CODEX_BASE_URL: optionalUrlSchema,
  CODEX_DEFAULT_MODEL: z
    .string()
    .optional()
    .transform(emptyToUndefined)
    .transform((val) => val ?? 'gpt-5.3-codex'),
  CODEX_REASONING_EFFORT: z
    .enum(['minimal', 'low', 'medium', 'high', 'xhigh'])
    .optional()
    .transform((val): CodexReasoningEffort => val ?? 'medium'),
  CODEX_MAX_DURATION_SEC: z.coerce.number().int().min(10).max(3600).default(300),
  CODEX_TOKEN_BUDGET: z.coerce.number().int().min(1000).max(10000000).default(200000),

  NOTIFY_WEBHOOK_URL: optionalUrlSchema,
  DOWNSTREAM_MCPS_JSON: z.string().optional().transform(emptyToUndefined),
  DOWNSTREAM_MCPS_FILE: z.string().optional().transform(emptyToUndefined),

  INLINE_OUTPUT_MAX_BYTES: z.coerce.number().int().min(1024).max(262144).default(60000),
  WORKSPACE_EXEC_DEFAULT_WAIT_MS: z.coerce.number().int().min(500).max(15000).default(12000),
  WORKSPACE_EXEC_MAX_WAIT_MS: z.coerce.number().int().min(1000).max(15000).default(15000),
  MUTATION_PLAN_TTL_SEC: z.coerce.number().int().min(60).max(86400).default(900),

  SANDBOX_UID: optionalIntSchema,
  SANDBOX_GID: optionalIntSchema,
  SANDBOX_BWRAP_ISOLATION: z.string().optional(),
  SANDBOX_STRICT_ISOLATION: z.string().optional(),

  DEFAULT_AGENT_DRIVER: z
    .enum(['codex', 'claude_code', 'gemini_cli', 'opencode'])
    .optional()
    .transform((val): AgentDriverName => val ?? 'codex'),
  ANTHROPIC_API_KEY: z.string().optional().transform(emptyToUndefined),
  GEMINI_API_KEY: z.string().optional().transform(emptyToUndefined),
  AGENT_RUNNER_URL: optionalUrlSchema,
  AGENT_RUNNER_AUTH_TOKEN: z.string().optional().transform(emptyToUndefined),
  OPS_MCP_AUTH_TOKEN: z.string().optional().transform(emptyToUndefined),
});

function canonicalizeWithAncestor(targetPath: string): string {
  const resolved = path.resolve(targetPath);
  const missingSegments: string[] = [];
  let cursor = resolved;
  while (!fs.existsSync(cursor)) {
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    missingSegments.unshift(path.basename(cursor));
    cursor = parent;
  }

  let realBase = cursor;
  try {
    if (fs.existsSync(cursor)) {
      realBase = fs.realpathSync(cursor);
    }
  } catch {
    realBase = cursor;
  }

  const combined = path.join(realBase, ...missingSegments);
  return process.platform === 'win32' ? combined.toLowerCase() : combined;
}

function pathsOverlap(a: string, b: string): boolean {
  if (a === b) return true;
  const aWithSep = a.endsWith(path.sep) ? a : a + path.sep;
  const bWithSep = b.endsWith(path.sep) ? b : b + path.sep;
  return a.startsWith(bWithSep) || b.startsWith(aWithSep);
}

/**
 * Parses and validates environment variables into a typed GatewayConfig.
 * Accepts an explicit `env` map for isolated unit/integration testing.
 */
export function loadConfig(env: Record<string, string | undefined> = process.env): GatewayConfig {
  const parsed = envSchema.parse(env);
  const nodeEnv = (parsed.NODE_ENV ?? 'development') as NodeEnv;

  const googleOAuthAllowedEmails = parseCommaList(parsed.GOOGLE_OAUTH_ALLOWED_EMAILS, []);
  const githubOAuthAllowedUsers = parseCommaList(parsed.GITHUB_OAUTH_ALLOWED_USERS, []);
  const githubOAuthAllowedIds = parseCommaList(parsed.GITHUB_OAUTH_ALLOWED_IDS, []);

  for (const id of githubOAuthAllowedIds) {
    if (!/^\d+$/.test(id)) {
      throw new Error(`Invalid numeric GitHub user ID in GITHUB_OAUTH_ALLOWED_IDS: "${id}"`);
    }
  }

  if (nodeEnv === 'production') {
    const domainUrl = new URL(parsed.PUBLIC_DOMAIN);
    const isLoopback =
      domainUrl.hostname === 'localhost' || domainUrl.hostname === '127.0.0.1';
    if (domainUrl.protocol !== 'https:' && !isLoopback) {
      throw new Error(
        `PUBLIC_DOMAIN (${parsed.PUBLIC_DOMAIN}) must use https:// when NODE_ENV=production`,
      );
    }

    const secret = parsed.OAUTH_SIGNING_SECRET.trim();
    if (
      secret.length < 32 ||
      /replace[-_]?with|change[-_]?me|example|secret[-_]?here|placeholder/i.test(secret)
    ) {
      throw new Error(
        'OAUTH_SIGNING_SECRET must be at least 32 non-placeholder characters when NODE_ENV=production',
      );
    }

    if (
      (parsed.GOOGLE_OAUTH_CLIENT_ID || parsed.GOOGLE_OAUTH_CLIENT_SECRET) &&
      googleOAuthAllowedEmails.length === 0
    ) {
      throw new Error(
        'GOOGLE_OAUTH_ALLOWED_EMAILS must be set (non-empty) when Google OAuth credentials are configured in NODE_ENV=production',
      );
    }

    if (
      (parsed.GITHUB_OAUTH_CLIENT_ID || parsed.GITHUB_OAUTH_CLIENT_SECRET) &&
      githubOAuthAllowedUsers.length === 0 &&
      githubOAuthAllowedIds.length === 0
    ) {
      throw new Error(
        'GITHUB_OAUTH_ALLOWED_USERS or GITHUB_OAUTH_ALLOWED_IDS must be set (non-empty) when GitHub OAuth credentials are configured in NODE_ENV=production',
      );
    }

    if (parsed.AGENT_RUNNER_URL) {
      const runnerToken = parsed.AGENT_RUNNER_AUTH_TOKEN?.trim() ?? '';
      if (
        runnerToken.length < 24 ||
        /replace[-_]?with|change[-_]?me|example|secret[-_]?here|placeholder/i.test(runnerToken)
      ) {
        throw new Error(
          'AGENT_RUNNER_AUTH_TOKEN must be at least 24 non-placeholder characters when AGENT_RUNNER_URL is set in NODE_ENV=production',
        );
      }
    }
  }

  const dataDir = path.resolve(parsed.DATA_DIR);
  const workspacesDir = path.resolve(parsed.WORKSPACES_DIR);
  const artifactsDir = parsed.ARTIFACTS_DIR
    ? path.resolve(parsed.ARTIFACTS_DIR)
    : path.join(dataDir, 'artifacts');
  const databasePath =
    parsed.DATABASE_PATH === ':memory:'
      ? ':memory:'
      : parsed.DATABASE_PATH
        ? path.resolve(parsed.DATABASE_PATH)
        : path.join(dataDir, 'gateway.db');

  const resolvedArtifacts = path.resolve(artifactsDir);
  const resolvedWorkspaces = path.resolve(workspacesDir);

  const canonWorkspaces = canonicalizeWithAncestor(resolvedWorkspaces);
  const protectedTargets: Array<[string, string]> = [
    ['DATA_DIR', dataDir],
    ['ARTIFACTS_DIR', resolvedArtifacts],
  ];
  if (databasePath !== ':memory:') {
    protectedTargets.push(['DATABASE_PATH', databasePath]);
  }
  for (const [label, target] of protectedTargets) {
    if (pathsOverlap(canonicalizeWithAncestor(target), canonWorkspaces)) {
      throw new Error(
        `${label} (${target}) must not overlap with WORKSPACES_DIR (${resolvedWorkspaces})`,
      );
    }
  }

  return {
    nodeEnv,
    logLevel: (parsed.LOG_LEVEL ?? 'info') as LogLevel,
    port: parsed.PORT,
    publicDomain: parsed.PUBLIC_DOMAIN,
    trustCfConnectingIp: parseBooleanFlag(parsed.TRUST_CF_CONNECTING_IP, true),

    dataDir,
    workspacesDir,
    artifactsDir: resolvedArtifacts,
    databasePath,

    adminPasswordHash: parsed.ADMIN_PASSWORD_HASH,

    oauthSigningSecret: parsed.OAUTH_SIGNING_SECRET,
    oauthStaticClientId: parsed.OAUTH_STATIC_CLIENT_ID,
    oauthStaticClientSecret: parsed.OAUTH_STATIC_CLIENT_SECRET,
    oauthAllowedRedirectHosts: parseCommaList(
      parsed.OAUTH_ALLOWED_REDIRECT_HOSTS,
      DEFAULT_ALLOWED_REDIRECT_HOSTS,
    ),
    oauthAccessTokenTtlSec: parsed.OAUTH_ACCESS_TOKEN_TTL_SEC,
    oauthRefreshTokenTtlSec: parsed.OAUTH_REFRESH_TOKEN_TTL_SEC,
    oauthRefreshGraceSec: parsed.OAUTH_REFRESH_GRACE_SEC,

    googleOAuthClientId: parsed.GOOGLE_OAUTH_CLIENT_ID,
    googleOAuthClientSecret: parsed.GOOGLE_OAUTH_CLIENT_SECRET,
    googleOAuthAllowedEmails,
    githubOAuthClientId: parsed.GITHUB_OAUTH_CLIENT_ID,
    githubOAuthClientSecret: parsed.GITHUB_OAUTH_CLIENT_SECRET,
    githubOAuthAllowedUsers,
    githubOAuthAllowedIds,

    ghToken: parsed.GH_TOKEN,
    cloudflareApiToken: parsed.CLOUDFLARE_API_TOKEN,
    cloudflareReadonlyApiToken: parsed.CLOUDFLARE_READONLY_API_TOKEN,
    cloudflareAccountId: parsed.CLOUDFLARE_ACCOUNT_ID,

    openaiApiKey: parsed.OPENAI_API_KEY,
    codexApiKey: parsed.CODEX_API_KEY,
    codexBaseUrl: parsed.CODEX_BASE_URL,
    codexDefaultModel: parsed.CODEX_DEFAULT_MODEL,
    codexReasoningEffort: parsed.CODEX_REASONING_EFFORT,
    codexMaxDurationSec: parsed.CODEX_MAX_DURATION_SEC,
    codexTokenBudget: parsed.CODEX_TOKEN_BUDGET,

    notifyWebhookUrl: parsed.NOTIFY_WEBHOOK_URL,
    downstreamMcpsJson: parsed.DOWNSTREAM_MCPS_JSON,
    downstreamMcpsFile: parsed.DOWNSTREAM_MCPS_FILE,

    inlineOutputMaxBytes: parsed.INLINE_OUTPUT_MAX_BYTES,
    workspaceExecDefaultWaitMs: Math.min(
      parsed.WORKSPACE_EXEC_DEFAULT_WAIT_MS,
      parsed.WORKSPACE_EXEC_MAX_WAIT_MS,
    ),
    workspaceExecMaxWaitMs: parsed.WORKSPACE_EXEC_MAX_WAIT_MS,
    mutationPlanTtlSec: parsed.MUTATION_PLAN_TTL_SEC,

    sandboxUid: parsed.SANDBOX_UID,
    sandboxGid: parsed.SANDBOX_GID,
    sandboxBwrapIsolation: parseBooleanFlag(
      parsed.SANDBOX_BWRAP_ISOLATION,
      process.platform === 'linux',
    ),
    sandboxStrictIsolation: parseBooleanFlag(parsed.SANDBOX_STRICT_ISOLATION, false),

    defaultAgentDriver: parsed.DEFAULT_AGENT_DRIVER,
    anthropicApiKey: parsed.ANTHROPIC_API_KEY,
    geminiApiKey: parsed.GEMINI_API_KEY,
    agentRunnerUrl: parsed.AGENT_RUNNER_URL,
    agentRunnerAuthToken: parsed.AGENT_RUNNER_AUTH_TOKEN,
    opsMcpAuthToken: parsed.OPS_MCP_AUTH_TOKEN,
  };
}

let cachedConfig: GatewayConfig | null = null;

/**
 * Returns the lazily-initialized process-wide GatewayConfig singleton.
 */
export function getConfig(): GatewayConfig {
  if (!cachedConfig) {
    cachedConfig = loadConfig(process.env);
  }
  return cachedConfig;
}

/**
 * Clears the cached singleton config (intended for tests).
 */
export function resetConfigCache(): void {
  cachedConfig = null;
}

/**
 * Returns true only when Google OAuth client credentials AND a non-empty allowed-emails list are configured.
 */
export function isGoogleOAuthEnabled(
  config: Pick<
    GatewayConfig,
    'googleOAuthClientId' | 'googleOAuthClientSecret' | 'googleOAuthAllowedEmails'
  >,
): boolean {
  return Boolean(
    config.googleOAuthClientId &&
      config.googleOAuthClientSecret &&
      config.googleOAuthAllowedEmails.length > 0,
  );
}

/**
 * Returns true only when GitHub OAuth client credentials AND a non-empty user/ID allowlist are configured.
 */
export function isGitHubOAuthEnabled(
  config: Pick<
    GatewayConfig,
    | 'githubOAuthClientId'
    | 'githubOAuthClientSecret'
    | 'githubOAuthAllowedUsers'
    | 'githubOAuthAllowedIds'
  >,
): boolean {
  return Boolean(
    config.githubOAuthClientId &&
      config.githubOAuthClientSecret &&
      (config.githubOAuthAllowedUsers.length > 0 || config.githubOAuthAllowedIds.length > 0),
  );
}
