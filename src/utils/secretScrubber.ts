import fs from 'node:fs';
import type { DownstreamMcpServerConfig, GatewayConfig, ScrubberLike } from '../types.js';

export const REDACTED_PLACEHOLDER = '[REDACTED_SECRET]';

const SENSITIVE_KEY_PATTERN =
  /(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL|WEBHOOK|SIGNING|AUTH_HEADER|BEARER|COOKIE|DATABASE_URL)/i;

const EXPLICIT_SECRET_KEYS = [
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'CLOUDFLARE_API_TOKEN',
  'CLOUDFLARE_READONLY_API_TOKEN',
  'OPENAI_API_KEY',
  'CODEX_API_KEY',
  'ANTHROPIC_API_KEY',
  'GEMINI_API_KEY',
  'OPS_MCP_AUTH_TOKEN',
  'AGENT_RUNNER_AUTH_TOKEN',
  'OAUTH_SIGNING_SECRET',
  'OAUTH_STATIC_CLIENT_SECRET',
  'GOOGLE_OAUTH_CLIENT_SECRET',
  'GITHUB_OAUTH_CLIENT_SECRET',
  'ADMIN_PASSWORD_HASH',
  'NOTIFY_WEBHOOK_URL',
  'DOWNSTREAM_MCPS_JSON',
];

const REGEX_SCRUB_RULES: Array<{ pattern: RegExp; replacement: string }> = [
  // GitHub PATs and OAuth tokens
  {
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{16,}\b/g,
    replacement: REDACTED_PLACEHOLDER,
  },
  {
    pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
    replacement: REDACTED_PLACEHOLDER,
  },
  // OpenAI / Codex / Anthropic-style sk- tokens
  {
    pattern: /\bsk-(?:proj-|svcacct-|admin-|ant-)?[A-Za-z0-9_-]{16,}\b/g,
    replacement: REDACTED_PLACEHOLDER,
  },
  // Google / Gemini API keys
  {
    pattern: /\bAIza[0-9A-Za-z_-]{30,}\b/g,
    replacement: REDACTED_PLACEHOLDER,
  },
  // JWTs (header.payload.signature or header.payload)
  {
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)?\b/g,
    replacement: REDACTED_PLACEHOLDER,
  },
  // Cloudflare token formats
  {
    pattern: /\bcfut_[A-Za-z0-9_-]{16,}\b/g,
    replacement: REDACTED_PLACEHOLDER,
  },
  {
    pattern: /\bv1\.0-[A-Fa-f0-9]{16,}-[A-Fa-f0-9]{16,}\b/g,
    replacement: REDACTED_PLACEHOLDER,
  },
  // Authorization Bearer / Basic headers
  {
    pattern: /(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi,
    replacement: `$1${REDACTED_PLACEHOLDER}`,
  },
  {
    pattern: /(\bBasic\s+)[A-Za-z0-9+/=]{8,}/gi,
    replacement: `$1${REDACTED_PLACEHOLDER}`,
  },
  // Credentials embedded in URLs (https://user:pass@host)
  {
    pattern: /(https?:\/\/[^:\s/@]+:)([^@\s/]+)(@)/gi,
    replacement: `$1${REDACTED_PLACEHOLDER}$3`,
  },
];

export interface SecretScrubberOptions {
  extraSecrets?: string[];
  env?: Record<string, string | undefined>;
  config?: Partial<GatewayConfig> & { downstreamMcps?: DownstreamMcpServerConfig[] };
  downstreamMcps?: DownstreamMcpServerConfig[];
  minSecretLength?: number;
}

function extractDownstreamServers(parsed: unknown): DownstreamMcpServerConfig[] {
  if (Array.isArray(parsed)) {
    return parsed as DownstreamMcpServerConfig[];
  }
  if (parsed && typeof parsed === 'object') {
    const asObj = parsed as { servers?: unknown };
    if (Array.isArray(asObj.servers)) {
      return asObj.servers as DownstreamMcpServerConfig[];
    }
    return Object.values(parsed as Record<string, DownstreamMcpServerConfig>).filter(
      (entry): entry is DownstreamMcpServerConfig => Boolean(entry && typeof entry === 'object'),
    );
  }
  return [];
}

/**
 * Scrubs known gateway secrets and common token/credential patterns from strings and objects.
 */
export class SecretScrubber implements ScrubberLike {
  private readonly minSecretLength: number;
  private readonly envRef: Record<string, string | undefined>;
  private readonly exactSecrets = new Set<string>();
  private sortedSecrets: string[] = [];

  constructor(options: SecretScrubberOptions = {}) {
    this.minSecretLength = options.minSecretLength ?? 8;
    this.envRef = options.env ?? process.env;

    if (options.env) {
      this.collectFromEnv(options.env);
    }
    if (options.config) {
      this.collectFromConfig(options.config);
    }
    if (options.downstreamMcps) {
      this.collectFromDownstreamMcps(options.downstreamMcps, this.envRef);
    }
    if (options.extraSecrets) {
      for (const secret of options.extraSecrets) {
        this.addSecret(secret);
      }
    }
  }

  addSecret(value: string | undefined | null): void {
    if (!value) return;
    const trimmed = value.trim();
    if (trimmed.length < this.minSecretLength) return;
    if (!this.exactSecrets.has(trimmed)) {
      this.exactSecrets.add(trimmed);
      this.sortedSecrets = Array.from(this.exactSecrets).sort((a, b) => b.length - a.length);
    }
  }

  collectFromEnv(env: Record<string, string | undefined>): void {
    for (const [key, val] of Object.entries(env)) {
      if (!val) continue;
      if (EXPLICIT_SECRET_KEYS.includes(key) || SENSITIVE_KEY_PATTERN.test(key)) {
        this.addSecret(val);
      }
    }
  }

  collectFromDownstreamMcps(
    servers: DownstreamMcpServerConfig[],
    env: Record<string, string | undefined> = this.envRef,
  ): void {
    for (const server of servers) {
      if (!server || typeof server !== 'object') continue;
      this.addSecret(server.authToken);
      if (server.authTokenEnv && env[server.authTokenEnv]) {
        this.addSecret(env[server.authTokenEnv]);
      }
      if (server.headers && typeof server.headers === 'object') {
        for (const [headerKey, headerVal] of Object.entries(server.headers)) {
          if (!headerVal) continue;
          if (/authorization|token|secret|api[-_]?key/i.test(headerKey)) {
            this.addSecret(headerVal);
            if (/^bearer\s+/i.test(headerVal)) {
              this.addSecret(headerVal.replace(/^bearer\s+/i, '').trim());
            }
          }
        }
      }
    }
  }

  collectFromConfig(
    config: Partial<GatewayConfig> & { downstreamMcps?: DownstreamMcpServerConfig[] },
  ): void {
    this.addSecret(config.adminPasswordHash);
    this.addSecret(config.oauthSigningSecret);
    this.addSecret(config.oauthStaticClientSecret);
    this.addSecret(config.googleOAuthClientSecret);
    this.addSecret(config.githubOAuthClientSecret);
    this.addSecret(config.ghToken);
    this.addSecret(config.cloudflareApiToken);
    this.addSecret(config.cloudflareReadonlyApiToken);
    this.addSecret(config.openaiApiKey);
    this.addSecret(config.codexApiKey);
    this.addSecret(config.anthropicApiKey);
    this.addSecret(config.geminiApiKey);
    this.addSecret(config.agentRunnerAuthToken);
    this.addSecret(config.opsMcpAuthToken);
    this.addSecret(config.notifyWebhookUrl);

    if (Array.isArray(config.downstreamMcps)) {
      this.collectFromDownstreamMcps(config.downstreamMcps, this.envRef);
    }
    if (config.downstreamMcpsJson) {
      try {
        const servers = extractDownstreamServers(JSON.parse(config.downstreamMcpsJson));
        if (servers.length > 0) {
          this.collectFromDownstreamMcps(servers, this.envRef);
        }
      } catch {
        // Ignore malformed JSON during best-effort scrubber collection
      }
    }
    if (config.downstreamMcpsFile) {
      try {
        if (fs.existsSync(config.downstreamMcpsFile)) {
          const servers = extractDownstreamServers(
            JSON.parse(fs.readFileSync(config.downstreamMcpsFile, 'utf8')),
          );
          if (servers.length > 0) {
            this.collectFromDownstreamMcps(servers, this.envRef);
          }
        }
      } catch {
        // Ignore unreadable/malformed file during best-effort scrubber collection
      }
    }
  }

  scrub(input: string): string {
    if (!input) return input;
    let output = input;

    for (const secret of this.sortedSecrets) {
      if (output.includes(secret)) {
        output = output.split(secret).join(REDACTED_PLACEHOLDER);
      }
    }

    for (const rule of REGEX_SCRUB_RULES) {
      output = output.replace(rule.pattern, rule.replacement);
    }

    return output;
  }

  scrubObject<T>(value: T, seen = new WeakSet<object>()): T {
    if (typeof value === 'string') {
      return this.scrub(value) as T;
    }
    if (value === null || typeof value !== 'object') {
      return value;
    }
    if (seen.has(value as object)) {
      return value;
    }
    seen.add(value as object);

    if (Array.isArray(value)) {
      return value.map((item) => this.scrubObject(item, seen)) as T;
    }

    if (value instanceof Date || value instanceof RegExp || Buffer.isBuffer(value)) {
      return value;
    }

    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      result[k] = this.scrubObject(v, seen);
    }
    return result as T;
  }
}

export function createSecretScrubber(
  config?: Partial<GatewayConfig>,
  env: Record<string, string | undefined> = process.env,
): SecretScrubber {
  return new SecretScrubber({ config, env });
}
