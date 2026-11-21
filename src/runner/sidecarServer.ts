import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadConfig } from '../config.js';
import { AgentRunnerRegistry } from '../core/agentDrivers/index.js';
import { resolveWorkspaceRoot } from '../core/workspaceLock.js';
import type {
  AgentDriverName,
  AgentRunOptions,
  AgentRunner,
  CodexReasoningEffort,
  GatewayConfig,
  NodeEnv,
  ScrubberLike,
} from '../types.js';
import { createSecretScrubber } from '../utils/secretScrubber.js';

export interface RunnerSidecarServerOptions {
  authToken?: string;
  workspacesDir?: string;
  host?: string;
  port?: number;
  config?: GatewayConfig;
  runner?: AgentRunner;
  scrubber?: ScrubberLike;
}

export interface RunnerSidecarServerHandle {
  server: http.Server;
  port: number;
  url: string;
  close: () => Promise<void>;
}

const MIN_RUNNER_AUTH_TOKEN_LEN = 24;
const MAX_REQUEST_BODY_BYTES = 64 * 1024;
const PLACEHOLDER_TOKEN_PATTERN = /(?:replace-with|changeme|change-me|example|secret-here)/i;
const VALID_DRIVERS = new Set<AgentDriverName>(['codex', 'claude_code', 'gemini_cli', 'opencode']);

class PayloadTooLargeError extends Error {
  constructor() {
    super('Request body exceeds 64KB limit');
    this.name = 'PayloadTooLargeError';
  }
}

function sha256Digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

function verifyBearerHeader(authHeader: string | undefined, expectedToken: string): boolean {
  if (!authHeader) return false;
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match?.[1]) return false;
  return timingSafeEqual(sha256Digest(match[1].trim()), sha256Digest(expectedToken));
}

function sendJson(res: ServerResponse, statusCode: number, body: Record<string, unknown>): void {
  const payload = JSON.stringify(body);
  res.statusCode = statusCode;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  res.end(payload);
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > MAX_REQUEST_BODY_BYTES) {
      throw new PayloadTooLargeError();
    }
    chunks.push(buf);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw.trim()) return {};
  return JSON.parse(raw) as Record<string, unknown>;
}

function buildSidecarConfig(
  workspacesDirOverride?: string,
  env: Record<string, string | undefined> = process.env,
): GatewayConfig {
  const rawNodeEnv = env.NODE_ENV;
  const nodeEnv: NodeEnv =
    rawNodeEnv === 'production' || rawNodeEnv === 'test' || rawNodeEnv === 'development'
      ? rawNodeEnv
      : 'development';

  const workspacesDir = path.resolve(workspacesDirOverride ?? env.WORKSPACES_DIR ?? '/workspaces');
  const dataDir = path.resolve(env.DATA_DIR ?? path.join(os.tmpdir(), 'runner-data'));

  // Parse non-OAuth runner fields without triggering gateway OAuth/PUBLIC_DOMAIN startup checks
  const parsed = loadConfig({
    ...env,
    NODE_ENV: 'test',
    PUBLIC_DOMAIN: 'http://127.0.0.1:8788',
    OAUTH_SIGNING_SECRET: '',
    AGENT_RUNNER_URL: '',
    DATA_DIR: dataDir,
    WORKSPACES_DIR: workspacesDir,
  });

  return {
    ...parsed,
    nodeEnv,
    workspacesDir,
    agentRunnerUrl: undefined,
    agentRunnerAuthToken: undefined,
    sandboxUid: undefined,
    sandboxGid: undefined,
  };
}

/**
 * Creates and starts the standalone isolated-runner HTTP sidecar server.
 * Fails closed at startup if `AGENT_RUNNER_AUTH_TOKEN` is missing, shorter than 24 characters,
 * or uses a placeholder pattern in production.
 */
export async function createRunnerSidecarServer(
  options: RunnerSidecarServerOptions = {},
): Promise<RunnerSidecarServerHandle> {
  const authToken = (options.authToken ?? process.env.AGENT_RUNNER_AUTH_TOKEN ?? '').trim();
  const isProd = (options.config?.nodeEnv ?? process.env.NODE_ENV) === 'production';

  if (authToken.length < MIN_RUNNER_AUTH_TOKEN_LEN) {
    throw new Error(
      `Isolated runner sidecar requires AGENT_RUNNER_AUTH_TOKEN (>= ${MIN_RUNNER_AUTH_TOKEN_LEN} chars)`,
    );
  }
  if (isProd && PLACEHOLDER_TOKEN_PATTERN.test(authToken)) {
    throw new Error(
      'Isolated runner sidecar refuses placeholder AGENT_RUNNER_AUTH_TOKEN in production',
    );
  }

  const baseConfig = options.config ?? buildSidecarConfig(options.workspacesDir);
  const workspacesDir = options.workspacesDir ?? baseConfig.workspacesDir;
  const scrubber = options.scrubber ?? createSecretScrubber(baseConfig);

  // Sidecar never delegates back to itself and never invokes sudo from UID 1002
  const sidecarConfig: GatewayConfig = {
    ...baseConfig,
    workspacesDir,
    agentRunnerUrl: undefined,
    agentRunnerAuthToken: undefined,
    sandboxUid: undefined,
    sandboxGid: undefined,
  };

  const runner: AgentRunner =
    options.runner ??
    new AgentRunnerRegistry({
      config: sidecarConfig,
      scrubber,
      useRemoteSidecar: false,
    });

  const activeJobs = new Map<string, AbortController>();

  const server = http.createServer(async (req, res) => {
    const reqUrl = new URL(req.url ?? '/', 'http://127.0.0.1');
    const method = (req.method ?? 'GET').toUpperCase();

    if (method === 'GET' && reqUrl.pathname === '/healthz') {
      sendJson(res, 200, { ok: true, role: 'isolated-runner' });
      return;
    }

    if (!verifyBearerHeader(req.headers.authorization, authToken)) {
      sendJson(res, 401, { error: 'unauthorized', message: 'Invalid or missing bearer token' });
      return;
    }

    if (method === 'POST' && reqUrl.pathname.startsWith('/cancel/')) {
      let jobId: string;
      try {
        jobId = decodeURIComponent(reqUrl.pathname.slice('/cancel/'.length));
      } catch {
        sendJson(res, 400, { error: 'bad_request', message: 'Malformed jobId URI encoding' });
        return;
      }
      const controller = activeJobs.get(jobId);
      if (!controller) {
        sendJson(res, 200, { ok: true, jobId, cancelled: false });
        return;
      }
      controller.abort();
      sendJson(res, 200, { ok: true, jobId, cancelled: true });
      return;
    }

    if (method === 'POST' && reqUrl.pathname === '/run') {
      let body: Record<string, unknown>;
      try {
        body = await readJsonBody(req);
      } catch (err) {
        if (err instanceof PayloadTooLargeError) {
          sendJson(res, 413, {
            error: 'payload_too_large',
            message: err.message,
          });
          return;
        }
        sendJson(res, 400, {
          error: 'bad_request',
          message: scrubber.scrub(err instanceof Error ? err.message : String(err)),
        });
        return;
      }

      const jobId = typeof body.jobId === 'string' && body.jobId.trim() ? body.jobId.trim() : '';
      const workspaceSlug =
        typeof body.workspaceSlug === 'string' ? body.workspaceSlug.trim() : '';
      const mode = body.mode === 'write' ? 'write' : 'readonly';
      const objective = typeof body.objective === 'string' ? body.objective : '';
      const driverRaw = typeof body.driver === 'string' ? (body.driver as AgentDriverName) : undefined;
      const driver = driverRaw && VALID_DRIVERS.has(driverRaw) ? driverRaw : sidecarConfig.defaultAgentDriver;

      if (!jobId || !workspaceSlug || !objective) {
        sendJson(res, 400, {
          error: 'bad_request',
          message: 'jobId, workspaceSlug, and objective are required',
        });
        return;
      }

      let realWorkspaceRoot: string;
      try {
        ({ realWorkspaceRoot } = resolveWorkspaceRoot(workspacesDir, workspaceSlug));
        if (!fs.existsSync(realWorkspaceRoot)) {
          sendJson(res, 404, {
            error: 'workspace_not_found',
            message: `Workspace "${workspaceSlug}" does not exist`,
          });
          return;
        }
      } catch (err) {
        sendJson(res, 400, {
          error: 'invalid_workspace',
          message: scrubber.scrub(err instanceof Error ? err.message : String(err)),
        });
        return;
      }

      const controller = new AbortController();
      activeJobs.set(jobId, controller);

      const onClientClose = () => {
        if (!res.writableFinished) {
          controller.abort();
        }
      };
      res.on('close', onClientClose);

      res.statusCode = 200;
      res.setHeader('content-type', 'application/x-ndjson; charset=utf-8');
      res.setHeader('cache-control', 'no-store');

      const writePacket = (pkt: Record<string, unknown>) => {
        if (!res.writableEnded && !res.destroyed) {
          res.write(`${JSON.stringify(scrubber.scrubObject(pkt))}\n`);
        }
      };

      const runOptions: AgentRunOptions = {
        jobId,
        workspaceSlug,
        workspaceDir: realWorkspaceRoot,
        mode,
        objective,
        driver,
        resumeThreadId:
          typeof body.resumeThreadId === 'string' ? body.resumeThreadId : undefined,
        model: typeof body.model === 'string' ? body.model : undefined,
        reasoningEffort:
          typeof body.reasoningEffort === 'string'
            ? (body.reasoningEffort as CodexReasoningEffort)
            : undefined,
        maxDurationSec:
          typeof body.maxDurationSec === 'number' ? body.maxDurationSec : undefined,
        tokenBudget: typeof body.tokenBudget === 'number' ? body.tokenBudget : undefined,
        signal: controller.signal,
        onEvent: (event) => {
          writePacket({ type: 'event', event });
        },
      };

      try {
        const result = await runner.run(runOptions);
        if (result.threadId) {
          writePacket({ type: 'thread', threadId: result.threadId });
        }
        if (result.tokenUsage) {
          writePacket({ type: 'token_usage', tokenUsage: result.tokenUsage });
        }
        writePacket({ type: 'result', result });
      } catch (err) {
        const errMsg = scrubber.scrub(err instanceof Error ? err.message : String(err));
        writePacket({
          type: 'result',
          result: {
            status: controller.signal.aborted ? 'cancelled' : 'failed',
            threadId: null,
            finalReport: '',
            tokenUsage: null,
            errorMessage: errMsg,
          },
        });
      } finally {
        res.off('close', onClientClose);
        activeJobs.delete(jobId);
        if (!res.writableEnded) {
          res.end();
        }
      }
      return;
    }

    sendJson(res, 404, { error: 'not_found' });
  });

  const listenHost = options.host ?? process.env.AGENT_RUNNER_HOST ?? '0.0.0.0';
  const listenPort =
    options.port ?? Number(process.env.AGENT_RUNNER_PORT ?? process.env.PORT ?? 8788);

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => {
      server.off('listening', onListening);
      reject(err);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(listenPort, listenHost);
  });

  const addr = server.address();
  const boundPort = typeof addr === 'object' && addr ? addr.port : listenPort;
  const hostForUrl = listenHost === '0.0.0.0' ? '127.0.0.1' : listenHost;

  const close = async () => {
    for (const controller of activeJobs.values()) {
      controller.abort();
    }
    activeJobs.clear();
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  };

  return {
    server,
    port: boundPort,
    url: `http://${hostForUrl}:${boundPort}`,
    close,
  };
}

const isEntrypoint =
  typeof process.argv[1] === 'string' &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isEntrypoint) {
  createRunnerSidecarServer()
    .then((handle) => {
      console.log(`[isolated-runner] Listening on ${handle.url}`);
      const shutdown = async () => {
        await handle.close();
        process.exit(0);
      };
      process.on('SIGINT', () => void shutdown());
      process.on('SIGTERM', () => void shutdown());
    })
    .catch((err) => {
      console.error(`[isolated-runner] Failed to start: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    });
}
