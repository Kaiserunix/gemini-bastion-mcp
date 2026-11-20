import type { GatewayConfig, JobRecord, ScrubberLike } from '../types.js';
import { createSecretScrubber } from '../utils/secretScrubber.js';

export interface WebhookNotifyResult {
  sent: boolean;
  skipped?: boolean;
  statusCode?: number;
  error?: string;
}

export interface WebhookNotifyOptions {
  scrubber?: ScrubberLike;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
  logger?: Pick<Console, 'warn' | 'error'>;
}

const DEFAULT_WEBHOOK_TIMEOUT_MS = 5000;

type WebhookVendor = 'slack' | 'discord' | 'feishu' | 'generic';

function detectWebhookVendor(urlStr: string): WebhookVendor {
  try {
    const parsed = new URL(urlStr);
    const host = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    if (host.includes('slack.com')) return 'slack';
    if (host.includes('discord.com') || host.includes('discordapp.com')) return 'discord';
    if (
      host.includes('feishu.cn') ||
      host.includes('larksuite.com') ||
      pathname.includes('/bot/v2/hook/')
    ) {
      return 'feishu';
    }
  } catch {
    // Fallback to generic
  }
  return 'generic';
}

function buildHumanSummary(event: string, payload: Record<string, unknown>): string {
  if (event === 'job.finished') {
    const jobId = String(payload.job_id ?? '');
    const slug = String(payload.workspace_slug ?? '');
    const runner = String(payload.runner_type ?? '');
    const status = String(payload.status ?? '');
    const summary = payload.summary ? `\nSummary: ${String(payload.summary)}` : '';
    const err = payload.error_message ? `\nError: ${String(payload.error_message)}` : '';
    return `[omni-mcp-gateway] Job ${jobId} (${runner} @ ${slug}) -> ${status}${summary}${err}`;
  }
  const detail = payload.summary ? `: ${String(payload.summary)}` : '';
  return `[omni-mcp-gateway] ${event}${detail}`;
}

function formatVendorPayload(
  urlStr: string,
  event: string,
  scrubbedPayload: Record<string, unknown>,
): Record<string, unknown> {
  const vendor = detectWebhookVendor(urlStr);
  const text = buildHumanSummary(event, scrubbedPayload);

  switch (vendor) {
    case 'slack':
      return {
        text,
        ...scrubbedPayload,
      };
    case 'discord':
      return {
        content: text.slice(0, 1900),
      };
    case 'feishu':
      return {
        msg_type: 'text',
        content: {
          text,
        },
      };
    case 'generic':
    default:
      return {
        event,
        timestamp: new Date().toISOString(),
        text,
        ...scrubbedPayload,
      };
  }
}

/**
 * Sends a scrubbed JSON webhook notification with a 5s timeout and non-fatal error handling.
 */
export async function sendWebhookNotification(
  config: Pick<GatewayConfig, 'notifyWebhookUrl'> & Partial<GatewayConfig>,
  event: string,
  payload: Record<string, unknown>,
  options: WebhookNotifyOptions = {},
): Promise<WebhookNotifyResult> {
  const webhookUrl = config.notifyWebhookUrl?.trim();
  if (!webhookUrl) {
    return { sent: false, skipped: true };
  }

  const scrubber = options.scrubber ?? createSecretScrubber(config);
  const fetchFn = options.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_WEBHOOK_TIMEOUT_MS;
  const logger = options.logger ?? console;

  const scrubbedPayload = scrubber.scrubObject(payload);
  const bodyObj = scrubber.scrubObject(formatVendorPayload(webhookUrl, event, scrubbedPayload));

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();

  try {
    const response = await fetchFn(webhookUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': 'omni-mcp-gateway/1.0',
      },
      body: JSON.stringify(bodyObj),
      signal: controller.signal,
    });

    if (!response.ok) {
      const msg = `Webhook responded with HTTP ${response.status}`;
      logger.warn(`[webhookNotifier] ${msg}`);
      return { sent: false, statusCode: response.status, error: msg };
    }

    return { sent: true, statusCode: response.status };
  } catch (err) {
    const rawMsg = err instanceof Error ? err.message : String(err);
    const safeMsg = scrubber.scrub(rawMsg);
    logger.warn(`[webhookNotifier] Non-fatal webhook delivery error: ${safeMsg}`);
    return { sent: false, error: safeMsg };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Sends a job completion/failure/cancellation/timeout summary to `NOTIFY_WEBHOOK_URL`.
 */
export async function notifyJobFinished(
  config: Pick<GatewayConfig, 'notifyWebhookUrl'> & Partial<GatewayConfig>,
  job: Pick<
    JobRecord,
    | 'job_id'
    | 'workspace_slug'
    | 'runner_type'
    | 'status'
    | 'command_or_objective'
    | 'codex_thread_id'
    | 'checkpoint_id'
    | 'token_usage'
    | 'final_report_text'
    | 'error_message'
    | 'created_at'
    | 'updated_at'
  >,
  options: WebhookNotifyOptions = {},
): Promise<WebhookNotifyResult> {
  const summarySnippet = job.final_report_text
    ? job.final_report_text.slice(0, 600)
    : undefined;

  return sendWebhookNotification(
    config,
    'job.finished',
    {
      job_id: job.job_id,
      workspace_slug: job.workspace_slug,
      runner_type: job.runner_type,
      status: job.status,
      command_or_objective: job.command_or_objective.slice(0, 300),
      codex_thread_id: job.codex_thread_id,
      checkpoint_id: job.checkpoint_id,
      token_usage: job.token_usage,
      summary: summarySnippet,
      error_message: job.error_message,
      duration_ms: Math.max(0, job.updated_at - job.created_at),
    },
    options,
  );
}
