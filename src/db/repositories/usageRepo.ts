import type { GatewayDatabase } from '../sqlite.js';
import type {
  AgentTokenWindowSummary,
  HourlyUsageBucket,
  ToolUsageBreakdown,
  UsageSummary,
  UsageWindowSummary,
} from '../../types.js';

const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

/**
 * Estimates token count using a lightweight bilingual heuristic (~4 ASCII chars/token, ~1.5 tokens/non-ASCII char).
 * Never persists raw prompt or response text.
 */
export function estimateTokens(text: string): number {
  if (!text) return 0;
  let asciiChars = 0;
  let nonAsciiChars = 0;
  for (const ch of text) {
    if (ch.codePointAt(0)! <= 0x7f) {
      asciiChars += 1;
    } else {
      nonAsciiChars += 1;
    }
  }
  return Math.ceil(asciiChars / 4 + nonAsciiChars * 1.5);
}

export interface RecordToolCallInput {
  toolName: string;
  clientId?: string | null;
  status: 'ok' | 'error';
  inputBytes: number;
  outputBytes: number;
  estInputTokens: number;
  estOutputTokens: number;
  durationMs: number;
  createdAt?: number;
}

interface WindowAggRow {
  calls: number | null;
  errors: number | null;
  input_bytes: number | null;
  output_bytes: number | null;
  est_input_tokens: number | null;
  est_output_tokens: number | null;
  total_duration_ms: number | null;
  last_call_at: number | null;
}

interface ToolBreakdownRow {
  tool_name: string;
  calls_24h: number | null;
  calls_30d: number | null;
  errors_30d: number | null;
  est_total_tokens_30d: number | null;
  avg_duration_ms_30d: number | null;
}

interface HourlyAggRow {
  bucket_idx: number;
  calls: number | null;
  est_total_tokens: number | null;
}

interface JobTokenRow {
  token_usage_json: string;
  updated_at: number;
}

function clampInt(val: number): number {
  if (!Number.isFinite(val)) return 0;
  return Math.max(0, Math.round(val));
}

function emptyAgentSummary(): AgentTokenWindowSummary {
  return {
    jobsCount: 0,
    inputTokens: 0,
    cachedInputTokens: 0,
    outputTokens: 0,
    totalTokens: 0,
  };
}

function addAgentUsage(
  target: AgentTokenWindowSummary,
  inputTokens: number,
  cachedInputTokens: number,
  outputTokens: number,
  totalTokens: number,
): void {
  target.jobsCount += 1;
  target.inputTokens += inputTokens;
  target.cachedInputTokens += cachedInputTokens;
  target.outputTokens += outputTokens;
  target.totalTokens += totalTokens;
}

function mapWindowRow(row: WindowAggRow | undefined): UsageWindowSummary {
  const calls = Number(row?.calls ?? 0);
  const errors = Number(row?.errors ?? 0);
  const inputBytes = Number(row?.input_bytes ?? 0);
  const outputBytes = Number(row?.output_bytes ?? 0);
  const estInputTokens = Number(row?.est_input_tokens ?? 0);
  const estOutputTokens = Number(row?.est_output_tokens ?? 0);
  const totalDurationMs = Number(row?.total_duration_ms ?? 0);
  const lastCallAt = row?.last_call_at !== null && row?.last_call_at !== undefined
    ? Number(row.last_call_at)
    : null;

  return {
    calls,
    errors,
    inputBytes,
    outputBytes,
    estInputTokens,
    estOutputTokens,
    estTotalTokens: estInputTokens + estOutputTokens,
    avgDurationMs: calls > 0 ? Math.round(totalDurationMs / calls) : 0,
    lastCallAt,
  };
}

export class UsageRepository {
  constructor(private readonly db: GatewayDatabase) {}

  recordToolCall(input: RecordToolCallInput): void {
    const createdAt = input.createdAt ?? Date.now();
    this.db
      .prepare(
        `INSERT INTO mcp_usage_events
         (tool_name, client_id, status, input_bytes, output_bytes, est_input_tokens, est_output_tokens, duration_ms, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.toolName,
        input.clientId ?? null,
        input.status === 'error' ? 'error' : 'ok',
        clampInt(input.inputBytes),
        clampInt(input.outputBytes),
        clampInt(input.estInputTokens),
        clampInt(input.estOutputTokens),
        clampInt(input.durationMs),
        createdAt,
      );
  }

  private queryWindow(cutoffMs: number | null, now: number): UsageWindowSummary {
    const row = (
      cutoffMs !== null
        ? this.db
            .prepare(
              `SELECT
                 COUNT(*) AS calls,
                 SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors,
                 SUM(input_bytes) AS input_bytes,
                 SUM(output_bytes) AS output_bytes,
                 SUM(est_input_tokens) AS est_input_tokens,
                 SUM(est_output_tokens) AS est_output_tokens,
                 SUM(duration_ms) AS total_duration_ms,
                 MAX(created_at) AS last_call_at
               FROM mcp_usage_events
               WHERE created_at >= ? AND created_at <= ?`,
            )
            .get(cutoffMs, now)
        : this.db
            .prepare(
              `SELECT
                 COUNT(*) AS calls,
                 SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors,
                 SUM(input_bytes) AS input_bytes,
                 SUM(output_bytes) AS output_bytes,
                 SUM(est_input_tokens) AS est_input_tokens,
                 SUM(est_output_tokens) AS est_output_tokens,
                 SUM(duration_ms) AS total_duration_ms,
                 MAX(created_at) AS last_call_at
               FROM mcp_usage_events
               WHERE created_at <= ?`,
            )
            .get(now)
    ) as WindowAggRow | undefined;

    return mapWindowRow(row);
  }

  getUsageSummary(now = Date.now()): UsageSummary {
    const c1h = now - HOUR_MS;
    const c3h = now - 3 * HOUR_MS;
    const c24h = now - DAY_MS;
    const c7d = now - 7 * DAY_MS;
    const c30d = now - 30 * DAY_MS;

    const last1h = this.queryWindow(c1h, now);
    const last3h = this.queryWindow(c3h, now);
    const last24h = this.queryWindow(c24h, now);
    const last7d = this.queryWindow(c7d, now);
    const last30d = this.queryWindow(c30d, now);
    const allTime = this.queryWindow(null, now);

    const toolRows = this.db
      .prepare(
        `SELECT
           tool_name,
           SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) AS calls_24h,
           COUNT(*) AS calls_30d,
           SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS errors_30d,
           SUM(est_input_tokens + est_output_tokens) AS est_total_tokens_30d,
           ROUND(AVG(duration_ms)) AS avg_duration_ms_30d
         FROM mcp_usage_events
         WHERE created_at >= ? AND created_at <= ?
         GROUP BY tool_name
         ORDER BY calls_30d DESC, tool_name ASC`,
      )
      .all(c24h, c30d, now) as ToolBreakdownRow[];

    const byTool: ToolUsageBreakdown[] = toolRows.map((row) => ({
      toolName: row.tool_name,
      calls24h: Number(row.calls_24h ?? 0),
      calls30d: Number(row.calls_30d ?? 0),
      errors30d: Number(row.errors_30d ?? 0),
      estTotalTokens30d: Number(row.est_total_tokens_30d ?? 0),
      avgDurationMs30d: Number(row.avg_duration_ms_30d ?? 0),
    }));

    const currentHourStart = Math.floor(now / HOUR_MS) * HOUR_MS;
    const oldestHourStart = currentHourStart - 23 * HOUR_MS;
    const hourlyEnd = currentHourStart + HOUR_MS;

    const hourlyRows = this.db
      .prepare(
        `SELECT
           CAST((created_at - ?) / ? AS INTEGER) AS bucket_idx,
           COUNT(*) AS calls,
           SUM(est_input_tokens + est_output_tokens) AS est_total_tokens
         FROM mcp_usage_events
         WHERE created_at >= ? AND created_at < ? AND created_at <= ?
         GROUP BY bucket_idx`,
      )
      .all(oldestHourStart, HOUR_MS, oldestHourStart, hourlyEnd, now) as HourlyAggRow[];

    const hourlyMap = new Map<number, { calls: number; estTotalTokens: number }>();
    for (const row of hourlyRows) {
      hourlyMap.set(Number(row.bucket_idx), {
        calls: Number(row.calls ?? 0),
        estTotalTokens: Number(row.est_total_tokens ?? 0),
      });
    }

    const hourly24h: HourlyUsageBucket[] = [];
    for (let i = 0; i < 24; i += 1) {
      const bucket = hourlyMap.get(i);
      hourly24h.push({
        hourStartMs: oldestHourStart + i * HOUR_MS,
        calls: bucket?.calls ?? 0,
        estTotalTokens: bucket?.estTotalTokens ?? 0,
      });
    }

    const agent24h = emptyAgentSummary();
    const agent7d = emptyAgentSummary();
    const agent30d = emptyAgentSummary();
    const agentAll = emptyAgentSummary();

    const jobRows = this.db
      .prepare(
        'SELECT token_usage_json, updated_at FROM jobs WHERE token_usage_json IS NOT NULL AND updated_at <= ?',
      )
      .all(now) as JobTokenRow[];

    for (const row of jobRows) {
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(row.token_usage_json) as Record<string, unknown>;
      } catch {
        continue;
      }
      if (!parsed || typeof parsed !== 'object') continue;

      const inputTokens = clampInt(Number(parsed.input_tokens ?? 0));
      const cachedInputTokens = clampInt(Number(parsed.cached_input_tokens ?? 0));
      const outputTokens = clampInt(Number(parsed.output_tokens ?? 0));
      const totalTokens = clampInt(
        Number(parsed.total_tokens ?? inputTokens + outputTokens),
      );

      addAgentUsage(agentAll, inputTokens, cachedInputTokens, outputTokens, totalTokens);
      if (row.updated_at >= c30d) {
        addAgentUsage(agent30d, inputTokens, cachedInputTokens, outputTokens, totalTokens);
      }
      if (row.updated_at >= c7d) {
        addAgentUsage(agent7d, inputTokens, cachedInputTokens, outputTokens, totalTokens);
      }
      if (row.updated_at >= c24h) {
        addAgentUsage(agent24h, inputTokens, cachedInputTokens, outputTokens, totalTokens);
      }
    }

    return {
      generatedAt: now,
      last1h,
      last3h,
      last24h,
      last7d,
      last30d,
      allTime,
      byTool,
      hourly24h,
      agentTokens: {
        last24h: agent24h,
        last7d: agent7d,
        last30d: agent30d,
        allTime: agentAll,
      },
    };
  }

  purgeOlderThan(cutoffMs: number): number {
    const info = this.db
      .prepare('DELETE FROM mcp_usage_events WHERE created_at < ?')
      .run(cutoffMs);
    return info.changes;
  }
}
