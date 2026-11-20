import type { GatewayDatabase } from '../sqlite.js';
import type { JobEvent, JobRecord, JobRunnerType, JobStatus, TokenUsage } from '../../types.js';

interface JobRow {
  job_id: string;
  workspace_slug: string;
  runner_type: string;
  status: string;
  command_or_objective: string;
  codex_thread_id: string | null;
  checkpoint_id: string | null;
  events_json: string;
  token_usage_json: string | null;
  final_report_text: string | null;
  error_message: string | null;
  created_at: number;
  updated_at: number;
}

function mapJob(row: JobRow): JobRecord {
  return {
    job_id: row.job_id,
    workspace_slug: row.workspace_slug,
    runner_type: row.runner_type as JobRunnerType,
    status: row.status as JobStatus,
    command_or_objective: row.command_or_objective,
    codex_thread_id: row.codex_thread_id,
    checkpoint_id: row.checkpoint_id,
    events: JSON.parse(row.events_json) as JobEvent[],
    token_usage: row.token_usage_json ? (JSON.parse(row.token_usage_json) as TokenUsage) : null,
    final_report_text: row.final_report_text,
    error_message: row.error_message,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

export class JobRepository {
  constructor(private readonly db: GatewayDatabase) {}

  createJob(input: {
    job_id: string;
    workspace_slug: string;
    runner_type: JobRunnerType;
    status?: JobStatus;
    command_or_objective: string;
    codex_thread_id?: string | null;
    checkpoint_id?: string | null;
    events?: JobEvent[];
    token_usage?: TokenUsage | null;
    final_report_text?: string | null;
    error_message?: string | null;
    created_at?: number;
  }): JobRecord {
    const now = input.created_at ?? Date.now();
    const status: JobStatus = input.status ?? 'queued';
    const events = input.events ?? [];
    const tokenUsage = input.token_usage ?? null;

    this.db
      .prepare(
        `INSERT INTO jobs
         (job_id, workspace_slug, runner_type, status, command_or_objective, codex_thread_id, checkpoint_id, events_json, token_usage_json, final_report_text, error_message, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.job_id,
        input.workspace_slug,
        input.runner_type,
        status,
        input.command_or_objective,
        input.codex_thread_id ?? null,
        input.checkpoint_id ?? null,
        JSON.stringify(events),
        tokenUsage ? JSON.stringify(tokenUsage) : null,
        input.final_report_text ?? null,
        input.error_message ?? null,
        now,
        now,
      );

    return {
      job_id: input.job_id,
      workspace_slug: input.workspace_slug,
      runner_type: input.runner_type,
      status,
      command_or_objective: input.command_or_objective,
      codex_thread_id: input.codex_thread_id ?? null,
      checkpoint_id: input.checkpoint_id ?? null,
      events,
      token_usage: tokenUsage,
      final_report_text: input.final_report_text ?? null,
      error_message: input.error_message ?? null,
      created_at: now,
      updated_at: now,
    };
  }

  getJob(jobId: string): JobRecord | null {
    const row = this.db
      .prepare('SELECT * FROM jobs WHERE job_id = ?')
      .get(jobId) as JobRow | undefined;
    return row ? mapJob(row) : null;
  }

  listJobs(filter: { workspace_slug?: string; status?: JobStatus; limit?: number } = {}): JobRecord[] {
    const clauses: string[] = [];
    const params: Array<string | number> = [];

    if (filter.workspace_slug) {
      clauses.push('workspace_slug = ?');
      params.push(filter.workspace_slug);
    }
    if (filter.status) {
      clauses.push('status = ?');
      params.push(filter.status);
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = filter.limit ?? 50;
    params.push(limit);

    const rows = this.db
      .prepare(`SELECT * FROM jobs ${where} ORDER BY updated_at DESC LIMIT ?`)
      .all(...params) as JobRow[];
    return rows.map(mapJob);
  }

  countActiveJobs(): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS cnt FROM jobs WHERE status IN ('queued', 'running')")
      .get() as { cnt: number };
    return Number(row.cnt);
  }

  updateJob(
    jobId: string,
    patch: {
      status?: JobStatus;
      codex_thread_id?: string | null;
      checkpoint_id?: string | null;
      token_usage?: TokenUsage | null;
      final_report_text?: string | null;
      error_message?: string | null;
    },
  ): JobRecord | null {
    const existing = this.getJob(jobId);
    if (!existing) return null;

    const updatedAt = Date.now();
    const nextStatus = patch.status ?? existing.status;
    const nextThreadId =
      patch.codex_thread_id !== undefined ? patch.codex_thread_id : existing.codex_thread_id;
    const nextCheckpointId =
      patch.checkpoint_id !== undefined ? patch.checkpoint_id : existing.checkpoint_id;
    const nextTokenUsage =
      patch.token_usage !== undefined ? patch.token_usage : existing.token_usage;
    const nextFinalReport =
      patch.final_report_text !== undefined ? patch.final_report_text : existing.final_report_text;
    const nextError =
      patch.error_message !== undefined ? patch.error_message : existing.error_message;

    this.db
      .prepare(
        `UPDATE jobs
         SET status = ?, codex_thread_id = ?, checkpoint_id = ?, token_usage_json = ?, final_report_text = ?, error_message = ?, updated_at = ?
         WHERE job_id = ?`,
      )
      .run(
        nextStatus,
        nextThreadId,
        nextCheckpointId,
        nextTokenUsage ? JSON.stringify(nextTokenUsage) : null,
        nextFinalReport,
        nextError,
        updatedAt,
        jobId,
      );

    return {
      ...existing,
      status: nextStatus,
      codex_thread_id: nextThreadId,
      checkpoint_id: nextCheckpointId,
      token_usage: nextTokenUsage,
      final_report_text: nextFinalReport,
      error_message: nextError,
      updated_at: updatedAt,
    };
  }

  appendEvent(
    jobId: string,
    event: Omit<JobEvent, 'seq'> & { seq?: number },
    maxEvents = 250,
  ): JobEvent | null {
    return this.db.transaction(() => {
      const row = this.db
        .prepare('SELECT events_json FROM jobs WHERE job_id = ?')
        .get(jobId) as { events_json: string } | undefined;
      if (!row) return null;

      const events = JSON.parse(row.events_json) as JobEvent[];
      const nextSeq =
        event.seq ?? (events.length > 0 ? events[events.length - 1]!.seq + 1 : 1);
      const entry: JobEvent = {
        seq: nextSeq,
        ts: event.ts,
        type: event.type,
        message: event.message,
        ...(event.data !== undefined ? { data: event.data } : {}),
      };

      events.push(entry);
      const bounded = events.length > maxEvents ? events.slice(events.length - maxEvents) : events;
      const updatedAt = Date.now();

      this.db
        .prepare('UPDATE jobs SET events_json = ?, updated_at = ? WHERE job_id = ?')
        .run(JSON.stringify(bounded), updatedAt, jobId);

      return entry;
    })();
  }
}
