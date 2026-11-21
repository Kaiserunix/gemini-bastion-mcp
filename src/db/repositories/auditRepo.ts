import type { AuditLogger } from '../../auth/store.js';
import type { GatewayDatabase } from '../sqlite.js';
import type { AuditEventPublisher } from '../../security/auditSink.js';
import type { AuditLogRecord, ScrubberLike } from '../../types.js';

interface AuditLogRow {
  id: number;
  actor: string;
  action: string;
  target: string;
  status: string;
  details_json: string;
  created_at: number;
}

export interface AuditRepositoryOptions {
  scrubber?: ScrubberLike;
  publisher?: AuditEventPublisher;
}

function mapAuditLog(row: AuditLogRow): AuditLogRecord {
  return {
    id: row.id,
    actor: row.actor,
    action: row.action,
    target: row.target,
    status: row.status,
    details: JSON.parse(row.details_json) as Record<string, unknown>,
    created_at: row.created_at,
  };
}

export class AuditRepository implements AuditLogger {
  private scrubber?: ScrubberLike;
  private publisher?: AuditEventPublisher;
  private suppressPublisherForward = false;

  constructor(
    private readonly db: GatewayDatabase,
    options: AuditRepositoryOptions = {},
  ) {
    this.scrubber = options.scrubber;
    this.publisher = options.publisher;
  }

  configure(options: AuditRepositoryOptions): void {
    if (options.scrubber !== undefined) {
      this.scrubber = options.scrubber;
    }
    if (options.publisher !== undefined) {
      this.publisher = options.publisher;
    }
  }

  isForwardingToPublisher(): boolean {
    return this.suppressPublisherForward;
  }

  /**
   * Inserts a scrubbed audit record into SQLite without re-emitting to `publisher`
   * (used by `SqliteAuditSink` when `StructuredAuditLogger` originates an event).
   */
  recordDirect(input: {
    actor: string;
    action: string;
    target: string;
    status: string;
    details?: Record<string, unknown>;
    created_at?: number;
  }): AuditLogRecord {
    const createdAt = input.created_at ?? Date.now();
    const actor = this.scrubber ? this.scrubber.scrub(input.actor) : input.actor;
    const action = this.scrubber ? this.scrubber.scrub(input.action) : input.action;
    const target = this.scrubber ? this.scrubber.scrub(input.target) : input.target;
    const status = this.scrubber ? this.scrubber.scrub(input.status) : input.status;
    const rawDetails = input.details ?? {};
    const details = this.scrubber ? this.scrubber.scrubObject(rawDetails) : rawDetails;

    const info = this.db
      .prepare(
        `INSERT INTO audit_logs (actor, action, target, status, details_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(actor, action, target, status, JSON.stringify(details), createdAt);

    return {
      id: Number(info.lastInsertRowid),
      actor,
      action,
      target,
      status,
      details,
      created_at: createdAt,
    };
  }

  record(input: {
    actor: string;
    action: string;
    target: string;
    status: string;
    details?: Record<string, unknown>;
    created_at?: number;
  }): AuditLogRecord {
    const saved = this.recordDirect(input);

    if (this.publisher && !this.suppressPublisherForward) {
      this.suppressPublisherForward = true;
      try {
        this.publisher.emit({
          actor: saved.actor,
          action: saved.action,
          target: saved.target,
          status: saved.status,
          details: saved.details,
          created_at: saved.created_at,
        });
      } finally {
        this.suppressPublisherForward = false;
      }
    }

    return saved;
  }

  list(
    filter: {
      actor?: string;
      action?: string;
      target?: string;
      status?: string;
      limit?: number;
      offset?: number;
    } = {},
  ): AuditLogRecord[] {
    const clauses: string[] = [];
    const params: Array<string | number> = [];

    if (filter.actor) {
      clauses.push('actor = ?');
      params.push(filter.actor);
    }
    if (filter.action) {
      clauses.push('action = ?');
      params.push(filter.action);
    }
    if (filter.target) {
      clauses.push('target = ?');
      params.push(filter.target);
    }
    if (filter.status) {
      clauses.push('status = ?');
      params.push(filter.status);
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = filter.limit ?? 100;
    const offset = filter.offset ?? 0;
    params.push(limit, offset);

    const rows = this.db
      .prepare(`SELECT * FROM audit_logs ${where} ORDER BY id DESC LIMIT ? OFFSET ?`)
      .all(...params) as AuditLogRow[];
    return rows.map(mapAuditLog);
  }
}
