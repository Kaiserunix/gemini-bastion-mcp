import type { AuditLogger } from '../../auth/store.js';
import type { GatewayDatabase } from '../sqlite.js';
import type { AuditLogRecord } from '../../types.js';

interface AuditLogRow {
  id: number;
  actor: string;
  action: string;
  target: string;
  status: string;
  details_json: string;
  created_at: number;
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
  constructor(private readonly db: GatewayDatabase) {}

  record(input: {
    actor: string;
    action: string;
    target: string;
    status: string;
    details?: Record<string, unknown>;
    created_at?: number;
  }): AuditLogRecord {
    const createdAt = input.created_at ?? Date.now();
    const details = input.details ?? {};
    const info = this.db
      .prepare(
        `INSERT INTO audit_logs (actor, action, target, status, details_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        input.actor,
        input.action,
        input.target,
        input.status,
        JSON.stringify(details),
        createdAt,
      );

    return {
      id: Number(info.lastInsertRowid),
      actor: input.actor,
      action: input.action,
      target: input.target,
      status: input.status,
      details,
      created_at: createdAt,
    };
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
