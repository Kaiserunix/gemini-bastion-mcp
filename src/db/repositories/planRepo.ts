import type { ClaimPlanResult, PlanStore } from '../../policy/types.js';
import type { GatewayDatabase } from '../sqlite.js';
import type { MutationPlanRecord, MutationPlanStatus } from '../../types.js';

export type { ClaimPlanResult };

interface MutationPlanRow {
  plan_id: string;
  target_service: string;
  summary_diff_text: string;
  payload_json: string;
  rollback_payload_json: string | null;
  status: string;
  expires_at: number;
  created_at: number;
  executed_at: number | null;
}

function mapPlan(row: MutationPlanRow): MutationPlanRecord {
  return {
    plan_id: row.plan_id,
    target_service: row.target_service,
    summary_diff_text: row.summary_diff_text,
    payload: JSON.parse(row.payload_json) as Record<string, unknown>,
    rollback_payload: row.rollback_payload_json
      ? (JSON.parse(row.rollback_payload_json) as Record<string, unknown>)
      : null,
    status: row.status as MutationPlanStatus,
    expires_at: row.expires_at,
    created_at: row.created_at,
    executed_at: row.executed_at,
  };
}

export class PlanRepository implements PlanStore {
  constructor(private readonly db: GatewayDatabase) {}

  createPlan(input: {
    plan_id: string;
    target_service: string;
    summary_diff_text: string;
    payload: Record<string, unknown>;
    rollback_payload?: Record<string, unknown> | null;
    status?: MutationPlanStatus;
    expires_at: number;
    created_at?: number;
  }): MutationPlanRecord {
    const createdAt = input.created_at ?? Date.now();
    const status: MutationPlanStatus = input.status ?? 'staged';
    const rollbackPayload = input.rollback_payload ?? null;

    this.db
      .prepare(
        `INSERT INTO mutation_plans
         (plan_id, target_service, summary_diff_text, payload_json, rollback_payload_json, status, expires_at, created_at, executed_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(
        input.plan_id,
        input.target_service,
        input.summary_diff_text,
        JSON.stringify(input.payload),
        rollbackPayload ? JSON.stringify(rollbackPayload) : null,
        status,
        input.expires_at,
        createdAt,
      );

    return {
      plan_id: input.plan_id,
      target_service: input.target_service,
      summary_diff_text: input.summary_diff_text,
      payload: input.payload,
      rollback_payload: rollbackPayload,
      status,
      expires_at: input.expires_at,
      created_at: createdAt,
      executed_at: null,
    };
  }

  getPlan(planId: string): MutationPlanRecord | null {
    const row = this.db
      .prepare('SELECT * FROM mutation_plans WHERE plan_id = ?')
      .get(planId) as MutationPlanRow | undefined;
    return row ? mapPlan(row) : null;
  }

  listPlans(
    filter: { status?: MutationPlanStatus; target_service?: string; limit?: number } = {},
  ): MutationPlanRecord[] {
    const clauses: string[] = [];
    const params: Array<string | number> = [];

    if (filter.status) {
      clauses.push('status = ?');
      params.push(filter.status);
    }
    if (filter.target_service) {
      clauses.push('target_service = ?');
      params.push(filter.target_service);
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const limit = filter.limit ?? 50;
    params.push(limit);

    const rows = this.db
      .prepare(`SELECT * FROM mutation_plans ${where} ORDER BY created_at DESC LIMIT ?`)
      .all(...params) as MutationPlanRow[];
    return rows.map(mapPlan);
  }

  updatePlanStatus(
    planId: string,
    status: MutationPlanStatus,
    executedAt?: number | null,
  ): MutationPlanRecord | null {
    const existing = this.getPlan(planId);
    if (!existing) return null;

    const nextExecutedAt = executedAt !== undefined ? executedAt : existing.executed_at;
    this.db
      .prepare('UPDATE mutation_plans SET status = ?, executed_at = ? WHERE plan_id = ?')
      .run(status, nextExecutedAt, planId);

    return {
      ...existing,
      status,
      executed_at: nextExecutedAt,
    };
  }

  updatePlanRollbackPayload(
    planId: string,
    rollbackPayload: Record<string, unknown> | null,
  ): MutationPlanRecord | null {
    const existing = this.getPlan(planId);
    if (!existing) return null;

    this.db
      .prepare('UPDATE mutation_plans SET rollback_payload_json = ? WHERE plan_id = ?')
      .run(rollbackPayload ? JSON.stringify(rollbackPayload) : null, planId);

    return {
      ...existing,
      rollback_payload: rollbackPayload,
    };
  }

  /**
   * Atomically validates that a staged plan has not expired and transitions it to executing.
   */
  claimForExecution(planId: string, now = Date.now()): ClaimPlanResult {
    return this.db.transaction((): ClaimPlanResult => {
      const row = this.db
        .prepare('SELECT * FROM mutation_plans WHERE plan_id = ?')
        .get(planId) as MutationPlanRow | undefined;
      if (!row) {
        return { ok: false, reason: 'not_found' };
      }

      const plan = mapPlan(row);
      if (plan.status !== 'staged') {
        return { ok: false, reason: 'invalid_status', plan };
      }

      if (plan.expires_at <= now) {
        this.db
          .prepare('UPDATE mutation_plans SET status = ? WHERE plan_id = ? AND status = ?')
          .run('expired', planId, 'staged');
        return { ok: false, reason: 'expired', plan: { ...plan, status: 'expired' } };
      }

      const info = this.db
        .prepare('UPDATE mutation_plans SET status = ? WHERE plan_id = ? AND status = ?')
        .run('executing', planId, 'staged');
      if (info.changes === 0) {
        return { ok: false, reason: 'invalid_status', plan };
      }

      return {
        ok: true,
        plan: { ...plan, status: 'executing' },
      };
    })();
  }

  /**
   * Atomically claims an executed plan for rollback by transitioning executed -> rolling_back.
   */
  claimForRollback(planId: string): ClaimPlanResult {
    return this.db.transaction((): ClaimPlanResult => {
      const row = this.db
        .prepare('SELECT * FROM mutation_plans WHERE plan_id = ?')
        .get(planId) as MutationPlanRow | undefined;
      if (!row) {
        return { ok: false, reason: 'not_found' };
      }

      const plan = mapPlan(row);
      if (plan.status !== 'executed') {
        return { ok: false, reason: 'invalid_status', plan };
      }

      const info = this.db
        .prepare('UPDATE mutation_plans SET status = ? WHERE plan_id = ? AND status = ?')
        .run('rolling_back', planId, 'executed');
      if (info.changes === 0) {
        return { ok: false, reason: 'invalid_status', plan };
      }

      return {
        ok: true,
        plan: { ...plan, status: 'rolling_back' },
      };
    })();
  }

  countActiveStagedPlans(now = Date.now()): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS cnt FROM mutation_plans WHERE status = 'staged' AND expires_at > ?")
      .get(now) as { cnt: number };
    return Number(row.cnt);
  }

  expireStalePlans(now = Date.now()): number {
    const info = this.db
      .prepare("UPDATE mutation_plans SET status = 'expired' WHERE status = 'staged' AND expires_at <= ?")
      .run(now);
    return info.changes;
  }
}
