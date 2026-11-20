import type { AuditLogger } from '../auth/store.js';
import type {
  DownstreamMcpServerConfig,
  MutationPlanRecord,
  MutationPlanStatus,
  ScrubberLike,
} from '../types.js';
import { SecretScrubber } from '../utils/secretScrubber.js';
import type {
  ApprovalGatePolicy,
  ClaimPlanResult,
  DownstreamToolClassification,
  DownstreamToolPhase,
  MutationTargetAdapter,
  PlanStore,
  PolicyDecision,
  PolicyDenyCode,
  RequiredMcpScope,
} from './types.js';

const DEFAULT_PROTECTED_BRANCHES = ['main', 'master'] as const;

export class ApprovalGatePolicyError extends Error {
  constructor(
    message: string,
    public readonly code: PolicyDenyCode,
  ) {
    super(message);
    this.name = 'ApprovalGatePolicyError';
  }
}

export interface DefaultApprovalGatePolicyOptions {
  protectedBranches?: readonly string[];
}

function normalizeBranch(branch: string): string {
  return branch.trim().replace(/^refs\/heads\//, '');
}

/**
 * Default fail-closed Approval-Gate Policy Engine.
 * All policy checks are pure, deterministic, and default-deny on unknown/unlisted states.
 */
export class DefaultApprovalGatePolicy implements ApprovalGatePolicy {
  private readonly protectedBranches: Set<string>;

  constructor(options: DefaultApprovalGatePolicyOptions = {}) {
    const names = options.protectedBranches ?? DEFAULT_PROTECTED_BRANCHES;
    this.protectedBranches = new Set(names.map((b) => normalizeBranch(b).toLowerCase()));
  }

  evaluateScope(scopes: readonly string[], required: RequiredMcpScope): PolicyDecision {
    if (scopes.includes('mcp:tools') || scopes.includes('mcp:write')) {
      return { allowed: true };
    }
    if (required === 'read' && scopes.includes('mcp:read')) {
      return { allowed: true };
    }
    return {
      allowed: false,
      code: 'INSUFFICIENT_SCOPE',
      reason: `"${required}" operation requires ${required === 'read' ? '"mcp:read", "mcp:tools", or "mcp:write"' : '"mcp:tools" or "mcp:write"'} scope (granted: ${scopes.join(' ') || 'none'}).`,
    };
  }

  evaluateProtectedBranch(
    branchName: string,
    defaultBranch?: string,
    baseBranch?: string,
  ): PolicyDecision {
    const normalized = normalizeBranch(branchName);
    if (!normalized) {
      return {
        allowed: false,
        code: 'INVALID_BRANCH_NAME',
        reason: 'Branch name must not be empty.',
      };
    }

    if (
      /\s/.test(normalized) ||
      normalized.includes('..') ||
      normalized.startsWith('-') ||
      normalized.toUpperCase() === 'HEAD'
    ) {
      return {
        allowed: false,
        code: 'INVALID_BRANCH_NAME',
        reason: `Invalid feature branch name: "${normalized}"`,
      };
    }

    const lower = normalized.toLowerCase();
    if (this.protectedBranches.has(lower)) {
      return {
        allowed: false,
        code: 'PROTECTED_BRANCH',
        reason: `Direct push to "${normalized}" is strictly blocked (is a protected default branch). Use a feature branch instead.`,
      };
    }

    if (defaultBranch) {
      const normDefault = normalizeBranch(defaultBranch);
      if (lower === normDefault.toLowerCase()) {
        return {
          allowed: false,
          code: 'PROTECTED_BRANCH',
          reason: `Direct push to "${normalized}" is strictly blocked (matches protected/default branch "${defaultBranch}"). Use a feature branch instead.`,
        };
      }
    }

    if (baseBranch) {
      const normBase = normalizeBranch(baseBranch);
      if (lower === normBase.toLowerCase()) {
        return {
          allowed: false,
          code: 'PROTECTED_BRANCH',
          reason: `Direct push to "${normalized}" is strictly blocked (matches protected/default branch "${baseBranch}"). Use a feature branch instead.`,
        };
      }
    }

    return { allowed: true };
  }

  classifyDownstreamTool(
    server: DownstreamMcpServerConfig,
    toolName: string,
  ): DownstreamToolClassification {
    if (server.deniedTools.includes(toolName)) {
      return 'denied';
    }
    if (server.readonlyTools.includes(toolName)) {
      return 'readonly';
    }
    if (server.mutatingTools.includes(toolName)) {
      return 'mutating';
    }
    return 'unlisted';
  }

  evaluateDownstreamTool(
    server: DownstreamMcpServerConfig,
    toolName: string,
    phase: DownstreamToolPhase,
  ): PolicyDecision {
    const classification = this.classifyDownstreamTool(server, toolName);

    if (classification === 'denied') {
      return {
        allowed: false,
        code: 'DOWNSTREAM_DENIED',
        reason: `Tool "${toolName}" on "${server.id}" is explicitly denied by policy.`,
      };
    }

    if (phase === 'inspect') {
      if (classification === 'readonly') {
        return { allowed: true };
      }
      if (classification === 'mutating') {
        return {
          allowed: false,
          code: 'DOWNSTREAM_PHASE_MISMATCH',
          reason: `Tool "${toolName}" on "${server.id}" is classified as mutating and must be staged via stage_mutation_plan.`,
        };
      }
      return {
        allowed: false,
        code: 'DOWNSTREAM_UNLISTED',
        reason: `Tool "${toolName}" on "${server.id}" is not in readonlyTools (default-deny).`,
      };
    }

    // phase === 'stage' || phase === 'execute'
    if (classification === 'mutating') {
      return { allowed: true };
    }
    if (classification === 'readonly') {
      return {
        allowed: false,
        code: 'DOWNSTREAM_PHASE_MISMATCH',
        reason: `Tool "${toolName}" on "${server.id}" is readonly and should be called directly via infra_inspect.`,
      };
    }
    return {
      allowed: false,
      code: 'DOWNSTREAM_UNLISTED',
      reason:
        phase === 'execute'
          ? `Tool "${toolName}" on "${server.id}" is no longer permitted in mutatingTools.`
          : `Tool "${toolName}" on "${server.id}" is not listed in mutatingTools (default-deny).`,
    };
  }

  evaluatePlanExecution(
    plan: MutationPlanRecord | null,
    options: { expectedTargetPrefix?: string; now?: number } = {},
  ): PolicyDecision {
    if (!plan) {
      return {
        allowed: false,
        code: 'PLAN_NOT_FOUND',
        reason: 'Mutation plan not found.',
      };
    }
    if (plan.status !== 'staged') {
      return {
        allowed: false,
        code: 'PLAN_INVALID_STATUS',
        reason: `Mutation plan "${plan.plan_id}" cannot be executed in status "${plan.status}".`,
      };
    }
    const now = options.now ?? Date.now();
    if (plan.expires_at <= now) {
      return {
        allowed: false,
        code: 'PLAN_EXPIRED',
        reason: `Mutation plan "${plan.plan_id}" has expired (15-minute TTL exceeded).`,
      };
    }
    if (
      options.expectedTargetPrefix &&
      !plan.target_service.startsWith(options.expectedTargetPrefix)
    ) {
      return {
        allowed: false,
        code: 'PLAN_TARGET_MISMATCH',
        reason: `Plan "${plan.plan_id}" targets "${plan.target_service}", not "${options.expectedTargetPrefix}".`,
      };
    }
    return { allowed: true };
  }

  evaluatePlanRollback(
    plan: MutationPlanRecord | null,
    options: { expectedTargetPrefix?: string } = {},
  ): PolicyDecision {
    if (!plan) {
      return {
        allowed: false,
        code: 'PLAN_NOT_FOUND',
        reason: 'Mutation plan not found.',
      };
    }
    if (plan.status !== 'executed') {
      return {
        allowed: false,
        code: 'PLAN_INVALID_STATUS',
        reason: `Plan "${plan.plan_id}" cannot be rolled back from status "${plan.status}" (must be "executed").`,
      };
    }
    if (
      options.expectedTargetPrefix &&
      !plan.target_service.startsWith(options.expectedTargetPrefix)
    ) {
      return {
        allowed: false,
        code: 'PLAN_TARGET_MISMATCH',
        reason: `Plan "${plan.plan_id}" targets "${plan.target_service}", not "${options.expectedTargetPrefix}".`,
      };
    }
    if (!plan.rollback_payload) {
      return {
        allowed: false,
        code: 'PLAN_NO_ROLLBACK',
        reason: `Plan "${plan.plan_id}" has no rollback_payload stored.`,
      };
    }
    return { allowed: true };
  }
}

export const defaultApprovalGatePolicy = new DefaultApprovalGatePolicy();

export interface MutationPlanGateOptions {
  planStore: PlanStore;
  auditLogger: AuditLogger;
  policy?: ApprovalGatePolicy;
  scrubber?: ScrubberLike;
  adapters?: MutationTargetAdapter[];
}

export interface GateExecutePlanResult {
  planId: string;
  targetService: string;
  status: 'executed';
  result: unknown;
}

export interface GateRollbackPlanResult {
  planId: string;
  targetService: string;
  status: 'rolled_back';
  result: unknown;
}

/**
 * Unified two-phase approval gate coordinator for `execute_staged_plan` and `rollback_plan`.
 * Validates target adapter & rollback availability BEFORE claiming plan state so mismatched
 * requests never corrupt an otherwise valid `staged` or `executed` plan.
 */
export class MutationPlanGate {
  private readonly planStore: PlanStore;
  private readonly auditLogger: AuditLogger;
  private readonly policy: ApprovalGatePolicy;
  private readonly scrubber: ScrubberLike;
  private readonly adapters: MutationTargetAdapter[] = [];

  constructor(options: MutationPlanGateOptions) {
    this.planStore = options.planStore;
    this.auditLogger = options.auditLogger;
    this.policy = options.policy ?? defaultApprovalGatePolicy;
    this.scrubber = options.scrubber ?? new SecretScrubber();
    if (options.adapters) {
      for (const adapter of options.adapters) {
        this.registerAdapter(adapter);
      }
    }
  }

  registerAdapter(adapter: MutationTargetAdapter): void {
    this.adapters.push(adapter);
  }

  private findAdapter(targetService: string): MutationTargetAdapter | undefined {
    return this.adapters.find((a) => a.matchesTargetService(targetService));
  }

  async executePlan(planId: string, actor = 'system'): Promise<GateExecutePlanResult> {
    const preview = this.planStore.getPlan(planId);
    const preDecision = this.policy.evaluatePlanExecution(preview);
    if (!preDecision.allowed) {
      if (preDecision.code === 'PLAN_EXPIRED' && preview?.status === 'staged') {
        this.planStore.expireStalePlans();
      }
      this.auditLogger.record({
        actor,
        action: 'publish_changes.execute_staged_plan',
        target: planId,
        status: 'denied',
        details: { code: preDecision.code, reason: preDecision.reason },
      });
      throw new ApprovalGatePolicyError(preDecision.reason, preDecision.code);
    }

    const adapter = this.findAdapter(preview!.target_service);
    if (!adapter) {
      const reason = `No mutation executor registered for target service "${preview!.target_service}".`;
      this.auditLogger.record({
        actor,
        action: 'publish_changes.execute_staged_plan',
        target: planId,
        status: 'denied',
        details: { code: 'PLAN_TARGET_MISMATCH', target_service: preview!.target_service },
      });
      throw new ApprovalGatePolicyError(reason, 'PLAN_TARGET_MISMATCH');
    }

    const claim = this.planStore.claimForExecution(planId);
    if (!claim.ok) {
      const reason =
        claim.reason === 'not_found'
          ? `Mutation plan "${planId}" not found.`
          : claim.reason === 'expired'
            ? `Mutation plan "${planId}" has expired (15-minute TTL exceeded).`
            : `Mutation plan "${planId}" cannot be executed in status "${claim.plan?.status ?? 'unknown'}".`;
      const code: PolicyDenyCode =
        claim.reason === 'not_found'
          ? 'PLAN_NOT_FOUND'
          : claim.reason === 'expired'
            ? 'PLAN_EXPIRED'
            : 'PLAN_INVALID_STATUS';
      this.auditLogger.record({
        actor,
        action: `${adapter.auditActionPrefix}.execute_plan`,
        target: planId,
        status: 'denied',
        details: { reason: claim.reason },
      });
      throw new ApprovalGatePolicyError(reason, code);
    }

    const plan = claim.plan;
    try {
      const execOut = await adapter.executeStagedPayload(plan, actor);
      if (execOut.updatedRollbackPayload !== undefined) {
        this.planStore.updatePlanRollbackPayload(planId, execOut.updatedRollbackPayload);
      }
      this.planStore.updatePlanStatus(planId, 'executed', Date.now());
      this.auditLogger.record({
        actor,
        action: `${adapter.auditActionPrefix}.execute_plan`,
        target: execOut.auditTarget ?? planId,
        status: 'success',
        details: this.scrubber.scrubObject(execOut.auditDetails ?? { plan_id: planId }),
      });

      return {
        planId,
        targetService: plan.target_service,
        status: 'executed',
        result: this.scrubber.scrubObject(execOut.result),
      };
    } catch (err) {
      const safeMsg = this.scrubber.scrub(err instanceof Error ? err.message : String(err));
      this.planStore.updatePlanStatus(planId, 'failed');
      this.auditLogger.record({
        actor,
        action: `${adapter.auditActionPrefix}.execute_plan`,
        target: planId,
        status: 'failure',
        details: { plan_id: planId, target_service: plan.target_service, error: safeMsg },
      });
      throw err;
    }
  }

  async rollbackPlan(planId: string, actor = 'system'): Promise<GateRollbackPlanResult> {
    const preview = this.planStore.getPlan(planId);
    const preDecision = this.policy.evaluatePlanRollback(preview);
    if (!preDecision.allowed) {
      this.auditLogger.record({
        actor,
        action: 'publish_changes.rollback_plan',
        target: planId,
        status: 'denied',
        details: { code: preDecision.code, reason: preDecision.reason },
      });
      throw new ApprovalGatePolicyError(preDecision.reason, preDecision.code);
    }

    const adapter = this.findAdapter(preview!.target_service);
    if (!adapter || !adapter.rollbackExecutedPayload) {
      const reason = `Rollback is not supported for target service "${preview!.target_service}".`;
      this.auditLogger.record({
        actor,
        action: 'publish_changes.rollback_plan',
        target: planId,
        status: 'denied',
        details: { code: 'PLAN_NO_ROLLBACK', target_service: preview!.target_service },
      });
      throw new ApprovalGatePolicyError(reason, 'PLAN_NO_ROLLBACK');
    }

    const claim = this.planStore.claimForRollback(planId);
    if (!claim.ok) {
      const reason =
        claim.reason === 'not_found'
          ? `Mutation plan "${planId}" not found.`
          : `Plan "${planId}" cannot be rolled back from status "${claim.plan?.status ?? 'unknown'}" (must be "executed").`;
      const code: PolicyDenyCode =
        claim.reason === 'not_found' ? 'PLAN_NOT_FOUND' : 'PLAN_INVALID_STATUS';
      this.auditLogger.record({
        actor,
        action: `${adapter.auditActionPrefix}.rollback_plan`,
        target: planId,
        status: 'denied',
        details: { reason: claim.reason },
      });
      throw new ApprovalGatePolicyError(reason, code);
    }

    const plan = claim.plan;
    try {
      const rbOut = await adapter.rollbackExecutedPayload(plan, actor);
      this.planStore.updatePlanStatus(planId, 'rolled_back');
      this.auditLogger.record({
        actor,
        action: `${adapter.auditActionPrefix}.rollback_plan`,
        target: rbOut.auditTarget ?? planId,
        status: 'success',
        details: this.scrubber.scrubObject(rbOut.auditDetails ?? { plan_id: planId }),
      });

      return {
        planId,
        targetService: plan.target_service,
        status: 'rolled_back',
        result: this.scrubber.scrubObject(rbOut.result),
      };
    } catch (err) {
      const safeMsg = this.scrubber.scrub(err instanceof Error ? err.message : String(err));
      this.planStore.updatePlanStatus(planId, 'failed');
      this.auditLogger.record({
        actor,
        action: `${adapter.auditActionPrefix}.rollback_plan`,
        target: planId,
        status: 'failure',
        details: { plan_id: planId, target_service: plan.target_service, error: safeMsg },
      });
      throw err;
    }
  }
}

/**
 * In-memory `PlanStore` implementation enabling isolated approval-gate testing without SQLite.
 */
export class InMemoryPlanStore implements PlanStore {
  private readonly plans = new Map<string, MutationPlanRecord>();

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
    const record: MutationPlanRecord = {
      plan_id: input.plan_id,
      target_service: input.target_service,
      summary_diff_text: input.summary_diff_text,
      payload: structuredClone(input.payload),
      rollback_payload: input.rollback_payload ? structuredClone(input.rollback_payload) : null,
      status: input.status ?? 'staged',
      expires_at: input.expires_at,
      created_at: input.created_at ?? Date.now(),
      executed_at: null,
    };
    this.plans.set(record.plan_id, record);
    return structuredClone(record);
  }

  getPlan(planId: string): MutationPlanRecord | null {
    const found = this.plans.get(planId);
    return found ? structuredClone(found) : null;
  }

  listPlans(
    filter: { status?: MutationPlanStatus; target_service?: string; limit?: number } = {},
  ): MutationPlanRecord[] {
    let items = Array.from(this.plans.values());
    if (filter.status) {
      items = items.filter((p) => p.status === filter.status);
    }
    if (filter.target_service) {
      items = items.filter((p) => p.target_service === filter.target_service);
    }
    items.sort((a, b) => b.created_at - a.created_at);
    return items.slice(0, filter.limit ?? 50).map((p) => structuredClone(p));
  }

  updatePlanStatus(
    planId: string,
    status: MutationPlanStatus,
    executedAt?: number | null,
  ): MutationPlanRecord | null {
    const existing = this.plans.get(planId);
    if (!existing) return null;
    existing.status = status;
    if (executedAt !== undefined) {
      existing.executed_at = executedAt;
    }
    return structuredClone(existing);
  }

  updatePlanRollbackPayload(
    planId: string,
    rollbackPayload: Record<string, unknown> | null,
  ): MutationPlanRecord | null {
    const existing = this.plans.get(planId);
    if (!existing) return null;
    existing.rollback_payload = rollbackPayload ? structuredClone(rollbackPayload) : null;
    return structuredClone(existing);
  }

  claimForExecution(planId: string, now = Date.now()): ClaimPlanResult {
    const existing = this.plans.get(planId);
    if (!existing) {
      return { ok: false, reason: 'not_found' };
    }
    if (existing.status !== 'staged') {
      return { ok: false, reason: 'invalid_status', plan: structuredClone(existing) };
    }
    if (existing.expires_at <= now) {
      existing.status = 'expired';
      return { ok: false, reason: 'expired', plan: structuredClone(existing) };
    }
    existing.status = 'executing';
    return { ok: true, plan: structuredClone(existing) };
  }

  claimForRollback(planId: string): ClaimPlanResult {
    const existing = this.plans.get(planId);
    if (!existing) {
      return { ok: false, reason: 'not_found' };
    }
    if (existing.status !== 'executed') {
      return { ok: false, reason: 'invalid_status', plan: structuredClone(existing) };
    }
    existing.status = 'rolling_back';
    return { ok: true, plan: structuredClone(existing) };
  }

  countActiveStagedPlans(now = Date.now()): number {
    let count = 0;
    for (const p of this.plans.values()) {
      if (p.status === 'staged' && p.expires_at > now) count += 1;
    }
    return count;
  }

  expireStalePlans(now = Date.now()): number {
    let changed = 0;
    for (const p of this.plans.values()) {
      if (p.status === 'staged' && p.expires_at <= now) {
        p.status = 'expired';
        changed += 1;
      }
    }
    return changed;
  }
}
