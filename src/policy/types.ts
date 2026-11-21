import type {
  DownstreamMcpServerConfig,
  MutationPlanRecord,
  MutationPlanStatus,
} from '../types.js';

export type RequiredMcpScope = 'read' | 'write';

export type PolicyDenyCode =
  | 'INSUFFICIENT_SCOPE'
  | 'PROTECTED_BRANCH'
  | 'INVALID_BRANCH_NAME'
  | 'DOWNSTREAM_DENIED'
  | 'DOWNSTREAM_UNLISTED'
  | 'DOWNSTREAM_PHASE_MISMATCH'
  | 'PLAN_NOT_FOUND'
  | 'PLAN_EXPIRED'
  | 'PLAN_INVALID_STATUS'
  | 'PLAN_TARGET_MISMATCH'
  | 'PLAN_NO_ROLLBACK'
  | 'ORIGIN_NOT_ALLOWED'
  | 'POLICY_DENIED';

export type PolicyDecision =
  | {
      allowed: true;
      reason?: string;
    }
  | {
      allowed: false;
      code: PolicyDenyCode;
      reason: string;
    };

export type DownstreamToolClassification = 'readonly' | 'mutating' | 'denied' | 'unlisted';

export type DownstreamToolPhase = 'inspect' | 'stage' | 'execute';

export type ClaimPlanResult =
  | { ok: true; plan: MutationPlanRecord }
  | { ok: false; reason: 'not_found' | 'expired' | 'invalid_status'; plan?: MutationPlanRecord };

/**
 * Storage-agnostic typed contract for staged mutation plans (`mutation_plans`).
 */
export interface PlanStore {
  createPlan(input: {
    plan_id: string;
    target_service: string;
    summary_diff_text: string;
    payload: Record<string, unknown>;
    rollback_payload?: Record<string, unknown> | null;
    status?: MutationPlanStatus;
    expires_at: number;
    created_at?: number;
  }): MutationPlanRecord;
  getPlan(planId: string): MutationPlanRecord | null;
  listPlans(filter?: {
    status?: MutationPlanStatus;
    target_service?: string;
    limit?: number;
  }): MutationPlanRecord[];
  updatePlanStatus(
    planId: string,
    status: MutationPlanStatus,
    executedAt?: number | null,
  ): MutationPlanRecord | null;
  updatePlanRollbackPayload(
    planId: string,
    rollbackPayload: Record<string, unknown> | null,
  ): MutationPlanRecord | null;
  claimForExecution(planId: string, now?: number): ClaimPlanResult;
  claimForRollback(planId: string): ClaimPlanResult;
  countActiveStagedPlans(now?: number): number;
  expireStalePlans(now?: number): number;
}

/**
 * Typed fail-closed approval-gate policy engine contract.
 * Centralizes OAuth scope checks, protected-branch enforcement, downstream MCP-2
 * capability classification, and staged mutation plan execution/rollback gates.
 */
export interface ApprovalGatePolicy {
  evaluateScope(scopes: readonly string[], required: RequiredMcpScope): PolicyDecision;
  evaluateProtectedBranch(
    branchName: string,
    defaultBranch?: string,
    baseBranch?: string,
  ): PolicyDecision;
  classifyDownstreamTool(
    server: DownstreamMcpServerConfig,
    toolName: string,
  ): DownstreamToolClassification;
  evaluateDownstreamTool(
    server: DownstreamMcpServerConfig,
    toolName: string,
    phase: DownstreamToolPhase,
  ): PolicyDecision;
  evaluatePlanExecution(
    plan: MutationPlanRecord | null,
    options?: { expectedTargetPrefix?: string; now?: number },
  ): PolicyDecision;
  evaluatePlanRollback(
    plan: MutationPlanRecord | null,
    options?: { expectedTargetPrefix?: string },
  ): PolicyDecision;
}

/**
 * Typed adapter for executing and rolling back staged plans for a given target service.
 */
export interface MutationTargetAdapter {
  readonly targetPrefix: string;
  readonly auditActionPrefix: string;
  matchesTargetService(targetService: string): boolean;
  executeStagedPayload(
    plan: MutationPlanRecord,
    actor: string,
  ): Promise<{
    result: unknown;
    auditTarget?: string;
    auditDetails?: Record<string, unknown>;
    updatedRollbackPayload?: Record<string, unknown> | null;
  }>;
  rollbackExecutedPayload?(
    plan: MutationPlanRecord,
    actor: string,
  ): Promise<{
    result: unknown;
    auditTarget?: string;
    auditDetails?: Record<string, unknown>;
  }>;
}
