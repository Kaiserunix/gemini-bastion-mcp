export {
  ApprovalGatePolicyError,
  DefaultApprovalGatePolicy,
  InMemoryPlanStore,
  MutationPlanGate,
  defaultApprovalGatePolicy,
  type DefaultApprovalGatePolicyOptions,
  type GateExecutePlanResult,
  type GateRollbackPlanResult,
  type MutationPlanGateOptions,
} from './approvalGate.js';
export type {
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
