import type { AuditLogger } from '../../auth/store.js';
import type {
  CloudflareResourceType,
  DeployPagesOptions,
  DeployPagesResult,
  DeployWorkerOptions,
  DeployWorkerResult,
  ExecutePlanResult,
  InspectCloudflareParams,
  InspectCloudflareResult,
  RollbackPlanResult,
  StageCloudflarePlanInput,
} from '../../core/cloudflareService.js';
import type {
  ApplyPatchOptions,
  CodePatchResult,
  CreateOrOverwriteOptions,
  DeleteFilesOptions,
} from '../../core/codePatcher.js';
import type { CodexRunOptions } from '../../core/codexRunner.js';
import type {
  DownstreamCallResult,
  DownstreamRollbackSpec,
  ExecuteDownstreamPlanResult,
  ListedDownstreamServer,
  RollbackDownstreamPlanResult,
} from '../../core/downstreamMcpBridge.js';
import type {
  CreateOrUpdatePrInput,
  CreateOrUpdatePrResult,
  IssueInspectionResult,
  PostCommentResult,
  PrInspectionResult,
  SubmitPrReviewInput,
  SubmitPrReviewResult,
  WorkflowFailureResult,
} from '../../core/githubService.js';
import type {
  CfOpsContext,
  InitCfOpsWorkspaceOptions,
  RollbackOptions,
  RollbackResult,
  SyncGitHubRepoOptions,
  SyncGitHubRepoResult,
} from '../../core/gitSnapshot.js';
import type {
  ValidationPipelineOptions,
  ValidationPipelineResult,
} from '../../core/validationPipeline.js';
import type { WorkspaceExecOptions, WorkspaceExecResult } from '../../core/workspaceExec.js';
import type { MutationTargetAdapter, PlanStore } from '../../policy/index.js';
import type { AgentRunResult, AgentRunner, MutationPlanRecord } from '../../types.js';

/**
 * Typed GitHub tool adapter decoupled from Octokit/git concrete implementation.
 */
export interface GitHubToolAdapter {
  inspectPr(repoSpec: string, prNumber: number): Promise<PrInspectionResult>;
  inspectIssue(repoSpec: string, issueNumber: number): Promise<IssueInspectionResult>;
  inspectWorkflowFailure(repoSpec: string, runId?: number): Promise<WorkflowFailureResult>;
  createOrUpdatePr(input: CreateOrUpdatePrInput): Promise<CreateOrUpdatePrResult>;
  submitPrReview(
    repoSpec: string,
    prNumber: number,
    review: SubmitPrReviewInput,
  ): Promise<SubmitPrReviewResult>;
  postIssueOrPrComment(
    repoSpec: string,
    issueNumber: number,
    body: string,
  ): Promise<PostCommentResult>;
}

/**
 * Typed Cloudflare tool adapter decoupled from the Cloudflare SDK & Wrangler CLI.
 */
export interface CloudflareToolAdapter {
  inspectResource(
    resource: CloudflareResourceType,
    params?: InspectCloudflareParams,
  ): Promise<InspectCloudflareResult>;
  stageCloudflarePlan(
    planStore: PlanStore,
    rawInput: StageCloudflarePlanInput,
  ): Promise<MutationPlanRecord>;
  deployWorker(workspacePath: string, opts?: DeployWorkerOptions): Promise<DeployWorkerResult>;
  deployPages(workspacePath: string, opts: DeployPagesOptions): Promise<DeployPagesResult>;
  executeStagedCloudflarePlan(
    planStore: PlanStore,
    auditLogger: AuditLogger,
    planId: string,
    actor?: string,
  ): Promise<ExecutePlanResult>;
  rollbackExecutedPlan(
    planStore: PlanStore,
    auditLogger: AuditLogger,
    planId: string,
    actor?: string,
  ): Promise<RollbackPlanResult>;
  asMutationTargetAdapter?(): MutationTargetAdapter;
}

/**
 * Typed Downstream MCP-2 federation adapter decoupled from MCP SDK client transports.
 */
export interface DownstreamMcpToolAdapter {
  listDownstreamTools(serverName?: string): Promise<ListedDownstreamServer[]>;
  callReadonlyTool(
    serverName: string,
    toolName: string,
    args?: Record<string, unknown>,
  ): Promise<DownstreamCallResult>;
  stageMutatingToolPlan(
    planStore: PlanStore,
    serverName: string,
    toolName: string,
    args: Record<string, unknown>,
    reason: string,
    rollback?: DownstreamRollbackSpec,
  ): MutationPlanRecord;
  executeStagedDownstreamPlan(
    planStore: PlanStore,
    auditLogger: AuditLogger,
    planId: string,
    actor?: string,
  ): Promise<ExecuteDownstreamPlanResult>;
  rollbackExecutedDownstreamPlan?(
    planStore: PlanStore,
    auditLogger: AuditLogger,
    planId: string,
    actor?: string,
  ): Promise<RollbackDownstreamPlanResult>;
  asMutationTargetAdapter?(): MutationTargetAdapter;
  closeAll(): Promise<void>;
}

/**
 * Typed agent runner adapter decoupled from `@openai/codex-sdk`.
 */
export interface AgentRunnerAdapter extends AgentRunner {
  run(options: CodexRunOptions): Promise<AgentRunResult>;
}

/**
 * Typed workspace operations adapter decoupled from direct git/fs/subprocess helpers.
 */
export interface WorkspaceToolAdapter {
  syncGitHubRepo(options: SyncGitHubRepoOptions): Promise<SyncGitHubRepoResult>;
  initCfOpsWorkspace(options: InitCfOpsWorkspaceOptions): CfOpsContext;
  rollbackToCheckpoint(
    slug: string,
    checkpointId: string,
    options: RollbackOptions,
  ): Promise<RollbackResult>;
  applyPatch(options: ApplyPatchOptions): Promise<CodePatchResult>;
  createOrOverwriteFiles(options: CreateOrOverwriteOptions): Promise<CodePatchResult>;
  deleteFiles(options: DeleteFilesOptions): Promise<CodePatchResult>;
  workspaceExec(options: WorkspaceExecOptions): Promise<WorkspaceExecResult>;
  runValidationPipeline(options: ValidationPipelineOptions): Promise<ValidationPipelineResult>;
}
