/**
 * Shared foundational TypeScript types and interfaces for omni-mcp-gateway.
 * Downstream modules (auth-admin, core-sandbox, integrations-mcp) import from here.
 */

import type { GatewayDatabase } from './db/sqlite.js';
import type { Repositories } from './db/repositories/index.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';
export type NodeEnv = 'development' | 'test' | 'production';
export type CodexReasoningEffort = 'minimal' | 'low' | 'medium' | 'high' | 'xhigh';
export type AgentDriverName = 'codex' | 'claude_code' | 'gemini_cli' | 'opencode';

export interface GatewayConfig {
  nodeEnv: NodeEnv;
  logLevel: LogLevel;
  port: number;
  publicDomain: string;
  trustCfConnectingIp: boolean;

  dataDir: string;
  workspacesDir: string;
  artifactsDir: string;
  databasePath: string;

  adminPasswordHash?: string;

  oauthSigningSecret: string;
  oauthStaticClientId?: string;
  oauthStaticClientSecret?: string;
  oauthAllowedRedirectHosts: string[];
  oauthAccessTokenTtlSec: number;
  oauthRefreshTokenTtlSec: number;
  oauthRefreshGraceSec: number;

  googleOAuthClientId?: string;
  googleOAuthClientSecret?: string;
  googleOAuthAllowedEmails: string[];
  githubOAuthClientId?: string;
  githubOAuthClientSecret?: string;
  githubOAuthAllowedUsers: string[];
  githubOAuthAllowedIds: string[];

  ghToken?: string;
  cloudflareApiToken?: string;
  cloudflareReadonlyApiToken?: string;
  cloudflareAccountId?: string;

  openaiApiKey?: string;
  codexApiKey?: string;
  codexBaseUrl?: string;
  codexDefaultModel: string;
  codexReasoningEffort: CodexReasoningEffort;
  codexMaxDurationSec: number;
  codexTokenBudget: number;

  notifyWebhookUrl?: string;
  downstreamMcpsJson?: string;
  downstreamMcpsFile?: string;

  inlineOutputMaxBytes: number;
  workspaceExecDefaultWaitMs: number;
  workspaceExecMaxWaitMs: number;
  mutationPlanTtlSec: number;

  auditLogFilePath?: string;
  mcpRateLimitMaxRequests?: number;
  mcpRateLimitWindowMs?: number;
  circuitBreakerFailureThreshold?: number;
  circuitBreakerResetTimeoutMs?: number;
  securityPolicyJson?: string;
  securityPolicyFile?: string;

  sandboxUid?: number;
  sandboxGid?: number;
  sandboxBwrapIsolation: boolean;
  sandboxStrictIsolation: boolean;

  defaultAgentDriver: AgentDriverName;
  anthropicApiKey?: string;
  geminiApiKey?: string;
  agentRunnerUrl?: string;
  agentRunnerAuthToken?: string;
  opsMcpAuthToken?: string;

  watchdogEnabled: boolean;
  githubWebhookSecret?: string;
  watchdogAllowedRepos: string[];
  watchdogAgentDriver?: AgentDriverName;
}

// ============================================================================
// OAuth 2.1 + PKCE + DCR Records
// ============================================================================

export interface OAuthClient {
  client_id: string;
  client_secret_hash: string | null;
  client_name: string;
  redirect_uris: string[];
  is_static: boolean;
  created_at: number;
}

export interface OAuthAuthRequest {
  auth_req_id: string;
  client_id: string;
  redirect_uri: string;
  state: string | null;
  code_challenge: string;
  code_challenge_method: 'S256';
  scope: string;
  resource: string | null;
  csrf_token: string;
  expires_at: number;
  used: boolean;
}

export interface OAuthCode {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  scope: string;
  resource: string | null;
  expires_at: number;
  used: boolean;
  issued_family_id?: string | null;
}

export type OAuthTokenType = 'access' | 'refresh';

export interface OAuthToken {
  token_hash: string;
  token_type: OAuthTokenType;
  client_id: string;
  scope: string;
  resource: string | null;
  token_family_id: string;
  expires_at: number;
  grace_expires_at: number | null;
  revoked: boolean;
  created_at: number;
}

export type UpstreamOAuthProvider = 'google' | 'github';
export type UpstreamOAuthPurpose = 'admin' | 'mcp_authorize';

export interface OAuthUpstreamState {
  state: string;
  provider: UpstreamOAuthProvider;
  purpose: UpstreamOAuthPurpose;
  auth_req_id: string | null;
  code_verifier: string;
  binding_hash: string;
  expires_at: number;
  used: boolean;
  created_at: number;
}

// ============================================================================
// Workspaces, Checkpoints, Jobs, Mutation Plans, Audit Logs
// ============================================================================

export interface DetectedStack {
  languages: string[];
  packageManagers: string[];
  frameworks: string[];
  testCommands: string[];
  lintCommands: string[];
  buildCommands: string[];
  typecheckCommands: string[];
  hasDockerfile?: boolean;
  hasWrangler?: boolean;
  playbookSources?: string[];
}

export interface WorkspaceRecord {
  slug: string;
  repo_url: string;
  default_branch: string;
  detected_stack: DetectedStack;
  playbook_text: string | null;
  last_synced_at: number | null;
}

export type MemoryCategory = 'task_state' | 'decision' | 'pitfall' | 'preference' | 'note';

export interface WorkspaceMemoryRecord {
  memory_id: string;
  workspace_slug: string;
  category: MemoryCategory;
  key: string;
  content: string;
  pinned: boolean;
  created_at: number;
  updated_at: number;
}

export interface CheckpointRecord {
  checkpoint_id: string;
  workspace_slug: string;
  git_commit_sha: string;
  git_ref: string;
  reason: string;
  created_at: number;
}

export type JobRunnerType =
  | 'shell'
  | 'codex_readonly'
  | 'codex_write'
  | 'agent_readonly'
  | 'agent_write'
  | 'shell_task';
export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled' | 'timed_out';

export type JobEventType =
  | 'status'
  | 'stdout'
  | 'stderr'
  | 'agent_message'
  | 'tool_call'
  | 'checkpoint'
  | 'error'
  | 'token_usage';

export interface JobEvent {
  seq: number;
  ts: number;
  type: JobEventType;
  message: string;
  data?: Record<string, unknown>;
}

export interface TokenUsage {
  input_tokens: number;
  cached_input_tokens?: number;
  output_tokens: number;
  total_tokens: number;
}

export interface JobRecord {
  job_id: string;
  workspace_slug: string;
  runner_type: JobRunnerType;
  status: JobStatus;
  command_or_objective: string;
  codex_thread_id: string | null;
  checkpoint_id: string | null;
  events: JobEvent[];
  token_usage: TokenUsage | null;
  final_report_text: string | null;
  error_message: string | null;
  created_at: number;
  updated_at: number;
}

export type MutationPlanStatus =
  | 'staged'
  | 'executing'
  | 'executed'
  | 'rolling_back'
  | 'rolled_back'
  | 'expired'
  | 'failed';
export type MutationPlanTargetService = 'cloudflare' | 'downstream_mcp';

export interface MutationPlanRecord {
  plan_id: string;
  target_service: MutationPlanTargetService | string;
  summary_diff_text: string;
  payload: Record<string, unknown>;
  rollback_payload: Record<string, unknown> | null;
  status: MutationPlanStatus;
  expires_at: number;
  created_at: number;
  executed_at: number | null;
}

export interface AuditLogRecord {
  id: number;
  actor: string;
  action: string;
  target: string;
  status: 'success' | 'failure' | 'denied' | string;
  details: Record<string, unknown>;
  created_at: number;
}

// ============================================================================
// Downstream MCP-2 Federation Config
// ============================================================================

export interface DownstreamMcpServerConfig {
  id: string;
  transport: 'http' | 'stdio';
  url?: string;
  headers?: Record<string, string>;
  authToken?: string;
  authTokenEnv?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  description?: string;
  enabled?: boolean;
  timeoutMs?: number;
  readonlyTools: string[];
  mutatingTools: string[];
  deniedTools: string[];
}

// ============================================================================
// Agent Runner, Validation Pipeline & MCP Tool Context
// ============================================================================

export interface AgentRunOptions {
  jobId: string;
  workspaceSlug: string;
  workspaceDir: string;
  mode: 'readonly' | 'write';
  objective: string;
  driver?: AgentDriverName;
  resumeThreadId?: string;
  model?: string;
  reasoningEffort?: CodexReasoningEffort;
  maxDurationSec?: number;
  tokenBudget?: number;
  signal?: AbortSignal;
  onEvent?: (event: Omit<JobEvent, 'seq'>) => void;
}

export interface AgentRunResult {
  status: 'completed' | 'failed' | 'cancelled' | 'timed_out';
  threadId: string | null;
  finalReport: string;
  tokenUsage: TokenUsage | null;
  errorMessage?: string;
}

export interface AgentRunner {
  readonly name: string;
  run(options: AgentRunOptions): Promise<AgentRunResult>;
}

export type ValidationLevel = 'L0' | 'L1' | 'L2';

export interface ValidationStepResult {
  level: ValidationLevel;
  tool: string;
  passed: boolean;
  exitCode: number | null;
  summary: string;
  output: string;
  durationMs: number;
  skipped?: boolean;
}

export interface ValidationResult {
  passed: boolean;
  highestLevelRun: ValidationLevel | null;
  steps: ValidationStepResult[];
  summary: string;
}

export interface McpTextContent {
  [key: string]: unknown;
  type: 'text';
  text: string;
}

export interface McpToolResult {
  [key: string]: unknown;
  content: McpTextContent[];
  isError?: boolean;
}

export interface ScrubberLike {
  scrub(input: string): string;
  scrubObject<T>(value: T): T;
}

export interface ToolContext {
  config: GatewayConfig;
  db: GatewayDatabase;
  repos: Repositories;
  scrubber: ScrubberLike;
  actor: string;
  clientId?: string;
  scope?: string;
  notifyWebhook?: (event: string, payload: Record<string, unknown>) => Promise<void>;
}

// ============================================================================
// MCP Throughput & Background Agent Token Metering
// ============================================================================

export interface McpUsageEventRecord {
  id: number;
  tool_name: string;
  client_id: string | null;
  status: 'ok' | 'error';
  input_bytes: number;
  output_bytes: number;
  est_input_tokens: number;
  est_output_tokens: number;
  duration_ms: number;
  created_at: number;
}

export interface UsageWindowSummary {
  calls: number;
  errors: number;
  inputBytes: number;
  outputBytes: number;
  estInputTokens: number;
  estOutputTokens: number;
  estTotalTokens: number;
  avgDurationMs: number;
  lastCallAt: number | null;
}

export interface ToolUsageBreakdown {
  toolName: string;
  calls24h: number;
  calls30d: number;
  errors30d: number;
  estTotalTokens30d: number;
  avgDurationMs30d: number;
}

export interface HourlyUsageBucket {
  hourStartMs: number;
  calls: number;
  estTotalTokens: number;
}

export interface AgentTokenWindowSummary {
  jobsCount: number;
  inputTokens: number;
  cachedInputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export interface UsageSummary {
  generatedAt: number;
  last1h: UsageWindowSummary;
  last3h: UsageWindowSummary;
  last24h: UsageWindowSummary;
  last7d: UsageWindowSummary;
  last30d: UsageWindowSummary;
  allTime: UsageWindowSummary;
  byTool: ToolUsageBreakdown[];
  hourly24h: HourlyUsageBucket[];
  agentTokens: {
    last24h: AgentTokenWindowSummary;
    last7d: AgentTokenWindowSummary;
    last30d: AgentTokenWindowSummary;
    allTime: AgentTokenWindowSummary;
  };
}
