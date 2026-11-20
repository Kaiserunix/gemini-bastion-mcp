import fs from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import type { AuditEventPublisher } from './auditSink.js';

export const KNOWN_BASTION_TOOLS = [
  'workspace_manage',
  'code_explore',
  'code_patch',
  'workspace_exec',
  'dispatch_runner',
  'job_status',
  'github_inspect',
  'infra_inspect',
  'stage_mutation_plan',
  'publish_changes',
] as const;

export type KnownBastionToolName = (typeof KNOWN_BASTION_TOOLS)[number];
export type PolicyEffect = 'allow' | 'deny' | 'require_staged_plan';
export type PolicyCombiningAlgorithm = 'deny-overrides' | 'first-applicable';
export type PolicyRequiredScope = 'read' | 'write';

export interface PolicyEvaluationContext {
  actor: string;
  clientId?: string;
  scopes?: string[];
  toolName: string;
  action?: string;
  workspaceSlug?: string;
  repo?: string;
  branch?: string;
  baseBranch?: string;
  defaultBranch?: string;
  paths?: string[];
  command?: string;
  deployTarget?: string;
  downstreamServer?: string;
  downstreamTool?: string;
  planId?: string;
  args?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface PolicyMatchCriteria {
  tools?: string[];
  actions?: string[];
  actors?: string[];
  notActors?: string[];
  clientIds?: string[];
  notClientIds?: string[];
  workspaces?: string[];
  notWorkspaces?: string[];
  repos?: string[];
  notRepos?: string[];
  branches?: string[];
  protectedDefaultBranch?: boolean;
  pathGlobs?: string[];
  commandSubstrings?: string[];
  commandRegexes?: string[];
  deployTargets?: string[];
  downstreamServers?: string[];
  downstreamTools?: string[];
  missingRequiredScope?: PolicyRequiredScope;
  missingPlanId?: boolean;
}

export interface PolicyRule {
  id: string;
  description?: string;
  priority?: number;
  enabled?: boolean;
  effect: PolicyEffect;
  reason?: string;
  match?: PolicyMatchCriteria;
  predicate?: (ctx: PolicyEvaluationContext) => boolean;
}

export interface MatchedPolicyRuleSummary {
  id: string;
  effect: PolicyEffect;
  priority: number;
  reason: string;
}

export interface PolicyDecision {
  allowed: boolean;
  effect: PolicyEffect;
  matchedRuleId: string | null;
  matchedRules: MatchedPolicyRuleSummary[];
  reason: string;
  evaluatedRuleCount: number;
  defaultApplied: boolean;
}

export interface PolicyEvaluatorPort {
  evaluate(ctx: PolicyEvaluationContext): PolicyDecision;
}

// ============================================================================
// Declarative Zod Schema for External JSON / File Policy Definitions
// ============================================================================

const matchCriteriaSchema = z
  .object({
    tools: z.array(z.string().min(1)).optional(),
    actions: z.array(z.string().min(1)).optional(),
    actors: z.array(z.string().min(1)).optional(),
    notActors: z.array(z.string().min(1)).optional(),
    clientIds: z.array(z.string().min(1)).optional(),
    notClientIds: z.array(z.string().min(1)).optional(),
    workspaces: z.array(z.string().min(1)).optional(),
    notWorkspaces: z.array(z.string().min(1)).optional(),
    repos: z.array(z.string().min(1)).optional(),
    notRepos: z.array(z.string().min(1)).optional(),
    branches: z.array(z.string().min(1)).optional(),
    protectedDefaultBranch: z.boolean().optional(),
    pathGlobs: z.array(z.string().min(1)).optional(),
    commandSubstrings: z.array(z.string().min(1)).optional(),
    commandRegexes: z.array(z.string().min(1).max(256)).optional(),
    deployTargets: z.array(z.string().min(1)).optional(),
    downstreamServers: z.array(z.string().min(1)).optional(),
    downstreamTools: z.array(z.string().min(1)).optional(),
    missingRequiredScope: z.enum(['read', 'write']).optional(),
    missingPlanId: z.boolean().optional(),
  })
  .strict();

export const policyRuleSchema = z
  .object({
    id: z.string().min(1).max(128),
    description: z.string().optional(),
    priority: z.number().int().min(-10_000).max(10_000).optional(),
    enabled: z.boolean().optional(),
    effect: z.enum(['allow', 'deny', 'require_staged_plan']),
    reason: z.string().optional(),
    match: matchCriteriaSchema.optional(),
  })
  .strict();

export function parsePolicyRulesPayload(raw: unknown): PolicyRule[] {
  if (Array.isArray(raw)) {
    return z.array(policyRuleSchema).parse(raw);
  }
  if (raw && typeof raw === 'object') {
    const obj = raw as Record<string, unknown>;
    if (Array.isArray(obj.rules)) {
      return z.array(policyRuleSchema).parse(obj.rules);
    }
  }
  throw new Error('Security policy payload must be a JSON array of rules or { "rules": [...] }.');
}

export function loadPolicyRulesFromSources(options: {
  rules?: PolicyRule[];
  policyJson?: string;
  policyFile?: string;
}): PolicyRule[] {
  const loaded: PolicyRule[] = [];

  if (options.rules) {
    loaded.push(...options.rules);
  }
  if (options.policyFile && options.policyFile.trim().length > 0) {
    const resolved = path.resolve(options.policyFile.trim());
    if (!fs.existsSync(resolved)) {
      throw new Error(`SECURITY_POLICY_FILE not found: ${resolved}`);
    }
    const rawText = fs.readFileSync(resolved, 'utf8').trim();
    if (rawText.length > 0) {
      loaded.push(...parsePolicyRulesPayload(JSON.parse(rawText)));
    }
  }
  if (options.policyJson && options.policyJson.trim().length > 0) {
    loaded.push(...parsePolicyRulesPayload(JSON.parse(options.policyJson)));
  }

  return loaded;
}

// ============================================================================
// Pattern & Scope Helpers
// ============================================================================

function wildcardToRegExp(pattern: string, caseInsensitive = false): RegExp {
  const normalized = pattern.replace(/\\/g, '/');
  const escaped = normalized
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '::GLOBSTAR::')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/::GLOBSTAR::/g, '.*');
  return new RegExp(`^${escaped}$`, caseInsensitive ? 'i' : '');
}

function matchesAnyWildcard(
  candidate: string | undefined,
  patterns: readonly string[],
  caseInsensitive = false,
): boolean {
  if (candidate === undefined || candidate === '') return false;
  const normCandidate = candidate.replace(/\\/g, '/');
  for (const pat of patterns) {
    if (pat === '*') return true;
    if (wildcardToRegExp(pat, caseInsensitive).test(normCandidate)) {
      return true;
    }
  }
  return false;
}

function matchesAnyPathGlob(paths: readonly string[] | undefined, globs: readonly string[]): boolean {
  if (!paths || paths.length === 0) return false;
  for (const rawPath of paths) {
    const norm = rawPath.replace(/\\/g, '/').replace(/^\.\/+/, '');
    const base = path.posix.basename(norm);
    for (const glob of globs) {
      const re = wildcardToRegExp(glob, true);
      if (re.test(norm) || re.test(base)) {
        return true;
      }
    }
  }
  return false;
}

function normalizeGitBranchRef(branch: string | undefined): string | undefined {
  if (!branch) return undefined;
  const trimmed = branch.trim();
  if (!trimmed) return undefined;
  return trimmed.replace(/^refs\/heads\//i, '');
}

export function hasSufficientMcpScope(
  scopes: readonly string[],
  required: PolicyRequiredScope,
): boolean {
  if (scopes.includes('mcp:tools') || scopes.includes('mcp:write')) {
    return true;
  }
  if (required === 'read') {
    return scopes.includes('mcp:read');
  }
  return false;
}

/**
 * Determines the required OAuth scope ('read' | 'write') for any of the 10 Bastion MCP tools.
 */
export function resolveRequiredScopeForTool(
  toolName: string,
  action?: string,
  args?: Record<string, unknown>,
): PolicyRequiredScope {
  switch (toolName) {
    case 'code_explore':
    case 'github_inspect':
    case 'infra_inspect':
      return 'read';
    case 'workspace_manage':
      return action && ['list', 'init_cf_ops', 'list_checkpoints'].includes(action)
        ? 'read'
        : 'write';
    case 'job_status':
      return args?.cancel === true ? 'write' : 'read';
    default:
      return 'write';
  }
}

/**
 * Extracts a normalized `PolicyEvaluationContext` from raw MCP tool invocation arguments and auth metadata.
 */
export function extractToolPolicyContext(
  toolName: string,
  rawArgs: unknown,
  extra?: {
    authInfo?: {
      clientId?: string;
      scopes?: string[];
    };
  },
  fallbackActor = 'mcp-operator',
): PolicyEvaluationContext {
  const args =
    rawArgs && typeof rawArgs === 'object' ? (rawArgs as Record<string, unknown>) : {};

  const action =
    typeof args.action === 'string'
      ? args.action
      : typeof args.mode === 'string'
        ? args.mode
        : undefined;

  const collectedPaths: string[] = [];
  if (typeof args.path === 'string' && args.path.trim()) {
    collectedPaths.push(args.path.trim());
  }
  if (typeof args.config_path === 'string' && args.config_path.trim()) {
    collectedPaths.push(args.config_path.trim());
  }
  if (typeof args.directory === 'string' && args.directory.trim()) {
    collectedPaths.push(args.directory.trim());
  }
  if (Array.isArray(args.paths)) {
    for (const p of args.paths) {
      if (typeof p === 'string' && p.trim()) collectedPaths.push(p.trim());
    }
  }
  if (Array.isArray(args.files)) {
    for (const f of args.files) {
      if (f && typeof f === 'object' && typeof (f as Record<string, unknown>).path === 'string') {
        collectedPaths.push(String((f as Record<string, unknown>).path).trim());
      }
    }
  }
  if (Array.isArray(args.edits)) {
    for (const e of args.edits) {
      if (e && typeof e === 'object' && typeof (e as Record<string, unknown>).path === 'string') {
        collectedPaths.push(String((e as Record<string, unknown>).path).trim());
      }
    }
  }

  let command: string | undefined;
  if (typeof args.command === 'string') {
    const extraCmdArgs = Array.isArray(args.args)
      ? args.args.filter((item): item is string => typeof item === 'string').join(' ')
      : '';
    command = extraCmdArgs ? `${args.command} ${extraCmdArgs}` : args.command;
  } else if (toolName === 'dispatch_runner' && action === 'shell_task' && typeof args.objective === 'string') {
    command = args.objective;
  }

  const rawBranch =
    toolName === 'publish_changes' && action === 'github_pr'
      ? typeof args.branch_name === 'string'
        ? args.branch_name
        : undefined
      : typeof args.branch_name === 'string'
        ? args.branch_name
        : typeof args.branch === 'string'
          ? args.branch
          : undefined;

  const clientId = extra?.authInfo?.clientId;
  const actor = clientId || fallbackActor;

  return {
    actor,
    clientId,
    scopes: Array.isArray(extra?.authInfo?.scopes) ? [...extra!.authInfo!.scopes!] : undefined,
    toolName,
    action,
    workspaceSlug: typeof args.slug === 'string' ? args.slug : undefined,
    repo: typeof args.repo === 'string' ? args.repo : undefined,
    branch: normalizeGitBranchRef(rawBranch),
    baseBranch: normalizeGitBranchRef(
      typeof args.base_branch === 'string' ? args.base_branch : undefined,
    ),
    paths: collectedPaths.length > 0 ? collectedPaths : undefined,
    command,
    deployTarget: typeof args.target === 'string' ? args.target : undefined,
    downstreamServer: typeof args.server_name === 'string' ? args.server_name : undefined,
    downstreamTool: typeof args.tool_name === 'string' ? args.tool_name : undefined,
    planId: typeof args.plan_id === 'string' ? args.plan_id : undefined,
    args,
  };
}

// ============================================================================
// Built-In Bastion Baseline Security Rules
// ============================================================================

const SENSITIVE_WORKSPACE_PATH_GLOBS = [
  '.env',
  '.env.*',
  '**/.env',
  '**/.env.*',
  '*.pem',
  '**/*.pem',
  '*.key',
  '**/*.key',
  'id_rsa*',
  '**/id_rsa*',
  'id_ed25519*',
  '**/id_ed25519*',
  '.dev.vars',
  '.dev.vars.*',
  '**/.dev.vars',
  '**/.dev.vars.*',
  '.git/**',
  '**/.git/**',
];

export function createBuiltinBastionPolicyRules(): PolicyRule[] {
  return [
    {
      id: 'builtin:oauth-scope-read',
      description: 'Require at least mcp:read (or mcp:write / mcp:tools) when OAuth scopes are present.',
      priority: 1000,
      effect: 'deny',
      predicate: (ctx) => {
        if (!Array.isArray(ctx.scopes)) return false;
        const req = resolveRequiredScopeForTool(ctx.toolName, ctx.action, ctx.args);
        return req === 'read' && !hasSufficientMcpScope(ctx.scopes, 'read');
      },
      reason:
        'insufficient_scope — "read" operation requires "mcp:read", "mcp:write", or "mcp:tools" scope.',
    },
    {
      id: 'builtin:oauth-scope-write',
      description: 'Require mcp:write or mcp:tools when OAuth scopes are present for mutating tools.',
      priority: 1000,
      effect: 'deny',
      predicate: (ctx) => {
        if (!Array.isArray(ctx.scopes)) return false;
        const req = resolveRequiredScopeForTool(ctx.toolName, ctx.action, ctx.args);
        return req === 'write' && !hasSufficientMcpScope(ctx.scopes, 'write');
      },
      reason:
        'insufficient_scope — "write" operation requires "mcp:tools" or "mcp:write" scope.',
    },
    {
      id: 'builtin:no-protected-branch-push',
      description: 'Block publish_changes(github_pr) from pushing directly to main, master, or default/base branch.',
      priority: 950,
      effect: 'deny',
      match: {
        tools: ['publish_changes'],
        actions: ['github_pr'],
        protectedDefaultBranch: true,
      },
      reason:
        'Protected branch policy violation: direct push/PR from main, master, or base/default branch is strictly forbidden.',
    },
    {
      id: 'builtin:sensitive-workspace-paths',
      description: 'Deny direct read/patch/deploy targeting sensitive workspace credential files.',
      priority: 900,
      effect: 'deny',
      match: {
        tools: ['code_explore', 'code_patch', 'publish_changes'],
        pathGlobs: SENSITIVE_WORKSPACE_PATH_GLOBS,
      },
      reason: 'Access to sensitive workspace file is denied by bastion policy.',
    },
    {
      id: 'builtin:forbid-legacy-codex-mcp-cli',
      description: 'Forbid invoking deprecated "codex mcp-server" CLI in shell commands.',
      priority: 850,
      effect: 'deny',
      match: {
        tools: ['workspace_exec', 'dispatch_runner'],
        commandSubstrings: ['codex mcp-server'],
      },
      reason:
        'Deprecated "codex mcp-server" CLI invocation is prohibited; use dispatch_runner with @openai/codex-sdk.',
    },
    {
      id: 'builtin:require-staged-plan-id',
      description: 'Require a non-empty staged plan_id for execute_staged_plan and rollback_plan.',
      priority: 800,
      effect: 'require_staged_plan',
      match: {
        tools: ['publish_changes'],
        actions: ['execute_staged_plan', 'rollback_plan'],
        missingPlanId: true,
      },
      reason:
        'Two-phase mutation gate requires a valid staged "plan_id" created via stage_mutation_plan.',
    },
    {
      id: 'builtin:allow-known-10-tools',
      description: 'Allow calls to the exact 10 registered Bastion MCP tools when no deny rule triggers.',
      priority: -100,
      effect: 'allow',
      match: {
        tools: [...KNOWN_BASTION_TOOLS],
      },
      reason: 'Permitted under standard 10-tool Bastion contract.',
    },
  ];
}

// ============================================================================
// PolicyEvaluator Engine
// ============================================================================

export interface PolicyEvaluatorOptions {
  rules?: PolicyRule[];
  includeBuiltinRules?: boolean;
  combiningAlgorithm?: PolicyCombiningAlgorithm;
  defaultEffect?: 'allow' | 'deny';
  requireExplicitScopes?: boolean;
  auditPublisher?: AuditEventPublisher;
  auditAllows?: boolean;
}

function doesCriteriaMatch(criteria: PolicyMatchCriteria, ctx: PolicyEvaluationContext): boolean {
  if (criteria.tools && !matchesAnyWildcard(ctx.toolName, criteria.tools)) {
    return false;
  }
  if (criteria.actions && !matchesAnyWildcard(ctx.action, criteria.actions)) {
    return false;
  }
  if (criteria.actors && !matchesAnyWildcard(ctx.actor, criteria.actors)) {
    return false;
  }
  if (criteria.notActors && matchesAnyWildcard(ctx.actor, criteria.notActors)) {
    return false;
  }
  if (criteria.clientIds && !matchesAnyWildcard(ctx.clientId, criteria.clientIds)) {
    return false;
  }
  if (
    criteria.notClientIds &&
    ctx.clientId !== undefined &&
    matchesAnyWildcard(ctx.clientId, criteria.notClientIds)
  ) {
    return false;
  }
  if (criteria.workspaces && !matchesAnyWildcard(ctx.workspaceSlug, criteria.workspaces)) {
    return false;
  }
  if (
    criteria.notWorkspaces &&
    ctx.workspaceSlug !== undefined &&
    matchesAnyWildcard(ctx.workspaceSlug, criteria.notWorkspaces)
  ) {
    return false;
  }
  if (criteria.repos && !matchesAnyWildcard(ctx.repo, criteria.repos, true)) {
    return false;
  }
  if (
    criteria.notRepos &&
    ctx.repo !== undefined &&
    matchesAnyWildcard(ctx.repo, criteria.notRepos, true)
  ) {
    return false;
  }
  if (criteria.branches && !matchesAnyWildcard(ctx.branch, criteria.branches)) {
    return false;
  }
  if (criteria.protectedDefaultBranch !== undefined) {
    const branch = normalizeGitBranchRef(ctx.branch)?.toLowerCase();
    const base = normalizeGitBranchRef(ctx.baseBranch)?.toLowerCase();
    const def = normalizeGitBranchRef(ctx.defaultBranch)?.toLowerCase();
    const isProtected = Boolean(
      branch &&
        (branch === 'main' ||
          branch === 'master' ||
          (base && branch === base) ||
          (def && branch === def)),
    );
    if (isProtected !== criteria.protectedDefaultBranch) {
      return false;
    }
  }
  if (criteria.pathGlobs && !matchesAnyPathGlob(ctx.paths, criteria.pathGlobs)) {
    return false;
  }
  if (criteria.commandSubstrings) {
    if (!ctx.command) return false;
    const lowerCmd = ctx.command.toLowerCase();
    const hit = criteria.commandSubstrings.some((sub) => lowerCmd.includes(sub.toLowerCase()));
    if (!hit) return false;
  }
  if (criteria.commandRegexes) {
    if (!ctx.command) return false;
    const boundedCmd = ctx.command.slice(0, 8192);
    const hit = criteria.commandRegexes.some((pat) => new RegExp(pat, 'i').test(boundedCmd));
    if (!hit) return false;
  }
  if (criteria.deployTargets && !matchesAnyWildcard(ctx.deployTarget, criteria.deployTargets)) {
    return false;
  }
  if (
    criteria.downstreamServers &&
    !matchesAnyWildcard(ctx.downstreamServer, criteria.downstreamServers)
  ) {
    return false;
  }
  if (
    criteria.downstreamTools &&
    !matchesAnyWildcard(ctx.downstreamTool, criteria.downstreamTools)
  ) {
    return false;
  }
  if (criteria.missingRequiredScope) {
    if (!Array.isArray(ctx.scopes)) return false;
    if (hasSufficientMcpScope(ctx.scopes, criteria.missingRequiredScope)) {
      return false;
    }
  }
  if (criteria.missingPlanId !== undefined) {
    const isMissing = !ctx.planId || ctx.planId.trim().length === 0;
    if (isMissing !== criteria.missingPlanId) {
      return false;
    }
  }

  return true;
}

/**
 * Deterministic, fail-closed Policy-Rule Evaluator for Bastion MCP tool invocations,
 * OAuth scopes, workspace/repo boundaries, protected branches, and staged mutation gates.
 */
export class PolicyEvaluator implements PolicyEvaluatorPort {
  private readonly rules: PolicyRule[];
  private readonly combiningAlgorithm: PolicyCombiningAlgorithm;
  private readonly defaultEffect: 'allow' | 'deny';
  private readonly requireExplicitScopes: boolean;
  private readonly auditPublisher?: AuditEventPublisher;
  private readonly auditAllows: boolean;

  constructor(options: PolicyEvaluatorOptions = {}) {
    const includeBuiltin = options.includeBuiltinRules ?? false;
    const combined = [
      ...(includeBuiltin ? createBuiltinBastionPolicyRules() : []),
      ...(options.rules ?? []),
    ];
    this.rules = combined
      .filter((r) => r.enabled !== false)
      .map((r, idx) => ({ rule: r, idx }))
      .sort((a, b) => {
        const prioDiff = (b.rule.priority ?? 0) - (a.rule.priority ?? 0);
        return prioDiff !== 0 ? prioDiff : a.idx - b.idx;
      })
      .map((entry) => entry.rule);

    this.combiningAlgorithm = options.combiningAlgorithm ?? 'deny-overrides';
    this.defaultEffect = options.defaultEffect ?? 'deny';
    this.requireExplicitScopes = options.requireExplicitScopes ?? false;
    this.auditPublisher = options.auditPublisher;
    this.auditAllows = options.auditAllows ?? false;
  }

  getRules(): readonly PolicyRule[] {
    return this.rules;
  }

  evaluate(ctx: PolicyEvaluationContext): PolicyDecision {
    try {
      if (this.requireExplicitScopes && !Array.isArray(ctx.scopes)) {
        const decision: PolicyDecision = {
          allowed: false,
          effect: 'deny',
          matchedRuleId: 'system:missing-explicit-scopes',
          matchedRules: [
            {
              id: 'system:missing-explicit-scopes',
              effect: 'deny',
              priority: 10_000,
              reason: 'insufficient_scope — explicit OAuth scopes are required by policy.',
            },
          ],
          reason: 'insufficient_scope — explicit OAuth scopes are required by policy.',
          evaluatedRuleCount: 0,
          defaultApplied: false,
        };
        this.emitPolicyAudit(ctx, decision);
        return decision;
      }

      const matched: MatchedPolicyRuleSummary[] = [];
      let evaluatedCount = 0;

      for (const rule of this.rules) {
        evaluatedCount += 1;
        const criteriaOk = rule.match ? doesCriteriaMatch(rule.match, ctx) : true;
        if (!criteriaOk) continue;

        const predicateOk = rule.predicate ? rule.predicate(ctx) : true;
        if (!predicateOk) continue;

        const reason =
          rule.reason ??
          rule.description ??
          `Matched policy rule "${rule.id}" (${rule.effect}).`;

        const summary: MatchedPolicyRuleSummary = {
          id: rule.id,
          effect: rule.effect,
          priority: rule.priority ?? 0,
          reason,
        };
        matched.push(summary);

        if (this.combiningAlgorithm === 'first-applicable') {
          const allowed =
            rule.effect === 'allow' ||
            (rule.effect === 'require_staged_plan' && Boolean(ctx.planId?.trim()));
          const decision: PolicyDecision = {
            allowed,
            effect: allowed && rule.effect === 'require_staged_plan' ? 'allow' : rule.effect,
            matchedRuleId: rule.id,
            matchedRules: matched,
            reason,
            evaluatedRuleCount: evaluatedCount,
            defaultApplied: false,
          };
          this.emitPolicyAudit(ctx, decision);
          return decision;
        }
      }

      // 'deny-overrides' combining resolution:
      // 1. Any explicit deny wins immediately.
      const firstDeny = matched.find((m) => m.effect === 'deny');
      if (firstDeny) {
        const decision: PolicyDecision = {
          allowed: false,
          effect: 'deny',
          matchedRuleId: firstDeny.id,
          matchedRules: matched,
          reason: firstDeny.reason,
          evaluatedRuleCount: evaluatedCount,
          defaultApplied: false,
        };
        this.emitPolicyAudit(ctx, decision);
        return decision;
      }

      // 2. Any require_staged_plan without a non-empty planId blocks until staged.
      const firstStagedReq = matched.find((m) => m.effect === 'require_staged_plan');
      if (firstStagedReq && (!ctx.planId || ctx.planId.trim().length === 0)) {
        const decision: PolicyDecision = {
          allowed: false,
          effect: 'require_staged_plan',
          matchedRuleId: firstStagedReq.id,
          matchedRules: matched,
          reason: firstStagedReq.reason,
          evaluatedRuleCount: evaluatedCount,
          defaultApplied: false,
        };
        this.emitPolicyAudit(ctx, decision);
        return decision;
      }

      // 3. Any explicit allow (or satisfied require_staged_plan accompanied by allow) permits.
      const firstAllow = matched.find((m) => m.effect === 'allow');
      if (firstAllow) {
        const decision: PolicyDecision = {
          allowed: true,
          effect: 'allow',
          matchedRuleId: firstAllow.id,
          matchedRules: matched,
          reason: firstAllow.reason,
          evaluatedRuleCount: evaluatedCount,
          defaultApplied: false,
        };
        this.emitPolicyAudit(ctx, decision);
        return decision;
      }

      // 4. Fallback to defaultEffect (fail-closed 'deny' by default).
      const allowedByDefault = this.defaultEffect === 'allow';
      const decision: PolicyDecision = {
        allowed: allowedByDefault,
        effect: this.defaultEffect,
        matchedRuleId: null,
        matchedRules: matched,
        reason: allowedByDefault
          ? 'Allowed by default policy.'
          : `Denied by fail-closed default policy for tool "${ctx.toolName}".`,
        evaluatedRuleCount: evaluatedCount,
        defaultApplied: true,
      };
      this.emitPolicyAudit(ctx, decision);
      return decision;
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      const failClosedDecision: PolicyDecision = {
        allowed: false,
        effect: 'deny',
        matchedRuleId: 'system:evaluator-error-fail-closed',
        matchedRules: [],
        reason: `Policy evaluation failed closed due to internal rule error: ${errMsg}`,
        evaluatedRuleCount: 0,
        defaultApplied: false,
      };
      this.emitPolicyAudit(ctx, failClosedDecision);
      return failClosedDecision;
    }
  }

  private emitPolicyAudit(ctx: PolicyEvaluationContext, decision: PolicyDecision): void {
    if (!this.auditPublisher) return;
    if (decision.allowed && !this.auditAllows) return;

    const target = [ctx.toolName, ctx.action, ctx.workspaceSlug ?? ctx.repo ?? ctx.planId]
      .filter(Boolean)
      .join(':');

    this.auditPublisher.emit({
      actor: ctx.actor,
      action: decision.allowed
        ? 'policy.allowed'
        : decision.effect === 'require_staged_plan'
          ? 'policy.require_staged_plan'
          : 'policy.denied',
      target,
      status: decision.allowed ? 'success' : 'denied',
      category: 'policy',
      severity: decision.allowed ? 'info' : 'high',
      clientId: ctx.clientId,
      details: {
        tool: ctx.toolName,
        ...(ctx.action ? { tool_action: ctx.action } : {}),
        effect: decision.effect,
        matched_rule_id: decision.matchedRuleId,
        reason: decision.reason,
        default_applied: decision.defaultApplied,
      },
    });
  }
}

/**
 * Factory constructing a fail-closed Bastion `PolicyEvaluator` preloaded with the 10-tool
 * architectural guardrails plus optional custom operator rules from JSON or file.
 */
export function createBastionPolicyEvaluator(
  options: {
    rules?: PolicyRule[];
    policyJson?: string;
    policyFile?: string;
    combiningAlgorithm?: PolicyCombiningAlgorithm;
    requireExplicitScopes?: boolean;
    auditPublisher?: AuditEventPublisher;
    auditAllows?: boolean;
  } = {},
): PolicyEvaluator {
  const customRules = loadPolicyRulesFromSources({
    rules: options.rules,
    policyJson: options.policyJson,
    policyFile: options.policyFile,
  });

  return new PolicyEvaluator({
    rules: customRules,
    includeBuiltinRules: true,
    combiningAlgorithm: options.combiningAlgorithm ?? 'deny-overrides',
    defaultEffect: 'deny',
    requireExplicitScopes: options.requireExplicitScopes ?? false,
    auditPublisher: options.auditPublisher,
    auditAllows: options.auditAllows ?? false,
  });
}
