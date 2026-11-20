import path from 'node:path';
import { Octokit } from 'octokit';
import { wrapUntrustedData } from '../mcp/outputGuard.js';
import type { ScrubberLike } from '../types.js';
import { buildSandboxedEnv, runSubprocess, type ExecResult } from '../utils/exec.js';
import { SecretScrubber } from '../utils/secretScrubber.js';
import { isSensitiveWorkspacePath } from './workspaceLock.js';

const PROTECTED_BRANCH_NAMES = new Set(['main', 'master']);
const MAX_LOG_TAIL_LINES = 150;
const MAX_LOG_TAIL_BYTES = 16_000;
const NULL_DEVICE = process.platform === 'win32' ? 'NUL' : '/dev/null';

const GIT_HARDENING_CONFIG_ARGS = [
  '-c',
  `core.hooksPath=${NULL_DEVICE}`,
  '-c',
  'credential.helper=',
  '-c',
  'http.https://github.com/.followRedirects=false',
];

const GIT_IDENTITY_ENV: Record<string, string> = {
  GIT_AUTHOR_NAME: 'omni-mcp-gateway',
  GIT_AUTHOR_EMAIL: 'gateway@omni.local',
  GIT_COMMITTER_NAME: 'omni-mcp-gateway',
  GIT_COMMITTER_EMAIL: 'gateway@omni.local',
};

function isSensitiveGitPath(relPath: string): boolean {
  const normalized = relPath.trim().replace(/^"|"$/g, '').replace(/\\/g, '/').replace(/^\/+/, '');
  if (!normalized) return false;
  if (isSensitiveWorkspacePath(normalized)) return true;
  const base = path.basename(normalized).toLowerCase().replace(/[. ]+$/, '');
  return base === '.dev.vars' || base.startsWith('.dev.vars.');
}

function parsePorcelainPaths(statusOutput: string): string[] {
  const paths: string[] = [];
  for (const rawLine of statusOutput.split(/\r?\n/)) {
    if (rawLine.length < 4) continue;
    let filePart = rawLine.slice(3).trim();
    const arrowIdx = filePart.indexOf(' -> ');
    if (arrowIdx !== -1) {
      filePart = filePart.slice(arrowIdx + 4).trim();
    }
    if (filePart.startsWith('"') && filePart.endsWith('"')) {
      filePart = filePart.slice(1, -1);
    }
    if (filePart) paths.push(filePart);
  }
  return paths;
}

const DIFF_SECRET_PATTERNS: RegExp[] = [
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{16,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  /\bsk-(?:proj-|svcacct-|admin-|ant-)?[A-Za-z0-9_-]{20,}\b/,
  /\bcfut_[A-Za-z0-9_-]{16,}\b/,
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
];

export class ProtectedBranchError extends Error {
  constructor(branchName: string, defaultBranch?: string) {
    const reason = defaultBranch
      ? `matches protected/default branch "${defaultBranch}"`
      : 'is a protected default branch';
    super(`Direct push to "${branchName}" is strictly blocked (${reason}). Use a feature branch instead.`);
    this.name = 'ProtectedBranchError';
  }
}

export interface OctokitRestLike {
  pulls: {
    get(params: {
      owner: string;
      repo: string;
      pull_number: number;
      mediaType?: { format: string };
    }): Promise<{ data: unknown }>;
    list(params: {
      owner: string;
      repo: string;
      head?: string;
      state?: 'open' | 'closed' | 'all';
      per_page?: number;
    }): Promise<{ data: Array<{ number: number; html_url: string; state: string; draft?: boolean }> }>;
    listFiles(params: {
      owner: string;
      repo: string;
      pull_number: number;
      per_page?: number;
    }): Promise<{
      data: Array<{
        filename: string;
        status: string;
        additions: number;
        deletions: number;
        changes: number;
        patch?: string;
      }>;
    }>;
    create(params: {
      owner: string;
      repo: string;
      title: string;
      body?: string;
      head: string;
      base: string;
      draft?: boolean;
    }): Promise<{ data: { number: number; html_url: string; draft?: boolean; state: string } }>;
    update(params: {
      owner: string;
      repo: string;
      pull_number: number;
      title?: string;
      body?: string;
      state?: 'open' | 'closed';
    }): Promise<{ data: { number: number; html_url: string; draft?: boolean; state: string } }>;
    createReview(params: {
      owner: string;
      repo: string;
      pull_number: number;
      event: 'COMMENT' | 'REQUEST_CHANGES' | 'APPROVE';
      body?: string;
      comments?: Array<{
        path: string;
        body: string;
        line?: number;
        side?: 'LEFT' | 'RIGHT';
        start_line?: number;
        start_side?: 'LEFT' | 'RIGHT';
        position?: number;
      }>;
    }): Promise<{ data: { id: number; html_url: string; state: string } }>;
  };
  issues: {
    get(params: { owner: string; repo: string; issue_number: number }): Promise<{ data: unknown }>;
    listComments(params: {
      owner: string;
      repo: string;
      issue_number: number;
      per_page?: number;
    }): Promise<{ data: Array<Record<string, unknown>> }>;
    createComment(params: {
      owner: string;
      repo: string;
      issue_number: number;
      body: string;
    }): Promise<{ data: { id: number; html_url: string } }>;
  };
  checks: {
    listForRef(params: {
      owner: string;
      repo: string;
      ref: string;
      per_page?: number;
    }): Promise<{ data: { check_runs: Array<Record<string, unknown>> } }>;
  };
  actions: {
    listWorkflowRunsForRepo(params: {
      owner: string;
      repo: string;
      head_sha?: string;
      status?: string;
      per_page?: number;
    }): Promise<{ data: { workflow_runs: Array<Record<string, unknown>> } }>;
    getWorkflowRun(params: {
      owner: string;
      repo: string;
      run_id: number;
    }): Promise<{ data: Record<string, unknown> }>;
    listJobsForWorkflowRun(params: {
      owner: string;
      repo: string;
      run_id: number;
      per_page?: number;
    }): Promise<{ data: { jobs: Array<Record<string, unknown>> } }>;
    downloadJobLogsForWorkflowRun(params: {
      owner: string;
      repo: string;
      job_id: number;
    }): Promise<{ data: unknown }>;
  };
  repos: {
    get(params: {
      owner: string;
      repo: string;
    }): Promise<{ data: { default_branch: string; full_name?: string } }>;
  };
}

export interface OctokitLike {
  rest: OctokitRestLike;
}

export type GitCommandRunner = (args: string[], cwd: string) => Promise<ExecResult>;

export interface GitHubServiceOptions {
  token?: string;
  octokit?: OctokitLike;
  scrubber?: ScrubberLike;
  gitRunner?: GitCommandRunner;
}

export interface PrInspectionResult {
  repo: string;
  number: number;
  state: string;
  draft: boolean;
  htmlUrl: string;
  author: string;
  headBranch: string;
  headSha: string;
  baseBranch: string;
  titleWrapped: string;
  bodyWrapped: string;
  changedFiles: Array<{
    filename: string;
    status: string;
    additions: number;
    deletions: number;
    changes: number;
  }>;
  unifiedDiffWrapped: string;
  checkRuns: Array<{
    name: string;
    status: string;
    conclusion: string | null;
    title: string | null;
    htmlUrl: string | null;
  }>;
  failedActionsLogs: Array<{
    runId: number;
    runName: string;
    jobId: number;
    jobName: string;
    logTailWrapped: string;
  }>;
  summaryText: string;
}

export interface IssueInspectionResult {
  repo: string;
  number: number;
  state: string;
  htmlUrl: string;
  author: string;
  labels: string[];
  titleWrapped: string;
  bodyWrapped: string;
  comments: Array<{
    id: number;
    author: string;
    createdAt: string;
    bodyWrapped: string;
  }>;
  summaryText: string;
}

export interface WorkflowFailureResult {
  mode: 'recent_failures' | 'run_detail';
  repo: string;
  runs?: Array<{
    id: number;
    name: string;
    headBranch: string;
    headSha: string;
    status: string;
    conclusion: string | null;
    event: string;
    createdAt: string;
    htmlUrl: string;
  }>;
  runDetail?: {
    id: number;
    name: string;
    status: string;
    conclusion: string | null;
    headBranch: string;
    headSha: string;
    htmlUrl: string;
    failedJobs: Array<{
      jobId: number;
      jobName: string;
      conclusion: string | null;
      failedSteps: Array<{ name: string; number: number; conclusion: string | null }>;
      logTailWrapped: string;
    }>;
  };
  summaryText: string;
}

export interface CreateOrUpdatePrInput {
  workspacePath: string;
  repo: string;
  branchName: string;
  baseBranch?: string;
  title: string;
  body?: string;
  commitMessage?: string;
  draft?: boolean;
  stageAll?: boolean;
  autoCommit?: boolean;
}

export interface CreateOrUpdatePrResult {
  repo: string;
  prNumber: number;
  url: string;
  branchName: string;
  baseBranch: string;
  draft: boolean;
  updated: boolean;
  committed: boolean;
}

export interface PrReviewCommentInput {
  path: string;
  line?: number;
  side?: 'LEFT' | 'RIGHT';
  start_line?: number;
  start_side?: 'LEFT' | 'RIGHT';
  position?: number;
  body?: string;
  suggestion?: string;
}

export interface SubmitPrReviewInput {
  event: 'COMMENT' | 'REQUEST_CHANGES' | 'APPROVE';
  body?: string;
  comments?: PrReviewCommentInput[];
}

export interface SubmitPrReviewResult {
  repo: string;
  prNumber: number;
  reviewId: number;
  state: string;
  htmlUrl: string;
  commentCount: number;
}

export interface PostCommentResult {
  repo: string;
  issueNumber: number;
  commentId: number;
  htmlUrl: string;
}

/**
 * Parses `owner/repo`, `https://github.com/owner/repo(.git)`, or `git@github.com:owner/repo(.git)`.
 */
export function parseRepoSlug(repo: string): { owner: string; repo: string; fullName: string } {
  const trimmed = repo.trim().replace(/\.git$/i, '').replace(/\/+$/, '');
  const sshMatch = /^git@[^:]+:([^/]+)\/([^/]+)$/.exec(trimmed);
  if (sshMatch) {
    return {
      owner: sshMatch[1],
      repo: sshMatch[2],
      fullName: `${sshMatch[1]}/${sshMatch[2]}`,
    };
  }

  try {
    if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
      const url = new URL(trimmed);
      const parts = url.pathname.split('/').filter(Boolean);
      if (parts.length >= 2) {
        return {
          owner: parts[0],
          repo: parts[1],
          fullName: `${parts[0]}/${parts[1]}`,
        };
      }
    }
  } catch {
    // Fall through to owner/repo check
  }

  const slashMatch = /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/.exec(trimmed);
  if (slashMatch) {
    return {
      owner: slashMatch[1],
      repo: slashMatch[2],
      fullName: `${slashMatch[1]}/${slashMatch[2]}`,
    };
  }

  throw new Error(`Invalid GitHub repository specifier: "${repo}". Expected "owner/repo".`);
}

function normalizeBranchName(branch: string): string {
  return branch.trim().replace(/^refs\/heads\//, '');
}

function assertValidFeatureBranchName(branch: string, defaultBranch?: string): string {
  const normalized = normalizeBranchName(branch);
  if (!normalized) {
    throw new Error('Branch name must not be empty.');
  }
  if (
    /\s/.test(normalized) ||
    normalized.includes('..') ||
    normalized.startsWith('-') ||
    normalized.toUpperCase() === 'HEAD'
  ) {
    throw new Error(`Invalid feature branch name: "${normalized}"`);
  }

  const lower = normalized.toLowerCase();
  if (PROTECTED_BRANCH_NAMES.has(lower)) {
    throw new ProtectedBranchError(normalized);
  }
  if (defaultBranch && lower === normalizeBranchName(defaultBranch).toLowerCase()) {
    throw new ProtectedBranchError(normalized, defaultBranch);
  }

  return normalized;
}

function extractTail(text: string, maxLines = MAX_LOG_TAIL_LINES, maxBytes = MAX_LOG_TAIL_BYTES): string {
  const normalized = text.replace(/\r\n/g, '\n');
  const lines = normalized.split('\n');
  const tailLines = lines.slice(-maxLines).join('\n');
  const buf = Buffer.from(tailLines, 'utf8');
  if (buf.length <= maxBytes) {
    return tailLines;
  }
  return buf.subarray(buf.length - maxBytes).toString('utf8');
}

function coerceLogText(data: unknown): string {
  if (typeof data === 'string') return data;
  if (Buffer.isBuffer(data)) return data.toString('utf8');
  if (data instanceof ArrayBuffer) return Buffer.from(data).toString('utf8');
  if (ArrayBuffer.isView(data)) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString('utf8');
  }
  if (data === null || data === undefined) return '';
  return JSON.stringify(data);
}

/**
 * Formats a review comment body, appending a GitHub native ```suggestion``` block when provided.
 */
export function formatReviewCommentBody(body?: string, suggestion?: string): string {
  const trimmedBody = body?.trim() ?? '';
  if (suggestion === undefined) {
    if (!trimmedBody) {
      throw new Error('PR review comment must include either body or suggestion.');
    }
    return trimmedBody;
  }

  const suggestionBlock = `\`\`\`suggestion\n${suggestion.replace(/\r\n/g, '\n')}\n\`\`\``;
  return trimmedBody ? `${trimmedBody}\n\n${suggestionBlock}` : suggestionBlock;
}

/**
 * Service encapsulating read-only GitHub inspection and controlled publishing via Octokit + git.
 */
export class GitHubService {
  private readonly octokit: OctokitLike;
  private readonly token?: string;
  private readonly scrubber: ScrubberLike;
  private readonly gitRunner?: GitCommandRunner;

  constructor(options: GitHubServiceOptions = {}) {
    this.token = options.token;
    this.octokit =
      options.octokit ?? (new Octokit({ auth: options.token }) as unknown as OctokitLike);
    this.scrubber =
      options.scrubber ?? new SecretScrubber({ extraSecrets: options.token ? [options.token] : [] });
    this.gitRunner = options.gitRunner;
  }

  private wrap(sourceLabel: string, text: string): string {
    return wrapUntrustedData(sourceLabel, this.scrubber.scrub(text));
  }

  private async runGit(args: string[], cwd: string, allowTokenAuth = false): Promise<ExecResult> {
    const hardenedArgs = [...GIT_HARDENING_CONFIG_ARGS, ...args];
    if (this.gitRunner) {
      return this.gitRunner(hardenedArgs, cwd);
    }

    const extraEnv: Record<string, string> = { ...GIT_IDENTITY_ENV };
    if (allowTokenAuth && this.token) {
      const basic = Buffer.from(`x-access-token:${this.token}`, 'utf8').toString('base64');
      extraEnv.GIT_CONFIG_COUNT = '1';
      extraEnv.GIT_CONFIG_KEY_0 = 'http.https://github.com/.extraheader';
      extraEnv.GIT_CONFIG_VALUE_0 = `AUTHORIZATION: basic ${basic}`;
    }

    const env = buildSandboxedEnv({ extraEnv });

    return runSubprocess({
      command: 'git',
      args: hardenedArgs,
      cwd,
      env,
      timeoutMs: 60_000,
    });
  }

  private async runGitChecked(args: string[], cwd: string, allowTokenAuth = false): Promise<string> {
    const res = await this.runGit(args, cwd, allowTokenAuth);
    if (res.exitCode !== 0) {
      const detail = this.scrubber.scrub((res.stderr || res.stdout || '').trim());
      throw new Error(`git ${args[0]} failed (exit ${res.exitCode}): ${detail}`);
    }
    return res.stdout;
  }

  /**
   * Read-only PR aggregation: metadata, changed files, unified diff, Check Runs, and failed Actions logs.
   */
  async inspectPr(repoSpec: string, prNumber: number): Promise<PrInspectionResult> {
    const { owner, repo, fullName } = parseRepoSlug(repoSpec);

    const [prResp, filesResp] = await Promise.all([
      this.octokit.rest.pulls.get({ owner, repo, pull_number: prNumber }),
      this.octokit.rest.pulls.listFiles({ owner, repo, pull_number: prNumber, per_page: 100 }),
    ]);

    const pr = prResp.data as Record<string, unknown>;
    const head = (pr.head ?? {}) as Record<string, unknown>;
    const base = (pr.base ?? {}) as Record<string, unknown>;
    const user = (pr.user ?? {}) as Record<string, unknown>;

    const headBranch = String(head.ref ?? '');
    const headSha = String(head.sha ?? '');
    const baseBranch = String(base.ref ?? '');
    const state = String(pr.state ?? 'unknown');
    const draft = Boolean(pr.draft);
    const htmlUrl = String(pr.html_url ?? '');
    const author = String(user.login ?? 'unknown');

    const titleWrapped = this.wrap(`github:pr#${prNumber}:title`, String(pr.title ?? ''));
    const bodyWrapped = this.wrap(`github:pr#${prNumber}:body`, String(pr.body ?? ''));

    const changedFiles = filesResp.data.map((f) => ({
      filename: f.filename,
      status: f.status,
      additions: f.additions,
      deletions: f.deletions,
      changes: f.changes,
    }));

    let rawDiff = '';
    try {
      const diffResp = await this.octokit.rest.pulls.get({
        owner,
        repo,
        pull_number: prNumber,
        mediaType: { format: 'diff' },
      });
      if (typeof diffResp.data === 'string') {
        rawDiff = diffResp.data;
      }
    } catch {
      // Fallback to file patches below
    }

    if (!rawDiff) {
      rawDiff = filesResp.data
        .map((f) => `--- a/${f.filename}\n+++ b/${f.filename}\n${f.patch ?? '[binary or omitted patch]'}`)
        .join('\n\n');
    }

    const unifiedDiffWrapped = this.wrap(`github:pr#${prNumber}:diff`, rawDiff);

    const checkRuns: PrInspectionResult['checkRuns'] = [];
    if (headSha) {
      try {
        const checksResp = await this.octokit.rest.checks.listForRef({
          owner,
          repo,
          ref: headSha,
          per_page: 50,
        });
        for (const cr of checksResp.data.check_runs ?? []) {
          const output = (cr.output ?? {}) as Record<string, unknown>;
          checkRuns.push({
            name: String(cr.name ?? ''),
            status: String(cr.status ?? ''),
            conclusion: cr.conclusion ? String(cr.conclusion) : null,
            title: output.title ? this.scrubber.scrub(String(output.title)) : null,
            htmlUrl: cr.html_url ? String(cr.html_url) : null,
          });
        }
      } catch {
        // Checks API may be unavailable for some tokens/repos
      }
    }

    const failedActionsLogs: PrInspectionResult['failedActionsLogs'] = [];
    if (headSha) {
      try {
        const runsResp = await this.octokit.rest.actions.listWorkflowRunsForRepo({
          owner,
          repo,
          head_sha: headSha,
          per_page: 10,
        });
        const failedRuns = (runsResp.data.workflow_runs ?? []).filter((r) =>
          ['failure', 'timed_out', 'action_required'].includes(String(r.conclusion ?? '')),
        );

        for (const run of failedRuns.slice(0, 3)) {
          const runId = Number(run.id);
          const runName = String(run.name ?? `run-${runId}`);
          const jobsResp = await this.octokit.rest.actions.listJobsForWorkflowRun({
            owner,
            repo,
            run_id: runId,
            per_page: 50,
          });
          const failedJobs = (jobsResp.data.jobs ?? []).filter((j) =>
            ['failure', 'timed_out'].includes(String(j.conclusion ?? '')),
          );
          for (const job of failedJobs.slice(0, 3)) {
            const jobId = Number(job.id);
            const jobName = String(job.name ?? `job-${jobId}`);
            let logText = '';
            try {
              const logResp = await this.octokit.rest.actions.downloadJobLogsForWorkflowRun({
                owner,
                repo,
                job_id: jobId,
              });
              logText = extractTail(coerceLogText(logResp.data));
            } catch (err) {
              logText = `[Unable to download job log: ${err instanceof Error ? err.message : String(err)}]`;
            }
            failedActionsLogs.push({
              runId,
              runName,
              jobId,
              jobName,
              logTailWrapped: this.wrap(`github:actions:run#${runId}:job#${jobId}`, logText),
            });
          }
        }
      } catch {
        // Actions logs may be unavailable
      }
    }

    const filesSummary = changedFiles
      .map((f) => `- ${f.filename} (${f.status}, +${f.additions}/-${f.deletions})`)
      .join('\n');
    const checksSummary =
      checkRuns.length > 0
        ? checkRuns.map((c) => `- ${c.name}: ${c.status} (${c.conclusion ?? 'pending'})`).join('\n')
        : '(none)';
    const logsSummary =
      failedActionsLogs.length > 0
        ? failedActionsLogs
            .map((l) => `### Failed Job: ${l.runName} / ${l.jobName} (run=${l.runId}, job=${l.jobId})\n${l.logTailWrapped}`)
            .join('\n\n')
        : '(no failed Actions logs)';

    const summaryText = [
      `# Pull Request ${fullName}#${prNumber}`,
      `State: ${state}${draft ? ' (draft)' : ''} | Author: ${author} | ${headBranch} -> ${baseBranch}`,
      `URL: ${htmlUrl}`,
      '',
      '## Title',
      titleWrapped,
      '',
      '## Body',
      bodyWrapped,
      '',
      `## Changed Files (${changedFiles.length})`,
      filesSummary || '(none)',
      '',
      '## Check Runs',
      checksSummary,
      '',
      '## Failed Actions Log Tail',
      logsSummary,
      '',
      '## Unified Diff',
      unifiedDiffWrapped,
    ].join('\n');

    return {
      repo: fullName,
      number: prNumber,
      state,
      draft,
      htmlUrl,
      author,
      headBranch,
      headSha,
      baseBranch,
      titleWrapped,
      bodyWrapped,
      changedFiles,
      unifiedDiffWrapped,
      checkRuns,
      failedActionsLogs,
      summaryText,
    };
  }

  /**
   * Read-only Issue inspection: metadata, labels, body, and recent comments wrapped in untrusted boundaries.
   */
  async inspectIssue(repoSpec: string, issueNumber: number): Promise<IssueInspectionResult> {
    const { owner, repo, fullName } = parseRepoSlug(repoSpec);

    const [issueResp, commentsResp] = await Promise.all([
      this.octokit.rest.issues.get({ owner, repo, issue_number: issueNumber }),
      this.octokit.rest.issues.listComments({ owner, repo, issue_number: issueNumber, per_page: 30 }),
    ]);

    const issue = issueResp.data as Record<string, unknown>;
    const user = (issue.user ?? {}) as Record<string, unknown>;
    const labelsRaw = Array.isArray(issue.labels) ? issue.labels : [];
    const labels = labelsRaw.map((l) =>
      typeof l === 'string' ? l : String((l as Record<string, unknown>).name ?? ''),
    );

    const state = String(issue.state ?? 'unknown');
    const htmlUrl = String(issue.html_url ?? '');
    const author = String(user.login ?? 'unknown');
    const titleWrapped = this.wrap(`github:issue#${issueNumber}:title`, String(issue.title ?? ''));
    const bodyWrapped = this.wrap(`github:issue#${issueNumber}:body`, String(issue.body ?? ''));

    const comments = commentsResp.data.map((c) => {
      const cId = Number(c.id ?? 0);
      const cUser = ((c.user ?? {}) as Record<string, unknown>).login;
      const cAuthor = String(cUser ?? 'unknown');
      const createdAt = String(c.created_at ?? '');
      return {
        id: cId,
        author: cAuthor,
        createdAt,
        bodyWrapped: this.wrap(
          `github:issue#${issueNumber}:comment#${cId}:${cAuthor}`,
          String(c.body ?? ''),
        ),
      };
    });

    const commentsSection =
      comments.length > 0
        ? comments
            .map((c) => `### Comment #${c.id} by ${c.author} (${c.createdAt})\n${c.bodyWrapped}`)
            .join('\n\n')
        : '(no comments)';

    const summaryText = [
      `# Issue ${fullName}#${issueNumber}`,
      `State: ${state} | Author: ${author} | Labels: ${labels.join(', ') || '(none)'}`,
      `URL: ${htmlUrl}`,
      '',
      '## Title',
      titleWrapped,
      '',
      '## Body',
      bodyWrapped,
      '',
      `## Recent Comments (${comments.length})`,
      commentsSection,
    ].join('\n');

    return {
      repo: fullName,
      number: issueNumber,
      state,
      htmlUrl,
      author,
      labels,
      titleWrapped,
      bodyWrapped,
      comments,
      summaryText,
    };
  }

  /**
   * Read-only Actions workflow failure inspection: lists recent failed runs or inspects failed jobs/logs for a runId.
   */
  async inspectWorkflowFailure(repoSpec: string, runId?: number): Promise<WorkflowFailureResult> {
    const { owner, repo, fullName } = parseRepoSlug(repoSpec);

    if (runId === undefined) {
      const runsResp = await this.octokit.rest.actions.listWorkflowRunsForRepo({
        owner,
        repo,
        status: 'failure',
        per_page: 10,
      });

      const runs = (runsResp.data.workflow_runs ?? []).map((r) => ({
        id: Number(r.id),
        name: String(r.name ?? ''),
        headBranch: String(r.head_branch ?? ''),
        headSha: String(r.head_sha ?? ''),
        status: String(r.status ?? ''),
        conclusion: r.conclusion ? String(r.conclusion) : null,
        event: String(r.event ?? ''),
        createdAt: String(r.created_at ?? ''),
        htmlUrl: String(r.html_url ?? ''),
      }));

      const summaryText = [
        `# Recent Failed Workflow Runs (${fullName})`,
        runs.length > 0
          ? runs
              .map(
                (r) =>
                  `- Run #${r.id} "${r.name}" [${r.conclusion ?? r.status}] branch=${r.headBranch} sha=${r.headSha.slice(0, 7)} (${r.createdAt}) ${r.htmlUrl}`,
              )
              .join('\n')
          : '(no recent failed workflow runs found)',
      ].join('\n');

      return {
        mode: 'recent_failures',
        repo: fullName,
        runs,
        summaryText,
      };
    }

    const [runResp, jobsResp] = await Promise.all([
      this.octokit.rest.actions.getWorkflowRun({ owner, repo, run_id: runId }),
      this.octokit.rest.actions.listJobsForWorkflowRun({ owner, repo, run_id: runId, per_page: 50 }),
    ]);

    const run = runResp.data;
    const allJobs = jobsResp.data.jobs ?? [];
    const targetJobs = allJobs.filter((j) =>
      ['failure', 'timed_out', 'cancelled'].includes(String(j.conclusion ?? '')),
    );
    const jobsToInspect = targetJobs.length > 0 ? targetJobs : allJobs.slice(0, 3);

    const failedJobs: NonNullable<WorkflowFailureResult['runDetail']>['failedJobs'] = [];
    for (const job of jobsToInspect) {
      const jobId = Number(job.id);
      const jobName = String(job.name ?? `job-${jobId}`);
      const stepsRaw = Array.isArray(job.steps) ? job.steps : [];
      const failedSteps = stepsRaw
        .filter((s) => (s as Record<string, unknown>).conclusion === 'failure')
        .map((s) => {
          const step = s as Record<string, unknown>;
          return {
            name: String(step.name ?? ''),
            number: Number(step.number ?? 0),
            conclusion: step.conclusion ? String(step.conclusion) : null,
          };
        });

      let logText = '';
      try {
        const logResp = await this.octokit.rest.actions.downloadJobLogsForWorkflowRun({
          owner,
          repo,
          job_id: jobId,
        });
        logText = extractTail(coerceLogText(logResp.data));
      } catch (err) {
        logText = `[Unable to download job log: ${err instanceof Error ? err.message : String(err)}]`;
      }

      failedJobs.push({
        jobId,
        jobName,
        conclusion: job.conclusion ? String(job.conclusion) : null,
        failedSteps,
        logTailWrapped: this.wrap(`github:actions:run#${runId}:job#${jobId}`, logText),
      });
    }

    const runDetail: NonNullable<WorkflowFailureResult['runDetail']> = {
      id: Number(run.id ?? runId),
      name: String(run.name ?? ''),
      status: String(run.status ?? ''),
      conclusion: run.conclusion ? String(run.conclusion) : null,
      headBranch: String(run.head_branch ?? ''),
      headSha: String(run.head_sha ?? ''),
      htmlUrl: String(run.html_url ?? ''),
      failedJobs,
    };

    const summaryText = [
      `# Workflow Run #${runDetail.id} (${fullName})`,
      `Name: ${runDetail.name} | Status: ${runDetail.status} | Conclusion: ${runDetail.conclusion ?? 'none'}`,
      `Branch: ${runDetail.headBranch} | SHA: ${runDetail.headSha} | URL: ${runDetail.htmlUrl}`,
      '',
      ...failedJobs.map((j) =>
        [
          `## Job #${j.jobId}: ${j.jobName} (${j.conclusion ?? 'unknown'})`,
          `Failed steps: ${j.failedSteps.map((s) => `${s.number}. ${s.name}`).join(', ') || '(none)'}`,
          j.logTailWrapped,
        ].join('\n'),
      ),
    ].join('\n');

    return {
      mode: 'run_detail',
      repo: fullName,
      runDetail,
      summaryText,
    };
  }

  /**
   * Controlled publishing (used ONLY by publish_changes):
   * Hard-blocks direct push to main, master, or repo's default_branch.
   * Checks out a feature branch, commits changes, verifies diff secret safety,
   * pushes the feature branch, and creates or updates a Pull Request (default draft: true).
   */
  async createOrUpdatePr(input: CreateOrUpdatePrInput): Promise<CreateOrUpdatePrResult> {
    const { owner, repo, fullName } = parseRepoSlug(input.repo);

    // 1. Pre-check static protected names before any git or API mutation
    assertValidFeatureBranchName(input.branchName);

    // 2. Fetch repository default_branch and enforce hard block against it
    const repoResp = await this.octokit.rest.repos.get({ owner, repo });
    const defaultBranch = repoResp.data.default_branch;
    const branchName = assertValidFeatureBranchName(input.branchName, defaultBranch);
    const baseBranch = normalizeBranchName(input.baseBranch || defaultBranch);

    if (branchName.toLowerCase() === baseBranch.toLowerCase()) {
      throw new ProtectedBranchError(branchName, baseBranch);
    }

    // 3. Checkout or create feature branch in workspace
    const verifyRef = await this.runGit(
      ['show-ref', '--verify', '--quiet', `refs/heads/${branchName}`],
      input.workspacePath,
    );
    if (verifyRef.exitCode === 0) {
      await this.runGitChecked(['checkout', branchName], input.workspacePath);
    } else {
      await this.runGitChecked(['checkout', '-b', branchName], input.workspacePath);
    }

    // Double-check active HEAD branch is not protected before committing/pushing
    const activeBranch = normalizeBranchName(
      await this.runGitChecked(['rev-parse', '--abbrev-ref', 'HEAD'], input.workspacePath),
    );
    assertValidFeatureBranchName(activeBranch, defaultBranch);

    // 4. Commit dirty changes if autoCommit !== false (after blocking sensitive files)
    let committed = false;
    if (input.autoCommit !== false) {
      const statusOut = await this.runGitChecked(['status', '--porcelain'], input.workspacePath);
      const dirtyPaths = parsePorcelainPaths(statusOut);
      for (const p of dirtyPaths) {
        if (isSensitiveGitPath(p)) {
          throw new Error(
            `Refusing to commit/push sensitive file "${p}" to GitHub.`,
          );
        }
      }
      if (statusOut.trim().length > 0) {
        if (input.stageAll !== false) {
          await this.runGitChecked(['add', '-A'], input.workspacePath);
        }
        const commitMsg = input.commitMessage?.trim() || input.title;
        await this.runGitChecked(['commit', '-m', commitMsg], input.workspacePath);
        committed = true;
      }
    }

    // 5. Sensitive-file & multi-commit history secret-scan (fail-closed if truncated or errored)
    const headCheck = await this.runGit(['rev-parse', '--verify', 'HEAD'], input.workspacePath);
    if (headCheck.exitCode === 0) {
      let baseRange = '';
      const localBase = await this.runGit(['rev-parse', '--verify', baseBranch], input.workspacePath);
      if (localBase.exitCode === 0) {
        baseRange = `${baseBranch}..HEAD`;
      } else {
        const originBase = await this.runGit(
          ['rev-parse', '--verify', `origin/${baseBranch}`],
          input.workspacePath,
        );
        if (originBase.exitCode === 0) {
          baseRange = `origin/${baseBranch}..HEAD`;
        }
      }

      const logNameArgs = baseRange
        ? ['log', '--name-only', '--format=', baseRange]
        : ['log', '--name-only', '--format=', '-n', '20', 'HEAD'];
      const nameOnlyRes = await this.runGit(logNameArgs, input.workspacePath);
      if (nameOnlyRes.exitCode !== 0 || nameOnlyRes.truncated) {
        throw new Error(
          'Outgoing git filename scan failed or was truncated; refusing to push.',
        );
      }
      for (const p of nameOnlyRes.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)) {
        if (isSensitiveGitPath(p)) {
          throw new Error(
            `Refusing to push sensitive file "${p}" to GitHub.`,
          );
        }
      }

      const logPatchArgs = baseRange
        ? ['log', '-p', '--format=', baseRange]
        : ['log', '-p', '--format=', '-n', '20', 'HEAD'];
      const patchRes = await this.runGit(logPatchArgs, input.workspacePath);
      if (patchRes.exitCode !== 0 || patchRes.truncated) {
        throw new Error(
          'Outgoing git commit history secret-scan failed or was truncated; refusing to push.',
        );
      }

      const addedLines = patchRes.stdout
        .split('\n')
        .filter((line) => line.startsWith('+') && !line.startsWith('+++'))
        .join('\n');

      for (const pattern of DIFF_SECRET_PATTERNS) {
        if (pattern.test(addedLines)) {
          throw new Error(
            'Secret-scan check failed: potential credential/private key detected in outgoing commit history. Aborting push.',
          );
        }
      }
      if (this.scrubber.scrub(addedLines) !== addedLines) {
        throw new Error(
          'Secret-scan check failed: known gateway secret detected in outgoing commit history. Aborting push.',
        );
      }
    }

    // 6. Push feature branch directly to canonical GitHub HTTPS URL (never unverified workspace origin)
    const canonicalRemoteUrl = `https://github.com/${owner}/${repo}.git`;
    await this.runGitChecked(
      ['push', canonicalRemoteUrl, `refs/heads/${branchName}:refs/heads/${branchName}`],
      input.workspacePath,
      true,
    );

    // 7. Create or update Pull Request (default draft: true)
    const existing = await this.octokit.rest.pulls.list({
      owner,
      repo,
      head: `${owner}:${branchName}`,
      state: 'open',
      per_page: 5,
    });

    if (existing.data.length > 0) {
      const pr = existing.data[0];
      const updatedPr = await this.octokit.rest.pulls.update({
        owner,
        repo,
        pull_number: pr.number,
        title: input.title,
        body: input.body,
      });
      return {
        repo: fullName,
        prNumber: updatedPr.data.number,
        url: updatedPr.data.html_url,
        branchName,
        baseBranch,
        draft: Boolean(updatedPr.data.draft),
        updated: true,
        committed,
      };
    }

    const draft = input.draft ?? true;
    const createdPr = await this.octokit.rest.pulls.create({
      owner,
      repo,
      title: input.title,
      body: input.body ?? '',
      head: branchName,
      base: baseBranch,
      draft,
    });

    return {
      repo: fullName,
      prNumber: createdPr.data.number,
      url: createdPr.data.html_url,
      branchName,
      baseBranch,
      draft: Boolean(createdPr.data.draft ?? draft),
      updated: false,
      committed,
    };
  }

  /**
   * Submits a formal PR review with optional line-level comments and native ```suggestion``` blocks.
   */
  async submitPrReview(
    repoSpec: string,
    prNumber: number,
    review: SubmitPrReviewInput,
  ): Promise<SubmitPrReviewResult> {
    const { owner, repo, fullName } = parseRepoSlug(repoSpec);

    const formattedComments = (review.comments ?? []).map((c) => {
      const formattedBody = formatReviewCommentBody(c.body, c.suggestion);
      return {
        path: c.path,
        body: formattedBody,
        ...(c.line !== undefined ? { line: c.line } : {}),
        ...(c.side !== undefined ? { side: c.side } : {}),
        ...(c.start_line !== undefined ? { start_line: c.start_line } : {}),
        ...(c.start_side !== undefined ? { start_side: c.start_side } : {}),
        ...(c.position !== undefined ? { position: c.position } : {}),
      };
    });

    const resp = await this.octokit.rest.pulls.createReview({
      owner,
      repo,
      pull_number: prNumber,
      event: review.event,
      ...(review.body !== undefined ? { body: review.body } : {}),
      ...(formattedComments.length > 0 ? { comments: formattedComments } : {}),
    });

    return {
      repo: fullName,
      prNumber,
      reviewId: resp.data.id,
      state: resp.data.state,
      htmlUrl: resp.data.html_url,
      commentCount: formattedComments.length,
    };
  }

  /**
   * Posts a comment on a GitHub Issue or Pull Request.
   */
  async postIssueOrPrComment(
    repoSpec: string,
    issueNumber: number,
    body: string,
  ): Promise<PostCommentResult> {
    const { owner, repo, fullName } = parseRepoSlug(repoSpec);
    const trimmed = body.trim();
    if (!trimmed) {
      throw new Error('Comment body must not be empty.');
    }

    const resp = await this.octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: issueNumber,
      body: trimmed,
    });

    return {
      repo: fullName,
      issueNumber,
      commentId: resp.data.id,
      htmlUrl: resp.data.html_url,
    };
  }
}
