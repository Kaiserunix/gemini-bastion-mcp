/**
 * Exact 10-Tool MCP Contract — aligned 1:1 with src/mcp/tools/*.ts
 */
export const TOOLS = [
  {
    num: 1,
    name: 'workspace_manage',
    tier: 'tier-1',
    tierLabelEn: '🟢 Tier 1 · Always Allow',
    tierLabelZh: '🟢 Tier 1 · 始终允许',
    scope: 'mcp:read | mcp:write',
    readOnlyHint: false,
    destructiveHint: false,
    openWorldHint: false,
    sourceFile: 'src/mcp/tools/workspaceTools.ts',
    actions: 'action: list | sync_github | init_cf_ops | list_checkpoints | rollback',
    descEn:
      'List registered workspaces, sync GitHub repos into /workspaces/{slug}, detect stack & AGENTS.md/CLAUDE.md playbooks, inspect Wrangler ops context, or rollback to a checkpoint (creating a safety snapshot first).',
    descZh:
      '管理已注册沙盒工作区、克隆或同步 GitHub 仓库至 /workspaces/{slug}（自动检测技术栈与 AGENTS.md/CLAUDE.md 规范）、检查 Wrangler 配置，或安全回滚至指定快照。',
  },
  {
    num: 2,
    name: 'code_explore',
    tier: 'tier-1',
    tierLabelEn: '🟢 Tier 1 · Always Allow',
    tierLabelZh: '🟢 Tier 1 · 始终允许',
    scope: 'mcp:read',
    readOnlyHint: true,
    destructiveHint: false,
    openWorldHint: false,
    sourceFile: 'src/mcp/tools/workspaceTools.ts',
    actions: 'mode: pack | search | ast | read_lines | read_artifact | git_diff',
    descEn:
      'Read-only code exploration via repomix packing, ripgrep search, ast-grep structural queries, bounded line-range reader (5MB cap), paginated artifact reader (/data/artifacts), and secret-excluded git_diff.',
    descZh:
      '只读代码探索：支持 repomix 仓库打包、ripgrep 搜索、ast-grep 语法树匹配、行范围读取、超长构件 (/data/artifacts) 分页读取，以及自动排除敏感文件的 git_diff。',
  },
  {
    num: 3,
    name: 'code_patch',
    tier: 'tier-1',
    tierLabelEn: '🟢 Tier 1 · Always Allow',
    tierLabelZh: '🟢 Tier 1 · 始终允许',
    scope: 'mcp:write',
    readOnlyHint: false,
    destructiveHint: false,
    openWorldHint: false,
    sourceFile: 'src/mcp/tools/workspaceTools.ts',
    actions: 'action: patch (edits[].hunks[{search, replace, line_hint}]) | create_or_overwrite | delete_file',
    descEn:
      'Atomic multi-file edits inside /workspaces/{slug} with pre-patch GIT_INDEX_FILE checkpoint, L0/L1/L2 validation pipeline (biome, ruff, tsc, pyright, vitest, pytest), and optional rollback_on_failure.',
    descZh:
      '工作区内多文件原子补丁编辑，自动创建修改前 GIT_INDEX_FILE 无损快照，并联动 L0/L1/L2 语法/类型/单测流水线校验与失败自动回滚。',
  },
  {
    num: 4,
    name: 'workspace_exec',
    tier: 'tier-1',
    tierLabelEn: '🟢 Tier 1 · Always Allow',
    tierLabelZh: '🟢 Tier 1 · 始终允许',
    scope: 'mcp:write',
    readOnlyHint: false,
    destructiveHint: false,
    openWorldHint: false,
    sourceFile: 'src/mcp/tools/execRunnerTools.ts',
    actions: 'slug, command, args?, cwd?, readonly?, wait_ms? (default 12000, max 15000)',
    descEn:
      'Runs a shell command inside /workspaces/{slug} under UID 1002 with buildSandboxedEnv() (zero gateway secrets). Commands running past wait_ms seamlessly auto-promote to a background SQLite job_id.',
    descZh:
      '以 UID 1002 与 buildSandboxedEnv() 零网关密钥环境在工作区内执行命令；超过 wait_ms（默认 12s，最大 15s）未结束时无损晋升为后台 SQLite job_id。',
  },
  {
    num: 5,
    name: 'dispatch_runner',
    tier: 'tier-1',
    tierLabelEn: '🟢 Tier 1 · Always Allow',
    tierLabelZh: '🟢 Tier 1 · 始终允许',
    scope: 'mcp:write',
    readOnlyHint: false,
    destructiveHint: false,
    openWorldHint: false,
    sourceFile: 'src/mcp/tools/execRunnerTools.ts',
    actions: 'mode: codex_readonly | codex_write | shell_task (resume_thread_id?, token_budget?)',
    descEn:
      'Dispatches asynchronous @openai/codex-sdk threads (with pre-run git checkpoint on codex_write and thread resumption) or long background shell_task jobs, firing scrubbed webhooks on finish.',
    descZh:
      '异步派发原生 @openai/codex-sdk 智能体线程（codex_write 自动打快照、支持 resume_thread_id 续接）或长耗时 shell_task，完成后推送脱敏 Webhook。',
  },
  {
    num: 6,
    name: 'job_status',
    tier: 'tier-1',
    tierLabelEn: '🟢 Tier 1 · Always Allow',
    tierLabelZh: '🟢 Tier 1 · 始终允许',
    scope: 'mcp:read (cancel: mcp:write)',
    readOnlyHint: false,
    destructiveHint: false,
    openWorldHint: false,
    sourceFile: 'src/mcp/tools/execRunnerTools.ts',
    actions: 'job_id, since_seq?, cancel?: boolean (AbortController + SIGTERM -> SIGKILL)',
    descEn:
      'Polls incremental job events (since_seq), duration, token usage, codex_thread_id, live workspace git status -sb, and final report — or aborts the process group when cancel=true.',
    descZh:
      '按序号增量轮询异步任务事件流、Token 消耗、codex_thread_id、实时 git status -sb 与最终报告，或传入 cancel=true 强杀整个进程组。',
  },
  {
    num: 7,
    name: 'github_inspect',
    tier: 'tier-1',
    tierLabelEn: '🟢 Tier 1 · Always Allow',
    tierLabelZh: '🟢 Tier 1 · 始终允许',
    scope: 'mcp:read',
    readOnlyHint: true,
    destructiveHint: false,
    openWorldHint: true,
    sourceFile: 'src/mcp/tools/infraPublishTools.ts',
    actions: 'mode: pr | issue | workflow_failure (repo, pr_number? | issue_number? | run_id?)',
    descEn:
      'Strictly read-only GitHub inspection via Octokit (PR metadata/files/diffs/checks, Issue threads, or failed Actions workflow step logs), wrapped in untrusted-data boundaries.',
    descZh:
      '基于 Octokit 的只读 GitHub 巡检（PR 详情/Diff/Checks、Issue 讨论串、workflow_failure 失败日志），外部返回内容均包裹不可信数据边界。',
  },
  {
    num: 8,
    name: 'infra_inspect',
    tier: 'tier-1',
    tierLabelEn: '🟢 Tier 1 · Always Allow',
    tierLabelZh: '🟢 Tier 1 · 始终允许',
    scope: 'mcp:read',
    readOnlyHint: true,
    destructiveHint: false,
    openWorldHint: true,
    sourceFile: 'src/mcp/tools/infraPublishTools.ts',
    actions: 'action: zones | dns_records | workers | pages | kv_namespaces | d1_databases | waf_rules | worker_tail_logs | downstream_list | downstream_call',
    descEn:
      'Read-only Cloudflare resource & tail-log inspection (using CLOUDFLARE_READONLY_API_TOKEN) plus downstream MCP-2 sidecar queries strictly restricted to readonlyTools.',
    descZh:
      '使用只读 Token 巡检 Cloudflare (Zones/DNS/Workers/Pages/KV/D1/WAF/Tail Logs)，并支持调用下游 MCP-2 联邦服务白名单内的 readonlyTools。',
  },
  {
    num: 9,
    name: 'stage_mutation_plan',
    tier: 'tier-2',
    tierLabelEn: '🟡 Tier 2 · Stage Only (0 External Writes)',
    tierLabelZh: '🟡 Tier 2 · 预演暂存（零外部写入）',
    scope: 'mcp:write',
    readOnlyHint: false,
    destructiveHint: false,
    openWorldHint: false,
    sourceFile: 'src/mcp/tools/infraPublishTools.ts',
    actions: 'target: cloudflare (dns_record_* | waf_rule_update | d1_sql_mutation) | downstream_mcp',
    descEn:
      'Captures pre-change live state into rollback_payload, renders a human-readable diff, and persists a 15-minute TTL plan_id in SQLite. Performs zero external mutations.',
    descZh:
      '针对 Cloudflare (DNS/WAF/D1) 或下游 MCP-2 变更工具抓取变更前状态生成回滚快照与可读 Diff，签发 15 分钟 TTL 的 plan_id，零外部写入。',
  },
  {
    num: 10,
    name: 'publish_changes',
    tier: 'tier-3',
    tierLabelEn: '🔴 Tier 3 · Single External Write Gate',
    tierLabelZh: '🔴 Tier 3 · 唯一外部写出口（人工审批闸门）',
    scope: 'mcp:write',
    readOnlyHint: false,
    destructiveHint: true,
    openWorldHint: true,
    sourceFile: 'src/mcp/tools/infraPublishTools.ts',
    actions: 'action: github_pr | github_pr_review | github_comment | cloudflare_worker_deploy | cloudflare_pages_deploy | execute_staged_plan | rollback_plan',
    descEn:
      'The ONLY external mutation exit across the gateway. Runs pre-PR L0/L1 validation, blocks pushes to main/master/default_branch, defaults Worker deploys to preview, executes or rolls back staged plans, and records audit_logs.',
    descZh:
      '全网关唯一的外部写操作总闸门：发 PR 前自动跑 L0/L1 校验并拦截直推 main/master、默认部署 Worker 预览版、执行或一键回滚已暂存计划，并写入审计日志。',
  },
];
