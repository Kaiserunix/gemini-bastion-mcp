/**
 * Interactive 1-Gate Blast-Radius Flow Simulator Scenarios
 * Grounded in src/mcp/tools/*.ts, src/core/gitSnapshot.ts, and src/core/validationPipeline.ts
 */
export const PIPELINE_NODES = [
  {
    id: 'client',
    labelEn: '1. Web / Mobile AI',
    labelZh: '1. 网页/移动端 AI',
    subEn: 'Gemini / Claude / ChatGPT',
    subZh: 'Gemini / Claude / ChatGPT',
  },
  {
    id: 'auth',
    labelEn: '2. OAuth 2.1 + Origin',
    labelZh: '2. OAuth 2.1 鉴权',
    subEn: 'RFC 8707 + Bearer Scope',
    subZh: 'RFC 8707 + 作用域校验',
  },
  {
    id: 'sandbox',
    labelEn: '3. Tier 1/2 Sandbox',
    labelZh: '3. Tier 1/2 隔离沙盒',
    subEn: 'Always Allow · 0 Popups',
    subZh: '始终允许 · 0 弹窗自治',
  },
  {
    id: 'gate',
    labelEn: '4. Single Approval Gate',
    labelZh: '4. 唯一人工审批闸门',
    subEn: 'Tool #10 publish_changes',
    subZh: '仅 #10 publish_changes',
  },
  {
    id: 'external',
    labelEn: '5. Audited External Exit',
    labelZh: '5. 受审计外部目标',
    subEn: 'GitHub / CF / MCP-2 + Audit',
    subZh: 'GitHub / CF / MCP-2 + 审计',
  },
];

export const GATE_SCENARIOS = [
  {
    id: 'pr_flow',
    tabEn: '🚀 Code Patch → Feature PR',
    tabZh: '🚀 沙盒改码 → 提分支 PR',
    steps: [
      {
        tool: 'code_explore',
        tierBadge: '🟢 Tier 1 · Always Allow',
        popupCount: 0,
        activeNode: 'sandbox',
        passedNodes: ['client', 'auth'],
        kind: 'normal',
        summaryEn: 'Search rate-limiter middleware via ripgrep with sensitive globs excluded',
        summaryZh: '使用 ripgrep 检索限流中间件，自动排除 .env/*.pem 等敏感文件',
        explainEn:
          'Client invokes code_explore(mode="search"). Because Tools 1–9 have destructiveHint: false, Web Gemini / Claude runs it autonomously with zero confirmation popups.',
        explainZh:
          '客户端调用 code_explore(mode="search")。由于工具 1–9 均标记为非破坏性 (destructiveHint: false)，AI 客户端直接静默放行，零弹窗打扰。',
        requestJson: `{
  "tool": "code_explore",
  "arguments": {
    "mode": "search",
    "slug": "bastion-api",
    "query": "IpRateLimiter",
    "glob": "src/**/*.ts"
  }
}`,
        stateJson: `OAuth Scope : mcp:read (verified for https://mcp.example.com/mcp)
Sandbox Env : UID 1002 · !*.pem !.env* !.dev.vars* excluded
Client UX   : 0 approval popups`,
      },
      {
        tool: 'code_patch',
        tierBadge: '🟢 Tier 1 · Always Allow',
        popupCount: 0,
        activeNode: 'sandbox',
        passedNodes: ['client', 'auth'],
        kind: 'normal',
        summaryEn: 'Atomic hunk edit + temporary GIT_INDEX_FILE snapshot + L0/L1 validation',
        summaryZh: '多文件原子补丁 + 临时 GIT_INDEX_FILE 无损快照 + L0/L1 自动验证',
        explainEn:
          'Before touching disk, code_patch snapshots tracked and untracked files into refs/mcp-checkpoints/* via a temporary GIT_INDEX_FILE, applies exact hunks, and runs L0 (tsc --noEmit) + L1 (vitest).',
        explainZh:
          '写入磁盘前，code_patch 通过临时 GIT_INDEX_FILE 将工作区完整快照至 refs/mcp-checkpoints/*，完成原子替换后立即运行 L0 类型检查与 L1 关联单测。',
        requestJson: `{
  "tool": "code_patch",
  "arguments": {
    "action": "patch",
    "slug": "bastion-api",
    "edits": [{
      "path": "src/auth/rateLimit.ts",
      "hunks": [{ "search": "maxAttempts = 20", "replace": "maxAttempts = 15", "line_hint": 18 }]
    }],
    "rollback_on_failure": true
  }
}`,
        stateJson: `Checkpoint  : cp_20261121_8a4f (refs/mcp-checkpoints/cp_20261121_8a4f)
Validation  : L0 tsc --noEmit PASS | L1 vitest PASS (14/14)
Audit Table : action="code_patch.patch" status="success"`,
      },
      {
        tool: 'workspace_exec',
        tierBadge: '🟢 Tier 1 · Always Allow',
        popupCount: 0,
        activeNode: 'sandbox',
        passedNodes: ['client', 'auth'],
        kind: 'normal',
        summaryEn: 'Run integration suite in zero-secret sandbox (auto-promotes if >15s)',
        summaryZh: '在零密钥沙盒内跑集成测试（超 15 秒无损自动晋升后台 Job）',
        explainEn:
          'workspace_exec strips GH_TOKEN, CLOUDFLARE_*, and OAUTH_SIGNING_SECRET via buildSandboxedEnv(). Finishes in 4.2s synchronously (or promotes to SQLite jobs if >15s). Still 0 popups!',
        explainZh:
          'workspace_exec 通过 buildSandboxedEnv() 剥离全部网关密钥，4.2 秒内同步返回脱敏结果（若超 15 秒则自动转入 SQLite 后台任务），全程依然 0 弹窗。',
        requestJson: `{
  "tool": "workspace_exec",
  "arguments": {
    "slug": "bastion-api",
    "command": "npm",
    "args": ["test"],
    "wait_ms": 12000
  }
}`,
        stateJson: `Process UID : 1002 (worker) · /data 0700 unreachable
Env Stripped: GH_TOKEN, CLOUDFLARE_*, OAUTH_SIGNING_SECRET -> [STRIPPED]
Exit Status : 0 (4210ms) · SecretScrubber: clean`,
      },
      {
        tool: 'publish_changes',
        tierBadge: '🔴 Tier 3 · Single Approval Gate',
        popupCount: 1,
        activeNode: 'gate',
        passedNodes: ['client', 'auth', 'sandbox', 'external'],
        kind: 'gate',
        summaryEn: 'Human approves ONCE → pushes feature branch & opens Draft GitHub PR',
        summaryZh: '人工仅在此审批 1 次 → 推送特性分支并创建 GitHub Draft PR',
        explainEn:
          'The ONLY prompt in your chat session! publish_changes re-verifies L0/L1 on changed files, confirms branch_name ("feat/tighten-dcr-limit") is not main/master, scans diffs for secrets, pushes via gateway Octokit, and logs to audit_logs.',
        explainZh:
          '整场对话唯一的审批弹窗！publish_changes 再次校验变更文件、确认目标分支非 main/master、扫描 Diff 无密钥泄漏后，由网关代签推送并创建 PR，写入审计日志与 Webhook。',
        requestJson: `{
  "tool": "publish_changes",
  "arguments": {
    "action": "github_pr",
    "slug": "bastion-api",
    "repo": "Kaiserunix/bastion-api",
    "branch_name": "feat/tighten-dcr-limit",
    "title": "security(auth): tighten DCR rate limit window",
    "draft": true
  }
}`,
        stateJson: `Human Gate  : 1 approval prompt (destructiveHint: true, openWorldHint: true)
Branch Guard: "feat/tighten-dcr-limit" != default_branch ("main") ✓
Audit & Hook: publish_changes.github_pr -> PR #42 created · Webhook sent`,
      },
    ],
  },
  {
    id: 'cf_plan',
    tabEn: '☁️ Two-Phase Cloudflare DNS / D1',
    tabZh: '☁️ 两阶段 Cloudflare 变更预演',
    steps: [
      {
        tool: 'infra_inspect',
        tierBadge: '🟢 Tier 1 · Always Allow',
        popupCount: 0,
        activeNode: 'sandbox',
        passedNodes: ['client', 'auth'],
        kind: 'normal',
        summaryEn: 'Inspect live Cloudflare DNS records using CLOUDFLARE_READONLY_API_TOKEN',
        summaryZh: '使用只读 Token (CLOUDFLARE_READONLY_API_TOKEN) 巡检线上 DNS 记录',
        explainEn:
          'infra_inspect uses the scoped read-only Cloudflare token to list current zone records without exposing write credentials, wrapping external output in untrusted-content markers.',
        explainZh:
          'infra_inspect 优先使用只读权限的 CLOUDFLARE_READONLY_API_TOKEN 查询当前解析记录，外部输出自动加装不可信数据边界标记。',
        requestJson: `{
  "tool": "infra_inspect",
  "arguments": {
    "action": "dns_records",
    "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
    "name": "api-canary.example.com"
  }
}`,
        stateJson: `Token Used  : CLOUDFLARE_READONLY_API_TOKEN (readOnlyHint: true)
Boundary    : Wrapped as untrusted external data
External Mut: 0 writes · 0 popups`,
      },
      {
        tool: 'stage_mutation_plan',
        tierBadge: '🟡 Tier 2 · Stage Only (0 Writes)',
        popupCount: 0,
        activeNode: 'sandbox',
        passedNodes: ['client', 'auth'],
        kind: 'normal',
        summaryEn: 'Capture rollback_payload snapshot & stage 15-minute TTL plan_id in SQLite',
        summaryZh: '抓取变更前快照 rollback_payload，生成 15 分钟有效期 plan_id',
        explainEn:
          'stage_mutation_plan fetches the current DNS record state for rollback_payload, renders a human-readable diff, and stores plan_91c0e4 in SQLite mutation_plans (expires in 900s). Zero external writes occur.',
        explainZh:
          'stage_mutation_plan 自动读取线上旧记录构建回滚载荷 rollback_payload，输出可读 Diff 并写入 SQLite mutation_plans（默认 900 秒过期），不触发任何外部写入。',
        requestJson: `{
  "tool": "stage_mutation_plan",
  "arguments": {
    "target": "cloudflare",
    "mutation_type": "dns_record_update",
    "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
    "record_id": "rec_77ab19",
    "record": { "type": "A", "name": "api-canary.example.com", "content": "198.51.100.42", "proxied": true }
  }
}`,
        stateJson: `SQLite Plan : plan_91c0e4 (status="staged", TTL=900s)
Rollback    : Captured prior A -> 198.51.100.10 (proxied=true)
External Mut: 0 writes · Safe for Always Allow`,
      },
      {
        tool: 'publish_changes',
        tierBadge: '🔴 Tier 3 · Single Approval Gate',
        popupCount: 1,
        activeNode: 'gate',
        passedNodes: ['client', 'auth', 'sandbox', 'external'],
        kind: 'gate',
        summaryEn: 'Human reviews diff & approves execute_staged_plan (instant rollback ready)',
        summaryZh: '人工核对可读 Diff 后批准执行计划（随时支持 rollback_plan 一键回滚）',
        explainEn:
          'You review the exact staged diff in chat and approve publish_changes(action="execute_staged_plan"). The gateway atomically claims the non-expired plan_id, applies the DNS update, and retains rollback_payload for instant undo.',
        explainZh:
          '您在聊天窗口核对清晰的变更 Diff 后点击一次确认，网关原子消费未过期的 plan_id 执行变更，并保留 rollback_payload 支持随时一键回滚。',
        requestJson: `{
  "tool": "publish_changes",
  "arguments": {
    "action": "execute_staged_plan",
    "plan_id": "plan_91c0e4"
  }
}`,
        stateJson: `Plan Claim  : status="staged" -> "executed" (atomic SQLite transition)
Undo Ready  : publish_changes(action="rollback_plan", plan_id="plan_91c0e4")
Audit Table : action="publish_changes.execute_staged_plan" status="success"`,
      },
    ],
  },
  {
    id: 'codex_ops',
    tabEn: '🤖 Async Codex + MCP-2 Sidecar',
    tabZh: '🤖 Codex 异步线程 + MCP-2 联邦',
    steps: [
      {
        tool: 'dispatch_runner',
        tierBadge: '🟢 Tier 1 · Always Allow',
        popupCount: 0,
        activeNode: 'sandbox',
        passedNodes: ['client', 'auth'],
        kind: 'normal',
        summaryEn: 'Launch background @openai/codex-sdk write thread with token/time budgets',
        summaryZh: '启动后台 @openai/codex-sdk 写线程（自动打快照 + Token/时长预算）',
        explainEn:
          'dispatch_runner creates a pre-run GIT_INDEX_FILE checkpoint and starts a background Codex SDK thread (default model gpt-5.3-codex) returning job_id immediately so mobile browsers never time out.',
        explainZh:
          'dispatch_runner 自动创建运行前快照并启动后台 @openai/codex-sdk 线程，立即返回 job_id，手机端即使切后台或锁屏也绝不断连。',
        requestJson: `{
  "tool": "dispatch_runner",
  "arguments": {
    "mode": "codex_write",
    "slug": "edge-worker",
    "objective": "Add structured request-id logging and unit tests",
    "reasoning_effort": "high",
    "max_duration_sec": 300
  }
}`,
        stateJson: `Job Queued  : job_6d21f09a8b12c4e1 (runner="codex_write")
Checkpoint  : cp_20261121_codex_pre · Budget: 200,000 tokens / 300s
Webhook     : Will POST scrubbed summary on completion`,
      },
      {
        tool: 'job_status',
        tierBadge: '🟢 Tier 1 · Always Allow',
        popupCount: 0,
        activeNode: 'sandbox',
        passedNodes: ['client', 'auth'],
        kind: 'normal',
        summaryEn: 'Poll incremental events (since_seq), token usage & live git status -sb',
        summaryZh: '增量拉取任务事件流、Token 消耗与实时工作区 git status -sb',
        explainEn:
          'job_status streams incremental events, reports codex_thread_id (reusable via resume_thread_id), and shows live git status -sb. Setting cancel=true triggers AbortController + process-group kill.',
        explainZh:
          'job_status 增量返回事件流、codex_thread_id（后续可通过 resume_thread_id 续接上下文）及工作区实时变更；传入 cancel=true 可终止进程组。',
        requestJson: `{
  "tool": "job_status",
  "arguments": {
    "job_id": "job_6d21f09a8b12c4e1",
    "since_seq": 4
  }
}`,
        stateJson: `Job Status  : completed · Thread: thread_cx_8821a
Git Status  : ## main...origin/main / M src/index.ts / A test/logger.test.ts
Tokens Used : input=11,240 · output=2,190`,
      },
      {
        tool: 'stage_mutation_plan',
        tierBadge: '🟡 Tier 2 · Stage Only (0 Writes)',
        popupCount: 0,
        activeNode: 'sandbox',
        passedNodes: ['client', 'auth'],
        kind: 'normal',
        summaryEn: 'Stage downstream MCP-2 mutating tool on internal Docker ops_net',
        summaryZh: '对内网 ops_net 上的下游 MCP-2 变更工具生成预演计划',
        explainEn:
          'Downstream MCP-2 tools listed in mutatingTools cannot be called in infra_inspect; they must be staged with an explicit audit reason via stage_mutation_plan.',
        explainZh:
          '下游 MCP-2 配置在 mutatingTools 中的写工具严禁由 infra_inspect 直接调用，必须附带 reason 经由 stage_mutation_plan 预演暂存。',
        requestJson: `{
  "tool": "stage_mutation_plan",
  "arguments": {
    "target": "downstream_mcp",
    "server_name": "ops-ssh",
    "tool_name": "reload_nginx_canary",
    "args": { "host": "canary-01.internal" },
    "reason": "Reload canary proxy after Worker preview verification"
  }
}`,
        stateJson: `Target Svc  : downstream_mcp:ops-ssh (internal: true ops_net)
Policy Check: "reload_nginx_canary" in mutatingTools ✓ (not in deniedTools)
Staged Plan : plan_ops_4410 (15m TTL, 0 external writes yet)`,
      },
      {
        tool: 'publish_changes',
        tierBadge: '🔴 Tier 3 · Single Approval Gate',
        popupCount: 1,
        activeNode: 'gate',
        passedNodes: ['client', 'auth', 'sandbox', 'external'],
        kind: 'gate',
        summaryEn: 'Approve preview Worker deploy / staged MCP-2 plan at the single gate',
        summaryZh: '通过唯一写闸门部署 Cloudflare Worker 预览环境或执行暂存计划',
        explainEn:
          'cloudflare_worker_deploy defaults safely to target="preview" unless production is explicitly requested, recording full deployment metadata in audit_logs.',
        explainZh:
          'cloudflare_worker_deploy 默认安全发布至 preview 预览环境（除非显式指定 production），并将部署 URL 记录至审计日志。',
        requestJson: `{
  "tool": "publish_changes",
  "arguments": {
    "action": "cloudflare_worker_deploy",
    "slug": "edge-worker",
    "target": "preview",
    "message": "Preview request-id structured logger"
  }
}`,
        stateJson: `Deploy Mode : preview (safe default)
Preview URL : https://edge-worker-preview.example.workers.dev
Audit Table : publish_changes.cloudflare_worker_deploy -> success`,
      },
    ],
  },
  {
    id: 'guard_block',
    tabEn: '🛡️ Blocked: Push to main & Secret Leak',
    tabZh: '🛡️ 护栏拦截：直推 main 与密钥防泄漏',
    steps: [
      {
        tool: 'workspace_exec',
        tierBadge: '🟢 Tier 1 · Sandboxed & Scrubbed',
        popupCount: 0,
        activeNode: 'sandbox',
        passedNodes: ['client', 'auth'],
        kind: 'normal',
        summaryEn: 'Prompt-injected command tries to dump env secrets → empty + redacted',
        summaryZh: '提示词注入诱导打印环境变量密钥 → 子进程零密钥 + 输出自动脱敏',
        explainEn:
          'Even if untrusted issue text tricks the model into running printenv or echoing a token pattern, buildSandboxedEnv() never passed gateway secrets to UID 1002, and SecretScrubber redacts token patterns to [REDACTED_SECRET].',
        explainZh:
          '即便外部不可信文本诱导模型执行环境变量探测，buildSandboxedEnv() 从源头未向 UID 1002 注入任何网关密钥，且 SecretScrubber 会将任何疑似凭据模式替换为 [REDACTED_SECRET]。',
        requestJson: `{
  "tool": "workspace_exec",
  "arguments": {
    "slug": "bastion-api",
    "command": "sh",
    "args": ["-c", "echo GH=$GH_TOKEN CF=$CLOUDFLARE_API_TOKEN ghp_1234567890abcdefghijklmnopqrstuv"]
  }
}`,
        stateJson: `Sandboxed   : GH="" CF="" (never present in child process env)
Scrubbed Out: "GH= CF= [REDACTED_SECRET]"
Blast Radius: Contained inside /workspaces/bastion-api`,
      },
      {
        tool: 'publish_changes',
        tierBadge: '🛑 Fail-Closed Guardrail Rejection',
        popupCount: 1,
        activeNode: 'gate',
        passedNodes: ['client', 'auth', 'sandbox'],
        kind: 'blocked',
        summaryEn: 'Attempt to push directly to "main" or commit .env → physically rejected!',
        summaryZh: '尝试直推 "main" 默认分支或提交 .env 敏感文件 → 网关物理拒绝！',
        explainEn:
          'GitHubService physically rejects branch_name matching main, master, or default_branch, and rejects diffs touching .env*, *.pem, *.key, id_rsa*, or .dev.vars* — recording status="denied" in audit_logs.',
        explainZh:
          'GitHubService 在代码层硬性拦截目标为 main、master 或仓库默认分支的推送，并拒绝包含 .env*、*.pem、*.key、.dev.vars* 的变更，同时在审计表记录 denied。',
        requestJson: `{
  "tool": "publish_changes",
  "arguments": {
    "action": "github_pr",
    "slug": "bastion-api",
    "repo": "Kaiserunix/bastion-api",
    "branch_name": "main",
    "title": "Hotfix directly on main"
  }
}`,
        stateJson: `Guardrail   : BLOCKED — Direct push to protected branch "main" is prohibited
MCP Output  : { isError: true, content: [{ type: "text", text: "..." }] }
Audit Table : action="publish_changes.github_pr" status="denied"`,
      },
    ],
  },
];
