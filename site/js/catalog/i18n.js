/**
 * Bilingual Copy Dictionary (EN / 简体中文) — strictly aligned with src/
 */
export const I18N = {
  en: {
    skip_main: 'Skip to main content',
    nav_why: 'Why It Exists',
    nav_arch: 'Architecture',
    nav_gate: 'Approval-Gate Sim',
    nav_tools: '10 Tools · 1 Gate',
    nav_setup: 'OAuth 2.1 + Tunnel',
    nav_preview: 'UI Previews',
    nav_security: '6-Layer Security',

    hero_title: 'The Self-Hosted OAuth 2.1 MCP Bastion for Web Gemini, Claude & ChatGPT',
    hero_subtitle:
      '10 Tools · 1 Approval Gate · Stateless Streamable HTTP (/mcp) · Codex SDK · Cloudflare & MCP-2 Ops',
    hero_lead:
      'Turn any browser or mobile AI chat into a sandboxed full-stack coding, background @openai/codex-sdk runner, and two-phase Cloudflare operations agent — without 40-tool popup fatigue or gateway secret leakage.',
    cta_setup: 'OAuth 2.1 + Tunnel Walkthrough',
    cta_sim: 'Simulate 1-Gate Flow',
    cta_github: 'View on GitHub',

    stat_1_val: '10 → 1 Gate',
    stat_1_lbl: 'Tools 1–9 Always Allow · #10 Single Write Exit',
    stat_2_val: 'UID 1001 / 1002',
    stat_2_lbl: '0700 /data Control Plane vs 0-Secret Worker',
    stat_3_val: '16 URIs · 8KB State',
    stat_3_lbl: 'Gemini DCR + PKCE S256 + 60s Token Grace',
    stat_4_val: '15s → Async Job',
    stat_4_lbl: 'Auto-Promoted SQLite Jobs + Codex Thread Resume',

    hero_notice:
      'ℹ️ This GitHub Pages portal is the static architecture & interactive setup showcase. The live stateless Streamable HTTP /mcp server and /admin PWA run self-hosted in your own Docker / VPS environment behind Cloudflare Tunnel or HTTPS.',

    why_eyebrow: 'Comparison Matrix',
    why_title: 'Why GeminiBastionMCP Exists',
    why_desc:
      'Connecting Web Gemini (gemini.google.com), Claude.ai, or ChatGPT to real repositories and infrastructure typically fails on strict OAuth 2.1 DCR handshakes, constant approval popups, or child-process secret exposure.',
    cmp_col_cap: 'Capability',
    cmp_col_proxy: 'Generic MCP Aggregators',
    cmp_col_remote: 'Single-Vendor Remote MCPs',
    cmp_col_local: 'Local Stdio Shell MCPs',
    cmp_r1_k: 'Web Gemini (gemini.google.com) OAuth 2.1 DCR',
    cmp_r1_v1:
      '✅ Native (RFC 9728/8414/7591/8707, up to 16 redirect URIs, 8KB state, 60s refresh grace rotation)',
    cmp_r1_v2: '⚠️ Often missing RFC 8707 resource binding or 8KB state storage',
    cmp_r1_v3: '✅ Single-vendor hosted only',
    cmp_r1_v4: '❌ Local desktop stdio only',
    cmp_r2_k: 'Web & Mobile Approval UX',
    cmp_r2_v1:
      '✅ 10 Tools, 1 Approval Gate (Tools 1–9 safe for Always Allow; only publish_changes writes externally)',
    cmp_r2_v2: '❌ Exposes 30–60 granular tools causing constant popup fatigue',
    cmp_r2_v3: '⚠️ Read and write tools mixed across prompts',
    cmp_r2_v4: '❌ Approve every shell command or run wide open',
    cmp_r3_k: 'Sandboxed Test Runner & Background Codex',
    cmp_r3_v1:
      '✅ 15s sync wait auto-promotes to SQLite job_id + native @openai/codex-sdk thread orchestration',
    cmp_r3_v2: '❌ Protocol router only; no git workspace sandbox',
    cmp_r3_v3: '❌ REST API wrapper only; cannot run builds or unit tests',
    cmp_r3_v4: '⚠️ Runs on host OS with no background job promotion',
    cmp_r4_k: 'Zero Gateway Secret Leakage & Undo Checkpoints',
    cmp_r4_v1:
      '✅ UID 1001/1002 split + buildSandboxedEnv() + SecretScrubber + temporary GIT_INDEX_FILE snapshots',
    cmp_r4_v2: '❌ Depends on downstream servers',
    cmp_r4_v3: '✅ Cloud-isolated',
    cmp_r4_v4: '❌ Subprocesses inherit host environment secrets',
    cmp_r5_k: 'Two-Phase Infra Mutations (Plan → Execute → Rollback)',
    cmp_r5_v1:
      '✅ stage_mutation_plan (DNS/WAF/D1 & MCP-2, 15m TTL + rollback snapshot) → publish_changes',
    cmp_r5_v2: '❌ Direct write pass-through',
    cmp_r5_v3: '❌ Immediate external writes',
    cmp_r5_v4: '❌ None',

    arch_eyebrow: 'System Topology',
    arch_title: 'Blast-Radius-Contained Architecture',
    arch_desc:
      'Stateless WebStandardStreamableHTTPServerTransport mounted on Hono (POST /mcp) with strict network & Linux UID separation between the OAuth/SQLite control plane (UID 1001) and the zero-secret execution sandbox (UID 1002).',
    arch_s1_title: 'AI Clients & Zero-Port Edge',
    arch_s1_n1: 'Connected Apps via OAuth 2.1 DCR + PKCE (S256) + Origin check',
    arch_s1_n2: 'Stateless Streamable HTTP (POST /mcp; GET/DELETE -> 405)',
    arch_s1_n3: 'cloudflared on edge_net -> http://gateway:8787 (0 host ports)',
    arch_s2_title: 'Gateway Control Plane',
    arch_s2_n1: 'RFC 9728/8414/8707 + 60s token family rotation + Google/GitHub IdP',
    arch_s2_n2: 'Mode 0700 owned by UID 1001; unreachable by UID 1002 worker',
    arch_s2_n3: 'Redacts credentials across all tool outputs, artifacts, logs & webhooks',
    arch_s3_title: 'Zero-Secret Worker Sandbox',
    arch_s3_n1: 'Non-destructive GIT_INDEX_FILE refs/mcp-checkpoints/* + L0/L1/L2 checks',
    arch_s3_n2: 'Strips GH_TOKEN, CLOUDFLARE_*, OAUTH_SIGNING_SECRET, ADMIN_PASSWORD_HASH',
    arch_s3_n3: 'codex_readonly / codex_write / shell_task with AbortController kill',
    arch_s4_title: 'Audited External Exit',
    arch_s4_n1: 'Feature-branch PRs, reviews & comments; main/master push blocked',
    arch_s4_n2: 'Read-only inspect vs staged DNS/WAF/D1 plans & preview Worker deploys',
    arch_s4_n3: 'Internal ops_net sidecars enforcing readonlyTools vs mutatingTools',

    gate_eyebrow: 'Interactive Blast-Radius Walkthrough',
    gate_title: 'Interactive Approval-Gate Flow Simulator',
    gate_desc:
      'Select a real workflow below and step through how Tools 1–9 execute autonomously inside the sandbox with 0 confirmation popups, while Tool #10 (publish_changes) acts as the single human-verified exit.',
    sim_prev: '← Prev Step',
    sim_next: 'Next Step →',
    sim_auto: '▶ Auto-Step',
    sim_stop: '⏸ Pause',
    sim_req_lbl: 'MCP Tool Call Payload',
    sim_state_lbl: 'Gateway Security, SQLite & Audit State',

    tools_eyebrow: '10-Tool MCP Contract (Verified Against src/)',
    tools_title: '10 Tools, 1 Approval Gate',
    tools_desc:
      'Every capability is grouped by blast radius. Configure Tools 1–9 as "Always Allow" in Web Gemini / Claude, and set Tool #10 (publish_changes) to "Ask Before Running".',
    filter_all: 'All 10 Tools',
    filter_t1: '🟢 Tier 1: Sandbox Autonomy & Read-Only (1–8)',
    filter_t2: '🟡 Tier 2: Stage Plan (9)',
    filter_t3: '🔴 Tier 3: Single Write Gate (10)',

    setup_eyebrow: 'Step-by-Step Deployment & Handshake Guide',
    setup_title: 'OAuth 2.1 + Cloudflare Tunnel Setup Walkthrough',
    setup_desc:
      'Enter your public hostname to customize every configuration block, Zero Trust route, OAuth callback URL, and discovery endpoint below.',
    setup_domain_lbl: 'PUBLIC_DOMAIN:',
    setup_reset_btn: 'Reset Example',
    oauth_seq_title: 'Under the Hood: Web Gemini & Claude OAuth 2.1 DCR Handshake',
    oauth_seq_sub:
      'Why GeminiBastionMCP connects cleanly where generic proxies fail — every RFC step implemented in src/auth/:',

    prev_eyebrow: 'Built-In Self-Hosted Web Interfaces',
    prev_title: 'Interactive UI Previews: GET / Portal, OAuth Consent & /admin PWA',
    prev_desc:
      'Inspect the three built-in web views served by Hono: the zero-leakage GET / portal, the fail-closed /oauth/authorize consent screen, and the /admin mobile operator cockpit.',
    prev_tab_portal: '🌐 GET / Public Portal',
    prev_tab_consent: '🔐 /oauth/authorize Consent',
    prev_tab_admin: '📱 /admin Operator PWA',
    prev_static_badge: 'Static Interactive Mockup (Zero Live Backend)',

    sec_eyebrow: 'Defense-in-Depth Guardrails',
    sec_title: '6-Layer Security & Isolation Architecture',
    sec_desc:
      'Fail-closed invariants enforced in code so browser AI agents can safely work on real repositories and production Cloudflare zones.',
    sec_1_t: '🔒 1. Zero Gateway Secret Leakage',
    sec_1_d:
      'buildSandboxedEnv() enforces a minimal env allowlist and strips GH_TOKEN, CLOUDFLARE_*, OAUTH_SIGNING_SECRET, ADMIN_PASSWORD_HASH, and DOWNSTREAM_MCPS_*. SecretScrubber redacts tokens across all MCP responses, artifacts, logs, and webhooks.',
    sec_2_t: '🧱 2. Linux UID 1001 / 1002 & Non-Overlapping Storage',
    sec_2_d:
      'In Docker, gateway (UID 1001) owns /data (mode 0700 SQLite WAL DB, /data/artifacts, /data/codex), while worker (UID 1002) runs workspace subprocesses with zero access to /data. loadConfig() rejects overlapping DATA_DIR and WORKSPACES_DIR.',
    sec_3_t: '⏪ 3. Non-Destructive GIT_INDEX_FILE Snapshots',
    sec_3_d:
      'Before every code_patch, codex_write, or rollback, tracked and untracked files are snapshotted into refs/mcp-checkpoints/* via a temporary GIT_INDEX_FILE without mutating your working tree .git/index or HEAD.',
    sec_4_t: '🚦 4. Protected Branches & Two-Phase Infra Plans',
    sec_4_d:
      'publish_changes(github_pr) blocks direct pushes to main, master, or default_branch and scans diffs for .env* / *.pem / *.key. Cloudflare DNS/WAF/D1 and MCP-2 mutations require a 15-minute TTL stage_mutation_plan with rollback snapshot.',
    sec_5_t: '🛡️ 5. Untrusted External Data & Origin Boundaries',
    sec_5_d:
      'POST /mcp enforces an explicit browser Origin allowlist, while github_inspect and infra_inspect wrap PR bodies, comments, workflow failure logs, and tail logs in untrusted-content boundaries against indirect prompt injection.',
    sec_6_t: '🔑 6. OAuth 2.1 Family Rotation & Fail-Closed IdPs',
    sec_6_d:
      'Mandates PKCE (S256) and RFC 8707 resource binding. Refresh tokens rotate with a 60-second concurrent retry grace window and revoke the entire family on post-grace replay. Optional Google/GitHub SSO fails startup closed if allowlists are empty.',

    btn_copy: 'Copy',
    copied_label: 'Copied ✓',
  },

  zh: {
    skip_main: '跳至主内容',
    nav_why: '核心对比',
    nav_arch: '隔离架构',
    nav_gate: '单闸门推演',
    nav_tools: '10 工具 · 1 闸门',
    nav_setup: 'OAuth 2.1 + 隧道部署',
    nav_preview: '内置界面预览',
    nav_security: '六层安全护栏',

    hero_title: '专为 Web Gemini、Claude 与 ChatGPT 打造的自托管 OAuth 2.1 MCP 研发运维堡垒',
    hero_subtitle:
      '10 大复合工具 · 1 道审批总闸门 · 无状态 Streamable HTTP (/mcp) · Codex SDK · Cloudflare 与 MCP-2 联邦',
    hero_lead:
      '将网页端或手机端 AI 聊天直接升级为拥有隔离沙盒工作区、后台 @openai/codex-sdk 异步引擎与两阶段 Cloudflare 变更能力的研发智能体——彻底告别几十个工具的弹窗轰炸与环境变量密钥裸奔。',
    cta_setup: 'OAuth 2.1 + 隧道部署指南',
    cta_sim: '交互推演单闸门审批流',
    cta_github: '访问 GitHub 仓库',

    stat_1_val: '10 → 1 闸门',
    stat_1_lbl: '工具 1–9 始终允许零弹窗 · 仅 #10 唯一写出口',
    stat_2_val: 'UID 1001 / 1002',
    stat_2_lbl: '0700 控制面数据库 vs 零密钥 Worker 沙盒',
    stat_3_val: '16 回调 · 8KB State',
    stat_3_lbl: '原生兼容 Gemini DCR + PKCE S256 + 60s 宽限轮换',
    stat_4_val: '15s → 异步 Job',
    stat_4_lbl: '长命令无损转后台 SQLite 任务 + Codex 线程续接',

    hero_notice:
      'ℹ️ 当前 GitHub Pages 页面为静态交互式架构与部署展示门户。真实的无状态 Streamable HTTP /mcp 网关与 /admin 移动控制台通过 Docker 或 VPS 自托管运行在您的 Cloudflare Tunnel 或 HTTPS 域名后。',

    why_eyebrow: '横向能力矩阵',
    why_title: '为什么需要 GeminiBastionMCP？',
    why_desc:
      '将 Web Gemini (gemini.google.com)、Claude.ai 或 ChatGPT 接入真实代码库与云基础设施时，往往受制于严苛的 OAuth 2.1 DCR 握手、细粒度工具弹窗疲劳或子进程密钥泄漏。',
    cmp_col_cap: '能力维度',
    cmp_col_proxy: '通用 MCP 聚合网关',
    cmp_col_remote: '单一厂商托管远程 MCP',
    cmp_col_local: '本地 Stdio Shell MCP',
    cmp_r1_k: 'Web Gemini (gemini.google.com) OAuth 2.1 DCR',
    cmp_r1_v1:
      '✅ 原生打通 (RFC 9728/8414/7591/8707、16 Redirect URIs、8KB State、60s 并发刷新宽限期)',
    cmp_r1_v2: '⚠️ 常缺失 RFC 8707 资源绑定或 8KB State 持久化',
    cmp_r1_v3: '✅ 仅限单一厂商托管能力',
    cmp_r1_v4: '❌ 仅限本地桌面端 Stdio',
    cmp_r2_k: '网页与移动端审批交互体验',
    cmp_r2_v1:
      '✅ 10 工具收敛 + 1 道总闸门（前 9 个安全设为始终允许，仅 publish_changes 触发外部写入）',
    cmp_r2_v2: '❌ 暴露 30–60 个细粒度工具，授权弹窗点到手软',
    cmp_r2_v3: '⚠️ 读写工具混杂，频繁打断对话',
    cmp_r2_v4: '❌ 每条命令都弹窗或完全无防护裸奔',
    cmp_r3_k: '隔离沙盒跑单测 + 后台异步 Codex',
    cmp_r3_v1:
      '✅ 15 秒同步等待超时无损晋升 SQLite 后台 Job + 原生 @openai/codex-sdk 线程编排',
    cmp_r3_v2: '❌ 仅做协议转发，无代码工作区沙盒',
    cmp_r3_v3: '❌ 仅封装 REST API，无法执行构建与测试',
    cmp_r3_v4: '⚠️ 直接在宿主机运行，无后台任务晋升机制',
    cmp_r4_k: '零网关密钥泄漏与无损快照回滚',
    cmp_r4_v1:
      '✅ 双 UID (1001/1002) 隔离 + buildSandboxedEnv() + SecretScrubber + 临时 GIT_INDEX_FILE 快照',
    cmp_r4_v2: '❌ 取决于下游实现，无统一沙盒剥离',
    cmp_r4_v3: '✅ 云端托管隔离',
    cmp_r4_v4: '❌ 子进程直接继承宿主机敏感环境变量',
    cmp_r5_k: '两阶段基础设施变更 (Plan → Execute → Rollback)',
    cmp_r5_v1:
      '✅ stage_mutation_plan (DNS/WAF/D1 与 MCP-2，15m TTL + 回滚快照) → publish_changes',
    cmp_r5_v2: '❌ 直接透传写操作',
    cmp_r5_v3: '❌ 立即执行外部写入',
    cmp_r5_v4: '❌ 无',

    arch_eyebrow: '系统拓扑与信任边界',
    arch_title: '爆炸半径受控的五域隔离架构',
    arch_desc:
      '基于 Hono 挂载无状态 WebStandardStreamableHTTPServerTransport (POST /mcp)，在 OAuth/SQLite 控制面 (UID 1001) 与零密钥执行沙盒 (UID 1002) 之间实施严格的容器网络与文件系统物理隔离。',
    arch_s1_title: 'AI 客户端与零端口边缘隧道',
    arch_s1_n1: '通过 OAuth 2.1 DCR + PKCE (S256) + Origin 白名单接入',
    arch_s1_n2: '无状态 Streamable HTTP (POST /mcp；GET/DELETE 返回 405)',
    arch_s1_n3: 'cloudflared 经 edge_net 转发至 gateway:8787（宿主机零暴露端口）',
    arch_s2_title: '网关控制面 (UID 1001)',
    arch_s2_n1: 'RFC 9728/8414/8707 + 60s 令牌族宽限轮换 + Google/GitHub SSO',
    arch_s2_n2: '0700 权限独占 /data，UID 1002 沙盒进程物理不可读写',
    arch_s2_n3: '对所有工具响应、Artifact 构件、日志与 Webhook 全局脱敏',
    arch_s3_title: '零密钥执行沙盒 (UID 1002)',
    arch_s3_n1: '临时 GIT_INDEX_FILE 快照至 refs/mcp-checkpoints/* + L0/L1/L2 校验',
    arch_s3_n2: '剥离 GH_TOKEN、CLOUDFLARE_*、OAUTH_SIGNING_SECRET 等全部敏感变量',
    arch_s3_n3: 'codex_readonly / codex_write / shell_task 预算控制与进程组强杀',
    arch_s4_title: '受审计唯一外部写通道',
    arch_s4_n1: '仅允许特性分支创建 PR/评审/评论；硬性拦截直推 main/master',
    arch_s4_n2: '只读 Token 巡检 vs DNS/WAF/D1 暂存计划 & Worker 默认预览发布',
    arch_s4_n3: '内网 ops_net Sidecar 联邦，严格分离 readonlyTools 与 mutatingTools',

    gate_eyebrow: '交互式审批流推演',
    gate_title: '10 工具 · 1 道审批闸门：端到端交互模拟器',
    gate_desc:
      '切换下方 4 类真实研发/运维场景，逐步观察工具 1–9 如何在隔离沙盒内 0 弹窗自治运行，并将所有外部副作用精准收敛至第 10 号工具 (publish_changes) 唯一人工审批点。',
    sim_prev: '← 上一步',
    sim_next: '下一步 →',
    sim_auto: '▶ 自动演示',
    sim_stop: '⏸ 暂停',
    sim_req_lbl: 'MCP 工具调用载荷 (JSON-RPC)',
    sim_state_lbl: '网关安全护栏、SQLite 状态与审计记录',

    tools_eyebrow: '10 工具契约浏览器（1:1 对齐 src/ 源码实现）',
    tools_title: '10 大复合工具 · 1 道审批总闸门',
    tools_desc:
      '按爆炸半径分级筛选。在 Web Gemini 或 Claude 中将工具 1–9 设为「始终允许 (Always Allow)」，仅将工具 #10 (publish_changes) 设为「运行前询问」。',
    filter_all: '全部 10 个工具',
    filter_t1: '🟢 Tier 1: 沙盒内自治与外部只读 (1–8)',
    filter_t2: '🟡 Tier 2: 变更预演暂存 (9)',
    filter_t3: '🔴 Tier 3: 唯一外部写闸门 (10)',

    setup_eyebrow: '全流程部署与协议握手指南',
    setup_title: 'OAuth 2.1 + Cloudflare Tunnel 交互式部署指南',
    setup_desc:
      '在下方输入您的自定义域名，页面中的所有 .env 配置片段、Cloudflare Zero Trust 路由、SSO 回调地址与协议发现端点将实时同步生成。',
    setup_domain_lbl: 'PUBLIC_DOMAIN:',
    setup_reset_btn: '重置示例域名',
    oauth_seq_title: '底层协议透视：Web Gemini 与 Claude 的 OAuth 2.1 DCR 完整握手链',
    oauth_seq_sub:
      '为什么通用反代经常在 Gemini Connected Apps 上握手失败？以下是 src/auth/ 完整实现的 5 步标准协议栈：',

    prev_eyebrow: '内置自托管 Web 界面',
    prev_title: '交互式界面预览：GET / 公开门户、OAuth 授权页 & /admin 移动座舱',
    prev_desc:
      '切换查看网关内置的三大 Web 视图：零隐私泄漏的 GET / 状态门户、支持 Google/GitHub SSO 的 /oauth/authorize 授权确认页，以及移动端优先的 /admin PWA 运维座舱。',
    prev_tab_portal: '🌐 GET / 公开状态门户',
    prev_tab_consent: '🔐 /oauth/authorize 授权页',
    prev_tab_admin: '📱 /admin 运维指挥座舱',
    prev_static_badge: '静态交互预览（未连接真实后端）',

    sec_eyebrow: '纵深防御护栏',
    sec_title: '六层硬核安全与物理隔离架构',
    sec_desc:
      '所有安全不变量均在源码层默认开启且默认拒绝 (Fail-Closed)，让您放心地将浏览器 AI 接入真实生产仓库与云账号。',
    sec_1_t: '🔒 1. 零网关密钥泄漏 (Zero Secret Leakage)',
    sec_1_d:
      'buildSandboxedEnv() 实施最小白名单环境变量，彻底剥离 GH_TOKEN、CLOUDFLARE_*、OAUTH_SIGNING_SECRET、ADMIN_PASSWORD_HASH 与 DOWNSTREAM_MCPS_*；SecretScrubber 对所有响应、构件、日志与 Webhook 全局脱敏。',
    sec_2_t: '🧱 2. Linux 双 UID (1001/1002) 与目录防重叠校验',
    sec_2_d:
      'Docker 镜像中 gateway (UID 1001) 独占 /data (0700 SQLite WAL、/data/artifacts、/data/codex)；沙盒命令由 worker (UID 1002) 执行，无权访问 /data。loadConfig() 启动时强校验目录不重叠。',
    sec_3_t: '⏪ 3. 非破坏性 GIT_INDEX_FILE 自动快照',
    sec_3_d:
      '每次执行 code_patch、codex_write 或 rollback 前，使用临时 GIT_INDEX_FILE 将已追踪与未追踪文件快照至 refs/mcp-checkpoints/*，绝不篡改真实 .git/index 或 HEAD。',
    sec_4_t: '🚦 4. 保护分支物理拦截与两阶段基础设施变更',
    sec_4_d:
      'publish_changes(github_pr) 硬性拦截向 main/master/默认分支直推并拦截 .env*/*.pem/*.key 提交；Cloudflare DNS/WAF/D1 与 MCP-2 变更必须先经 stage_mutation_plan 生成 15m TTL 回滚快照。',
    sec_5_t: '🛡️ 5. 不可信外部数据边界与 Origin 校验',
    sec_5_d:
      'POST /mcp 强制校验浏览器 Origin 白名单；github_inspect 与 infra_inspect 返回的外部 PR、评论、构建日志与 Worker Tail 日志均包裹不可信数据边界标记，抵御间接提示词注入。',
    sec_6_t: '🔑 6. OAuth 2.1 令牌家族轮换与默认关闭 SSO',
    sec_6_d:
      '强制 PKCE (S256) 与 RFC 8707 资源绑定；Refresh Token 轮换具备 60 秒并发重试宽限期，超期重放旧令牌立即吊销整族；Google/GitHub SSO 若未配置白名单在生产环境直接拒绝启动。',

    btn_copy: '复制',
    copied_label: '已复制 ✓',
  },
};
