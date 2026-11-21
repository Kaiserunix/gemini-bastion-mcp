# GeminiBastionMCP (`gemini-bastion-mcp`) — User Journey Copy & Bilingual Microcopy Playbook

> **Companion Artifact to**: [`docs/UX_EXPERIENCE_AND_DESIGN_SPEC.md`](./UX_EXPERIENCE_AND_DESIGN_SPEC.md) (`swarm/ux-design-2`)  
> **Purpose**: Ready-to-use, code-truthful bilingual (`English` + `简体中文`) UX copy blocks for onboarding flows, the 60-second mobile Prompt-to-PR transcript, client setup guides, `/oauth/authorize`, `GET /`, and the `/admin` Mobile Operator Cockpit PWA.

---

## 1. Hero Positioning & 60-Second Mobile Prompt-to-PR Transcript

### 1.1 English Hero Hook
> **Stop Clicking "Allow" 40 Times on Your Phone.**  
> **Turn `gemini.google.com`, Claude.ai & ChatGPT into a sandboxed coding, background Codex & Cloudflare ops agent — with 10 tools funneled through 1 single external write gate (`publish_changes`).**

### 1.2 简体中文 Hero Hook
> **告别在手机网页上连点 40 次「允许」的弹窗地狱。**  
> **将 `gemini.google.com`、Claude.ai 与 ChatGPT 一键接入自托管 OAuth 2.1 研发运维堡垒——隔离沙盒改码跑测、Codex 异步后台执行、10 大复合工具收敛至唯一外部写操作总闸门 (`publish_changes`)。**

### 1.3 The "60-Second Mobile Prompt-to-PR" User Journey Transcript

#### English Version
```text
📱 You (in gemini.google.com on your phone):
"Sync Kaiserunix/my-api, fix the failing rate-limit test in src/auth/, run vitest, and open a draft PR."

🟢 [Auto-Allowed · Tier 1B] workspace_manage(action="sync_github", slug="my-api", repo="Kaiserunix/my-api")
   -> Cloned into /workspaces/my-api (Node/TypeScript stack & AGENTS.md playbook detected).

🟢 [Auto-Allowed · Tier 1A] code_explore(mode="search", slug="my-api", query="IpRateLimiter")
   -> Located rate limiter implementation and test suite in 120ms (0 approval popups).

🟢 [Auto-Allowed · Tier 1B] code_patch(action="patch", slug="my-api", edits=[...])
   -> Auto-created non-destructive GIT_INDEX_FILE checkpoint (chk_1763694012_4a1b).
   -> L0 in-memory AST/secret/placeholder check + L1 Biome lint passed automatically.

🟢 [Auto-Allowed · Tier 1B] workspace_exec(slug="my-api", command="npx vitest run")
   -> Executed in UID 1002 zero-secret sandbox. 18/18 tests passing in 3.4s.

🔴 [SINGLE APPROVAL PROMPT · Tier 3] publish_changes(action="github_pr", slug="my-api", branch_name="fix/rate-limit-window", draft=true)
   -> Gemini asks ONCE: "Allow publish_changes?" -> You tap [Allow].
   -> Pushes feature branch (main/master physically blocked), scans diff for secrets, and opens Draft PR #42!
```

#### 简体中文版本
```text
📱 你（在手机浏览器打开 gemini.google.com）：
“同步 Kaiserunix/my-api，修复 src/auth/ 下失败的限流单测，跑通 vitest 并提一个 Draft PR。”

🟢 [自动放行 · Tier 1B] workspace_manage(action="sync_github", slug="my-api", repo="Kaiserunix/my-api")
   -> 同步至隔离目录 /workspaces/my-api（自动识别 TypeScript 技术栈与 AGENTS.md 规范）。

🟢 [自动放行 · Tier 1A] code_explore(mode="search", slug="my-api", query="IpRateLimiter")
   -> 120ms 定位目标源码与测试文件（全程 0 授权弹窗）。

🟢 [自动放行 · Tier 1B] code_patch(action="patch", slug="my-api", edits=[...])
   -> 自动创建无损 GIT_INDEX_FILE 快照 (chk_1763694012_4a1b)，不污染工作区 HEAD。
   -> L0 内存级语法/密钥/省略号拦截 + L1 代码规范检查自动通过。

🟢 [自动放行 · Tier 1B] workspace_exec(slug="my-api", command="npx vitest run")
   -> 在 UID 1002 零密钥白名单沙盒内运行：18/18 项单测 3.4 秒全绿通过。

🔴 [唯一一次人工确认 · Tier 3] publish_changes(action="github_pr", slug="my-api", branch_name="fix/rate-limit-window", draft=true)
   -> Web Gemini 仅弹窗一次：“是否允许运行 publish_changes？” -> 点击【允许】。
   -> 网关物理拦截直推 main/master、完成 Diff 密钥扫描并自动创建 Draft PR #42！
```

---

## 2. Zero-Friction 90-Second Onboarding Copy (EN + ZH)

### 2.1 Copy-Paste Multi-Client `.env` Preset
```dotenv
# Public HTTPS URL fronted by Cloudflare Tunnel or TLS reverse proxy
PUBLIC_DOMAIN=https://mcp.yourdomain.com
TRUST_CF_CONNECTING_IP=true

# Allow Web Gemini, AI Studio, Claude.ai, ChatGPT & Local MCP Inspector OAuth DCR callbacks
OAUTH_ALLOWED_REDIRECT_HOSTS=gemini.google.com,aistudio.google.com,accounts.google.com,claude.ai,chatgpt.com,chat.openai.com,localhost,127.0.0.1

# Generated via the 1-command scrypt + signing-secret snippet below
ADMIN_PASSWORD_HASH=scrypt:...
OAUTH_SIGNING_SECRET=...

# Cloudflare Zero Trust Tunnel token (consumed by cloudflared only; stripped from gateway)
CLOUDFLARE_TUNNEL_TOKEN=...
```

### 2.2 Multi-Client Connection Cheat Sheet Copy

| AI Client | How to Connect (`https://mcp.yourdomain.com/mcp`) | Required `.env` & Permission Setup |
| :--- | :--- | :--- |
| **Web Gemini (`gemini.google.com`)** | **Connected Apps** -> Add custom MCP connector -> Paste `https://mcp.yourdomain.com/mcp`. OAuth 2.1 DCR (16 redirect URIs + 8KB `state` + PKCE `S256`) completes automatically. | Works out-of-the-box with default `OAUTH_ALLOWED_REDIRECT_HOSTS`. Set Tools 1–9 to **Always Allow**, Tool 10 (`publish_changes`) to **Ask**. |
| **Claude.ai (Web & Mobile)** | **Settings -> Connectors -> Add Custom Connector** -> Paste `https://mcp.yourdomain.com/mcp` and complete the OAuth consent screen. | Ensure `claude.ai` is in `OAUTH_ALLOWED_REDIRECT_HOSTS` (or configure `OAUTH_STATIC_CLIENT_ID` / `SECRET` if using static credentials). |
| **ChatGPT (Connectors / Deep Research)** | **Settings -> Connectors -> Create Custom MCP Connector** -> Paste `https://mcp.yourdomain.com/mcp`. | Ensure `chatgpt.com,chat.openai.com` are in `OAUTH_ALLOWED_REDIRECT_HOSTS`. |
| **Cursor / Local MCP Inspector** | Connect via Streamable HTTP transport to `https://mcp.yourdomain.com/mcp` (or `http://127.0.0.1:8787/mcp` in local dev). | `localhost,127.0.0.1` are enabled by default. |

---

## 3. UI Surface Microcopy Dictionary (English & 简体中文)

### 3.1 `GET /` Public Gateway Portal (`src/mcp/landingPage.ts`)

| UI Element | English Copy | 简体中文文案 |
| :--- | :--- | :--- |
| **Status Pill (Healthy)** | `● ONLINE · SQLite WAL Ready` | `● 在线运行 · SQLite WAL 就绪` |
| **Status Pill (Degraded)** | `▲ DEGRADED · SQLite Check Failed` | `▲ 降级运行 · 数据库连接异常` |
| **Zero-Leakage Privacy Badge** | `Zero-Leakage Public Portal: No private workspaces, jobs, tokens, or secrets are queried or exposed on this endpoint.` | `零隐私泄漏公开门户：此页面绝不查询或暴露任何私有工作区、后台任务、OAuth 令牌或网关密钥。` |
| **1-Gate Setup Tip** | `Recommended Client Policy: Set Tools 1–9 (Tier 1A/1B/2) to "Always Allow" for zero-popup coding & staging. Keep Tool #10 (publish_changes) on "Ask Before Running" as your single external write gate.` | `客户端授权建议：将工具 1–9（Tier 1A/1B/2）设为「始终允许」以获得零弹窗编码与变更预演体验；仅将工具 #10 (publish_changes) 设为「运行前询问」作为唯一外部写闸门。` |

### 3.2 `/oauth/authorize` Operator Consent Screen (`src/auth/authorize.ts`)

| UI Element | English Copy | 简体中文文案 |
| :--- | :--- | :--- |
| **Header Subtitle** | `Verify your operator identity to grant this AI client access to your self-hosted GeminiBastionMCP gateway.` | `请验证管理员身份，授权该 AI 客户端连接您的 GeminiBastionMCP 网关。` |
| **Scope Option 1 (`mcp:tools`)** | `Full Sandbox & Staged Ops (mcp:tools) — Can sync repos, edit/test code in isolated /workspaces (0 secrets, auto-checkpointed), stage 15m TTL plans, and request publish_changes.` | `完整沙盒与预演权限 (mcp:tools) — 可同步仓库、在零密钥隔离沙盒内改码跑测（自动 Git 快照）、暂存 15 分钟变更计划，并发起 publish_changes 审批请求。` |
| **Scope Option 2 (`mcp:read`)** | `Read-Only Inspection Only (mcp:read) — Strictly limited to code_explore, job_status polling, github_inspect, and infra_inspect. Zero workspace or external writes.` | `纯只读巡检模式 (mcp:read) — 严格限制仅可调用代码检索、任务查询、GitHub 与基础设施只读巡检，物理阻断一切本地与外部写入。` |
| **1-Tap Session Button** | `Approve as Signed-In Operator` | `以当前已登录管理员身份一键授权` |

### 3.3 `/admin` Mobile Operator Cockpit PWA (`src/admin/ui.ts`)

| UI Element | English Copy | 简体中文文案 |
| :--- | :--- | :--- |
| **KPI 1: Active Jobs** | `Active Jobs (running / queued)` | `活跃任务（运行中 / 排队中）` |
| **KPI 2: Staged Plans** | `Staged Plans (15m TTL pending approval)` | `暂存变更计划（15 分钟有效期 · 待审批）` |
| **KPI 3: Workspaces** | `Workspaces (isolated in /workspaces)` | `隔离工作区（/workspaces 沙盒）` |
| **KPI 4: OAuth Sessions** | `OAuth Sessions (active token families)` | `OAuth 会话（活跃令牌家族）` |
| **Job Card: Rollback CTA** | `⏪ Rollback Workspace to Pre-Job Checkpoint` | `⏪ 回滚工作区至任务前快照` |
| **Plan Card: Execute CTA** | `Approve & Execute Plan` | `批准并执行变更计划` |
| **Plan Card: Discard CTA** | `Discard Staged Plan` | `废弃此暂存计划` |
| **Plan Card: Rollback CTA** | `⏪ Rollback Executed Plan` | `⏪ 使用快照回滚已执行计划` |
| **Confirm: Rollback Workspace** | `Restore workspace "{slug}" to checkpoint {id}? A pre-rollback safety snapshot will be created automatically so this rollback can also be undone.` | `确认将工作区 "{slug}" 回滚至快照 {id}？系统将自动创建回滚前安全快照，确保本次回滚同样可撤销。` |

---

## 4. Operator Pre-Flight & Troubleshooting Checklist

1. **[ ] Single `.env` Loaded by Both Services**: Did you launch with `docker compose --env-file .env -f docker/docker-compose.yml up -d --build` so `cloudflared` receives `CLOUDFLARE_TUNNEL_TOKEN` and `gateway` receives `ADMIN_PASSWORD_HASH` & `OAUTH_SIGNING_SECRET`?
2. **[ ] Multi-Client Redirect Hosts Configured**: If connecting **Claude.ai** or **ChatGPT** in addition to **Web Gemini**, does `OAUTH_ALLOWED_REDIRECT_HOSTS` in `.env` include `claude.ai,chatgpt.com,chat.openai.com`?
3. **[ ] Docker-Compose-Safe Password Hash Format**: Does `ADMIN_PASSWORD_HASH` start with `scrypt:<saltHex>:<keyHex>` (colon delimiter, avoiding Docker Compose `$` variable interpolation)?
4. **[ ] Fail-Closed Upstream IdP Allowlist**: If you configured `GOOGLE_OAUTH_CLIENT_ID` or `GITHUB_OAUTH_CLIENT_ID`, did you also populate `GOOGLE_OAUTH_ALLOWED_EMAILS` or `GITHUB_OAUTH_ALLOWED_USERS` / `GITHUB_OAUTH_ALLOWED_IDS`? *(In `NODE_ENV=production`, startup fails closed if IdP credentials are provided without a non-empty allowlist.)*
5. **[ ] Client Permission Tiers Set (`10 Tools, 1 Gate`)**: After completing the OAuth handshake in Web Gemini / Claude / ChatGPT, did you set Tools #1–#9 to **`Always Allow`** and Tool #10 (`publish_changes`) to **`Ask Before Running`**?
