<div align="center">

# GeminiBastionMCP (`gemini-bastion-mcp`)

**[English](README.md) | 简体中文 | [项目主页 (Live Showcase)](https://kaiserunix.github.io/gemini-bastion-mcp/) | [GitHub 仓库](https://github.com/Kaiserunix/gemini-bastion-mcp)**

**专为 Web Gemini、Claude 与 ChatGPT 打造的开源自托管 OAuth 2.1 MCP 研发运维堡垒网关：内置沙盒工作区、Codex 异步引擎与 Cloudflare 管控，以「10 大复合工具 + 1 道唯一出闸门」彻底终结授权弹窗地狱与密钥泄漏。**

[![CI](https://github.com/Kaiserunix/gemini-bastion-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Kaiserunix/gemini-bastion-mcp/actions/workflows/ci.yml)
[![Deploy GitHub Pages](https://github.com/Kaiserunix/gemini-bastion-mcp/actions/workflows/pages.yml/badge.svg)](https://kaiserunix.github.io/gemini-bastion-mcp/)
[![MCP 2025-11-25](https://img.shields.io/badge/MCP-2025--11--25%20Streamable%20HTTP-3b82f6?style=flat-square)](https://modelcontextprotocol.io)
[![OAuth 2.1 + PKCE + DCR](https://img.shields.io/badge/OAuth%202.1-PKCE%20%2B%20DCR%20%2B%20RFC%208707-10b981?style=flat-square)](#连接-ai-客户端)
[![Node.js >= 22.23.4](https://img.shields.io/badge/Node.js-%3E%3D%2022.23.4%20LTS-22c55e?style=flat-square)](docker/Dockerfile)
[![Docker Ready](https://img.shields.io/badge/Docker-UID%201001%2F1002%20Isolated-0ea5e9?style=flat-square)](docker/docker-compose.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-64748b?style=flat-square)](LICENSE)

</div>

---

- **在手机或浏览器用 `gemini.google.com` 写代码、跑测试**：打开网页版 Gemini，一键同步 GitHub 仓库，用 `ripgrep`、`ast-grep` 和 `repomix` 探索代码，打多文件原子补丁并跑通 L0/L1/L2 校验流水线——无需守在电脑前。
- **把重任务委托给后台 Codex 与长耗时构建**：一条指令派发 `@openai/codex-sdk` 异步线程或测试构建（`workspace_exec` 超过 15 秒自动晋升为后台 SQLite Job）。关掉网页照样跑，完成后通过 Webhook 推送脱敏通知到手机。
- **零密钥泄漏 & 单闸门爆炸半径控制**：沙盒内子进程彻底剥离 `GH_TOKEN`、`CLOUDFLARE_*` 等网关密钥；`GIT_INDEX_FILE` 非破坏性快照保护工作树，物理拦截直推 `main`/`master`，一切外部写入操作强制收束于**唯一出闸门 (`publish_changes`)**。

> **原生适配 Web Gemini Connected Apps、Claude.ai、ChatGPT Connectors、Cursor 与 MCP Inspector。**

---

## 为什么做这个项目（Why This Exists）

大多数远程 MCP 方案都面临两难：要么暴露三四十个零碎工具，导致网页端每读一个文件、跑一次测试就弹一次授权确认框；要么直接在宿主机裸跑 Shell，毫无密钥隔离与回滚保护。

| 能力维度 | **GeminiBastionMCP** | 通用聚合网关 (如 MetaMCP) | 官方远程 MCP (GitHub / CF) | 本地 Shell / Stdio MCP |
| :--- | :--- | :--- | :--- | :--- |
| **Web Gemini (`gemini.google.com`) 原生接入** | **完整支持** (OAuth 2.1 + PKCE S256 + DCR 支持 16 个 Redirect URIs + 8KB `state` + RFC 8707/9728) | 多数缺少 RFC 9728/8707 或大 `state` 支持 | 仅限单一官方平台 | 仅限本地桌面客户端 |
| **Web 聊天端授权弹窗体验** | **10 工具收敛 + 唯一审批闸门** (Tier 1/2 可设始终允许，仅 `publish_changes` 需确认) | 几十个底层工具导致确认弹窗点到手软 | 读写工具混杂 | 每次执行命令均需确认或全裸奔 |
| **真沙盒跑测试 + 异步 Codex 引擎** | **原生内置** (`workspace_exec` 15s 自动转后台 Job + `@openai/codex-sdk` 线程续接) | 无代码执行沙盒 | 仅 API 调用，不能跑本地构建/测试 | 跑在宿主机，无后台 Job 晋升机制 |
| **密钥隔离与无损回滚** | **双 UID (1001/1002) + 环境白名单 + `SecretScrubber` + `GIT_INDEX_FILE` 快照** | 取决于下游服务 | 云端托管 | 子进程直接继承宿主机全量环境变量 |
| **两阶段基础设施变更 (Plan -> Apply)** | **`stage_mutation_plan` (15 分钟 TTL + 回滚快照) -> `publish_changes`** | 直接透传写操作 | 直接执行写操作 | 无 |

---

## 整体架构图

```mermaid
flowchart LR
  subgraph Clients["Web 与移动端 AI 客户端"]
    G["gemini.google.com\n(Connected Apps)"]
    C["Claude.ai / ChatGPT\n/ Cursor / Inspector"]
  end

  subgraph Edge["零暴露端口边缘接入"]
    CF["Cloudflare Tunnel\n或 TLS Nginx 反向代理"]
  end

  subgraph Gateway["GeminiBastionMCP 网关 (UID 1001: gateway)"]
    Portal["GET / 公开入口页\n(零私有数据泄漏)"]
    Auth["OAuth 2.1 + PKCE + DCR\nRFC 8707/9728 + Token 家族轮换"]
    Scrub["SecretScrubber 与\n不可信内容边界包装"]
    Admin["/admin 移动端 PWA 控制台\nSSE 实时任务流与一键回滚"]
    DB[("SQLite WAL (/data)\n0700 仅 gateway 可读写")]

    subgraph Funnel["10 大工具契约 (1 道唯一审批闸门)"]
      T1_8["Tier 1 (1-8): 沙盒自治与只读洞察\nworkspace_manage · code_explore · code_patch\nworkspace_exec · dispatch_runner · job_status\ngithub_inspect · infra_inspect"]
      T9["Tier 2 (9): 两阶段变更预演\nstage_mutation_plan (15 分钟 TTL + 快照)"]
      T10["Tier 3 (10): 唯一外部写出口\npublish_changes (PR / CF 部署 / 执行计划)"]
    end
  end

  subgraph Sandbox["隔离 Worker 沙盒 (UID 1002: worker)"]
    WS["/workspaces/{slug}\nGIT_INDEX_FILE 检查点\nL0/L1/L2 自动校验"]
    Codex["@openai/codex-sdk 与\n无密钥沙盒 Shell"]
  end

  subgraph External["外部目标与内部 ops_net"]
    GH["GitHub API\n(禁止直推 main/master)"]
    CFApi["Cloudflare API\n(Workers / Pages / DNS / KV)"]
    MCP2["下游 MCP-2 Sidecar\n(如 ops_net 内网的 ops-ssh)"]
  end

  Clients -->|"Streamable HTTP /mcp"| CF --> Auth --> Funnel
  CF --> Portal & Admin
  T1_8 --> WS & Codex
  T1_8 -.->|"仅只读"| GH & CFApi & MCP2
  T9 -->|"暂存计划 + 回滚快照"| DB
  T10 -->|"审计并脱敏写入"| GH & CFApi & MCP2
  Admin --> DB & WS
```

---

## 10 大工具，1 道审批闸门

与其暴露 40 多个细粒度工具让用户在手机/网页上被弹窗淹没，`GeminiBastionMCP` 按**影响半径 (Blast Radius)** 将全部能力收敛为 3 档：

### Tier 1 — 沙盒内自治与只读洞察 *（客户端建议设为 `Always Allow` 始终允许）*

| # | 工具名 | 核心动作与行为 |
|---|--------|----------------|
| 1 | `workspace_manage` | `list`、`sync_github`、`init_cf_ops`、`list_checkpoints`、`rollback`（自动识别技术栈与 `AGENTS.md` / `CLAUDE.md`） |
| 2 | `code_explore` | `pack` (repomix)、`search` (ripgrep)、`ast` (ast-grep)、`read_lines`、`read_artifact`、`git_diff` |
| 3 | `code_patch` | 原子化多文件 `patch`（支持 `hunks` + `line_hint`）、`create_or_overwrite`、`delete_file`，自带自动检查点与 L0/L1/L2 校验回滚 |
| 4 | `workspace_exec` | 在 `/workspaces/{slug}` 内运行沙盒命令（`wait_ms` 最长 `15000`；超时自动转后台 SQLite `job_id`） |
| 5 | `dispatch_runner` | 派发后台 `codex_readonly`、`codex_write` 或 `shell_task`，支持线程续接、Token/时长预算及自动检查点 |
| 6 | `job_status` | 查询任务状态、流式事件、Token 消耗、`thread_id`、`git status -sb`、最终报告，或通过 `cancel: true` 实时中止 |
| 7 | `github_inspect` | 只读查看 PR Diff/文件、Issue 评论与失败的 Actions 日志（带防 Prompt 注入的不可信数据边界包装） |
| 8 | `infra_inspect` | 只读巡检 Cloudflare（`zones`、`dns_records`、`workers`、`pages`、`kv_namespaces`、`d1_databases`、`waf_rules`、`worker_tail_logs`）及下游 MCP-2 `readonlyTools` |

### Tier 2 — 零副作用变更预演 *（客户端建议设为 `Always Allow`）*

| # | 工具名 | 核心动作与行为 |
|---|--------|----------------|
| 9 | `stage_mutation_plan` | 抓取变更前线上快照生成 `rollback_payload` 与人类可读 Diff，签发 15 分钟有效期的 `plan_id`（适用于 Cloudflare 变更或下游 MCP-2 `mutatingTools`）。**不执行任何真实写入。** |

### Tier 3 — 唯一外部写出口 *（客户端设为 `Ask Before Running` 每次询问）*

| # | 工具名 | 核心动作与行为 |
|---|--------|----------------|
| 10 | `publish_changes` | **全网关唯一的外部写入总闸门**：`github_pr`（物理拦截直推 `main`/`master`/默认分支）、`github_pr_review`、`github_comment`、`cloudflare_worker_deploy`（默认预览 URL）、`cloudflare_pages_deploy`、`execute_staged_plan`、`rollback_plan`。 |

---

## 3 分钟快速上手

### 方式 A：Docker Compose + Cloudflare Tunnel（推荐）

[`docker/docker-compose.yml`](docker/docker-compose.yml) 启动的 `gateway` 容器**不向宿主机暴露任何公网端口**（仅内部 `expose: ["8787"]`），全部外部 HTTPS 流量由 `cloudflared` 隧道安全引入。

1. **复制环境变量模板**：
   ```bash
   cp .env.example .env
   ```

2. **生成 `ADMIN_PASSWORD_HASH`（`scrypt:`）与 `OAUTH_SIGNING_SECRET`**：
   生产环境推荐无 `$` 符号、可安全用于 Docker Compose 的 `scrypt:<saltHex>:<keyHex>` 与 `sha256:<hex>` 格式（同时兼容 `scrypt$<saltHex>$<keyHex>` 与 `sha256$<hex>`；若在 Docker Compose `.env` 中使用 `$` 格式需转义为 `$$`）。使用 Node 22 一行命令生成 `scrypt:` 哈希：
   ```bash
   node -e 'const c=require("node:crypto"),s=c.randomBytes(16).toString("hex");console.log(`scrypt:${s}:${c.scryptSync(process.argv[1],s,32,{N:16384,r:8,p:1}).toString("hex")}`)' 'your-admin-password'
   ```
   生成 32 字节 `OAUTH_SIGNING_SECRET`：
   ```bash
   node -e 'console.log(require("node:crypto").randomBytes(32).toString("hex"))'
   ```

3. **填写 `.env` 关键配置**：
   - `PUBLIC_DOMAIN=https://mcp.yourdomain.com`
   - `TRUST_CF_CONNECTING_IP=true`
   - `OAUTH_SIGNING_SECRET=<上一步生成的随机十六进制串>`
   - `ADMIN_PASSWORD_HASH=<上一步生成的 scrypt:... 哈希>`
   - `CLOUDFLARE_TUNNEL_TOKEN=<Cloudflare Zero Trust Tunnel Token>`
   - 按需填写集成凭据：`GH_TOKEN`、`OPENAI_API_KEY` / `CODEX_API_KEY`、`CLOUDFLARE_ACCOUNT_ID`、`CLOUDFLARE_READONLY_API_TOKEN`、`CLOUDFLARE_API_TOKEN`

4. **配置 Cloudflare Tunnel 路由**：在 Cloudflare Zero Trust 控制台（Networks -> Tunnels）添加 Public Hostname（如 `mcp.yourdomain.com`），指向 `http://gateway:8787`，并将 `CLOUDFLARE_TUNNEL_TOKEN=<token>` 写入 `docker/.env`（或在 Shell 中 export）。

5. **构建并启动容器栈**：
   ```bash
   docker compose -f docker/docker-compose.yml up -d --build
   ```
   > **关于 Docker Compose `.env` 转义的提示**：使用 `scrypt:<saltHex>:<keyHex>` 可彻底避免 Docker Compose 对 `$` 做变量插值；若在 `.env` 中使用旧版 `scrypt$...` 格式，请将每个 `$` 转义为 `$$`。
   > **Node 22 安全基线**：[`docker/Dockerfile`](docker/Dockerfile) 在构建期强制校验 `Node >= 22.23.4`。若本地缓存的基础镜像版本偏旧，可在 `docker/.env` 中设置 `NODE_IMAGE=node:22.23.4-bookworm-slim` 或使用 `--pull` 重新构建。注意 `cloudflared` 仅接收 `TUNNEL_TOKEN`（不会挂载 `../.env`）。

### 方式 B：Nginx 反向代理部署（本机回环端口）

如果你已有带 TLS 证书的 VPS 并使用 Nginx 反代（不使用 Cloudflare Tunnel）：

1. 通过 `docker-compose.override.yml` 将 `gateway` 仅绑定到宿主机回环地址（如 `127.0.0.1:8787:8787` 或 `127.0.0.1:39120:8787`），若前端未套 Cloudflare 请在 `.env` 设 `TRUST_CF_CONNECTING_IP=false`，并仅启动 `gateway` 服务：
   ```bash
   docker compose -f docker/docker-compose.yml up -d --build gateway
   ```
2. 在 Nginx 中关闭缓冲以支持 Streamable HTTP 与 `/admin` SSE 流式推送：
   ```nginx
   location / {
     proxy_pass http://127.0.0.1:8787;
     proxy_http_version 1.1;
     proxy_set_header Host $host;
     proxy_set_header X-Real-IP $remote_addr;
     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
     proxy_set_header X-Forwarded-Proto $scheme;
     proxy_buffering off;
     proxy_read_timeout 300s;
   }
   ```

### 方式 C：本地开发模式

**环境要求**：Node.js `>= 22.23.4`、`git`，以及编译 `better-sqlite3` 所需的 C++ 构建工具。

```bash
npm install
cp .env.example .env
# 在 .env 中设置 DATA_DIR=./.local/data、WORKSPACES_DIR=./.local/workspaces、OAUTH_SIGNING_SECRET 与 ADMIN_PASSWORD_HASH
npm run typecheck
npm test
npm run dev
```

启动后访问 `http://127.0.0.1:8787/healthz` 与 `http://127.0.0.1:8787/` 验证服务在线。`npm run dev` 与 `npm start` 均通过 Node 原生 `--env-file-if-exists=.env` 自动加载 `.env`。

---

## 连接 AI 客户端

`GeminiBastionMCP` 遵循 **MCP 2025-11-25 Streamable HTTP** 规范（无状态 `/mcp`，彻底摒弃旧版 HTTP+SSE），支持 **OAuth 2.1 + PKCE (`S256`) + RFC 8707 Resource Indicators + RFC 9728 Protected Resource Metadata**。

### Web Gemini（`gemini.google.com` Connected Apps）

1. 确认 `PUBLIC_DOMAIN` 与公网 HTTPS 域名一致，且 `OAUTH_ALLOWED_REDIRECT_HOSTS` 包含 `gemini.google.com,aistudio.google.com,accounts.google.com`（`.env.example` 已默认配置）。
2. 在 Gemini Connected Apps / 自定义 MCP 连接器中填写端点 URL：
   ```text
   https://mcp.yourdomain.com/mcp
   ```
3. Gemini 会自动发现 `/.well-known/oauth-protected-resource` 与 `/.well-known/oauth-authorization-server`，并通过 `POST /oauth/register` 完成动态客户端注册（支持单客户端最多 **16 个 Redirect URIs** 与高达 **8192 字节**的 `state` 参数）。
4. 在浏览器中完成 OAuth 授权确认即可。Refresh Token 每次刷新自动轮换，并提供 60 秒并发重试宽限期。

### Claude.ai、ChatGPT 与 MCP Inspector（DCR 或静态客户端兜底）

- **自动 DCR**：直接填写 `https://mcp.yourdomain.com/mcp` 即可完成自动握手。
- **静态客户端兜底**：如果客户端需要预置凭据，在 `.env` 中配置 `OAUTH_STATIC_CLIENT_ID` 与 `OAUTH_STATIC_CLIENT_SECRET` 并重启 `gateway`，随后填入：
  - **MCP URL**：`https://mcp.yourdomain.com/mcp`
  - **Authorization URL**：`https://mcp.yourdomain.com/oauth/authorize`
  - **Token URL**：`https://mcp.yourdomain.com/oauth/token`

---

## 公开网关门户 (`GET /`) 与 `/admin` 移动端 PWA 控制台

- **公开网关门户 (`GET /`)**：浏览器访问根路径呈现暗色主题在线状态页，提供一键复制 `/mcp` 端点、`.well-known` 元数据链接、快速接入指引与 `/admin` 入口——**严禁查询或泄漏任何私有工作区、任务、Token 或密钥信息**；请求头包含 `Accept: application/json` 时返回结构化 JSON 状态。
- **运维指挥座舱 (`/admin`)**：使用与 `ADMIN_PASSWORD_HASH` 匹配的密码登录。支持添加到手机主屏幕（PWA），内置顶部 **4 宫格态势感知条**（`Active Jobs`、`Staged Plans`、`Workspaces`、`OAuth Sessions`）、顶栏一键复制 `/mcp` 地址、SSE 实时日志与 `[Expand / Collapse]` 展开、危险操作（`Kill`、`Rollback`、`Revoke`、`Delete Client`）二次确认以及脱敏审计日志。

---

## 六层安全防线与护栏

1. **零网关密钥泄漏**：`workspace_exec`、`shell_task` 与 Codex Runner 均通过 `buildSandboxedEnv()` 构建严格环境变量白名单（剥离 `GH_TOKEN`、`CLOUDFLARE_*`、`OAUTH_SIGNING_SECRET`、`ADMIN_PASSWORD_HASH`、`NOTIFY_WEBHOOK_URL` 与 `DOWNSTREAM_MCPS_*`），全部输出、产物与 Webhook 载荷均经 `SecretScrubber` 脱敏。
2. **Linux UID 1001 / 1002 物理隔离**：Docker 容器内 `gateway`（UID `1001`）独占 `/data`（权限 `0700`，存放 SQLite 数据库、`/data/artifacts` 以及 `CODEX_HOME=/data/codex`）及 `/app`，而 `worker`（UID `1002`）拥有 `/workspaces` 与 `/opt/mise`，对 `/data` 零访问权限（且 `gateway` 的 `PATH` 不包含 `/opt/mise/shims`）。
3. **非破坏性 Git 快照**：每次 `code_patch` 与 Codex 写入前均使用临时 `GIT_INDEX_FILE` 创建 `refs/mcp-checkpoints/*` 快照，不污染当前暂存区与 `HEAD`。
4. **受保护分支与敏感文件拦截**：`publish_changes` (`github_pr`) 物理禁止向 `main`、`master` 或仓库默认分支直接推送，并阻止提交 `.env*`、`*.pem`、`*.key`、`id_rsa*`、`.dev.vars*` 等敏感文件。
5. **不可信内容边界防御**：GitHub Issue/PR/Actions 日志、Cloudflare 尾部日志与下游 MCP-2 返回均会封装为不可信外部数据边界，抵御间接 Prompt 注入。
6. **OAuth 2.1 Token 家族防重放熔断**：Refresh Token 超过 60 秒宽限期被重复使用时，立即吊销整条 Token Family。

---

## 可选 `ops-mcp` 运维 Sidecar 联邦（MCP-2）

在完全不向 `/workspaces` 暴露 SSH 私钥的前提下，通过内部隔离网络 `ops_net` 联邦调用下游 HTTP 或本地 `stdio` MCP 服务（例如经 `mcp-proxy` 桥接的 `uarlouski/ssh-mcp-server`）：

1. 创建 `docker/ops-ssh/` 目录并放入受限的 `config.json` 与最小权限 SSH 密钥。
2. 复制 [`docker/ops-mcp-config.example.json`](docker/ops-mcp-config.example.json) 为 `docker/ops-mcp-config.json`，按需配置 `readonlyTools`、`mutatingTools` 与 `deniedTools` 策略清单。
3. 在 [`docker/docker-compose.yml`](docker/docker-compose.yml) 中取消 `./ops-mcp-config.json:/etc/gemini-bastion/ops-mcp-config.json:ro` 挂载行的注释，并在 `.env` 设置 `DOWNSTREAM_MCPS_FILE=/etc/gemini-bastion/ops-mcp-config.json`。
4. 使用 `ops` profile 构建并启动（基于 [`docker/Dockerfile.ops-mcp`](docker/Dockerfile.ops-mcp) 预装二进制，可在 `internal: true` 的离线 `ops_net` 中以非 root `node` 用户运行）：
   ```bash
   docker compose -f docker/docker-compose.yml --profile ops up -d --build
   ```

**策略执行**：`readonlyTools` 可在 `infra_inspect` 中直接调用；`mutatingTools` 必须经 `stage_mutation_plan` 暂存后再由 `publish_changes` 审批执行；`deniedTools` 及未登记工具一律拒绝。

---

## Webhook 通知

在 `.env` 中设置 `NOTIFY_WEBHOOK_URL`，即可在后台任务完成/失败/取消或基础设施变更计划执行/回滚时，接收经 `SecretScrubber` 脱敏的 JSON POST 通知。

---

## 开源发布前 GitHub 仓库配置与配图清单

发布到 GitHub 时建议配置以下仓库信息：

- **About 简介**：`Self-hosted OAuth 2.1 Streamable HTTP MCP bastion for Web Gemini, Claude & ChatGPT. Sandboxed git workspaces, Codex SDK, Cloudflare ops & 10-tool/1-gate funnel.`
- **Topics 标签**：`mcp`, `model-context-protocol`, `gemini`, `claude`, `codex`, `oauth21`, `streamable-http`, `cloudflare-tunnel`, `ai-agents`, `devops`, `self-hosted`, `typescript`
- **建议补充的演示素材**（放置于 `docs/assets/`）：
  - `demo-gemini-pr.gif` — 15 秒实录：Web Gemini 从 `code_explore` -> `code_patch` -> 唯一一次 `publish_changes` 确认并创建 GitHub PR
  - `portal-and-oauth.png` — `GET /` 公开网关着陆页与 OAuth 2.1 授权页截图
  - `admin-mobile-pwa.png` — 手机端 `/admin` PWA 指挥座舱截图（展示 4 宫格 KPI 与 SSE 实时日志流）
