<p align="center">
  <img src="docs/assets/hero-banner.svg" alt="GeminiBastionMCP — Self-Hosted OAuth 2.1 Remote MCP Server for Web Gemini, Claude & ChatGPT" width="100%" />
</p>

<div align="center">

# GeminiBastionMCP (`gemini-bastion-mcp`)

**Stop clicking "Allow" 40 times on your phone.**
**The self-hosted OAuth 2.1 Remote MCP Server & bastion that turns Web Gemini Connected Apps, Claude.ai Custom Connectors & ChatGPT MCP into a sandboxed full-stack coding, OpenAI Codex SDK & Cloudflare Workers/Pages ops agent — with 10 tools funneled through 1 external approval gate (`publish_changes`).**

[![CI](https://github.com/Kaiserunix/gemini-bastion-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Kaiserunix/gemini-bastion-mcp/actions/workflows/ci.yml)
[![Deploy GitHub Pages](https://github.com/Kaiserunix/gemini-bastion-mcp/actions/workflows/pages.yml/badge.svg)](https://kaiserunix.github.io/gemini-bastion-mcp/)
[![Release v0.1.0](https://img.shields.io/badge/Release-v0.1.0-6366f1?style=flat-square)](CHANGELOG.md)
[![Node.js >= 22.23.4](https://img.shields.io/badge/Node.js-%3E%3D%2022.23.4%20LTS-22c55e?style=flat-square)](docker/Dockerfile)
[![MCP 2025-11-25](https://img.shields.io/badge/MCP-2025--11--25%20Streamable%20HTTP-3b82f6?style=flat-square)](https://modelcontextprotocol.io)
[![OAuth 2.1 + PKCE + DCR](https://img.shields.io/badge/OAuth%202.1-PKCE%20%2B%20DCR%20%2B%20RFC%208707-10b981?style=flat-square)](#connecting-ai-clients)
[![Tests 59/59](https://img.shields.io/badge/Tests-59%2F59%20Passing-10b981?style=flat-square)](.github/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-64748b?style=flat-square)](LICENSE)

**English | [简体中文](README.zh-CN.md)**

[Live Showcase](https://kaiserunix.github.io/gemini-bastion-mcp/) · [Why This Exists](#why-this-exists) · [Architecture](#architecture-overview) · [10 Tools](#10-tools-1-approval-gate) · [UI Preview](#visual-ui-preview) · [Quick Start](#3-minute-quick-start) · [Google/GitHub SSO](#upstream-operator-login-google--github-oauth) · [Security](#6-layer-security--guardrails) · [Product Strategy](docs/PRODUCT_STRATEGY.md)

</div>

---

- **Code from `gemini.google.com` Connected Apps on Mobile or Desktop**: Open Web Gemini, sync a GitHub repo, inspect AST/files with `ripgrep` / `ast-grep` / `repomix`, apply atomic multi-file patches, and run L0/L1/L2 validation suites — without opening a laptop.
- **Delegate Heavy Engineering to Background OpenAI Codex SDK & Shell Jobs**: Dispatch autonomous `@openai/codex-sdk` threads or long builds (`workspace_exec` auto-promotes to background SQLite jobs after 15s). Close the browser tab and receive a scrubbed Webhook alert when it finishes.
- **Zero Secret Leakage & 1-Gate Blast Radius**: Sandboxed shell and Codex subprocesses run with a strict env allowlist (`buildSandboxedEnv()`) that strips `GH_TOKEN`, `CLOUDFLARE_*`, and gateway secrets. Non-destructive `GIT_INDEX_FILE` checkpoints protect your working tree, direct pushes to `main`/`master` are blocked, and every external side effect is funneled through **one single approval gate (`publish_changes`)**.

> [!TIP]
> **Built for Web Gemini Connected Apps, `claude.ai` Custom Connectors, ChatGPT MCP, Cursor & MCP Inspector** — over stateless **MCP 2025-11-25 Streamable HTTP** and **OAuth 2.1 + PKCE + Dynamic Client Registration (DCR)**.

---

## What a 60-Second Mobile Prompt-to-PR Looks Like

> **You (on phone in Web Gemini):** *"Check why CI failed on PR #42, fix the bug, run tests, and open a fix PR."*
>
> 1. `github_inspect` *(Tier 1 · Always Allow)* — Fetches failed Actions logs wrapped in an untrusted-data boundary.
> 2. `workspace_manage` + `code_explore` *(Tier 1 · Always Allow)* — Syncs repo to `/workspaces/{slug}` and locates the fault via `ripgrep` / `ast-grep`.
> 3. `code_patch` + `workspace_exec` *(Tier 1 · Always Allow)* — Creates an automatic `GIT_INDEX_FILE` checkpoint, applies the atomic patch, and runs the test suite as UID `1002` (`worker`) with zero gateway secrets.
> 4. `publish_changes` *(Tier 3 · **Ask Before Running — 1 prompt total**)* — Shows the scrubbed branch/PR summary. You tap **Allow once** → PR opens on a non-protected branch (`main`/`master` direct push blocked).

---

## Why This Exists

Most Remote MCP Servers force an unpleasant tradeoff: either expose dozens of fine-grained tools (triggering endless confirmation popups on every file read or test run) or run an unguarded shell directly on your host.

| Capability | **GeminiBastionMCP** | Generic Aggregators (e.g. MetaMCP) | Official Remote MCPs (GitHub / CF) | Local Shell / Stdio MCP |
| :--- | :--- | :--- | :--- | :--- |
| **Web Gemini (`gemini.google.com`) OAuth 2.1 DCR** | **Full Support** (PKCE `S256`, DCR up to 16 redirect URIs, 8KB `state`, RFC 8707/9728) | Often missing RFC 9728/8707 or large `state` support | Single-vendor hosted only | Desktop/local client only |
| **Web & Mobile Approval UX** | **10 Tools, 1 Approval Gate** (Tier 1/2 `Always Allow`, only `publish_changes` asks) | Dozens of fragmented tools = constant confirmation popups | Read & write tools mixed | Confirm every shell command or run wide open |
| **Sandboxed Test Runner + OpenAI Codex SDK** | **Built-in** (`workspace_exec` 15s auto-promotion + `@openai/codex-sdk` thread resume) | No execution sandbox | API-only; cannot run builds/tests | Runs on host; no background job promotion |
| **Secret Isolation & Non-Destructive Undo** | **UID 1002 Shell Isolation + Strict Env Allowlist + `SecretScrubber` + `GIT_INDEX_FILE` Snapshots** | Depends on downstream servers | Cloud-managed | Child processes inherit host env |
| **Two-Phase Infra Mutations** | **`stage_mutation_plan` (15m TTL + rollback snapshot) -> `publish_changes`** | Direct passthrough writes | Direct writes | None |

---

## Architecture Overview

```mermaid
flowchart LR
  subgraph Clients["Web & Mobile AI Clients"]
    G["gemini.google.com\n(Connected Apps)"]
    C["Claude.ai / ChatGPT\n/ Cursor / Inspector"]
  end

  subgraph Edge["Zero-Port Edge Ingress"]
    CF["Cloudflare Tunnel\nor TLS Nginx Proxy"]
  end

  subgraph Gateway["GeminiBastionMCP Gateway (UID 1001: gateway)"]
    Portal["GET / Public Portal\n(Zero Private Data)"]
    Auth["OAuth 2.1 + PKCE + DCR\nGoogle & GitHub SSO"]
    Scrub["SecretScrubber &\nUntrusted Boundary"]
    Admin["/admin Mobile PWA\nSSE Live Jobs & Rollback"]
    DB[("SQLite WAL (/data)\n0700 gateway-only")]

    subgraph Funnel["10-Tool Contract (1 Approval Gate)"]
      T1_8["Tier 1 (1-8): Workspace Autonomy & External Read-Only\nworkspace_manage · code_explore · code_patch\nworkspace_exec · dispatch_runner · job_status\ngithub_inspect · infra_inspect"]
      T9["Tier 2 (9): Two-Phase Stage\nstage_mutation_plan (15m TTL + Snapshot)"]
      T10["Tier 3 (10): Single External Write Gate\npublish_changes (PR / CF Deploy / Execute Plan)"]
    end
  end

  subgraph Sandbox["Isolated Workspace Sandbox (/workspaces)"]
    WS["/workspaces/{slug}\nGIT_INDEX_FILE Checkpoints\nL0/L1/L2 Validation"]
    Shell["workspace_exec & shell_task\nUID 1002 (worker) · 0 Secrets"]
    Codex["@openai/codex-sdk\nworkspace-write · 0 Secrets"]
  end

  subgraph External["External Targets & Internal ops_net"]
    GH["GitHub API\n(No push to main/master)"]
    CFApi["Cloudflare API\n(Workers / Pages / DNS / WAF / D1)"]
    MCP2["Downstream MCP-2 Sidecars\n(e.g. ops-ssh on ops_net)"]
  end

  Clients -->|"Streamable HTTP /mcp"| CF --> Auth --> Funnel
  CF --> Portal & Admin
  T1_8 --> WS & Shell & Codex
  T1_8 -.->|"Read-Only"| GH & CFApi & MCP2
  T9 -->|"Stage Plan + Rollback Snapshot"| DB
  T10 -->|"Audited & Scrubbed Writes"| GH & CFApi & MCP2
  Admin --> DB & WS
```

---

## 10 Tools, 1 Approval Gate

Instead of exposing 40+ fine-grained tools that bury mobile/web users under approval prompts, `GeminiBastionMCP` groups every capability by **blast radius** so you can configure per-tool approvals cleanly in Web Gemini or Claude:

### Tier 1 — Workspace-Scoped Autonomy & External Read-Only *(Safe for `Always Allow`)*

> **Why `Always Allow` is safe here**: Tools 3–5 (`code_patch`, `workspace_exec`, `dispatch_runner`) edit files and run commands **strictly inside `/workspaces/{slug}`** — protected by zero-secret `buildSandboxedEnv()`, `SecretScrubber`, and automatic `GIT_INDEX_FILE` rollback checkpoints — while performing **zero external writes** to GitHub, Cloudflare, or production hosts.

| # | Tool | Scope & Behavior |
|---|------|------------------|
| 1 | `workspace_manage` | `list`, `sync_github`, `init_cf_ops`, `list_checkpoints`, `rollback` (auto-detects stack & `AGENTS.md` / `CLAUDE.md`) |
| 2 | `code_explore` | Read-only workspace inspection: `pack` (repomix), `search` (ripgrep), `ast` (ast-grep), `read_lines`, `read_artifact`, `git_diff` |
| 3 | `code_patch` | Local workspace mutation: atomic multi-file `patch` (`hunks` + `line_hint`), `create_or_overwrite`, `delete_file` with auto-checkpoint + L0/L1/L2 validation |
| 4 | `workspace_exec` | Sandboxed shell in `/workspaces/{slug}` executed as UID `1002` (`worker`) (`wait_ms` up to `15000`; auto-promotes long runs to background SQLite `job_id`) |
| 5 | `dispatch_runner` | Background `codex_readonly`, `codex_write` (`@openai/codex-sdk` `workspace-write` sandbox), or `shell_task` (UID `1002`) with thread resume, token/duration budgets, and auto-checkpoint |
| 6 | `job_status` | Poll job status, streamed events, token usage, `thread_id`, `git status -sb`, final report, or `cancel: true` |
| 7 | `github_inspect` | External read-only: PR diffs/files, issue threads, and failed Actions logs (wrapped with untrusted-data boundary markers) |
| 8 | `infra_inspect` | External read-only: Cloudflare inspection (`zones`, `dns_records`, `workers`, `pages`, `kv_namespaces`, `d1_databases`, `waf_rules`, `worker_tail_logs`) + downstream MCP-2 `readonlyTools` |

### Tier 2 — Zero-Side-Effect Change Staging *(Safe for `Always Allow`)*

| # | Tool | Actions & Behavior |
|---|------|--------------------|
| 9 | `stage_mutation_plan` | Captures pre-change live state to build a `rollback_payload` and human-readable diff, issuing a 15-minute `plan_id`. Supports **5 Cloudflare plan types** (`dns_record_create`, `dns_record_update`, `dns_record_delete`, `waf_rule_update`, `d1_sql_mutation`) plus downstream MCP-2 `mutatingTools`. **Performs zero writes.** |

### Tier 3 — Single External Write Gate *(Set to `Ask Before Running`)*

| # | Tool | Actions & Behavior |
|---|------|--------------------|
| 10 | `publish_changes` | **The ONLY external write exit**: `github_pr` (blocks direct push to `main`/`master`/default), `github_pr_review`, `github_comment`, `cloudflare_worker_deploy` (preview URL default), `cloudflare_pages_deploy`, `execute_staged_plan`, `rollback_plan`. |

---

## Visual UI Preview

<table>
  <tr>
    <td width="50%" align="center">
      <img src="docs/assets/preview-portal.svg" alt="GeminiBastionMCP Public Gateway Portal (GET /)" width="100%" />
      <br />
      <sub><strong>Public Gateway Portal (<code>GET /</code>)</strong> — Zero-data-leak status page with one-click <code>/mcp</code> copy, <code>.well-known</code> links &amp; JSON content negotiation.</sub>
    </td>
    <td width="50%" align="center">
      <img src="docs/assets/preview-admin.svg" alt="GeminiBastionMCP Mobile Operator Cockpit (/admin PWA)" width="100%" />
      <br />
      <sub><strong>Mobile Operator Cockpit (<code>/admin</code> PWA)</strong> — 4-KPI Pulse Strip, SSE live job streaming, one-click <code>Kill</code> / <code>Rollback</code> confirmations &amp; scrubbed audit trail.</sub>
    </td>
  </tr>
</table>

---

## 3-Minute Quick Start

### Option A: Docker Compose + Cloudflare Tunnel (Recommended)

[`docker/docker-compose.yml`](docker/docker-compose.yml) runs `gateway` with **zero host ports exposed** (`expose: ["8787"]` only). All external HTTPS traffic enters through `cloudflared`.

1. **Clone & initialize `.env`**:
   ```bash
   git clone https://github.com/Kaiserunix/gemini-bastion-mcp.git
   cd gemini-bastion-mcp
   cp .env.example .env
   ```

2. **Generate `OAUTH_SIGNING_SECRET` and `ADMIN_PASSWORD_HASH` (`scrypt:`) in one shot** (Node 22+):
   ```bash
   node -e 'const c=require("node:crypto"),s=c.randomBytes(16).toString("hex");console.log(`OAUTH_SIGNING_SECRET=${c.randomBytes(32).toString("hex")}\nADMIN_PASSWORD_HASH=scrypt:${s}:${c.scryptSync(process.argv[1],s,32,{N:16384,r:8,p:1}).toString("hex")}`)' 'your-admin-password'
   ```
   *(The `scrypt:<saltHex>:<keyHex>` format contains no `$` characters, avoiding Docker Compose `.env` interpolation issues; legacy `scrypt$...` and `sha256:` formats remain supported if `$` is escaped as `$$`.)*

3. **Fill required `.env` values**:
   - `PUBLIC_DOMAIN=https://mcp.yourdomain.com`
   - `TRUST_CF_CONNECTING_IP=true`
   - `OAUTH_SIGNING_SECRET=<generated above>`
   - `ADMIN_PASSWORD_HASH=<generated above>`
   - `CLOUDFLARE_TUNNEL_TOKEN=<your Cloudflare Zero Trust tunnel token>`
   - Optional client & integration settings: append `claude.ai,chatgpt.com` to `OAUTH_ALLOWED_REDIRECT_HOSTS` if connecting Claude/ChatGPT; add `GH_TOKEN`, `OPENAI_API_KEY` / `CODEX_API_KEY`, `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_READONLY_API_TOKEN`, `CLOUDFLARE_API_TOKEN` as needed.

4. **Point your Cloudflare Tunnel Public Hostname** (Zero Trust → Networks → Tunnels) for `mcp.yourdomain.com` to `http://gateway:8787`.

5. **Build & launch with a single root `.env`** (pass `--env-file .env` so `cloudflared` reads `CLOUDFLARE_TUNNEL_TOKEN` from root `.env` without creating a separate `docker/.env`):
   ```bash
   docker compose --env-file .env -f docker/docker-compose.yml up -d --build
   ```

> [!IMPORTANT]
> **Node 22 & Token Isolation Baseline**: [`docker/Dockerfile`](docker/Dockerfile) enforces `Node >= 22.23.4` at build time (override with `NODE_IMAGE=node:22.23.4-bookworm-slim` if needed). `cloudflared` receives only `TUNNEL_TOKEN` (never mounts `../.env`), and `gateway` explicitly clears `CLOUDFLARE_TUNNEL_TOKEN` from its own environment.

<details>
<summary><strong>Environment Variable Reference (.env)</strong></summary>

| Variable | Purpose |
| :--- | :--- |
| `PUBLIC_DOMAIN` | Exact HTTPS origin of your gateway (e.g. `https://mcp.yourdomain.com`) |
| `TRUST_CF_CONNECTING_IP` | `true` behind Cloudflare Tunnel/CDN; `false` behind standalone Nginx |
| `OAUTH_SIGNING_SECRET` | `>= 32`-character random hex/base64 secret (`NODE_ENV=production` rejects placeholders) |
| `ADMIN_PASSWORD_HASH` | `scrypt:<saltHex>:<keyHex>` (recommended) or `sha256:<hex>` |
| `OAUTH_ALLOWED_REDIRECT_HOSTS` | Allowed OAuth client redirect hosts (append `claude.ai,chatgpt.com` for Claude/ChatGPT DCR) |
| `OAUTH_STATIC_CLIENT_ID` / `_SECRET` | Optional static OAuth client credentials (fallback for non-DCR clients) |
| `GOOGLE_OAUTH_*` / `GITHUB_OAUTH_*` | Optional fail-closed upstream operator SSO credentials + allowlists |
| `GH_TOKEN` | GitHub PAT (gateway-only; never exposed to `workspace_exec` or Codex) |
| `CLOUDFLARE_ACCOUNT_ID` / `_READONLY_API_TOKEN` / `_API_TOKEN` | Cloudflare account + split read-only vs write tokens |
| `OPENAI_API_KEY` / `CODEX_API_KEY` | OpenAI / Codex SDK runner credentials (`CODEX_DEFAULT_MODEL`, `CODEX_TOKEN_BUDGET`) |
| `NOTIFY_WEBHOOK_URL` | Optional webhook endpoint for scrubbed job & plan alerts |
| `DOWNSTREAM_MCPS_FILE` / `_JSON` | Optional downstream MCP-2 federation registry |

</details>

### Option B: Reverse Proxy with Nginx (Loopback Host Port)

Bind `gateway` strictly to loopback (`127.0.0.1:8787:8787` or `127.0.0.1:39120:8787`) via a `docker-compose.override.yml`, set `TRUST_CF_CONNECTING_IP=false` in `.env` (unless fronted by Cloudflare), and run `gateway` without `cloudflared`:

```bash
docker compose --env-file .env -f docker/docker-compose.yml up -d --build gateway
```

<details>
<summary><strong>Nginx Reverse Proxy Config (Streamable HTTP, SSE &amp; 8KB OAuth State)</strong></summary>

```nginx
server {
  listen 443 ssl http2;
  server_name mcp.yourdomain.com;

  # Required so Gemini's 2400-8192 byte OAuth state query string never hits 414 Request-URI Too Large
  large_client_header_buffers 4 16k;
  client_max_body_size 1m;

  location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 300s;
  }
}
```

</details>

### Option C: Local Development

**Prerequisites**: Node.js `>= 22.23.4`, `git`, and C++ build tools for `better-sqlite3`.

```bash
npm install
cp .env.example .env
# Set DATA_DIR=./.local/data, WORKSPACES_DIR=./.local/workspaces, OAUTH_SIGNING_SECRET, and ADMIN_PASSWORD_HASH
npm run typecheck
npm test
npm run dev
```

Verify at `http://127.0.0.1:8787/healthz` and `http://127.0.0.1:8787/`. Both `npm run dev` and `npm start` automatically load `.env` via Node's `--env-file-if-exists=.env`.

---

## Connecting AI Clients

`GeminiBastionMCP` implements **MCP 2025-11-25 Streamable HTTP** (stateless `/mcp`, zero legacy HTTP+SSE) with **OAuth 2.1 + PKCE (`S256`) + RFC 8707 Resource Indicators + RFC 9728 Protected Resource Metadata**.

### Web Gemini (`gemini.google.com` Connected Apps)

1. Confirm `PUBLIC_DOMAIN` matches your public HTTPS URL and `OAUTH_ALLOWED_REDIRECT_HOSTS` includes `gemini.google.com,aistudio.google.com,accounts.google.com` (default in `.env.example`).
2. In Gemini Connected Apps / Custom MCP connector settings, enter `https://mcp.yourdomain.com/mcp`.
3. Gemini automatically discovers `/.well-known/oauth-protected-resource`, `/.well-known/oauth-authorization-server`, and registers via `POST /oauth/register` (up to **16 redirect URIs** per client and **`state` up to 8192 bytes**).
4. Complete the browser OAuth consent prompt. Refresh tokens rotate with a 60-second grace window for concurrent retries.
5. **Recommended tool permissions**: Set Tools 1–9 (`workspace_manage` through `stage_mutation_plan`) to **Always Allow**, and keep Tool 10 (`publish_changes`) on **Ask Before Running**.

### Claude.ai, ChatGPT & MCP Inspector (DCR or Static Client Fallback)

> [!IMPORTANT]
> **Required for Claude.ai & ChatGPT OAuth DCR**: By default, `OAUTH_ALLOWED_REDIRECT_HOSTS` in `.env.example` only allowlists Google/Gemini and localhost hosts (`gemini.google.com,aistudio.google.com,accounts.google.com,localhost,127.0.0.1`). Before connecting Claude.ai or ChatGPT, append their callback hosts in `.env` and restart `gateway`:
> ```env
> OAUTH_ALLOWED_REDIRECT_HOSTS=gemini.google.com,aistudio.google.com,accounts.google.com,claude.ai,chatgpt.com,localhost,127.0.0.1
> ```

- **Automatic DCR**: Point Claude.ai Custom Connectors, ChatGPT MCP, or MCP Inspector directly to `https://mcp.yourdomain.com/mcp`.
- **Static Client Fallback**: Set `OAUTH_STATIC_CLIENT_ID` and `OAUTH_STATIC_CLIENT_SECRET` in `.env`, restart `gateway`, and point Authorization URL to `/oauth/authorize` and Token URL to `/oauth/token`.

---

## Upstream Operator Login (Google & GitHub OAuth)

In addition to `ADMIN_PASSWORD_HASH`, you can enable **Google OAuth** and/or **GitHub OAuth** SSO for one-tap operator sign-in on `/admin/login` and MCP consent approval on `/oauth/authorize`:

1. **Register Callback URLs**:
   - **Google Cloud Console** (OAuth 2.0 Web Application): `https://<PUBLIC_DOMAIN>/auth/idp/google/callback`
   - **GitHub Developer Settings** (OAuth App): `https://<PUBLIC_DOMAIN>/auth/idp/github/callback`
2. **Set `.env` Credentials & Allowlists**:
   - **Google**: `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, `GOOGLE_OAUTH_ALLOWED_EMAILS`
   - **GitHub**: `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, `GITHUB_OAUTH_ALLOWED_USERS`, optional `GITHUB_OAUTH_ALLOWED_IDS` *(when both users & IDs are set, both must match)*

> [!IMPORTANT]
> **Fail-Closed Single-Operator Security**: Both IdPs stay disabled unless credentials **and** a non-empty allowlist are configured — and in `NODE_ENV=production`, providing client credentials without an allowlist fails startup closed. Google requires `email_verified: true`, and all upstream flows enforce PKCE `S256`, `HttpOnly` binding cookies, and CSRF validation.

---

## 6-Layer Security & Guardrails

1. **Zero Gateway Secret Leakage**: `workspace_exec`, `shell_task`, and Codex runners use `buildSandboxedEnv()` (strict allowlist stripping `GH_TOKEN`, `CLOUDFLARE_*`, `OAUTH_SIGNING_SECRET`, `ADMIN_PASSWORD_HASH`, `NOTIFY_WEBHOOK_URL`, and `DOWNSTREAM_MCPS_*`). All outputs, artifacts, and webhooks pass through `SecretScrubber`.
2. **Linux UID 1001 / 1002 Isolation**: In Docker, `gateway` (UID `1001`) owns `/data` (`0700`, SQLite DB, `/data/artifacts`, and `CODEX_HOME=/data/codex`) and `/app`, while `worker` (UID `1002`) owns `/workspaces` and `/opt/mise` with zero access to `/data` (and `/opt/mise/shims` is excluded from `gateway`'s `PATH`). `workspace_exec` and `shell_task` drop privileges to UID `1002` (`sudo -n -H -u #1002`); Codex tasks run under `@openai/codex-sdk`'s `workspace-write` sandbox + strict env allowlist *(extending UID `1002` isolation to `code_patch` L1/L2 validation subprocesses is tracked as P0 in [docs/PRODUCT_STRATEGY.md](docs/PRODUCT_STRATEGY.md))*.
3. **Non-Destructive Git Checkpoints**: Pre-patch and pre-Codex snapshots use a temporary `GIT_INDEX_FILE` (`refs/mcp-checkpoints/*`) without mutating your working tree index or `HEAD`.
4. **Protected Branch & Diff Guard**: `publish_changes` (`github_pr`) blocks direct pushes to `main`, `master`, or the repo's default branch, and blocks committing sensitive files (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `.dev.vars*`).
5. **Untrusted Data Boundary**: External GitHub issues/PRs/logs, Cloudflare tail logs, and downstream MCP-2 responses are wrapped as untrusted external content to defend against prompt injection.
6. **OAuth 2.1 Family Rotation & Replay Protection**: Refresh token reuse outside the 60-second grace window revokes the entire token family immediately.

---

## Optional `ops-mcp` Sidecar Federation (MCP-2) & Webhooks

Federate internal HTTP or local `stdio` MCP servers (such as `uarlouski/ssh-mcp-server` bridged via `mcp-proxy` on isolated `ops_net`) without exposing SSH keys to `/workspaces`:

- Set `NOTIFY_WEBHOOK_URL` in `.env` for `SecretScrubber`-sanitized JSON POST alerts on job completion/failure or staged plan execution/rollback.
- Enable the `ops` Docker Compose profile (`docker compose --env-file .env -f docker/docker-compose.yml --profile ops up -d --build`) using [`docker/Dockerfile.ops-mcp`](docker/Dockerfile.ops-mcp) and [`docker/ops-mcp-config.example.json`](docker/ops-mcp-config.example.json):
  - `readonlyTools` run in `infra_inspect`
  - `mutatingTools` must stage via `stage_mutation_plan` before `publish_changes`
  - `deniedTools` and unlisted tools are strictly rejected

<details>
<summary><strong>Example DOWNSTREAM_MCPS_FILE Configuration (docker/ops-mcp-config.example.json)</strong></summary>

1. Create `docker/ops-ssh/` containing your restricted `config.json` and scoped SSH key(s).
2. Copy `docker/ops-mcp-config.example.json` to `docker/ops-mcp-config.json`.
3. Uncomment `./ops-mcp-config.json:/etc/gemini-bastion/ops-mcp-config.json:ro` in `docker/docker-compose.yml` and set `DOWNSTREAM_MCPS_FILE=/etc/gemini-bastion/ops-mcp-config.json` in `.env`.

```json
[
  {
    "id": "ops-ssh",
    "transport": "http",
    "url": "http://ops-mcp:8090/mcp",
    "enabled": true,
    "timeoutMs": 30000,
    "readonlyTools": ["list_hosts", "read_file", "list_directory", "get_host_status"],
    "mutatingTools": ["exec_command", "write_file", "upload_file"],
    "deniedTools": ["delete_file", "remove_directory", "create_tunnel", "raw_sudo_shell"]
  }
]
```

</details>

---

## Roadmap, Contributing, Security & Docs

- **Documentation Hub**: [Documentation Index (`docs/INDEX.md`)](docs/INDEX.md) · [Architecture & Design (`DESIGN.md`)](DESIGN.md) · [Product Strategy & Security Roadmap (`docs/PRODUCT_STRATEGY.md`)](docs/PRODUCT_STRATEGY.md) · [UX Design Spec (`docs/UX_EXPERIENCE_AND_DESIGN_SPEC.md`)](docs/UX_EXPERIENCE_AND_DESIGN_SPEC.md)
- **Roadmap**: Per-job ephemeral container/microVM worker isolation (`v0.2`), UID `1002` privilege drop for L1/L2 validation subprocesses, dedicated sidecar process for `@openai/codex-sdk` runner, and multi-operator RBAC policies.
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, architectural guardrails, and PR checklist.
- **Security Policy**: See [SECURITY.md](SECURITY.md) for threat model and private vulnerability reporting.
- **Release History & License**: [CHANGELOG.md](CHANGELOG.md) · [MIT License](LICENSE)
