# Changelog

All notable changes to **GeminiBastionMCP** (`gemini-bastion-mcp`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-11-21

### Added
- **Cross-Session Persistent Workspace Memory (`workspace_memories`)**:
  - Added SQLite migration v3 (`workspace_memories`) and `MemoryRepository` (`task_state`, `decision`, `pitfall`, `preference`, `note`; up to 100 entries / 8KB per entry).
  - Extended `workspace_manage` with `memory_list`, `memory_upsert` (scans for secrets before persisting), and `memory_delete`, plus automatic memory recall in `list`, `sync_github`, and `init_cf_ops`.
  - Added `include_memory` (default `true`) on `dispatch_runner` to inject `[Workspace Persistent Memory]` context into background coding agents, and added a **Memory** tab (`GET /admin/api/memories`, `DELETE /admin/api/memories/:id`) to `/admin`.
- **MCP `instructions` & 4 Built-In MCP Prompts**:
  - Added `MCP_SERVER_INSTRUCTIONS` to `McpServer` initialization and registered `review_pr`, `fix_issue`, `resume_workspace_task`, and `ops_health_check` prompts while preserving the 10-tool contract.
- **Optional Read-Only GitHub CI Watchdog (`POST /webhooks/github`)**:
  - Added HMAC-SHA256 verified (`GITHUB_WEBHOOK_SECRET`), repo-allowlisted (`WATCHDOG_ALLOWED_REPOS`), fail-closed `workflow_run` failure diagnostics dispatching strictly `mode: "readonly"` agent runs, saving `ci-failure-<runId>` `task_state` memory, and notifying via `NOTIFY_WEBHOOK_URL`.
- **Gemini Gem / Claude Project System Prompt (`docs/GEMINI_GEM_PROMPT.md`)**:
  - Added ready-to-paste bilingual SOP system prompts and setup guide (`docs/GEMINI_GEM_PROMPT.md` + `site/index.html`).
- **Automated Official MCP Registry Publishing (`github-oidc`)**:
  - Fixed `server.json` description length (`<= 100` chars, validated via `mcp-publisher 1.8.10`) and added `publish-mcp-registry` OIDC job in `.github/workflows/docker-publish.yml` triggered on `v*` tags after GHCR push.

## [0.2.0] - 2026-11-21

### Added
- **Zero-Build GHCR Dual Images & Official MCP Registry (`server.json`)**:
  - Added multi-target `docker/Dockerfile` (`runtime-lite` ~300–400MB fast onboarding image + `runtime-full` full linter/toolchain image) and `.github/workflows/docker-publish.yml` publishing `ghcr.io/kaiserunix/gemini-bastion-mcp:{lite,full,latest}` and `ghcr.io/kaiserunix/gemini-bastion-mcp-ops:latest`.
  - Added Official MCP Registry manifest [`server.json`](server.json) (`io.github.kaiserunix/gemini-bastion-mcp`, schema `2025-12-11`).
- **Per-Workspace `bwrap` Filesystem & Network Jail (`Security v2`)**:
  - `workspace_exec` and CLI agent drivers run inside a per-workspace Linux `bubblewrap` (`bwrap`) sandbox (`--ro-bind / /`, `--tmpfs /workspaces`, `--bind <workspaceDir>`, `--tmpfs /data`, `--unshare-net` by default; opt-in `allow_network: true` on `workspace_exec`), configurable via `SANDBOX_BWRAP_ISOLATION` and fail-closed `SANDBOX_STRICT_ISOLATION`.
- **Pluggable Multi-Agent Drivers**:
  - Added `AgentRunnerRegistry` supporting `codex` (`@openai/codex-sdk`), `claude_code` (`ANTHROPIC_API_KEY`), `gemini_cli` (`GEMINI_API_KEY`), and `opencode` via `DEFAULT_AGENT_DRIVER` or per-call `dispatch_runner` (`runner_type: "agent_readonly" | "agent_write"`, `agent_driver`).
- **Authenticated `ops-mcp` Bearer Proxy & Dedicated `isolated-runner` Sidecar**:
  - Added zero-dep `docker/ops-mcp-auth-proxy.mjs` enforcing `OPS_MCP_AUTH_TOKEN` (>= 24 chars, `crypto.timingSafeEqual`) on `ops-mcp` port `9000`, plus `authToken`/`authTokenEnv` per-request Bearer injection in `DownstreamMcpBridge`.
  - Added `src/runner/sidecarServer.ts` (`npm run start:runner`) and optional `isolated-runner` Docker Compose profile (`profiles: ["isolated-runner"]`, UID `1002`, zero `/data` or gateway secrets, authenticated via `AGENT_RUNNER_AUTH_TOKEN`).
- **Multi-Client Positioning**:
  - Updated portal, showcase (`site/`), and bilingual docs to highlight **Web Gemini (`gemini.google.com`), `claude.ai` Custom Connectors, and ChatGPT MCP** equally.

## [0.1.0] - 2026-11-21

### Added
- **MCP 2025-11-25 Streamable HTTP Gateway**: Stateless `WebStandardStreamableHTTPServerTransport` mounted at `/mcp` on Hono + Node.js 22 LTS (`>= 22.23.4`).
- **10-Tool, 1-Approval-Gate Contract**:
  - Tier 1 (`Always Allow`): `workspace_manage`, `code_explore`, `code_patch`, `workspace_exec`, `dispatch_runner`, `job_status`, `github_inspect`, `infra_inspect`.
  - Tier 2 (`Always Allow`): `stage_mutation_plan` (15-minute TTL + pre-change rollback snapshot).
  - Tier 3 (`Ask Before Running`): `publish_changes` (single external write exit for GitHub PRs/reviews/comments, Cloudflare Workers/Pages deploys, and staged plan execution/rollback).
- **OAuth 2.1 + PKCE (`S256`) + DCR**: Full `/.well-known/oauth-protected-resource` (RFC 9728), `/.well-known/oauth-authorization-server` (RFC 8414), RFC 8707 Resource Indicators, DCR up to 16 redirect URIs, 8192-byte `state` preservation for `gemini.google.com` Connected Apps, 60-second refresh token rotation grace window with family revocation on replay, and static client fallback.
- **Upstream Operator SSO (Google & GitHub OAuth)**: Fail-closed single-operator login on `/admin/login` and `/oauth/authorize` via `GOOGLE_OAUTH_*` (`email_verified: true` + email allowlist) and `GITHUB_OAUTH_*` (user/ID allowlists), protected by PKCE `S256`, `HttpOnly` binding cookies, and CSRF validation.
- **Public Gateway Portal (`GET /`) & Mobile `/admin` PWA**: Zero-leakage dark-theme `GET /` portal (HTML + JSON content negotiation) and mobile-first `/admin` operator cockpit with 4-KPI Pulse Strip, one-click `/mcp` copy, SSE live job logs, confirmation prompts on destructive actions, and scrubbed `audit_logs`.
- **Execution Sandbox & Validation**: Non-destructive `GIT_INDEX_FILE` checkpoints (`refs/mcp-checkpoints/*`), L0/L1/L2 validation pipeline (`tsc`, `biome`, `ruff`, `pyright`, `shellcheck`, `hadolint`, `actionlint`, `gitleaks`), `@openai/codex-sdk` runner with thread resume and budget caps, strict `buildSandboxedEnv()` allowlist, `SecretScrubber`, and out-of-workspace `/data/artifacts` offloading.
- **MCP-2 Sidecar Federation & Webhooks**: `DownstreamMcpBridge` (`DOWNSTREAM_MCPS_FILE` / `DOWNSTREAM_MCPS_JSON`) with `readonlyTools` / `mutatingTools` / `deniedTools` policy enforcement, optional `ops-mcp` Docker sidecar on internal `ops_net`, and scrubbed `NOTIFY_WEBHOOK_URL` alerts.
- **Production Packaging & GitHub Pages Showcase**: Hardened multi-stage `docker/Dockerfile` (`gateway` UID 1001 / `worker` UID 1002 isolation, `Node >= 22.23.4` gate), `docker/Dockerfile.ops-mcp`, `docker/docker-compose.yml`, bilingual `README.md` / `README.zh-CN.md`, CI/Pages workflows, and static showcase portal under `site/`.

### Security
- Completed independent multi-round security audits (Neon + GPT-6.2-Astra `xhigh` reasoning), hardening redirect URI validation, symlink/NTFS traversal checks, git flag-injection guards, scope enforcement (`mcp:read` vs `mcp:write`/`mcp:tools`), `/mcp` Origin allowlisting, atomic SQLite state transitions, and Docker `PATH`/`CODEX_HOME`/`cloudflared` isolation (59/59 automated Vitest checks passing).
