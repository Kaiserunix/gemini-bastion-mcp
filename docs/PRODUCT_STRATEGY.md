# GeminiBastionMCP — Product Strategy, Security Boundary Truth & Roadmap

> **Status**: Pod A Cross-Functional Consensus (Tech Lead + Marketing & Growth + Simulated Power-User Developer)
> **Scope**: Conversion positioning, code-accurate security boundary language, onboarding friction removal, and prioritized hardening roadmap for `Kaiserunix/gemini-bastion-mcp`.

---

## 1. Executive Positioning & Hero Conversion Narrative

### Category-Defining Hook
- **Headline (EN)**: **Stop Clicking "Allow" 40 Times on Your Phone.**
- **Subhead (EN)**: The self-hosted OAuth 2.1 MCP bastion that turns Web Gemini (`gemini.google.com`), Claude.ai & ChatGPT into a sandboxed full-stack coding, Codex & Cloudflare ops agent — funneling **10 tools through 1 external write gate (`publish_changes`)**.
- **Headline (CN)**: **告别手机端连点 40 次「允许」——10 大复合工具收敛至 1 道唯一外部出闸门 (`publish_changes`)。**

### Core Differentiation vs. Generic MCP Aggregators & Local Stdio MCPs
1. **Built for Real Web Gemini OAuth 2.1 Quirks**: Native PKCE `S256` + Dynamic Client Registration supporting up to **16 redirect URIs**, **8192-byte `state`**, RFC 8707 Resource Indicators, RFC 9728 Protected Resource Metadata, and refresh-token family rotation with a 60-second concurrent retry grace window.
2. **Blast-Radius Tool Funnel**: Groups every capability into 3 approval tiers so web/mobile users set Tier 1 & Tier 2 to `Always Allow` and get prompted **only once** when shipping external side effects (`publish_changes`).
3. **Resilient Async Execution for Mobile Tabs**: `workspace_exec` auto-promotes long builds (>15s) to background SQLite jobs, `dispatch_runner` supports resumable `@openai/codex-sdk` threads, and `SecretScrubber` sanitizes webhook notifications & `/admin` mobile PWA SSE streams.
4. **Fail-Closed Operator Auth**: Supports `scrypt:` admin password hashes plus fail-closed Google & GitHub upstream OAuth (startup refuses production boot if IdP credentials lack an explicit operator allowlist).

---

## 2. Code-Truth Security Boundaries (Anti-Overpromise Contract)

To preserve high-trust developer credibility (HN / r/selfhosted / security reviewers), documentation MUST stay 100% faithful to current implementation boundaries:

| Security Claim | Exact Current Code Behavior | Documentation & Copy Rule |
| :--- | :--- | :--- |
| **Tier 1 Permission Label** | Tools 1–8 include local workspace writers (`code_patch`, `workspace_exec`, `dispatch_runner` with `codex_write`/`shell_task`) alongside external read-only tools (`github_inspect`, `infra_inspect`). | **NEVER** label Tier 1 simply `"Read-Only"`. Label it **"Tier 1 — Workspace-Scoped Autonomy & External Read-Only *(Safe for `Always Allow`)*"**, clearly noting edits stay inside `/workspaces/{slug}` with zero gateway secrets and automatic `GIT_INDEX_FILE` rollback checkpoints. |
| **Linux Dual-UID 1001 / 1002 Isolation** | `workspaceExec.ts` passes `uid: config.sandboxUid` (`sudo -n -H -u #1002`) for `workspace_exec` and `shell_task`. Currently, `validationPipeline.ts` L1/L2 repo linters/tests and `codexRunner.ts` (`CODEX_HOME=/data/codex`) still execute under UID 1001 (`gateway`), relying on `buildSandboxedEnv()` allowlist + Codex SDK `workspace-write` sandbox. | Qualify Dual-UID 1002 isolation accurately as covering `workspace_exec`/`shell_task`, while Codex uses `workspace-write` sandbox + strict env allowlist. Track extending UID 1002 privilege drop to `validationPipeline` and `codexRunner` as **P0 Security Hardening**. |
| **Cloudflare Two-Phase Staging (`stage_mutation_plan`)** | `cloudflareService.ts` currently implements **5 Cloudflare mutation plan types** (`dns_record_create`, `dns_record_update`, `dns_record_delete`, `waf_rule_update`, `d1_sql_mutation`) plus downstream MCP-2 `mutatingTools`. | List the exact 5 implemented Cloudflare plan types; do **not** claim KV writes or Worker route/secret staging until implemented. |
| **Claude.ai / ChatGPT OAuth DCR** | `DEFAULT_ALLOWED_REDIRECT_HOSTS` in `src/config.ts` / `.env.example` defaults to `gemini.google.com,aistudio.google.com,accounts.google.com,localhost,127.0.0.1`. | Explicitly instruct Claude.ai and ChatGPT operators to append `claude.ai,chatgpt.com` to `OAUTH_ALLOWED_REDIRECT_HOSTS` in `.env` (or use Static Client Fallback). |
| **Docker Compose `.env` Resolution** | `gateway` loads `env_file: ../.env`, whereas `cloudflared` reads `${CLOUDFLARE_TUNNEL_TOKEN}` via Compose variable substitution (which defaults to `docker/.env` if `--env-file` is omitted). | Standardize Quick Start on `docker compose --env-file .env -f docker/docker-compose.yml up -d --build` so operators maintain a single root `.env`. |

---

## 3. Prioritized Engineering & Decoupling Roadmap

### P0 — Security Isolation & Zero-Friction Onboarding
1. **Extend UID 1002 (`worker`) Privilege Drop to `validationPipeline.ts`**: Pass `sandboxUid`/`sandboxGid` into L1/L2 repo verification subprocesses (`biome`, `ruff`, `tsc`, `vitest`, `pytest`) so untrusted repo code never runs under UID 1001 (`gateway`, owner of `/data/gateway.db`). Audit and document `CodexSdkRunner` UID vs. bubblewrap isolation boundaries.
2. **Add `npm run init:env` Bootstrap CLI**: Generate `ADMIN_PASSWORD_HASH` (`scrypt:`), `OAUTH_SIGNING_SECRET`, and `.env` in one interactive/non-interactive command, with optional `--clients gemini,claude,chatgpt` preset that automatically populates `OAUTH_ALLOWED_REDIRECT_HOSTS`.

### P1 — Architectural Decoupling & Spec Sync
1. **Split Monolithic Integration Services**: Decompose `cloudflareService.ts` (~48 KB) and `githubService.ts` (~38 KB) into separate read-only inspection modules (`*Inspector`) and staged/write execution modules (`*Publisher`) behind typed interfaces.
2. **Sync `DESIGN.md` & Clean Legacy Identifiers**: Align `DESIGN.md` directory paths with the actual `src/core/` architecture (removing stale `workspace/`, `runners/`, `integrations/`, `security/` paths and `/home/worker/.codex` drift), align Cloudflare staging docs with the 5 implemented plan types (or implement KV/Worker-route staging), and rename the legacy `omni-mcp-gateway-federation` identifier in `downstreamMcpBridge.ts`.

### P2 — Expanded Infrastructure Coverage & Observability
1. **Expand `stage_mutation_plan` Coverage**: Add snapshot + rollback support for Cloudflare KV writes and Worker route/secret mutations.
2. **Structured Audit Sink & Policy Middleware**: Decouple rate limiting, circuit breaking, and audit-log sinks behind pluggable interfaces for multi-operator or SIEM export workflows.

---

## 4. Distribution, GitHub Metadata & Visual Asset Checklist

*(Moved here from the public README to keep the front page clean and conversion-focused.)*

- **GitHub About**: `Self-hosted OAuth 2.1 Streamable HTTP MCP bastion for Web Gemini, Claude & ChatGPT. Sandboxed git workspaces, Codex SDK, Cloudflare ops & 10-tool/1-gate funnel.`
- **GitHub Topics**: `mcp`, `model-context-protocol`, `gemini`, `claude`, `codex`, `oauth21`, `streamable-http`, `cloudflare-tunnel`, `ai-agents`, `devops`, `self-hosted`, `typescript`
- **Distribution Hooks**:
  - **HN / r/selfhosted / r/LocalLLaMA**: *"Why remote MCP servers break on Web Gemini (8KB OAuth state, 16 redirect URIs, RFC 8707/9728, and approval popup fatigue) — and our 10-tool / 1-gate bastion."*
  - **V2EX / X**: *"躺在床上用手机网页版 Gemini 改代码、跑测试、发 PR：Cloudflare Tunnel 零端口暴露 + 10 工具收口到唯一外部写闸门。"*
- **Recommended Visual Assets (`docs/assets/`)**:
  - `demo-gemini-pr.gif` — 15s Web Gemini workflow from `code_explore` → `code_patch` → single `publish_changes` PR approval
  - `portal-and-oauth.png` — `GET /` Public Gateway Portal & OAuth 2.1 consent view
  - `admin-mobile-pwa.png` — `/admin` mobile PWA cockpit showing KPI Pulse Strip & SSE live job stream
