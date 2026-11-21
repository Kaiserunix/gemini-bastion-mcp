# Changelog

All notable changes to **GeminiBastionMCP** (`gemini-bastion-mcp`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
