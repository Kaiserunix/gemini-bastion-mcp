# Architecture Guardrails (`GeminiBastionMCP` / `gemini-bastion-mcp`)

These guardrails are mandatory invariants for all code, tests, and refactors in this repository.

## 1. MCP Transport, Public Portal & Tool Response Format
- **NO legacy HTTP+SSE transport**: Never implement `/sse` + `/messages` legacy MCP SSE transport.
- **Streamable HTTP Stateless Mode**: All MCP traffic MUST use `WebStandardStreamableHTTPServerTransport` from `@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js` in **stateless mode** (`sessionIdGenerator: undefined`) mounted on Hono (`/mcp`).
- **Zero-Leakage Public Gateway Portal (`GET /`)**: `GET /` MUST only serve public service metadata, Quick Connect instructions, static 10-tool contract overview, and `/admin` navigation (HTML or JSON via `Accept`); it MUST NEVER query or leak private workspaces, repo URLs, jobs, OAuth clients/tokens, or secrets, and MUST NOT use inline `onclick=` handlers.
- **Standardized Tool Outputs**: Every MCP tool handler MUST return `content: [{ type: "text", text: string }]` (and optional `isError: true` on errors). Never return raw binary/non-text content blocks or throw unhandled exceptions out of tool handlers.
- **Exact 10-Tool Surface**: Do not register ad-hoc top-level tools beyond the 10-tool contract (`workspace_manage`, `code_explore`, `code_patch`, `workspace_exec`, `dispatch_runner`, `job_status`, `github_inspect`, `infra_inspect`, `stage_mutation_plan`, `publish_changes`).

## 2. Codex Execution Model
- **NO deprecated `codex mcp-server` CLI**: Never shell out to `codex mcp-server` or parse stdio MCP from Codex CLI.
- **Official `@openai/codex-sdk`**: `CodexSdkRunner` (`src/core/codexRunner.ts`) MUST use `@openai/codex-sdk` (`Codex` / `startThread` / `resumeThread` / `runStreamed`), honoring `CODEX_DEFAULT_MODEL`, `CODEX_REASONING_EFFORT`, `CODEX_MAX_DURATION_SEC`, `CODEX_TOKEN_BUDGET`, `AbortSignal`, and sandbox mode (`read-only` vs `workspace-write`).

## 3. OAuth 2.1 + DCR + Gemini Compatibility
- **Dynamic Client Registration (DCR)**: `POST /oauth/register` MUST support up to **16 redirect URIs** per client (`redirect_uris.length <= 16`) and validate hosts against `OAUTH_ALLOWED_REDIRECT_HOSTS` (plus loopback `localhost`/`127.0.0.1`).
- **Large State Parameter**: `oauth_auth_requests.state` and OAuth authorize/callback flows MUST preserve `state` up to **8192 bytes** without truncation.
- **RFC 8707 Resource Indicator**: Validate and bind `resource` across `/authorize`, `/token`, and `/.well-known/oauth-protected-resource`, rejecting mismatched resource audiences.
- **Refresh Token Rotation & 60s Leeway**: Refresh tokens MUST use `token_family_id` rotation with a **60-second grace window (`grace_expires_at`)** for concurrent retries; reuse outside the grace window MUST revoke the entire token family.
- **Strict PKCE S256**: Only `S256` is accepted for `code_challenge_method` on public/DCR clients.

## 4. Mutation Funnel & Blast-Radius Containment
- **Single External Mutation Exit (`publish_changes`)**: Every external side effect — GitHub PR creation, PR review comments, issue comments, Cloudflare Worker/Pages deployment, staged infrastructure mutation execution, or downstream MCP-2 mutating tool execution — MUST be funneled strictly through `publish_changes`.
- **Two-Phase Staging for Infra / MCP-2 Mutations**: `infra_inspect` is strictly read-only (`readonlyTools` only). Any mutating Cloudflare API action (`dns_record_*`, `waf_rule_update`, `d1_sql_mutation`) or downstream MCP-2 `mutatingTools` call MUST first be staged via `stage_mutation_plan` (capturing a pre-change rollback snapshot for Cloudflare plans—or caller-provided `rollback_sql` for D1—and a 15-minute expiry; downstream MCP-2 plans store `rollback_payload: null`) and then explicitly executed via `publish_changes` (`execute_staged_plan`).
- **Protected Branch Enforcement**: `publish_changes` (`github_pr`) MUST NEVER push directly to `main`, `master`, or the repository's `default_branch`; it must create a feature branch, open a PR, and verify diff safety.

## 5. Secret Isolation & Output Scrubbing
- **Zero Gateway Secret Leakage**: `workspace_exec`, `dispatch_runner` (`shell_task`), and git commands MUST run with `buildSandboxedEnv()`, which constructs a strict env allowlist and strips `GH_TOKEN`, `CLOUDFLARE_*`, `OPENAI_API_KEY`, `CODEX_API_KEY`, `OAUTH_SIGNING_SECRET`, `GOOGLE_OAUTH_CLIENT_SECRET`, `GITHUB_OAUTH_CLIENT_SECRET`, `ADMIN_PASSWORD_HASH`, `NOTIFY_WEBHOOK_URL`, and `DOWNSTREAM_MCPS_*`. `CodexSdkRunner` MUST use `buildCodexSandboxedEnv()`, which adds only `CODEX_HOME`, `CODEX_API_KEY`/`OPENAI_API_KEY`, and optional `CODEX_BASE_URL`/`OPENAI_BASE_URL`.
- **Mandatory `SecretScrubber`**: All tool outputs, logs, artifacts, webhook payloads, and error messages MUST pass through `SecretScrubber.scrub()` before leaving the gateway or being persisted.
- **UID & Directory Isolation**: `/data` (SQLite, `/data/artifacts`, and `CODEX_HOME=/data/codex`, owned by UID 1001 `gateway` mode `0700`) MUST live outside `/workspaces` (owned by UID 1002 `worker`) so sandboxed commands in `/workspaces/{slug}` cannot access gateway state or truncated artifacts directly.

## 6. Git Checkpoints & Artifact Offloading
- **Non-Destructive Snapshots via `GIT_INDEX_FILE`**: Auto-checkpoints before `code_patch`, `dispatch_runner`, or rollback MUST copy `.git/index` to a temporary `GIT_INDEX_FILE` and run `git add -A` / `git write-tree` / `git commit-tree` / `git update-ref` (`refs/mcp-checkpoints/*`) so the workspace's real `.git/index` and `HEAD` are never mutated unexpectedly (`git read-tree --reset -u` is used only on rollback).
- **Artifact Offloading**: Tool outputs exceeding inline byte limits MUST be written to `ARTIFACTS_DIR` (`/data/artifacts`, outside `/workspaces`), returning a bounded preview and `artifact_id` readable via `code_explore` (`mode: "read_artifact"`).

## 7. Untrusted Boundary Hardening
- Data fetched by `github_inspect` (PR bodies, issue comments, Actions logs) and `infra_inspect` (worker tail logs, downstream responses) MUST be wrapped/labeled as untrusted external content so prompt injection cannot masquerade as system instructions.
