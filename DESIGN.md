# `GeminiBastionMCP` (`gemini-bastion-mcp`) — Engineering Architecture Specification

## 1. Overview & Goals

`GeminiBastionMCP` (`gemini-bastion-mcp`) is a self-hosted, single-operator **MCP 2025-11-25** bastion gateway engineered for web/mobile AI clients (`gemini.google.com` Connected Apps, Claude.ai, and ChatGPT), combining:
- **Stateless Streamable HTTP MCP transport** (`WebStandardStreamableHTTPServerTransport`) mounted on Hono (`/mcp`).
- **OAuth 2.1 + PKCE (`S256`) + Dynamic Client Registration (DCR) + RFC 8707 Resource Indicators** with SQLite-backed token family rotation and a 60-second refresh grace window.
- **Sandboxed Multi-Workspace Execution** with GitHub synchronization, playbook discovery (`AGENTS.md` / `CLAUDE.md`), non-destructive `GIT_INDEX_FILE` checkpoints, atomic multi-file patching with an L0/L1/L2 validation pipeline, bounded `workspace_exec` with automatic background SQLite job promotion, and out-of-workspace artifact offloading (`/data/artifacts`).
- **Native `@openai/codex-sdk` Orchestration** (`codex_readonly` / `codex_write` / `shell_task`) with thread resumption, duration/token budgets, and real `AbortController` + process-group cancellation.
- **Blast-Radius-Contained External Operations**: Read-only GitHub and Cloudflare/MCP-2 inspection (`github_inspect`, `infra_inspect`), two-phase staged mutations (`stage_mutation_plan`), and a single external mutation exit (`publish_changes`).
- **Admin PWA (`/admin`) & Webhook Notifications** for operational visibility, token/client management, audit logs, and job monitoring.

---

## 2. Runtime Stack & Directory Layout

- **Runtime**: Node.js 22+ LTS (ESM `"type": "module"`), TypeScript 5.7+ (`strict: true`, `moduleResolution: "NodeNext"`).
- **Web & Transport**: `hono`, `@hono/node-server`, `@modelcontextprotocol/sdk` (`>=1.24.0`).
- **Persistence**: `better-sqlite3` in WAL mode (`foreign_keys = ON`, `busy_timeout = 5000`).
- **Integrations**: `@openai/codex-sdk`, `octokit`, `cloudflare`, `zod`.
- **Testing**: `vitest`.

```text
src/
├── index.ts                      # HTTP server entrypoint, graceful shutdown, router wiring
├── config.ts                     # Zod-validated env configuration + loadConfig(env?)
├── types.ts                      # Shared domain, DB, runner, validation, and MCP tool types
├── db/
│   ├── sqlite.ts                 # WAL setup, pragmas, idempotent versioned migrations
│   └── repositories/             # Typed SQLite DAOs (oauth, workspace, job, plan, audit)
├── utils/
│   ├── exec.ts                   # Cross-platform process-group runner + buildSandboxedEnv()
│   └── secretScrubber.ts         # SecretScrubber (env secret collection + token regexes)
├── auth/                         # OAuth 2.1, DCR, PKCE, RFC 8707, Bearer middleware, Admin auth
├── admin/                        # /admin PWA UI & JSON management APIs
├── mcp/
│   ├── server.ts                 # Hono /mcp Streamable HTTP stateless handler + 10-tool registry
│   └── tools/                    # Implementations of the 10 MCP tools
├── workspace/                    # Git sync, checkpoints (GIT_INDEX_FILE), stack/playbook detector, artifacts
├── runners/                      # CodexRunner (@openai/codex-sdk), ShellRunner, JobManager
├── integrations/                 # GitHub Octokit, Cloudflare SDK, Downstream MCP-2 federation, Webhooks
└── security/                     # Path traversal guards, untrusted-boundary wrappers, audit helpers
```

---

## 3. Transport & HTTP Surface

1. **No Legacy HTTP+SSE**: `/sse` and `/messages` legacy transports are strictly prohibited.
2. **MCP Endpoint (`ALL /mcp`)**:
   - Protected by OAuth Bearer token middleware validating signature/DB state, expiration, revocation, and RFC 8707 `resource` audience matching `PUBLIC_DOMAIN` / `${PUBLIC_DOMAIN}/mcp`.
   - Uses `WebStandardStreamableHTTPServerTransport` in **stateless mode** (`sessionIdGenerator: undefined`) so horizontal restarts or serverless/edge proxy reconnects never lose session state.
   - Every tool returns `content: [{ type: "text", text }]` (with `isError: true` on tool failures) scrubbed via `SecretScrubber`.
3. **Public Portal, Health & Discovery Endpoints**:
   - `GET /`: Public Gateway Portal (dark-themed status & Quick Connect landing page with copyable `/mcp` endpoint, `.well-known` discovery links, static 10-tool tier badges, and `/admin` link; supports `Accept: application/json` content negotiation). **Strict zero-leakage invariant**: `GET /` MUST NEVER query or expose private workspaces, repo URLs, jobs, OAuth clients/tokens, or internal secrets.
   - `GET /healthz`: Unauthenticated liveness/DB readiness check.
   - `GET /.well-known/oauth-protected-resource` (and `/.well-known/oauth-protected-resource/mcp`): RFC 9728 metadata pointing to `authorization_servers: [PUBLIC_DOMAIN]` and `resource`.
   - `GET /.well-known/oauth-authorization-server`: RFC 8414 metadata advertising `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint`, `code_challenge_methods_supported: ["S256"]`, `scopes_supported`.

---

## 4. OAuth 2.1, DCR, PKCE & Token Rotation

Designed specifically for strict OAuth 2.1 compliance and `gemini.google.com` Connected Apps compatibility:

- **Dynamic Client Registration (`POST /oauth/register`)**:
  - Accepts up to **16 `redirect_uris`** per client (`1 <= redirect_uris.length <= 16`).
  - Validates every redirect URI host against `OAUTH_ALLOWED_REDIRECT_HOSTS` (plus `localhost` / `127.0.0.1` loopback); HTTPS required for non-loopback hosts.
  - Also supports pre-configured static client (`OAUTH_STATIC_CLIENT_ID` / `OAUTH_STATIC_CLIENT_SECRET`) upserted at boot.
- **Authorization Endpoint (`GET /oauth/authorize` & `POST /oauth/authorize`)**:
  - Requires PKCE (`code_challenge_method=S256`).
  - Preserves `state` up to **8192 bytes** in SQLite (`oauth_auth_requests.state`).
  - Validates RFC 8707 `resource` parameter when supplied and binds it through auth request -> auth code -> access/refresh tokens.
  - Renders single-operator consent/login page protected by `ADMIN_PASSWORD_HASH` verification (recommended Docker-Compose-safe `scrypt:<saltHex>:<keyHex>`; also supports `scrypt$<saltHex>$<keyHex>`, `sha256:<hex>`, and `sha256$<hex>`) and a per-request CSRF token (`csrf_token`).
- **Token Endpoint (`POST /oauth/token`)**:
  - `grant_type=authorization_code`: Atomically consumes `oauth_codes` row, verifies `code_verifier` against `code_challenge` (`S256`), validates `redirect_uri` and `client_id` (and secret for confidential clients), issues opaque/signed access token (`1h` default) + refresh token (`30d` default) under a new `token_family_id`.
  - `grant_type=refresh_token`:
    - Implements **token family rotation** with a **60-second grace leeway (`grace_expires_at`)**.
    - First use of a valid refresh token rotates to a fresh refresh token in the same `token_family_id` and sets `grace_expires_at = now + 60_000` on the old token so concurrent client retries succeed gracefully within 60s.
    - Reuse of an already-rotated refresh token *after* `grace_expires_at` triggers immediate revocation of the entire `token_family_id` (theft detection).

---

## 5. SQLite Data Model (`src/db/sqlite.ts`)

SQLite operates in WAL mode (`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;`) at `${DATA_DIR}/gateway.db` (strictly outside `WORKSPACES_DIR`):

1. `oauth_clients (client_id PK, client_secret_hash, client_name, redirect_uris_json, is_static, created_at)`
2. `oauth_auth_requests (auth_req_id PK, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope, resource, csrf_token, expires_at, used)`
3. `oauth_codes (code PK, client_id, redirect_uri, code_challenge, scope, resource, expires_at, used)`
4. `oauth_tokens (token_hash PK, token_type, client_id, scope, resource, token_family_id, expires_at, grace_expires_at, revoked, created_at)`
5. `workspaces (slug PK, repo_url, default_branch, detected_stack_json, playbook_text, last_synced_at)`
6. `checkpoints (checkpoint_id PK, workspace_slug, git_commit_sha, git_ref, reason, created_at)`
7. `jobs (job_id PK, workspace_slug, runner_type, status, command_or_objective, codex_thread_id, checkpoint_id, events_json, token_usage_json, final_report_text, error_message, created_at, updated_at)`
8. `mutation_plans (plan_id PK, target_service, summary_diff_text, payload_json, rollback_payload_json, status, expires_at, created_at, executed_at)`
9. `audit_logs (id PK AUTOINCREMENT, actor, action, target, status, details_json, created_at)`

---

## 6. Security & Isolation Architecture

### 6.1 Secret Isolation & Scrubbing
- **Gateway Process vs. Workspace Subprocesses**: `GH_TOKEN`, `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_READONLY_API_TOKEN`, `OPENAI_API_KEY`, `CODEX_API_KEY`, `OAUTH_SIGNING_SECRET`, `ADMIN_PASSWORD_HASH`, `NOTIFY_WEBHOOK_URL`, and `DOWNSTREAM_MCPS_*` exist only in the gateway process.
- **`buildSandboxedEnv()` (`src/utils/exec.ts`)**: Constructs a minimal allowlist environment (`PATH`, `HOME`, `LANG`, toolchain caches) and rejects/strips all sensitive keys while enforcing `CI=true`, `DEBIAN_FRONTEND=noninteractive`, `GIT_TERMINAL_PROMPT=0`, `PAGER=cat`.
- **`SecretScrubber` (`src/utils/secretScrubber.ts`)**: Collects all sensitive env/config values (`length >= 8`) plus regexes for `ghp_`, `gho_`, `github_pat_`, `sk-`, JWT `eyJ...`, `Bearer`/`Basic` headers, URL credentials, and Cloudflare tokens, replacing matches with `[REDACTED_SECRET]` across all MCP responses, artifacts, logs, and webhooks.

### 6.2 Filesystem & UID Separation
- `/data` (SQLite DB + `/data/artifacts`) is owned by `gateway` (UID 1001, mode `0700`).
- `/workspaces` and `/home/worker/.codex` are owned by `worker` (UID 1002).
- `ARTIFACTS_DIR` is validated by `loadConfig()` to never reside inside `WORKSPACES_DIR`.
- All workspace path operations resolve symlinks (`fs.realpath`) and verify containment within `/workspaces/{slug}`.

### 6.3 Non-Destructive Checkpoints (`GIT_INDEX_FILE`)
- Checkpoints snapshot tracked **and** untracked workspace files using a temporary index file (`GIT_INDEX_FILE=<tmp>` + `git read-tree` / `git add -A` / `git write-tree` / `git commit-tree`) stored under `refs/mcp-checkpoints/<checkpoint_id>` and recorded in SQLite `checkpoints`.
- The workspace's real `.git/index` and `HEAD` remain completely untouched during snapshot creation.

### 6.4 Untrusted Content Boundary
- Data returned by `github_inspect` (PR descriptions, issue bodies/comments, GitHub Actions logs) and `infra_inspect` (worker tail logs, downstream MCP responses) is explicitly tagged/delimited as untrusted external data to mitigate indirect prompt injection.

---

## 7. The 10-Tool MCP Contract

All 10 tools register explicit MCP annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`) and return `{ content: [{ type: "text", text }] }`:

### 1. `workspace_manage`
- **Annotations**: `readOnlyHint: false`, `destructiveHint: false`, `openWorldHint: false`
- **Actions**:
  - `list`: List registered workspaces, default branches, detected stacks, and last sync timestamps.
  - `sync_github`: Clone or fast-forward/sync a GitHub repository (`owner/repo` or URL) into `/workspaces/{slug}`, detect stack (Node/Python/Go/Rust/Docker/Wrangler), and ingest repo playbooks (`AGENTS.md`, `CLAUDE.md`).
  - `init_cf_ops`: Inspect/scaffold Cloudflare Worker/Pages operational context and `wrangler` metadata for a workspace.
  - `list_checkpoints`: List git checkpoints recorded for `{slug}`.
  - `rollback`: Restore workspace working tree to a target `checkpoint_id` (creating a safety checkpoint first).

### 2. `code_explore`
- **Annotations**: `readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: false`
- **Actions**:
  - `pack`: Generate a token-budgeted repository map/pack (via `repomix` or structured walker respecting `.gitignore`).
  - `search`: Fast regex/literal search (`ripgrep` / fallback) with file globs and context lines.
  - `ast`: Structural AST search (`ast-grep` / fallback) across supported languages.
  - `read_lines`: Bounded line-range file reader (`start_line`, `end_line`).
  - `read_artifact`: Paginated reader (`offset`, `limit`) for offloaded outputs stored in `ARTIFACTS_DIR` by `artifact_id`.
  - `git_diff`: Inspect staged/unstaged/branch diffs in `/workspaces/{slug}` (auto-offloading oversized diffs to `ARTIFACTS_DIR`).

### 3. `code_patch`
- **Annotations**: `readOnlyHint: false`, `destructiveHint: false`, `openWorldHint: false`
- **Actions**:
  - `patch`: Multi-file atomic edits using structured `hunks` (`old_text`, `new_text`, optional `line_hint` for disambiguation). Validates all files before writing; creates a pre-patch checkpoint.
  - `create_or_overwrite`: Atomically create or replace files within `/workspaces/{slug}`.
  - `delete_file`: Safely delete specified files within `/workspaces/{slug}`.
- **L0/L1/L2 Validation Pipeline** (optional/configurable post-patch):
  - **L0**: Syntax / parse / fast lint (`biome`, `ruff`, `shellcheck`, `hadolint`, `actionlint`, `tsc --noEmit` / `pyright`).
  - **L1**: Targeted unit tests (`vitest`, `pytest`, etc.) scoped to affected files/modules.
  - **L2**: Full project build / typecheck / test verification.
  - Automatically rolls back or reports structured diagnostics if validation fails when `rollback_on_failure` is enabled.

### 4. `workspace_exec`
- **Annotations**: `readOnlyHint: false`, `destructiveHint: false`, `openWorldHint: false`
- **Behavior**:
  - Executes a shell command in `/workspaces/{slug}` using `buildSandboxedEnv()` (zero gateway secrets).
  - Bounded synchronous wait: default `wait_ms: 12000`, maximum `15000`.
  - If the command finishes within `wait_ms`, returns scrubbed `stdout`/`stderr` (offloading to `ARTIFACTS_DIR` if > `INLINE_OUTPUT_MAX_BYTES`).
  - If the command is still running at `wait_ms`, **auto-promotes** the live process to a background SQLite job (`jobs` table) and returns the `job_id` immediately without killing the process.

### 5. `dispatch_runner`
- **Annotations**: `readOnlyHint: false`, `destructiveHint: false`, `openWorldHint: false`
- **Modes**:
  - `codex_readonly`: Runs `@openai/codex-sdk` in `read-only` sandbox mode (for deep analysis, planning, audits).
  - `codex_write`: Creates a pre-run git checkpoint, then runs `@openai/codex-sdk` in `workspace-write` mode.
  - `shell_task`: Launches a long-running background shell task tracked in SQLite `jobs`.
- **Capabilities**: Supports `resume_thread_id` for continuing Codex threads, configurable `model`, `reasoning_effort`, `max_duration_sec`, `token_budget`, and real `AbortController` cancellation. Emits webhook notifications on completion/failure when `NOTIFY_WEBHOOK_URL` is configured.

### 6. `job_status`
- **Annotations**: `readOnlyHint: true` (note: supports `cancel: true` for aborting a job), `destructiveHint: false`, `openWorldHint: false`
- **Behavior**:
  - Returns job `status`, `runner_type`, `codex_thread_id`, `checkpoint_id`, incremental `events` (supports `since_seq`), `token_usage`, live `git status -sb` for the workspace, and `final_report_text` / `error_message`.
  - When `cancel: true`, triggers the job's `AbortController` and executes cross-platform process-group termination (`SIGTERM` -> `SIGKILL` / `taskkill /T /F`).

### 7. `github_inspect`
- **Annotations**: `readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: true`
- **Behavior**:
  - Read-only GitHub inspection via Octokit (`GH_TOKEN`): PR metadata/files/reviews/checks, Issue details & comments, and GitHub Actions workflow run/job logs (including failed step log extraction).
  - Wraps all returned external text in explicit untrusted-data boundaries.

### 8. `infra_inspect`
- **Annotations**: `readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: true`
- **Actions**:
  - **Cloudflare Read-Only** (uses `CLOUDFLARE_READONLY_API_TOKEN` with fallback to `CLOUDFLARE_API_TOKEN`): `zones | dns_records | workers | pages | kv_namespaces | d1_databases | waf_rules | worker_tail_logs`.
  - **Downstream MCP-2 Read-Only Federation**: `downstream_list` (lists configured downstream servers and their allowed read-only/mutating tool policies) and `downstream_call` (strictly enforces that the requested tool is in `readonlyTools` and NOT in `deniedTools` or `mutatingTools`).

### 9. `stage_mutation_plan`
- **Annotations**: `readOnlyHint: false`, `destructiveHint: false`, `openWorldHint: false`
- **Behavior**:
  - Stages an infrastructure mutation for **Cloudflare** (e.g., DNS record create/update/delete, KV write/delete, Worker route/secret/setting update, WAF rule update) or a **Downstream MCP-2** tool listed in `mutatingTools`.
  - Fetches current state to capture a `rollback_payload` snapshot, renders a human-readable `summary_diff_text`, and persists the plan in `mutation_plans` with a **15-minute TTL** (`expires_at`) returning `plan_id`.
  - Performs **zero** external writes.

### 10. `publish_changes`
- **Annotations**: `readOnlyHint: false`, `destructiveHint: true`, `openWorldHint: true`
- **Role**: The **only** external mutation exit in the entire gateway. Every action is recorded in `audit_logs` and optionally fires `NOTIFY_WEBHOOK_URL`.
- **Actions**:
  - `github_pr`: Pushes a non-default feature branch and creates/updates a Pull Request. **Strictly blocks** direct push to `main`, `master`, or `default_branch`. Runs secret-scan sanity checks on diff before pushing.
  - `github_pr_review`: Submits a PR review with line-level GitHub ```` ```suggestion ```` blocks or review comments.
  - `github_comment`: Posts a comment on a GitHub Issue or PR.
  - `cloudflare_worker_deploy`: Deploys a Worker from a workspace (defaults to preview/versions URL unless production promotion is explicitly requested).
  - `cloudflare_pages_deploy`: Deploys Pages assets/branch from a workspace.
  - `execute_staged_plan`: Atomically claims a non-expired `staged` `plan_id` from SQLite and executes the Cloudflare or Downstream MCP-2 mutation.
  - `rollback_plan`: Executes the stored `rollback_payload` for a previously executed `plan_id` and marks it `rolled_back`.

---

## 8. Downstream MCP-2 Federation

Configured via `DOWNSTREAM_MCPS_JSON` or `DOWNSTREAM_MCPS_FILE`:
- Supports both `http` (Streamable HTTP over internal Docker network e.g. `ops_net`) and `stdio` transports.
- Enforces per-server capability lists:
  - `deniedTools`: Always blocked.
  - `readonlyTools`: Callable via `infra_inspect` (`downstream_call`).
  - `mutatingTools`: Must be staged via `stage_mutation_plan` and executed via `publish_changes` (`execute_staged_plan`).

---

## 9. Admin PWA (`/admin`) & Webhook Notifications

- **`/admin`**: Lightweight progressive web app (manifest + service worker + cookie/CSRF-protected login using `ADMIN_PASSWORD_HASH`) providing:
  - Workspace status, sync/checkpoint overview
  - Active & recent jobs with live log/event tail and cancel button
  - Staged & executed mutation plans with diff preview
  - OAuth DCR clients & active token families with one-click revocation
  - Audit log viewer
- **Webhook Notifications (`NOTIFY_WEBHOOK_URL`)**:
  - Fires scrubbed JSON POST events on async job completion/failure/timeout and `publish_changes` executions.
