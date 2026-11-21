# `GeminiBastionMCP` (`gemini-bastion-mcp`) — Architecture Specification

> See [docs/INDEX.md](docs/INDEX.md) for the documentation map and [.agents/rules/architecture-guardrails.md](.agents/rules/architecture-guardrails.md) for mandatory invariants.

## 1. Overview, Runtime Stack & Validated Commands

`GeminiBastionMCP` is a self-hosted, single-operator **MCP 2025-11-25** bastion gateway for web/mobile AI clients (`gemini.google.com` Connected Apps, Claude.ai, ChatGPT, and MCP Inspector), pairing stateless Streamable HTTP (`/mcp`) and OAuth 2.1/PKCE/DCR with dual-UID workspace sandboxing, `@openai/codex-sdk` job orchestration, and a 10-tool / 1-approval-gate mutation funnel.

| Layer | Technology / Baseline |
|---|---|
| Runtime | Node.js `>= 22.23.4` LTS (`package.json`, CI, `docker/Dockerfile`), ESM (`"type": "module"`) |
| Language | TypeScript `^5.8.0` (`strict: true`, `moduleResolution: "NodeNext"`) |
| HTTP & MCP | `hono`, `@hono/node-server`, `@modelcontextprotocol/sdk` (`^1.24.0`) |
| Persistence | `better-sqlite3` (`WAL`, `synchronous = NORMAL`, `foreign_keys = ON`, `busy_timeout = 5000`) |
| Integrations | `@openai/codex-sdk`, `octokit`, `cloudflare`, `zod` |
| Tests | `vitest` (`vitest run`) |

```bash
npm run typecheck                                                        # tsc --noEmit
npm run build                                                            # tsc -> dist/
npm test                                                                 # vitest run
npm run dev                                                              # tsx --env-file-if-exists=.env watch src/index.ts
npm start                                                                # node --env-file-if-exists=.env dist/index.js
docker compose -f docker/docker-compose.yml up -d --build                # gateway + cloudflared
docker compose -f docker/docker-compose.yml --profile ops up -d --build  # + ops-mcp sidecar
```

---

## 2. Repository & Source Layout

```text
src/
├── index.ts                      # HTTP server (@hono/node-server) + SIGINT/SIGTERM graceful shutdown (10s force exit)
├── app.ts                        # createGatewayApp(): Hono wiring, GET /, GET /healthz, orphan job recovery, 15m cleanup timer
├── config.ts                     # Zod env validation + loadConfig(env?) + fail-closed prod & path-overlap guards
├── types.ts                      # Shared config, OAuth, workspace, job, mutation plan, validation, and MCP tool types
├── db/
│   ├── sqlite.ts                 # WAL setup, pragmas, versioned transactional migrations (v1 + v2)
│   └── repositories/             # oauthRepo, workspaceRepo, jobRepo, planRepo, auditRepo, index
├── utils/
│   ├── exec.ts                   # buildSandboxedEnv(), startSubprocess()/runSubprocess(), sudo UID drop, process-group kill
│   └── secretScrubber.ts         # SecretScrubber (env/config secret collection + token regex redaction)
├── auth/                         # Discovery, DCR, authorize, token/revoke, upstreamIdp, Bearer middleware, cookies, crypto, rateLimit
├── admin/                        # /admin mobile PWA UI (ui.ts) & CSRF/session-protected JSON/SSE APIs (index.ts)
├── mcp/
│   ├── server.ts                 # Stateless Streamable HTTP /mcp handler + Origin allowlist + McpServer factory
│   ├── landingPage.ts            # Zero-leakage GET / portal HTML/JSON + SHA-256 script CSP
│   ├── outputGuard.ts            # withMcpGuardrails(): OAuth scope check, scrubbing, 60KB artifact offload, untrusted boundary
│   └── tools/                    # index, context, workspaceTools (#1-#3), execRunnerTools (#4-#6), infraPublishTools (#7-#10)
└── core/
    ├── workspaceLock.ts          # Slug validation, dual-check path/symlink sandbox, sensitive-file blacklist, FIFO RW lock
    ├── gitSnapshot.ts            # GitHub sync, stack/playbook detector, initCfOpsWorkspace, GIT_INDEX_FILE checkpoints & rollback
    ├── codePatcher.ts            # Atomic multi-file patch/create/delete with pre-write checks, auto-checkpoint & rollback
    ├── validationPipeline.ts     # L0 in-process checks, L1 adaptive CLI linters, L2 non-blocking test hint
    ├── workspaceExec.ts          # Bounded command runner (<=15s) with background job promotion & active-job cancel registry
    ├── codexRunner.ts            # CodexSdkRunner (@openai/codex-sdk), buildCodexSandboxedEnv(), reconcileOrphanJobs()
    ├── githubService.ts          # Read-only PR/Issue/Actions inspection + protected-branch PR publish/review/comment
    ├── cloudflareService.ts      # Read-only CF inspection, 2-phase CF plan stage/execute/rollback, Wrangler Worker/Pages deploy
    ├── downstreamMcpBridge.ts    # MCP-2 client federation (HTTP/stdio), tool policy classification, staged mutating execution
    └── webhookNotifier.ts        # Scrubbed Slack/Discord/Feishu/generic webhook delivery (5s non-fatal timeout)
docker/
├── Dockerfile                    # Multi-stage Node >=22.23.4 image with UID 1001 (gateway) / UID 1002 (worker) isolation
├── docker-compose.yml            # gateway (no host port), cloudflared (edge_net), optional ops-mcp (--profile ops on ops_net)
├── Dockerfile.ops-mcp            # Pre-built offline mcp-proxy + @uarlouski/ssh-mcp-server image (non-root node, port 8090)
├── entrypoint.sh                 # umask 0027, enforces 0700 on DATA_DIR/ARTIFACTS_DIR/CODEX_HOME, checks WORKSPACES_DIR
└── ops-mcp-config.example.json   # Reference MCP-2 server policy manifest (readonlyTools / mutatingTools / deniedTools)
```

---

## 3. HTTP Surface & Stateless Streamable HTTP Transport

Legacy HTTP+SSE routes (`/sse`, `/messages`) are prohibited.

| Endpoint | Auth | Behavior |
|---|---|---|
| `GET /` | Public | Zero-leakage Gateway Portal (HTML with CSP script hash, copyable `/mcp` URL, `.well-known` links, static 10-tool badges, `/admin` link; `Accept: application/json` returns status JSON). Never queries workspaces, jobs, tokens, or secrets. |
| `GET /healthz` | Public | Liveness & SQLite `SELECT 1` readiness (`200` / `503`). |
| `GET /.well-known/oauth-protected-resource` & `/mcp` | Public | RFC 9728 metadata (`resource: "${PUBLIC_DOMAIN}/mcp"`, `authorization_servers: [PUBLIC_DOMAIN]`, `bearer_methods_supported: ["header"]`, `scopes_supported`). |
| `GET /.well-known/oauth-authorization-server` | Public | RFC 8414 metadata (`issuer`, `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/register`, `code_challenge_methods_supported: ["S256"]`, `token_endpoint_auth_methods_supported: ["none", "client_secret_post"]`). |
| `POST /mcp` | OAuth Bearer | Stateless `WebStandardStreamableHTTPServerTransport` (`sessionIdGenerator: undefined`, JSON response). `GET`/`DELETE`/other methods return `405` (`Allow: POST`). Disallowed `Origin` headers return `403` (allows `PUBLIC_DOMAIN`, `gemini.google.com`, `aistudio.google.com`, `claude.ai`, `chatgpt.com`, and HTTPS/loopback `OAUTH_ALLOWED_REDIRECT_HOSTS`). |

- **Bearer Middleware (`src/auth/middleware.ts`)**: SHA-256 hashes the opaque token, verifies `oauth_tokens` (`token_type === 'access'`, non-revoked, unexpired, RFC 8707 `resource` matches `PUBLIC_DOMAIN` or `${PUBLIC_DOMAIN}/mcp`), and returns `401` with `WWW-Authenticate: Bearer resource_metadata="${PUBLIC_DOMAIN}/.well-known/oauth-protected-resource"` on failure.
- **Tool Guardrails (`src/mcp/outputGuard.ts`)**: `withMcpGuardrails()` enforces OAuth scopes (`mcp:tools`/`mcp:write` vs `mcp:read`), scrubs outputs, enforces `{ content: [{ type: "text", text }] }` (plus `isError: true` on error), and offloads outputs `> INLINE_OUTPUT_MAX_BYTES` (default `60,000` bytes) to `${ARTIFACTS_DIR}/{artifactId}.log` with head/tail preview.

---

## 4. OAuth 2.1, DCR, PKCE, Token Rotation & Upstream IdP

- **DCR (`POST /oauth/register`)**: Accepts `1..16` `redirect_uris`, max `500` dynamic clients (`20/min/IP`, `64KB` body), `token_endpoint_auth_method` `"none"` | `"client_secret_post"`. Permits loopback (`localhost`/`127.0.0.1`), built-in Google redirect patterns (`oauth-redirect.googleusercontent.com/{r,a}/*`, `oauth-redirect-{sandbox,test}.googleusercontent.com/*`, `vertexaisearch.cloud.google.com/oauth-redirect`), and HTTPS `OAUTH_ALLOWED_REDIRECT_HOSTS` (rejects fragments, wildcards, userinfo, traversal). Optional static client (`OAUTH_STATIC_CLIENT_ID`/`SECRET`) is upserted at boot; stale static clients are retired.
- **Authorization (`GET|POST /oauth/authorize`)**: Requires `response_type=code` and PKCE `S256`; preserves `state` up to `8192` bytes; validates scopes (`mcp:tools` default, `mcp:read`, `mcp:write`) and RFC 8707 `resource` (default `${PUBLIC_DOMAIN}/mcp`). Uses `gb_mcp_auth_bind` cookie + per-request `csrf_token`; verifies `ADMIN_PASSWORD_HASH` (`scrypt:<saltHex>:<keyHex>` Compose-safe default, plus `scrypt$<salt>$<hex>`, `sha256:<hex>`, `sha256$<hex>`; `plain$`/unprefixed non-prod only). TTLs: auth request `10m`, auth code `5m`.
- **Token & Revocation (`POST /oauth/token`, `POST /oauth/revoke`)**:
  - `authorization_code`: Atomically consumes `oauth_codes`, verifies PKCE `S256`, `redirect_uri`, client auth, and `resource`; issues opaque 32-byte `base64url` access (`3600s`) + refresh (`30d`) tokens stored by SHA-256 hash under a new `token_family_id`.
  - `refresh_token`: Rotates within `token_family_id` and sets `grace_expires_at = now + OAUTH_REFRESH_GRACE_SEC * 1000` (default `60s`) on the prior token for concurrent retries. Reuse after `grace_expires_at` or reuse of a revoked token revokes the entire `token_family_id`.
  - `POST /oauth/revoke`: Revokes a single access token or the entire `token_family_id` when given a refresh token.
- **Upstream IdP (`POST /auth/idp/:provider/start`, `GET /auth/idp/:provider/callback`)**: Optional Google (`{PUBLIC_DOMAIN}/auth/idp/google/callback`) and GitHub (`{PUBLIC_DOMAIN}/auth/idp/github/callback`) login for `/admin/login` (`purpose=admin`) and `/oauth/authorize` (`purpose=mcp_authorize`). **Fail-closed**: Google requires client ID/secret, non-empty `GOOGLE_OAUTH_ALLOWED_EMAILS`, and `email_verified === true`; GitHub requires client ID/secret and non-empty `GITHUB_OAUTH_ALLOWED_USERS` and/or `GITHUB_OAUTH_ALLOWED_IDS` (both must match if both set); `NODE_ENV=production` throws on boot if credentials exist without an allowlist. Protected by single-use PKCE `S256`, CSRF, `gb_mcp_auth_bind`, and `gb_upstream_oauth` cookie bound to `oauth_upstream_states.binding_hash` (`10m` TTL).

---

## 5. SQLite Data Model (`src/db/sqlite.ts`)

Path: `${DATA_DIR}/gateway.db` (overridable via `DATABASE_PATH` or `:memory:`). Pragmas: `journal_mode = WAL`, `synchronous = NORMAL`, `foreign_keys = ON`, `busy_timeout = 5000`. Migrations tracked in `schema_migrations (version PK, name, applied_at)` (`v1: initial_schema`, `v2: upstream_oauth_states`):

1. `oauth_clients (client_id PK, client_secret_hash, client_name, redirect_uris_json, is_static, created_at)`
2. `oauth_auth_requests (auth_req_id PK, client_id FK, redirect_uri, state, code_challenge, code_challenge_method, scope, resource, csrf_token, expires_at, used)`
3. `oauth_codes (code PK, client_id FK, redirect_uri, code_challenge, scope, resource, expires_at, used)`
4. `oauth_tokens (token_hash PK, token_type, client_id FK, scope, resource, token_family_id, expires_at, grace_expires_at, revoked, created_at)`
5. `oauth_upstream_states (state PK, provider, purpose, auth_req_id, code_verifier, binding_hash, expires_at, used, created_at)`
6. `workspaces (slug PK, repo_url, default_branch, detected_stack_json, playbook_text, last_synced_at)`
7. `checkpoints (checkpoint_id PK, workspace_slug FK, git_commit_sha, git_ref, reason, created_at)`
8. `jobs (job_id PK, workspace_slug, runner_type, status, command_or_objective, codex_thread_id, checkpoint_id, events_json, token_usage_json, final_report_text, error_message, created_at, updated_at)`
9. `mutation_plans (plan_id PK, target_service, summary_diff_text, payload_json, rollback_payload_json, status, expires_at, created_at, executed_at)`
10. `audit_logs (id PK AUTOINCREMENT, actor, action, target, status, details_json, created_at)`

---

## 6. Security, Sandbox & Docker Isolation

- **Docker Dual-UID & Networks (`docker/`)**: `gateway` (UID `1001`, GID `1001`, member of `worker`) owns `/data`, `/data/artifacts`, `CODEX_HOME=/data/codex` (`0700`, enforced by `entrypoint.sh` + `umask 0027`), and `/app`; `IMMUTABLE_GATEWAY_PATH` excludes `/opt/mise/shims`; exposes only internal port `8787` (zero host ports) and clears `CLOUDFLARE_TUNNEL_TOKEN`/`TUNNEL_TOKEN`. `worker` (UID `1002`, GID `1002`) owns `/workspaces` (`2775`), `/home/worker`, and `/opt/mise` (`2775`) with zero access to `/data`. When `SANDBOX_UID`/`SANDBOX_GID` are set, `startSubprocess()` drops privileges via `/usr/bin/sudo -n -H -u #1002 -g #1002 -- /usr/bin/env ...` (prepending `/opt/mise/shims` only to worker `PATH`) and terminates process groups (`SIGTERM` -> `SIGKILL` with `sudo` fallback on `EPERM` / `taskkill /T /F` on Windows). `cloudflared` sits on `edge_net` with `TUNNEL_TOKEN` only; optional `ops-mcp` (`--profile ops`) runs offline on `internal: true` `ops_net` as non-root `node` with `no-new-privileges:true`.
- **Env Allowlist, Scrubbing & Untrusted Boundary**: `buildSandboxedEnv()` (`src/utils/exec.ts`) enforces an allowlist + `FORBIDDEN_ENV_KEY_PATTERN` stripping all gateway secrets and sets `CI=true`, `DEBIAN_FRONTEND=noninteractive`, `GIT_TERMINAL_PROMPT=0`, `PAGER=cat`, `GIT_PAGER=cat`, `TERM=dumb`, `NO_COLOR=1`. `buildCodexSandboxedEnv()` (`src/core/codexRunner.ts`) adds only `CODEX_HOME`, `CODEX_API_KEY`/`OPENAI_API_KEY`, and optional `CODEX_BASE_URL`/`OPENAI_BASE_URL`. `SecretScrubber` (`src/utils/secretScrubber.ts`) redacts known env/config secrets (`length >= 8`) and token regexes (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`, `github_pat_`, `sk-...`, JWT `eyJ...`, `cfut_`, `v1.0-...`, `Bearer`/`Basic`, URL credentials) to `[REDACTED_SECRET]`. `wrapUntrustedData()` (`src/mcp/outputGuard.ts`) delimits external GitHub, Cloudflare tail, and MCP-2 outputs with `<<<BEGIN_UNTRUSTED_DATA ...>>>` / `<<<END_UNTRUSTED_DATA ...>>>` after neutralizing spoofed markers.
- **Path Confinement, Locks & Checkpoints**: `loadConfig()` rejects `DATA_DIR`, `ARTIFACTS_DIR`, or `DATABASE_PATH` overlapping `WORKSPACES_DIR`. `resolveSafeWorkspacePath()` (`src/core/workspaceLock.ts`) verifies logical + `realpathSync` containment in `${WORKSPACES_DIR}/{slug}`, rejects broken symlinks, and blocks `.env*`, `.dev.vars*`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`, `.git/config`, and `.git/hooks/*` (including Windows trailing dot/space normalization). `WorkspaceLockManager` provides fair FIFO per-workspace RW locks (`5000ms` default timeout; fast-fail `ACTIVE_JOB_LOCK` on active background write jobs). `createCheckpoint()` (`src/core/gitSnapshot.ts`) copies `.git/index` to a temp `GIT_INDEX_FILE` and runs `git add -A` -> `git write-tree` -> `git commit-tree` -> `git update-ref refs/mcp-checkpoints/<id>` (with `core.hooksPath=/dev/null`, `credential.helper=`); rollback creates a safety checkpoint then runs `git clean -fd` + `git read-tree --reset -u <sha>`.

---

## 7. The 10-Tool MCP Contract

All 10 tools live in `src/mcp/tools/` and return `{ content: [{ type: "text", text }] }` (with `isError: true` on error).

| # | Tool | Annotations (`R/D/O`) | OAuth Scope | Selector & Supported Operations |
|---|---|---|---|---|
| 1 | `workspace_manage` | `false / false / false` | `read` (`list`, `init_cf_ops`, `list_checkpoints`) / `write` (`sync_github`, `rollback`) | `action`: `list`, `sync_github` (clone/ff-only; `fetched_only_dirty` if dirty; detects stack + `AGENTS.md`/`AGENTS.override.md`/`CLAUDE.md`), `init_cf_ops` (read-only `wrangler.toml`/`wrangler.jsonc` inspection), `list_checkpoints`, `rollback` |
| 2 | `code_explore` | `true / false / false` | `read` | `mode`: `pack` (`repomix --compress` / walker fallback), `search` (`rg` / fallback), `ast` (`ast-grep` / fallback), `read_lines` (5MB cap), `read_artifact` (`offset`, `limit` 1–50,000, default 20,000), `git_diff` (`staged`, `base_ref`); excludes sensitive files |
| 3 | `code_patch` | `false / false / false` | `write` | `action`: `patch`, `create_or_overwrite`, `delete_file` (see contract below) |
| 4 | `workspace_exec` | `false / false / false` | `write` | Sandboxed command in `/workspaces/{slug}` (`args`, `cwd`, `readonly` read-lock, `wait_ms` 500–15,000 default 12,000, `max_duration_sec` clamped to `CODEX_MAX_DURATION_SEC`); auto-promotes to background SQLite `shell_task` job on `wait_ms` expiry |
| 5 | `dispatch_runner` | `false / false / false` | `write` | `mode`: `codex_readonly` (`read-only`, network off), `codex_write` (pre-run checkpoint + `workspace-write`, optional `allow_network`), `shell_task`. Supports `resume_thread_id`, `model`, `reasoning_effort`, config-clamped duration/token budgets, `CODEX_OUTPUT_SCHEMA` |
| 6 | `job_status` | `false / false / false` | `read` (`write` if `cancel: true`) | Status, duration, `codex_thread_id`, `checkpoint_id`, `token_usage`, `git status -sb`, incremental events (`since_seq`, default last 20), report/error; `cancel: true` aborts via `AbortController` + process-group kill |
| 7 | `github_inspect` | `true / false / true` | `read` | `mode`: `pr` (metadata, files, diff, checks, failed Actions logs), `issue` (body + comments), `workflow_failure` (recent failures or specific `run_id` logs) |
| 8 | `infra_inspect` | `true / false / true` | `read` | `action`: Cloudflare (`zones`, `dns_records`, `workers`, `pages`, `kv_namespaces`, `d1_databases`, `waf_rules`, `worker_tail_logs` via `CLOUDFLARE_READONLY_API_TOKEN` fallback `CLOUDFLARE_API_TOKEN`) + MCP-2 (`downstream_list`, `downstream_call` for `readonlyTools` only) |
| 9 | `stage_mutation_plan` | `false / false / false` | `write` | `target`: `cloudflare` (`mutation_type`: `dns_record_create`, `dns_record_update`, `dns_record_delete`, `waf_rule_update`, `d1_sql_mutation`) or `downstream_mcp` (`mutatingTools` + required `reason`). Zero writes; persists `MUTATION_PLAN_TTL_SEC` (900s) `plan_id` |
| 10 | `publish_changes` | `false / true / true` | `write` | **Single external write exit** (`action`): `github_pr`, `github_pr_review`, `github_comment`, `cloudflare_worker_deploy`, `cloudflare_pages_deploy`, `execute_staged_plan`, `rollback_plan` (audited & webhook-notified) |

*`R/D/O` = `readOnlyHint / destructiveHint / openWorldHint`.*

- **`code_patch` & L0/L1/L2 Pipeline (`src/core/codePatcher.ts`, `src/core/validationPipeline.ts`)**: `patch` uses `edits: [{ path, hunks: [{ search, replace, line_hint? }] }]` (`±25`-line disambiguation). Runs pre-write anti-placeholder & secret checks before checkpointing and atomic temp-file rename. Post-write validation: **L0** in-process anti-placeholder/conflict-marker (excludes `.md`/`.txt`/`.json`, overridable via `allow_placeholder_markers`), secret scan, and JSON/JS/TS syntax parsing; **L1** adaptive CLI linters (`2.5s` budget inside `2.8s` sync budget; skipped if `skip_l1` or binary missing/timed out: `biome`, `ruff`, `gofmt`/`go vet`, `shellcheck`, `hadolint`, `yamllint`, `actionlint`, `tofu fmt`, plus `tsc --noEmit --incremental`, `pyright`, `wrangler deploy --dry-run` only when `run_heavy_checks: true`); **L2** non-blocking `test-hint` suggesting `workspace_exec` commands. Rolls back on failure **by default** (`rollback_on_failure !== false`). `delete_file` skips validation.
- **Crash Recovery**: `reconcileOrphanJobs()` (`src/core/codexRunner.ts`) marks orphaned `queued`/`running` jobs `failed` on startup.
- **`publish_changes` Guarantees**: `github_pr` runs L0+L1 validation (`skipL2: true`) unless `skip_validation: true`, blocks `main`/`master`/`default_branch`/`base_branch`, fails closed on sensitive files, diff secrets, or truncated git scans, pushes to canonical `https://github.com/{owner}/{repo}.git`, and defaults `draft: true`. `cloudflare_worker_deploy` runs `wrangler versions upload` (`preview`, default) or `wrangler deploy` (`production`). `rollback_plan` runs `rollback_payload_json` for executed **Cloudflare** plans (`d1_sql_mutation` requires caller-supplied `rollback_sql`; `downstream_mcp` plans store `rollback_payload: null`).

---

## 8. Downstream MCP-2 Federation (`src/core/downstreamMcpBridge.ts`)

Loaded from `DOWNSTREAM_MCPS_JSON` and/or `DOWNSTREAM_MCPS_FILE` (array, `{ servers: [...] }`, or keyed map; `enabled: false` skipped). Supports `http` (`StreamableHTTPClientTransport`, e.g., `http://ops-mcp:8090/mcp` on `ops_net`) and `stdio` (`StdioClientTransport` using `buildSandboxedEnv()` + explicit server `env`). Tool policy precedence (default-deny): `deniedTools` > `readonlyTools` (`infra_inspect`) > `mutatingTools` (`stage_mutation_plan` -> `publish_changes`) > unlisted (blocked).

---

## 9. Admin PWA (`/admin`) & Webhook Notifications

- **`/admin` (`src/admin/index.ts`, `src/admin/ui.ts`)**: Decoupled from `src/core/*` via injected `cancelJob` / `rollbackCheckpoint` callbacks. Password or IdP login issues HMAC-signed `gb_admin_session` cookie (`12h` TTL) paired with `x-csrf-token` on mutating `/admin/api/*` requests. Serves PWA assets (`/admin/manifest.webmanifest`, `/admin/sw.js`, `/admin/icon.svg`) and APIs (`GET /api/summary`, `GET /api/jobs`, `GET /api/jobs/stream` SSE, `POST /api/jobs/:id/cancel`, `GET /api/workspaces`, `POST /api/workspaces/:slug/rollback`, `GET /api/oauth`, `POST /api/oauth/tokens/:hash/revoke`, `DELETE /api/oauth/clients/:id`, `GET /api/plans`, `GET /api/audit`).
- **Webhooks (`src/core/webhookNotifier.ts`)**: `NOTIFY_WEBHOOK_URL` sends scrubbed JSON POST alerts (`5s` non-fatal timeout) on job finish/failure/cancel/timeout and `publish_changes` actions, auto-formatting for Slack, Discord, Feishu/Lark, or generic JSON.
