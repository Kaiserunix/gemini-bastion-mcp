# Documentation Cleanup Changelog (`swarm/doc-cleanup`)

Code-truth audit of all non-README markdown documentation in `Kaiserunix/gemini-bastion-mcp` verified directly against `src/`, `docker/`, `package.json`, `.env.example`, and `.github/workflows/ci.yml`.

## Files Updated & Added

| File | Action | Before -> After (lines) | Summary |
|---|---|---|---|
| [DESIGN.md](../DESIGN.md) | Audited & rewritten | 236 -> 160 (-76) | Replaced drifted pre-implementation claims with code-verified architecture, directory layout, Docker UID isolation, OAuth/token mechanics, and 10-tool schemas |
| [.agents/rules/architecture-guardrails.md](../.agents/rules/architecture-guardrails.md) | Audited & updated | 38 -> 38 (0) | Corrected 4 minor code-drift items (`CodexSdkRunner` name, `buildCodexSandboxedEnv()` + IdP secrets, `GIT_INDEX_FILE` copy-index vs rollback mechanics, CF vs MCP-2 rollback scope) |
| [docs/INDEX.md](INDEX.md) | Created | 0 -> 23 (+23) | Added single-source documentation map with status (`Active` / `Reference`) and verified relative links |
| [docs/CLEANUP_CHANGELOG.md](CLEANUP_CHANGELOG.md) | Created | 0 -> 30 (+30) | Recorded forensic audit findings and out-of-scope README notes |

*Untouched by policy (owned by marketing/README track): [README.md](../README.md) (304 lines), [README.zh-CN.md](../README.zh-CN.md) (304 lines), and all `src/`, `tests/`, `docker/`, `site/`, and `.github/` files.*

## Discrepancies Fixed Against Real Code (`src/` & `docker/`)

1. **Phantom directory tree (`DESIGN.md` §2)**: Removed 4 nonexistent directories (`src/workspace/`, `src/runners/`, `src/integrations/`, `src/security/`); documented actual layout (`src/app.ts`, `src/core/*`, `src/mcp/landingPage.ts`, `src/mcp/outputGuard.ts`, `docker/*`) and exact runtime baselines (`Node >= 22.23.4`, `TypeScript ^5.8.0`).
2. **Docker UID & `CODEX_HOME` ownership (`DESIGN.md` §6, `architecture-guardrails.md` §5)**: Fixed false claim that `/home/worker/.codex` is owned by `worker` (UID 1002); `docker/Dockerfile`, `docker/docker-compose.yml`, and `docker/entrypoint.sh` place `CODEX_HOME=/data/codex` under `gateway` (UID 1001, mode `0700`), while `worker` (UID 1002) owns `/workspaces` and `/opt/mise` (`2775`) and receives commands via `sudo -n -H -u #1002 -g #1002`.
3. **Cloudflare `stage_mutation_plan` feature hallucination (`DESIGN.md` §7)**: Removed unimplemented claims (`KV write/delete`, `Worker route/secret/setting update`) and documented the actual 5-value `mutation_type` enum in `src/mcp/tools/infraPublishTools.ts` & `src/core/cloudflareService.ts` (`dns_record_create`, `dns_record_update`, `dns_record_delete`, `waf_rule_update`, `d1_sql_mutation`).
4. **`code_patch` hunk schema & L0/L1/L2 pipeline (`DESIGN.md` §7)**: Fixed hunk fields from `old_text`/`new_text` to actual `edits[].hunks[].{ search, replace, line_hint? }`; replaced inaccurate L0/L1/L2 descriptions with real `src/core/validationPipeline.ts` behavior (L0 in-process anti-placeholder/secret/JSON+JS/TS syntax; L1 2.5s CLI linters + opt-in `run_heavy_checks`; L2 non-blocking `test-hint`), default `rollback_on_failure: true`, and `delete_file` skipping validation.
5. **`job_status` annotation & tool selector parameters (`DESIGN.md` §7)**: Corrected `job_status` `readOnlyHint` from `true` to actual `false` (`src/mcp/tools/execRunnerTools.ts`); documented exact `mode` (`code_explore`, `github_inspect`, `dispatch_runner`) vs `action` vs `target` selectors and OAuth scope requirements.
6. **OAuth token format, `/mcp` HTTP methods & IdP callback URL (`DESIGN.md` §3–§4)**: Clarified that access/refresh tokens are opaque 32-byte tokens stored by SHA-256 hash (not signed JWTs), `POST /mcp` returns `405` on `GET`/`DELETE` and enforces `Origin` allowlist (`403`), documented `POST /oauth/revoke` and built-in Google redirect patterns, and fixed double-scheme callback URL (`https://{PUBLIC_DOMAIN}/auth/idp/...` -> `{PUBLIC_DOMAIN}/auth/idp/...`).
7. **Git checkpoint mechanics & `init_cf_ops` (`DESIGN.md` §6–§7, `architecture-guardrails.md` §6)**: Clarified `createCheckpoint()` copies `.git/index` to temp `GIT_INDEX_FILE` (`git read-tree --reset -u` is rollback-only), `init_cf_ops` inspects (does not scaffold) Wrangler config, `rollback_plan` applies only to executed Cloudflare plans (`downstream_mcp` plans store `rollback_payload: null`), and `schema_migrations` + `synchronous = NORMAL` are part of `src/db/sqlite.ts`.

## Out-of-Scope Audit Notes (Not Modified Here)

Observed in [README.md](../README.md) and [README.zh-CN.md](../README.zh-CN.md) (left untouched for the `swarm/strategy-copy` README track):
- Lines 232 & 236 show `https://<PUBLIC_DOMAIN>/auth/idp/{google,github}/callback`; since `PUBLIC_DOMAIN` already includes `https://`, `<PUBLIC_DOMAIN>/auth/idp/...` avoids a double scheme.
- Lines 301–304 reference `docs/assets/` media files (`demo-gemini-pr.gif`, `portal-and-oauth.png`, `admin-mobile-pwa.png`) that do not exist yet as a pre-release checklist.
