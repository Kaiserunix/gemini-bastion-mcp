# Contributing to GeminiBastionMCP

Thank you for your interest in contributing to **GeminiBastionMCP** (`gemini-bastion-mcp`)!

## Prerequisites

- **Node.js**: `>= 22.23.4` LTS (enforced in `package.json` and `docker/Dockerfile`)
- **Git**: `>= 2.38`
- **Build tools**: C/C++ compiler toolchain for `better-sqlite3` native bindings if prebuilds are unavailable on your platform

## Local Development Setup

```bash
git clone https://github.com/Kaiserunix/gemini-bastion-mcp.git
cd gemini-bastion-mcp
npm install
cp .env.example .env
```

Set local paths and dev credentials in `.env`:

```dotenv
DATA_DIR=./.local/data
WORKSPACES_DIR=./.local/workspaces
OAUTH_SIGNING_SECRET=local-dev-secret-at-least-32-characters-long
ADMIN_PASSWORD_HASH=scrypt:<saltHex>:<keyHex>
```

Run checks and start the hot-reloading server:

```bash
npm run typecheck
npm run build
npm test
npm run dev
```

## Architectural Guardrails

Every pull request must preserve the invariants in [`.agents/rules/architecture-guardrails.md`](.agents/rules/architecture-guardrails.md):

1. **Stateless Streamable HTTP Only**: Use `WebStandardStreamableHTTPServerTransport` at `/mcp`; never introduce legacy HTTP+SSE (`/sse`, `/messages`).
2. **Official Codex SDK Only**: Use `@openai/codex-sdk`; never invoke deprecated `codex mcp-server`.
3. **10-Tool Contract & Single External Write Gate**: Do not add ad-hoc top-level MCP tools beyond the 10-tool surface. All external mutations must stay funneled through `publish_changes`, and infrastructure/MCP-2 writes must stage first via `stage_mutation_plan`.
4. **Zero Gateway Secret Leakage**: Never expose `GH_TOKEN`, `CLOUDFLARE_*`, `OAUTH_SIGNING_SECRET`, `ADMIN_PASSWORD_HASH`, `NOTIFY_WEBHOOK_URL`, or `DOWNSTREAM_MCPS_*` to `workspace_exec`, `shell_task`, or Codex child processes. Scrub all outputs, artifacts, and webhooks with `SecretScrubber`.
5. **Non-Destructive Git & Out-of-Workspace Artifacts**: Use temporary `GIT_INDEX_FILE` for checkpoints and store truncated artifacts strictly inside `ARTIFACTS_DIR` outside `WORKSPACES_DIR`.
6. **Zero Data Leaks on Public Routes & XSS Hygiene**: `GET /` must never query or leak private workspaces, jobs, tokens, or secrets. Admin and portal HTML views must avoid inline `onclick=` handlers and enforce strict CSP headers.

## Pull Request Checklist

- [ ] `npm run typecheck` passes with zero errors
- [ ] `npm run build` succeeds cleanly
- [ ] `npm test` passes (all existing and new regression tests green)
- [ ] No secrets, `.env` files, private keys, or personal paths committed
- [ ] Documentation (`README.md`, `README.zh-CN.md`, or `DESIGN.md`) updated if behavior or env vars changed
