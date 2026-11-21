# Documentation Index (`gemini-bastion-mcp`)

Authoritative map of all markdown documentation and key reference manifests in this repository.

## Markdown Documentation

| Document | Status | Purpose |
|---|---|---|
| [README.md](../README.md) | Active | English user-facing overview, architecture diagram, quick start, client setup, and ops guide |
| [README.zh-CN.md](../README.zh-CN.md) | Active | Simplified Chinese user-facing overview, quick start, and ops guide |
| [DESIGN.md](../DESIGN.md) | Active | Code-verified engineering architecture specification (layout, HTTP/OAuth 2.1, SQLite schema, Docker UID isolation, 10-tool contract, MCP-2 federation, Admin PWA) |
| [.agents/rules/architecture-guardrails.md](../.agents/rules/architecture-guardrails.md) | Active | Mandatory engineering & security invariants enforced across code, tests, and refactors |
| [docs/INDEX.md](INDEX.md) | Active | Central map of surviving repository documentation and status |
| [docs/CLEANUP_CHANGELOG.md](CLEANUP_CHANGELOG.md) | Reference | Forensic audit record of documentation discrepancies fixed against `src/` and `docker/` |

## Configuration & Deployment Reference Files

| File | Status | Purpose |
|---|---|---|
| [.env.example](../.env.example) | Reference | Full environment variable template (OAuth 2.1, Google/GitHub IdP, GitHub, Cloudflare, Codex SDK, webhooks, MCP-2) |
| [docker/docker-compose.yml](../docker/docker-compose.yml) | Reference | Production Compose stack (`gateway`, `cloudflared`, optional `--profile ops` `ops-mcp` sidecar) |
| [docker/Dockerfile](../docker/Dockerfile) | Reference | Multi-stage Node `>= 22.23.4` runtime image with UID `1001` (`gateway`) / UID `1002` (`worker`) separation |
| [docker/ops-mcp-config.example.json](../docker/ops-mcp-config.example.json) | Reference | Example Downstream MCP-2 federation policy (`readonlyTools` / `mutatingTools` / `deniedTools`) |
