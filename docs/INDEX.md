# Documentation Index (`gemini-bastion-mcp`)

Authoritative map of all markdown documentation and key reference manifests in this repository.

## Markdown Documentation

| Document | Status | Purpose |
|---|---|---|
| [README.md](../README.md) | Active | English user-facing overview, architecture diagram, quick start, client setup, and ops guide |
| [README.zh-CN.md](../README.zh-CN.md) | Active | Simplified Chinese user-facing overview, quick start, and ops guide |
| [DESIGN.md](../DESIGN.md) | Active | Code-verified engineering architecture specification (layout, HTTP/OAuth 2.1, SQLite schema, `bwrap` & Docker UID isolation, multi-agent drivers, 10-tool contract, MCP-2 federation, Admin PWA, CI Watchdog) |
| [.agents/rules/architecture-guardrails.md](../.agents/rules/architecture-guardrails.md) | Active | Mandatory engineering & security invariants enforced across code, tests, and refactors |
| [docs/GEMINI_GEM_PROMPT.md](GEMINI_GEM_PROMPT.md) | Active | Ready-to-paste bilingual (EN / 简体中文) system prompt for Gemini Gems, Claude Projects, and ChatGPT Custom GPTs |
| [docs/PRODUCT_STRATEGY.md](PRODUCT_STRATEGY.md) | Active | Product positioning, code-verified capability alignment, prioritized P0/P1/P2 roadmap, and distribution checklist |
| [docs/UX_EXPERIENCE_AND_DESIGN_SPEC.md](UX_EXPERIENCE_AND_DESIGN_SPEC.md) | Active | Code-verified UX experience & design specification across `GET /`, `/oauth/authorize`, `/admin` PWA, and GitHub Pages showcase |
| [docs/USER_JOURNEY_COPY.md](USER_JOURNEY_COPY.md) | Active | Bilingual (EN / 简体中文) onboarding, OAuth consent, approval-gate, and error-recovery journey copy |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Active | Contributor local setup, architectural guardrails, and pull request checklist |
| [SECURITY.md](../SECURITY.md) | Active | Threat model, defense-in-depth invariants, and private vulnerability reporting policy |
| [CHANGELOG.md](../CHANGELOG.md) | Reference | Release history and versioned milestone notes |
| [docs/INDEX.md](INDEX.md) | Active | Central map of surviving repository documentation and status |
| [docs/CLEANUP_CHANGELOG.md](CLEANUP_CHANGELOG.md) | Reference | Forensic audit record of documentation discrepancies fixed against `src/` and `docker/` |
| [site/index.html](../site/index.html) | Active | Editorial minimalist bilingual (EN / 中文) GitHub Pages showcase with light/dark theme, 10-tool tier explorer, and Gemini Gem Prompt tabs |

## Configuration & Deployment Reference Files

| File | Status | Purpose |
|---|---|---|
| [.env.example](../.env.example) | Reference | Full environment variable template (OAuth 2.1, Google/GitHub IdP, `bwrap`, multi-agent drivers, GitHub, Cloudflare, Watchdog, webhooks, MCP-2) |
| [server.json](../server.json) | Reference | Official MCP Registry manifest (`io.github.Kaiserunix/gemini-bastion-mcp`, schema `2025-12-11`) |
| [docker/docker-compose.yml](../docker/docker-compose.yml) | Reference | Production Compose stack (`gateway`, `cloudflared`, optional `--profile ops` `ops-mcp` & `--profile isolated-runner` sidecars) |
| [docker/Dockerfile](../docker/Dockerfile) | Reference | Multi-stage Node `>= 22.23.4` `:lite` & `:full` runtime images with `bwrap` and UID `1001` (`gateway`) / UID `1002` (`worker`) separation |
| [docker/ops-mcp-config.example.json](../docker/ops-mcp-config.example.json) | Reference | Example Downstream MCP-2 federation policy (`readonlyTools` / `mutatingTools` / `deniedTools`) |
