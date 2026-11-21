# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| `0.1.x` | Yes       |

## Security Architecture & Threat Model

`GeminiBastionMCP` (`gemini-bastion-mcp`) is a **single-operator, self-hosted** OAuth 2.1 MCP bastion designed to isolate untrusted AI tool execution and external API responses from gateway credentials:

- **Fail-Closed Production Defaults**:
  - `NODE_ENV=production` rejects missing, placeholder, or `< 32`-character `OAUTH_SIGNING_SECRET` values, rejects non-HTTPS `PUBLIC_DOMAIN` (except loopback), and rejects overlapping `DATA_DIR`/`ARTIFACTS_DIR` and `WORKSPACES_DIR` paths.
  - Upstream Google/GitHub operator OAuth requires both client credentials **and** a non-empty allowlist (failing closed at startup if misconfigured in production); Google login additionally requires `email_verified === true`.
- **Two-User Linux Isolation (Docker)**:
  - `gateway` (UID `1001`) owns `/data` (`0700`, SQLite DB, `/data/artifacts`, `/data/codex`) and `/app`.
  - `worker` (UID `1002`) owns `/workspaces` and `/opt/mise`, runs sandboxed `workspace_exec` / `shell_task` commands via `sudo -n -H -u #1002 -g #1002`, and has zero access to `/data`.
- **OAuth 2.1 Hardening**:
  - Mandatory PKCE `S256`, RFC 8707 resource binding, strict redirect URI allowlisting (blocking authority `@`, fragments `#`, wildcards `*`, and encoded traversal), 60-second refresh token grace window with full family revocation on replay, and `/mcp` `Origin` checks.

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report vulnerabilities privately via [GitHub Security Advisories](https://github.com/Kaiserunix/gemini-bastion-mcp/security/advisories/new) with:

1. A clear description of the vulnerability and affected component/file
2. Steps to reproduce or a minimal proof-of-concept
3. Potential impact and any suggested remediation

We will acknowledge receipt promptly, investigate, and coordinate a fix and release advisory before public disclosure.
