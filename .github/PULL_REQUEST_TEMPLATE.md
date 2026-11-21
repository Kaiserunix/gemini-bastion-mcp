## Summary

<!-- Describe what this PR changes and why. -->

## Related Issue

<!-- Link issue if applicable, e.g. Fixes #123 -->

## Verification

- [ ] `npm run typecheck` passes
- [ ] `npm run build` passes
- [ ] `npm test` passes (include new regression tests for bug fixes or security changes)

## Security & Architecture Checklist

- [ ] Preserves stateless Streamable HTTP `/mcp` (no legacy HTTP+SSE)
- [ ] Preserves the 10-tool contract and single external write exit (`publish_changes`)
- [ ] Zero gateway secrets leaked to `workspace_exec`, `shell_task`, or Codex child processes
- [ ] Outputs/logs/artifacts pass through `SecretScrubber`
- [ ] No inline `onclick=` handlers or private data leaks on `GET /`
- [ ] Updated `README.md` / `README.zh-CN.md` / `.env.example` if config or behavior changed
