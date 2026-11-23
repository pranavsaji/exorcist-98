# Design: m5-canary

- `packages/shield/src/canary.ts`: `newToken()` (crypto random, base32),
  `plantCanaries(dir, n)`, `loadCanaries(dir)`, `findCanary(value, tokens)`
  (checks raw, base64-decoded candidates, percent-decoded, whitespace-stripped
  strings collected with `collectStringsChecked`).
- Engine: `EngineOptions.canaries?: { token, file }[]`. In `onToolCall`, check
  canaries before `inspectCall`; block regardless of `policy.mode`.
  In `onToolResult`, medium alert. Add EX-022 YAML in `definitions/` for the
  encyclopedia (description, OWASP mapping) even though matching is in code.
- `packages/shield/src/proxy.ts` loads canaries from the project's
  `.exorcist/canaries.json` (and `policy.canaries` path) and passes them in.
- Core scan: a small built-in check in the orchestrator when
  `.exorcist/canaries.json` exists in the scanned root.
- CLI: `packages/cli/src/commands/canary.ts` (`plant`, `--list`, `--remove`),
  registered in index.ts and help.
- Simulator: add `canary` scenario; update SCENARIO_IDS and tests; the web Lab
  picks it up automatically from `/api/shield-sim`.
