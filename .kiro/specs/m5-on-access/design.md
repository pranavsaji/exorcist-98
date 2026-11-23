# Design: m5-on-access

- `packages/core/src/on-access.ts`: `extractReadPaths(toolInput)`,
  `decideRead(stdin: string, opts: { defs, cwd?, allowed?: Set<string> })`.
  Uses `scanText` (packages/core/src/scanner/scan-text.ts) and the walker's
  `classifyFile` for the role. Export from index.ts.
- `packages/cli/src/commands/on-access.ts` (+ `allow-read`), registered in
  `packages/cli/src/index.ts` and the help text. Loads definitions via the
  same lookup `scan` uses.
- `scripts/hook-on-access.ts`: thin stdin -> decideRead -> exit code, like
  `scripts/hook-pre-commit-secrets.ts`.
- `.kiro/hooks/on-access-scan.json` in the v1 JSON format used by the other
  hooks in `.kiro/hooks/`.
- `packages/cli/src/commands/init.ts`: add the hook to what it writes.
- Tests: `packages/core/src/__tests__/on-access.test.ts` (+ property file),
  CLI test running the built bundle with an event on stdin (exit 2 on the
  EX-002 Haunted Repo sample, exit 0 on README.md of this repo).
