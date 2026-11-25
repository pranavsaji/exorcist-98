# Feature brief: make Exorcist 98 easy to adopt on a real team

Write a Kiro spec in `.kiro/specs/m9-adoption/` (requirements, design, tasks),
then implement every task. Follow `.kiro/steering/`.

## 1. Baseline and suppressions

Today the only way to quiet a finding is a path prefix (`--ignore`,
`.exorcistignore`). Teams need to adopt the scanner on an existing repo without
fixing everything first.

- `exorcist baseline [folder]` writes `.exorcist-baseline.json`: one entry per
  current finding (rule id, file, a content fingerprint of the matched span and
  its line, not the raw text, and no secrets).
- `exorcist scan --baseline <file>` (and the GitHub Action input `baseline`)
  reports only findings not in the baseline; it says how many were suppressed.
  A finding whose fingerprint changed is new again. Line moves must not
  resurrect a baselined finding.
- Inline suppression for one rule on one line, with a required reason, for
  example `exorcist-ignore EX-012: <reason>` in a comment on the same or the
  previous line. Report every suppression in the summary so it can be audited.
  Hidden characters (EX-001) and secrets (EX-011) can never be suppressed inline,
  and a suppression comment cannot itself hide an attack (test that the comment
  text is still scanned).
- SARIF output marks baselined and suppressed results with SARIF's
  `suppressions` property instead of dropping them.

## 2. Tool descriptions in server source code (docs/KNOWN_LIMITATIONS.md, L-051)

EX-005 only reads JSON tool definitions. Most real MCP servers define tools in
TypeScript, Python or Go. Extract the description strings passed to common tool
registration calls (`server.tool(...)`, `registerTool`, `@mcp.tool` and
`@server.tool` decorators and their docstrings, Go `mcp.NewTool(...,
mcp.WithDescription(...))`) and run the tool-description checks on them only.
Keep it quiet on ordinary hints such as "use X before calling this tool": the
field scan found 188 such strings in 62 popular repos and none was an attack.
Add look-alikes for those to the benchmark. Update L-051.

## 3. Stale definitions

Warn (once per run, on stderr, not in machine output) when the bundled or
installed definitions are older than 30 days, and say how to update. Do not add
any network call by default.

## 4. CLI wording found by a review

- The summary said "8 threats in 5 files" when the threats were in 3 files: count
  only files that have findings, and say how many were scanned separately.
- "in 1 files": pluralise correctly everywhere.
- `exorcist init` listed every file twice; list each once. When the MCP config it
  reads has `autoApprove` with `"*"`, warn about it in plain words.
- Print an overall verdict line like the web app (CLEAN, SUSPICIOUS, POSSESSED)
  in the text output.

Tests for each item. A row in `docs/KIRO_LOG.md` for this work by the Kiro IDE
agent. Update README and the CLI help briefly. Run `pnpm -r typecheck` and
`pnpm vitest run`. Commit. Do not push.
