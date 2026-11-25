# Design Document

## Overview

Mostly pure code in `packages/core`, wired into the CLI. No new dependency, no network call.
The scan itself (`scanRepo`) is unchanged for baseline and suppression: they are a pass over
its findings, so the web app, MCP server and Shield behave as before.

## Architecture

```
scanRepo  ->  findings  ->  applyInline (reads files)  ->  applyBaseline  ->  report
                                  |                              |
                          suppressed[]                    baselined[]
```

- `packages/core/src/baseline.ts` (pure): `fingerprintOf(finding)`, `buildBaseline(findings)`,
  `parseBaseline(text)` (zod, typed result), `applyBaseline(findings, baseline)`.
- `packages/core/src/suppress.ts` (pure): `parseDirectives(text)`, `applyInline(findings, readText)`,
  `NEVER_INLINE = ['EX-001','EX-011']`.
- `packages/core/src/source-tools.ts` (pure): `extractToolDescriptions(text, lang)` returns
  `{ text, offset }[]`; `scanSourceTools(file, text, defs)` runs EX-005 on those strings only.
- `packages/core/src/plural.ts`, `verdict.ts` (pure): `plural(n, word)`, `verdictFor(level)`.
  `apps/web/.../ResultsSummary.tsx` imports `verdictFor` from core instead of its own copy.
- `packages/core/src/staleness.ts` (pure): `staleness(dateIso, now, days = 30)`.
- `packages/cli/src/commands/baseline.ts`: the `baseline` command.
- `packages/cli/src/commands/scan.ts`: `--baseline`, shared `runScan` used by `baseline` too.

## Baseline

Entry: `{ ruleId, file, fingerprint, line }`. File: `{ version: 1, entries: [...] }`, sorted by
file, ruleId, fingerprint, line; no timestamp so the file diffs cleanly.

Fingerprint = first 32 hex chars of SHA-256 over `ruleId \0 file \0 span` where span is
`redactFinding(f).span` with whitespace runs collapsed. The line and column are not included,
so a moved finding keeps its fingerprint. Redaction first means no hash of a secret is stored.

Matching is a multiset: for each key `ruleId|file|fingerprint` the baseline holds a count; each
finding consumes one. A finding with no count left is active. Findings are consumed in
(line, col) order, so the result does not depend on the walk order.

## Inline directives

Per line, the first match of
`(?:\/\/|#|<!--|\/\*|--|;)\s*exorcist-ignore\s+(EX-\d{3})\s*:(.*)$` (no nested quantifiers; the line
is cut to 1,000 characters first). The reason is the rest of the line without a trailing `-->` or
`*/`, trimmed. A directive covers its own line and the next line.

A directive suppresses a finding when all hold: same rule id; the finding is on the directive's
line and starts before the comment opener, or on the next line; the rule is not in `NEVER_INLINE`;
the finding is not a timeout finding; the reason has a letter or digit. A finding that starts at or
after the opener on the directive line stays active (requirement 2.4). Rejected directives are
returned with a cause: `no-reason`, `never-suppressible`, `timeout`.

Reasons are untrusted: printed through `displayMessage` after `redactSecretText`, capped at 200.

`applyInline(findings, readText)` reads each distinct file once through a callback; the CLI's
callback resolves the path inside the scan root and returns null for anything outside it.

## SARIF and JSON

`toSarif(findings, root, marks?)`: `marks` is `ReadonlyMap<Finding, SarifSuppression>`; a marked
result gets `suppressions: [{ kind, status: 'accepted', justification }]`. The CLI passes all
findings (active, baselined, suppressed). `toJson` gains an optional `suppressed` object.
`ScanReportSchema` is extended compatibly (optional field).

## Tool descriptions in source

Language by extension: `.ts .tsx .js .mjs .cjs .mts` ; `.py` ; `.go`. The walker already classes
these as `code`. EX-005 is limited to `mcp-config` and `config` roles today, so the new pass does
not use `applies_to`: the orchestrator calls `scanSourceTools` for `code` files and passes the
extracted strings to `runSignatures` as a synthetic `mcp-config` text for the EX-005 definition only
(`defs.filter(d => d.id === 'EX-005')`), then maps each hit back to the source position through the
string's offset. The EX-005 `file_regex` is for `config` role only, so it does not block this.

Extractor: a small scanner, not regexes over the whole file, to stay linear.
1. Find registration sites with fixed-prefix searches: `.tool(`, `registerTool(`, `registerTool<`;
   `@mcp.tool`, `@server.tool`, `@app.tool`; `mcp.NewTool(`, `WithDescription(`.
2. From the site, read string literals (single, double, backtick, Python triple quotes, Go raw
   backticks) with escape handling, bounded to 20,000 characters ahead and 100 sites per file.
3. TS/JS: for `.tool(`, the first argument is the name and the next string literal argument is the
   description; for `registerTool`, the string after `description:` in the options object.
   Python: `description=` keyword in the decorator, else the function's docstring (first string
   literal after the `def ...:` line). Go: the argument of `mcp.WithDescription(`.
4. Each result carries the offset of the string's content in the file.

Anything the scanner cannot read is skipped, never an error. Strings assembled at run time
(concatenation, template substitution, variables) are not covered; L-051 says so.

Quiet on ordinary hints: EX-005 has "before using this tool" in its regex, which fires on
"use X before calling this tool"? It matches `before (responding|answering|using this tool)` and
`(prior to|before) (invoking|calling|running|using) (this|any|the)`. The look-alike set must show
whether these fire. If they do on the benign look-alikes, the source pass drops a match whose
sentence has an imperative about another tool with no secret/user-concealment signal (design below);
otherwise no rule change is needed. The subagent measures first, writes the benign cases, and only
then tightens, using `exclude_regex` or a source-pass-only filter, so the JSON-config behaviour and
the existing attack benchmark do not change. The attack cases use concealment ("do not tell the
user"), secret paths (`~/.ssh`, `.env`), and "before responding" patterns.

## Stale definitions

`activeDefinitions()` gives `{ date }`. `staleness('2026-11-24', now)` returns
`{ stale: boolean, days: number }`. The CLI prints once per process
(`warnIfStale(io, {custom, now})`); custom folder means no warning. Stderr only.

## CLI wording

- Summary: files with findings = distinct `file` among active findings; scanned = `stats.filesScanned`.
  `8 threats in 3 files (...). Scanned 120 files.` Same in markdown.
- Verdict: `Verdict: POSSESSED. <line>` at the end of text output. The web words are
  CLEAN, HAUNTED, POSSESSED; the brief says SUSPICIOUS but the web app says HAUNTED, and the
  requirement is to match the web app, so HAUNTED is used.
- `init`: the summary builds its list from a Map keyed by relative path; the hooks block and the
  other blocks no longer repeat a file. The `autoApprove` check reads the config (already parsed
  in `describeMcpConfig`) and warns per server whose `autoApprove` array includes `"*"`.

## Testing

Unit tests next to each module. fast-check properties: fingerprint ignores line; baseline built
from findings F matches F exactly (nothing active); a directive for EX-001 or EX-011 never
suppresses; every finding is in exactly one of active, baselined, suppressed. CLI tests drive
`scanCommand` and `baselineCommand` against temp folders. Benchmark: new attack and benign cases
per language. The Haunted Repo snapshot is unchanged.
