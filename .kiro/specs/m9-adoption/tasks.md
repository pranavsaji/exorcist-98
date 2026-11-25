# Implementation Plan: m9-adoption

## Overview

Shared helpers first (they are small and used everywhere), then the four areas, then docs.

## Tasks

- [x] 1. Shared helpers in `packages/core` (requirements 6.2, 6.5, 5.1, 5.2)
  - [x] 1.1 `plural.ts`, `verdict.ts` (with web app `verdictFor` using it), `staleness.ts`; export from index; unit tests
- [x] 2. Baseline (requirements 1.1 to 1.9)
  - [x] 2.1 `baseline.ts` (fingerprint, build, parse with zod, apply) with unit and fast-check tests
  - [x] 2.2 `suppress.ts` (directives, `applyInline`) with unit and fast-check tests, including the "comment text is still scanned" test
  - [x] 2.3 SARIF `suppressions` and JSON `suppressed` in the reporters, with tests
  - [x] 2.4 CLI: `runScan` shared, `--baseline`, `baseline` command, exit code from active findings, help text
  - [x] 2.5 GitHub Action input `baseline`, with a test that reads `action.yml`
- [x] 3. Tool descriptions in source (requirements 4.1 to 4.7)
  - [x] 3.1 `source-tools.ts` extractor for TS/JS, Python, Go, with unit tests and a linear-time test
  - [x] 3.2 Wire into the orchestrator (EX-005 only, mapped back to source positions)
  - [x] 3.3 Benchmark: attack and look-alike benign cases per language; update `labels.json`
  - [x] 3.4 Update L-051 in `docs/KNOWN_LIMITATIONS.md`
- [x] 4. Stale definitions warning in `scan`, `baseline` and `map` (requirements 5.1 to 5.4), with tests
- [x] 5. CLI wording (requirements 6.1 to 6.5)
  - [x] 5.1 `scan` and markdown summary: files with findings, scanned count, plural, verdict line
  - [x] 5.2 `init`: each file once, `autoApprove: "*"` warning
- [ ] 6. Docs and checks (requirements 7.3 to 7.5)
  - [x] 6.1 README and CLI help; row in `docs/KIRO_LOG.md`
  - [x] 6.2 `pnpm -r typecheck` and `pnpm vitest run` pass from the repository root
  - [-] 6.3 Commit (do not push)

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "2.2", "3.1"] },
    { "id": 2, "tasks": ["2.3", "3.2"] },
    { "id": 3, "tasks": ["2.4", "3.3", "3.4"] },
    { "id": 4, "tasks": ["2.5", "5.1", "5.2"] },
    { "id": 5, "tasks": ["4"] },
    { "id": 6, "tasks": ["6.1"] },
    { "id": 7, "tasks": ["6.2"] },
    { "id": 8, "tasks": ["6.3"] }
  ]
}
```

## Notes

Tasks 2.4, 5.1 and 4 all touch `packages/cli/src/commands/scan.ts`; run them in the waves shown.
