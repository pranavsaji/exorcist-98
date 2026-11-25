# Implementation Plan: m14-first-five-minutes
## Overview
Read the sources first (the comparison needs each tool's documentation), then the script and its test, the documents, the site footer, and last the facts, the log and the commit.
## Tasks
- [x] 1. Read the sources for the comparison (requirements FF-3.1 to FF-3.3)
  - [x] 1.1 Read the README or documentation of Snyk Agent Scan, Invariant Guardrails, Lakera Guard, semgrep-rules-mcp, GitHub secret scanning, MCPTrust and mcp-fence; note what each says and what it does not
- [x] 2. CI that installs the published shape (requirements FF-4.1 to FF-4.9)
  - [x] 2.1 `scripts/published-shape.mjs` and `scripts/published-shape.d.mts`
  - [x] 2.2 `packages/cli/src/__tests__/published-shape.test.ts`
  - [x] 2.3 Job `published-shape` in `.github/workflows/ci.yml`
- [x] 3. Documents (requirements FF-1, FF-2.1 to FF-2.7, FF-2.9, FF-3.4 to FF-3.6)
  - [x] 3.1 Comparison section in `docs/REFERENCE.md`, replacing the unsourced one
  - [x] 3.2 `docs/START-HERE.md`, and add it to `DOCS` in `scripts/facts.mjs`
  - [x] 3.3 README: recording and caption under the pitch, START-HERE line, two-line comparison
  - [x] 3.4 `packages/cli/src/__tests__/first-five-minutes.test.ts`
- [x] 4. Site footer (requirement FF-2.8)
  - [x] 4.1 `SiteFooter` in `RetroFrame`, the product page and the how-we-used-Kiro page; link in the About window
  - [x] 4.2 `apps/web/src/__tests__/site-footer.test.tsx`
- [x] 5. Finish (requirements FF-5.1 to FF-5.5)
  - [x] 5.1 Row in `docs/KIRO_LOG.md`; move the brief to `docs/kiro-briefs/`
  - [x] 5.2 `node scripts/facts.mjs --run-tests --docs`
  - [x] 5.3 `pnpm -r typecheck`, `pnpm vitest run`, and `pnpm e2e` pass
  - [x] 5.4 Commit (do not push)
## Task Dependency Graph
```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "3.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "3.2", "4.1"] },
    { "id": 3, "tasks": ["3.3", "4.2"] },
    { "id": 4, "tasks": ["3.4"] },
    { "id": 5, "tasks": ["5.1"] },
    { "id": 6, "tasks": ["5.2"] },
    { "id": 7, "tasks": ["5.3"] },
    { "id": 8, "tasks": ["5.4"] }
  ]
}
```
## Notes
Tasks 3.2 and 3.3 both change numbers that `scripts/facts.mjs` rewrites; run task 5.2 after them.
