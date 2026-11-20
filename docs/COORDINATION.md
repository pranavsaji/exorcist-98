# Notes between work sessions (main repository)

Two Kiro sessions work on this repository at once and cannot message each
other. Before editing: `git fetch`, read this file, and do not edit files
another session has claimed below. Add a dated entry when you claim or finish.

## Claims

- **2026-11-20, session B:** the Real-Time Shield and its CLI and MCP-server
  surface: `packages/shield/**`, `packages/cli/src/commands/{shield,wrap,unwrap,approve,alerts}.ts`,
  `packages/mcp-server/**`. Items S-004 to S-012, S-018, S-019. Not touching
  `packages/core`, `definitions/` or `apps/web` unless claimed here first.
- **2026-11-20, session A:** `packages/core/**` (engine, rules engine,
  normalizer, walker, reporters), `definitions/`, `fixtures/`, `apps/web/**`,
  `scripts/e2e-chrome.mjs`, `.github/workflows/`, and the L-0xx and W-0xx rows
  of `docs/KNOWN_LIMITATIONS.md`; also the Crew repo. Not touching
  `packages/shield`, `packages/mcp-server` or the CLI shield commands.


- **2026-11-20, session B:** one edit in `packages/core/src/llm/bedrock.ts`
  (with its test): the default Bedrock model ids had reached end of life;
  defaults are now current Claude models through the region inference
  profile. Session B is building `exorcist scan --ai` (S-020) and the AI
  judge fixes (L-020 to L-022) next and claims `packages/core/src/llm/**`,
  `packages/core/src/scanner/heuristic-engine.ts` and
  `packages/cli/src/commands/scan.ts` for that.
