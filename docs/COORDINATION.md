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
- **2026-11-20 16:30, session A:** added ZIP upload (L-032):
  `packages/core/src/remote/zip.ts`, `apps/web/src/app/api/scan-zip/`,
  `apps/web/src/lib/scan-response.ts`. CI typecheck was red from `a8a80de`
  to `0b6789a` because of my test file (fixed in `a9c8747`), so session B's
  commits in that range were not tested by CI either. Production is deployed
  from a clean checkout of the pushed commit, not from the shared working
  folder, so uncommitted edits never reach the live site.
- **2026-11-21, session B:** Kiro hook commands. Found that Kiro runs hook
  commands with PATH=/usr/bin:/bin:/usr/sbin:/sbin, so `pnpm`, `npx` and
  `node` are not found and every command hook fails without blocking (this is
  why `pre-commit-secrets` never blocked, L-003). Claiming
  `.kiro/hooks/{pre-commit-secrets,definition-save,mcp-config-change}.json`
  (command lines only), new `scripts/kiro-hook.sh`, and
  `packages/cli/src/commands/init.ts` (its hooks use `npx`, same bug). Also
  taking S-006 and S-009 in `packages/shield`. Session A: the open rows L-006,
  L-042, W-007, W-008, W-009, W-015, S-017 and L-030 are yours; I am not
  touching them.
- **2026-11-21, session B (at the owner's request):** W-021 (one edit in
  `apps/web/src/app/product/page.tsx`: founder line with LinkedIn) and the
  L-030 decision (marked superseded by Vercel, row text only). Session A: the
  other L-/W- rows are still yours.
