# Brief: put together release 0.1.2

You are on branch `release/0.1.2`, made from `main`. Three finished branches
need to go into it, in this order, using git in the terminal:

1. `feat/touchid`: OS-verified release for the Session Guard (Touch ID). You
   (the Kiro IDE agent) built it from `.kiro/specs/m6-os-release/`.
2. `feat/console`: `exorcist console`, a read-only live dashboard of what the
   Shield is doing. Built with Claude Code outside Kiro. Shields now append
   events to `<stateDir>/events.jsonl` through an `onEvent` hook in `engine.ts`
   and `proxy.ts`.
3. `feat/distribution`: listings prepared for the MCP Registry
   (`server.json`, `mcpName`), GitHub Marketplace and Kiro Powers, plus the
   version bump to 0.1.2 everywhere. Built with Claude Code outside Kiro. The
   submit steps are in `distribution/SUBMIT.md`; do not submit anything.

Steps:

- Merge each branch with `git merge --no-ff <branch>`. Expect conflicts in
  `packages/shield/src/engine.ts`, `proxy.ts` and `index.ts` (touchid and console
  both changed them), `README.md`, `docs/KNOWN_LIMITATIONS.md` and
  `packages/cli/src/index.ts`. Resolve them by keeping both features working:
  the console's event hook must also record the new OS-release outcomes (held
  while the system prompt is open, released by the OS, refused after deny,
  error or timeout) as events, with no reason text or file content in the log.
- The console page and its docs say a held session is released only with
  `exorcist approve session` in a terminal. Under `sessionRelease: os` that is
  no longer true: update the console text (`packages/cli/src/console/`) so it
  says the release happens in the system prompt (Touch ID or login password)
  when the OS mode is in force, and keep the terminal wording for terminal mode.
  Keep the page read-only.
- Make sure every place that pins a version says 0.1.2 consistently (the
  distribution branch did this; check that the merges did not undo it).
- `docs/KIRO_LOG.md`: refresh the "Counts" section at the bottom to the real
  numbers after the merge (tests passing, files, fc.assert properties, specs),
  and make sure each new row says who built it: Kiro IDE agent for m6 (and m7
  when it lands), Claude Code for the console and the listings.
  `docs/HOW_KIRO.md` is generated from `apps/web/src/lib/how-kiro.ts` by
  `node_modules/.bin/tsx scripts/how-kiro-md.ts`; edit the source, then
  regenerate.
- Run `pnpm -r typecheck` and `pnpm vitest run` from the repository root until
  everything passes. The machine is heavily loaded: if a timing test fails, run
  that file alone before treating it as a real failure.
- Commit the merge resolutions with clear messages. Do not push.
