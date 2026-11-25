# Brief: make the Kiro log about Kiro, and keep the docs about the product

Goal: the documentation should describe the product, and the Kiro log should
record what Kiro did. Other tools used to build parts of the project do not need
to be named. One rule is absolute: **nothing may say or imply that Kiro did work
it did not do.** When a sentence about Kiro would become untrue or misleading
without its context, rewrite it to say only what Kiro did, or remove it.

## Keep (these are about the product, not about how it was built)

- Mentions of coding agents the product protects (Kiro, Cursor, Claude Code,
  Copilot, Cline, Windsurf, Gemini), `CLAUDE.md` files it scans, and the Claude
  model the AI judge runs on Amazon Bedrock. Keep all of these exactly.
- Git history and commit messages: do not rewrite history.
- `docs/kiro-briefs/`: the briefs given to the Kiro agent stay.

## Change

1. `docs/KIRO_LOG.md`: keep only rows that record Kiro's own work (Kiro IDE,
   Kiro CLI, Kiro hooks, specs written or implemented by Kiro, Kiro's Powers
   panel). Remove the rows that describe work done without Kiro (for example
   the rows marked "outside Kiro" or "not Kiro"). Where a kept row mixes the two,
   keep only the Kiro part and make sure it does not claim the rest. The
   "Counts" section: label the project-wide numbers (tests, files, properties)
   as counts for the whole project, not as Kiro's output, and keep the number
   of specs written with Kiro accurate.
2. `apps/web/src/lib/how-kiro.ts` (then regenerate `docs/HOW_KIRO.md` with
   `node_modules/.bin/tsx scripts/how-kiro-md.ts`): remove the list of work
   done with other tools and the `git log --grep "(Claude Code)"` pointers.
   Rewrite the sentences that named another tool so they state only what Kiro
   did. For example: the M5 specs are in Kiro's spec format and Kiro CLI
   implemented parts of six M5 features before the account hit its monthly
   usage limit (the commits marked "partial implementation by Kiro" list them).
   Do not say Kiro wrote those specs or finished those features. If the page
   title or any heading claims Kiro built the whole project, make it
   accurate, for example "How we used Kiro". Update
   `apps/web/src/__tests__/how-kiro.test.tsx` to match.
3. `docs/KNOWN_LIMITATIONS.md` S-027 and S-028, and `docs/EXTENSION.md`: drop
   "built with Claude Code" and "written with Claude Code, outside Kiro";
   describe the feature only.
4. `README.md` and `docs/SUBMISSION.md`: remove any remaining statements about
   which tool built which part, unless the statement is about Kiro and true.

Run `pnpm -r typecheck` and `pnpm vitest run`. Commit with a clear message.
Do not push.
