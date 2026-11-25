# Brief: put together release 0.2.0

You are on branch `release/0.2.0`, made from `release/0.1.3` (0.1.3 is being
published to npm now). Four finished branches, each built by the Kiro IDE agent
from a brief in `docs/kiro-briefs/`, go into it. Merge them with
`git merge --no-ff` in this order:

1. `feat/kirodepth2`: `exorcist gate` and its Stop hook, the Power and custom
   agents checked against Kiro's docs (m10).
2. `feat/adoption`: baseline and inline suppressions, tool descriptions from
   server source, stale-definitions warning, CLI wording (m9).
3. `feat/incidents`: the published Kiro attacks: hidden-text rule, possessed
   filenames, exfiltration sentences, the MCP config write guard hook, Lab
   attack 8, docs/INCIDENTS.md (m8).
4. `feat/polish`: one source for every number (`scripts/facts.mjs`,
   `docs/facts.json`), the short README, product page, console text, video
   script, submission text.

Expect conflicts in README.md, docs/KIRO_LOG.md, apps/web/src/lib/how-kiro.ts,
packages/cli/src/commands/init.ts, packages/cli/src/index.ts, action.yml,
scripts/e2e-chrome.mjs, docs/SUBMISSION.md and docs/KNOWN_LIMITATIONS.md. Keep
every feature working; take the short README from polish and add one line for
each new feature (gate, baseline, incident rules), linking to the docs.

Then:

- **Our own README must not be possessed.** m8 made the scanner catch the
  example sentence the README quoted, so m8 added README.md to the ignore list
  of the CI dogfood scan. Instead: describe the attack in the README in words
  without quoting a working instruction (the real sample lives in the Haunted
  Repo fixture and the benchmark), remove README.md from that ignore list, and
  make sure `exorcist scan README.md` is clean and the on-access hook would let
  an agent read it.
- Bump both packages to 0.2.0 and move every pin that must move with them
  (power/mcp.json, Power skills, server.json, init defaults, package READMEs,
  version tests). Keep historical statements ("0.1.2 published ...").
- Run `node scripts/facts.mjs --run-tests` (or how the script says) so every
  number is current, and update the docs it checks. KIRO_LOG counts: specs
  written and implemented with Kiro IDE are now 10 (m0 to m4, m6, m7, m8, m9,
  m10); keep project-wide numbers labelled as such, and no row may claim Kiro
  did work it did not do.
- Run `pnpm -r typecheck`, `pnpm vitest run`, build the web app and run the
  browser suite against it. The machine is busy: rerun a timing test alone before
  treating it as a failure.
- Commit with clear messages. Do not push.
