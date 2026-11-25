# Feature brief: the first five minutes for a judge, and CI that installs what we publish

Write a Kiro spec in `.kiro/specs/m14-first-five-minutes/` (requirements,
design, tasks), then implement every task. Follow `.kiro/steering/`. Give every
requirement an ID (FF-1, FF-2, ...) and start the name of each test that checks
it with that ID.

## 1. A moving picture at the top of the README

`docs/media/rug-pull-demo.gif` (2 MB, 21 seconds, recorded from the live site)
shows the Possession Lab rug pull: the same attack with and without the
Shield, ending on "Result: protected". Put it right under the one-line pitch
in `README.md`, with alt text that says what happens in it, and a caption
linking the live demo. Keep the Touch ID placeholder comment for the other
image. Keep the README short (about 100 lines) and keep our own scan of it
CLEAN.

## 2. `docs/START-HERE.md`

A page for someone with five minutes, linked from the top of the README and
from the site footer:
- 60 seconds, nothing to install: the three live links (scan the Haunted
  Repo, the rug pull, the Lethal Trifecta) and what to look for in each.
- 5 minutes on your own machine: `npx -y @exorcist-98/cli scan .`, the Kiro
  Power import URL, `exorcist init --kiro`.
- A scenario table: each demo or attack, what Exorcist 98 does, and the
  expected result (for example the Haunted Repo gives "Verdict: POSSESSED"),
  so a reader can check each claim.
- Where to look for each judging question (impact, how Kiro was used, design,
  what is new), each with links to the evidence in this repository.
- The honest limits in three lines, linking `docs/KNOWN_LIMITATIONS.md`.

## 3. How this differs from tools that already exist

A comparison table in `docs/REFERENCE.md`, summarised in two lines in the
README: Exorcist 98 next to existing tools for MCP and agent security (for
example mcp-scan, Lakera Guard, Semgrep rules for prompt injection, GitHub
secret scanning, and any MCP proxy or firewall you find). Read each tool's own
documentation and state only what it says; link the source for every row; if
a feature cannot be confirmed, write "not documented" rather than guess. Say
what Exorcist 98 adds and also where another tool does more.

## 4. CI that installs the published shape

A CI job (in the existing workflow) that packs `@exorcist-98/cli` and
`@exorcist-98/mcp-server`, installs the tarballs into an empty temporary
project with no workspace links, and checks:
- `exorcist --version` matches `package.json`;
- scanning `fixtures/haunted-repo` exits non-zero and prints
  "Verdict: POSSESSED";
- scanning a clean temporary folder exits 0 and prints "Verdict: CLEAN";
- the MCP server answers `initialize` and `tools/list` over stdio with the
  expected tool names.
Put the logic in a script under `scripts/` so it also runs locally, with a
test.

## 5. Finish

Run `node scripts/facts.mjs --run-tests --docs`, add a row to
`docs/KIRO_LOG.md` for this work by the Kiro IDE agent, and move this brief to
`docs/kiro-briefs/`. Run `pnpm -r typecheck` and `pnpm vitest run` until they
pass, and the web e2e if you touched the site. Commit. Do not push.
