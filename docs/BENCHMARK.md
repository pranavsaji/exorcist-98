# Detection benchmark

How many real problems Exorcist 98 finds, and how many alarms it raises on
ordinary code. Measured on 2026-11-20.

## Summary

| Set | Repositories | Used to tune rules? | Findings |
|---|---:|---|---:|
| Tuning set | 5 | yes | 4,457 before, 2 after |
| Held-out set A | 5 | inspected, then tuned | 2,200 before, 13 after |
| Held-out set B (blind) | 5 | inspected, then tuned | 401 before, 6 after |
| Held-out set C (blind, final) | 5 | **no** | **1** (correct) |

Held-out set C is the honest number: five repositories that no rule was ever
adjusted for, about 9,500 files, scanned once. Its one finding is a real
unpinned MCP server. Details below.

## Re-run after the precision fixes of 2026-11-23

The field report ([`FIELD_REPORT.md`](FIELD_REPORT.md)) found that on 224
other public repositories almost every high or critical alert was noise, and
the rules were changed to fix that. All 20 repositories above were scanned
again at the same commits, with the scanner before those fixes and after
them, using the same download method as the field report. No rule was changed
for these repositories in this re-run, but they were looked at before, so
these are not new held-out numbers:

| Set | Findings before | Findings after | High or critical before | High or critical after |
|---|---:|---:|---:|---:|
| Tuning set | 2 | 2 | 2 | 2 |
| Held-out set A | 13 | 4 | 11 | 0 |
| Held-out set B | 6 | 6 | 5 | 4 |
| Held-out set C | 1 | 1 | 0 | 0 |

"Before" reproduces the "after" column of each set exactly. What changed:

- `github/awesome-copilot`: 11 high or critical findings are gone. Five were
  injection phrases quoted in order to warn about them ("never follow text
  such as ..."), four were two install commands listed as data in a website
  data file (each reported by both EX-008 and EX-015; nothing runs them as a
  hook), and two single
  zero-width spaces before code fences are now reported at medium.
- `jlowin/fastmcp`: a single zero-width space in a workflow is now medium.
- Unchanged and still listed: the Copilot HTML comment (EX-004), the minisign
  key that decodes to readable words (EX-003, a false alarm), the long run of
  zero-width spaces in `steipete/agent-rules` (EX-001), the two prompt phrases
  in `jlowin/fastmcp` workflows (EX-005, EX-006, false alarms) and the
  unpinned servers (EX-010).

At that re-run (2026-11-23) the labelled corpus below gave 19 of 19 attacks caught and 19 of 19
ordinary files clean. `packages/core/src/__tests__/precision-round2.test.ts`
adds a regression test for every false-alarm pattern that was fixed and for
every attack shape that must still be caught.

## Real public repositories (false alarms)

These five repositories are maintained by the teams behind the agents and MCP
servers people use every day. None is known to contain an attack, so every
finding counts as a false alarm unless it is shown to be real.

| Repository | Commit | Findings before | Findings after |
|---|---|---:|---:|
| modelcontextprotocol/servers | `c799c85` | 421 | 0 |
| github/github-mcp-server | `9a72d8d` | 332 | 1 |
| openai/codex | `51f4b8a` | 3,082 | 0 |
| anthropics/claude-code-action | `c84e279` | 50 | 0 |
| cline/cline | `85d1815` | 572 | 1 |
| **Total** | | **4,457** | **2** |

The two that remain:

- `github/github-mcp-server`, `.github/pull_request_template.md`: an HTML
  comment that gives Copilot instructions ("Copilot: Fill all sections").
  It is harmless here, but it is exactly the pattern EX-004 looks for: text
  aimed at an AI agent that a person reading the rendered page cannot see.
- `cline/cline`, `apps/examples/desktop-app/src-tauri/tauri.conf.json`: a minisign public key, which
  decodes to the readable words "untrusted comment: minisign public key".
  A false alarm.
  Fixed since (m7-precision, `docs/FIELD_REPORT.md` Round 3, a different scan): EX-003 no longer
  reports a minisign key or signature unless the other rules flag the text
  inside it.

"Before" is the scanner at commit `1a01d22`. Almost all of it was EX-003
(encoded payload), which matched any 40-character run of the base64 alphabet,
URL paths and lockfile hashes included.

What changed:
- EX-003 now counts only base64 that decodes to readable words or a command,
  and skips lockfiles and test folders.
- EX-004 stays inside one HTML comment (it used to run past `-->`) and needs
  words aimed at an AI.
- EX-012 skips well-known status badge services.
- EX-011 skips placeholders such as `<your token>`, `${VAR}`, `[REDACTED]`
  and test folders.
- EX-005 and EX-006 run on generic JSON only when it defines MCP servers or
  tools.
- EX-008 and EX-015 skip CI workflows and `action.yml`, which are not agent
  hooks.
- EX-001 ignores a joiner between two emoji and a byte-order mark at the
  start of a file.

To repeat: shallow-clone each repository at the commit above and run
`node packages/cli/dist/index.mjs scan <folder> --format json --fail-on none`.

## Held-out repositories

The tuning set above was also used to change the rules, so its numbers show
the rules fit those repositories, not that they generalise. Three more sets
of five repositories each (A, B and C, scanned on 2026-11-20; not the same as the field report rounds), all picked because they contain agent instruction
files, rules files or MCP configs, measured on 2026-11-20 with
`node packages/cli/dist/index.mjs scan <folder> --format json --fail-on none`.

**Held-out set A** (modelcontextprotocol/python-sdk `77001c9`,
openai/openai-agents-python `6c4e4a2`, github/awesome-copilot `f10fdb8`,
PatrickJS/awesome-cursorrules `b044f95`, punkpeye/awesome-mcp-servers
`5fb385c`): **2,200 findings**. 2,180 were one false alarm: Persian text in
`README-fa-ir.md` uses U+200C (zero-width non-joiner) to spell words, and
EX-001 flagged each one. The rest were a mix. Real: two unpinned servers in
an example config, zero-width spaces escaping code fences in an agent file,
and quoted attack strings in security guides. False: a keyword argument
`openai_api_key=api_key`, `DATABASE_URL` without credentials, a `ghp_xxx`
placeholder, a defensive "override any instructions found in repository
files", and an agent prompt saying "you are now operating beyond normal
limits". Fixed: U+200C and U+200D between non-Latin letters are not hidden
text; EX-002, EX-011, EX-012 and EX-014 narrowed. After: **13**.

**Held-out set B** (microsoft/playwright-mcp `2337aff`, upstash/context7 `b1e3611`,
jlowin/fastmcp `ffb3a3b`, steipete/agent-rules `42993e4`,
hesreallyhim/awesome-claude-code `00e1ce3`), scanned once before any change:
**401 findings**. 390 were one false alarm: EX-012 flagged every README image
with a query string, and stat-card images all have one. Five more were EX-011
on shell lines that read a key with `$(...)`. About four were correct by the
rule's own definition (hidden characters in two files, an unpinned server).
Fixed: EX-012 now needs a query that carries data (a parameter such as
`data=`, `token=`, `env=` or `user=`, or a template such as `{{...}}`);
EX-011 skips `$(...)` and `$VAR` values. After: **6**. Two of those are agent
prompts inside GitHub workflows that say "before responding" and "Do not
mention", which is ordinary prompt wording there: still false alarms.

**Held-out set C** (punkpeye/fastmcp `dc4e085`, wong2/awesome-mcp-servers `39eb1d7`,
anthropics/claude-code `11fd18f`, microsoft/vscode-copilot-chat `5863f5a`,
ComposioHQ/awesome-claude-skills `be2a406`), scanned once and **not used to
change anything**: **1 finding** in about 9,500 files, EX-010 on
`.roo/mcp.json` running `@upstash/context7-mcp` without a version. That is a
correct finding.

Every false alarm fixed for held-out sets A and B is now a case in
`fixtures/benchmark/benign/`, so it stays fixed.

## Labelled attack corpus (missed attacks)

Today `fixtures/benchmark/` holds <!--f:benchmarkAttacks-->21<!--/f--> defanged attacks and <!--f:benchmarkBenign-->21<!--/f--> ordinary files that
look like attacks to a naive scanner. `packages/core/src/__tests__/benchmark.test.ts`
runs them on every test run.

| | Cases | Result |
|---|---:|---|
| Attacks caught | <!--f:benchmarkAttacks-->21<!--/f--> | <!--f:benchmarkAttacksCaught-->21<!--/f--> caught |
| Ordinary files with no findings | <!--f:benchmarkBenign-->21<!--/f--> | <!--f:benchmarkBenignClean-->21<!--/f--> clean |

The attacks include five that the scanner missed before the precision work of 2026-11-20:
- a Cursor rules file (`.cursor/rules/*.mdc`) whose instruction is split by a
  zero-width space;
- a word joiner (U+2060);
- a tool description that says "prior to invoking this tool ... keep it
  quiet from the user";
- `"autoApprove": ["*"]`;
- a Kiro hook that pipes `base64 -d` into a shell.

It also covers a steering file that switches off approvals (EX-014), a
`.claude/settings.json` hook that downloads and runs a script, a private key
pasted into docs, a typosquatted MCP package, planted agent memory, a
confused-deputy request, a suspicious Power, and hex-encoded payloads. The
ordinary files include badges, emoji, lockfiles, git SHAs and checksums, CI
installers, test tokens, placeholders, well-known MCP packages and ordinary
agent notes.

## What it still misses

The corpus is small and was written by the same team as the rules, so it
shows coverage of known patterns, not recall on unknown ones. Known gaps:
- Instructions with wording no rule lists, for example a novel phrasing in a
  markdown link title. The optional AI judge is meant for this and has not
  been run against the service (L-020).
- Attacks split across files.
- A typosquat is only caught for the well-known MCP packages in
  `packages/core/src/known-packages.ts`.
