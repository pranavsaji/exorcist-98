# Detection benchmark

How many real problems Exorcist 98 finds, and how many alarms it raises on
ordinary code. Measured on 2026-11-20.

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
- `cline/cline`, `src-tauri/tauri.conf.json`: a minisign public key, which
  decodes to the readable words "untrusted comment: minisign public key".
  A false alarm.

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

## Labelled attack corpus (missed attacks)

`fixtures/benchmark/` holds 12 defanged attacks and 12 ordinary files that
look like attacks to a naive scanner. `packages/core/src/__tests__/benchmark.test.ts`
runs them on every test run.

| | Cases | Result |
|---|---:|---|
| Attacks caught | 12 | 12 caught |
| Ordinary files with no findings | 12 | 12 clean |

The attacks include five that the scanner missed before this round:
- a Cursor rules file (`.cursor/rules/*.mdc`) whose instruction is split by a
  zero-width space;
- a word joiner (U+2060);
- a tool description that says "prior to invoking this tool ... keep it
  quiet from the user";
- `"autoApprove": ["*"]`;
- a Kiro hook that pipes `base64 -d` into a shell.

It also covers a steering file that switches off approvals (new rule EX-014),
and a `.claude/settings.json` hook that downloads and runs a script.

## What it still misses

The corpus is small and was written by the same team as the rules, so it
shows coverage of known patterns, not unknown ones. Known gaps:
- Instructions with wording no rule lists, for example a novel phrasing in a
  markdown link title. The optional AI judge is meant for this and has not
  been run against the service (L-020).
- Attacks split across files.
- Rules EX-013, EX-018, EX-019 and EX-020 have fixtures but no rule yet.
