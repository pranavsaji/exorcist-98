# Notes: m5-on-access

Decisions made while finishing the spec (Claude Code, after Kiro's partial run).

- **Read tools only.** `decideRead` allows any event whose `tool_name` does not
  contain "read" (REQ-01.2 says "for read-like tools"); the hook matcher already
  filters, this keeps the decider correct if it is wired to other tools. An
  event with no `tool_name` is still checked by its path keys.
- **Nested path keys.** Some read tools take a list of operations
  (`{ operations: [{ mode, path }] }`), so the REQ-01.2 keys are looked for up
  to four levels deep, not only at the top of `tool_input`.
- **Files outside `cwd`** are scanned when they can be read (REQ-01.2 only says
  unreadable ones are ignored); the message names them by base name.
- **One entry per rule per file** in the block message, with all its lines
  (`lines 11, 12, 14  EX-002 ...`) and the fix once, instead of the same fix
  repeated per line. The header no longer says every block is an injection:
  any high or critical rule blocks (for example EX-011 on a `.env` file).
- **A rule that runs out of time** (L-004) is a medium finding, so the read is
  allowed (REQ-01.5) with a warning saying the file could not be fully checked.
  A crafted file that makes one rule slow can therefore get past on-access with
  a warning; the full scan reports the same medium finding.
- **State folder.** `allow-read`, `exorcist on-access` and
  `scripts/hook-on-access.ts` all find `.exorcist/` the same way
  (`findStateDir`: EXORCIST_DIR, else the project's `.exorcist`).
- **Regex time limit unchanged.** Kiro had made the per-rule retry use the full
  1.5 s budget for every rule, which let one crafted file cost up to
  1.5 s x (rules + 1) and hid a slow rule instead of fixing it. That was
  reverted; instead EX-008 and EX-015 got a lookahead that only checks a
  "| shell" follows within 1,200 characters (a condition every match already
  meets), which makes them about 5x faster on long lines that mention curl.
  `remote-shell-lookahead.property.test.ts` checks the patterns match exactly
  what they matched before.
- **Task 5 left unticked.** On 2026-11-23 the machine ran at load 70-180 on 8
  cores (other worktrees building and testing), and `pnpm test` failed only
  wall-clock tests in suites this spec does not touch (shield proxy,
  mcp-server, web route, orchestrator: 5 s timeouts; the precision-round2
  "stays fast" bound). Every on-access, hook, CLI and init test passed in both
  full runs. Tick it after a green `pnpm test` on an idle machine.
- **`packages/cli/build.mjs`** now updates `definitions/` file by file (atomic
  renames) instead of swapping the folder, which left a moment with no folder
  and gave a parallel test reading it ENOENT.
