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
- **A rule that runs out of time fails closed on access.** The full scan
  reports a time-out as a medium finding (never "clean"). REQ-01.5 would let a
  medium finding through, so a file crafted to make a rule slow got past
  on-access with a warning. Now a time-out on a rule whose own severity is high
  or critical blocks the read, says the file could not be fully checked, and
  points to `exorcist allow-read`. A time-out on a medium or low rule still
  only warns. The engine's retry budget is unchanged (L-004).
- **Allowances live outside the project (REQ-03 deviation).** The spec put
  them in `.exorcist/allowed-reads.json`, inside the scanned repository, so a
  repo could ship its own list with the hash of its poisoned file. They are now
  per user: `$EXORCIST_DIR/allowed-reads/<sha256 of the project's real
  path>.json`, default `~/.exorcist/...`. A list that would be inside the
  project tree (EXORCIST_DIR pointing into it, a symlink into it, or any
  `.exorcist/allowed-reads.json` the repo carries) is ignored, and allow-read
  refuses to write there. Each entry binds the file's real absolute path to its
  SHA-256, so the same bytes at another path are scanned again. `allow-read`
  lost its `--dir` option.
- **Files over 1 MB are still allowed with a note** (REQ-01.3, as specified).
  This is the same kind of gap: a file padded past 1 MB is not scanned on
  access (the full scan skips it too). Left as specified; worth a decision.
- **Regex time limit unchanged.** Kiro had made the per-rule retry use the full
  1.5 s budget for every rule, which let one crafted file cost up to
  1.5 s x (rules + 1) and hid a slow rule instead of fixing it. That was
  reverted; instead EX-008 and EX-015 got a lookahead that only checks a
  "| shell" follows within 1,200 characters (a condition every match already
  meets), which makes them about 5x faster on long lines that mention curl.
  `remote-shell-lookahead.property.test.ts` checks the patterns match exactly
  what they matched before.
- **Task 5.** The first runs on 2026-11-23 failed only on wall-clock tests in
  untouched suites while the machine ran at load 70-180 on 8 cores (other
  worktrees). After the security fixes `pnpm test` passed twice in a row,
  831/831.
- **`packages/cli/build.mjs`** now updates `definitions/` file by file (atomic
  renames) instead of swapping the folder, which left a moment with no folder
  and gave a parallel test reading it ENOENT.
