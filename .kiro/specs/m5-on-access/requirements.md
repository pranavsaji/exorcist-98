# Spec: m5-on-access (On-Access Scanning)

90s antivirus did not wait for a full scan: the on-access scanner checked every
file the moment a program opened it. Exorcist 98 does the same for an AI agent:
a Kiro `PreToolUse` hook scans a file *before* the agent reads it, and refuses
the read when the file carries instructions aimed at the AI.

## REQ-01 Decide on a read

1. `decideRead(event, defs, opts)` in `@exorcist-98/core` takes a Kiro hook
   event (`{ hook_event_name, cwd, tool_name, tool_input }`) and returns
   `{ exitCode: 0 | 2, message }`.
2. It finds the file paths in `tool_input` for read-like tools (keys `path`,
   `file_path`, `filePath`, `paths`, `uri`; `file://` URIs accepted), resolves
   them against `cwd`, and ignores anything outside `cwd` it cannot read.
3. Each file (max 1 MB; larger files are allowed with a note) is scanned with
   the same definitions as `exorcist scan`, using `scanText`.
4. Exit 2 (block) when any finding is critical or high. The message lists, per
   file: rule id, title, line, and the fix, and tells the user how to allow it
   once (`exorcist allow-read <file>`; see REQ-03). It never quotes the
   attacker's text (the agent will read this message).
5. Medium/low findings allow the read (exit 0) with a one-line warning.
6. Unknown event shape, missing files, or unreadable JSON: allow (exit 0). The
   hook must never brick the agent.

## REQ-02 The hook and the CLI

1. `exorcist on-access` reads the event on stdin and exits with the decision.
2. `.kiro/hooks/on-access-scan.json`: trigger `PreToolUse`, matcher covering
   Kiro's read tools (`read|readFile|read_file|readCode|fs_read|readMultipleFiles`),
   command `sh scripts/kiro-hook.sh node_modules/.bin/tsx scripts/hook-on-access.ts`,
   timeout 15.
3. `exorcist init` also writes this hook for user projects (through
   `.exorcist/kiro-hook.sh`, as for the other hooks).

## REQ-03 Allow once

1. `exorcist allow-read <file>` records the file's SHA-256 in
   `.exorcist/allowed-reads.json`. A read of a file whose current hash is
   allowed passes. Editing the file invalidates the allowance.

## REQ-04 Speed

1. Definitions are loaded once per process; a decision on a 100 KB file takes
   under 300 ms on a laptop (measured in a test with a generous bound).

## Property-based tests

- PBT-ACC-01: any event whose tool_input has no path-like value is allowed.
- PBT-ACC-02: a file containing a Haunted Repo critical sample at any position
  inside random benign text is blocked.
- PBT-ACC-03: after `allow-read`, the same bytes pass; any one-byte change is
  checked again.
