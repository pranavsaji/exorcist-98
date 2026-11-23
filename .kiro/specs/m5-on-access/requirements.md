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
3. Each file is scanned with the same definitions as `exorcist scan`, using
   `scanText`, in one pass over the whole text up to 10 MB (no window
   boundaries for a payload to straddle). One deadline (10 s, under the
   hook's 15 s timeout) covers the whole call; each scan's regex time limit is
   taken from the time left so that even retried rules end before it. A file
   left when the deadline passes, and a file over 10 MB, is blocked when
   `classifyFile` gives a role an agent takes instructions or config from
   (instruction, memory, hook, config except lockfiles, mcp-config, tool
   results, powers) and allowed with a one-line warning otherwise.
4. Exit 2 (block) when any finding is critical or high. The message lists, per
   file: rule id, title, line, and the fix, and says that the user must review
   the file and allow it themselves (`exorcist allow-read`; see REQ-03); the
   agent must not run it. It never quotes the attacker's text, and file names
   are shown with control, hidden and bidi characters escaped and shell-quoted
   (the agent will read this message). A high or critical rule that runs out
   of time on the file also blocks (fail closed).
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

1. `exorcist allow-read <file>` records the file's real path and SHA-256 in a
   per-user list outside the project
   (`$EXORCIST_DIR/allowed-reads/<sha256 of the project's real path>.json`,
   default `~/.exorcist/...`). A read of a file whose path and current hash
   are allowed passes. Editing the file invalidates the allowance. A list
   inside the project tree is never used (the project could plant it).
2. `allow-read` runs only when stdin and stdout are a TTY, and only after the
   user types the first 6 characters of the file's SHA-256 shown there, so an
   agent's non-interactive shell tool cannot approve its own read. There is no
   flag or variable that skips this.

## REQ-04 Speed

1. Definitions are loaded once per process; a decision on a 100 KB file takes
   under 300 ms on a laptop (measured in a test with a generous bound).

## Property-based tests

- PBT-ACC-01: any event whose tool_input has no path-like value is allowed.
- PBT-ACC-02: a file containing a Haunted Repo critical sample at any position
  inside random benign text is blocked.
- PBT-ACC-03: after `allow-read`, the same bytes pass; any one-byte change is
  checked again.
