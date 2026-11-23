# Spec: m5-lockfile (exorcist.lock: an integrity checker for MCP tools)

In the 90s, integrity checkers kept a checksum of every program and raised the
alarm when one changed. Today each developer's Shield pins MCP tools on their
own machine, so a rug pull that hits a teammate first is invisible to everyone
else. `exorcist.lock` is a committed, reviewable list of the MCP tools a team
has approved, like a package lockfile for tool descriptions.

## REQ-01 The file

1. `exorcist.lock` (JSON, sorted keys, 2-space indent, trailing newline) at the
   project root: `{ "version": 1, "servers": { "<name>": { "launch": "<sha256
   of command+args>", "tools": { "<tool>": { "sha256": "...", "description":
   "<first 200 chars>" } } } } }`.
2. Deterministic: the same tools always produce byte-identical files.

## REQ-02 Create and update

1. `exorcist lock` starts each MCP server in `.kiro/settings/mcp.json` (or a
   given config), lists its tools over MCP stdio with a 20 s timeout, and
   writes the lock. Remote (http/sse) servers are listed with their URL and
   skipped with a note.
2. `exorcist lock --from-shield` builds the lock from the local Shield pin file
   instead, without starting anything.

## REQ-03 Verify (CI and locally)

1. `exorcist lock --check` re-lists the tools and exits 1 on any difference:
   added tool, removed tool, changed description/schema (with a unified diff of
   the description), changed launch command. Exit 0 when identical.
2. The Shield, when `exorcist.lock` exists, treats locked fingerprints as
   approved and a mismatch as a rug pull (same EX-006 behaviour) even on a
   machine that never pinned the tool before.
3. The GitHub Action gains an input `lock-check: true` that runs
   `exorcist lock --check` and comments the diff on the pull request.

## Property-based tests

- PBT-LCK-01: writing a lock from any set of tools and reading it back gives
  the same fingerprints; serialising twice gives identical bytes.
- PBT-LCK-02: changing any single character of any tool's description makes
  `--check` report exactly that tool.
- PBT-LCK-03: reordering tools or object keys never changes the lock.
