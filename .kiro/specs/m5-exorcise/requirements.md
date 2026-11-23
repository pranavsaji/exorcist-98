# Spec: m5-exorcise (Disinfect)

Finding a virus was half of 90s antivirus; the "Clean" button was the other
half. `exorcist exorcise` repairs the threats that have one safe, mechanical
fix, and always keeps a backup in the Quarantine Vault.

## REQ-01 Fixes (only these; everything else is reported, never edited)

1. EX-001 hidden Unicode: remove zero-width, bidi-override and tag-block
   characters (and EX-021 variation-selector runs of 4+ when that rule exists).
   Never touch a single U+FE0F/U+200D inside an emoji sequence.
2. EX-010 unpinned MCP server: pin `npx -y pkg` / `uvx pkg` to the exact
   version currently resolved (`npm view pkg version` for npm; skipped with a
   note when offline or for other runners).
3. EX-012 markdown image exfiltration: replace the image with its alt text and
   a comment `<!-- exorcised: remote image removed -->`.
4. HTML comments flagged by EX-002/EX-004: remove the comment.

## REQ-02 Command

1. `exorcist exorcise [dir]` prints a unified diff of every change and changes
   nothing (dry run is the default).
2. `--write` applies the changes. Before writing, each file is copied into the
   vault (`.exorcist/vault/`, exact bytes + sha256), so
   `exorcist vault restore <id>` undoes it.
3. `--only EX-001,EX-010` limits the fixes.
4. After `--write`, the scan is re-run on the changed files and the result
   ("12 threats removed, 2 need a human") is printed.

## REQ-03 Web

1. After a scan of an uploaded .zip or a GitHub repo, the results window has
   "Download exorcism patch": a `.patch` file (unified diff) built on the
   server from the same fix code, for the fixable findings only.

## Property-based tests

- PBT-EXO-01: removing hidden characters from any string leaves the visible
  text identical and the result has no EX-001 findings.
- PBT-EXO-02: an emoji ZWJ sequence or a single FE0F is never changed.
- PBT-EXO-03: exorcise --write then vault restore returns every file to its
  exact original bytes.
