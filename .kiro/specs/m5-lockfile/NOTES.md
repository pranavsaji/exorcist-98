# Notes: m5-lockfile

Decisions made while finishing the spec, where it left room or was silent.

- **Remote servers have no `launch`.** REQ-01.1 shows `launch` on every
  server, but a remote (http/sse) server has no command or arguments. Its
  entry is `{ "url", "note", "tools": {} }`; the URL is stored without
  credentials, query or fragment, because those can hold tokens.
- **Disabled servers are never started (REQ-02.1).** Their entry in the
  existing lock is carried over unchanged (and not reported by `--check`), so
  quarantining a server in the vault does not silently drop its approvals.
- **Wrapped configs.** A config run through `exorcist wrap` is unwrapped in
  memory first, so the lock fingerprints the real server, as the Shield does.
- **Raw tool JSON.** Tools are listed with the MCP SDK client, but the result
  is validated with a permissive schema so the fingerprints are computed on
  exactly the JSON the server sent: the same bytes the Shield hashes.
- **Descriptions past 200 characters.** Only the first 200 characters (code
  points) are stored, so a change after that point is still reported by its
  fingerprint, but the message says the visible part is unchanged instead of
  showing an empty diff.
- **A lock cannot pre-approve a poisoned tool.** `exorcist.lock` comes from
  the project folder (untrusted). Pins seeded from it are marked
  `source: "lock"`; the first time the Shield sees the tool with that
  fingerprint it still runs the first-use signature checks (EX-005) before
  confirming the pin.
- **Exit codes.** `--check` exits 0 when identical, 1 on any difference, 2 when
  it could not check (no lock, a server that would not list its tools within
  the timeout, a bad config).
- **The Action** comments the lock report in its own comment (marker
  `<!-- exorcist-98-lock -->`), only when `comment` is also true; a passing
  check updates an earlier comment but never starts a new one. The report is
  put in a code fence longer than any run of backticks in it.
