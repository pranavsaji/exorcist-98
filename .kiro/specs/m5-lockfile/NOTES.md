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
- **The lock records expected fingerprints, never approvals (REQ-03.2).**
  `exorcist.lock` comes with the repository, which is untrusted input, so the
  Shield never treats it as an approval. It is read into a separate, in-memory
  map of expected fingerprints per server (`EngineOptions.expected`), used
  only to detect drift:
  - A tool this machine has not pinned whose fingerprint differs from the
    lock is a rug pull: EX-006, withheld, with a diff against the locked
    description, and held in `pending` for `exorcist approve tool`.
  - A tool that matches the lock goes through exactly the same first-use path
    as a never-seen tool: signature checks (EX-005), the AI judge when
    `aiReview` is on, and the review hold when `firstUse` is `review`.
  - The lock is never written into `tools`, and `unreviewed` entries are
    never removed (`seedFromLock` only reads the state).
  - A program never pinned here that differs from the lock's `launch` is
    held like a changed program (EX-010, blocked under `launchPin: block`)
    until `exorcist approve server`; a matching one is pinned by the normal
    trust-on-first-use, not by the lock.
  - A local pin always wins over the lock; one that disagrees is reported.
  An earlier version of this branch seeded lock fingerprints into the pins
  (marked `source: "lock"`), which let a committed lock skip the AI judge
  and the `firstUse: review` hold. Security review caught it; it was replaced
  by the design above.
- **CI never starts pull-request-controlled servers (REQ-03.3).** A live
  `lock --check` starts every server in the config, and on a pull request the
  config belongs to its author, so a PR could run any command in CI with the
  job's secrets and token (security review finding). `lock --check --static`
  starts nothing: it compares the set of server names, each local server's
  launch fingerprint (command, arguments, and the contents of argument files,
  read but never run), remote URLs and the lock's validity; tools are carried
  over from the lock. The Action's `lock-check: true` always uses `--static`.
  `lock-check: live` compares tool descriptions too, and the Action refuses
  it (exit 2) on `pull_request` and `pull_request_target` events and when the
  head repository differs from the base repository.
- **Minimal environment for started servers.** `exorcist lock` passes only
  PATH, HOME, LANG, LC_*, TMPDIR (and the Windows equivalents: SYSTEMROOT,
  WINDIR, USERPROFILE, APPDATA, LOCALAPPDATA, PATHEXT, COMSPEC, TEMP, TMP)
  plus the entry's own `env`. GITHUB_*, ACTIONS_*, RUNNER_*, AWS_*,
  NPM_TOKEN, *_TOKEN, *_KEY, *_SECRET, LD_*, DYLD_* and NODE_OPTIONS are
  never inherited; only the entry's `env` can set them. The MCP SDK adds its
  own safe defaults (HOME, LOGNAME, PATH, SHELL, TERM, USER).
- **Exit codes.** `--check` exits 0 when identical, 1 on any difference, 2 when
  it could not check (no lock, a server that would not list its tools within
  the timeout, a bad config).
- **The Action** comments the lock report in its own comment (marker
  `<!-- exorcist-98-lock -->`), only when `comment` is also true; a passing
  check updates an earlier comment but never starts a new one. The report is
  put in a code fence longer than any run of backticks in it.
