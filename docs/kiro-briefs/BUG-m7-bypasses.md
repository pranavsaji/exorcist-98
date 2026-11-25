# Bug: three m7 false-alarm fixes open detection bypasses

Found by an automated security review of commit e1647e3 (m7-precision). Each
exemption added to cut false alarms can be written by an attacker on purpose.

1. **EX-012** (`definitions/EX-012-markdown-image-exfil.yaml`): the Google
   Docs exemption matches the host with `[a-z0-9.-]*googleusercontent\.com`, so
   `attacker-googleusercontent.com` or `googleusercontent.com.evil.example`-style
   look-alikes may pass. Query parameters before `key=` are also allowed, so data
   can ride along. Fix: anchor the host on a dot boundary
   (`(?:[a-z0-9-]+\.)*googleusercontent\.com`), allow only the expected
   parameter (`\?key=` as the first and only one) and do the same for the
   GitBook branch (`alt=media` and `token` only, nothing else).
2. **EX-002 (and EX-001, EX-004, EX-023)** `skip_paths` for test, spec,
   fixture, e2e and eval folders drops findings completely. Agents read files in
   those folders, and agent-facing files can live there (`AGENTS.md`,
   `CLAUDE.md`, `.kiro/**`, `.claude/**`, `.cursor/**`,
   `.github/*instructions*`, MCP configs, hooks). Fix: never skip a file whose
   role is agent-facing (instruction, hook, MCP config; see how roles are
   classified in packages/core), and for other files in those folders lower the
   severity to low instead of dropping the finding, if the rule format supports
   it (add that support if it does not, the same way for all four rules).
3. **EX-004** (`definitions/EX-004-html-comment-smuggling.yaml`): any comment
   that starts with `noqa` is exempt unless it contains a listed attack phrase,
   so an attacker can write `<!-- noqa` followed by a hidden instruction worded
   differently. Fix: exempt only a short linter directive with nothing else in it,
   for example `^<!--\s*noqa(?::\s*[A-Z0-9-]+(?:,\s*[A-Z0-9-]+)*)?\s*-->$`. Any
   free text after the code is still reported.

For each: a failing test with the bypass first (defanged), then the fix, plus a
test that the original false alarm stays fixed. The benchmark (19 of 19 caught,
19 of 19 look-alikes left alone) and the Haunted Repo (47 findings) must not
change. If a field-scan number in docs/FIELD_REPORT.md round 3 changes, update
it honestly. Add a line to the m7 entry in docs/KIRO_LOG.md saying a security
review found these and the Kiro agent fixed them. Run `pnpm -r typecheck` and
`pnpm vitest run`. Do not commit or push.

4. **Web snippets and patches** (`apps/web/src/lib/snippet.ts`, and
   `redactPatch`): redaction runs line by line, so the body lines of a
   multi-line private key block (between its BEGIN and END lines) are shown in
   the clear. Fix: redact the whole source text (or the whole patch) before
   splitting it into lines, or track private-key block ranges and blank every
   line inside them. Test with a defanged multi-line key block (build the
   marker strings at run time, as the existing tests do, so the repository's
   own no-private-keys check stays happy).
