# Security policy

Exorcist 98 is a security tool, so a flaw in it can leave people exposed while
they believe they are protected. Reports are welcome and taken seriously.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on
[pranavsaji/exorcist-98](https://github.com/pranavsaji/exorcist-98/security).
Please do not open a public issue for a vulnerability.

Include what you did, what you expected the tool to do, and what it did
instead. A minimal file, MCP server or tool-call sequence that shows it is the
most useful thing you can send. Never include real credentials: use fakes such
as `EXAMPLE_KEY_DO_NOT_USE`.

We aim to acknowledge a report within 3 days, to agree a fix plan within 10,
and to credit you in the release notes unless you prefer not to be named.

## In scope

- **Shield bypasses.** A tool call, tool list, tool result or server-initiated
  request that should be stopped (secrets leaving, an unapproved host, a
  changed tool, a canary, a poisoned result) but is let through in `enforce`
  mode.
- **Scanner evasion.** A file that an AI agent would obey as an instruction,
  hidden or encoded so that no rule flags it, when a rule claims to cover that
  technique.
- **Self-protection.** Anything that makes Exorcist 98 itself dangerous to run:
  executing code from a scanned repository, following symlinks out of it,
  writing outside its state folder, leaking a secret it found into logs,
  reports, the website or the AI judge.
- **The website** (`exorcist-98.vercel.app`): anything that lets one visitor
  affect another, reach internal networks through the scanner, or run up the
  AI judge's bill past its documented limits.
- **Approval paths.** An agent approving its own file read, tool or server
  (`exorcist allow-read`, `exorcist approve`) without a person.

## Out of scope

- Attacks the documentation already lists as not covered
  ([docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md)), unless you show a
  way to fix them.
- Monitor mode letting something through. That is its job; it only alerts.
- Findings that need a compromised machine or a malicious Exorcist 98 build.

## Supported versions

The latest release of `@exorcist-98/cli` and `@exorcist-98/mcp-server` on
npm, and `main`. Releases are published from CI with
[npm provenance](https://docs.npmjs.com/generating-provenance-statements), so
`npm audit signatures` shows that a package was built from this repository.

## How we disclose what we find

When Exorcist 98 finds a real threat or a leaked secret in someone else's
public repository, we tell the maintainer privately first, withhold the
repository's name until it is fixed or the secret is revoked, and never use a
credential we find. See [docs/FIELD_REPORT.md](docs/FIELD_REPORT.md).
