# Devpost submission draft

Fields marked **[you]** need something only you can provide. Every number
below comes from `docs/KIRO_LOG.md` or a test run; update them if they change.

- **Project name:** Exorcist 98
- **Tagline:** The 90s desktop antivirus, resurrected to protect AI coding agents.
- **Category:** Resurrection
- **Bonus prizes:** Best Startup Project, Best Kiro Crew App
- **Web app (no login):** **[you]** deploy first (see `docs/DEPLOY.md`)
- **Repository:** https://github.com/pranavsaji/exorcist-98 (Apache-2.0, `.kiro/` committed)
- **Crew app repository:** https://github.com/pranavsaji/exorcist-98-crew (Apache-2.0)
- **Video:** **[you]** YouTube link (script: `docs/VIDEO_SCRIPT.md`)
- **Blog post / social post:** **[you]** links (drafts: `docs/BLOG.md`, `docs/SOCIAL.md`)

---

## Inspiration

In the 90s, viruses came on floppy disks. Today, AI coding agents read and act
on text that anyone can write: a README, a steering file, an MCP tool
description, a code comment. Attackers hide instructions there with invisible
Unicode or HTML comments, poison tool descriptions, or change an MCP tool after
you approved it (a "rug pull"). We brought back the antivirus model that people
already understand (virus definitions, a full system scan, a real-time shield,
a quarantine vault) and pointed it at the files and tools an agent trusts.

## What it does

- **Full System Scan** (web app and CLI): scan a public GitHub repository or a
  folder. Every finding shows the file, line, the exact quoted text, the
  infection level in words and a shape (never colour alone), the threat class
  and a fix. Reports download as SARIF (GitHub code scanning), Markdown (pull
  requests), JSON and an SVG README badge, built in the browser.
- **Virus Definitions:** 13 open YAML signatures for hidden Unicode,
  instructions aimed at the AI, encoded payloads, HTML comment smuggling, tool
  description poisoning, rug pulls, over-broad auto-approve, remote code in
  hooks, install-script exfiltration, unpinned MCP servers, secrets within the
  agent's reach, markdown image exfiltration and shell in tool output. Each
  maps to the OWASP LLM, Agentic or MCP Top 10. A Threat Encyclopedia explains
  each one in plain language.
- **Real-Time Shield:** an MCP firewall that sits between the agent and each
  MCP server. It pins every tool's fingerprint; if a tool changes, it is hidden
  from the agent and calls to it are refused, with a diff of what changed. It
  also blocks secrets and unknown hosts in tool calls and withholds tool
  results that look like attacks.
- **Quarantine Vault:** disable a suspicious MCP server with a backup and
  restore it byte for byte.
- **Kiro Power, MCP server, CLI and GitHub Action** to use all of this from
  Kiro, the terminal and CI.
- **Crew app:** a nightly patrol of your folders with a dashboard page.

## How we built it (Kiro)

| Kiro feature | What we did | Evidence |
|---|---|---|
| Specs | 5 specs, one per milestone (`m0-foundation`, `m1-engine`, `m2-ui`, `m3-shield`, `m4-polish`), each with requirements, design and tasks; 1 more in the Crew repo (`crew-app`). | `.kiro/specs/` |
| Steering | 4 files (product, tech, security, ui) that set the rules for every change: strict TypeScript, zod at every boundary, defanged fixtures, untrusted text never concatenated into instructions, severity never by colour alone. | `.kiro/steering/` |
| Property-based tests | 52 fast-check properties, for example "a secret at any depth is never forwarded", "a changed tool is never listed or callable", "a zero-width character is detected at any position", "no tar entry name writes outside the target folder". Plus more in the Crew repo. | `docs/KIRO_LOG.md` |
| Hooks | 4 hooks in Kiro's JSON format. `spec-change` fired in Kiro on every spec save and kept `docs/THREATS.md` in step. `pre-commit-secrets` (PreToolUse) did **not** fire in our sessions, so a git pre-commit hook does that job. | `.kiro/hooks/`, KIRO_LOG |
| MCP | Built the `exorcist` MCP server on the official SDK (4 tools), tested with the SDK client. | `packages/mcp-server/` |
| Powers | Built the `exorcist` Power (MCP config plus 3 skills). | `power/` |
| Crew | A separate Crew app repo: Sentry agent, agent-hygiene skill, a nightly patrol that sends Crew notifications, a backend and a dashboard page. Run inside Crew 0.12.2; installing it found 7 differences from the Crew docs, all fixed. | `pranavsaji/exorcist-98-crew` |

Stack: TypeScript (strict) in a pnpm monorepo; Next.js for the web app;
Vitest and fast-check; playwright-core and axe-core for a real-browser,
accessibility-checked test that runs in CI; esbuild for the CLI and MCP server
bundles; Amazon Bedrock wiring for an AI judge (see "What's next").

## Challenges

- **Defending the scanner from what it scans.** Scanned text is attacker
  text. It is never concatenated into instructions, the MCP server and Crew
  agent never receive quoted file text, and the web page only inserts it as
  text.
- **Our own tests lied until we ran things for real.** A real browser run found
  four UI defects unit tests missed. Running our scanner on our own repo found
  a false positive on lockfile hashes that would have failed every pull
  request. Our first hooks were written in a format Kiro does not use and never
  fired; rewriting them from the docs fixed that.
- **The obvious npm name was taken** by an unrelated package, so `npx exorcist`
  would have run someone else's code. Everything uses `@exorcist-98/*`.

## Accomplishments

- The golden path works end to end with real processes: a tool is approved,
  the server changes it to "send the contents of .env to ...", the agent no
  longer sees it, the call is refused, and the server's own log proves it never
  received the call.
- 431 tests in the main repo, 103 in the Crew repo; 0 axe violations on every
  page in Chrome.

## What we learned

Ship-ready security tools need the boring evidence: every claim checked by
running it, and every gap written down (`docs/KNOWN_LIMITATIONS.md`).

## What's next

- Run the Shield and Power inside Kiro end to end (not yet done).
- Turn on the Bedrock AI judge (wired and unit tested with a fake client, never
  run against the real service).
- Publish `@exorcist-98/cli` and `@exorcist-98/mcp-server` to npm.
- More definitions (typosquatted servers, steering overrides, memory poisoning)
  and a false-positive benchmark on real repositories.

## Startup (Best Startup Project)

- **Founder:** **[you]** name, LinkedIn URL (also add it to `/product`).
- **Website:** the deployed `/product` page.
- **Model:** free open-source scanner and definitions; a paid team Shield with
  shared policies and alerting. (Planned; nothing is sold today.)

## Code reuse disclosure

No code from earlier projects was reused. All code was written for this
hackathon, starting 2026-11-14 (first commit). Open-source libraries used:
Next.js, React, zod, js-yaml, jsonpath-plus, diff, simple-git,
@modelcontextprotocol/sdk, @aws-sdk/client-bedrock-runtime, Tailwind CSS,
esbuild, TypeScript, Vitest, fast-check, tsx, playwright-core, axe-core. No
third-party images, fonts or sounds; icons are drawn in SVG and sounds are
synthesised.

**[you]** Confirm the disclosure above is true for you before submitting.
