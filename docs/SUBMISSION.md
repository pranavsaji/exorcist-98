# Devpost submission draft

Fields marked **[you]** need something only you can provide. Every number
that can change comes from `docs/facts.json` (written by `scripts/facts.mjs`
from the repository and the last test run); a test fails if this file disagrees
with it. Run `node scripts/facts.mjs --docs` to refresh the marked numbers.

- **Project name:** Exorcist 98
- **Tagline:** The 90s desktop antivirus, resurrected to protect AI coding agents.
- **Category:** Resurrection
- **Bonus prizes:** Best Kiro Crew App, Best Demo (automatic), Bonus Blog and Social Blitz if posted. **[you]** Best Startup Project only if you are the founder of a real startup and can give your LinkedIn and startup website; otherwise leave it out (the rules require both).
- **Web app (no login):** https://exorcist-98.vercel.app
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
- **Virus Definitions:** <!--f:definitions-->25<!--/f--> open YAML signatures for hidden Unicode,
  instructions aimed at the AI, encoded payloads, HTML comment smuggling, tool
  description poisoning, rug pulls, over-broad auto-approve, remote code in
  hooks, install-script exfiltration, unpinned MCP servers, secrets within the
  agent's reach, markdown image exfiltration, steering overrides, typosquatted
  MCP packages, confused-deputy requests, agent memory poisoning, suspicious
  Powers, shell in tool output, smuggled bytes, canary tokens, the lethal
  trifecta and a program-loader environment, across the files Kiro, Cursor, Cline, Windsurf, Copilot, Claude
  Code and Gemini read. Each
  maps to the OWASP LLM, Agentic or MCP Top 10. A Threat Encyclopedia explains
  each one in plain language.
- **Measured precision:** on five well-known public agent and MCP repos it
  raises 2 alarms in total (down from 4,457 before tuning); on five more repos never used for tuning (held-out set C, about 9,500 files) it raised 1, and that one is correct, and it catches <!--f:benchmarkAttacksCaught-->21<!--/f-->
  of <!--f:benchmarkAttacks-->21<!--/f--> attacks in a labelled corpus that runs with the tests
  (`docs/BENCHMARK.md`).
- **Private code too:** upload a .zip (up to 4 MB) instead of a GitHub link;
  it is unpacked only for the scan and deleted straight after. Branch, tag and
  commit links work as well.
- **Protect a repo in one step:** a GitHub Action that scans every pull
  request and comments on new threats; the web app shows the workflow file to
  copy after each scan.
- **Possession Lab** (in the web app): seven attacks (rug pull, poisoned tool,
  secret leak, unknown host, poisoned tool result, canary, lethal trifecta), each replayed twice from
  the same script, once through the real Shield engine and once with nothing
  in between, side by side and step by step. It is the Shield code itself
  running in the browser's backend, not an animation.
- **Real-Time Shield:** an MCP firewall that sits between the agent and each
  MCP server. It pins every tool's fingerprint; if a tool changes, it is hidden
  from the agent and calls to it are refused, with a diff of what changed. It
  also blocks secrets and unknown hosts in tool calls and withholds tool
  results that look like attacks.
- **Session Guard (EX-027):** the Shield remembers what a session has
  actually read. Once it has taken in untrusted text (an issue, a web page)
  and private data (`.env`, a secret), the next call that could send data out
  is held until the person approves it, even when each step went through a
  different MCP server. Only the person can release it. On macOS that is the
  system prompt (Touch ID or the login password), which only the Shield process
  can answer; on Linux and Windows the fallback is a typed code in a real
  terminal, which is weaker (`docs/KNOWN_LIMITATIONS.md`, S-030). Possession
  Lab: `/?demo=trifecta`. `exorcist console` shows held and blocked calls live.
- **Quarantine Vault:** disable a suspicious MCP server with a backup and
  restore it byte for byte.
- **Kiro Power, MCP server, CLI and GitHub Action** to use all of this from
  Kiro, the terminal and CI.
- **Editor extension "Exorcist 98 for Kiro"** (`packages/vscode`): poisoned
  lines in steering, spec, hook and MCP files and `AGENTS.md` are underlined as
  you type, hidden messages are decoded on hover, and a one-click *Exorcise*
  fix removes hidden characters. Read-only, no network, works in Restricted
  Mode. Seen running inside Kiro 1.5.11, where Kiro offers its own *Ask Kiro to
  Fix* on our findings (screenshots in the README).
  On Open VSX: `kiro --install-extension exorcist-98.exorcist-98-kiro`.
- **Ten more 90s antivirus ideas, brought back:** On-Access Scanning (a Kiro
  hook scans a file before the agent reads it; only the user can allow it, at a
  real terminal), the Ouija Decoder (reads invisible Unicode smuggling back
  into plain text), Canary Traps (bait tokens; the Shield blocks any tool call
  carrying one, in every mode), Bring Your Own Attack (paste any text for the
  real scanner's and Shield's verdict), the Haunted House Map (the "lethal
  trifecta" across a config's MCP servers, EX-023), Disinfect (a one-click
  patch for mechanical fixes, with exact vault backups), `exorcist.lock` (team
  MCP fingerprints; CI never starts a pull request's servers), Possession
  Origin (the commit that introduced each threat, never running a repo's own
  git filters), signed LiveUpdate definitions, and the Detonation Chamber (a
  sandboxed model with fake tools shows whether text *tries* to do harm).
- **Field Report:** the scanner on <!--f:fieldReport.repos-->483<!--/f--> real public MCP servers and
  agent-config repos in <!--f:fieldReport.rounds-->3<!--/f--> rounds, every serious alert read by hand.
  Round 1 exposed too many false alarms; the fixes cut serious alerts from 4.0
  to 0.24 per repository on a fresh set in round 2. Round 3 (popular repos,
  not held out) found no real issue (docs/FIELD_REPORT.md).
- **Crew app:** a nightly patrol of your folders with a dashboard page, an MCP rug-pull watch, and a confirm-first quarantine that only the dashboard owner can use.

## Best Kiro Crew App: writeup (paste into the bonus field)

**Repository:** https://github.com/pranavsaji/exorcist-98-crew (public, Apache-2.0, first commit 2026-11-14, created on GitHub 2026-11-15; both inside the Submission Period of 2026-10-30 to 2026-12-04).

Exorcist 98 for Kiro Crew patrols your project folders every night for text
that tries to take over an AI agent, and shows the results on a Crew dashboard
page.

- **Nightly patrol.** At 02:00 the app's backend scans every watched folder with
  the Exorcist 98 scanner (hidden Unicode, instructions aimed at the AI,
  poisoned MCP tool descriptions, risky agent and MCP settings) and sends a Crew
  notification for new serious findings or a failed scan.
- **Dashboard page.** Each folder's infection level as a text label plus a
  shape, never colour alone; every finding with file, line, the quoted text
  (shown as text, never as HTML) and how to fix it.
- **MCP rug-pull watch.** Reads the Exorcist 98 Shield's pin file in each folder
  and reports every MCP tool whose description changed after you approved it.
- **Quarantine, confirm first.** "Move file to vault..." moves a flagged file
  into a vault with an exact copy; "Restore..." puts back the same bytes. Only
  the signed-in dashboard owner can do it: the app asks Crew to sign who sent
  each request, and agents, schedules, MCP tools and other apps are refused.
- **Exorcist Sentry agent** with a read-only `patrol_status` MCP tool, so you
  can ask about the patrol in chat. It never sees the scanned text, so a
  poisoned file cannot steer it, and it never moves or deletes anything.
- **Agent-hygiene skill:** safe habits for any Crew agent that reads repos or
  uses MCP servers.

Tested inside Crew 0.12.2 and 0.13.0 (install, enable, page, patrol,
notification, agent chat, cron, quarantine and restore), plus 143 unit and
property tests and a 20-step Chrome run with 0 axe violations. Every place
where Crew behaved differently from its docs is listed in
`docs/KNOWN_LIMITATIONS.md` of that repo.

## How we built it (Kiro)

| Kiro feature | What we did | Evidence |
|---|---|---|
| Specs | The repository has <!--f:specs-->17<!--/f--> specs in `.kiro/specs/`. Kiro IDE wrote and implemented seven: `m0-foundation`, `m1-engine`, `m2-ui`, `m3-shield`, `m4-polish`, `m6-os-release` and `m7-precision`, each with requirements, design and tasks. The ten `m5-*` specs are in Kiro's spec format but Kiro did not write them; Kiro CLI implemented parts of six of those features. One more spec is in the Crew repo (`crew-app`). | `.kiro/specs/`, KIRO_LOG |
| Steering | Four files written with Kiro IDE before any code (product, tech, security, ui) set the rules for every change: strict TypeScript, zod at every boundary, defanged fixtures, untrusted text never concatenated into instructions, severity never by colour alone. The repository now has <!--f:steering-->10<!--/f--> steering files; the six added later with the M5 work are not credited to Kiro IDE in `docs/KIRO_LOG.md`. | `.kiro/steering/` |
| Property-based tests | The repository has <!--f:propertyTests-->139<!--/f--> fast-check properties (not all written by Kiro), for example "a secret at any depth is never forwarded", "a changed tool is never listed or callable", "a zero-width character is detected at any position", "no tar entry name writes outside the target folder". Plus more in the Crew repo. | `docs/KIRO_LOG.md` |
| Hooks | <!--f:hooks-->5<!--/f--> hooks in the main repo and 1 in the Crew repo, in Kiro's JSON format. All five were seen working in Kiro IDE. `on-access-scan` (scan a file before the agent reads it) was seen on 2026-11-24 blocking Kiro's own first read of a brief that quoted an injection phrase (EX-002, line 50); the owner reworded the line and the second read went through. The others: `spec-change` (on every spec save; kept `docs/THREATS.md` in step), `pre-commit-secrets` (PreToolUse; stopped a `git commit` of a staged fake key before it ran), `mcp-config-change` (scanned a saved MCP config), `definition-save` (ran the core tests), and the Crew repo's `validate-app-json`. The command hooks first did nothing: Kiro runs hook commands with a PATH that has no Node, so they now go through `scripts/kiro-hook.sh`. | `.kiro/hooks/`, KIRO_LOG |
| MCP | Built the `exorcist` MCP server on the official SDK (4 tools), tested with the SDK client. | `packages/mcp-server/` |
| Powers | Built the `exorcist` Power (MCP config plus 3 skills). It was installed through Kiro's Powers panel on 2026-11-24 (Kiro 1.5.11) from the repository URL, and its MCP server connected with 4 tools. That first use found a bug (the server scanned its own install folder and reported no threats), which the Kiro IDE agent fixed in 0.1.3. | `power/`, KIRO_LOG |
| Measurement | We ran our own scanner on five real repos and found it raised 4,457 alarms, none real. Kiro then worked through a precision spec: rule-level controls in the YAML format, a labelled attack corpus, and a re-run: 2 alarms; the labelled corpus has since grown to <!--f:benchmarkAttacks-->21<!--/f--> attacks, all caught. The same run found a CLI bug that cut reports at 64 KB. | `docs/BENCHMARK.md`, `fixtures/benchmark/` |
| Kiro CLI | Ran **Kiro CLI 3.5.0 headless** on six M5 specs in parallel (one git worktree each), resuming each conversation until Kiro reported done. Kiro hit the account's monthly usage limit part-way: its partial work for each feature is committed separately (`git log --grep "partial implementation by Kiro"`). We also learned that Kiro Crew's `run` task runner can report success from an empty sandbox, so we check the working tree, not the summary. | `docs/KIRO_LOG.md` |
| Crew | A separate Crew app repo: Sentry agent, agent-hygiene skill, a nightly patrol that sends Crew notifications, a backend and a dashboard page. Run inside Crew 0.12.2 and 0.13.0, including the Sentry agent reading results through its own read-only MCP tool; installing and running it found places where Crew behaves differently from its docs (each recorded in that repo's `docs/KNOWN_LIMITATIONS.md`) and fixed. | `pranavsaji/exorcist-98-crew` |

Stack: TypeScript (strict) in a pnpm monorepo; Next.js for the web app;
Vitest and fast-check; playwright-core and axe-core for a real-browser,
accessibility-checked test that runs in CI; esbuild for the CLI and MCP server
bundles; an optional AI judge on Amazon Bedrock (Claude Haiku for triage, Sonnet as the
judge), run against the real service.

## How it compares to existing MCP scanners

Open-source tools such as Invariant Labs' mcp-scan, mcp-security-guard,
mcp-audit-scanner and trustmcp already detect tool poisoning, and several pin
tool descriptions by hash to catch rug pulls. Exorcist 98 adds: a check of
every tool against its pin before every call (needed because Kiro caches the
tool list, which we found by running the Shield inside Kiro); scanning of the
whole repository across the files seven coding agents read, not just MCP
config; a measured false-positive rate on repos it was never tuned on; Kiro
hooks, a Power, an MCP server and a Crew app; and an exact-restore quarantine.

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
- <!--f:tests-->2,042<!--/f--> tests in <!--f:testFiles-->137<!--/f--> files in the main repo (unit, <!--f:propertyTests-->139<!--/f--> property-based with fast-check, and
  real processes), 143 in the Crew repo; a <!--f:browserSteps-->44<!--/f-->-step Chrome run with <!--f:browserAxeViolationTypes-->0<!--/f--> axe
  violations on every window that plays all seven Possession Lab attacks.

## How the Kiro tools differed

- **Kiro IDE** carried the spec-driven work: one spec per milestone
  (requirements, design, tasks), steering that every change had to follow,
  and hooks on file save. `spec-change` fired on every spec save.
- **Kiro Crew** was a different kind of target: a running agent platform we
  built an app for, then installed and ran. Doing that found places where
  Crew behaved differently from its docs. Examples: the proxy header is
  `X-KiroCrew-Proxy`, crons need `permissions.cron`, and the page must be a
  React default export. Each is fixed and recorded.
- **Custom agents:** the Crew app's Exorcist Sentry agent, with one read-only
  MCP tool, so it can report patrol results but never sees scanned text and
  never moves files.

## Spec-driven versus vibe coding

Specs made a security tool falsifiable: every requirement got a test, and
property-based tests found real defects that example tests missed (KIRO_LOG,
"What worked well"). Where we skipped measuring, we were wrong. Rule tuning
looked fine on the planted fixtures and failed badly on real repos, until a
spec-style task forced a benchmark.

## What we learned

Ship-ready security tools need the boring evidence: every claim checked by
running it, and every gap written down (`docs/KNOWN_LIMITATIONS.md`).

## What's next

- Re-run the Shield's check-before-every-call fix inside Kiro (tested with real
  processes and the MCP SDK; the first Kiro run is what found the gap) and run
  the Shield console during a real Kiro session.
- Make the AI judge cheaper to leave on: it already runs on Amazon Bedrock and
  catches reworded attacks that patterns miss (on real Bedrock it hid a French
  exfiltration instruction no signature caught), but it costs money per call.
- A bigger benchmark corpus and more well-known MCP packages for the
  typosquat check.
- Release in the system prompt on Linux and Windows. Today it is macOS only
  (Touch ID or login password); elsewhere a held session falls back to a typed
  code in a terminal (`docs/KNOWN_LIMITATIONS.md`, S-030).
- A fleet view and a central audit log for teams (each machine keeps its own
  `events.jsonl` today).

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
