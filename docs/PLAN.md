# Exorcist 98: Build Plan

> The 90s desktop antivirus, resurrected to protect AI coding agents.
> Kiroween 2026 entry. Category: **Resurrection**. Bonus targets: **Best Startup Project**, **Best Kiro Crew App** (see `pranavsaji/exorcist-98-crew`).

Deadline: **Dec 4, 2026, 2:00 pm Pacific**. Kiro credits request deadline: Dec 1, 12:00 pm Pacific.

---

## 1. The pitch

Remember when your PC got viruses from floppy disks? Your AI agent now gets them from READMEs, MCP servers and pull requests.

Coding agents read and act on text that anyone can write: a README, a steering file, an MCP tool description, a code comment. Attackers hide instructions in those places (prompt injection), poison MCP tool descriptions, or ship hooks that run remote code. Exorcist 98 brings back the classic antivirus model, virus definitions, full system scan, quarantine and real-time shield, and points it at the files and tools an AI agent trusts.

## 2. Judging criteria (each 20%) and how we hit them

| Criterion | How Exorcist 98 scores |
| --- | --- |
| Potential Impact | Every team using coding agents has this attack surface today; free scanner for open source, paid shield for teams |
| Technological Implementation | Two-layer detection engine, MCP firewall proxy, property-based tests, Kiro Power, Kiro Crew app, CLI in CI |
| Design | Original haunted retro desktop UI where the antivirus metaphor does real work |
| Innovation / Idea | First antivirus-style product for agent supply chains; rug-pull detection for MCP tools |
| Presentation | 3-minute video with a live save: an agent tries to leak `.env`, Exorcist blocks it |

## 3. Scope

### 3.1 The four parts (golden path)

1. **Full System Scan** (web app; the judges' URL)
   - Input: public GitHub repo URL, or a folder upload (zip).
   - Scans every file an agent would read or execute:
     - Agent instructions: `.kiro/steering/**`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, `.github/copilot-instructions.md`, `SKILL.md`, `README*`.
     - Agent config: MCP configs (`.kiro/settings/mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`), Kiro hooks, Powers, auto-approve and trust settings.
     - Supply chain: `package.json` scripts (`preinstall`, `postinstall`), MCP server packages and pinned versions.
   - Output: findings with file, line, quoted span, severity, threat class, fix.
2. **Virus Definitions** (the engine, `packages/core`)
   - Layer 1, signatures: YAML rules with regex, Unicode classes and structural checks.
   - Layer 2, heuristics: an LLM judge on Amazon Bedrock that returns a strict JSON verdict and must quote the exact span it flags.
   - Every finding maps to OWASP Top 10 for LLM Applications, OWASP Top 10 for Agentic Applications (ASI01 to ASI10) or the OWASP MCP Top 10.
3. **Real-Time Shield** (MCP firewall, `packages/shield`)
   - A local MCP proxy between Kiro and your MCP servers.
   - Pins a hash of each tool's name, description and input schema on first approval; alerts if it changes later (rug pull).
   - Inspects tool calls and tool results; blocks secrets leaving, calls to unknown hosts, and injected instructions inside tool output.
   - Asks the user in plain words before a risky call goes through.
4. **Quarantine Vault**
   - One click disables an infected MCP server, hook or steering file; keeps a backup and a diff; restores on demand.

### 3.2 Product features (after the golden path works)

- **Threat Encyclopedia**: one page per signature with the attack, a defanged example and the fix.
- **SARIF export** for GitHub code scanning, plus an "Exorcised" README badge.
- **Haunted Repo** fixtures (`fixtures/haunted-repo/`): 20 defanged, planted attacks so judges see detections instantly.
- **Community definitions**: signatures live in `definitions/` with a contribution guide.
- **Kiro Power `exorcist`**: installs the MCP server, steering and hooks into any Kiro project.
- **CLI**: `npx exorcist scan .` for CI (GitHub Actions), with a PR comment.

### 3.3 Out of scope for Dec 4

- Real malware samples (never; all fixtures are defanged).
- Private repo scanning with OAuth.
- Paid tier billing.

## 4. Threat catalogue (first 20 signatures)

| ID | Name | Where | Detection | Severity |
| --- | --- | --- | --- | --- |
| EX-001 | Hidden Unicode instructions | Any text | Zero-width, bidi override, tag characters (U+E0000 block) | Critical |
| EX-002 | Instructions addressed to AI | Docs, comments | Imperative phrases aimed at agents ("ignore previous", "you are now", "as an AI") | High |
| EX-003 | Encoded payload | Any text | Base64 or hex blobs that decode to instructions or URLs | High |
| EX-004 | HTML comment smuggling | Markdown | Instructions inside `<!-- -->` | High |
| EX-005 | Tool description poisoning | MCP tool metadata | Instructions in tool descriptions or parameter docs | Critical |
| EX-006 | MCP rug pull | Shield | Tool hash changed since approval | Critical |
| EX-007 | Over-broad auto-approve | MCP config | `autoApprove` on write or shell tools | High |
| EX-008 | Remote code in hook | Kiro hooks | Hook command fetches and runs remote code (`curl | sh`) | Critical |
| EX-009 | Install-script exfiltration | `package.json` | `postinstall` reads env or files and calls the network | Critical |
| EX-010 | Unpinned MCP server | MCP config | `npx some-server` without a version | Medium |
| EX-011 | Secrets in agent reach | Repo | `.env`, keys, tokens not in `.kiroignore` | High |
| EX-012 | Markdown image exfiltration | Docs | Image URLs with query strings built from data | High |
| EX-013 | Typosquat MCP package | MCP config | Name close to a known server | Medium |
| EX-014 | Steering override | `.kiro/steering` | Steering that disables safety or approvals | High |
| EX-015 | Shell in tool output | Shield | Tool result contains commands for the agent to run | High |
| EX-016 | Data to unknown host | Shield | Outbound URL not on the allowlist | High |
| EX-017 | Credential in tool call args | Shield | Secret patterns in arguments | Critical |
| EX-018 | Confused-deputy prompt | Docs | Requests to act with elevated permissions | Medium |
| EX-019 | Agent memory poisoning | Memory files | Instructions planted in agent memory or notes | High |
| EX-020 | Suspicious Power | Powers | Power bundles a hook or server with any Critical finding | High |

## 5. Architecture

```
                 +--------------------+
  GitHub URL --> |  Web app (Next.js) | <-- judges
  or zip upload  |  retro desktop UI  |
                 +---------+----------+
                           |
                    API (AWS Lambda)
                           |
          +----------------+----------------+
          |                                 |
  packages/core (scan engine)        Amazon Bedrock
  - file walker + classifiers        (LLM heuristic layer,
  - signature engine (YAML)           strict JSON verdicts)
  - heuristic orchestrator
  - SARIF / JSON reporters
          |
  definitions/*.yaml  (virus definitions)

  Local, on the developer machine:
  Kiro  <-->  packages/shield (MCP proxy)  <-->  real MCP servers
                 |  hash pins, policies, quarantine vault
  packages/mcp-server  (scan_repo, scan_mcp_config, explain_finding, quarantine)
  packages/cli         (npx exorcist scan)
  power/               (Kiro Power bundle)
```

### Tech stack

- TypeScript everywhere, Node 20+, pnpm workspaces.
- Web: Next.js (App Router), Tailwind, custom retro components (no third-party brand assets).
- API: AWS Lambda (or Amplify Hosting functions), S3 for uploaded zips with a 24-hour lifecycle.
- AI: Amazon Bedrock (Claude Haiku for triage, Sonnet for the judge).
- Tests: Vitest + fast-check (property-based tests).
- Hosting: AWS Amplify or Vercel for the web app.

### Repo layout

```
exorcist-98/
  .kiro/
    steering/        product.md, tech.md, security.md, ui.md
    specs/           one folder per spec (created with Kiro)
    hooks/           hook definitions (created with Kiro)
    settings/mcp.json
  apps/web/          Next.js retro UI + API routes
  packages/core/     scan engine
  packages/shield/   MCP firewall proxy
  packages/mcp-server/
  packages/cli/
  definitions/       YAML virus definitions
  fixtures/haunted-repo/  defanged attack samples
  power/             Kiro Power bundle
  docs/              PLAN.md, THREATS.md, KIRO_LOG.md
```

## 6. Detection engine design

1. **Walk**: list files, classify by role (instruction, config, code, docs, manifest). Skip binaries and files over 1 MB.
2. **Normalize**: decode HTML entities, reveal hidden Unicode, extract HTML comments, decode base64 candidates.
3. **Signatures**: run YAML rules; each rule has `id`, `title`, `severity`, `applies_to`, `match` (regex, unicode_class, json_path), `owasp`, `fix`.
4. **Heuristics**: send only suspicious spans plus 3 lines of context to Bedrock with random-nonce delimiters; the model returns `{verdict: malicious|suspicious|benign, threat_class, quoted_span, rationale}`. Drop any verdict whose `quoted_span` is not in the file.
5. **Score**: severity x confidence; dedupe by file and span.
6. **Report**: JSON for the UI, SARIF for GitHub, Markdown for PR comments.

### Defending the scanner itself

The scanner reads attacker-written text, so:
- The LLM never decides control flow; it only labels spans.
- Untrusted text is always wrapped in nonce delimiters and never concatenated into instructions.
- A scan of `fixtures/haunted-repo/` must never change the scanner's own config or output format (tested).

## 7. Kiro usage plan (log everything in `docs/KIRO_LOG.md`)

| Kiro feature | How we use it | Evidence |
| --- | --- | --- |
| Specs | One spec per part: scanner, signatures, heuristics, shield, quarantine, web UI, CLI, Power | `.kiro/specs/*` |
| Property-based testing | e.g. "for any input containing a secret pattern, the shield never forwards it"; "scanning is idempotent"; "a zero-width payload is detected at any position" | fast-check tests mapped to requirements |
| Steering | product, tech, security, ui (already in `.kiro/steering/`) | files |
| Hooks | on save of `definitions/*.yaml` run signature tests; on change to MCP config run a scan; on spec change update THREATS.md; pre-commit secrets check | `.kiro/hooks/*` + a clip of one firing |
| MCP | our own `exorcist` MCP server used during development; Context7 for docs; GitHub MCP | `.kiro/settings/mcp.json` |
| Custom agents | "Red Teamer" writes new defanged samples; "Rule Smith" turns a sample into a signature plus tests | agent configs |
| Powers | ship Exorcist as a Kiro Power | `power/` |
| CLI | headless Kiro CLI in GitHub Actions on every PR | workflow file |
| Web | Kiro Web for a multi-repo change across this repo and the Crew repo | PR links |
| Crew | the separate Crew app repo | `pranavsaji/exorcist-98-crew` |

## 8. Milestones (today is Nov 15)

### M0 Setup (Nov 15 to 18, light days)
- [ ] Request 4,000 Kiro credits (done Nov 14) and redeem the code when it arrives
- [ ] Open this repo in Kiro so it creates `.kiro/`; keep the steering files here
- [ ] Generate specs 1 to 3 with Kiro: scanner, signatures, web UI
- [ ] Write 20 Haunted Repo fixtures (defanged) = the test set

### M1 Engine (Nov 19 to 24)
- [ ] File walker, classifiers, normalizer
- [ ] Signature engine + first 12 signatures + property tests
- [ ] Bedrock heuristic layer with strict JSON and span verification
- [ ] Lambda API: GitHub URL to findings

### M2 UI (Nov 22 to 26)
- [ ] Retro desktop shell, scan window with live log, results list, finding detail
- [ ] Threat Encyclopedia pages from `definitions/`

### M3 Shield and Kiro extensions (Nov 25 to 29)
- [ ] MCP proxy with hash pinning, call and result inspection, user prompt
- [ ] Quarantine Vault (backup, diff, restore)
- [ ] `exorcist` MCP server and Kiro Power
- [ ] CLI + GitHub Action

### M4 Polish and bonuses (Nov 30 to Dec 2)
- [ ] Accessibility pass, sound toggle (muted by default), empty states
- [ ] SARIF export and badge
- [ ] Crew app finished in its own repo
- [ ] Startup landing page (needed for Best Startup Project)

### M5 Story and submit (Dec 3 to 4)
- [ ] Video under 3 minutes, public on YouTube, original audio, no brand logos
- [ ] Devpost write-up with Kiro feature counts from KIRO_LOG.md
- [ ] Blog post and `#KiroweenHackathon26` social post
- [ ] Submit by Dec 3 evening

**Cut lines if late:** drop Kiro Web usage, SARIF, then the Threat Encyclopedia. Never cut the golden path.

## 9. Video script (under 3:00)

| Time | Beat |
| --- | --- |
| 0:00 | An agent reads a harmless-looking README and quietly tries to send `.env` to a stranger |
| 0:20 | Exorcist 98 boots: "Your agent has a virus" |
| 0:35 | Full System Scan of the Haunted Repo; the hidden line is highlighted and explained |
| 1:20 | In Kiro, an MCP tool description changes after approval; the shield blocks it and quarantines the server |
| 2:00 | Built with Kiro: specs, property tests, hooks firing, Power install, Crew dashboard |
| 2:40 | Who it protects, open definitions, install link |

## 10. Submission checklist

- [ ] Working web app URL, no login needed
- [ ] Public repo, Apache-2.0 visible in About, `.kiro/` committed at the root (not gitignored)
- [ ] Crew app repo linked
- [ ] Category: Resurrection; bonuses: Best Startup Project (founder, LinkedIn, website), Best Kiro Crew App
- [ ] Kiro write-up covering every feature in section 7
- [ ] Disclose any earlier open source code reused
- [ ] Blog and social links
- [ ] All fixtures defanged
