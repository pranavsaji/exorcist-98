# Exorcist 98

**The 90s antivirus, resurrected for AI coding agents.**

**Try it now, no install:** https://exorcist-98.vercel.app (paste any public GitHub repo or branch link, upload a .zip of a private project, or scan the Haunted Repo)

Your AI coding agent obeys what it reads: READMEs, steering and rules files, MCP tool descriptions, hooks. Anyone can write those. Exorcist 98 scans them for hidden instructions, poisoned or changed MCP tools and dangerous hooks, and runs a real-time shield between Kiro and its MCP servers.

**Who it is for:** developers and teams who let Kiro, Cursor, Claude Code, Copilot or Cline work in repositories and with MCP servers they did not write.

![The Exorcist 98 desktop after scanning the Haunted Repo, with a finding open](docs/media/web-finding.png)

Built with [Kiro](https://kiro.dev) for **Kiroween 2026** (category: Resurrection). Companion Kiro Crew app: [pranavsaji/exorcist-98-crew](https://github.com/pranavsaji/exorcist-98-crew).

## Why trust the findings

A scanner that cries wolf gets switched off. We measured it ([`docs/BENCHMARK.md`](docs/BENCHMARK.md)):

- **5 well-known public repos** (modelcontextprotocol/servers, github/github-mcp-server, openai/codex, anthropics/claude-code-action, cline/cline): **2 findings in total**, down from 4,457 before we tuned the rules. One of the two is a real hidden instruction to Copilot in an HTML comment.
- **A labelled attack corpus** (`fixtures/benchmark/`): 19 of 19 defanged attacks caught (including Rules File Backdoor tricks in `.cursor/rules`, typosquatted MCP packages, memory poisoning and hex payloads), and 15 of 15 look-alike ordinary files left alone. It runs on every test run.

## Protect a repo in one step

Add `.github/workflows/exorcist.yml`; every pull request is scanned and gets a comment, and the check fails on high or critical threats:

```yaml
name: Exorcist 98
on: [pull_request]
permissions:
  contents: read
  pull-requests: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pranavsaji/exorcist-98@main
        with:
          fail-on: high
```

## The four parts

| Part                  | What it does                                                                                                                                                          | Where                                        |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| **Full System Scan**  | Paste a GitHub URL, or scan a folder. Findings show the file, line, quoted span, severity and fix.                                                                    | `apps/web`, `packages/cli` (`exorcist scan`) |
| **Virus Definitions** | 18 YAML signatures with per-rule precision controls, plus an optional AI judge on Amazon Bedrock (built, not yet run against the service).                          | `definitions/`, `packages/core`              |
| **Real-Time Shield**  | An MCP firewall: pins each tool's hash, hides a tool that changes after approval, blocks secrets and unknown hosts in tool calls, withholds attack-like tool results. | `packages/shield` (`exorcist shield`)        |
| **Quarantine Vault**  | Disable an infected MCP server, hook or steering file, with a backup, a diff and an exact restore.                                                                    | `packages/shield`, `exorcist vault`          |

## Try it

Needs Node 20+ and pnpm.

```sh
pnpm install

# Scan the Haunted Repo (defanged planted attacks)
pnpm --filter @exorcist-98/cli build
node packages/cli/dist/index.mjs scan fixtures/haunted-repo

# Watch the Shield stop a rug pull (20 seconds, no Kiro needed)
node scripts/demo-rug-pull.mjs

# The web app
pnpm --filter @exorcist-98/web build
pnpm --filter @exorcist-98/web exec next start

# Everything
pnpm test        # unit, property-based and real-process tests
pnpm e2e         # drives Chrome against a running web app (see scripts/e2e-chrome.mjs)
```


## Honest status

Built and tested: the scan engine and virus definitions, the web app (live, with sound, report downloads, a README badge and a `/product` page), the Real-Time Shield, the Quarantine Vault, the CLI, an MCP server, a Kiro Power, a GitHub Action and a Kiro Crew app (run inside Crew 0.12.2 and 0.13.0).

**Read [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) before trusting any claim here.** The main open gaps: the Shield, the Power and the MCP server have not been run inside Kiro itself (only through their own tests and a terminal demo), nothing is published to npm, and the AI (Bedrock) layer has never run against the real service.

## Using it with Kiro

- **Hooks and steering.** `exorcist init` writes a hook that blocks `git commit` while secrets are staged, a hook that scans MCP config when it is saved, and a steering file. This repo's own hooks are in `.kiro/hooks/`.
- **The Shield.** `exorcist wrap .kiro/settings/mcp.json` runs every local MCP server through the shield. `exorcist unwrap` puts the original commands back exactly. Alerts: `exorcist alerts`. Approve a changed tool: `exorcist approve tool <server> <tool>`.
- **The MCP server.** `packages/mcp-server` exposes `scan_repo`, `scan_mcp_config`, `explain_finding` and `quarantine`.
- **The Power.** `power/` follows the Agent Plugins layout. It points at an npm package that is not published yet.

## Repository layout

```
apps/web/            Next.js retro desktop and the scan API
packages/core/       scan engine, reporters, plain-language text
packages/shield/     MCP firewall, Quarantine Vault, config wrapping
packages/cli/        the `exorcist` command (bundled with esbuild)
packages/mcp-server/ the `exorcist` MCP server
definitions/         YAML virus definitions
fixtures/haunted-repo/  defanged attack samples
power/               Kiro Power
action.yml           GitHub Action
.kiro/               steering, specs (one per milestone), hooks
docs/                plan, threat list, Kiro usage log, known limitations
```

## Related repo

- Kiro Crew app (nightly scans and a Crew dashboard): [pranavsaji/exorcist-98-crew](https://github.com/pranavsaji/exorcist-98-crew)

## Safety

All attack samples in `fixtures/` are defanged: no working endpoints, no real malware. The one deliberate exception to "no control characters" is the hidden-Unicode sample, which carries only a placeholder string.

## License

Apache-2.0
