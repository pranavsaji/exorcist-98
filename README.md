# Exorcist 98

**The 90s antivirus, resurrected for AI coding agents.**

Your agent reads READMEs, steering files, MCP tool descriptions and pull requests, and anyone can write those. Exorcist 98 scans them for prompt injection, tool poisoning and dangerous hooks, and runs a real-time shield between Kiro and its MCP servers.

Built with [Kiro](https://kiro.dev) for **Kiroween 2026** (category: Resurrection).

## Status

Milestones M0 to M3 are built and tested: the scan engine and virus definitions, the web app, the Real-Time Shield, the Quarantine Vault, the CLI, an MCP server, a Kiro Power and a GitHub Action. M4 (polish, SARIF badge, landing page) and M5 (video, write-up, submission) are not started. See [`docs/PLAN.md`](docs/PLAN.md).

**Read [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) before trusting any claim here.** The most important gaps: the Shield, the Power and the MCP server have not been run inside Kiro, nothing is published to npm, the GitHub Action has not run on GitHub, and the AI (Bedrock) heuristic layer has never run against the real service.

## The four parts

| Part                  | What it does                                                                                                                                                          | Where                                        |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| **Full System Scan**  | Paste a GitHub URL, or scan a folder. Findings show the file, line, quoted span, severity and fix.                                                                    | `apps/web`, `packages/cli` (`exorcist scan`) |
| **Virus Definitions** | 13 YAML signatures, plus an AI judge on Amazon Bedrock (library only).                                                                                                | `definitions/`, `packages/core`              |
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
