# Exorcist 98

**The 90s antivirus, resurrected for AI coding agents.**

![A screen recording of the Possession Lab rug pull: a trusted MCP tool changes its own description after approval, and the same attack plays twice. Without the Shield the agent follows the new orders and the result is "compromised". With the Shield the changed tool is hidden and the call is refused, and the result is "protected".](docs/media/rug-pull-demo.gif)

*The rug pull from the [live demo](https://exorcist-98.vercel.app/?demo=rug-pull), 21 seconds: the same attack with and without the Shield, ending on "Result: protected". Open the link to run it yourself.*

**Five minutes? Start with [`docs/START-HERE.md`](docs/START-HERE.md):** three live links with nothing to install, then three commands for your own machine.

[![Kiroween 2026: Resurrection](https://img.shields.io/badge/Kiroween_2026-Resurrection-8a3fb0)](https://kiroween.devpost.com/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Used Kiro](https://img.shields.io/badge/used-Kiro-6b3fd4)](docs/HOW_KIRO.md)

AI coding agents obey what they read (READMEs, rules files, tool descriptions), and anyone can write those files.
Exorcist 98 scans a repository for hidden instructions and risky agent settings, and runs a Shield between your agent and its MCP servers that stops a tool from turning on you.

## Try it in 30 seconds

- **In the browser, nothing to install:** **[exorcist-98.vercel.app](https://exorcist-98.vercel.app)**, then click *Scan the Haunted Repo*. Or watch [a trusted tool turn bad and get blocked](https://exorcist-98.vercel.app/?demo=rug-pull), or [the Lethal Trifecta demo](https://exorcist-98.vercel.app/?demo=trifecta).
- **On your own project:** `npx -y @exorcist-98/cli scan .`

<!-- PLACEHOLDER FOR THE OWNER: record a short GIF of `node scripts/demo-touchid.mjs` on a Mac, with the
     Touch ID prompt open and the call held, and save it as docs/media/session-guard-touchid.gif.
     Then replace the image below with ![...](docs/media/session-guard-touchid.gif). -->
![The Shield console while the Session Guard holds a message after a GitHub issue and a .env read](docs/media/shield-console-desktop.png)

*The Shield console during the Lethal Trifecta demo: an outgoing message is held after an issue and a `.env` read. The Touch ID prompt itself is not in this image, and this capture was taken with terminal release. A GIF with the prompt open is still to be recorded.*

## What it protects you from

Two plain-words terms used below:

- **A rug pull** is an MCP tool you approved that later changes its own description, after you said yes, to tell your agent something else.
- **The lethal trifecta** is an agent that has read text an attacker wrote, can read your secrets and can send data out. Each step looks harmless alone. Together, one hidden sentence can steal your `.env`.

| | What it does | Where |
|---|---|---|
| **Scan** | <!--f:definitions-->27<!--/f--> open YAML virus definitions find hidden Unicode, instructions aimed at the AI, poisoned tool descriptions, remote code in hooks and more, in the files seven coding agents read. Every finding shows the file, line, the exact quoted text, a severity in words, the threat class and a fix. | web app, `exorcist scan`, GitHub Action, MCP server |
| **Shield** | A firewall between the agent and each MCP server. It pins every tool and re-checks it before every call, hides a tool that changed, blocks secrets and canary tokens in tool calls, withholds attack-like tool results, and holds data going out once a session has read untrusted text and private data (the Session Guard). | `exorcist shield` / `wrap` |
| **Disinfect** | One patch for every safe mechanical fix, with an exact backup in the Quarantine Vault. | `exorcist exorcise` |

New in 0.2.0:
- **Gate:** `exorcist gate`, run by a Kiro `Stop` hook, fails when the agent's changes since the last commit add a high or critical finding to a steering, spec, hook, agent or MCP file ([`docs/REFERENCE.md`](docs/REFERENCE.md#in-your-editor-and-your-ci)).
- **Baseline:** `exorcist baseline` records the findings you accept today so `scan --baseline` fails only on new ones; `exorcist-ignore EX-012: reason` silences one rule on one line ([`docs/REFERENCE.md`](docs/REFERENCE.md#adopting-on-an-existing-repo)).
- **Published Kiro attacks:** rules for text hidden from people on a web page (EX-028) and for file names that give the AI orders (EX-029), plus a hook that asks a person before the agent writes to an MCP config ([`docs/INCIDENTS.md`](docs/INCIDENTS.md)).
Around those: an on-access hook that scans a file before Kiro's agent reads it, canary traps, a team lockfile for MCP tools, a map of risky server combinations, signed definition updates, a Kiro Crew app that patrols your folders nightly, and an optional AI judge for reworded attacks.

How this differs from tools that already exist: Snyk Agent Scan, Invariant Guardrails, Lakera Guard, MCPTrust, mcp-fence, Semgrep rules and GitHub secret scanning each cover part of this, and do more in places (fleet discovery, custom rules, hosted detection, signed lockfiles).
Exorcist 98 adds a scan of the repository's own agent files, Kiro hooks and a one-patch fix. Every row, with its source: [`docs/REFERENCE.md`](docs/REFERENCE.md#how-this-differs-from-tools-that-already-exist).

## Install

Only what is published today:

| What | Where | How |
|---|---|---|
| CLI | [npm `@exorcist-98/cli`](https://www.npmjs.com/package/@exorcist-98/cli), 0.1.2 | `npx -y @exorcist-98/cli scan .` |
| MCP server | [npm `@exorcist-98/mcp-server`](https://www.npmjs.com/package/@exorcist-98/mcp-server), 0.1.2 | `"command": "npx", "args": ["-y", "@exorcist-98/mcp-server"]` |
| Editor extension | [Open VSX `exorcist-98.exorcist-98-kiro`](https://open-vsx.org/extension/exorcist-98/exorcist-98-kiro) | `kiro --install-extension exorcist-98.exorcist-98-kiro` |
| GitHub Action | this repository | `uses: pranavsaji/exorcist-98@main` |
| Kiro Power | this repository, [`power/`](power) | Powers panel, *Add Custom Power*, *Import power from a repository URL*: `https://github.com/pranavsaji/exorcist-98/tree/main/power` |

The repository is at 0.2.0 (the gate, the baseline and the incident rules), which is not on npm yet; npm has 0.1.2, and 0.1.3 (a Power fix) is being published. Kiro setup in one command: `npx @exorcist-98/cli init --kiro`.

## Built with Kiro

- **Kiro IDE** wrote and implemented ten specs (requirements, design, tasks), among them the OS release, the precision work, the incident rules, the baseline and the gate. Four steering files set the security rules before any code. The repository has <!--f:specs-->23<!--/f--> specs, <!--f:steering-->11<!--/f--> steering files and <!--f:hooks-->10<!--/f--> hooks.
- **Seen working in Kiro:** the Power was installed through Kiro's Powers panel, and the on-access hook was seen firing in Kiro IDE: it blocked the agent's read of a brief that quoted an injection phrase ([`docs/KIRO_LOG.md`](docs/KIRO_LOG.md)).
- **Session evidence:** the exported transcripts of this project's Kiro sessions come to <!--f:kiroSessions-->27<!--/f--> sessions, <!--f:kiroCredits-->1,540.57<!--/f--> credits and <!--f:kiroToolCalls-->3,766<!--/f--> tool calls, in which hooks ran <!--f:hookRuns-->1,718<!--/f--> times and blocked <!--f:hookBlocks-->3<!--/f--> tool calls. The specs hold <!--f:shallLines-->184<!--/f--> acceptance criteria and <!--f:tasksDone-->295<!--/f--> of <!--f:tasksTotal-->327<!--/f--> tasks are done.
- **Kiro CLI** implemented parts of six features in headless runs. **Kiro Crew** runs the [nightly patrol app](https://github.com/pranavsaji/exorcist-98-crew).
- Not everything is Kiro's work. The dated record of what Kiro did and did not do is [`docs/KIRO_LOG.md`](docs/KIRO_LOG.md); the feature-by-feature map is [How we used Kiro](https://exorcist-98.vercel.app/how-kiro).

## Measured

- <!--f:tests-->2,431<!--/f--> tests in <!--f:testFiles-->166<!--/f--> files (<!--f:propertyTests-->202<!--/f--> fast-check properties), and a <!--f:browserSteps-->45<!--/f-->-step Chrome run with an accessibility scan.
- A corpus we wrote: <!--f:benchmarkAttacksCaught-->28<!--/f--> of <!--f:benchmarkAttacks-->28<!--/f--> attacks caught, <!--f:benchmarkBenignClean-->27<!--/f--> of <!--f:benchmarkBenign-->27<!--/f--> ordinary look-alikes left alone. It shows coverage of known patterns, not real-world recall.
- On 5 public repositories never used for tuning (about 9,500 files) the scanner raised 1 finding, and it was correct ([`docs/BENCHMARK.md`](docs/BENCHMARK.md)).
- A field report on <!--f:fieldReport.repos-->483<!--/f--> public repositories in <!--f:fieldReport.rounds-->3<!--/f--> rounds. The first round was noisy; after the fixes, serious alerts fell from 4.0 to 0.24 per repository on a fresh set. That set had no real threats, so it shows how quiet the scanner is, not how often an alert is right ([`docs/FIELD_REPORT.md`](docs/FIELD_REPORT.md)).

## Windows and Linux

The one feature that is macOS-only by design: **releasing a held Session Guard call in the system prompt (Touch ID or login password) is macOS only.** Everything else is written to run on all three. CI runs on Linux, and the hands-on checks were done on a Mac. On Linux and Windows the Shield says so, sends nothing, and a person releases the session with `exorcist approve session <key>` in a real terminal, which asks for a typed code. That is weaker, because an agent that drives a real terminal could read the code. Details: [S-030](docs/KNOWN_LIMITATIONS.md).

## Run it locally

Needs Node 20+ and pnpm.

```sh
pnpm install
pnpm --filter @exorcist-98/cli build
node packages/cli/dist/index.mjs scan fixtures/haunted-repo   # the defanged Haunted Repo
node scripts/demo-rug-pull.mjs                                 # a rug pull blocked, real processes, no Kiro needed
node scripts/demo-touchid.mjs                                  # the Lethal Trifecta, macOS only, you at the keyboard
pnpm vitest run                                                # all tests
node scripts/facts.mjs                                         # recount the numbers in docs/facts.json
```

## Where the detail is

| | |
|---|---|
| [`docs/REFERENCE.md`](docs/REFERENCE.md) | Every feature, the Shield table, CLI commands, definitions list, architecture, how the scanner protects itself |
| [`docs/KNOWN_LIMITATIONS.md`](docs/KNOWN_LIMITATIONS.md) | Every known gap and how sure we are of it |
| [`docs/FIELD_REPORT.md`](docs/FIELD_REPORT.md), [`docs/BENCHMARK.md`](docs/BENCHMARK.md) | The measurements and how to repeat them |
| [`docs/EXTENSION.md`](docs/EXTENSION.md), [`docs/WEB_AI.md`](docs/WEB_AI.md) | The editor extension and the optional AI layer |
| [`docs/SUBMISSION.md`](docs/SUBMISSION.md), [`docs/VIDEO_SCRIPT.md`](docs/VIDEO_SCRIPT.md) | The hackathon submission text and video script |
| [`SECURITY.md`](SECURITY.md) | Reporting a way past the Shield or the scanner |

All attack samples in `fixtures/` are defanged: `.invalid` hosts, placeholder secrets, no real malware.

Apache-2.0. See [`LICENSE`](LICENSE).
