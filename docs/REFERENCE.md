# Exorcist 98: reference

The long version of the [README](../README.md): every feature in detail. Numbers come from [`facts.json`](facts.json).

---

## Try it in one minute

No install, no sign-in. Every link below opens the live app on that exact moment:

| Link | What you see |
|---|---|
| [`/?demo=haunted`](https://exorcist-98.vercel.app/?demo=haunted) | The Haunted Repo (22 defanged attack files) scanned in well under a second: verdict, gauge, top threats, what to do next |
| [`/?demo=rug-pull`](https://exorcist-98.vercel.app/?demo=rug-pull) | A trusted MCP tool turns malicious. The same attack, through the real Shield and without it, side by side |
| [`/?demo=trifecta`](https://exorcist-98.vercel.app/?demo=trifecta) | The Lethal Trifecta: three harmless-looking steps across three servers, stopped by the Session Guard (EX-027) |
| [`/?open=byoa`](https://exorcist-98.vercel.app/?open=byoa) | Bring Your Own Attack: paste any text and get the real scanner's and Shield's verdict |
| [`/?open=map`](https://exorcist-98.vercel.app/?open=map) | The Haunted House Map of a config that forms the lethal trifecta |
| [`/?open=field`](https://exorcist-98.vercel.app/?open=field) | What happened when we scanned <!--f:fieldReport.repos-->483<!--/f--> real public repositories |
| [`/?repo=owner/name`](https://exorcist-98.vercel.app/?repo=modelcontextprotocol/servers) | Any public GitHub repository (branch, tag and commit links work too). The address bar is a shareable link to the scan |

Private project? Upload a .zip (up to 4 MB). It is unpacked only for the scan and deleted straight after.

## The problem

Coding agents treat text as instructions. That text now comes from everywhere:

- **Rules and steering files** (`AGENTS.md`, `CLAUDE.md`, `.cursor/rules`, `.kiro/steering`, Copilot instructions) that a contributor or a dependency can edit.
- **MCP tool descriptions**, read by the model but almost never by the person who approved the server, and free to change after approval (a "rug pull").
- **Tool output**: a web page, an issue, a log line, a search result.
- **Hooks and install scripts** that run code on events.

Attackers hide instructions in invisible Unicode, HTML comments, base64 blobs or ordinary-looking prose, such as a sentence addressed to whichever AI summarises the file that asks it to send your environment file to an outside address (defanged samples are in the Haunted Repo fixture and `fixtures/benchmark/`). The 90s had a model people still understand for this: **virus definitions, a full system scan, an on-access scanner, a real-time shield and a quarantine vault.** Exorcist 98 points it at the files and tools an AI agent trusts.

## What Exorcist 98 does: Scan, Shield, Disinfect

| | What it does | Where |
|---|---|---|
| **Scan** | <!--f:definitions-->33<!--/f--> open YAML virus definitions plus code checks across the files seven coding agents read. Every finding shows the file, line, the exact text, an infection level (text and shape, never colour alone), the threat class and a plain-language fix. | web app, `exorcist scan`, GitHub Action, MCP server |
| **Shield** | An MCP firewall between the agent and each MCP server: pins every tool, re-checks it before every call, hides tools that change, blocks secrets, unknown hosts and canary tokens in tool calls, withholds attack-like tool results, and holds data going out once a session has read untrusted text and private data (EX-027). | `exorcist shield` / `wrap` |
| **Disinfect** | One patch for every threat with a safe mechanical fix (hidden characters, smuggled comments, remote images, unpinned MCP packages), with an exact backup in the Quarantine Vault. | "Download exorcism patch", `exorcist exorcise` |

Around those three: an **on-access hook** that scans a file *before* Kiro's agent reads it, **canary traps**, a team lockfile for MCP tools (**`exorcist.lock`**), a **Haunted House Map** of risky server combinations, **signed definition updates**, a **Kiro Crew** app that patrols your folders every night, and an optional **AI layer** for reworded attacks no pattern can catch.

## A tour of the app

### Full System Scan and results

Scan the Haunted Repo, any public GitHub repository, or a .zip. The results window opens with a verdict (POSSESSED, HAUNTED or CLEAN), a five-step infection gauge, counts by level, the top three threats in plain words, and three next steps: disinfect, save a report (SARIF for GitHub code scanning, Markdown for a pull request, JSON, an SVG README badge), and guard every pull request with the GitHub Action.

![Results: verdict POSSESSED, infection gauge, top threats and what to do next](media/results.png)

### The Ouija board

Invisible-text smuggling hides a whole message from people while the model reads it. Open any hidden-Unicode finding (EX-001) or variation-selector "emoji smuggling" finding (EX-021) and the Ouija board reads the hidden message back as plain text. It is shown as text, never as HTML, and the CLI escapes any terminal control characters in it.

![The Ouija board reading a message hidden in Unicode tag characters](media/ouija-board.png)

### The Haunted House Map

An agent is dangerous when one session combines **private data**, **untrusted input** and **a way out** (the "lethal trifecta"). Each MCP server looks harmless alone. The map puts every enabled server from a Kiro, Cursor, Claude Code, VS Code, Gemini or Cline config into its rooms and flags the configs that complete the trifecta (EX-023, critical when any server on a leg is auto-approved). Capability rules are data (`definitions/capabilities.yaml`), each with tested examples.

![The Haunted House Map: Vault of Secrets, Open Door and Escape Tunnel](media/haunted-house-map.png)

### The Possession Lab

Seven attacks (rug pull, poisoned tool, secret leak, unknown host, poisoned tool result, canary, lethal trifecta), each replayed twice from the same script: once through the **real Shield engine** (the code that runs on your machine, not an animation) and once with nothing in between. Step through them side by side and watch one side end *EXORCISED* and the other *POSSESSED*.

![The Possession Lab: the rug pull, protected versus compromised](media/possession-lab.png)

The newest, **The Lethal Trifecta**, needs the Session Guard (EX-027): an issue comment, a `.env` read and a chat message are each harmless alone, so no single-call check stops them. The Shield remembers that this session already took in untrusted text and read a secret, and holds the base64-encoded post that would close the loop ([watch it](https://exorcist-98.vercel.app/?demo=trifecta)).

![The Lethal Trifecta: the encoded .env is held by EX-027 on the left and reaches the chat server on the right](media/lethal-trifecta.png)

### Bring Your Own Attack

The 90s gave everyone the EICAR test file. Paste any text, say where your agent meets it (a README, an MCP tool description, a tool result, tool-call arguments), and see what the real scanner and the real Shield do with it. The text is judged in memory and never stored or logged, and the response quotes at most 200 characters of it. A clean result comes with an honest caveat: patterns miss reworded attacks.

![Bring Your Own Attack: a booby-trapped web page, EXORCISED](media/bring-your-own-attack.png)

**Patterns are not enough, and the app says so.** Pick the *Polite request* sample: an attack written in ordinary words, asking the agent to post every environment variable to an issue tracker. The signatures honestly say CLEAN. Underneath, the **AI judge** gives a second opinion and catches it, quoting the exact sentence:

![Signatures say CLEAN; the AI judge calls it credential exfiltration and quotes the sentence](media/ai-judge.png)

The AI judge on the public site is off unless the operator turns it on, with per-visitor limits and a daily call budget ([`docs/WEB_AI.md`](WEB_AI.md)); when it is off, the panel says so and how to run it yourself.

### Field Report

We pointed the scanner at **<!--f:fieldReport.repos-->483<!--/f--> public MCP servers and agent-config repositories** in <!--f:fieldReport.rounds-->3<!--/f--> rounds and read every serious alert by hand. Round 1 exposed too many false alarms; every pattern got a general fix, measured on a fresh set of repositories in round 2. Serious alerts fell from **4.0 to 0.24 per repository**; round 3 (62 popular repositories, not held out) found no real issue. Real finds include a jailbreak hidden in base64 and a leaked GitHub token (repository withheld until it is revoked). Full method, every false alarm and the limits: [`docs/FIELD_REPORT.md`](FIELD_REPORT.md).

![The Field Report window](media/field-report.png)

It works on a phone too:

<img src="media/mobile.png" alt="Exorcist 98 at 390 pixels wide" width="300">

## The Real-Time Shield

`exorcist wrap .kiro/settings/mcp.json` runs every local MCP server in a Kiro (or Cursor, Claude Code, VS Code) config through the Shield; `exorcist unwrap` restores the file byte for byte.

| Protection | How |
|---|---|
| **Rug pulls** | Every tool's name, description and input schema is pinned (SHA-256) on first use. A tool that changes is hidden from the agent and calls to it are refused, with a diff, until `exorcist approve tool`. |
| **Cached tool lists** | Found by running the Shield inside Kiro: Kiro caches the tool list, so a changed tool was called with no alert. The Shield now holds each call, re-reads the server's tool list and refuses the call if the tool no longer matches its pin. |
| **Poisoned tools** | New tool descriptions are checked against the definitions (and, if enabled, the AI judge) before the agent ever sees them. |
| **Secrets and hosts** | Arguments carrying credentials are blocked; data going to a host that is not on the allowed list is held for approval. |
| **Canary traps** | `exorcist canary plant` writes unique tokens into trap files. A token in any agent-to-server message (raw, base64, percent-encoded or split) is blocked in every mode, with a critical alert naming the trap. |
| **Attack-like results** | Tool output that reads like instructions to the AI is withheld; the agent gets a refusal instead. |
| **Lethal trifecta, at run time (Session Guard, EX-027)** | EX-023 says a config *could* combine untrusted text, private data and a way out. The Session Guard watches what really happens in one agent session, across all its Shield-wrapped servers: once the agent has taken in untrusted text (an issue, a web page, a flagged result) **and** read private data (a secret in a result, a `.env` or `~/.ssh` read, a private-data tool), the next call that could send data out is held for your approval, or refused; only a person should release it, with `exorcist approve session <key>`. On macOS the release is verified by the operating system (Touch ID or your login password) in a prompt only the Shield process can answer, so a forged `cli.json` no longer releases a call; policy `"sessionRelease"` chooses `"os"` or `"terminal"`. Elsewhere it is unchanged: the command refuses to run without an interactive terminal and asks for a typed one-time code (weaker: an agent driving a real terminal could read it). Each step alone looks harmless, so each alone is allowed. The Shields share facts only (tool, server, rule, time; never text or secrets) in the state folder. Policy `"sessionGuard": "hold"` (default), `"block"`, `"monitor"` or `"off"`. Limits: [S-027](KNOWN_LIMITATIONS.md). On Linux and Windows the system-prompt release is not available: see [S-030](KNOWN_LIMITATIONS.md). |
| **Changed programs** | The program behind each server (command, arguments, file contents, environment and loader variables such as `NODE_OPTIONS`) is pinned; a change holds the server until `exorcist approve server`. |
| **Team lockfile** | `exorcist.lock` records the tool fingerprints a team expects. On a machine that never pinned a tool, drift from the lock is still a rug pull. The lock never approves anything, and `lock --check --static` runs in CI without starting a pull request's servers. |
| **Quarantine Vault** | Disable an infected MCP server, hook or steering file with a backup, a diff and an exact restore. |

**Watch it live: `exorcist console`.** Opens a local page that shows, as they happen, every tool call the Shields of a state folder allowed, held or blocked, the rule and the reason (EX-006 rug pull, EX-022 canary, EX-027 Session Guard...), which server, and what the Session Guard has seen in each agent session (untrusted text, private data, calls waiting for your answer). Each Shield appends its decisions to `.exorcist/events.jsonl` (bounded, names and rule ids only, never arguments or results); the console tails it. It is a **read-only** view: it cannot approve or release anything, which stays with you: in `exorcist approve ...` in your own terminal, or, when the Shield uses OS release (`sessionRelease: os`, macOS), in the system prompt (Touch ID or your login password). It listens on 127.0.0.1 only, behind a random token in the URL, with a Host check and a strict CSP. Limits: [S-028](KNOWN_LIMITATIONS.md).

**A log that shows if it was edited: the hash chain.** Each line the Shield writes to `events.jsonl` is linked to the line before it, like pages numbered and stamped in a ledger. Every event carries three extra fields: `seq` (its position, starting at 1), `prev` (the hash of the event before it) and `hash` (SHA-256 of the event itself, including `seq` and `prev`). Change, remove, insert or swap a line and the links after it no longer fit.

- **Genesis file.** The first event links to a random value kept in `events.genesis.json`, created once (exclusively, so two Shields starting together share one value). It ties the head file to this log.
- **Head file.** `events.head.json` holds the genesis value and the `seq` and `hash` of the newest event. It is written to a temporary file in the same folder and then renamed, so a reader never sees half a file. A log that was cut short, or whose end was replaced, no longer matches it.
- **Several Shields at once.** Shields that share a state folder take a short lock (`events.lock`, a folder, the same one rotation uses) around "read the head, write the line, write the head", so they still produce one chain in order. A lock left behind by a dead process is removed after 10 seconds. If a Shield cannot get the lock after about 2.4 seconds of trying, it writes the event **unchained** (no `seq`, `prev` or `hash`) instead of dropping it or freezing your agent. Verification tolerates such lines only at the very end of the log, and says how many it did not check. In the middle of a chain, an unchained line reads as tampering ([S-031](KNOWN_LIMITATIONS.md)).
- **Rotation.** At 1 MiB the log is renamed to `events.1.jsonl` and a new `events.jsonl` starts. The chain carries on across the two files. Rotation drops the oldest events, so verification then starts at the first event still there and cannot see before it.
- **Old logs.** A log written before the chain, or an empty one, has none. It is reported as "not chained", not as broken.

**What the chain detects, and what it does not.** It detects a partial edit: a changed, removed, inserted or swapped event, and a log whose end no longer matches the head file. `exorcist verify-log` names the first event that is wrong. It does **not** stop anyone who can write the state folder: they can rewrite the whole log and the head file together, and the result verifies as intact. That full rewrite is caught only if you saved a head hash somewhere outside the state folder (a CI log, a ticket, a note) and check it with `--expect`. This is detection, not prevention. The full list of limits is [S-031](KNOWN_LIMITATIONS.md).

**Where to find the head hash.** The last line of `exorcist alerts` prints `Event log head: <hash> (event <n>)`, or says there is none yet. `exorcist gate` prints the same line, on stdout when the check passes and after its result on stderr when it fails (it reads the folder given with `--dir`, default the Shield state folder). The Shield console shows it next to a chain badge whose text says **intact**, **broken at event N** or **not chained**; the words carry the meaning, the colour only adds to it. Save the hash outside the state folder if you want to detect a full rewrite later.

**Checking it: `exorcist verify-log [--dir <folder>] [--expect <hash | seq:hash>] [--json]`.** Reads the log (both files), the head file and the genesis file in one pass.

| Result | Plain-text message | Exit code |
|---|---|---|
| Intact | `The log is intact: <n> events, none changed. Head hash: <hash>` (adds `<k> later lines are not chained and were not checked.` when the log ends with unchained lines) | 0 |
| Not chained | `The log is not chained: it has no hash chain (an old or empty log), so there is nothing to check.` | 0 (1 with `--expect`, whose message is `The log is not chained, so the expected head cannot be matched.`) |
| Broken | `The log is broken at event <n>: <reason>. <detail>`, where the reason is one of `an event was changed`, `an event was removed`, `an event was inserted`, `events were swapped`, `the log's end does not match its head record`, or `the log's head does not match the expected hash` | 1 |
| Usage error | An unknown flag, an extra argument, or an `--expect` that is not a 64-character hash or `<seq>:<hash>`, with the help text | 2 |

- `--dir` is the Shield state folder (default: the project's `.exorcist` folder, or `EXORCIST_DIR`).
- `--expect <hash>` must equal the log's current head. `--expect <seq>:<hash>` must equal the hash of event number `seq`, and stays valid after the log has grown, so it suits a hash you saved last week. A mismatch is "broken" (exit 1).
- `--json` prints one JSON object and nothing else, with the same exit codes. Its shape is one of `{"status":"intact","head":{"v":1,"genesis":"<hex>","seq":<n>,"hash":"<hex>"}}` (plus `"unchained":<k>` when the log ends with unchained lines), `{"status":"not-chained"}`, or `{"status":"broken","atSeq":<n>,"reason":"changed|removed|inserted|reordered|head-mismatch|expect-mismatch","detail":"<text>"}`.

**What a person has to do to release a held call.** Releasing is only ever done by a person, and a code or a release cannot be reused:

- **Typed code (no OS prompt available).** The one-time code shown by `exorcist approve session` and `exorcist allow-read` is valid for a **fixed 15 minutes** and works **once**. Typing it late prints "That code has expired (it is valid for 15 minutes). Nothing was allowed. Run the command again."; typing it a second time prints "That code was already used. Nothing was allowed." A wrong answer is just "That does not match" and never says whether a code was expired or used.
- **OS release (macOS).** A successful Touch ID or login-password check releases **one** held call, grants nothing, and the next call is held again. The call is **re-checked in full** at that moment against the current state: a tool withheld while the prompt was open (a rug pull or a poisoned description) is still refused, and a call to a host that is not allowed still goes through the unknown-host check (EX-016).
- **Every outcome is in the log.** Each approval, refusal and expiry is written as an event, so it is chained like any other: accepted, declined, expired, already used, and a timed-out or cancelled OS prompt. The CLI commands (`approve session`, `allow-read`, `guard-mcp-write`) write theirs without file text, codes or reasons.

**Try it (macOS, with you at the keyboard).** `pnpm --filter @exorcist-98/cli build && node scripts/demo-touchid.mjs` makes a temporary project with a fake `.env`, starts real Shields in front of fake servers, and plays the trifecta: an issue that hides an instruction, the `.env` read, then an email to an allowed host. The email is held and the system prompt asks for Touch ID (or your login password); Cancel it to see the call refused. It prints the `exorcist console` command to watch it live, and refuses to run in tests, in CI or off macOS.

<img src="media/shield-console-desktop.png" alt="The Shield console: tool calls allowed, held and blocked with rule ids, and an armed Session Guard holding a Slack message after a GitHub issue and a .env read" width="800">

## In your editor and your CI

**Kiro, in one command:**

```sh
npx @exorcist-98/cli init --kiro          # hooks, steering, the hook PATH wrapper and the reviewer agent
npx @exorcist-98/cli init --kiro --shield # also run every local MCP server through the Shield
```

This writes Kiro hooks that block `git commit` while secrets or canary tokens are staged, scan an MCP config the moment it is saved, scan a file before the agent reads it, ask a person before the agent writes to an MCP config (`mcp-config-write-guard`), and (a `Stop` hook running `exorcist gate`) fail when the agent's turn ends with a high or critical finding added to a steering, spec, hook, agent or MCP file since the last commit; steering that tells the agent how to treat tool output; and an `exorcist-reviewer` custom agent that may only use the read-only tools of the Exorcist MCP server. Start an agent from `.kiro/agents/` (`exorcist-reviewer`, or `exorcist-red-team` in this repository) by trusting the workspace and picking it in the chat header's agent picker in Kiro IDE, or with `kiro-cli chat --agent exorcist-reviewer`. You can also run `exorcist gate` by hand at any time.

**Editor extension: Exorcist 98 for Kiro** ([`packages/vscode`](../packages/vscode/README.md), works in VS Code too):

- Live diagnostics on the files agents obey (Kiro steering, specs, hooks and MCP configs, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, Copilot instructions, READMEs, any config with `mcpServers`), on open, edit, save and when an agent changes them on disk; each rule id links to its encyclopedia page.
- Hidden characters drawn as visible markers (`ZWSP×2`, `RLO`, `TAG×51`); hover one to see the decoded hidden message (the Ouija board).
- Quick fix *Exorcise: remove hidden characters*, the CLI's exorcise logic as one undoable edit; also fixes for hidden HTML comments and data-leaking images.
- A ghost count in the status bar and a *Scan workspace* command.
- Read-only and offline: it never runs anything from the workspace and makes no network request, so it also runs in Restricted Mode, where a repository's own settings cannot switch it off.

Running inside Kiro on a poisoned steering file: the Problems panel, the decoded hidden message on hover, and the *Exorcise* quick fix next to Kiro's own *Ask Kiro to Fix*.

| Findings in Kiro | Hidden message decoded | One-click Exorcise |
|---|---|---|
| ![Exorcist 98 findings in Kiro's Problems panel](media/kiro-extension-problems.png) | ![Hover decoding a hidden tag-character message](media/kiro-extension-ouija-hover.png) | ![Exorcise quick fix in Kiro](media/kiro-extension-quickfix.png) |

On Open VSX as [`exorcist-98.exorcist-98-kiro`](https://open-vsx.org/extension/exorcist-98/exorcist-98-kiro): search *Exorcist 98* in Kiro's Extensions view, or run

```sh
kiro --install-extension exorcist-98.exorcist-98-kiro
```

To build it yourself instead: `pnpm install && pnpm --filter exorcist-98-kiro package`, then `kiro --install-extension packages/vscode/exorcist-98-kiro-0.1.0.vsix`. Details: [`docs/EXTENSION.md`](EXTENSION.md).

**The pieces individually:**

| | |
|---|---|
| **On-access hook** | A Kiro `PreToolUse` hook (`exorcist on-access`) scans a file before the agent reads it and blocks the read if it carries high or critical threats. Only a person can allow a blocked file: `exorcist allow-read` needs a real terminal and, on macOS, a click in a system dialog, so an agent cannot approve its own read. Allowances live outside the repository, bound to the path and the content hash. |
| **MCP config write guard** | A Kiro `PreToolUse` hook (`exorcist guard-mcp-write`) asks a person before an agent writes to `.kiro/settings/mcp.json`, the step of the published CVE-2026-10591 attack. With nobody to ask, the write is blocked. See [`docs/INCIDENTS.md`](INCIDENTS.md). |
| **MCP server** | `@exorcist-98/mcp-server`: `scan_repo`, `scan_mcp_config`, `explain_finding`, `quarantine`. It returns plain-language findings without quoting file text by default, so it cannot become an injection channel itself. |
| **Kiro Power** | `power/`, in the Agent Plugins layout, pointing at the MCP server. |
| **Custom agents** | `.kiro/agents/exorcist-reviewer.json` (read-only Exorcist tools) and `exorcist-red-team.json` (writes defanged samples into the benchmark, runs only the benchmark test). |
| **Kiro Crew app** | [`pranavsaji/exorcist-98-crew`](https://github.com/pranavsaji/exorcist-98-crew): a nightly patrol of your folders, a dashboard page, an MCP rug-pull watch, an owner-only quarantine and a read-only Sentry agent. Run inside Kiro Crew 0.12.2 and 0.13.0. |

**GitHub Action.** Every pull request is scanned and gets a comment; the check fails on high or critical threats:

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
          lock-check: true   # optional: fail if MCP tools drift from exorcist.lock (never starts a PR's servers)
```

**CLI.** `npx @exorcist-98/cli <command>`:

| Command | What it does |
|---|---|
| `scan <path>` | Scan a folder or file (`--format text|json|sarif|markdown|badge`, `--fail-on`, `--ai`, `--baseline <file>`) |
| `baseline [folder]` | Write `.exorcist-baseline.json`: the findings you accept for now |
| `gate [folder] [--dir <state folder>]` | Fail if the changes since the last commit add a high or critical finding to a steering, spec, hook, agent or MCP file (read-only; run by the Kiro `Stop` hook). Also prints the Shield event log's head hash when the state folder has one; `--dir` picks that folder |
| `guard-mcp-write` | Hook helper: a person must confirm any agent write to an MCP config, to trusted commands in `.vscode/settings.json`, or to `.kiro/hooks/` and `.kiro/agents/` |
| `guard-web-fetch` | Hook helper: block a web fetch whose address holds a secret, canary token or `.env` value |
| `guard-env-write` | Hook helper: block writing a `.env` value into any other file |
| `exorcise [path]` | Disinfect: print a patch for every safe mechanical fix; `--write` applies it with a vault backup |
| `map [dir]` | Draw the Haunted House Map (EX-023) |
| `origin [dir]` | Trace each threat to the commit and author that introduced it |
| `shield`, `wrap`, `unwrap` | Run MCP servers behind the Real-Time Shield |
| `lock [--check] [--static]` | Write or check `exorcist.lock` |
| `canary plant|--list|--remove` | Canary traps (EX-022) |
| `console` | Open the live, read-only Shield console in your browser (new in 0.1.2) |
| `approve`, `alerts`, `vault` | Approve changed tools, hosts or servers, or a session the Session Guard holds (EX-027); read alerts (the last line is the event log's head hash); quarantine and restore |
| `verify-log [--dir] [--expect <hash\|seq:hash>] [--json]` | Check that the Shield's event log was not changed, cut short or reordered. Exit 0 intact or not chained, 1 broken (or not chained with `--expect`), 2 usage error. See "A log that shows if it was edited" above |
| `init [--kiro] [--shield] [--sandbox]` | Wire a Kiro project; `--sandbox` also writes `.kiro/settings/sandbox.json` (sandbox on, network blocked, MCP sandboxing on) |
| `on-access`, `allow-read` | The on-access hook and its person-only allowance |
| `update [--status]` | Install signed (Ed25519) definition updates, verified on download and on every load |
| `detonate <file>` | The Detonation Chamber (experimental, needs AWS) |

The published npm version is `@exorcist-98/cli@0.1.2`, and 0.1.3 (the Power start-folder fix) is being published. The repository is at 0.2.0, which is not published yet; `baseline`, `scan --baseline`, `gate`, `guard-mcp-write`, `guard-web-fetch`, `guard-env-write` and `init --sandbox` are new in 0.2.0. Under the published 0.2.0 CLI, `init --kiro` writes the two new hooks disabled, because that CLI lacks the commands.
### Adopting on an existing repo
You do not have to fix everything first. Record what is there today, then fail only on what is new:
```sh
npx @exorcist-98/cli baseline .                                    # writes .exorcist-baseline.json
npx @exorcist-98/cli scan . --baseline .exorcist-baseline.json     # reports new findings only
```
In the GitHub Action, set the input `baseline: .exorcist-baseline.json`.
- **Baseline.** One entry per finding: rule id, file and a fingerprint of the matched text. It holds no raw text and no secrets. A finding that moves to another line is still baselined; one whose text changes is new again. The scan says how many findings the baseline hid.
- **Inline suppression.** Write `exorcist-ignore EX-012: reason` in a comment on the same line or the line before. The reason is required. Hidden characters (EX-001) and secrets (EX-011) can never be suppressed this way. Every suppression is listed in the summary, and the comment text itself is still scanned.
- **SARIF.** Baselined and suppressed results stay in the SARIF file, marked with SARIF's `suppressions` property, so code scanning shows them as suppressed instead of losing them.
- **Old definitions.** If the definitions in use are more than 30 days old, `scan` and `map` print one warning on stderr with the way to update. It makes no network request.
- **Tool descriptions in source code.** EX-005 now reads the description strings of tools registered in TypeScript, Python and Go server source, not only JSON tool definitions. Ordinary hints such as "use X before calling this tool" are left alone. Covered forms and gaps: [L-051](KNOWN_LIMITATIONS.md).


## The optional AI layer

Signatures are fast, free, deterministic and cannot be prompt-injected, so they screen everything. Reworded attacks get past patterns, so with `--ai` (your own Amazon Bedrock account) an **AI judge** reads every agent-facing file whole, even when no signature fired: Claude Haiku triages, Claude Sonnet confirms, and a verdict counts only if its quoted text is really in the file.

Measured on reworded attacks that no signature catches, each with a benign look-alike ([`docs/AI_JUDGE_EVAL.md`](AI_JUDGE_EVAL.md), [`docs/DETONATION.md`](DETONATION.md)):

| Layer | First set (10 attacks, 10 look-alikes) | Held-out set, never tuned on (10 + 10) |
|---|---|---|
| Signatures | 0 of 10 (by construction) | 0 of 10 (by construction) |
| **AI judge** | **10 of 10 caught, 0 false alarms** | **10 of 10 caught, 0 false alarms** |
| Detonation Chamber (a sandboxed model with fake tools) | 1 of 10, 0 false alarms | not run |

The judge used to score 6 of 10. Tracing the misses showed the models had caught all four; our own check that the quoted text is really in the file threw the verdicts away when a quoted sentence wrapped across a line. That check now ignores whitespace differences and still requires the quoted words, in order. One run per set, 40 texts written by us: this shows the judge is not fooled by plain rewording, not real-world recall. The chamber scores low because a safety-trained model refuses to play a gullible agent; it stays available as an experiment.

Before any text reaches a model, every credential-shaped value is masked at the same length (known key formats, values under secret-named keys, passwords inside URLs), credential files are never sent, and the model is told when values were masked. Destinations and instructions are never masked, so masking cannot hide an attack from the judge.

## Measured, not claimed

- **Tests:** <!--f:tests-->2,738<!--/f--> tests in <!--f:testFiles-->193<!--/f--> files (unit, <!--f:propertyTests-->212<!--/f--> fast-check properties and real-process tests), plus a <!--f:browserSteps-->45<!--/f-->-step Chrome run with an axe accessibility scan on every window: <!--f:browserAxeViolationTypes-->0<!--/f--> violation types.
- **Labelled corpus** (`fixtures/benchmark/`): <!--f:benchmarkAttacksCaught-->38<!--/f--> of <!--f:benchmarkAttacks-->38<!--/f--> defanged attacks caught, <!--f:benchmarkBenignClean-->37<!--/f--> of <!--f:benchmarkBenign-->37<!--/f--> look-alike ordinary files left alone. We wrote this corpus, so it shows coverage of known patterns, not real-world recall.
- **Published Kiro attacks** ([`docs/INCIDENTS.md`](INCIDENTS.md)): defanged replicas of CVE-2026-10591 (hidden web text rewrites the MCP config) and the Mindgard file-name attack are in the corpus, with the rule, Shield or hook layer that stops each and what is not covered.
- **Held-out public repositories** ([`docs/BENCHMARK.md`](BENCHMARK.md), held-out set C): on 5 repos never used for tuning (about 9,500 files) the scanner raised 1 finding, and it is correct.
- **Field report** ([`docs/FIELD_REPORT.md`](FIELD_REPORT.md)): <!--f:fieldReport.repos-->483<!--/f--> public repositories in <!--f:fieldReport.rounds-->3<!--/f--> rounds; serious alerts from 4.0 to 0.24 per repository after the fixes (round 1 to round 2). Round 2 contained no real threats, so it shows how quiet the scanner is, not how often an alert is right.
- **Haunted Repo:** <!--f:hauntedRepoFindings-->47<!--/f--> findings, pinned by a snapshot test.
- **Inside Kiro:** the Shield and MCP server ran inside Kiro IDE; of the <!--f:hooks-->12<!--/f--> Kiro hooks in this repository, nine were seen firing there (the on-access hook on 2026-11-24; the `exorcist-gate` Stop hook and the MCP config write guard on 2026-11-26, Kiro 1.5.11). The three newest, `spec-trace`, `guard-web-fetch` and `guard-env-write`, are covered by tests but have not yet been seen firing in Kiro. The Power was installed through Kiro's Powers panel; the Crew app ran inside Kiro Crew. See [`docs/KIRO_LOG.md`](KIRO_LOG.md).

## How this differs from tools that already exist
Several tools already cover parts of this problem, and some do things Exorcist 98 does not. This table states only what each tool's own documentation says, read on 2026-11-25; the last column links the page it comes from. "Not documented" means we did not find it on that page, not that the tool lacks it. Tools change; check the source before you rely on a row.
| Tool | What it looks at | Runs between the agent and the server | Catches a tool that changed after approval | Where it runs and what leaves your machine | Source |
|---|---|---|---|---|---|
| **Exorcist 98** | The files in a repository that an agent reads (READMEs, rules and steering files, hooks, MCP configs, Powers, skills), and tool descriptions in server source code | Yes: `exorcist shield` (stdio, and remote servers over HTTP) | Yes: pins each tool and checks it again before every call | Your machine. Nothing is sent unless you turn on the optional AI judge with your own AWS account | this repository: [README](../README.md), [limits](KNOWN_LIMITATIONS.md) |
| **Snyk Agent Scan** (the `invariantlabs-ai/mcp-scan` address now serves its README) | MCP servers, tools, prompts, resources and agent skills it finds on the machine; hidden Unicode is one of its listed risks | Not documented (it describes a scan and a background scan that reports to Snyk Evo) | Not documented | Needs a Snyk token. Sends tool names, descriptions and skill content (secrets redacted) to Snyk's analysis API | [README](https://github.com/snyk/agent-scan), [issue codes](https://github.com/snyk/agent-scan/blob/main/docs/issue-codes.md) |
| **Invariant Guardrails** (with Invariant Gateway) | Agent messages, tool calls and tool results that pass through it, against rules you write, including flows between tools | Yes: deployed as an MCP or LLM proxy | Not documented | The README shows rules running locally with the `invariant-ai` package; the Gateway's hosting terms are not documented there | [README](https://github.com/invariantlabs-ai/invariant) |
| **Lakera Guard** (now Check Point AI Guardrails) | Content you send to its Guard API: prompts, reference documents, tool calls, tool responses and tool descriptions | No proxy documented: your gateway or app calls an API | Not documented | Cloud service or self-hosted product; needs an account | [documentation](https://docs.lakera.ai/guard) |
| **semgrep-rules-mcp** (a community ruleset, not by Semgrep) | Source code of MCP servers and clients: tool descriptions in code, shell calls built from tool arguments, SDK settings | No (static rules) | No (static rules) | Runs locally with Semgrep Community Edition; no login | [README](https://github.com/garag0l/semgrep-rules-mcp) |
| **GitHub secret scanning** | Credentials in git history, issues, pull requests, discussions, wikis and secret gists | No | No | On GitHub. Free on public repositories; private ones need GitHub Secret Protection | [documentation](https://docs.github.com/en/code-security/secret-scanning/introduction/about-secret-scanning) |
| **MCPTrust** | A server's tools, prompts and resources, recorded in a lockfile | Yes: a deny-by-default proxy | Yes: blocks anything not in the lockfile, and a CI step fails on drift | Your machine (a Go program) | [README](https://github.com/mcptrust/mcptrust) |
| **mcp-fence** | MCP messages in both directions, and a standalone scan of a file or text | Yes: stdio, SSE and Streamable HTTP | Yes: SHA-256 pins of tool descriptions, checked on `tools/list` responses | Your machine (Node.js) | [README](https://github.com/yjcho9617/mcp-fence) |
### What Exorcist 98 adds
- **It reads the repository, not only the server.** None of the other rows documents scanning a repository's README, rules, steering, hook and Power files for text that gives the agent orders. Snyk Agent Scan reads skills and MCP configs; mcp-fence scans one file or text you give it.
- **It acts inside Kiro.** An on-access hook scans a file before Kiro's agent reads it, a `Stop` hook (`exorcist gate`) checks the agent's changes, and there is a Kiro Power and a Crew app. See [How we used Kiro](HOW_KIRO.md).
- **It can fix, not only report.** `exorcist exorcise` writes one patch for every safe mechanical fix, with an exact backup in the Quarantine Vault. None of the other pages documents this.
- **Both sides of the accuracy are published.** The [benchmark](BENCHMARK.md) counts attacks caught and look-alike files left alone, and the [field report](FIELD_REPORT.md) counts alerts on <!--f:fieldReport.repos-->483<!--/f--> public repositories. Both are small and written by us.
### Where another tool does more
- **Snyk Agent Scan** finds agent configs and skills across a whole machine for 14 listed agents and supports fleet monitoring through Snyk Evo. Exorcist 98 scans folders you point it at.
- **Lakera Guard** is a hosted detection service with its own threat data, 100+ languages and content and PII checks. Exorcist 98 detects mostly by signature, so a reworded attack can get past it unless the optional AI judge is on ([limits](KNOWN_LIMITATIONS.md)).
- **Invariant Guardrails** and **mcp-fence** let you write your own rules for flows between tools (for example, reading a file and then sending an email). Exorcist 98's Session Guard is one built-in rule of that kind, not a rule language.
- **MCPTrust** signs lockfiles and pins and verifies the package a server runs, which Exorcist 98 does not.
- **mcp-fence** supports JWT authentication, which Exorcist 98 does not. Both keep a tamper-evident log: Exorcist 98 hash-chains the Shield log and checks it with `exorcist verify-log` ([S-031](KNOWN_LIMITATIONS.md) says what that does not prove).
- **semgrep-rules-mcp** finds code bugs in MCP servers that Exorcist 98 does not look for, such as tool arguments reaching a shell and missing SDK security settings.
- **GitHub secret scanning** checks every commit in history and tells the provider so it can revoke the key. Exorcist 98 checks the files in front of the agent.
These tools also work together: Exorcist 98 does not replace a secret scanner, a code scanner or a hosted guardrail service.
## Virus definitions

Open YAML in [`definitions/`](../definitions/), each with severity, the files it applies to, per-rule precision controls, an OWASP mapping (LLM, Agentic or MCP Top 10) and a plain-language fix. Browse them in the app's [Threat Encyclopedia](https://exorcist-98.vercel.app/encyclopedia).

| ID | Threat | Level |
|---|---|---|
| EX-001 | Hidden Unicode instructions (with the Ouija decoder) | critical |
| EX-002 | Instructions addressed to an AI | high |
| EX-003 | Encoded payload (base64, hex) | high |
| EX-004 | HTML comment smuggling | high |
| EX-005 | Tool description poisoning | critical |
| EX-006 | MCP rug pull | critical |
| EX-007 | Over-broad auto-approve | high |
| EX-008 | Remote code in a hook (`curl … \| sh`) | critical |
| EX-009 | Install-script exfiltration | critical |
| EX-010 | Unpinned MCP server | medium |
| EX-011 | Secrets within an agent's reach | high |
| EX-012 | Markdown image exfiltration | high |
| EX-013 | Typosquatted MCP package | high |
| EX-014 | Steering override (approvals switched off) | high |
| EX-015 | Shell commands in tool output | high |
| EX-016, EX-017 | Unknown hosts and secrets in tool calls (enforced by the Shield) | high, critical |
| EX-018 | Confused-deputy request | high |
| EX-019 | Agent memory poisoning | high |
| EX-020 | Suspicious Kiro Power | critical |
| EX-021 | Smuggled bytes in variation selectors | critical |
| EX-022 | Canary token out of its trap | critical |
| EX-023 | Lethal trifecta across MCP servers | high or critical |
| EX-024 | Detonated in the chamber (experimental) | critical |
| EX-025 | An MCP server's environment changes how its program loads (`NODE_OPTIONS`, `LD_PRELOAD`…) | high |
| EX-026 | An agent file too large to check (never skipped in silence) | medium |
| EX-027 | Lethal trifecta completed in a live session: after untrusted text and private data, data going out is held (the Shield's Session Guard) | critical |
| EX-028 | Hidden text, `<meta>` tags or image alt text that instruct the AI (white, tiny, `display:none`, off-screen) | high |
| EX-029 | File or folder name that instructs the AI, or hides characters | high |
| EX-030 | Instructions to change the agent's own settings or guard files | high |
| EX-031 | Instructions to weaken tests or checks | high |
| EX-032 | Instructions to push or publish somewhere else | high |
| EX-033 | Settings that let the agent run any command without asking (Kiro `kiroAgent.trustedCommands`, Claude Code `permissions.allow`, Cursor `.cursor/cli.json`) | critical |
| EX-034 | Copilot `chat.tools.terminal.autoApprove` map that trusts every command | critical |
| EX-035 | Info: a committed `.kiro/settings/sandbox.json` turns MCP sandboxing off (reported at low, because there is no info level) | low |

## How Exorcist 98 protects itself

A scanner reads attacker text all day, so it is built to be attacked:

- Scanned text is never concatenated into instructions; AI prompts fence it with a per-call random nonce, and an AI verdict counts only if its quote is really in the file.
- The web page inserts quoted text as text, never HTML; the CLI escapes terminal control, bidi and hidden characters in everything it prints.
- Every regular expression runs under a time limit per file; a rule that runs out of time is reported, never silently clean.
- Agent files are never skipped for size in silence (EX-026).
- Tar and zip uploads refuse links, `..` paths and control characters in names; nothing is kept after a scan.
- `exorcist origin` refuses to run git in a repository whose own config could run commands (filters, fsmonitor and similar), and reads only committed history.
- Credentials are masked before any text reaches a model; credential files are never sent.
- `allow-read` and `canary --remove` cannot be driven by an agent or turned against files outside their folders.

The Detonation Chamber, canaries and every Haunted Repo sample use fake secrets built at run time and `.invalid` hosts.

Releases and the repository itself:

- npm releases are built and published from CI ([`release.yml`](../.github/workflows/release.yml)) with **npm provenance**, so `npm audit signatures` proves a package came from this repository and commit. No npm token is stored anywhere.
- CodeQL (security-extended queries) runs on every change and weekly; Dependabot groups dependency and Actions updates weekly.
- The repository scans itself with its own GitHub Action on every pull request.
- Found a way past the Shield or the scanner? See [`SECURITY.md`](../SECURITY.md) for private reporting.

## How we used Kiro

Milestones M0 to M4, the OS release (m6), the precision work (m7), the incident rules (m8), adoption (m9) and the gate (m10) were specified spec by spec in **Kiro IDE**: ten specs written and implemented by Kiro IDE (requirements, design, tasks), four steering files that every change followed, property-based tests for the requirements, and hooks on file save and before commits. **Kiro CLI** implemented parts of six M5 features in headless runs, one git worktree per feature, until the account's monthly usage limit. The **Kiro Crew** app was built for Crew and run inside it.

Kiro surprised us more than once, and each surprise made the product better: Kiro caches the MCP tool list (so the Shield now re-checks every call), Kiro runs hook commands with a PATH that has no Node (so every hook now finds Node first), and Kiro Crew's task runner reported "8/8 tasks passed" from an empty sandbox.

The full, honest map of every Kiro feature, the exact files, the evidence and where Kiro surprised us: **[How we used Kiro](https://exorcist-98.vercel.app/how-kiro)** ([`docs/HOW_KIRO.md`](HOW_KIRO.md)), with the dated record in [`docs/KIRO_LOG.md`](KIRO_LOG.md).

## Architecture

```mermaid
flowchart LR
  subgraph Sources["What an agent reads"]
    R[Repository files<br/>rules, steering, hooks, READMEs]
    M[MCP tool descriptions]
    O[Tool output]
  end
  subgraph Core["@exorcist-98/core"]
    W[Walker and normalizer<br/>hidden Unicode, decoding] --> S[Signature engine<br/>YAML definitions, time-limited]
    S --> J[Optional AI judge<br/>Bedrock, masked input]
    S --> T[Trifecta analysis<br/>capabilities.yaml]
    S --> X[Exorcise fixers]
  end
  subgraph Shield["@exorcist-98/shield"]
    P[Pins and lockfile] --> E[Shield engine<br/>verify every call]
    C[Canaries] --> E
    E --> V[Quarantine Vault]
  end
  R --> W
  M --> E
  O --> E
  Core --> Web[Web app<br/>Next.js desktop]
  Core --> CLI[exorcist CLI]
  Core --> MCPS[MCP server]
  Core --> GA[GitHub Action]
  CLI --> Hooks[Kiro hooks<br/>on-access, secrets, MCP config]
  Shield --> CLI
  Core --> Crew[Kiro Crew app<br/>nightly patrol]
```

```
apps/web/            Next.js retro desktop, scan API, Possession Lab, /how-kiro
packages/core/       scan engine, definitions loader, AI judge, trifecta, exorcise, origin, LiveUpdate
packages/shield/     MCP firewall, pins, lockfile, canaries, Quarantine Vault, attack simulator
packages/cli/        the `exorcist` command (bundled with esbuild)
packages/mcp-server/ the `exorcist` MCP server
definitions/         YAML virus definitions and capability rules
fixtures/            the Haunted Repo, the labelled benchmark, the detonation set, field-scan data (all defanged)
power/               Kiro Power
action.yml           GitHub Action
.kiro/               specs, steering, hooks, custom agents
docs/                how we used Kiro, Kiro log, field report, benchmark, AI evaluations, known limitations
```

## Run it locally

Needs Node 20+ and pnpm.

```sh
pnpm install

# Scan the Haunted Repo (defanged planted attacks)
pnpm --filter @exorcist-98/cli build
node packages/cli/dist/index.mjs scan fixtures/haunted-repo

# Watch the Shield stop a rug pull with real processes (20 seconds, no Kiro needed)
node scripts/demo-rug-pull.mjs

# The web app
pnpm --filter @exorcist-98/web build
pnpm --filter @exorcist-98/web exec next start

# Everything
pnpm test        # unit, property-based and real-process tests
pnpm e2e         # drives Chrome against a running web app, with an axe accessibility scan
```

## Status and known limits

Working and tested: everything described above runs from this repository and the live app passes the full Chrome suite.

Open, in plain words:

- The Power was installed through Kiro's Powers panel on 2026-11-24, and the on-access hook was seen firing in Kiro IDE (see [`docs/KIRO_LOG.md`](KIRO_LOG.md)). The Shield's check-before-every-call fix has been tested with real processes and Kiro's restricted PATH but not re-run inside Kiro IDE, the Shield console has not been run inside Kiro, and the two custom agents have not been loaded in Kiro.
- The release of a held session in the system prompt is macOS only. Elsewhere it falls back to a typed code in a terminal ([S-030](KNOWN_LIMITATIONS.md)).
- Detection is mostly signatures; the AI judge caught 10 of 10 reworded attacks on each of our two small test sets, but it needs an AWS account and costs money to run. On the public website it is off until the operator turns it on ([`docs/WEB_AI.md`](WEB_AI.md)).

Every known gap, with how sure we are of it, is in [`docs/KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md) and the `NOTES.md` of each `.kiro/specs/m5-*` spec.

## Safety

All attack samples in `fixtures/`, the Possession Lab and the Detonation Chamber are defanged: no working endpoints (`example.invalid`), fake secrets built at run time, no real malware. The one deliberate exception to "no control characters" is the hidden-Unicode sample, which carries only a placeholder string.

## License

Apache-2.0
