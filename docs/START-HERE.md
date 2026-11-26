# Start here: Exorcist 98 in five minutes
Exorcist 98 is an antivirus for AI coding agents. It scans the files an agent reads for hidden orders, and it sits between the agent and its MCP servers so a tool that turns bad is stopped. This page is for someone with five minutes. The [README](../README.md) is the short version; [`REFERENCE.md`](REFERENCE.md) is the long one.
## 60 seconds, nothing to install
Open each link. No sign-in.
| Link | What to look for |
|---|---|
| [Scan the Haunted Repo](https://exorcist-98.vercel.app/?demo=haunted) | A repository of defanged attack files, scanned in about a second. The verdict is **POSSESSED**. Click any finding: it opens the exact line and the quoted text, with a severity in words, the threat class and a fix. |
| [A rug pull, with and without the Shield](https://exorcist-98.vercel.app/?demo=rug-pull) | A tool you trusted changes its own description. The same attack plays twice. Without the Shield the result is "Result: compromised." With it the changed tool is hidden, the call is refused and the result is "Result: protected." |
| [The Lethal Trifecta](https://exorcist-98.vercel.app/?demo=trifecta) | Three harmless-looking steps across three servers: read an issue someone wrote, read a `.env`, send a message. The Shield holds the outgoing message (the Session Guard, EX-027). |
Prefer to watch first? The README opens with a 21-second recording of the rug pull.
## 5 minutes on your own machine
Needs Node 20 or newer.
1. **Scan a project:** `npx -y @exorcist-98/cli scan .` prints each finding with its file, line, quoted text and fix, then a verdict (`CLEAN`, `HAUNTED` or `POSSESSED`). The exit code is 1 when it finds threats.
2. **Add it to Kiro as a Power:** in Kiro, open the Powers panel, choose *Add Custom Power*, then *Import power from a repository URL*, and paste `https://github.com/pranavsaji/exorcist-98/tree/main/power`.
3. **Set up a Kiro project:** `npx -y @exorcist-98/cli init --kiro` adds Kiro hooks, a steering file and a read-only reviewer agent, and prints each file it writes. Note that npm has an older release than this repository (see the limits below).
## Check each claim
Each row can be run, and each has an expected result. "Web" rows use the live site; "terminal" rows run from a clone after `pnpm install` and `pnpm --filter @exorcist-98/cli build`.
| Scenario | How to run it | What Exorcist 98 does | Expected result |
|---|---|---|---|
| Haunted Repo scan (web) | the first link above | Runs the real scanner on 22 defanged attack files | Verdict: POSSESSED, with the line and quoted text for every finding |
| Haunted Repo scan (terminal) | `node packages/cli/dist/index.mjs scan fixtures/haunted-repo` | Same scan, offline | Exit code 1, <!--f:hauntedRepoFindings-->47<!--/f--> threats, "Verdict: POSSESSED" |
| A clean folder | `node packages/cli/dist/index.mjs scan <an empty or ordinary folder>` | Finds nothing to report | Exit code 0, "Verdict: CLEAN" |
| This repository's own README | `node packages/cli/dist/index.mjs scan README.md` | A test fails the build if our own README is flagged | "Verdict: CLEAN" |
| Rug pull (web) | the second link above | Replays one attack through the real Shield engine and once without it | "Result: compromised." without the Shield, "Result: protected." with it |
| Rug pull (real processes) | `node scripts/demo-rug-pull.mjs` | Pins the tool, sees its description change, hides it, refuses the call | The tool list loses `read_note`; a critical EX-006 alert with a diff; "calls received by the real server: 1 (only the first one)" |
| Lethal Trifecta (web) | the third link above | Tracks one session across three servers | The outgoing message is held, with EX-027 named |
| The published packages work | `node scripts/published-shape.mjs` | Packs the CLI and the MCP server, installs the tarballs in an empty folder and checks them | Six `PASS` lines and "The published shape works." |
| The whole test suite | `pnpm vitest run` | Runs every test, including the checks above | <!--f:tests-->2,738<!--/f--> tests pass |
If your shell sets `PYTHONSTARTUP`, the Shield refuses to start the demo server (EX-025, a program-loader variable). Unset it for that run.
## Where to look for each judging question
| Question | Where to look |
|---|---|
| **Potential impact:** who is hurt and how much it helps | [`FIELD_REPORT.md`](FIELD_REPORT.md) (<!--f:fieldReport.repos-->483<!--/f--> public repositories scanned), [`BENCHMARK.md`](BENCHMARK.md) (attacks caught and look-alikes left alone), [`INCIDENTS.md`](INCIDENTS.md) (two published attacks on Kiro and the rules they led to), [`THREATS.md`](THREATS.md) |
| **How Kiro was used** | [`HOW_KIRO.md`](HOW_KIRO.md) (feature by feature, with what surprised us), [`KIRO_LOG.md`](KIRO_LOG.md) (the dated record, including what Kiro did not do), [`.kiro/specs/`](../.kiro/specs) (<!--f:specs-->24<!--/f--> specs), [`.kiro/steering/`](../.kiro/steering), [`.kiro/hooks/`](../.kiro/hooks), [`.kiro/agents/`](../.kiro/agents), [`power/`](../power) |
| **Design** | The live site; [`apps/web/src/components/`](../apps/web/src/components) (the desktop, windows and scan log); [`.kiro/steering/ui.md`](../.kiro/steering/ui.md) (the rules: infection levels in words, keyboard use, contrast); screenshots in [`docs/media/`](media) |
| **What is new** | [How this differs from tools that already exist](REFERENCE.md#how-this-differs-from-tools-that-already-exist) (with sources, and where others do more); [`definitions/`](../definitions) (open virus definitions); [`packages/shield/src/session.ts`](../packages/shield/src/session.ts) (the Session Guard); [`INCIDENTS.md`](INCIDENTS.md) |
## The honest limits
- Detection is mostly signatures, so a reworded attack can get past it unless the optional AI judge is on; our benchmark counts known patterns and is not a measure of real-world recall.
- Releasing a held call in the system prompt (Touch ID or login password) works on macOS only. Npm has 0.1.2 of the CLI; this repository is at 0.2.0 (the gate, the baseline and the incident rules), so `npx` runs an older build until 0.2.0 is published.
- Most Kiro checks were seen working in Kiro IDE, but not all (the two custom agents have not been loaded there). Every known gap, with how sure we are of it, is in [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md).
