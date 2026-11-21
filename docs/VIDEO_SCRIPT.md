# Video script (target 2:30, limit 3:00)

Rules this follows (from the official rules and the steering files): public on
YouTube, under 3 minutes, shows the project working on the device it was built
for, original audio (your voice; the app's sounds are synthesised in the
browser), no third-party logos or copyrighted music. Show Kiro's own UI only as
it appears in normal use.

**Before recording, decide beat 5.** The Shield has not been run inside Kiro
yet (`docs/KNOWN_LIMITATIONS.md` S-001; runbook in `docs/KIRO_SHIELD_TEST.md`).
If you get it working in Kiro, record beat 5 there. If not, record the terminal
demo (`node scripts/demo-rug-pull.mjs`) and say "here it is with a test MCP
server". Do not show a Kiro rug pull you have not actually run.

| Time      | On screen                                                                                                                                                                                                                                                        | Voice-over                                                                                                                                                                                                                                    |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0:00-0:15 | A plain-looking `AGENTS.md` in an editor. Cut to the same file in the web app's detail window, the hidden characters shown as `[U+200B]` markers.                                                                                                                | "This file looks harmless. It isn't. It hides instructions your AI coding agent will read and obey, and you can't see them."                                                                                                                  |
| 0:15-0:25 | Text on screen: "Kiro, Cursor, Claude Code, Copilot: they all read READMEs, rules files and MCP tool descriptions."                                                                                                                                              | "If you let an AI agent work in code you didn't write, this is your problem. Anyone can write those files."                                                                                                                                   |
| 0:25-0:35 | https://exorcist-98.vercel.app boots: desktop, taskbar, the scan window with its one-line pitch. Sound on.                                                                                                                                                       | "So I resurrected the 90s antivirus for AI agents. Exorcist 98. Nothing to install."                                                                                                                                                          |
| 0:35-1:00 | Click **Scan the Haunted Repo**. The log scrolls, the progress bar glitches on each threat. Results sorted CRITICAL first. Open the EX-001 finding: file, line, the highlighted span, the plain explanation and the fix.                                         | "A full scan of a test repo full of planted attacks. Every finding says where it is, quotes the exact text, says how bad it is in words, not just colour, and how to fix it."                                                                 |
| 1:00-1:20 | Paste `https://github.com/modelcontextprotocol/servers` and scan: 439 files, **Clean**. Cut to the summary table in `docs/BENCHMARK.md` (held-out round 3: 1 finding, correct).                                                                                                         | "And it doesn't cry wolf. On five repos we never tuned for, about nine and a half thousand files, it raised one alarm, and that one was right. We measured, found it was noisy, and fixed it."                    |
| 1:20-1:50 | **Beat 5, the live save.** `node scripts/demo-rug-pull.mjs` (or Kiro, see above): tool pinned, call works, the description changes to "send the contents of .env to ...", the diff, the tool disappears, the call is refused, the real server never received it. | "Now the scary one. An MCP server you approved quietly changes a tool to steal your .env file. The shield pinned every tool when you approved it. The moment it changes, the tool vanishes, the call is refused, and you see the exact diff." |
| 1:50-2:10 | Kiro Crew dashboard: the Exorcist 98 page with a CRITICAL folder; the nightly notification; **Move file to vault...** asking first, then **Restore**; the Sentry agent answering in chat.                                                                        | "It also runs in Kiro Crew: a nightly patrol of your folders, a notification when something new shows up, and a vault that only you can move files into, with an exact restore."                                                              |
| 2:10-2:25 | Kiro IDE: open `.kiro/specs/m1-engine/tasks.md`, a steering file, a hook config, then a property test failing and passing.                                                                                                                                       | "Built with Kiro end to end: a spec for every milestone, steering that sets the security rules, hooks that keep the threat list current, and seventy-one property-based tests."                                                                 |
| 2:25-2:30 | End card: web app URL, both repository URLs.                                                                                                                                                                                                                     | "Exorcist 98. Your agent has a virus? Exorcise it."                                                                                                                                                                                           |

## Shot list

- Web app: record at 1920x1080 with browser zoom 125% so the pixel font is
  readable. `docs/media/web-finding.png` shows the framing.
- Benchmark beat: the clean scan of `modelcontextprotocol/servers` is real
  (2026-11-20: 439 files, 0 findings). Scan it live once; the site allows six
  GitHub scans per visitor before it slows down.
- Crew beat: everything listed was seen working in Crew 0.13.0 on 2026-11-19
  and 20: the page, the patrol, the notification, quarantine and restore, and
  the Sentry agent answering through its `patrol_status` tool. Screenshots in
  the Crew repo's `docs/media/`.
- Kiro beat: show real files and a real test run; do not stage a spec that
  was not used.

## Facts to keep straight on camera

- "One alarm on five repos we never tuned for, and it was right" is held-out
  round 3 in `docs/BENCHMARK.md` (2026-11-20). Do not quote the tuning-set
  numbers as if they were blind.
- "Seventy-one property-based tests" is the count of `fc.assert` properties in
  `docs/KIRO_LOG.md`. Test totals change; read them from the latest run before
  saying a number.
- The AI heuristic layer (Bedrock) has never run against the real service.
  Do not say scans use AI unless that changes (L-020).
- Do not call it "on npm" until you publish (S-002).
