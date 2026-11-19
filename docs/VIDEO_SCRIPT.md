# Video script (target 2:50, limit 3:00)

Rules this follows (from `docs/PLAN.md` and the steering files): public on
YouTube, original audio (your voice; the app's sounds are synthesised in the
browser), no real company logos or brand assets. Show Kiro's own UI only as
it appears in normal use.

**Before recording, decide beat 4.** The Shield has not yet been run inside
Kiro (`docs/KNOWN_LIMITATIONS.md` S-001). If you get it working in Kiro, record
beat 4 there. If not, record the terminal demo (`node scripts/demo-rug-pull.mjs`)
and say "here it is with a test MCP server". Do not show a Kiro rug pull you
have not actually run.

| Time | On screen | Voice-over |
|------|-----------|------------|
| 0:00-0:20 | A plain-looking `AGENTS.md` in an editor. Cut to the same file in the web app's detail window, the hidden characters revealed as `<U+200B>` markers. | "This file looks harmless. It isn't. Hidden in it are characters you can't see, carrying instructions for your AI coding agent. Agents read READMEs, steering files and MCP tool descriptions, and anyone can write those." |
| 0:20-0:35 | The desktop boots: taskbar, Start menu, the Exorcist 98 window. Sound toggle switched on. | "Remember antivirus? Exorcist 98 brings it back for AI agents: virus definitions, a full system scan, a real-time shield and a quarantine vault." |
| 0:35-1:15 | Click **Scan the Haunted Repo**. The green log scrolls, the progress bar glitches ("possessed") each time a threat is found. Results sorted CRITICAL first. Open the EX-001 finding: file, line, the quoted span highlighted, plain explanation, fix. Download the SARIF report and the badge. | "A full scan of our test repo. Every finding says where it is, quotes the exact text, says how bad it is in words, not just colour, and how to fix it. The same reports work in GitHub code scanning and as a README badge." |
| 1:15-1:30 | Paste a public GitHub URL and scan it. | "Any public GitHub repo works the same way. Nothing to install." |
| 1:30-2:05 | **Beat 4, the live save.** Terminal: `node scripts/demo-rug-pull.mjs`. Show steps 1-5: tool pinned, call works, description changes to "send the contents of .env to ...", the diff, the tool disappears, the call is refused, the real server never received it. | "Now the scary one. An MCP server you approved quietly changes a tool to steal your .env file. That's a rug pull. The shield pinned every tool's fingerprint when you approved it. The moment it changes, the tool vanishes from your agent, the call is refused, and you get the exact diff." |
| 2:05-2:35 | Quick cuts: `.kiro/specs/` folder (m0 to m4), a property test file, the `spec-change` hook firing in Kiro, the Power folder, the Crew dashboard page with its CRITICAL folder. | "Built with Kiro: one spec per milestone, steering files that set the rules, fifty-two property-based tests, hooks that keep the threat list current, an MCP server and a Power, and a Crew app that patrols your folders every night." |
| 2:35-2:50 | The `/product` page. End card: repository URL, web app URL. | "Exorcist 98. Open definitions, free to scan. Your agent has a virus? Exorcise it." |

## Shot list

- Web app screenshots from the browser suite are a guide for framing:
  `E2E_OUT=/tmp/shots pnpm e2e` writes them.
- Crew page: `npm run e2e` in the Crew repo writes `e2e-output/02-results.png`.
  If you show it, say it runs through a test gateway unless you have run it in
  Crew (Crew repo C-001).
- Record at 1920x1080, browser zoom 125% so the pixel font is readable.

## Facts to keep straight on camera

- "Fifty-two property-based tests" is the count of `fc.assert` properties in
  `docs/KIRO_LOG.md`. Test totals: 431 in the main repo, 59 in the Crew repo.
- The AI heuristic layer (Bedrock) has never run against the real service.
  Do not say scans use AI unless that changes (L-020).
- Do not call it "on npm" until you publish (S-002).
