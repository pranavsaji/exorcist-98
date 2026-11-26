# Video script (target 2:55, limit 3:00)
Rules this follows (official rules and the steering files): public on YouTube,
under 3 minutes, shows the project working on the device it was built for,
original audio (your voice; the app's sounds are synthesised in the browser), no
third-party logos or copyrighted music. Show Kiro's own UI only as it appears in
normal use. Every number below comes from `docs/facts.json`.
Two beats need a Mac with you at the keyboard (1:30 needs Touch ID or a login
password) and one needs Kiro IDE. Rehearse them once off camera. Do not show
anything you have not actually run.
| Time | On screen | Voice-over |
| --- | --- | --- |
| 0:00-0:30 | **Kiro IDE.** A steering file that looks ordinary. The Exorcist 98 extension underlines it; the Problems panel lists the finding; the hidden characters are drawn as visible markers. Hover one: the decoded hidden message appears. Click the **Exorcise** quick fix: the markers go, one undoable edit. (Stills: `docs/media/kiro-extension-problems.png`, `-ouija-hover.png`, `-quickfix.png`, `-exorcised.png`.) | "This steering file looks harmless. It carries an invisible message that your AI agent reads and obeys. The extension shows where it hides, the hover decodes it, and one click removes it." |
| 0:30-1:00 | https://exorcist-98.vercel.app boots. Click **Scan the Haunted Repo**. The log scrolls, the bar glitches on each threat, the verdict reads POSSESSED. Open one finding: file, line, the highlighted quoted text, the plain explanation and the fix. | "Nothing to install. A full scan of a test repo full of planted attacks. Every finding gives the file, the line, the exact text, how bad it is in words, and how to fix it." |
| 1:00-1:30 | **A rug pull, blocked.** `/?demo=rug-pull` (or `node scripts/demo-rug-pull.mjs`): a tool is pinned, the call works, the description changes to ask for the `.env` file, the tool disappears, the call is refused, the diff is shown, and the real server never saw the call. Say it is a test MCP server. | "You approve an MCP server. Later it quietly changes one tool to steal your environment file. The Shield pinned every tool when you approved it. The moment one changes, it vanishes, the call is refused, and you see the exact diff." |
| 1:30-2:15 | **The lethal trifecta, on a Mac.** `node scripts/demo-touchid.mjs` in one window and `exorcist console` in another. Three steps, each harmless alone: a GitHub issue that hides an instruction, a read of a fake `.env`, then an email. The email is held and the Touch ID prompt opens. Leave it open for a beat, then **cancel**. The console shows the call as held, then blocked, as it happens. | "Here is the attack no single check catches. An issue with a hidden instruction. A read of the secrets file. Then a message going out. Each step is fine alone. The Session Guard remembers the whole session and holds the message. Only the system prompt, Touch ID, can release it. I cancel, and the console shows it held, then blocked." |
| 2:15-2:35 | The Field Report window (`/?open=field`) and the table in `docs/FIELD_REPORT.md`. | "We pointed the scanner at <!--f:fieldReport.repos-->483<!--/f--> real public repositories in <!--f:fieldReport.rounds-->3<!--/f--> rounds and read every serious alert by hand. The first round was noisy, so we fixed the rules and measured again on new repositories. Serious alerts fell from 4.0 to 0.24 per repository, and the last round found no real issue." |
| 2:35-2:50 | **Kiro IDE.** `docs/media/kiro-on-access-blocked-brief.png`: Kiro's agent tries to read a brief that quotes an injection phrase, and the on-access hook blocks the read. Cut to the same file after the owner rewords the line: the read goes through. | "And it guards itself. Kiro's own agent tried to read a brief that quoted an injection. Our hook blocked the read before the agent saw a word." |
| 2:50-2:55 | End card: the web address and the repository address. | "Exorcist 98. Your agent has a virus? Exorcise it." |
## Shot list
- Web app: record at 1920x1080 with browser zoom 125% so the pixel font is
  readable.
- 0:00 beat: use a steering file in a scratch workspace. The hidden message must
  be the defanged placeholder from `fixtures/haunted-repo`, never a real one.
- 1:30 beat: macOS only. The demo refuses to run in CI, in tests or off macOS.
  The Touch ID prompt is the operating system's own; do not blur or fake it.
  Cancel it on camera. If Touch ID is not set up, the login password works the
  same way.
- 2:35 beat: the screenshot is from 2026-11-24 (`docs/KIRO_LOG.md`). If you
  re-record it, use a brief that quotes an injection phrase, so the hook has
  something real to stop.
## Facts to keep straight on camera
- The rug pull is shown with a test MCP server, not with a real one. The first
  run inside Kiro found that Kiro caches the tool list; the Shield now checks
  every call, tested with real processes. Do not say a rug pull was blocked
  inside Kiro.
- The release in the system prompt is macOS only. On Linux and Windows a held
  session falls back to a typed code in a terminal (`docs/KNOWN_LIMITATIONS.md`,
  S-030). Say "on a Mac" when you show it.
- "No real issue in the last round" is Round 3 of `docs/FIELD_REPORT.md`
  (popular repositories, 2026-11-24). It was not held out from the fixes made
  after it. The held-out numbers are in Round 2 and in `docs/BENCHMARK.md`
  (held-out set C). Do not quote the tuning-set numbers as if they were blind.
- Do not say scans use AI. The AI judge is optional, needs your own AWS account,
  and is off on the public site unless the operator turns it on.
- Test and property counts change. Read them from `docs/facts.json` before you
  say one: <!--f:tests-->2,413<!--/f--> tests passed in the last recorded run.
- The Crew app is not in this video. Mention it in the written submission.
