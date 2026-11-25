# Feature brief: catch the published Kiro attacks

Write a Kiro spec in `.kiro/specs/m8-incidents/` (requirements, design, tasks),
then implement every task. Follow `.kiro/steering/`. All attack samples must be
defanged (`.invalid` hosts, obviously fake secrets) and kept in
`fixtures/benchmark/` with labels, like the existing corpus.

## Real incidents to cover (read the sources; do not copy their payloads)

1. **CVE-2026-10591** (Intezer and Kodem, fixed in Kiro IDE 0.11.130):
   https://research.intezer.com/blog/2026/07/remote-code-execution-kiro/
   A web page carried instructions in hidden text (white, one-pixel). When the
   developer asked Kiro to summarise the page, Kiro rewrote
   `~/.kiro/settings/mcp.json` and started an attacker-defined MCP server
   without asking.
2. **Mindgard, Kiro Powers and filenames** (fixed in Kiro IDE 0.8.140):
   https://mindgard.ai/disclosures/amazon-kiro-ide-data-exfiltration-via-filename-prompt-injection-and-kiro-powers-registry-fetching
   and https://thehackernews.com/2026/08/amazon-kiro-prompt-injection-can.html
   Instructions hidden in file and folder NAMES of a project, combined with
   Powers registry fetching, led to data leaving the machine. An earlier
   Mindgard finding used a steering-file directive to put local data into a
   Markdown image URL.

## Build

- **Hidden-text rule (new EX id):** text styled to be invisible to a person
  (white or near-background colour, font size at or under 2px, `display:none`,
  `visibility:hidden`, `opacity:0`, off-screen positioning, zero-size boxes) in
  HTML, Markdown and tool results, when the hidden text addresses the AI or asks
  for actions. Report it in files and in the Shield's tool-result check (results
  that look like attacks are already withheld; make sure this kind is).
- **Possessed-filename rule (new EX id):** file and folder names (path
  segments) that read as instructions to an AI or carry encoded or hidden
  characters. Scan the names of every walked path, not only contents. Keep
  ordinary long or odd names quiet (test against the benchmark look-alikes and
  the field-report repos' file lists if available).
- **Exfiltration instruction (EX-002 variant):** a sentence that tells the
  reader to send, upload or post environment files, credentials or secrets to a
  destination. The README "Problem" section quotes such a sentence and today
  `exorcist scan` reports it CLEAN; it must be caught. Keep negated sentences
  (defences) quiet, as m7 did.
- **MCP config tamper:** the agent writing to `.kiro/settings/mcp.json` or
  `~/.kiro/settings/mcp.json` is how CVE-2026-10591 worked. Add a PreToolUse
  Kiro hook (in `.kiro/hooks/`, Kiro's JSON format, like `on-access-scan`) and an
  `exorcist` CLI helper it calls, that blocks an agent write to an MCP config
  unless the person confirms at a real terminal or system prompt (reuse the
  existing person-only confirmation and the m6 OS prompt where available). Also
  make `exorcist init --kiro` install it. Check Kiro's hook docs for the right
  tool name for file writes.
- **Incident replicas:** one defanged replica per incident in the labelled
  corpus, plus look-alikes that must stay quiet. Benchmark must still catch all
  earlier attacks and leave all look-alikes alone; the Haunted Repo snapshot may
  only change if a new rule adds a true finding (explain each change).
- **docs/INCIDENTS.md:** for each incident: what happened (two sentences, with
  the source link), which Exorcist layer stops a copy of it (scanner rule, Shield,
  hook), and the test that proves it. No overclaiming: say what is not covered.
- Possession Lab (web): add an eighth attack, "Hidden web text rewrites your MCP
  config" (based on CVE-2026-10591), replayed with and without the Shield, like
  the others. Keep the e2e suite passing and add a step for it.
- A row in `docs/KIRO_LOG.md` for this work by the Kiro IDE agent.

Run `pnpm -r typecheck` and `pnpm vitest run`. Commit. Do not push.
