# Requirements Document

## Introduction

Spec m8-incidents: catch the published attacks on Kiro. Two disclosed incidents are the target. CVE-2026-10591 (Intezer and Kodem, fixed in Kiro IDE 0.11.130): a web page with hidden text made Kiro rewrite `~/.kiro/settings/mcp.json` and start an attacker-defined MCP server without asking. Mindgard's findings (fixed in Kiro IDE 0.8.140): instructions hidden in file and folder names, combined with Powers registry fetching, led to data leaving the machine, and an earlier steering-file directive put local data into a Markdown image URL. Sources are in `docs/INCIDENTS.md`. The samples are defanged replicas written for this repository, not copies of the researchers' payloads.

The README "Problem" section quotes an exfiltration sentence that `exorcist scan` reports CLEAN today. That is a known gap this spec closes.

## Requirements

### Requirement 1: Hidden text rule (EX-028)

**User Story:** As a developer who asks my agent to summarise a web page, I want text that a person cannot see, but that talks to the AI, to be reported, so that a page cannot give my agent orders.

#### Acceptance Criteria

1.1 A new definition `EX-028` (high) reports text styled to be invisible: white or near-background colour, font size at or under 2px, `display:none`, `visibility:hidden`, `opacity:0`, off-screen positioning, or a zero-size box. It applies to HTML, Markdown and tool results.
1.2 It reports only when the hidden text addresses the AI or asks for actions (for example names the agent or assistant, or tells the reader to write, edit, run, fetch, send or start something). Hidden text that does not (a closed modal, a screen-reader-only label, a collapsed menu) is not reported.
1.3 The finding carries the file, line, the quoted span (at most 120 characters) and a fix, and does not quote more than the engine's span limit.
1.4 The Shield's tool-result check withholds a tool result that contains such text, with a plain-language reason. A note-level result (not enough to withhold) is not produced for this rule.
1.5 Hidden text that a model reads but a person does not is also caught when the markup is in a `.html`, `.htm` or `.svg` file, which the walker already scans.
1.6 Each of the seven hiding methods has a test that fires, and each has a look-alike that stays quiet.

### Requirement 2: Possessed filename rule (EX-029)

**User Story:** As a developer opening a project I did not write, I want file and folder names that read as instructions to an AI to be reported, so that a name alone cannot steer my agent.

#### Acceptance Criteria

2.1 A new definition `EX-029` (high) reports a path segment (a file or folder name) that reads as an instruction to an AI, or that carries hidden or encoded characters (zero-width, bidi, tag-block and variation-selector characters, or control characters).
2.2 The scan checks the names of every path the walker visits: directories, empty files, binary files and files skipped for size, not only files whose contents are read. Each distinct path segment is reported once, with the repository-relative path as the file and line 1.
2.3 Ordinary long or odd names stay quiet: long kebab-case or snake-case names, names with spaces, dates and ids, non-Latin scripts, emoji, hash-like names, and names such as `ignore-previous-versions.md` or `please-read-me.txt`.
2.4 Names are untrusted text. The span is capped, and control and hidden characters are shown escaped (`[U+XXXX]`) in every report.
2.5 The rule runs in `scanRepo` with no change to the order or content of other findings.
2.6 Tests cover: an instruction-like folder name, a name with hidden characters, a name inside a skipped directory type that the walker still visits, and look-alikes that stay quiet.

### Requirement 3: Exfiltration instruction (EX-002)

**User Story:** As a developer, I want a sentence that tells the reader to send secrets somewhere to be reported, so that the README's own example of an attack is not scanned as clean.

#### Acceptance Criteria

3.1 EX-002 reports a sentence that tells the reader to send, upload, post, forward, email or paste environment files, credentials, tokens, keys or secrets to a destination (a URL, host, address or "to ..."). The README "Problem" sentence is reported.
3.2 A negated sentence (a defence such as "never send the .env file to a server") stays quiet, using the same `negated_cues` and `quoted_example_cues` mechanism as m7-precision.
3.3 Ordinary documentation stays quiet: "upload your build artifacts", "send a request to the API", "set the token in your environment".
3.4 `exorcist scan` on the repository root no longer reports the README "Problem" section as clean. If the same text appears in other docs of this repository, the finding is real, and the expected counts are updated and explained (Requirement 8).

### Requirement 4: MCP config tamper guard

**User Story:** As a developer, I want a person to confirm any agent write to an MCP config, so that a hidden instruction cannot add a server on its own, as in CVE-2026-10591.

#### Acceptance Criteria

4.1 A new CLI command `exorcist guard-mcp-write` reads a Kiro hook event on stdin. When the tool input targets `.kiro/settings/mcp.json` (in a project) or `~/.kiro/settings/mcp.json`, it asks the person to confirm. Paths are resolved first (`~`, `..`, relative to the event `cwd`, symlinks), so a spelling trick does not avoid the check.
4.2 The confirmation reuses the existing person-only mechanism (`personConfirms`, the OS dialog on macOS, a typed code at a real terminal). It never reads the answer from the agent's input, and it never relies on a terminal the agent's shell tool can answer.
4.3 When no person can be asked (no dialog, no terminal), the write is blocked (exit 2), with a message that says how to make the change by hand. A denied or timed-out prompt also blocks.
4.4 An event that is not a write to an MCP config exits 0. Input the command cannot understand (bad JSON, no path) exits 0, as the read hook does; it never blocks other tools.
4.5 The message never quotes the content the agent tried to write.
4.6 A hook file `.kiro/hooks/mcp-config-write-guard.json` (Kiro JSON, `PreToolUse`, matcher from the Kiro hooks documentation, runs through `scripts/kiro-hook.sh`) calls the command. Its timeout is longer than the dialog's.
4.7 `exorcist init --kiro` writes the hook, and the command is not called under a CLI version that lacks it (the hook is written disabled, as the on-access hook is under `@exorcist-98/cli@0.1.0`).
4.8 Shell commands that write to an MCP config (`>`, `>>`, `tee`, `sed -i`, `cp`, `mv`) are checked on a best-effort basis; this limit is stated in `docs/INCIDENTS.md`.
4.9 Tests use fakes only: no real dialog or terminal opens.

### Requirement 5: Incident replicas in the labelled corpus

**User Story:** As a maintainer, I want one defanged replica of each incident in the benchmark, with look-alikes that stay quiet, so that the rules are measured.

#### Acceptance Criteria

5.1 `fixtures/benchmark/attacks/` has a replica of CVE-2026-10591 (a saved web page with hidden text that asks the agent to edit an MCP config) and replicas of the Mindgard findings (a project tree with instruction-like names, and a steering file with a data-in-image-URL directive).
5.2 `fixtures/benchmark/benign/` has look-alikes: a page with ordinary hidden UI text, a project with long and odd names, a README with a negated exfiltration sentence.
5.3 `labels.json` names the rules each replica must trigger, and the benign list names the look-alikes. All earlier attacks are still caught and all earlier look-alikes still produce nothing.
5.4 Every host is `example.invalid`, every secret is obviously fake, and the safety tests for fixtures pass.
5.5 The Haunted Repo snapshot changes only if a new rule adds a true finding. Each change is explained in `docs/INCIDENTS.md`.

### Requirement 6: Possession Lab attack "Hidden web text rewrites your MCP config"

**User Story:** As a visitor to the web app, I want to watch the CVE-2026-10591 attack with and without the Shield, so that I can see what it does.

#### Acceptance Criteria

6.1 The Lab has an eighth scripted attack (id `hidden-web-text`) based on CVE-2026-10591, replayed through the real `ShieldEngine` with and without the Shield, in the same shape as the other seven.
6.2 Unshielded, the hidden text reaches the agent and the agent writes an MCP config that starts an attacker server. Shielded, the page result is withheld by EX-028.
6.3 The deep link `?demo=hidden-web-text`, the scenario list, the button label and the Lab's screen-reader labels include it. Everything in it is defanged and in memory.
6.4 The Lab says what it shows: the Shield layer. The fix for the CVE itself is in Kiro IDE 0.11.130.
6.5 The unit tests and the e2e suite pass, and the e2e suite has a step for the new attack (the Lab names list and a replay to the end).

### Requirement 7: Documentation

**User Story:** As a reader, I want to know what Exorcist 98 stops, what it does not, and which test proves it.

#### Acceptance Criteria

7.1 `docs/INCIDENTS.md` covers each incident: what happened in two sentences with the source link, which layer stops a copy (scanner rule, Shield, hook), and the test that proves it.
7.2 It says what is not covered: for example a page that hides text in an image, a hidden instruction that uses ordinary visible words, a write by a tool that is not a Kiro write tool or a shell command that the best-effort check misses, and Powers registry fetching itself.
7.3 `docs/KIRO_LOG.md` has a row for this work by the Kiro IDE agent, and the counts in it are correct.
7.4 `README.md`, `docs/THREATS.md` and any page that states the number of definitions are updated to the new count.
7.5 `docs/KNOWN_LIMITATIONS.md` marks the README exfiltration gap Fixed.

### Requirement 8: Nothing earlier breaks

**User Story:** As a maintainer, I want the golden path to keep working.

#### Acceptance Criteria

8.1 `pnpm -r typecheck` and `pnpm vitest run` pass from the repository root.
8.2 The benchmark catches all earlier attacks and leaves all earlier look-alikes alone. The golden path (scan the Haunted Repo, then block a rug-pulled MCP tool) is unchanged.
8.3 New code follows `.kiro/steering/`: strict TypeScript, no `any`, zod at boundaries, typed results, no new dependencies.
8.4 Each requirement above maps to at least one test.
