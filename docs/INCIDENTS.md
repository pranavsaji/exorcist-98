# Published attacks on Kiro, and what Exorcist 98 does about them

Two disclosed incidents were used as the target of spec `m8-incidents`
(`.kiro/specs/m8-incidents/`). Both are fixed in Kiro itself. This page is about
what happens if someone copies the idea against your project, and which layer
of Exorcist 98 would stop it. The samples in `fixtures/benchmark/` are defanged
replicas written for this repository (`example.invalid` hosts, fake secrets).
They are not the researchers' payloads.

## Incident 1: CVE-2026-10591, hidden text rewrites the MCP config

**What happened.** Intezer and Kodem found that a web page could carry
instructions in text a person cannot see (white, one pixel high). When a
developer asked Kiro to summarise the page, Kiro rewrote
`~/.kiro/settings/mcp.json` and started an attacker-defined MCP server without
asking. It was fixed in Kiro IDE 0.11.130.
Source: <https://research.intezer.com/blog/2026/07/remote-code-execution-kiro/>

**What stops a copy.**

| Layer | What it does | Rule or file |
|---|---|---|
| Scanner | Reports hidden text that talks to the AI, in HTML, Markdown and tool results. | EX-028, `definitions/EX-028-hidden-text.yaml`, `packages/core/src/hidden-text.ts` |
| Shield | The tool-result check withholds a fetched page that contains such text, so the agent never reads it. | EX-028 (high is a blocking level) |
| Hook | A Kiro `PreToolUse` hook asks a person before any agent write to `.kiro/settings/mcp.json`, in a project or the home folder. On macOS a system dialog asks; elsewhere a code is typed at the terminal. With nobody to ask, the write is blocked. | `.kiro/hooks/mcp-config-write-guard.json`, `exorcist guard-mcp-write` |

The hiding methods EX-028 knows are: white or near-background colour, font size
at or under 2px, `display:none`, `visibility:hidden`, `opacity:0`, off-screen
position, and a zero-size box. It reports only when the hidden text names the AI
or asks for an action. A closed modal or a screen-reader label stays quiet.

**Tests that prove it.**

- Scanner, all seven methods fire and each look-alike stays quiet:
  `packages/core/src/__tests__/hidden-text.test.ts`, "EX-028 hidden text: the
  seven hiding methods" (`<method>: fires when the hidden text gives orders`,
  `<method>: the same style around ordinary text stays quiet`) and "EX-028
  quiet look-alikes" (`a closed modal, a screen-reader-only label and a collapsed
  menu are not reported`).
- Benchmark replica: `packages/core/src/__tests__/benchmark.test.ts`,
  `attack cve-2026-10591-hidden-page is caught by EX-028`; look-alike
  `benign hidden-ui-text produces no findings`.
- Shield withholds the page:
  `packages/shield/src/__tests__/simulator.test.ts`, `hidden web text: the config
  is written without the Shield, and EX-028 withholds the page with it`.
- Hook: `packages/cli/src/__tests__/guard-mcp-write.test.ts`, `Deny blocks with
  exit 2 and a message that never quotes the content` and `with no dialog and no
  terminal it blocks`.

You can watch the Shield part in the web app: Possession Lab, "The Hidden Page"
(`?demo=hidden-web-text`). It shows the Shield layer. It does not show the CVE
or Kiro's fix.

## Incident 2: Mindgard, instructions in file names, and Powers registry fetching

**What happened.** Mindgard showed that instructions hidden in the names of
files and folders in a project, combined with Kiro Powers registry fetching,
could make data leave the machine. An earlier Mindgard finding used a steering
file that told the agent to put local data into a Markdown image URL. Both are
fixed in Kiro IDE 0.8.140.
Sources:
<https://mindgard.ai/disclosures/amazon-kiro-ide-data-exfiltration-via-filename-prompt-injection-and-kiro-powers-registry-fetching>
and <https://thehackernews.com/2026/08/amazon-kiro-prompt-injection-can.html>

**What stops a copy.**

| Layer | What it does | Rule or file |
|---|---|---|
| Scanner | Checks the name of every path the walker visits (folders, empty, binary and oversize files too) for names that read as orders to an AI, or that carry hidden or control characters. Each distinct name is reported once. | EX-029, `definitions/EX-029-possessed-filename.yaml`, `packages/core/src/path-names.ts` |
| Scanner | Reports a sentence that tells the reader to send env files, credentials, tokens or keys to a destination. | EX-002, the exfiltration alternative |
| Scanner | Reports a steering file that tells the agent to put data into an image URL. | EX-012 (existing rule) |
| Hook | The MCP config write guard above also covers the step where a copy would add its own server. | `exorcist guard-mcp-write` |

The Shield does not read file names, so there is no Shield layer for this
incident.

**Tests that prove it.**

- File names: `packages/core/src/__tests__/path-names.test.ts`, `flags names
  that read as orders to an AI`, `flags hidden and control characters and shows
  them escaped`, `reports an instruction-like folder once, at the folder path,
  line 1`, `reports hidden-character names in empty, binary and oversize files
  and in a nested folder`, `keeps ordinary long and odd names quiet`.
- Benchmark replicas: `benchmark.test.ts`,
  `attack mindgard-possessed-filenames is caught by EX-029 and EX-002` and
  `attack mindgard-steering-image-url is caught by EX-012`; look-alike
  `benign long-odd-filenames produces no findings`.
- Exfiltration sentence: `packages/core/src/__tests__/ex002-exfiltration.test.ts`,
  `reports orders to send secrets to a destination`, and the quiet cases
  `negated sentences are quiet` and `has no exfiltration finding`. Benchmark
  look-alike: `benign negated-exfil-docs produces no findings`.

Names containing hidden characters are not committed in the fixture, because
git and editors change them. The tests build them from code points.

## What is not covered

- **Hidden text in images.** EX-028 reads markup and text. Words drawn in a
  picture, or in a PDF or screenshot a model reads with vision, are not seen.
- **Hidden instructions in ordinary visible words.** A page or file name that
  gives orders in plain wording a person could also read is only caught if it
  matches a rule (EX-002 and others). A reworded attack can pass. The Detonation
  Chamber results in `docs/DETONATION.md` show how often.
- **Writes the guard does not see.** The guard checks Kiro's write and shell
  tools. Shell commands are read best-effort: redirects (`>`, `>>`), `tee`,
  `sed -i`, `cp` and `mv` are seen. A command built at run time, a program that
  writes the file by itself, or a tool outside those categories is missed. A
  `cd` before a relative path is also missed: the guard resolves the path
  against the folder Kiro reports, not against where an earlier `cd` in the same
  command moved to.
- **The guard matches any `.kiro/settings/mcp.json`.** It does not know which
  one is yours. A write to such a file in any folder asks for confirmation, and
  a `mcp.json` that is a symlink is followed.
- **The typed-code fallback.** Without a native dialog the guard asks for a code
  typed at a terminal. That shares the weakness noted for the read approval
  (`allow-read`) in `docs/KNOWN_LIMITATIONS.md` (S-027): an agent that runs as
  the same user can in principle read the code from a real terminal. The macOS
  dialog is stronger. The prompt itself has been checked by hand, not by
  automated tests.
- **Powers registry fetching.** The fetching that Mindgard combined with the
  file names is a Kiro feature. Exorcist 98 does not watch or limit it. A copy of
  the attack would be caught only at the name, and only if the name matches EX-029.
- **File names with plain instructions that look ordinary.** EX-029 is tuned to
  stay quiet on long and odd names. A short or well-disguised name can pass.

## What changed in the repository

- **New rules.** EX-028 (hidden text that instructs the AI) and EX-029 (file or
  folder name that instructs the AI). EX-002 gained an alternative for
  exfiltration orders: send, upload, post, forward, email or paste an env file,
  credentials, tokens or keys to a destination. Negated and quoted sentences stay
  quiet, as before.
- **The README Problem sentence is now reported.** The Problem section of
  `README.md` used to quote an exfiltration sentence as an example of an attack.
  It used to scan clean, and with this change it became an EX-002 finding. That
  is correct, so in release 0.2.0 the README no longer quotes it: it describes
  the attack in words, and the working sentence lives in the benchmark case
  `fixtures/benchmark/attacks/exfil-sentence-docs` (the Haunted Repo's EX-002
  sample covers the same kind of order). `exorcist scan README.md` is clean, the
  on-access hook lets an agent read it, and the CI dogfood scan
  (`.github/workflows/exorcist.yml`) scans `README.md` again. This page does not
  repeat the sentence, so that it does not trigger the rule too.
- **Haunted Repo snapshot unchanged.** `packages/core/src/__tests__/haunted-snapshot.test.ts`
  (`finds exactly the expected (rule, file, line) set`) passes without edits to
  the snapshot, so the new rules add no finding there.
- **Benchmark.** Six new cases (three attacks, three look-alikes). The corpus is
  now 24 attacks and 24 look-alikes, all caught or left alone. We wrote it, so it
  shows coverage of known patterns, not real-world recall.
- **Hook and init.** `.kiro/hooks/mcp-config-write-guard.json`, and
  `exorcist init --kiro` writes `exorcist-mcp-write-guard.json` (disabled under
  the default command, which lacks `guard-mcp-write`).
- **Possession Lab.** An eighth attack, `hidden-web-text`.

## Traceability: requirement to test

Requirements are in `.kiro/specs/m8-incidents/requirements.md`. Paths are
relative to the repository root. "Review" means no automated test exists and
the item was checked by reading.

| Req | Test (file, name) |
|---|---|
| 1.1, 1.6 | `packages/core/src/__tests__/hidden-text.test.ts`, "EX-028 hidden text: the seven hiding methods"; `near-white colour and a colour equal to the element background both count` |
| 1.2 | `hidden-text.test.ts`, `a closed modal, a screen-reader-only label and a collapsed menu are not reported`; `addressesAi` tests |
| 1.3 | `hidden-text.test.ts`, `carries file, line and a span of at most 121 characters` |
| 1.4 | `packages/shield/src/__tests__/simulator.test.ts`, `hidden web text: the config is written without the Shield, and EX-028 withholds the page with it` |
| 1.5 | `benchmark.test.ts`, `attack cve-2026-10591-hidden-page is caught by EX-028`; `hidden-text.test.ts` `fires when the hidden text gives orders` (also scans as `docs`) |
| 2.1, 2.4 | `packages/core/src/__tests__/path-names.test.ts`, `flags names that read as orders to an AI`; `flags hidden and control characters and shows them escaped`; `caps the span` |
| 2.2 | `path-names.test.ts`, `visits directories, empty, binary and oversize files, and skips SKIP_DIRS`; `reports an instruction-like folder once, at the folder path, line 1` |
| 2.3 | `path-names.test.ts`, `keeps ordinary long and odd names quiet`; `stays quiet on ordinary odd names`; `no benign benchmark case, haunted repo or wild-scan fixture path is flagged`; property test `never throws, and flags no name made of ids and digits` |
| 2.5 | `haunted-snapshot.test.ts` and the whole benchmark suite, which pin the other findings |
| 2.6 | `path-names.test.ts`, `reports hidden-character names in empty, binary and oversize files and in a nested folder` and the tests above |
| 3.1 | `packages/core/src/__tests__/ex002-exfiltration.test.ts`, `reports orders to send secrets to a destination`; `reports the README "Problem" sentence` |
| 3.2 | `ex002-exfiltration.test.ts`, `negated sentences are quiet`; `a quoted example in a warning is quiet` |
| 3.3 | `ex002-exfiltration.test.ts`, `has no exfiltration finding` |
| 3.4 | `ex002-exfiltration.test.ts`, `reports the README "Problem" sentence` (reads the benchmark case that now holds it); `packages/cli/src/__tests__/cli.test.ts`, the on-access test reads the real `README.md` and expects it to be allowed and clean |
| 4.1 | `packages/cli/src/__tests__/guard-mcp-write.test.ts`, `finds the project config by relative path, ../ and ~`; `finds a config reached through a symlink, and through any key` |
| 4.2 | `guard-mcp-write.test.ts`, `at a terminal without a dialog, the right typed code allows and a wrong one blocks; the code goes to the terminal, not stdout` |
| 4.3 | `guard-mcp-write.test.ts`, `with no dialog and no terminal it blocks`; `a prompt nobody answers times out and blocks`; `Deny blocks with exit 2 and a message that never quotes the content` |
| 4.4 | `guard-mcp-write.test.ts`, `ignores other files and non-events`; `allows other writes, other events and unparseable input without asking` |
| 4.5 | `guard-mcp-write.test.ts`, `a click on Allow confirms: exit 0, file named, content never shown`; `Deny blocks with exit 2 and a message that never quotes the content` |
| 4.6 | `packages/cli/src/__tests__/repo-files.test.ts`, `the MCP config write guard runs before write and shell tools, with a timeout above the dialog's`; `kiro-hook.test.ts`, `every command hook in this repo goes through it, never a bare pnpm, npx or node` |
| 4.7 | `packages/cli/src/__tests__/init-kiro.test.ts`, `the MCP write guard is written disabled under the default command, enabled under a local --bin` |
| 4.8 | `guard-mcp-write.test.ts`, "decideMcpWrite: shell write forms" (`sees: <command>` for each form; `leaves reads and unrelated writes alone`) |
| 4.9 | `guard-mcp-write.test.ts` (every test uses fake dependencies: dialog, terminal and clock) |
| 5.1, 5.2, 5.3 | `packages/core/src/__tests__/benchmark.test.ts`, `attack <name> is caught by ...` and `benign <name> produces no findings` for the six new cases and all earlier ones |
| 5.4 | `benchmark.test.ts`, `every name in labels.json is safe` (names only). Hosts and secrets in the fixtures were checked by review. |
| 5.5 | `packages/core/src/__tests__/haunted-snapshot.test.ts`, `finds exactly the expected (rule, file, line) set; review any change to the snapshot on purpose` (no change needed) |
| 6.1, 6.2 | `simulator.test.ts`, `hidden web text: the config is written without the Shield, and EX-028 withholds the page with it`; `apps/web/src/__tests__/shield-sim-route.test.ts`, `replays it: the config is written without the Shield, and EX-028 withholds the page with it` |
| 6.3 | `apps/web/src/__tests__/deeplink.test.ts` (`?demo=hidden-web-text`); `components.test.tsx`, `opens on the hidden-web-text attack from a deep link, with the attack group labelled`; `shield-sim-route.test.ts`, `is listed as the eighth attack` |
| 6.4 | `simulator.test.ts`, same test as 6.1 (summary contains "Shield layer" and "0.11.130") |
| 6.5 | `scripts/e2e-chrome.mjs`, step `Possession Lab: every attack ends with the shielded side protected` (clicks "The Hidden Page" and steps to the end); a later step opens `?demo=hidden-web-text` and plays it with no clicks; the unit tests above |
| 7.1, 7.2 | Review. No automated test reads this page; it is scanned with `exorcist scan docs/INCIDENTS.md`, which must report nothing. |
| 7.3 | Review (`docs/KIRO_LOG.md`) |
| 7.4 | `apps/web/src/__tests__/severity-plain.test.ts`, `every definition in definitions/ has a plain-language entry`; counts in README and `docs/THREATS.md` by review |
| 7.5 | Review (`docs/KNOWN_LIMITATIONS.md`) |
| 8.1 | `pnpm -r typecheck` and `pnpm vitest run` from the repository root |
| 8.2 | `benchmark.test.ts` (all cases) and `haunted-snapshot.test.ts` |
| 8.3 | `pnpm -r typecheck` (strict, no `any`); no dependency was added (review of `package.json` diffs) |
| 8.4 | This table |
