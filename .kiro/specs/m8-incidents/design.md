# Design: m8-incidents

## Overview

Three new detections (hidden text, possessed names, exfiltration sentences), one guard for writes to MCP configs, replicas in the benchmark, an eighth Lab attack and a page of documentation. Detection is in `definitions/*.yaml` and small engine hooks; the guard is a CLI command called by a Kiro hook.

## Architecture

```
definitions/EX-028 (regex, file text)  ──> signature engine ──> scanRepo / scanText (Shield tool-result check)
definitions/EX-029 (analysis: path-names) ─> packages/core/src/path-names.ts ─> scanRepo (every walked path)
definitions/EX-002 (extra alternative) ─> signature engine (negated_cues, quoted_example_cues)
.kiro/hooks/mcp-config-write-guard.json ─> scripts/kiro-hook.sh ─> exorcist guard-mcp-write ─> packages/core/src/mcp-write-guard.ts
```

## Components and Interfaces

### 1. EX-028 hidden text

`definitions/EX-028-hidden-text.yaml`, `applies_to: instruction, docs, memory, tool-result, unknown`, severity high. The schema needs a way to ask for "an element hidden by style whose text addresses the AI". Add a `match.hidden_text: true` code check rather than one large regex:

- `packages/core/src/hidden-text.ts`: `findHiddenText(text): Array<{ index; length; method }>`. Pure. It finds an HTML element whose `style` attribute (or a `hidden` attribute, for `display:none` equivalents is not enough on its own) uses one of the seven methods, takes the element's text up to its closing tag (at most 2,000 characters), and keeps it only when `addressesAi(text)` is true. The same function handles Markdown by finding inline HTML in it.
- Colour: white (`#fff`, `#ffffff`, `white`, `rgb(255,255,255)`) or a colour within a small distance of white or of an explicitly set background on the same element. Size: `font-size` at or under 2px or 0. Position: `left` or `top` at or below -999px, `text-indent` at or below -999px. Zero box: `width:0` or `height:0` with `overflow:hidden`.
- `addressesAi`: the text names the AI (`assistant`, `agent`, `AI`, `Kiro`, `Claude`, `model`, `LLM`, `copilot`) or begins with or contains an imperative about an action (`write`, `edit`, `modify`, `run`, `execute`, `fetch`, `send`, `start`, `add`, `install`, `delete`) with an object (`file`, `config`, `server`, `command`, `settings`, `mcp`). Exact lists and tests decide the final shape; precision is tuned against the look-alikes.
- Schema: `match.hidden_text: z.boolean().optional()`, counted as a match kind in the `superRefine`. The signature engine calls `findHiddenText`, reports `span` as the hidden element's text (cap `MAX_SPAN`), line and column from the offset. A tool-result is scanned as role `tool-result`, so the Shield's `inspectResult` withholds it (high is a blocking severity); a test proves it. `plain.ts` gets headline and explanation text for the new ids.

### 2. EX-029 possessed filenames

`definitions/EX-029-possessed-filename.yaml` with `analysis: path-names`. The schema's `analysis` enum gains `path-names`; the signature engine skips it, like `trifecta` and `detonation`.

- `packages/core/src/path-names.ts`: `checkPathSegment(name): { kind: 'instruction' | 'hidden-chars'; span } | null`. Pure. `hidden-chars` uses the normalizer's hidden-character detection plus control characters. `instruction` needs an imperative aimed at an AI: it requires either the AI named (`assistant`, `agent`, `ai`, `claude`, `kiro`, `copilot`, `llm`) with an imperative, or an imperative sentence of at least four words with an action verb and a sensitive object (`ignore previous instructions`, `read env and send to`), with `-`, `_`, `.` and camel case treated as spaces. Names under four words and ordinary names (`ignore-previous-versions`, `please-read-me`) stay quiet.
- The walker gets `walkPaths(root)`: an async generator of every file and directory (relative path), including binary and over-size files, honouring the same `SKIP_DIRS`. `walkRepo` is unchanged for contents. `scanRepo` iterates distinct segments (a segment is checked once per distinct parent path), yields findings with the path as `file`, line 1, column 1.
- Report text goes through the existing terminal-safe display functions; the span escapes hidden characters as `[U+XXXX]`.

### 3. EX-002 exfiltration variant

An extra alternative in the EX-002 regex: a verb (`send|upload|post|forward|email|mail|paste|submit|copy|transmit`) within a short window of an object (`.env`, `environment file(s)`, `credentials`, `secrets`, `tokens`, `api keys`, `private key`, `ssh key`) and a destination (`to https?://`, `to <host>`, `to <address>`, `to the following`), in either order within one sentence. Existing `negated_cues` and `quoted_example_cues` apply. Because EX-002 already has `low_severity_paths`, test folders stay low severity. Tests: the README sentence, negated forms, and ordinary doc sentences.

### 4. MCP config write guard

- `packages/core/src/mcp-write-guard.ts`: `decideMcpWrite(event, home, cwd): { target: 'mcp-config' | 'other'; path?: string }`. Pure. Resolves `~`, relative paths against the event `cwd`, `..`, and symlinks (when the path exists, `realpath`; otherwise the realpath of its parent). Reads paths from known keys (`path`, `file_path`, `filePath`, `target`, `destination`, `file`) and any string value of `tool_input`, since tool names differ by Kiro version. A shell command is parsed best-effort for the write forms in requirement 4.8.
- `packages/cli/src/commands/guard-mcp-write.ts`: reads stdin, calls the decision, and for an MCP config target calls `personConfirms(term, io, dialogText)` with the file shown by name only. Exit 2 and a plain message on deny, no dialog, or no terminal; exit 0 otherwise. Registered in `packages/cli/src/index.ts` with help text.
- `.kiro/hooks/mcp-config-write-guard.json`: `PreToolUse`, matcher `write|shell` per Kiro's tool categories documentation (kiro.dev/docs/hooks/types), command `sh scripts/kiro-hook.sh node_modules/.bin/tsx packages/cli/src/index.ts guard-mcp-write`, timeout 150 (the dialog gives up after 120 seconds).
- `init.ts`: writes `.kiro/hooks/exorcist-mcp-write-guard.json`, runs through `.exorcist/kiro-hook.sh`, disabled under the default bin version that lacks `guard-mcp-write` (`COMMANDS_MISSING_FROM_DEFAULT`, the existing mechanism). The `init` help text and tests list it.

### 5. Corpus

Cases (names kebab-case): attacks `cve-2026-10591-hidden-page`, `mindgard-possessed-filenames`, `mindgard-steering-image-url`; benign `hidden-ui-text`, `long-odd-filenames`, `negated-exfil-docs`. Hosts `example.invalid`; a placeholder `EXAMPLE_TOKEN_DO_NOT_USE`. Filenames with hidden characters are created by the test from code points, not committed, because git and editors mangle them.

### 6. Possession Lab

`packages/shield/src/simulator.ts` gets scenario `hidden-web-text`. A fake `fetch_page` tool returns a defanged page (built at run time) with hidden text; unshielded, the agent then calls a write tool to put an attacker server into `~/.kiro/settings/mcp.json`, and the fake server records it; shielded, `inspectResult` withholds the result (EX-028). `SCENARIO_IDS`, `LAB_SCENARIOS`, the Lab's name list in `PossessionLab.tsx`, the deep link and the e2e step `Possession Lab: every attack ends with the shielded side protected` are extended. The summary says it shows the Shield layer, and that the CVE itself was fixed in Kiro.

## Data Models

`VirusDefinitionSchema.match` gains `hidden_text: boolean` and `analysis: 'path-names'`. No new persisted data.

## Error Handling

Errors are typed results. The guard fails open on input it cannot understand and fails closed (blocks) only for a confirmed MCP config target with no person available. A rule that times out leaves the existing medium timeout finding.

## Testing Strategy

Vitest for each rule (fires, quiet look-alikes, each hiding method), fast-check properties (adding ordinary text around hidden text does not change detection; `checkPathSegment` never throws and never flags a name made only of dictionary-free ids), benchmark and Haunted Repo snapshot tests, Shield `inspectResult` and simulator tests, CLI tests with fake terminals, hook JSON and init tests, and the e2e step. Requirement 8.4 is met by a traceability table at the end of `docs/INCIDENTS.md`.
