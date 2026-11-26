# Implementation Plan: m11-config-tamper

## Overview
Rules first (EX-007 extension, EX-030, EX-031, EX-032, EX-028 extension), then the write guards (`guard-mcp-write` extension, `guard-web-fetch`, `guard-env-write`), then `init` wiring and the sandbox file, then the Possession Lab and benchmark fixtures, then docs and the record.

## Tasks

- [x] 1. EX-007 extension and EX-030/031/032 rule files
  - [x] 1.1 EX-007 extension: broad agent trust in committed settings (CT-1, CT-2, CT-3)
    - Read `definitions/EX-007-overbroad-autoapprove.yaml`; look up the exact setting name for Kiro trusted commands and for each of Claude Code, Cursor, Cline and Copilot in that agent's own current documentation; record every name and its source URL in `design.md`'s "What the documentation says" section (update it if a name differs from what is drafted there)
    - Extend `definitions/EX-007-overbroad-autoapprove.yaml` with the new file paths and `json_path`/`value_regex` branches for `.vscode/settings.json` (Kiro trusted commands), Kiro's own settings file, `.claude/settings*.json` (`permissions.allow`), Cursor and Cline settings, and Copilot's `chat.tools.terminal.autoApprove` map form
    - If Copilot's boolean-map form (or any other agent's form) cannot be expressed by EX-007's existing schema, create `definitions/EX-030-settings-tamper-instruction.yaml` instead for that one case and note the move in `design.md`
    - _Requirements: CT-1, CT-2, CT-3_
  - [x]* 1.2 Write unit tests for the EX-007 extension
    - One example per new agent settings shape (broad) and one narrow counter-example per agent
    - _Requirements: CT-1, CT-2, CT-3_
  - [x]* 1.3 Write property test for Properties 1 and 2
    - **Property 1: Narrow trust never fires CT-1/CT-2**, **Property 2: Broad trust always fires**
    - **Validates: Requirements CT-1, CT-2, CT-3**
  - [x] 1.4 EX-030: instructions to change agent settings or guard files (CT-4)
    - Create `definitions/EX-030-settings-tamper-instruction.yaml` (if not already created by 1.1), modeled on `EX-002`'s `regex`/`quoted_example_cues`/`negated_cues` shape, matching text addressed to an agent that asks it to change a Trusted-commands or auto-approve setting, or to edit `.kiro/hooks/`, `.kiro/agents/`, `.kiro/steering/` or `AGENTS.md`
    - Add an encyclopedia entry for EX-030 in `packages/core/src/plain.ts`
    - _Requirements: CT-4_
  - [x]* 1.5 Write unit tests for EX-030
    - One trigger-phrase example per target (settings file, `.kiro/hooks/`, `.kiro/agents/`, `AGENTS.md`) and one negated/quoted-example counter-example
    - _Requirements: CT-4_
  - [x] 1.6 EX-031: instructions to weaken tests or checks (CT-8, CT-9)
    - Create `definitions/EX-031-weaken-checks-instruction.yaml` covering `.skip`/`xit`/`test.todo`, deleting a test file "because it is flaky", `--no-verify`, `|| true` on a CI step, lowering a coverage threshold, and making a failing check pass, addressed to an agent, with `quoted_example_cues`/`negated_cues`
    - Add an encyclopedia entry for EX-031 in `packages/core/src/plain.ts`
    - _Requirements: CT-8_
  - [x]* 1.7 Write unit tests for EX-031 (attacks and the CT-9 counter-examples)
    - One example per phrase in the acceptance criteria; a test file that uses `.skip`/`xit`/`test.todo` as ordinary code; a CI file with `|| true`; documentation explaining `--no-verify` without addressing an agent
    - _Requirements: CT-8, CT-9_
  - [x] 1.8 EX-032: instructions to push or publish elsewhere (CT-10)
    - Create `definitions/EX-032-redirect-publish-instruction.yaml` covering pushing to a remote other than origin, adding a new remote, publishing a package, changing the package registry, and opening a pull request against a different repository, with `quoted_example_cues`/`negated_cues`
    - Add an encyclopedia entry for EX-032 in `packages/core/src/plain.ts`
    - _Requirements: CT-10_
  - [x]* 1.9 Write unit tests for EX-032
    - One example per phrase; a counter-example describing a maintainer release process for people
    - _Requirements: CT-10_
  - [x]* 1.10 Write property test for Property 3 (settings-tamper, weaken-checks, redirect-publish negation)
    - **Property 3: Negated settings-tamper/weaken/redirect text never fires**
    - **Validates: Requirements CT-4, CT-8, CT-10**
  - [x]* 1.11 Write property test for Property 4
    - **Property 4: Code `.skip`/`xit`/`test.todo` without agent-addressed text never fires EX-031**
    - **Validates: Requirements CT-9**

- [x] 2. EX-028 extension: meta tags and alt text
  - [x] 2.1 EX-028 extension implementation (CT-11, CT-12)
    - In `packages/core/src/hidden-text.ts`, add `metaTagFindings` (an HTML `<meta name="...">` whose name is aimed at a model, checked regardless of visibility) and `altTextFindings` (an `<img alt="...">` or Markdown `![alt](...)` whose text names the AI or asks for an action), wired into the existing EX-028 scan path
    - Widen `definitions/EX-028-hidden-text.yaml`'s title/comment to describe both checks; keep the rule id EX-028
    - _Requirements: CT-11, CT-12_
  - [x]* 2.2 Write unit tests for the EX-028 extension
    - A meta tag with an AI-aimed name and one with an ordinary name (`description`, `viewport`, `robots`); alt text that instructs and alt text that only describes; a meta tag and an alt text inside a Markdown code block
    - _Requirements: CT-11, CT-12_

- [x] 3. Checkpoint - ensure scanner rule tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. `decideMcpWrite` extension and `guard-mcp-write` command extension
  - [x] 4.1 `decideMcpWrite` extension: trusted-commands and guard-file targets (CT-5, CT-6, CT-7)
    - Widen the `decideMcpWrite` result type to the `WriteDecision` union (`'none' | 'mcp-config' | 'trusted-commands' | 'guard-file'`), keeping the existing `'mcp-config'` branch and its callers unchanged
    - Add `isTrustedCommandsWrite` (an `fs_write`/`str_replace`/recognised `execute_bash` write whose content adds or widens a Trusted-commands entry in `.vscode/settings.json`) and `isGuardFileWrite` (a create/modify/delete/move of a path under `.kiro/hooks/` or `.kiro/agents/`, resolving absolute, relative, `..`-containing and `~`-prefixed forms to the same target)
    - _Requirements: CT-5, CT-6, CT-7_
  - [x]* 4.2 Write unit tests for the `decideMcpWrite` extension
    - Trusted-commands write detected; narrow write to the same file allowed; guard-file write detected for each path form and each tool; a write to another `.kiro/` file (e.g. a spec) allowed; existing `'mcp-config'` cases unchanged
    - _Requirements: CT-5, CT-6, CT-7_
  - [x]* 4.3 Write property test for Property 7
    - **Property 7: Guard-file writes under `.kiro/hooks/` or `.kiro/agents/` always need confirmation, regardless of path form**
    - **Validates: Requirements CT-6**
  - [x] 4.4 `guard-mcp-write` command extension (CT-5, CT-6, CT-7)
    - In `packages/cli/src/commands/guard-mcp-write.ts`, add target-specific dialog/reason/block-message text for `'trusted-commands'` and `'guard-file'`, reusing `askPerson`'s confirmation flow unchanged; keep the `'mcp-config'` branch's text and behaviour exactly as before
    - _Requirements: CT-5, CT-6, CT-7_
  - [x]* 4.5 Write unit tests for the extended `guard-mcp-write` command
    - Confirmation required and refusal blocks for a trusted-commands write and for a guard-file write; existing MCP-config tests re-run unchanged (CT-7 regression)
    - _Requirements: CT-5, CT-6, CT-7_

- [x] 5. `.env*` value loader and `guard-web-fetch`
  - [x] 5.1 `packages/core/src/env-values.ts`: shared `.env*` value loader (CT-13, CT-14)
    - `loadEnvValues(cwd): string[]`: read every `.env*` file in the workspace root, collect assigned values, drop values shorter than 8 characters or equal to a short list of common words (`true`, `false`, `localhost`, a bare number)
    - _Requirements: CT-13, CT-14_
  - [x]* 5.2 Write unit tests for `loadEnvValues`
    - Values collected from multiple `.env*` files; short and common-word values dropped; no `.env*` file returns an empty list
    - _Requirements: CT-13, CT-14_
  - [x] 5.3 `guard-web-fetch` command (CT-13)
    - Create `packages/cli/src/commands/guard-web-fetch.ts`: parse a Kiro PreToolUse event from stdin, extract the `web_fetch` tool's URL, check it (and its percent-decoded, base64-decoded and split forms) against `redact-secrets`' secret patterns, `findCanaryInText`, and `loadEnvValues`; exit 2 with a one-line reason naming the kind of value and a redacted host, never the value or the full URL; exit 0 on no match or unparsable input
    - Wire the command into `packages/cli/src/index.ts` and its help text
    - _Requirements: CT-13_
  - [x]* 5.4 Write unit tests for `guard-web-fetch`
    - Blocks on a raw env value, a percent-encoded value, a base64-encoded value, a secret-shaped value and a canary token in the URL; allows an ordinary URL; allows on unparsable stdin
    - _Requirements: CT-13_
  - [x]* 5.5 Write property test for Property 5
    - **Property 5: Web-fetch guard matches workspace env values round trip**
    - **Validates: Requirements CT-13**
  - [x] 5.6 `.kiro/hooks/guard-web-fetch.json` hook
    - Create the hook file: `trigger: PreToolUse`, matcher for the `web_fetch` tool, command through `scripts/kiro-hook.sh`, a timeout
    - _Requirements: CT-13_
  - [x]* 5.7 Write a hook schema/format test for `guard-web-fetch.json`
    - Same schema checks as the other hooks; matcher covers `web_fetch`
    - _Requirements: CT-13_

- [x] 6. `guard-env-write` command and hook
  - [x] 6.1 `guard-env-write` command and hook (CT-14)
    - Create `packages/cli/src/commands/guard-env-write.ts`: parse a PreToolUse event for `fs_write`/`str_replace`, allow when the destination path matches `.env*`, otherwise block (exit 2, one-line reason, never the value) when the write's content contains a loaded env value; exit 0 on no match, no `.env*` file or unparsable input
    - Wire the command into `packages/cli/src/index.ts` and its help text
    - Create `.kiro/hooks/guard-env-write.json`: `trigger: PreToolUse`, matcher for `fs_write`/`str_replace`, command through `scripts/kiro-hook.sh`, a timeout
    - _Requirements: CT-14_
  - [x]* 6.2 Write unit tests for `guard-env-write` and its hook file
    - Blocks a write of an env value into a non-`.env*` file; allows the same value written into a `.env*` file; allows a short or common-word value; allows on unparsable stdin; hook file schema check
    - _Requirements: CT-14_
  - [x]* 6.3 Write property test for Property 6
    - **Property 6: Env-value write guard matches round trip, `.env*` destination excepted**
    - **Validates: Requirements CT-14**

- [x] 7. Checkpoint - ensure guard and hook tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Sandbox policy check
  - [x] 8.1 `packages/core/src/sandbox-policy.ts` (CT-18)
    - `sandboxFindings(text, rel): Finding[]`: an info finding when a committed `.kiro/settings/sandbox.json` sets MCP sandboxing, or the overall enabled flag, to off, with fix text noting a project file can only tighten the global policy
    - Wire `sandboxFindings` into the orchestrator next to `canaryFindings`
    - Add a `docs/REFERENCE.md`-visible id/entry for this check (as described in the design) so it is traceable
    - _Requirements: CT-18_
  - [x]* 8.2 Write unit tests for `sandboxFindings`
    - MCP sandboxing off fires; overall enabled off fires; sandboxing on produces no finding; severity is info
    - _Requirements: CT-18_
  - [x]* 8.3 Write property test for Property 8
    - **Property 8: Sandbox info finding tracks exactly the MCP-sandboxing-off field**
    - **Validates: Requirements CT-18**

- [x] 9. `exorcist init --kiro` extension and `--sandbox`
  - [x] 9.1 `exorcist init --kiro` extension: new hooks (CT-15)
    - In `packages/cli/src/commands/init.ts`, add `Planned` entries for `.kiro/hooks/exorcist-guard-web-fetch.json` and `.kiro/hooks/exorcist-guard-env-write.json`, following the existing `hook(...)`/`HOOK_RUNNER`/`MISSING_FROM_DEFAULT_BIN` pattern; list both in `INIT_HELP` and the `--kiro` summary
    - _Requirements: CT-15_
  - [x]* 9.2 Write unit tests for the init extension
    - Both hooks written by `--kiro`; written disabled with a reason when the pinned bin lacks the command; listed in help text and summary; existing file is kept without `--force`
    - _Requirements: CT-15_
  - [x] 9.3 `exorcist init --kiro --sandbox` (CT-16, CT-17)
    - Add a `--sandbox` flag to `initCommand`; `writeSandboxFile(root, io)` writes `.kiro/settings/sandbox.json` (sandbox enabled, network blocked, MCP sandboxing on) only when the file does not exist, printing what was written and how to undo it
    - Without `--sandbox`, `init`/`init --kiro` leaves the file untouched; add one `--sandbox` line to `INIT_HELP` and to the `--kiro` summary
    - _Requirements: CT-16, CT-17_
  - [x]* 9.4 Write unit tests for `--sandbox`
    - First run writes the file with the documented fields and prints the undo text; second run leaves it unchanged and says so (idempotence, CT-16.5); `init`/`init --kiro` without `--sandbox` never creates or changes the file; help text documents the option
    - _Requirements: CT-16, CT-17_

- [x] 10. Checkpoint - ensure init and sandbox tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Possession Lab attack 9
  - [x] 11.1 Possession Lab attack 9 implementation (CT-19)
    - Add attack 9 to the Possession Lab (`apps/web/src/components/PossessionLab*`): a defanged settings-tamper sample (adds a wildcard trusted command), shown blocked, with the result stated in text carrying the infection-level label (not colour alone)
    - Ensure the new controls are keyboard-reachable with focus rings and screen-reader labels, consistent with the existing attacks
    - _Requirements: CT-19_
  - [x]* 11.2 Write a component/unit test for Possession Lab attack 9
    - Renders attack 9, shows the blocked result with its text label, reachable by keyboard
    - _Requirements: CT-19_
  - [x]* 11.3 Extend the existing accessibility and end-to-end test suite with a step for attack 9
    - Add one step to the existing a11y/e2e checks; keep every existing step passing
    - _Requirements: CT-19_

- [x] 12. Benchmark fixtures with benign look-alikes
  - [x] 12.1 Add paired benchmark cases (CT-20)
    - Add paired `fixtures/benchmark/attacks/<case>/` and `fixtures/benchmark/benign/<case>/` cases, and `labels.json` entries, for CT-1, CT-2, CT-4, CT-8, CT-10, CT-11, CT-12 and CT-18, all defanged (`.invalid` hosts, placeholder tokens)
    - Update `fixtures/benchmark/README.md`'s case count
    - _Requirements: CT-20_
  - [x]* 12.2 Run the existing benchmark test against the new cases
    - Every new attack case fires its rule; every new benign case produces no finding
    - _Requirements: CT-20_

- [x] 13. Checkpoint - ensure web and benchmark tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. Documentation updates
  - [x] 14.1 `docs/INCIDENTS.md`: the 2025 Kiro trusted-commands incident (CT-21)
    - Search for the public write-up of the 2025 Kiro issue where a poisoned file made the agent change its trusted commands; add the entry with its link if a primary source is found, or state plainly that none was found if it is not; do not cite a secondary source as primary and do not invent one
    - _Requirements: CT-21_
  - [x] 14.2 `docs/REFERENCE.md`, `docs/KNOWN_LIMITATIONS.md` and `facts.mjs` (CT-21)
    - Add EX-030, EX-031, EX-032 and the EX-007/EX-028 extensions to `docs/REFERENCE.md`'s definitions list
    - Add an entry to `docs/KNOWN_LIMITATIONS.md` for what the new detections do not catch (e.g. settings keys not yet documented by an agent, obfuscated env-value matches beyond the covered encodings)
    - Run `node scripts/facts.mjs --run-tests --docs` and reconcile any count mismatch in the docs
    - _Requirements: CT-21_

- [x] 15. Record and finish
  - [x] 15.1 `docs/KIRO_LOG.md` row and moving the brief (CT-22)
    - Add a row to `docs/KIRO_LOG.md` for this work by the Kiro IDE agent
    - Move `TASK-config-tamper.md` to `docs/kiro-briefs/`
    - _Requirements: CT-22_
  - [x] 15.2 Final checkpoint - typecheck, test, commit (CT-22)
    - Run `pnpm -r typecheck` and `pnpm vitest run` until both pass
    - Commit the work; do not push
    - Ensure all tests pass, ask the user if questions arise.

## Notes
- Tasks marked with `*` are optional (tests) and are not implemented by this plan's execution unless un-marked; every requirement CT-1 to CT-22 maps to at least one test whose name starts with its ID.
- EX-030, EX-031 and EX-032 are new rule ids; EX-007 and EX-028 are extended in place, not replaced, per the brief.
- The sandbox check (task 8.1) is a dedicated function wired into the orchestrator, not a YAML signature, because it inspects specific boolean fields rather than a text/JSON-path pattern; it is still documented in `docs/REFERENCE.md` for traceability.
- No task implements code beyond what is listed; `exorcist init`'s file-writing side effects, the Possession Lab UI and the benchmark harness are covered by unit/integration/snapshot tests, not property tests, per the design's testing strategy.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.4", "1.6", "1.8", "2.1"] },
    { "id": 1, "tasks": ["1.2", "1.3", "1.5", "1.7", "1.9", "1.10", "1.11", "2.2"] },
    { "id": 2, "tasks": ["3"] },
    { "id": 3, "tasks": ["4.1", "5.1", "8.1"] },
    { "id": 4, "tasks": ["4.2", "4.3", "4.4", "5.2", "8.2", "8.3"] },
    { "id": 5, "tasks": ["4.5", "5.3", "6.1", "9.1"] },
    { "id": 6, "tasks": ["5.4", "5.5", "5.6", "6.2", "6.3", "9.2", "9.3"] },
    { "id": 7, "tasks": ["5.7", "9.4"] },
    { "id": 8, "tasks": ["7"] },
    { "id": 9, "tasks": ["10"] },
    { "id": 10, "tasks": ["11.1", "12.1", "14.1", "14.2"] },
    { "id": 11, "tasks": ["11.2", "11.3", "12.2"] },
    { "id": 12, "tasks": ["13"] },
    { "id": 13, "tasks": ["15.1"] },
    { "id": 14, "tasks": ["15.2"] }
  ]
}
```
