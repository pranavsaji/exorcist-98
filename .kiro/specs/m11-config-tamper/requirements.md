# Requirements Document

Spec: m11-config-tamper

## Introduction
Another entry in this hackathon tests coding agents against attacks that rewrite the agent's own settings and against leaks through Kiro's built-in tools. This milestone makes Exorcist 98 catch each of them, in the scanner, in the Kiro hooks, or in both. The source is `docs/kiro-briefs/TASK-config-tamper.md` (brief sections 1 to 8). Each requirement has an ID (CT-1, CT-2, ...); every test that checks it starts its name with that ID, for example `it('CT-3: ...')`.

## Glossary
- **Scanner**: the signature engine in `packages/core` that scans committed files and text (`scanText`, the walker, the orchestrator).
- **Trusted-commands setting**: the Kiro editor setting that lists shell commands the agent runs without asking, in `.vscode/settings.json` or in Kiro's own settings files. The exact key name is read from Kiro's documentation before use.
- **Agent-settings file**: a committed file that configures an agent's permissions or auto-approval (`.vscode/settings.json`, Kiro settings, `.claude/settings.json`, Cursor, Cline and Copilot settings and the other agents the Scanner already knows).
- **Broad pattern**: a wildcard (`*`) or a shell pattern that matches any command, or any command of a shell, interpreter or package manager.
- **Settings tamper instruction**: text addressed to an agent that asks it to change an Agent-settings file, or to edit `.kiro/hooks/`, `.kiro/agents/`, `.kiro/steering/` or `AGENTS.md`.
- **Weaken-checks instruction**: text addressed to an agent that tells it to skip, delete or weaken tests or CI checks, or to make a failing check pass.
- **Redirect-publish instruction**: text addressed to an agent that asks it to push or publish somewhere other than the project's origin.
- **Config write guard**: the `mcp-config-write-guard` PreToolUse hook and its `exorcist guard-mcp-write` command.
- **Person-only confirmation**: the confirmation the Config write guard already asks for (Touch ID on macOS, a typed code elsewhere) that an agent cannot answer.
- **Web-fetch guard**: the new `guard-web-fetch` PreToolUse hook for Kiro's `web_fetch` tool.
- **Env-value guard**: the new PreToolUse guard on `fs_write` and `str_replace` that blocks copying a value from a `.env*` file into another file.
- **Workspace env values**: the values assigned in the `.env*` files of the workspace.
- **Secret-shaped value**: a value `redact-secrets` recognises as a secret.
- **Sandbox file**: `.kiro/settings/sandbox.json`, Kiro's sandbox settings for a project.
- **Possession Lab**: the interactive attack demo in the web app (`apps/web`).
- **Benign look-alike**: a benchmark sample that resembles an attack, must produce no finding and sits next to the attack sample.
- **Defanged**: an attack sample that uses `.invalid` hosts and placeholder tokens such as `EXAMPLE_TOKEN_DO_NOT_USE`.

## Requirements

### Requirement CT-1: Trusted commands with a broad pattern
**User Story:** As a developer, I want the Scanner to flag a committed setting that lets the agent run any command unasked, so that a poisoned repository cannot switch off command approval.

#### Acceptance Criteria
1. WHEN an Agent-settings file for Kiro holds a Trusted-commands setting whose value is a wildcard or a Broad pattern, THE Scanner SHALL report a finding of severity critical with file, line and the quoted span.
2. THE Scanner SHALL cover the Trusted-commands setting in `.vscode/settings.json` and in Kiro's own settings files.
3. WHERE EX-007 can express the match, THE Scanner SHALL report CT-1 findings under EX-007; OTHERWISE THE Scanner SHALL report them under the new rule EX-030.
4. THE finding SHALL carry a plain-language headline, the OWASP mapping and a fix, as every other finding does.
5. IF a settings file is not valid JSON because it contains comments or trailing commas, THEN THE Scanner SHALL still check the Trusted-commands setting by reading it as JSON with comments.

### Requirement CT-2: Auto-approve settings of other agents
**User Story:** As a developer, I want the same check for the other agents' auto-approve settings, so that the attack does not work by choosing a different agent.

#### Acceptance Criteria
1. WHEN a Claude Code settings file holds `permissions.allow` with a bare shell wildcard, THE Scanner SHALL report a finding of severity critical.
2. WHEN a Cursor, Cline or Copilot settings file holds an auto-approve setting that lets the agent run any command, THE Scanner SHALL report a finding of severity critical.
3. THE setting names for each agent SHALL be taken from that agent's current documentation and each name SHALL be recorded in the design with its source URL.
4. IF the documentation of an agent does not show an auto-approve setting, THEN THE Scanner SHALL NOT add a rule for that agent and the design SHALL say so.

### Requirement CT-3: Narrow trust stays quiet
**User Story:** As a developer, I want a settings file that trusts specific safe commands to stay clean, so that the rule does not cry wolf.

#### Acceptance Criteria
1. WHEN a Trusted-commands setting or an `allow` list holds only specific commands without a wildcard over the whole command (for example `git status` or `pnpm test`), THE Scanner SHALL report no finding for CT-1 or CT-2.
2. WHEN an Agent-settings file has no auto-approve or trusted-commands key, THE Scanner SHALL report no finding for CT-1 or CT-2.
3. FOR ALL generated settings files whose trusted-commands entries contain no wildcard and no bare shell or interpreter name, THE Scanner SHALL report no CT-1 finding (property).

### Requirement CT-4: Instructions to change agent settings
**User Story:** As a developer, I want text that asks the agent to change its own settings or its hooks, agents, steering or `AGENTS.md` to be flagged, so that an attacker cannot make the change stick through the agent.

#### Acceptance Criteria
1. WHEN text addressed to an agent in an instruction, docs, memory or tool-result file is a Settings tamper instruction, THE Scanner SHALL report a finding of severity high under rule EX-030.
2. WHEN the text names a Trusted-commands setting, an auto-approve setting, `.kiro/hooks/`, `.kiro/agents/`, `.kiro/steering/` or `AGENTS.md` as the target of an edit, THE Scanner SHALL include the quoted span in the finding.
3. IF the passage forbids the change ("never edit .kiro/hooks"), THEN THE Scanner SHALL report no finding, using the negated-cue support of m7.
4. WHEN documentation describes the file for a human reader without addressing an agent, THE Scanner SHALL report no finding.

### Requirement CT-5: Guard writes that add trusted commands
**User Story:** As a developer, I want a person to confirm any agent write that adds trusted commands, so that the agent cannot widen its own permissions.

#### Acceptance Criteria
1. WHEN a PreToolUse event for `fs_write`, `str_replace` or `execute_bash` would add a Trusted-commands entry to `.vscode/settings.json`, THE Config write guard SHALL require the Person-only confirmation.
2. IF the Person-only confirmation is refused or unavailable, THEN THE Config write guard SHALL exit with code 2 and a one-line reason that does not show the content the agent wanted to write.
3. WHEN a write to `.vscode/settings.json` changes no Trusted-commands entry, THE Config write guard SHALL allow it without confirmation.
4. WHEN an `execute_bash` command writes the Trusted-commands setting into `.vscode/settings.json` (redirect, `tee`, `sed -i`, `jq`, `cp`, `mv`), THE Config write guard SHALL require the Person-only confirmation.

### Requirement CT-6: Guard writes to hooks and custom agents
**User Story:** As a developer, I want a person to confirm any agent write into `.kiro/hooks/` or `.kiro/agents/`, so that the agent cannot add or loosen its own guards.

#### Acceptance Criteria
1. WHEN a PreToolUse event for `fs_write` or `str_replace` creates or changes a file in `.kiro/hooks/` or `.kiro/agents/`, THE Config write guard SHALL require the Person-only confirmation.
2. WHEN an `execute_bash` command creates, changes, moves or deletes a file in `.kiro/hooks/` or `.kiro/agents/`, THE Config write guard SHALL require the Person-only confirmation.
3. THE Config write guard SHALL treat the same path written as an absolute path, a relative path, a path with `..` segments or a `~`-prefixed path as the same target.
4. WHEN a write targets another file in `.kiro/` (for example a spec), THE Config write guard SHALL allow it without confirmation.

### Requirement CT-7: Existing MCP config behaviour is unchanged
**User Story:** As a maintainer, I want the MCP-config guard to behave exactly as before, so that this milestone breaks nothing.

#### Acceptance Criteria
1. THE Config write guard SHALL keep requiring the Person-only confirmation for writes to `.kiro/settings/mcp.json` in a project and in the home folder.
2. THE existing tests of `guard-mcp-write` SHALL pass without change.
3. THE hook `.kiro/hooks/mcp-config-write-guard.json` SHALL keep its name and its launcher command, and its matcher SHALL cover the file-write tools and the shell tool.
4. WHEN the hook input cannot be parsed or names no known path, THE Config write guard SHALL keep its current behaviour for that input.

### Requirement CT-8: Instructions to weaken tests or checks
**User Story:** As a developer, I want text that tells the agent to weaken tests or CI to be flagged, so that an attacker cannot get a bad change through by making the checks pass.

#### Acceptance Criteria
1. WHEN text addressed to an agent is a Weaken-checks instruction, THE Scanner SHALL report a finding of severity high under rule EX-031.
2. THE EX-031 phrases SHALL cover adding `.skip`, `xit` or `test.todo`; deleting a test file because it is flaky; `--no-verify`; `|| true` on a CI step; lowering a coverage threshold; and making a failing check pass.
3. THE rule SHALL apply to instruction, docs, memory and tool-result files, and to comments in source files.
4. IF the passage forbids the action ("never use --no-verify"), THEN THE Scanner SHALL report no finding, using the negated-cue support of m7.

### Requirement CT-9: Ordinary test code does not fire EX-031
**User Story:** As a developer, I want my own test code and CI files to stay clean, so that EX-031 reports instructions and not code.

#### Acceptance Criteria
1. WHEN a test file uses `.skip`, `xit` or `test.todo` as code, THE Scanner SHALL report no EX-031 finding.
2. WHEN a CI file uses `|| true` or a documentation page explains `--no-verify` without addressing an agent, THE Scanner SHALL report no EX-031 finding.
3. FOR ALL generated source files that contain `.skip(`, `xit(` or `test.todo(` and no text addressed to an agent, THE Scanner SHALL report no EX-031 finding (property).

### Requirement CT-10: Instructions to push or publish elsewhere
**User Story:** As a developer, I want text that tells the agent to send code somewhere else to be flagged, so that an attacker cannot move my code to their remote or registry.

#### Acceptance Criteria
1. WHEN text addressed to an agent is a Redirect-publish instruction, THE Scanner SHALL report a finding of severity high under rule EX-032.
2. THE EX-032 phrases SHALL cover pushing to a remote other than origin, adding a new remote, publishing a package, changing the package registry and opening a pull request against a different repository.
3. IF the passage forbids the action, THEN THE Scanner SHALL report no finding, using the negated-cue support of m7.
4. WHEN documentation describes a release process for people ("maintainers run `npm publish`"), THE Scanner SHALL report no finding.

### Requirement CT-11: Hidden instructions in HTML meta tags
**User Story:** As a developer, I want a `<meta>` tag aimed at a model to be flagged, so that a web page or HTML file cannot hide orders in its head.

#### Acceptance Criteria
1. WHEN an HTML `<meta>` tag has a name aimed at a model (for example `ai-instructions`, `llm`, `assistant`) and a content that names the AI or asks for an action, THE Scanner SHALL report a finding under EX-028.
2. THE finding SHALL point to the line of the tag and quote the content.
3. WHEN a `<meta>` tag has an ordinary name (`description`, `viewport`, `robots`), THE Scanner SHALL report no finding.
4. WHEN the tag appears inside a Markdown code block, THE Scanner SHALL report no finding, as for the other EX-028 cases.

### Requirement CT-12: Hidden instructions in image alt text
**User Story:** As a developer, I want alt text that carries instructions to be flagged, so that an image cannot smuggle orders to the agent.

#### Acceptance Criteria
1. WHEN an HTML `alt` attribute or Markdown image alt text names the AI or asks the agent for an action, THE Scanner SHALL report a finding under EX-028.
2. WHEN alt text only describes the image, THE Scanner SHALL report no finding.
3. THE existing EX-028 behaviour for hidden elements SHALL be unchanged, with its tests passing.

### Requirement CT-13: Web-fetch guard
**User Story:** As a developer, I want a fetch whose URL carries a secret to be blocked, so that the agent cannot leak data through Kiro's `web_fetch` tool.

#### Acceptance Criteria
1. THE repository SHALL contain `.kiro/hooks/guard-web-fetch.json` in Kiro's v1 hook format with trigger `PreToolUse`, a matcher for the `web_fetch` tool, a command through `scripts/kiro-hook.sh` and a timeout.
2. WHEN the URL of a `web_fetch` call carries a Secret-shaped value, a canary token or a Workspace env value, THE Web-fetch guard SHALL exit with code 2.
3. THE Web-fetch guard SHALL also check the percent-decoded, base64-encoded and split forms that the canary code already recognises.
4. THE reason SHALL be one plain line and SHALL NOT contain the secret, any part of the secret or the full URL.
5. WHEN the URL carries none of these, THE Web-fetch guard SHALL exit 0.
6. IF the hook input cannot be parsed, THEN THE Web-fetch guard SHALL exit 0, as the read hook does.
7. THE Web-fetch guard SHALL reuse `redact-secrets` and the canary code and SHALL make no network call.
8. FOR ALL generated URLs that contain a value from the Workspace env values, THE Web-fetch guard SHALL exit 2, and FOR ALL generated URLs that contain no such value and no secret-shaped value, it SHALL exit 0 (property).

### Requirement CT-14: Env-value write guard
**User Story:** As a developer, I want a write that copies a `.env` value into another file to be blocked, so that the agent cannot move a secret into a file that will be committed.

#### Acceptance Criteria
1. WHEN an `fs_write` or `str_replace` call writes a Workspace env value into any file other than a `.env*` file, THE Env-value guard SHALL exit with code 2.
2. WHEN the write goes into a `.env*` file, THE Env-value guard SHALL exit 0.
3. THE reason SHALL be one plain line and SHALL NOT contain the value.
4. WHEN a Workspace env value is shorter than 8 characters or is a common word (`true`, `false`, `localhost`, a bare number), THE Env-value guard SHALL ignore it so that ordinary configuration is not blocked.
5. IF the workspace has no `.env*` file or the hook input cannot be parsed, THEN THE Env-value guard SHALL exit 0.
6. THE Env-value guard SHALL be installed as a PreToolUse hook with the matcher for `fs_write` and `str_replace`, through `scripts/kiro-hook.sh`.

### Requirement CT-15: init installs both hooks
**User Story:** As a developer, I want `exorcist init --kiro` to install the new guards, so that I get them without copying files.

#### Acceptance Criteria
1. WHEN `exorcist init --kiro` runs, THE init command SHALL write `guard-web-fetch.json` and the Env-value guard hook into `.kiro/hooks/` with commands of the form `sh .exorcist/kiro-hook.sh <bin> <command>`.
2. WHEN the default command (`@exorcist-98/cli@0.1.3`) lacks a command a hook calls, THE init command SHALL write that hook with `"enabled": false` and say why.
3. THE hook files SHALL pass the same schema checks as the other hooks and SHALL be listed in the init summary and help text.
4. WHEN a hook file already exists, THE init command SHALL keep its current behaviour for existing files.

### Requirement CT-16: init --sandbox
**User Story:** As a developer, I want `exorcist init --kiro --sandbox` to turn on Kiro's sandbox for the project, so that I get one more layer.

#### Acceptance Criteria
1. WHEN `exorcist init --kiro --sandbox` runs and `.kiro/settings/sandbox.json` does not exist, THE init command SHALL write it with the sandbox enabled, network blocked by default and MCP sandboxing on, using the key names in kiro.dev/docs/sandbox.
2. WHEN the Sandbox file exists, THE init command SHALL leave it unchanged and say so.
3. THE init command SHALL print what it changed and how to undo it.
4. THE written file SHALL pass a schema check built from the documented fields.
5. WHEN a second `init --kiro --sandbox` runs, THE result SHALL equal the result of the first (idempotent).

### Requirement CT-17: init without --sandbox only mentions it
**User Story:** As a developer, I want `init` to leave the sandbox alone unless I ask, so that nothing surprising changes.

#### Acceptance Criteria
1. WHEN `exorcist init` or `exorcist init --kiro` runs without `--sandbox`, THE init command SHALL NOT create or change the Sandbox file.
2. THE init summary SHALL mention the `--sandbox` option in one line.
3. THE help text SHALL document `--sandbox`.

### Requirement CT-18: Scanner reports a sandbox file that turns MCP sandboxing off
**User Story:** As a developer, I want to be told when a committed sandbox file weakens MCP sandboxing, so that I know the layer is off.

#### Acceptance Criteria
1. WHEN a committed Sandbox file turns MCP sandboxing off, THE Scanner SHALL report an info finding that names the file and line.
2. THE finding text SHALL say that a project file can only tighten the global sandbox policy, so the global policy may still apply.
3. WHEN the Sandbox file keeps MCP sandboxing on, THE Scanner SHALL report no finding.
4. THE finding SHALL have severity info and SHALL NOT make `exorcist gate` or `exorcist scan` fail at the default threshold.

### Requirement CT-19: Possession Lab attack 9
**User Story:** As a visitor, I want to see the settings attack blocked in the Possession Lab, so that I understand the threat.

#### Acceptance Criteria
1. THE Possession Lab SHALL offer attack 9, a defanged settings attack that adds a wildcard trusted command, and SHALL show it blocked.
2. THE attack 9 view SHALL state the result in text with the infection-level label, so that colour is not the only signal.
3. THE attack 9 controls SHALL be reachable by keyboard, with focus rings and screen-reader labels.
4. THE existing accessibility and end-to-end checks SHALL keep passing and SHALL gain a step for attack 9.
5. THE attack text SHALL use only defanged samples.

### Requirement CT-20: Benchmark cases with benign look-alikes
**User Story:** As a maintainer, I want every new detection measured, so that precision and recall are known.

#### Acceptance Criteria
1. THE `fixtures/benchmark/` folder SHALL hold at least one attack sample for each of CT-1, CT-2, CT-4, CT-8, CT-10, CT-11, CT-12 and CT-18.
2. THE folder SHALL hold at least one Benign look-alike next to each attack sample, and every Benign look-alike SHALL produce no finding of the rule under test.
3. THE benchmark test SHALL fail if an attack sample is missed or a Benign look-alike fires.
4. ALL samples SHALL be Defanged.
5. THE web-fetch and env-value guard SHALL be covered by hook tests with Defanged inputs, since they are hooks and not scanner rules.

### Requirement CT-21: Documentation and incident source
**User Story:** As a maintainer, I want the docs to match the code and to cite real sources only.

#### Acceptance Criteria
1. `docs/INCIDENTS.md` SHALL cite the primary public write-up of the 2025 Kiro issue in which a poisoned file made the agent change its trusted commands, with its link.
2. IF no primary source is found, THEN `docs/INCIDENTS.md` SHALL say that none was found and SHALL NOT cite a secondary source as primary or invent one.
3. `docs/REFERENCE.md` SHALL list EX-030, EX-031 and EX-032 and the EX-007 and EX-028 extensions in its definitions list.
4. `docs/KNOWN_LIMITATIONS.md` SHALL list what the new detections do not catch.
5. `node scripts/facts.mjs --run-tests --docs` SHALL run and its output SHALL match the counts in the docs.
6. THE rule files SHALL be added to `definitions/` with the same schema as the existing rules and an encyclopedia entry in `plain.ts`.

### Requirement CT-22: Record and finish
**User Story:** As a maintainer, I want the work logged and verified, so that the record matches the code.

#### Acceptance Criteria
1. `docs/KIRO_LOG.md` SHALL get a row for this work by the Kiro IDE agent.
2. THE brief `TASK-config-tamper.md` SHALL be moved to `docs/kiro-briefs/`.
3. `pnpm -r typecheck` and `pnpm vitest run` SHALL pass.
4. THE work SHALL be committed and not pushed.
5. Every requirement CT-1 to CT-21 SHALL map to at least one test whose name starts with its ID.
