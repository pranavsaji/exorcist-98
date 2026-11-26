# Requirements Document

Spec: m10-kiro-gate

## Introduction
Exorcist 98 already guards what the agent reads (on-access), runs (commit guard) and saves (MCP-config scan). This milestone adds a guard on what the agent leaves behind: a gate that runs when the agent finishes its turn and fails if the agent has just written something possessed into a file that agents obey. It also checks the Power and the two custom agents against Kiro's current documentation.

## Glossary
- **Gate**: `exorcist gate`, the check of what changed since `HEAD`.
- **Agent-facing file**: a file an AI agent takes instructions or settings from.
- **Stop hook**: a Kiro hook with trigger `Stop`, run when the agent finishes its turn.

## Requirements

### Requirement 1: The gate command
**User Story:** As a developer, I want a command that checks only what changed since the last commit, so that an agent cannot finish a turn after adding hidden instructions to the project.

#### Acceptance Criteria
1. KG-1 WHEN `exorcist gate [dir]` runs inside a git work tree, THE gate SHALL compare each changed, staged or untracked agent-facing file with its version in `HEAD`.
2. KG-2 THE agent-facing files SHALL be steering (`.kiro/steering/`), specs (`.kiro/specs/`), hooks (`.kiro/hooks/`), custom agents (`.kiro/agents/`), MCP configs, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` and the other rule files the walker classifies as instruction, memory or power files, and every `README*`.
3. KG-3 WHEN the change adds a finding of severity high or critical that the `HEAD` version of the same file did not have, THE gate SHALL exit 1 and print a short plain-language list: file, line, headline, rule id and fix.
4. KG-4 THE gate SHALL ignore findings already present in `HEAD`, matched by rule id and quoted span, so that moving a line or editing around it does not fail the gate.
5. KG-5 WHEN a changed file is new (untracked or added), THE gate SHALL treat every finding in it as added.
6. KG-6 WHEN no agent-facing file changed, or the change adds no high or critical finding, THE gate SHALL exit 0 and print nothing to stderr.
7. KG-7 THE gate SHALL be read-only (no file or git state is written), SHALL make no network call, and SHALL finish in under one second on this repository.
8. KG-8 THE gate SHALL NOT print a secret in full and SHALL show control and hidden characters as `[U+XXXX]` markers.
9. KG-9 WHEN an agent-facing file is larger than the scanner's hard limit, THE gate SHALL report it as EX-026 instead of treating it as clean.
10. KG-10 WHEN the folder is not a git work tree, git is missing or the repository config is unsafe, THE gate SHALL exit 0 and say on stdout that nothing was checked, so that it never stops an agent for an environment reason.

### Requirement 2: The Stop hook
**User Story:** As a developer, I want Kiro to run the gate at the end of every agent turn, so that the agent hears about a possessed change before it finishes.

#### Acceptance Criteria
1. KG-11 THE repository SHALL contain `.kiro/hooks/exorcist-gate.json` in Kiro's v1 hook format with trigger `Stop`, a command action and a timeout.
2. KG-12 THE command SHALL run through `scripts/kiro-hook.sh`, never a bare `node`, `npx` or `pnpm`.
3. KG-13 WHEN the gate exits non-zero, THE stderr list SHALL reach the agent (Kiro sends a failing command hook's stderr to the agent) and SHALL tell it to remove the change or tell the user, and not to retry the same change.
4. KG-14 `exorcist init --kiro` SHALL write `.kiro/hooks/exorcist-gate.json` (command `sh .exorcist/kiro-hook.sh <bin> gate`).
5. KG-15 WHEN the default command (`@exorcist-98/cli@0.1.3`) does not have `gate`, THE init hook SHALL be written with `"enabled": false` and say why, as for any command the published version lacks.
6. KG-16 THE hook JSON SHALL pass the same schema checks as the other hooks.

### Requirement 3: The Power follows Kiro's documentation
**User Story:** As a Kiro user, I want the Power to install and load the way Kiro documents, so that it works the first time.

#### Acceptance Criteria
1. KG-17 THE Power SHALL be checked against kiro.dev/docs/powers/create and the finding recorded in the design; a file Kiro requires and `power/` lacks SHALL be added.
2. KG-18 `plugin.json`, `mcp.json` and each `SKILL.md` SHALL stay valid against the Agent Plugins schema and the documented skill front matter, with a test.
3. KG-19 IF Kiro's documentation supports steering in a Power, THEN the Power SHALL carry one telling the agent to pass the absolute workspace path to `scan_repo` and to approve the folder prompt. OTHERWISE the same instruction SHALL stay in the skills and the design SHALL say why.
4. KG-20 THE version in `plugin.json`, `mcp.json`, the CLI and the MCP server SHALL be equal (0.1.3), with a test.

### Requirement 4: The two custom agents load in Kiro
**User Story:** As a Kiro user, I want `exorcist-reviewer` and `exorcist-red-team` to appear in the agent picker and work.

#### Acceptance Criteria
1. KG-21 BOTH agent files SHALL be checked against kiro.dev/docs/custom-agents/configuration-reference and every field either matches it or is fixed.
2. KG-22 THE committed `exorcist-reviewer` SHALL start its own `exorcist` MCP server, so its `@exorcist/...` tools exist without a workspace `.kiro/settings/mcp.json`.
3. KG-23 A test SHALL validate both files against a schema of the documented fields and check that each `tools` selector and `permissions` capability is one the documentation lists.
4. KG-24 THE documentation SHALL say how to start each agent in Kiro IDE and in Kiro CLI.

### Requirement 5: Record it
**User Story:** As a maintainer, I want the work logged and verified, so that the record matches the code.

#### Acceptance Criteria
1. KG-25 `docs/KIRO_LOG.md` SHALL get a row for this work by the Kiro IDE agent and the hooks count SHALL read six.
2. KG-26 Every requirement above SHALL map to at least one test.
3. KG-27 `pnpm -r typecheck` and `pnpm vitest run` SHALL pass, and the work SHALL be committed and not pushed.
