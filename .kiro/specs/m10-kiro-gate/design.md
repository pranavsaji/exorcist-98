# Design: m10-kiro-gate

## Overview
A pure function in `packages/core` decides which findings a change adds. A thin CLI command gathers the changed files from git, calls it and prints the result. A `Stop` hook runs the command. The Power and agents are corrected to match Kiro's documentation.

## What Kiro's documentation says (read 2026-11)
- Hooks (kiro.dev/docs/hooks, /hooks/types, /hooks/actions): standalone `.kiro/hooks/*.json`, `{"version": "v1", "hooks": [...]}`. The trigger `Stop` ("Agent Stop") fires "when the agent has completed its turn", for IDE, CLI and Web. For command actions, exit 0 puts stdout into the agent's context; any other exit code sends stderr to the agent and notifies it of an error. Only PreToolUse and PromptSubmit hooks block an action, so a Stop hook cannot cancel the turn. It hands the agent a failure message, which makes the agent act again. Command actions run in the project root and get the event as JSON on stdin. Default timeout 60 s.
- Powers (kiro.dev/docs/powers/create): "Every power needs a plugin.json manifest"; optional `skills/` and `mcp.json`, following the Agent Plugins spec. There is no `POWER.md` in the current docs. The keywords in `plugin.json` activate the Power. The docs list no steering folder for a Power.
- Custom agents (kiro.dev/docs/custom-agents/configuration-reference): JSON or Markdown in `.kiro/agents/`. Fields `name`, `description`, `prompt`, `mcpServers`, `tools` (selectors `read`, `write`, `shell`, `web`, `@server`, `@server/tool`, `@mcp`, `@builtin`, `*`), `permissions.rules` (capabilities `fs_read`, `fs_write`, `shell`, `web_fetch`, `web_search`, `mcp`, ...; effects `allow`, `ask`, `deny`; optional `exclude`), `resources`, `includeMcpJson`, `includePowers`, `welcomeMessage`. Workspace agents load only in a trusted workspace.

## Architecture
Kiro `Stop` hook -> `scripts/kiro-hook.sh` -> `exorcist gate` (CLI, git calls) -> `packages/core/src/gate.ts` (pure decision) -> stderr list and exit code -> Kiro returns it to the agent.

## Components and Interfaces
The three parts below: 1. Gate (core function, CLI command, hook, init), 2. Power, 3. Custom agents.

## Data Models
`SignatureFinding` (existing) is the only record. `GateThreshold` is the existing `Severity` union. No file or state is stored.

## 1. Gate

### Core: `packages/core/src/gate.ts` (pure, browser-safe, no `any`)
- `isGateFile(rel)`: true when `classifyFile(rel)` is `instruction`, `memory`, `hook`, `mcp-config` or `power`, or `rel` starts with `.kiro/specs/`, `.kiro/agents/` or `.kiro/steering/`, or the base name starts with `README`. `gateRole(rel)` gives the role used for scanning (`.kiro/specs/**` and `.kiro/agents/**` are scanned as `instruction`, so the prompt-injection rules apply to them).
- `gateFindings(rel, before, after, defs)`: `before` is the `HEAD` text or `null`. Scans both with `scanText`, and returns the findings of `after` that have no unmatched counterpart in `before`. A finding matches by `ruleId` plus `span`; matching is by multiset, so a second copy of an old line is new.
- `blocking(f)`: severity `high` or `critical`.
- `renderGate(findings)`: short plain-language text. Uses `plainFor` for the headline, `redactFinding` for secrets and `displayMessage` for hidden characters. Ends with: "Remove these changes, or stop and tell the user. Do not rewrite them in another form."
- Returns data, not exceptions.

### CLI: `packages/cli/src/commands/gate.ts`
1. `gitRepoRoot(dir)`. The origin command's config guard (`openRepo`) is not used: it refuses any repository with `core.hooksPath` set, which `exorcist init` itself tells users to set, so the gate would never run there. The gate runs only `rev-parse`, `ls-files`, `ls-tree`, `hash-object --no-filters` and `cat-file blob`, through `runGit`, which switches off fsmonitor, external diff, pagers and hooks; none of them runs a clean filter. Any failure: stdout "Exorcist gate: nothing checked (<reason>)", exit 0.
2. Candidates: `git ls-files -z --cached --others --exclude-standard`, filtered by `isGateFile`. Changed means the object id of the file on disk (`hash-object --no-filters`, one call) differs from its id in `git ls-tree -r HEAD` (one call); with no `HEAD` yet every candidate is new. This replaces `git diff`, which could run a clean filter, and keeps the cost near half a second here.
3. `before`: `git cat-file blob HEAD:<path>` for changed files only. `after`: the file on disk, read with `fs`. A symlink is not followed. A changed file over the hard limit is reported as EX-026 (medium, so it blocks only with `--fail-on medium`) and not read.
4. Definitions: `findDefinitionsDir()`. Load failure: nothing checked, exit 0.
5. Exit 1 with the rendered list on stderr when any added finding is blocking; otherwise exit 0 and silent.
`--fail-on <critical|high|medium|low>` changes the threshold (default high). `exorcist gate --help` documents it.

### Hook: `.kiro/hooks/exorcist-gate.json`
`trigger: Stop`, command `sh scripts/kiro-hook.sh node_modules/.bin/tsx packages/cli/src/index.ts gate`, timeout 30. The hook ignores the event on stdin.
Why exit 1 and not 2: for a Stop hook any non-zero code sends stderr to the agent; 2 has no extra meaning there.
Loop risk: a Stop hook that fails makes the agent take another turn, and the hook runs again. The message tells the agent to stop and tell the user when it cannot remove the change, and gate output is the same for the same change, so the agent can recognise it.

### Init
`exorcist init --kiro` plans `.kiro/hooks/exorcist-gate.json` with command `${HOOK_RUNNER} ${bin} gate`. `gate` joins `MISSING_FROM_DEFAULT_BIN`, so under the published 0.1.3 the hook is written disabled with a summary line; passing `--bin` with a newer build enables it. The help text and the summary list it. The plain `exorcist init` (without `--kiro`) also writes it, like the other hooks.

## 2. Power
Checked against /powers/create: `plugin.json` (required, present), `mcp.json` and `skills/` (optional, present). `POWER.md` is not part of the current Kiro Power format, so none is added; adding it would be an invented file. The Power's guidance for the agent stays in `skills/scan-repo/SKILL.md`, which already tells the agent to pass the absolute workspace path and to leave the folder prompt to the user; the docs list no steering folder for a Power, so none is added. Gaps found: the SKILL.md front matter has only `name` and `description`, which matches the docs. A test `power.test.ts` validates `plugin.json`, `mcp.json` (schema URLs, `type: stdio`, a pinned version) and each skill's front matter (name equals folder name, description present), and that versions equal the CLI and MCP server versions.

## 3. Custom agents
Checked field by field against the configuration reference. They could not be loaded in a Kiro session here, so the log records them as checked, not seen.
- `exorcist-reviewer.json`: it has `includeMcpJson: true` but no `mcpServers`, and the repository has no `.kiro/settings/mcp.json`, so `@exorcist/scan_repo` would not exist and the agent would have no tools. Fix: add `mcpServers.exorcist` (the same as `exorcist init --kiro` writes, with `EXORCIST_MCP_NO_QUOTES=1`) and set `includeMcpJson: false`, so the only server it can reach is its own. The committed file is then generated from `reviewerAgentForProject` and the existing test that keeps the two the same stays.
- `exorcist-red-team.json`: fields and capability names are valid. `tools` has `shell` and `write`, restricted by `permissions.rules` to one benchmark command and to `fixtures/benchmark/**`. No change except documentation.
- Start: Kiro IDE: open the folder in a trusted workspace, pick the agent in the agent picker of the chat header. Kiro CLI: `kiro-cli chat --agent exorcist-reviewer` (kiro.dev/docs/reference/cli-commands) or `/agent swap` in a session; `kiro-cli agent validate --path .kiro/agents/exorcist-reviewer.json` checks a file. Written in `docs/HOW_KIRO.md` and the README.

## Correctness Properties
### Property 1: Unchanged files add nothing
For any text, `gateFindings(rel, t, t)` is empty. Validates requirement 1.4.

### Property 2: Old findings stay old
Text added around a finding already in `before` never makes it new. Validates requirement 1.4.

### Property 3: New hidden characters always count
Hidden characters added to otherwise clean text are always reported as EX-001. Validates requirement 1.3.

All three are in `gate.property.test.ts`.

## Error Handling
Environment problems (no git, no definitions, unreadable file) never fail the gate: it exits 0 and prints why nothing was checked. A finding fails it with exit 1. A bad option exits 2.

## Testing Strategy
- `core/src/__tests__/gate.test.ts` and `gate.property.test.ts` (fast-check): findings already in `before` never block; adding a hidden character run to any clean text blocks; the result does not depend on line position.
- `cli/src/__tests__/gate.test.ts`: real temporary git repos. Clean change passes; hidden characters added to a steering file fail with exit 1 and a `[U+...]` marker free of raw characters; an old finding is ignored; a new file counts; non-git folder exits 0; timing under 1 s for the command's work on this repository.
- `cli/src/__tests__/kiro-hook.test.ts`: the repo hook and the init hook have trigger `Stop`, go through the launcher, and block with Kiro's minimal PATH.
- `cli/src/__tests__/repo-files.test.ts` (Power: strict Agent Plugins 1.0.0 schemas, file list, versions) and `kiro-config.test.ts` (agents: documented fields, reviewer equals the file `init --kiro` writes, tool selectors name a server the agent starts).
