# Implementation Plan: m10-kiro-gate

## Overview
Core function first, then the command, the hooks, then the Power and agents, then the records.

## Tasks
- [x] 1. Gate core (requirements 1.1 to 1.5, 1.8, 1.9)
  - [x] 1.1 `packages/core/src/gate.ts`: `isGateFile`, `gateRole`, `gateFindings`, `isBlocking`, `renderGate`; export from `index.ts`
  - [x] 1.2 `gate.test.ts` (unit) and `gate.property.test.ts` (fast-check)
- [x] 2. Gate command (requirements 1.1 to 1.10)
  - [x] 2.1 `packages/cli/src/commands/gate.ts`, wired in `index.ts` and its help
  - [x] 2.2 `packages/cli/src/__tests__/gate.test.ts`: temporary git repos, clean, hidden characters, old finding, new file, non-git, timing
- [x] 3. Stop hook (requirements 2.1 to 2.6)
  - [x] 3.1 `.kiro/hooks/exorcist-gate.json`
  - [x] 3.2 `exorcist init` writes it; `gate` is in `MISSING_FROM_DEFAULT_BIN`; help text and summary
  - [x] 3.3 Hook tests in `kiro-hook.test.ts` and `init-kiro.test.ts`; update `.kiro/steering/kiro-hooks.md`
- [x] 4. Power and agents (requirements 3 and 4)
  - [x] 4.1 strict Agent Plugins schema tests in `repo-files.test.ts`; agent tests in `kiro-config.test.ts`
  - [x] 4.2 Fix `exorcist-reviewer.json` (own MCP server); keep it equal to `reviewerAgentForProject`
  - [x] 4.3 How to start each agent in `docs/HOW_KIRO.md` and the README
- [x] 5. Record (requirement 5)
  - [x] 5.1 Row in `docs/KIRO_LOG.md`, hooks count six, `docs/HOW_KIRO.md` hooks list
  - [x] 5.2 `pnpm -r typecheck` and `pnpm vitest run` pass; commit, do not push

## Task Dependency Graph
```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "2.1", "4.1", "4.2"] },
    { "id": 2, "tasks": ["2.2", "3.1", "3.2", "4.3"] },
    { "id": 3, "tasks": ["3.3", "5.1"] },
    { "id": 4, "tasks": ["5.2"] }
  ]
}
```

## Notes
- Tasks are marked done by the Kiro IDE agent as each finishes; each requirement maps to at least one test.
