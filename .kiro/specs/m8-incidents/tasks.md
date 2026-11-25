# Implementation Plan: m8-incidents

## Overview

Rules first, then the guard, then corpus and Lab, then docs and the full run.

## Tasks

- [x] 1. Hidden text rule EX-028 (requirements 1.1 to 1.6)
  - [x] 1.1 `hidden-text.ts`, schema field, signature-engine call, `EX-028` YAML, plain-language text, unit and property tests
  - [x] 1.2 Shield: `inspectResult` withholds hidden-text results, with a test
- [x] 2. Possessed filename rule EX-029 (requirements 2.1 to 2.6)
  - [x] 2.1 `path-names.ts`, `walkPaths`, schema `analysis: path-names`, `EX-029` YAML, scanRepo wiring, tests
- [x] 3. Exfiltration instruction in EX-002 (requirements 3.1 to 3.4)
  - [x] 3.1 Regex alternative, quiet cases, tests, README sentence caught
- [x] 4. MCP config write guard (requirements 4.1 to 4.9)
  - [x] 4.1 `mcp-write-guard.ts` and `guard-mcp-write` command with fake-terminal tests
  - [x] 4.2 `.kiro/hooks/mcp-config-write-guard.json`, `init --kiro` support, hook and init tests
- [x] 5. Corpus (requirements 5.1 to 5.5)
  - [x] 5.1 Three attack replicas, three look-alikes, `labels.json`, benchmark run, Haunted Repo snapshot check
- [x] 6. Possession Lab attack 8 (requirements 6.1 to 6.5)
  - [x] 6.1 Simulator scenario, ids, deep link, component, tests
  - [x] 6.2 e2e step
- [x] 7. Documentation (requirements 7.1 to 7.5)
  - [x] 7.1 `docs/INCIDENTS.md` with the traceability table
  - [x] 7.2 Definition counts in README, THREATS and tests, `KNOWN_LIMITATIONS.md`, `KIRO_LOG.md`
- [-] 8. `pnpm -r typecheck` and `pnpm vitest run` pass from the repository root, then commit (requirements 8.1 to 8.4)

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "2.1"] },
    { "id": 2, "tasks": ["3.1", "4.1"] },
    { "id": 3, "tasks": ["4.2", "5.1"] },
    { "id": 4, "tasks": ["6.1"] },
    { "id": 5, "tasks": ["6.2", "7.1"] },
    { "id": 6, "tasks": ["7.2"] },
    { "id": 7, "tasks": ["8"] }
  ]
}
```

## Notes

Sub-tasks that share files run in different waves. Each sub-agent runs only the tests of its own area; the full run is task 8. Sample attacks are defanged and never copy a researcher's payload.
