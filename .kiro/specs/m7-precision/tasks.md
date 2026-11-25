# Implementation Plan: m7-precision

## Overview

Security fix first, then false alarms, then measurement and docs.

## Tasks

- [x] 1. Security fix: secrets never printed in full (requirements 1.1 to 1.7)
  - [x] 1.1 `packages/core/src/redact-secrets.ts` and its exports, with unit and property tests
  - [x] 1.2 Apply to `toJson`, `toSarif`, CLI `text`, `origin`; test every format with a fake key
  - [x] 1.3 Apply to the MCP server tools, with a test
  - [x] 1.4 Apply to the web API (findings, snippets, patch, AI judge, BYOA) and the Shield AI-review alert, with tests
  - [x] 1.5 Row in `docs/KNOWN_LIMITATIONS.md`, marked Fixed
- [x] 2. False alarms (requirements 2.1 to 2.9), each with a regression test and an attack-still-caught test
  - [x] 2.1 EX-003: code and query payloads, minisign keys
  - [x] 2.2 EX-001: zero-width space after `@`
  - [x] 2.3 EX-005: `pass` inside a word
  - [x] 2.4 EX-012: Google Docs and GitBook image links
  - [x] 2.5 EX-008 and EX-015: content-cache JSON
  - [x] 2.6 Negation for EX-018, EX-002 and `noqa` for EX-004
  - [x] 2.7 EX-010: `uvx --python 3.13`
  - [x] 2.8 `skip_paths` for EX-001, EX-002, EX-004 and EX-023
  - [x] 2.9 Benchmark (19 of 19) and Haunted Repo (47 findings) unchanged
- [x] 3. Measure and write up (requirements 3.1 to 3.4)
  - [x] 3.1 Rescan the 11 repositories and record before and after counts
  - [x] 3.2 "Round 3" in `docs/FIELD_REPORT.md`
  - [x] 3.3 Open gap row in `docs/KNOWN_LIMITATIONS.md`
  - [x] 3.4 Row in `docs/KIRO_LOG.md`
- [x] 4. `pnpm -r typecheck` and `pnpm vitest run` pass from the repository root

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3", "1.4"] },
    { "id": 2, "tasks": ["1.5", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8"] },
    { "id": 3, "tasks": ["2.9"] },
    { "id": 4, "tasks": ["3.1"] },
    { "id": 5, "tasks": ["3.2", "3.3", "3.4"] },
    { "id": 6, "tasks": ["4"] }
  ]
}
```

## Notes

Task 1 comes first because it fixes a leak. Task 3 needs the rule changes of task 2 to measure the after counts.
