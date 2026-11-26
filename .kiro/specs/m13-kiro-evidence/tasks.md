# Implementation Plan: m13-kiro-evidence

## Overview
Pure extractor and counters first, then the export script and its safety rescan, then publishing (evidence doc, facts), then spec-trace, then the new hooks/skills/steering/agent configuration, then the finish steps.

## Tasks

- [x] 1. Research the real session format
  - Inspect a few real folders under `~/.kiro/sessions/<workspace-hash>/` for this project (`session.json`, `messages.jsonl`, `tool-outputs/`) and a transcript containing a blocked `PreToolUse` hook
  - Record the observed field names and event types as code comments at the top of `packages/core/src/kiro-evidence.ts`, noting anything that differs from the design's guess
  - _Requirements: KE-1, KE-12, KE-13_

- [x] 2. Core extractor functions
  - [x] 2.1 Implement `isThisProjectWorkspace`, `redactHomePath`, `redactSecretsDeep`, `truncateToolPayload`, `parseEventLine` in `packages/core/src/kiro-evidence.ts`; export from `index.ts`
    - _Requirements: KE-2, KE-3, KE-6, KE-7, KE-8, KE-9_
  - [x]* 2.2 Write property test for workspace filter
    - **Property 1: Workspace filter is exhaustive and exclusive (KE-2, KE-7)**
    - **Validates: Requirements 2.2, 2.7**
  - [x]* 2.3 Write property test for tool payload truncation
    - **Property 2: Tool payloads never exceed the cap and never carry images (KE-3)**
    - **Validates: Requirements 1.3**
  - [x]* 2.4 Write property test for malformed-line parsing
    - **Property 4: Malformed lines never stop export (KE-6)**
    - **Validates: Requirements 1.6**
  - [x]* 2.5 Write property test for home-path redaction
    - **Property 5: The home path never survives redaction (KE-8)**
    - **Validates: Requirements 2.2**
  - [x]* 2.6 Write property test for deep secret redaction
    - **Property 6: No secret shape survives deep redaction (KE-9)**
    - **Validates: Requirements 2.3**

- [x] 3. Hook-run and hook-block recognition, and session/totals aggregation
  - [x] 3.1 Implement `isHookRun`, `isHookBlock`, `extractSessionRecord`, `aggregateTotals`, `containsSecretShape` in `packages/core/src/kiro-evidence.ts`
    - _Requirements: KE-4, KE-5, KE-10, KE-12, KE-13, KE-14_
  - [x]* 3.2 Write property test for hook run/block counting
    - **Property 7: Hook run and hook block counting matches construction (KE-12, KE-13)**
    - **Validates: Requirements 3.1, 3.2**
  - [x]* 3.3 Write property test for totals aggregation
    - **Property 3: Totals equal the sum of kept sessions (KE-5, KE-14)**
    - **Validates: Requirements 1.5, 3.3**
  - [x]* 3.4 Write unit tests for `extractSessionRecord` and `containsSecretShape` against a small hand-built fixture session
    - _Requirements: KE-4_

- [x] 4. Checkpoint: core extractor tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Export script with safety rescan
  - [x] 5.1 Write `scripts/kiro-evidence.mjs`: walk `~/.kiro/sessions/`, skip non-project sessions, write `evidence/kiro-sessions/<id>.jsonl.gz` and `index.json`, never descend into `~/.kiro/settings/`
    - _Requirements: KE-1, KE-7, KE-11_
  - [x] 5.2 Add the post-write rescan (re-read each written file, scan with `containsSecretShape`, delete and exit 1 on a hit) before leaving any output on disk
    - _Requirements: KE-10_
  - [x]* 5.3 Write unit test running the script against a temporary fake `~/.kiro/sessions/` tree: a kept session, a skipped session, a session whose output trips the rescan, and a fixture settings folder that must never be read
    - _Requirements: KE-1, KE-7, KE-10, KE-11_

- [x] 6. Checkpoint: export script tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Publish the evidence document
  - [x] 7.1 Implement `renderKiroEvidenceMd` and the `scripts/kiro-evidence-md.ts` CLI wrapper that writes `docs/KIRO_EVIDENCE.md` from `evidence/kiro-sessions/index.json`
    - _Requirements: KE-15, KE-16, KE-17_
  - [ ]* 7.2 Write property test for one evidence row per session
    - **Property 8: Every kept session gets exactly one evidence row (KE-16)**
    - **Validates: Requirements 4.2**
  - [ ]* 7.3 Write unit tests for the totals section and the hook-block narration against a small fixed fixture
    - _Requirements: KE-15, KE-17_

- [x] 8. Facts keys
  - [x] 8.1 Add `kiroEvidence()` reader and `countShallLines`/`countTasks` counters to `scripts/facts.mjs`; wire `kiroSessions`, `kiroCredits`, `kiroToolCalls`, `hookRuns`, `hookBlocks` plus the SHALL-line and task-count keys into the facts object and the README markers
    - _Requirements: KE-18, KE-19, KE-20, KE-21_
  - [ ]* 8.2 Write property test for SHALL-line counting
    - **Property 9: SHALL-line counting matches construction (KE-20)**
    - **Validates: Requirements 4.6**
  - [ ]* 8.3 Write property test for task counting
    - **Property 10: Task counting matches construction (KE-21)**
    - **Validates: Requirements 4.7**
  - [ ]* 8.4 Write unit test for the facts keys and README marker substitution against a fixture `index.json`
    - _Requirements: KE-18, KE-19_

- [x] 9. Checkpoint: publishing and facts tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Spec trace
  - [x] 10.1 Implement `extractRequirementIds`, `extractTestedIds`, `diffIds` in `packages/core/src/spec-trace.ts`; export from `index.ts`
    - _Requirements: KE-22, KE-23_
  - [ ]* 10.2 Write property test for the bidirectional ID diff
    - **Property 11: Requirement/test ID diff is exact in both directions (KE-22, KE-23)**
    - **Validates: Requirements 5.1, 5.2**
  - [x] 10.3 Implement `scripts/spec-trace.mjs`: find ID-bearing specs, collect test names, report gaps per spec, exit 0 only when every spec has no gaps
    - _Requirements: KE-22, KE-23, KE-24_
  - [ ]* 10.4 Write property test for the exit-code rule
    - **Property 12: Exit code reflects the diff (KE-24)**
    - **Validates: Requirements 5.3**
  - [x] 10.5 Add `.kiro/hooks/spec-trace.json` (`PostFileSave`, matcher for `.kiro/specs/**` and test files, command through `scripts/kiro-hook.sh`)
    - _Requirements: KE-25_
  - [ ]* 10.6 Write unit test asserting the hook JSON's trigger, matcher and command shape
    - _Requirements: KE-25_

- [x] 11. Migrate m10-kiro-gate to requirement IDs
  - [x] 11.1 Add inline `KG-1`, `KG-2`, ... IDs to each acceptance criterion in `.kiro/specs/m10-kiro-gate/requirements.md`, and prefix the matching test names in `gate.test.ts`, `gate.property.test.ts`, the CLI tests and the hook/agent tests with the same IDs
    - _Requirements: KE-26_
  - [ ]* 11.2 Run `scripts/spec-trace.mjs` against the real repository and confirm zero gaps for `m10-kiro-gate`
    - _Requirements: KE-26_
  - [x] 11.3 Add a sentence to `docs/KIRO_EVIDENCE.md` (or `docs/REFERENCE.md`) stating plainly that every spec other than `m10-kiro-gate` and `m13-kiro-evidence` predates requirement IDs and is outside `spec-trace.mjs`'s coverage
    - _Requirements: KE-27_

- [x] 12. Checkpoint: spec-trace tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 13. New hooks
  - [x] 13.1 Add `.kiro/hooks/verify-after-task.json` (`PostTaskExec`, command through `scripts/kiro-hook.sh`, running `pnpm -r typecheck` plus the vitest files related to the changed files)
    - _Requirements: KE-28_
  - [x] 13.2 Add `.kiro/hooks/kiro-log.json` (`Stop`, agent action, prompt instructing: append one dated row to `docs/KIRO_LOG.md` naming files changed and spec task IDs completed when the turn changed anything, edit nothing else, do nothing when the turn changed nothing, invent nothing)
    - _Requirements: KE-29, KE-30_
  - [ ]* 13.3 Write unit tests asserting both hook files' trigger, action type and required prompt/command content
    - _Requirements: KE-28, KE-29, KE-30_

- [x] 14. Skills and red-team resources
  - [x] 14.1 Write `.kiro/skills/add-virus-definition/SKILL.md` (front matter plus steps: rule YAML, unit test, benchmark attack and benign look-alike, docs, facts)
    - _Requirements: KE-31_
  - [x] 14.2 Write `.kiro/skills/triage-finding/SKILL.md` (front matter plus steps: deciding true/false positive, suppressing with a reason or a baseline)
    - _Requirements: KE-32_
  - [x] 14.3 Add `resources: ["skill://add-virus-definition", "skill://triage-finding"]` to `.kiro/agents/exorcist-red-team.json`
    - _Requirements: KE-33_
  - [x]* 14.4 Write unit tests asserting both SKILL.md files' front matter and required step headings, and that the agent's resources list both `skill://` URIs and that both files exist
    - _Requirements: KE-31, KE-32, KE-33_

- [x] 15. Steering modes
  - [x] 15.1 Add `.kiro/steering/release.md` with `inclusion: manual` front matter and release-cutting guidance
    - _Requirements: KE-34_
  - [x] 15.2 Implement the directory-vs-table completeness comparison used by the steering table check (pure function, e.g. in `packages/core/src/steering-table.ts`)
    - _Requirements: KE-36_
  - [ ]* 15.3 Write property test for the completeness comparison
    - **Property 13: The steering table's completeness check is exact (KE-36)**
    - **Validates: Requirements 8.3**
  - [x] 15.4 Add `STEERING_TABLE` to `apps/web/src/lib/how-kiro.ts`, one row per file under `.kiro/steering/` with its mode, patterns and a plain-language reason
    - _Requirements: KE-35_
  - [ ]* 15.5 Write unit test asserting `STEERING_TABLE`'s file list equals the real `.kiro/steering/` directory listing
    - _Requirements: KE-35, KE-36_

- [x] 16. Checkpoint: hooks, skills and steering tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 17. Auditor agent
  - [x] 17.1 Write `.kiro/agents/exorcist-auditor.json`: `fs_write` allowed only under `docs/reviews/**` and denied elsewhere; `shell` allowed only for a fixed read-only command list plus `pnpm vitest run`, denied otherwise; prompt instructing an audit of one named package against `.kiro/steering/security.md` producing `docs/reviews/<date>-<package>-audit.md` with severity, file:line, evidence and a suggested fix
    - _Requirements: KE-37, KE-38, KE-39, KE-40_
  - [ ]* 17.2 Write unit tests asserting the `fs_write` and `shell` permission rules and the required prompt content
    - _Requirements: KE-37, KE-38, KE-39_

- [x] 18. Checkpoint: all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 19. Finish
  - Run `node scripts/kiro-evidence.mjs`; commit `evidence/kiro-sessions/` only if the safety rescan passes, otherwise report the failure and stop before committing it
  - Regenerate `docs/HOW_KIRO.md` from `apps/web/src/lib/how-kiro.ts`
  - Run `node scripts/facts.mjs --run-tests --docs`
  - Add a dated row to `docs/KIRO_LOG.md` for this work, attributed to the Kiro IDE agent
  - Move `TASK-kiro-evidence.md` to `docs/kiro-briefs/TASK-kiro-evidence.md`
  - Run `pnpm -r typecheck` and `pnpm vitest run` until both pass
  - Commit the work; do not push
  - _Requirements: KE-41, KE-42, KE-43, KE-44, KE-45, KE-46, KE-47_

- [x] 20. Redact JWTs, AWS account IDs, emails and sign-in output in the export
  - [x] 20.1 Implement the four redactions and the sign-in output omission in `packages/core/src/kiro-evidence.ts`
    - JWT to `[redacted jwt]`, ARN and `Account` IDs to `[redacted account]`, non-example emails to `[redacted email]`, sign-in tool output to `[omitted: sign-in output]`
    - Apply in the deep redaction and the final per-line pass; add the JWT shape to the shared `redact-secrets` patterns only
    - _Requirements: KE-48, KE-49, KE-50, KE-51_
  - [x] 20.2 Add JWT and ARN-account shapes to `containsSecretShape` so the after-write rescan fails on them
    - _Requirements: KE-52_
  - [x] 20.3 Write KE tests with made-up values built at runtime, one per KE-48 to KE-52
    - Test names start with the KE-ID
    - _Requirements: KE-53_
  - [x] 20.4 Re-run `node scripts/kiro-evidence.mjs`, regenerate `docs/KIRO_EVIDENCE.md`, refresh facts, run the KE tests, `pnpm -r typecheck` and `pnpm vitest run`, and commit as a new commit without pushing
    - _Requirements: KE-46, KE-47_

- [x] 21. Redact sign-in URLs and omit files read outside the workspace
  - [x] 21.1 Implement KE-54 and KE-55 in `packages/core/src/kiro-evidence.ts`
    - URL redaction in the deep redaction and the final per-line pass (escaped forms included); pair `read_file`/`fs_read` calls with results by tool-call id and omit home-folder paths outside `workspacePaths`
    - _Requirements: KE-54, KE-55_
  - [x] 21.2 Add the sign-in URL shape to `containsSecretShape` so the after-write rescan fails on it
    - _Requirements: KE-56_
  - [x] 21.3 Write KE tests with made-up values built at runtime, one per KE-54, KE-55 and KE-56
    - Test names start with the KE-ID
    - _Requirements: KE-57_
  - [x] 21.4 Re-run `node scripts/kiro-evidence.mjs`, regenerate `docs/KIRO_EVIDENCE.md`, refresh facts, run the KE tests, `pnpm -r typecheck` and `pnpm vitest run`, and commit as a new commit without pushing
    - _Requirements: KE-46, KE-47_

- [x] 22. Drop model signature fields from the export
  - [x] 22.1 Implement KE-58 in `packages/core/src/kiro-evidence.ts` and write a KE-58 test
    - Remove `reasoningSignature` and `signature` at any depth in the same pass that drops images, before redaction
    - Test name starts with `KE-58`, using made-up values built at runtime
    - _Requirements: KE-58_
  - [x] 22.2 Re-run `node scripts/kiro-evidence.mjs`, regenerate `docs/KIRO_EVIDENCE.md`, refresh facts, run the KE tests, `pnpm -r typecheck` and `pnpm vitest run`, and commit as a new commit without pushing
    - _Requirements: KE-46, KE-47_

## Notes
- Tasks marked with `*` are optional and can be skipped for a faster pass; they are not implemented automatically when executing this plan.
- Each leaf task references the KE-IDs it covers; test names for those tasks must start with the referenced KE-ID.
- `m10-kiro-gate` is the first spec migrated to requirement IDs (task 11); specs other than it and `m13-kiro-evidence` predate IDs and are not covered by `spec-trace.mjs`.
- The auditor agent (task 17) is written but never started as part of this plan.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1"] },
    { "id": 1, "tasks": ["2.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "2.4", "2.5", "2.6"] },
    { "id": 3, "tasks": ["3.1"] },
    { "id": 4, "tasks": ["3.2", "3.3", "3.4"] },
    { "id": 5, "tasks": ["4"] },
    { "id": 6, "tasks": ["5.1"] },
    { "id": 7, "tasks": ["5.2"] },
    { "id": 8, "tasks": ["5.3"] },
    { "id": 9, "tasks": ["6"] },
    { "id": 10, "tasks": ["7.1", "8.1"] },
    { "id": 11, "tasks": ["7.2", "7.3", "8.2", "8.3", "8.4"] },
    { "id": 12, "tasks": ["9"] },
    { "id": 13, "tasks": ["10.1"] },
    { "id": 14, "tasks": ["10.2", "10.3"] },
    { "id": 15, "tasks": ["10.4", "10.5"] },
    { "id": 16, "tasks": ["10.6"] },
    { "id": 17, "tasks": ["11.1"] },
    { "id": 18, "tasks": ["11.2", "11.3"] },
    { "id": 19, "tasks": ["12"] },
    { "id": 20, "tasks": ["13.1", "13.2", "14.1", "14.2", "15.1", "15.2"] },
    { "id": 21, "tasks": ["13.3", "14.3", "15.3"] },
    { "id": 22, "tasks": ["14.4", "15.4"] },
    { "id": 23, "tasks": ["15.5"] },
    { "id": 24, "tasks": ["16"] },
    { "id": 25, "tasks": ["17.1"] },
    { "id": 26, "tasks": ["17.2"] },
    { "id": 27, "tasks": ["18"] },
    { "id": 28, "tasks": ["19"] },
    { "id": 29, "tasks": ["20.1"] },
    { "id": 30, "tasks": ["20.2"] },
    { "id": 31, "tasks": ["20.3"] },
    { "id": 32, "tasks": ["20.4"] },
    { "id": 33, "tasks": ["21.1"] },
    { "id": 34, "tasks": ["21.2"] },
    { "id": 35, "tasks": ["21.3"] },
    { "id": 36, "tasks": ["21.4"] },
    { "id": 37, "tasks": ["22.1"] },
    { "id": 38, "tasks": ["22.2"] }
  ]
}
```
