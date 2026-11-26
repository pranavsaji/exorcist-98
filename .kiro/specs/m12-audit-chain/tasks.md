# Implementation Plan: m12-audit-chain

## Overview

Convert the design into incremental coding steps. Each task builds on the ones before it and ends with the pieces wired together; no step leaves orphaned code. Test names start with the AC-ID they check (e.g. `it('AC-1: ...')`). Property tests are sub-tasks tagged with their design Property number and are not optional. Follow `.kiro/steering/` (security, tech, untrusted-output, repo-input): TypeScript strict, no `any`, typed results, zod at boundaries, never log file contents, never trust a grant written inside the state folder as more than drift-detection.

## Tasks

- [x] 1. Create `packages/shield/src/chain.ts` with the pure chain core
  - Export `Genesis`, `ChainFields`, `ChainedShieldEvent`, `HeadRecord`, `HeadRecordSchema` (zod), `ChainStatus`, `VerifyOptions`.
  - Implement `canonicalize(e)` (stable key order, includes `seq`/`prev`, excludes `hash`) and `eventHash(e)` (SHA-256 hex of `canonicalize(e)`).
  - Implement `verifyChain(lines, head, genesis, opts?)`: pure, no `node:fs` import, single pass over `lines`, returns `intact` / `not-chained` / `broken` (reasons `changed`, `removed`, `inserted`, `reordered`, `head-mismatch`, `expect-mismatch`) per the design's Chain_Status rules.
  - _Requirements: AC-1, AC-4, AC-5, AC-8, AC-30, AC-31_

- [x] 2. Add genesis and head file I/O to `chain.ts`
  - Implement `genesisPath(dir)`, `headPath(dir)`, `loadOrCreateGenesis(dir, random?)` (defaults to `randomBytes(32)`, writes once, returns the existing value on a second call), `readHead(dir)` (null when absent, validated with `HeadRecordSchema`), `writeHeadAtomic(dir, head)` (temp file in the same directory, then rename).
  - All I/O helpers return a `Result`-shaped value; none throw across the module boundary.
  - Export every new symbol from `packages/shield/src/index.ts`.
  - _Requirements: AC-2, AC-3_

- [x] 2.1 Write property test for the chain core
  - **Property 1: Building a chain from a sequence of events is self-consistent and matches the head**
  - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 6.1**

- [x] 2.2 Write property test for not-chained classification
  - **Property 3: A log with no chained events is reported as not-chained, never as broken**
  - **Validates: Requirements 1.5**

- [x] 2.3 Write property test for tamper detection
  - **Property 4: Any single-event tamper on a chained log is detected, and an untouched one is not**
  - **Validates: Requirements 2.2, 6.2**

- [x] 3. Add a shared lock helper and wire chaining into `EventLog.write`
  - In `packages/shield/src/events.ts`, factor the existing rotation `mkdirSync`/stale-lock logic into a small `withLock(dir, fn)` used by both `rotate()` and the new chaining step, preserving today's `STALE_LOCK_MS` recovery.
  - Add `EventLogOptions.chain` (default `true`) and `EventLogOptions.random`. In `write()`, when chaining is enabled: take the lock, call `readHead`/`loadOrCreateGenesis`, compute `seq`/`prev`/`hash` via `chain.ts`, merge into the record before `JSON.stringify`, perform the existing single `writeSync`, call `writeHeadAtomic`, release the lock.
  - If the lock cannot be obtained after bounded retries, write the event unchained (no `seq`/`prev`/`hash`) rather than dropping it or blocking; set `this.problem` accordingly.
  - _Requirements: AC-1, AC-2, AC-3, AC-6_

- [x] 3.1 Write property test for concurrent append ordering
  - **Property 2: Concurrent appends from several writers still produce one correctly ordered chain**
  - **Validates: Requirements 1.6**

- [x] 3.2 Write integration test for real multi-process concurrency
  - Spawn 2-3 real Node child processes, each calling `EventLog.write` against the same state folder; after all exit, `verifyChain` over the result is `intact` with the expected event count and no duplicate `seq`.
  - _Requirements: AC-6_

- [x] 3.3 Write unit tests for unchained fallback and old-log compatibility
  - `AC-5`: a log written with `chain: false` loads and reports `not-chained`. A lock that cannot be obtained within the retry bound still writes the event (unchained).
  - _Requirements: AC-5_

- [x] 4. Checkpoint - chain core and writer
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Create `verifyLogDir` and the streaming file reader
  - In `chain.ts`, implement `verifyLogDir(dir, opts?)`: reads `events.1.jsonl` then `events.jsonl` (reusing the existing line-parsing approach from `parseEventLines`), reads the head and genesis files, and calls `verifyChain` in one streaming pass (no O(n^2) re-hashing).
  - _Requirements: AC-7, AC-8, AC-9, AC-10, AC-13_

- [x] 5.1 Write performance integration test
  - Build a 100,000-event chained log via direct `EventLog.write` calls; assert `verifyLogDir` completes in under 15 seconds (parallel-load headroom; time logged) and reports `intact`.
  - _Requirements: AC-13_

- [x] 6. Create `exorcist verify-log`
  - New file `packages/cli/src/commands/verify-log.ts`: parse `--dir`, `--expect`, `--json`, `--help` with the project's `parse()`/`Io` pattern; malformed `--expect` or an unknown flag/extra positional exits 2.
  - Call `verifyLogDir`. Plain-text mode: one line for `intact` (states the head hash), one line naming the sequence number and reason for `broken` (including `head-mismatch` and `expect-mismatch`, worded as in the design), one line for `not-chained`. `--json` mode prints `JSON.stringify(ChainStatus)` only.
  - Exit codes: `intact` → 0; `broken`/`expect-mismatch` → 1; usage error → 2.
  - Register the command and its help text in `packages/cli/src/index.ts`.
  - _Requirements: AC-7, AC-8, AC-9, AC-10, AC-11, AC-12_

- [x] 6.1 Write unit tests for verify-log CLI wiring
  - `AC-7`: intact prints the head hash, exit 0. `AC-8`: one example per tamper kind (changed, removed, inserted, reordered), naming the sequence number, exit 1. `AC-9`: truncated log vs head file, exit 1. `AC-10`: `--expect` match and mismatch, exit 1 on mismatch. `AC-11`: malformed `--expect`, unknown flag, exit 2. `AC-12`: `--json` shape for each of the three statuses.
  - _Requirements: AC-7, AC-8, AC-9, AC-10, AC-11, AC-12_

- [x] 7. Checkpoint - verify-log command
  - Ensure all tests pass, ask the user if questions arise.

- [x] 8. Surface the head hash in `exorcist alerts` and `exorcist gate`
  - In `packages/cli/src/commands/approve.ts` (`alertsCommand`): after printing alert lines, read `readHead(dir)` and print the head hash, or a plain note when no head exists yet.
  - In `packages/cli/src/commands/gate.ts` (`gateCommand`): include the current head hash in its output when a head file exists.
  - _Requirements: AC-14, AC-15_

- [x] 8.1 Write unit tests for alerts and gate head-hash output
  - `AC-14`: `exorcist alerts` output contains the head hash when a head file exists. `AC-15`: `exorcist gate` output contains the head hash when a head file exists.
  - _Requirements: AC-14, AC-15_

- [x] 9. Add chain status to the console model and page
  - In `packages/cli/src/console/model.ts`: add `ConsoleState.chain: ChainStatus | null`, recomputed each poll from the events `EventTail` already buffered plus a read-only `readHead`/genesis read.
  - In `packages/cli/src/console/page.ts`: render a badge using the three Chain_Status text labels verbatim ("intact", "broken at event N", "not chained") as the primary signal, color as secondary only.
  - _Requirements: AC-16, AC-18_

- [x] 9.1 Write unit tests for the console chain badge
  - `AC-16`: head hash and chain status appear in `ConsoleState` given a prepared head file. `AC-18`: one example per Chain_Status value renders its label text, not color alone.
  - _Requirements: AC-16, AC-18_

- [x] 10. Checkpoint - head hash visible in alerts, gate and console
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Write `docs/KNOWN_LIMITATIONS.md` entry for the chain's limit
  - Add a row stating plainly: anyone who can write the state folder can rewrite the whole Event_Log and Head_File together; the chain still catches a partial edit; it catches a full rewrite only when a previous head hash was saved outside the state folder and checked with `--expect`.
  - _Requirements: AC-17_

- [x] 12. Add browser-safe chain controls to the web Possession Lab demos
  - Extend the Rug Pull and Trifecta scenario scripted event data so each scripted event carries `seq`/`prev`/`hash`, computed by a build/test-time script calling `chain.ts`'s `eventHash`/`canonicalize`.
  - Create `ChainControls` (new component next to `PossessionLab.tsx`) with "Rewrite an event" (mutates one field of one displayed event in React state, leaving its chain fields unchanged) and "Verify the log" (calls `verifyChain` from `@exorcist-98/shield` against the current in-state array and head value, renders the result and an `aria-live="polite"` announcement using the same three-label vocabulary as the console badge).
  - Both controls are plain `<button>` elements with `aria-label`s stating their effect in plain language, reachable by Tab/Enter.
  - Wire `ChainControls` into both the Rug Pull and Trifecta demo panes in `PossessionLab.tsx`.
  - _Requirements: AC-19, AC-20, AC-21, AC-22_

- [x] 12.1 Write component tests for the demo chain controls
  - `AC-19`: "Rewrite an event" changes exactly one event field. `AC-20`: "Verify the log" after a rewrite shows the sequence number and reason. `AC-21`: "Verify the log" with no rewrite shows intact. `AC-22`: both controls operable via keyboard events only; the live region's text updates on verify.
  - _Requirements: AC-19, AC-20, AC-21, AC-22_

- [x] 12.2 Add an axe accessibility check to the e2e script
  - In `scripts/e2e-chrome.mjs`, add a step that opens a page with the Rug Pull or Trifecta demo's chain controls visible and asserts the existing axe run reports 0 violations.
  - _Requirements: AC-23_

- [x] 13. Checkpoint - web demo chain controls
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. Fix the approval-code gap: expiry and single use
  - In `packages/cli/src/commands/on-access.ts`: change the typed-code fallback to generate `{ code, issuedAt }` (`ApprovalCode`), add an injectable `now()` (default `() => new Date()`) to `Terminal`/the relevant call sites, and implement pure `checkCode(answer, ticket, nowMs, usedAlready, ttlMs = 15 * 60 * 1000): CodeVerdict` (`'ok' | 'mismatch' | 'expired' | 'used'`).
  - Update `personConfirms` to track whether the generated code has already been checked successfully within the call (a local used-flag) and to call `checkCode` instead of `confirms`; on `'expired'` or `'used'` print a distinct refusal message; keep `confirms`'s old signature removed in favor of `checkCode` (update `askOwner`'s and `allowReadCommand`'s/`approveCommand`'s call sites).
  - _Requirements: AC-25, AC-26_

- [x] 14.1 Write property test for approval code expiry
  - **Property 7: An approval code is rejected once its time-to-live has passed**
  - **Validates: Requirements 5.2**

- [x] 14.2 Write property test for approval code single use
  - **Property 8: An approval code cannot be confirmed twice**
  - **Validates: Requirements 5.3**

- [x] 15. Checkpoint - approval code gap fix
  - Ensure all tests pass, ask the user if questions arise.

- [x] 16. Pin the existing OS-release single-use and full-re-check behavior with property tests
  - No production code change expected here (the design found `engine.ts`'s `onOwnerVerified`/`afterOwnerVerified` already satisfy this); add the tests against the current `packages/shield/src/engine.ts` and fix forward only if a test finds a real gap.
  - _Requirements: AC-24, AC-27_

- [x] 16.1 Write property test for OS-release single-use tickets
  - **Property 5: An OS-release ticket can release at most one held call**
  - **Validates: Requirements 5.1**

- [x] 16.2 Write property test for full re-check at release time
  - **Property 6: An OS-released call is re-evaluated against current state, not passed through unconditionally**
  - **Validates: Requirements 5.4**

- [x] 17. Chain every approval, refusal and expiry outcome
  - In `packages/shield/src/engine.ts`, confirm (and if missing, add) a `callEvent`/`EventLog.write` call for every outcome of `onOwnerVerified`, `onApprovalAnswer` and `onSessionAnswer` (already present per the design's research; add only what is missing).
  - In `packages/cli/src/commands/on-access.ts`, add a best-effort `EventLog` write at the three CLI-side outcomes that do not go through the engine (`approve session`/`allow-read`: accepted, declined, code expired), using the same never-throw contract as `EventLog.write`.
  - _Requirements: AC-29_

- [x] 17.1 Write property test for chained approval outcomes
  - **Property 9: Every held-call outcome produces exactly one new chained event**
  - **Validates: Requirements 5.6**

- [x] 17.2 Write unit tests for AC-28's reachability boundaries
  - `AC-28`: `exorcist approve session`/`exorcist allow-read` refuse before any prompt when `term.interactive` is false; no JSON-RPC message type accepted by the engine drives `onOwnerVerified` other than the proxy's own call with a verdict from `macOsAuth`.
  - _Requirements: AC-28_

- [x] 18. Checkpoint - approvals chained and pinned
  - Ensure all tests pass, ask the user if questions arise.

- [x] 19. Update `docs/REFERENCE.md`
  - Document `exorcist verify-log` (usage, exit codes, `--json`, `--expect`) and the Shield's hash-chained event log (head file, per-event `seq`/`prev`/`hash`, what it detects and what it does not) alongside the existing CLI command table and Shield section.
  - _Requirements: AC-7, AC-8, AC-9, AC-10, AC-11, AC-12, AC-17_

- [x] 20. Run `node scripts/facts.mjs --run-tests --docs`
  - Fix anything it reports as out of date.
  - _Requirements: AC-7 through AC-31 (documentation and fact consistency)_

- [x] 21. Add the row to `docs/KIRO_LOG.md`
  - Add a row for this work (m12-audit-chain) by the Kiro IDE agent: spec path, the hash-chained event log, `exorcist verify-log`, the head hash in alerts/gate/console, the web demo chain controls, and the approval single-use/expiry/chaining fixes.
  - _Requirements: AC-17_

- [x] 22. Move the brief to `docs/kiro-briefs/`
  - Move `TASK-audit-chain.md` to `docs/kiro-briefs/TASK-audit-chain.md`, matching the existing convention for completed briefs in that folder.
  - _Requirements: none (process step)_

- [x] 23. Run `pnpm -r typecheck` from the repository root
  - Fix every error. No `any`, no `@ts-ignore`.
  - _Requirements: AC-1 through AC-31 (typecheck gate)_

- [x] 24. Run `pnpm vitest run` from the repository root
  - All tests pass, including the full existing suite. Ensure all tests pass, ask the user if questions arise.
  - _Requirements: AC-1 through AC-31 (test gate)_

- [x] 25. Commit the work without pushing
  - Stage the new and changed files (spec, `packages/shield`, `packages/cli`, `apps/web`, `docs/REFERENCE.md`, `docs/KNOWN_LIMITATIONS.md`, `docs/KIRO_LOG.md`, `docs/THREATS.md`, `docs/kiro-briefs/TASK-audit-chain.md`) and commit with a message describing the hash-chained log, `verify-log`, and the approval hardening. Do not push.
  - _Requirements: none (process step)_

## Notes

- Tasks marked `*` are optional sub-tasks (tests) and are still required to be written and passing before their parent task's checkpoint; "optional" here follows the workflow convention that only non-test tasks are mandatory top-level items, but every AC must still have a test per the project's test-naming rule (`it('AC-N: ...')`).
- No test may write to a real `~/.exorcist` or production state folder; every test uses a temporary directory.
- Task 16 may find the existing engine code already satisfies AC-24/AC-27 with no change; that is an acceptable, expected outcome of writing the property tests first.
- `exorcist approve session`'s OS-mode short-circuit (writes nothing, returns 1) from m6-os-release is unchanged by this feature; only the terminal fallback code gains expiry and single-use.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1"] },
    { "id": 1, "tasks": ["2.1", "2.2", "2.3"] },
    { "id": 2, "tasks": ["3.1", "3.2", "3.3"] },
    { "id": 3, "tasks": ["4"] },
    { "id": 4, "tasks": ["5.1"] },
    { "id": 5, "tasks": ["6.1"] },
    { "id": 6, "tasks": ["7"] },
    { "id": 7, "tasks": ["8.1", "9.1"] },
    { "id": 8, "tasks": ["10"] },
    { "id": 9, "tasks": ["11", "12.1", "12.2"] },
    { "id": 10, "tasks": ["13"] },
    { "id": 11, "tasks": ["14.1", "14.2"] },
    { "id": 12, "tasks": ["15"] },
    { "id": 13, "tasks": ["16.1", "16.2"] },
    { "id": 14, "tasks": ["17.1", "17.2"] },
    { "id": 15, "tasks": ["18"] },
    { "id": 16, "tasks": ["19"] },
    { "id": 17, "tasks": ["20"] },
    { "id": 18, "tasks": ["21"] },
    { "id": 19, "tasks": ["22"] },
    { "id": 20, "tasks": ["23"] },
    { "id": 21, "tasks": ["24"] },
    { "id": 22, "tasks": ["25"] }
  ]
}
```
