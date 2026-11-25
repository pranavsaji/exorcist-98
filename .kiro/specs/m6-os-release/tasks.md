# Implementation Plan: m6-os-release

## Overview

A flat, ordered list. Each task is a leaf, builds on the ones before it, and names the requirements it covers. Tests are required (none are optional). Run the tasks one at a time. Follow `.kiro/steering/` (security, tech, untrusted-output, repo-input): TypeScript strict, no `any`, typed results, zod at boundaries, never log file contents.

## Tasks

- [x] 1. Create `packages/shield/src/os-auth.ts` with the types and pure helpers
  - Export `OsVerdict`, `OsAuth`, `blockedReason(env, platform)`, `sanitizeReason`, `buildReason(server, tool, facts)` (uses `describeFact`, then `sanitizeReason`).
  - `sanitizeReason` removes control, bidi, zero-width and tag characters (`u` flag, U+E0000 to U+E007F), collapses whitespace, caps at 200 characters.
  - Export from `packages/shield/src/index.ts`.
  - _Requirements: 1.1, 2.3, 2.4, 3.1, 3.2, 3.3, 3.6_

- [x] 2. Add `macOsAuth()` and `resolveRelease()` to `os-auth.ts`
  - Fixed constants `AVAILABLE_SCRIPT` and `VERIFY_SCRIPT` (ObjC bridge, `$.LAContext`, policy 2, `canEvaluatePolicyError`, `evaluatePolicyLocalizedReasonReply`, spin `$.NSRunLoop` until the reply). The reason is read from env `EXORCIST_REASON`, never put in the script or argv.
  - Spawn `/usr/bin/osascript -l JavaScript -e <script>` with a minimal env and stderr ignored; 60 s timeout kills the child and returns `'timeout'`; spawn errors and unknown output return `'error'`; exit codes map cancel and failure to `'denied'`.
  - Check `blockedReason` before any spawn, on every call. Spawner, env, platform and timeout are injectable.
  - `resolveRelease(policyValue, osAuth)` returns `{ mode, note? }`: `terminal` skips `available()`; `os` or absent uses `available()`; a throw counts as unavailable and gives a plain-language note.
  - _Requirements: 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.1, 2.2, 3.7, 3.8, 4.3, 4.4, 4.5, 10.3, 10.4_

- [x] 3. Add `sessionRelease` to the policy
  - In `packages/shield/src/policy.ts` add `sessionRelease: z.enum(['os', 'terminal']).optional()` to `PolicySchema`. Leave `DEFAULT_POLICY` unchanged.
  - Confirm `primitives.test.ts` still passes unchanged.
  - _Requirements: 4.1, 4.2, 12.3_

- [x] 4. Let the Session Guard ignore grants
  - In `packages/shield/src/session.ts` add a trailing `opts?: { ignoreGrants?: boolean }` to `assessSession` (no writer trusted when set) and pass it through `SessionGuard.assess(opts?)`. Defaults keep today's behaviour.
  - _Requirements: 7.1, 7.2_

- [x] 5. Add the OS release path to the engine
  - In `packages/shield/src/engine.ts`: add `Action` type `verify-owner`, `EngineOptions.release`, held-call kind `'os'`, and `onOwnerVerified(ticket, verdict)` and `abandon()`.
  - In `sessionCheck`: under `os` and mode `hold`, assess with `ignoreGrants`, hold the call, alert, and emit `verify-owner` with `buildReason(...)`; do not use the client elicitation prompt. Reuse the `MAX_OPEN_PROMPTS` limit.
  - `ok` sends the call once with no grant; `denied`, `error`, `timeout` refuse with the existing held message plus a note and a do-not-release-yourself line; unknown tickets return `[]`.
  - Under `terminal` with a note, add "release is by terminal because OS verification is unavailable here" to the refusal text and alert. Policy `terminal` adds nothing. `block`, `monitor`, `off` unchanged.
  - Alerts contain the cleaned tool and server names only, never the reason text.
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.6, 5.7, 6.1, 6.2, 6.3, 6.4, 6.5, 7.1, 7.4, 8.1, 8.2, 8.3, 8.4, 10.1, 10.2_

- [x] 6. Wire the Shield process
  - In `packages/shield/src/proxy.ts` (`prepareShield`, near the `SessionGuard` construction): add `ProxyOptions.osAuth`, call `resolveRelease` once, log the release mode and any fallback note, pass `release` to the engine, handle `verify-owner` in `handle` through a single promise chain (one prompt at a time), and expose `attach(deliver)` that `runProxy` and `packages/shield/src/remote.ts` call with their existing deliver function. Treat a rejected `verify` as `'error'`. Call `engine.abandon()` when the client input ends.
  - _Requirements: 4.6, 4.7, 5.2, 5.5, 6.3_

- [x] 7. Update `exorcist approve session` for OS release
  - In `packages/cli/src/commands/approve.ts`: add an injectable `osAuth` parameter (default `macOsAuth()`), resolve the release from the state folder's policy, and under `os` print that release happens in the system prompt, write nothing and return `1`, before the interactive check, the dialog and `grantSession`. Update `APPROVE_HELP`. `terminal` is unchanged.
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

- [x] 8. Test the pure helpers (`m6-os-release.test.ts`)
  - Create `packages/shield/src/__tests__/m6-os-release.test.ts`. Examples for `sanitizeReason` (control, bidi, zero-width, tag, whitespace, 200-cap) and `buildReason` (names server, tool, both facts).
  - fast-check, 100+ runs: **Property 1** (clean and bounded) and **Property 2** (idempotent), tagged `Feature: m6-os-release, Property N`.
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

- [x] 9. Test the real implementation with a fake spawner
  - Same test file. Fake spawner and injected non-blocked `darwin` env: `ok` and `denied` outputs, `error` on bad output and spawn error, `timeout` with a short injected timeout that checks the child was killed, minimal env, stderr ignored.
  - **Property 3** (script constant, reason only in `EXORCIST_REASON`, not in argv) and **Property 4** (blocked environments: non-darwin, `VITEST`, `CI`, `EXORCIST_OS_AUTH=off` never call the spawner; `available()` false, `verify()` `'error'`). Also assert `blockedReason` text per cause. Also `resolveRelease` cases (terminal skips `available()`, os and absent, fallback note, throwing `available()`).
  - _Requirements: 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 2.1, 2.2, 2.3, 2.4, 3.7, 3.8, 4.3, 4.4, 4.5, 10.3, 10.4_

- [x] 10. Test that a successful prompt releases exactly one call
  - Same file, harness like `s027-session-guard.test.ts`, fake `OsAuth`. Arm the session, make a call: nothing reaches the server and a `verify-owner` action carries the reason; answer `ok`: the call is sent once, no grant in any record, and the next armed call is held again. Two held calls are asked in order. No elicitation prompt under `os`.
  - **Property 5** (ignoring grants never arms less) and **Property 6** (each `ok` releases exactly one call, no grant written).
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 7.3_

- [x] 11. Test that denied, error and timeout refuse
  - Same file. For each verdict: nothing sent, error result with the original request id, the existing held message plus a note, no grant, EX-027 alert states the outcome. Unknown and repeated tickets return no actions. `abandon()` drops open held calls and a late answer is ignored.
  - **Property 7** (any non-ok verdict refuses and grants nothing).
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 12. Test that forged grants are ignored under `os`
  - Same file. Write a valid `cli.json` with `grantSession` on a `FileSessionStore`, and a grant in the Shield's own record: under `os` the armed call is still held and asked; under `terminal` the grants still release as before.
  - _Requirements: 7.1, 7.2, 7.4_

- [x] 13. Test terminal mode, fallback text and policy
  - Same file. **Property 8** (terminal mode equals the engine without `release`), including hold with prompt, hold without prompt, block, monitor and off. Fallback note appears in the refusal and alert only when OS verification is unavailable, not when policy says `terminal`. `PolicySchema` accepts `os` and `terminal`, rejects other values, and an old policy file without the key validates; `DEFAULT_POLICY` has no `sessionRelease`.
  - _Requirements: 4.1, 4.2, 8.1, 8.2, 8.3, 8.4_

- [x] 14. Test the proxy wiring
  - In `packages/shield/src/__tests__/` (next to the existing proxy tests): `prepareShield` with a fake `osAuth` logs the release mode, falls back with a note when unavailable, runs prompts one at a time through the promise chain, and delivers the result to the attached deliver function. No real prompt: a test using the default `macOsAuth()` runs under `VITEST` and asserts nothing was spawned.
  - _Requirements: 2.1, 4.6, 4.7, 5.5, 6.3_

- [x] 15. Test the CLI
  - In `packages/cli/src/__tests__/` (next to the `approve` tests): under `os` with a fake `osAuth`, `approve session <key>` prints the system-prompt message, returns `1`, writes no file in `sessions/<key>/` and does not call the dialog. Under `terminal` (policy or unavailable) the existing tests' behaviour is unchanged. Help text mentions the OS release.
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

- [x] 16. Test that no reason text or file content is logged
  - Same Shield test file. Run an `os` release with a reason containing a marker string; assert the alerts, log lines and state files never contain the marker or the argument text, and the alert contains only the cleaned tool and server names.
  - _Requirements: 10.1, 10.2_

- [x] 17. Update README and docs/KNOWN_LIMITATIONS.md
  - README Session Guard row: on macOS the release is verified by the operating system (Touch ID or login password), a forged `cli.json` no longer releases a call, and `sessionRelease` in `policy.json` chooses `os` or `terminal`.
  - S-027: say what is closed (forged release by another program on macOS) and what is not (a program with the user's rights can still kill the Shield, edit `policy.json` to set `sessionRelease` to `terminal`, or replace the Shield binary; non-macOS unchanged; a person present can click through the prompt). Update the EX-027 row in `docs/THREATS.md` from "planned" to the implemented text.
  - _Requirements: 11.1, 11.2, 11.3_

- [x] 18. Add the row to docs/KIRO_LOG.md
  - Add a row dated 2026-11-24 saying this feature (m6-os-release) was specified and implemented by the Kiro IDE agent, with the spec path and the new files.
  - _Requirements: 11.4_

- [x] 19. Run `pnpm -r typecheck` from the repository root
  - Fix every error. No `any`, no `@ts-ignore`.
  - _Requirements: 12.1_

- [x] 20. Run `pnpm vitest run` from the repository root
  - All tests pass, including `primitives.test.ts`. Ensure all tests pass, ask the user if questions arise.
  - _Requirements: 12.2, 12.3_

## Notes

- Every requirement has a test task: REQ-01 (9), REQ-02 (9, 14), REQ-03 (8, 9), REQ-04 (9, 13, 14), REQ-05 (10, 14), REQ-06 (11, 14), REQ-07 (10, 12), REQ-08 (13), REQ-09 (15), REQ-10 (9, 16), REQ-11 (docs, 17 and 18), REQ-12 (19, 20).
- No test may start a real prompt: only fakes and the injected spawner are used.
- Task 6 changes `proxy.ts` and `remote.ts`; both are small and covered by task 14.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1"] },
    { "id": 1, "tasks": ["2"] },
    { "id": 2, "tasks": ["3"] },
    { "id": 3, "tasks": ["4"] },
    { "id": 4, "tasks": ["5"] },
    { "id": 5, "tasks": ["6"] },
    { "id": 6, "tasks": ["7"] },
    { "id": 7, "tasks": ["8"] },
    { "id": 8, "tasks": ["9"] },
    { "id": 9, "tasks": ["10"] },
    { "id": 10, "tasks": ["11"] },
    { "id": 11, "tasks": ["12"] },
    { "id": 12, "tasks": ["13"] },
    { "id": 13, "tasks": ["14"] },
    { "id": 14, "tasks": ["15"] },
    { "id": 15, "tasks": ["16"] },
    { "id": 16, "tasks": ["17"] },
    { "id": 17, "tasks": ["18"] },
    { "id": 18, "tasks": ["19"] },
    { "id": 19, "tasks": ["20"] }
  ]
}
```
