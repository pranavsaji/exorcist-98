# Requirements Document

## Introduction

The Session Guard (EX-027) holds an outbound tool call once an agent session has taken in untrusted text and read private data. Today the person releases the call with `exorcist approve session <key>`, which writes a grant into `<state folder>/sessions/<key>/cli.json`. Any program running as the same user can write that file, so the release can be forged (docs/KNOWN_LIMITATIONS.md, S-027).

This feature (m6-os-release) moves the release into the operating system. On macOS, the Shield process asks the OS to verify the device owner (Touch ID, or the login password as the OS fallback) at the moment it holds a call. Another program cannot answer that prompt. Where the OS check is not available, behaviour stays as it is today and the refusal text says so.

## Glossary

- **Shield**: the Exorcist 98 proxy process that wraps one MCP server (`packages/shield`).
- **Session_Guard**: the EX-027 logic in `packages/shield/src/session.ts` and `engine.ts`.
- **Held_Call**: an outbound tool call the Session_Guard has stopped and not yet sent or refused.
- **Armed_Call**: a call that the Session_Guard assesses as armed (untrusted text and private data both seen in the session) and that could send data out.
- **OS_Auth**: the injected interface `{ available(): Promise<boolean>; verify(reason: string): Promise<'ok'|'denied'|'error'|'timeout'> }` in `packages/shield/src/os-auth.ts`.
- **Mac_OS_Auth**: the real OS_Auth implementation, `macOsAuth()`, which runs `osascript -l JavaScript` with a fixed script.
- **Release_Mode**: `os` (the OS verifies the device owner) or `terminal` (today's `exorcist approve session` and the client prompt).
- **Reason_Text**: the string shown in the OS prompt. It names the MCP server, the tool and the facts that armed the guard. It is untrusted text.
- **Grant**: a record in a session file (`cli.json`, or a Shield's own record) that lets data go out.
- **Policy_File**: `<state folder>/policy.json`, validated by `PolicySchema` in `packages/shield/src/policy.ts`.
- **CLI**: `packages/cli`, command `exorcist approve session`.
- **Blocked_Environment**: any of: `process.platform` is not `darwin`; `VITEST` is set; `CI` is set; `EXORCIST_OS_AUTH=off`.

## Requirements

### REQ-01 OS verification behind an injected interface

**User Story:** As a developer, I want the OS call behind a small interface, so that tests use a fake and no test ever opens a real prompt.

#### Acceptance Criteria

1. THE OS_Auth interface SHALL expose `available()` and `verify(reason)` with the result type `'ok' | 'denied' | 'error' | 'timeout'`, and neither method SHALL throw across the package boundary.
2. WHEN `verify(reason)` is called on Mac_OS_Auth in an allowed environment, THE Mac_OS_Auth SHALL run `/usr/bin/osascript -l JavaScript` with a fixed script that imports LocalAuthentication, creates an `LAContext`, evaluates policy 2 (`LAPolicyDeviceOwnerAuthentication`) with `evaluatePolicyLocalizedReasonReply`, and spins `NSRunLoop` until the reply arrives.
3. WHEN `available()` is called on Mac_OS_Auth in an allowed environment, THE Mac_OS_Auth SHALL run a fixed script that calls `canEvaluatePolicyError` for policy 2 and SHALL resolve `true` only when that call succeeds.
4. WHEN the script reports success, THE Mac_OS_Auth SHALL resolve `'ok'`.
5. WHEN the script reports that the user cancelled, the authentication failed, or the system or application cancelled, THE Mac_OS_Auth SHALL resolve `'denied'`.
6. IF the child process cannot start, exits abnormally, or prints anything other than a known result, THEN THE Mac_OS_Auth SHALL resolve `'error'`.
7. IF no reply arrives within 60 seconds, THEN THE Mac_OS_Auth SHALL kill the child process and resolve `'timeout'`.
8. THE Mac_OS_Auth SHALL receive its process spawner as an injected dependency, defaulting to `node:child_process`.

### REQ-02 The real implementation never runs under test, in CI, or off macOS

**User Story:** As a maintainer, I want the real OS call to refuse to run in test and CI environments, so that no automated run ever shows a prompt.

#### Acceptance Criteria

1. WHILE the environment is a Blocked_Environment, THE Mac_OS_Auth SHALL resolve `available()` to `false` and `verify()` to `'error'` before any child process is spawned.
2. THE Mac_OS_Auth SHALL evaluate the Blocked_Environment check on every call, from the injected environment and platform values.
3. WHEN the environment is a Blocked_Environment, THE `blockedReason` function SHALL return a plain-language reason naming the cause (not macOS, test run, CI, or turned off by `EXORCIST_OS_AUTH=off`).
4. WHEN the environment is not a Blocked_Environment, THE `blockedReason` function SHALL return `null`.

### REQ-03 The reason text is untrusted and is sanitised

**User Story:** As a user, I want the prompt text to be safe to read and impossible to use for injection, so that a malicious server or tool name cannot alter what I am approving.

#### Acceptance Criteria

1. THE `sanitizeReason` function SHALL remove control characters, bidirectional control characters, zero-width characters and tag characters (U+E0000 to U+E007F) from its input.
2. THE `sanitizeReason` function SHALL collapse runs of whitespace to a single space and trim the result.
3. THE `sanitizeReason` function SHALL return at most 200 characters, marking a cut with an ellipsis.
4. FOR ALL input strings, THE `sanitizeReason` function SHALL return a string that contains none of the removed character classes and has a length of at most 200 (invariant).
5. FOR ALL input strings, applying `sanitizeReason` twice SHALL give the same result as applying it once (idempotence).
6. THE `buildReason` function SHALL name the server, the tool and the facts that armed the guard, using `describeFact` for each fact, and SHALL pass the result through `sanitizeReason`.
7. THE Mac_OS_Auth SHALL pass the reason to the child process in an environment variable and SHALL NOT place the reason in the script source or in the argument list.
8. FOR ALL reason strings, THE script source passed to `osascript` SHALL be identical (the fixed script constant).

### REQ-04 Policy option and release mode resolution

**User Story:** As a user, I want to choose how a held call is released, so that I can keep terminal release where I prefer it.

#### Acceptance Criteria

1. THE PolicySchema SHALL accept an optional key `sessionRelease` with the values `os` and `terminal`, and SHALL keep `sessionGuard` as the existing enum.
2. WHEN `sessionRelease` is absent, THE `DEFAULT_POLICY` and the parsed policy SHALL NOT contain the key, and existing Policy_Files SHALL still validate.
3. THE `resolveRelease` function SHALL return `{ mode: 'os' }` WHEN the policy value is `os` or absent AND `available()` resolves `true`.
4. THE `resolveRelease` function SHALL return `{ mode: 'terminal' }` WHEN the policy value is `terminal`, without calling `available()`.
5. IF the policy value is `os` or absent AND `available()` resolves `false`, THEN THE `resolveRelease` function SHALL return `{ mode: 'terminal' }` with a plain-language note saying why OS verification is unavailable here.
6. IF the policy value is `os` (set explicitly) AND `available()` resolves `false`, THEN THE Shield SHALL log that it fell back to terminal release.
7. THE Shield SHALL resolve the Release_Mode once at start and SHALL log the result in its start-up line for the Session_Guard.

### REQ-05 A successful OS verification releases exactly one call

**User Story:** As a user, I want one touch of my finger to release one held call, so that approving one send does not open the rest of the session.

#### Acceptance Criteria

1. WHILE the Release_Mode is `os` AND the Session_Guard mode is `hold`, WHEN an Armed_Call arrives, THE engine SHALL keep the call held, SHALL emit a request to verify the device owner with the Reason_Text, and SHALL NOT send the call to the server.
2. WHILE the OS prompt is open, THE Shield SHALL leave the agent's request unanswered until the result arrives.
3. WHEN the verification result is `'ok'`, THE engine SHALL send the held call to the server once and SHALL NOT write any Grant.
4. WHEN a held call has been released by `'ok'`, THE engine SHALL hold the next Armed_Call again and ask again.
5. WHEN several Armed_Calls are held at the same time, THE Shield SHALL run the OS prompts one after the other, one prompt at a time.
6. IF the number of open held calls reaches the existing limit, THEN THE engine SHALL refuse the new call with the existing "prompts already waiting" message.
7. WHILE the Release_Mode is `os`, THE engine SHALL NOT show the client's elicitation prompt for the Session_Guard.

### REQ-06 Anything other than success refuses the call and grants nothing

**User Story:** As a user, I want a cancelled or failed check to keep my data in, so that failure is never a way out.

#### Acceptance Criteria

1. WHEN the verification result is `'denied'`, `'error'` or `'timeout'`, THE engine SHALL refuse the held call with the existing held message plus a short note saying what happened, and SHALL NOT write any Grant.
2. IF a verification result arrives for an unknown or already answered request, THEN THE engine SHALL ignore it and emit no forward action.
3. IF the Shield's client connection ends while a prompt is open, THEN THE Shield SHALL discard the pending verification without sending the call.
4. WHEN a call is refused after verification, THE engine SHALL emit an EX-027 alert that states the outcome (declined, failed or timed out) and nothing sent.
5. THE refusal text for `'denied'`, `'error'` and `'timeout'` SHALL tell the agent not to try to release the call itself.

### REQ-07 Forged grants are ignored under OS release

**User Story:** As a user, I want a file written by another program to be worthless as a release, so that the forgery in S-027 is closed.

#### Acceptance Criteria

1. WHILE the Release_Mode is `os`, THE Session_Guard SHALL ignore every Grant when it assesses the session, including grants from `cli.json`, from the asking Shield's own record, and from any other record.
2. WHILE the Release_Mode is `terminal`, THE Session_Guard SHALL assess grants exactly as before (`cli` writer and the asking Shield's own record).
3. FOR ALL sets of session records, assessing with grants ignored SHALL arm the guard whenever both an untrusted fact and a private fact are live (metamorphic: ignoring grants never reduces what is armed).
4. WHEN a valid `cli.json` grant covers all facts AND the Release_Mode is `os`, THE engine SHALL still hold an Armed_Call.

### REQ-08 Terminal mode and unavailable OS verification keep today's behaviour

**User Story:** As a user on Linux or Windows, I want nothing to change for me, and I want the refusal to say why.

#### Acceptance Criteria

1. WHILE the Release_Mode is `terminal`, THE engine SHALL produce the same actions as before this feature for every Session_Guard path (hold with prompt, hold without prompt, block, monitor, off, grant by prompt, grant by `cli`).
2. IF the Release_Mode is `terminal` because OS verification is unavailable, THEN THE refusal text and the alert SHALL state that release is by terminal because OS verification is unavailable here.
3. IF the Release_Mode is `terminal` because the policy says `terminal`, THEN THE refusal text SHALL NOT claim that OS verification is unavailable.
4. WHILE the Session_Guard mode is `block`, `monitor` or `off`, THE Release_Mode SHALL have no effect on the engine's actions.

### REQ-09 `exorcist approve session` under OS release

**User Story:** As a user, I want the command to tell me where release happens, so that I am not left typing into a terminal that does nothing.

#### Acceptance Criteria

1. WHILE the Release_Mode is `os`, WHEN `exorcist approve session <key>` runs, THE CLI SHALL print that release happens in the system prompt, SHALL write no file, and SHALL exit with code 1.
2. WHILE the Release_Mode is `os`, THE CLI SHALL decide this before the interactive-terminal check, before any dialog and before `grantSession`.
3. WHILE the Release_Mode is `terminal`, THE CLI SHALL behave exactly as before.
4. THE CLI SHALL resolve the Release_Mode from the Policy_File in the state folder and the same OS_Auth rules as the Shield.
5. THE `APPROVE_HELP` text SHALL describe the OS release and the `terminal` fallback.

### REQ-10 No file contents in logs, no reason text in alerts

**User Story:** As a user, I want the logs to stay free of private text, so that the safeguard does not become a leak.

#### Acceptance Criteria

1. THE Shield SHALL NOT write the Reason_Text, any tool argument, or any file content to alerts, logs or state files.
2. THE EX-027 alerts for the OS release SHALL contain the cleaned tool name and the cleaned server name only as the existing alerts do, and SHALL NOT contain the Reason_Text.
3. THE Mac_OS_Auth SHALL discard the child's stderr and SHALL NOT log it.
4. THE Mac_OS_Auth SHALL run the child with a minimal environment (the reason variable, `PATH` and `HOME` only).

### REQ-11 Documentation says what is closed and what is not

**User Story:** As a user, I want an honest account of the protection, so that I do not rely on more than it gives.

#### Acceptance Criteria

1. THE README Session Guard row SHALL state that on macOS the release is verified by the operating system (Touch ID or login password) and that a forged `cli.json` no longer releases a call.
2. THE docs/KNOWN_LIMITATIONS.md S-027 row SHALL state what is now closed: forged release by another program on macOS.
3. THE docs/KNOWN_LIMITATIONS.md S-027 row SHALL state what is not closed: a program with the user's rights can still kill the Shield, edit `policy.json` to set `sessionRelease` to `terminal`, or replace the Shield binary; non-macOS is unchanged; a person who is physically present can click through the prompt.
4. THE docs/KIRO_LOG.md SHALL gain a row dated 2026-11-24 stating that the feature was specified and implemented by the Kiro IDE agent.

### REQ-12 Whole-repository checks

**User Story:** As a maintainer, I want the repository to stay green, so that the golden path keeps working.

#### Acceptance Criteria

1. WHEN `pnpm -r typecheck` runs from the repository root, THE repository SHALL report no errors.
2. WHEN `pnpm vitest run` runs from the repository root, THE repository SHALL report no failing tests.
3. THE existing test `primitives.test.ts` SHALL keep passing with the `DEFAULT_POLICY` shape unchanged.

## Property-based tests

- PBT-REL-01: for all strings, `sanitizeReason` output has no control, bidi, zero-width or tag characters and at most 200 characters (REQ-03.4).
- PBT-REL-02: `sanitizeReason` is idempotent (REQ-03.5).
- PBT-REL-03: for all reason strings, the script source handed to the spawner is the same constant and never contains the reason (REQ-03.7, 03.8).
- PBT-REL-04: for all session records, ignoring grants never arms less than honouring them (REQ-07.3).
- PBT-REL-05: for all sequences of armed calls with a fake OS_Auth answering `ok`, each `ok` sends exactly one call and no grant is written (REQ-05.3, 05.4).
