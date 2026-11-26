# Requirements Document

## Introduction

The Shield's event log (`<stateDir>/events.jsonl`, `packages/shield/src/events.ts`) is append-only by convention, but nothing today detects a change, deletion, insertion or reordering of past lines, or a truncation at the end. Anyone who can write the state folder can rewrite the whole file undetected. This feature (m12-audit-chain) adds a hash chain to each appended event, a head file that records the chain's current tip, and a CLI command, `exorcist verify-log`, that checks the chain and reports exactly where it breaks. It surfaces the chain's head hash wherever the Shield already shows state (alerts, the Stop gate, the console) and in the web Shield demos, and it hardens the one-time nature of the Session Guard's OS and terminal approvals so a chained event exists for every approval, refusal and expiry. It does not try to stop a full rewrite by someone with write access to the state folder; it detects one, and `docs/KNOWN_LIMITATIONS.md` says so plainly.

## Glossary

- **Shield**: the Exorcist 98 proxy process that wraps one MCP server (`packages/shield`), one or more of which may run against the same state folder at once.
- **Event_Log**: the file at `<stateDir>/events.jsonl`, written by `EventLog.write` in `packages/shield/src/events.ts`.
- **Chained_Event**: an event line that carries `seq` (sequence number), `prev` (the SHA-256 hex digest of the previous event's canonical form), and `hash` (the SHA-256 hex digest of this event's own canonical form, which includes `prev`).
- **Genesis_Value**: a random 32-byte value, hex-encoded, generated once when a state folder's chain is created and used as `prev` for the first Chained_Event.
- **Head_File**: the file at `<stateDir>/events.head.json`, holding the Event_Log's current `seq` and `hash` plus the Genesis_Value, written atomically after every append that produces a Chained_Event.
- **Unchained_Event**: a line in the Event_Log written before this feature existed (no `seq`, `prev` or `hash` field) or otherwise missing those fields.
- **Verify_Log**: the check, used by both `exorcist verify-log` and the web demo's "Verify the log" control, that walks an Event_Log and its Head_File and reports whether the chain is intact.
- **Break_Report**: the structured result of Verify_Log: intact, or broken at a specific sequence number with a reason (changed, removed, inserted, moved/reordered, or the log's end does not match the Head_File).
- **Expected_Head**: a previously saved `(seq, hash)` pair supplied to Verify_Log with `--expect`, checked against the Event_Log's actual tip in addition to internal consistency.
- **Chain_Status**: one of `intact`, `broken` (with the breaking sequence number), or `not-chained` (the log has no Chained_Event, e.g. an old log, or is empty).
- **Approval_Release**: the act of letting one held Session_Guard call proceed, either through Mac_OS_Auth (`os` release) or through `exorcist approve session` (`terminal` release), as built in m6-os-release.
- **Approval_Code**: the typed one-time confirmation code shown by `exorcist approve session` and `exorcist allow-read` when no native dialog or OS verification is available (`packages/cli/src/commands/on-access.ts`).
- **Stop_Gate**: `exorcist gate`, run by the Kiro Stop hook (`packages/cli/src/commands/gate.ts`).
- **Console**: `exorcist console`, the live read-only Shield view (`packages/cli/src/console`).
- **Rug_Pull_Demo** and **Trifecta_Demo**: the Possession Lab's in-browser replays of a changed-tool attack and the lethal-trifecta attack (`apps/web/src/components/PossessionLab.tsx`), each driven by a scripted, in-memory event log.

## Requirements

### Requirement 1: Hash-chained events on append

**User Story:** As a user of the Shield, I want every appended event cryptographically linked to the one before it, so that a later change to the log is detectable.

#### Acceptance Criteria

1. AC-1: WHEN the Event_Log appends an event to a state folder that has a Genesis_Value, THE Event_Log SHALL write a Chained_Event whose `seq` is one more than the previous Chained_Event's `seq` (or 1 if there is none), whose `prev` is the previous Chained_Event's `hash` (or the Genesis_Value if there is none), and whose `hash` is the SHA-256 hex digest of a canonical form of the event that includes `seq` and `prev`.
2. AC-2: WHEN a state folder has no Genesis_Value yet, THE Event_Log SHALL create one with a cryptographically random 32-byte generator before writing the first Chained_Event.
3. AC-3: WHEN a Chained_Event is written, THE Event_Log SHALL write the Head_File, atomically, with the new `seq`, `hash` and the Genesis_Value.
4. AC-4: FOR ALL sequences of events appended by one or more Event_Log writers to the same state folder with no concurrent interruption, Verify_Log applied after all appends SHALL report Chain_Status `intact`.
5. AC-5: WHERE a state folder's Event_Log contains only Unchained_Event lines (an old log, written before this feature), Verify_Log SHALL report Chain_Status `not-chained` rather than `broken`.
6. AC-6: WHILE two or more Shield processes hold an open Event_Log for the same state folder, each process appending a Chained_Event SHALL read the current Head_File immediately before computing `seq` and `prev`, so that concurrent appends from different processes still produce a single, correctly ordered chain with no two events sharing a `seq`.

### Requirement 2: `exorcist verify-log`

**User Story:** As a user or CI job, I want a command that tells me plainly whether the Shield's event log is intact, so that I can trust what the console and alerts are showing.

#### Acceptance Criteria

1. AC-7: WHEN `exorcist verify-log [--dir <stateDir>]` is run against a state folder whose Event_Log and Head_File are consistent, THE CLI SHALL print a plain-language statement that the log is intact and the current head hash, and SHALL exit 0.
2. AC-8: WHEN `exorcist verify-log` is run against a state folder whose Event_Log has been changed, had an event removed, had an event inserted, or had two events swapped since it was last chained correctly, THE CLI SHALL print a plain-language statement naming the first affected sequence number and which of those four problems it is, and SHALL exit 1.
3. AC-9: WHEN `exorcist verify-log` is run against a state folder whose Event_Log's last Chained_Event does not match the Head_File (the end was cut off or the file was replaced), THE CLI SHALL print a plain-language statement that the log's end does not match its head record, and SHALL exit 1.
4. AC-10: WHEN `exorcist verify-log` is run with `--expect <head hash>` and the Event_Log's actual tip hash differs from `<head hash>` even though the chain is internally consistent, THE CLI SHALL print a plain-language statement that the log's head does not match the expected hash, and SHALL exit 1.
5. AC-11: IF `exorcist verify-log` is run with a malformed `--expect` value or an unknown option, THEN THE CLI SHALL print a usage error and exit 2.
6. AC-12: WHERE `--json` is given, THE CLI SHALL print a Break_Report as a single JSON object on stdout instead of plain-language text, in addition to using the same exit codes.
7. AC-13: WHEN `exorcist verify-log` is run against a state folder whose Event_Log holds 100,000 Chained_Events, THE CLI SHALL complete and report Chain_Status in no more than 15 seconds on the reference test machine used by the project's test suite, which runs test files in parallel. (The verification takes about 1.5 s when run alone; the bound leaves roughly 3x headroom over the 5 s observed under full parallel load, so the test does not flake.)

### Requirement 3: Honesty about the limit, and the head hash made visible

**User Story:** As a user deciding how much to trust the log, I want the current head hash shown wherever the Shield reports its state, and a plain written statement of what the chain does and does not prove.

#### Acceptance Criteria

1. AC-14: WHEN `exorcist alerts` is run against a state folder that has a Head_File, THE CLI SHALL print the current head hash alongside the alert lines.
2. AC-15: WHEN the Stop_Gate runs against a state folder that has a Head_File, THE Stop_Gate SHALL include the current head hash in its output.
3. AC-16: WHEN the Console is opened against a state folder that has a Head_File, THE Console SHALL show the current head hash and Chain_Status.
4. AC-17: THE project documentation SHALL state in `docs/KNOWN_LIMITATIONS.md` that anyone who can write the state folder can rewrite the whole Event_Log and Head_File together, that the chain still catches a partial edit, and that it catches a full rewrite only when the person checking kept a copy of a previous head hash outside the state folder to use with `--expect`.

### Requirement 4: Chain status shown in the console and the web demos

**User Story:** As a user, I want to see the chain's status at a glance in the console and to see a tamper attempt caught live in the web demos.

#### Acceptance Criteria

1. AC-18: WHEN the Console's live page is open against a state folder, THE Console SHALL show a chain status badge with one of the text labels "intact", "broken at event N" (N being the breaking sequence number), or "not chained", with the label as the primary signal and not color alone.
2. AC-19: WHEN a person activates the Rug_Pull_Demo's or Trifecta_Demo's "Rewrite an event" control, THE Demo SHALL change exactly one event already present in its in-memory event log.
3. AC-20: WHEN a person activates the Rug_Pull_Demo's or Trifecta_Demo's "Verify the log" control after an event has been rewritten, THE Demo SHALL run the same Verify_Log logic used by `exorcist verify-log` against the in-memory log and SHALL display the sequence number and reason the chain breaks.
4. AC-21: WHEN a person activates "Verify the log" and no event has been rewritten since the demo's log was built, THE Demo SHALL display that the chain is intact.
5. AC-22: WHILE a person operates "Rewrite an event" and "Verify the log" using only the keyboard, THE Demo SHALL make both controls operable and SHALL announce the verify result through an accessible live region.
6. AC-23: WHEN an automated accessibility scan (axe) runs against a page containing the Rug_Pull_Demo or Trifecta_Demo with "Rewrite an event" and "Verify the log" visible, THE scan SHALL report 0 violations.

### Requirement 5: Approvals that run once

**User Story:** As a user relying on the Session Guard's approval flow, I want a release to cover exactly the one call it was given for, an expiring code to work once, and every approval decision recorded in the chain, so that a captured or replayed approval cannot be reused.

#### Acceptance Criteria

1. AC-24: WHEN an Approval_Release of kind `os` is granted for a held call, THE Shield SHALL allow that one held call to proceed and SHALL NOT use that same release to allow any other held call, past or future.
2. AC-25: WHEN a terminal Approval_Code is generated by `exorcist approve session` or `exorcist allow-read`, THE CLI SHALL reject that code once more than 15 minutes have passed since it was generated. The expiry is fixed at 15 minutes and is not configurable, because the policy file sits in the state folder that the wrapped agent may be able to write, and a longer expiry set there would let the agent weaken approvals.
3. AC-26: WHEN a terminal Approval_Code is accepted once, THE CLI SHALL reject any later attempt to confirm with that same code.
4. AC-27: WHEN an Approval_Release of kind `os` is granted for a held call, THE Shield SHALL re-run the call's full check (the unknown-host and Session_Guard assessment that produced the hold) at release time rather than allowing the call on the strength of the earlier hold alone.
5. AC-28: IF an entity other than a person at the keyboard of the machine running the Shield or `exorcist approve session`/`exorcist allow-read` (including the wrapped agent, an MCP tool, or a script run by either) attempts to grant or complete an Approval_Release, THEN THE Shield and CLI SHALL refuse the attempt and SHALL NOT release the held call.
6. AC-29: WHEN a held call is approved, refused, or its Approval_Code expires unused, THE Event_Log SHALL append a Chained_Event recording that outcome.

### Requirement 6: Detecting tampering as a property

**User Story:** As a developer, I want confidence, across many generated logs, that any single-event tamper is always caught and an untouched log always verifies, not just on a few hand-picked examples.

#### Acceptance Criteria

1. AC-30: FOR ALL Event_Logs built by chaining a finite sequence of valid events from the Genesis_Value, Verify_Log applied to the untouched log SHALL report Chain_Status `intact`.
2. AC-31: FOR ALL Event_Logs built as in AC-30 with at least one event, and FOR ALL single tamper operations drawn from {change one event's content, delete one event, insert one new event at some position, swap two adjacent events}, Verify_Log applied to the tampered log SHALL report Chain_Status `broken`, naming a sequence number at or before the first position the two logs differ.
