# Requirements Document

Spec: m13-kiro-evidence

## Introduction
Exorcist 98 was built inside Kiro. This milestone makes that verifiable instead of claimed: it exports the agent sessions that built this project, publishes their totals and the real hook blocks Exorcist 98 produced while guarding Kiro, traces every spec requirement to the tests that check it, adds the hooks and skills this repository had not yet used, and records a table of why each steering file uses the inclusion mode it uses. Every acceptance criterion below has an ID (KE-1, KE-2, ...); the test that checks it starts its name with that ID.

## Glossary
- **Evidence export**: `scripts/kiro-evidence.mjs`, which reads `~/.kiro/sessions/` and writes `evidence/kiro-sessions/`.
- **Session**: one Kiro agent conversation, stored as a folder under a workspace-hash folder in `~/.kiro/sessions/`, holding `session.json`, `messages.jsonl` and `tool-outputs/`.
- **Workspace hash folder**: the per-project folder under `~/.kiro/sessions/` that groups the sessions run against one workspace path.
- **This project**: a workspace whose folder name is `exorcist-98` or matches `exorcist-98-wt-<name>` (a git worktree of this repository).
- **Hook run**: one invocation of a Kiro hook, found as a `tool_call`/`tool_result` pair (for a command hook) or a `ContextualHookInvoked` event (for an agent hook) in `messages.jsonl`.
- **Hook block**: a hook run of a `PreToolUse` hook whose command exited 2, shown in the transcript as the blocked tool's `tool_result` carrying the hook's stderr instead of the tool's normal output.
- **Secret shape**: a string matching `redact-secrets`'s own patterns (API keys, tokens, PEM headers, bearer headers, connection strings).
- **Spec-trace**: `scripts/spec-trace.mjs`, which compares requirement IDs named in a spec's `requirements.md` with the IDs named in test names under that area of the codebase.
- **Facts**: `docs/facts.json`, written by `scripts/facts.mjs`, the single source of the numbers quoted in the README and other docs.

## Requirements

### Requirement 1: Export Kiro sessions for this project
**User Story:** As a maintainer, I want the Kiro sessions that built this project exported into the repository, so that the Kiro-built claim has a record that can be checked.

#### Acceptance Criteria
1. KE-1 WHEN `node scripts/kiro-evidence.mjs` runs, THE export SHALL read every session folder under every workspace-hash folder in `~/.kiro/sessions/`.
2. KE-2 WHEN a session's workspace path has a folder name that is neither `exorcist-98` nor matching `exorcist-98-wt-<name>`, THE export SHALL skip that session, writing no file for it, and SHALL still add it to the totals of sessions seen and skipped.
3. KE-3 WHEN a session belongs to this project, THE export SHALL write `evidence/kiro-sessions/<session id>.jsonl.gz`, one line per kept event from `messages.jsonl`, with every `tool_result`/`tool_call` payload string cut to 2 KB and every image or binary attachment field removed.
4. KE-4 WHEN a session belongs to this project, THE export SHALL add one entry to `evidence/kiro-sessions/index.json` with the session id, title, agent mode, start time, end time, model, the autopilot and approve-for-me settings in effect, the credits reported by its `usage_summary` events, a count of tool calls by tool name, a count of hook runs by hook name, and the commit hashes made during the session when they can be identified from its tool outputs.
5. KE-5 THE export SHALL write a `totals` object in `index.json` with the sessions kept, sessions skipped, summed credits, summed tool calls by tool name and summed hook runs by hook name across every kept session.
6. KE-6 WHEN an event line in `messages.jsonl` cannot be parsed as JSON, THE export SHALL skip that line and continue, without failing the session's export.

### Requirement 2: Safety rules on the export
**User Story:** As a maintainer, I want the export to be safe to commit, so that it never leaks a secret, a home-folder path or Kiro's own settings.

#### Acceptance Criteria
1. KE-7 THE export SHALL be restricted to sessions of this project as defined by Requirement 1; a session of any other workspace SHALL never appear in an output file.
2. KE-8 THE export SHALL replace the current user's home folder path with `~` wherever it is a prefix of a string being written.
3. KE-9 THE export SHALL pass every string value it writes through `redact-secrets` before writing it.
4. KE-10 AFTER writing an output file, THE export SHALL scan that file's written content again for secret shapes and, IF any is found, THEN THE export SHALL delete the file (or write nothing in the first place) and exit non-zero, reporting which file and which pattern.
5. KE-11 THE export SHALL NOT read or copy any file under `~/.kiro/settings/`, any OAuth or API token, or any account identifier, into an output file.

### Requirement 3: Hook blocks in the transcript
**User Story:** As a maintainer, I want the export to recognise a blocked hook in a real transcript, so that Exorcist 98's own guard numbers (from guarding Kiro while it built this project) are counted correctly.

#### Acceptance Criteria
1. KE-12 THE export SHALL count a hook run for every `tool_call`/`tool_result` pair attributable to a command hook and every `ContextualHookInvoked` event attributable to an agent hook, grouped by hook name.
2. KE-13 WHEN a `PreToolUse` hook's command exited 2, THE export SHALL count that run as a hook block and attribute it to the blocked tool call's `tool_result` in the same transcript.
3. KE-14 THE export SHALL write `hookRuns` and `hookBlocks`, each keyed by hook name, into both the per-session entry and the `totals` object in `index.json`.

### Requirement 4: Publish the evidence
**User Story:** As a reader, I want a document and the project's own facts to show the Kiro totals, so that the claim "built with Kiro" is backed by numbers I can check.

#### Acceptance Criteria
1. KE-15 THE repository SHALL contain `docs/KIRO_EVIDENCE.md`, generated from `evidence/kiro-sessions/index.json`, with a totals section (sessions, credits, tool calls, hook runs, hook blocks).
2. KE-16 THE repository SHALL contain, in `docs/KIRO_EVIDENCE.md`, one row per kept session naming its title, agent mode, start time and a link to its exported transcript file.
3. KE-17 WHERE the totals include one or more hook blocks, THE document SHALL narrate each real block in prose naming its session id and time.
4. KE-18 `scripts/facts.mjs` SHALL add the keys `kiroSessions`, `kiroCredits`, `kiroToolCalls`, `hookRuns` and `hookBlocks`, each read from `evidence/kiro-sessions/index.json`'s totals.
5. KE-19 THE README's Kiro section SHALL quote `kiroSessions`, `kiroCredits`, `kiroToolCalls`, `hookRuns` and `hookBlocks` through the `<!--f:key-->value<!--/f-->` markers `scripts/facts.mjs --docs` fills in.
6. KE-20 `scripts/facts.mjs` SHALL add a key counting EARS acceptance criteria (lines containing `SHALL`) across every `requirements.md` under `.kiro/specs/`.
7. KE-21 `scripts/facts.mjs` SHALL add keys counting completed and total checkbox tasks (`- [x]` and `- [ ]`/`- [x]`) across every `tasks.md` under `.kiro/specs/`.

### Requirement 5: Trace requirements to tests
**User Story:** As a maintainer, I want to know which requirement IDs have no test and which test names an ID its spec does not have, so that requirement coverage can be checked instead of assumed.

#### Acceptance Criteria
1. KE-22 `scripts/spec-trace.mjs` SHALL, for each spec under `.kiro/specs/` whose `requirements.md` names at least one requirement ID, list every ID from that `requirements.md` that no test name in the repository starts with.
2. KE-23 `scripts/spec-trace.mjs` SHALL, for the same specs, list every test name that starts with an ID of that spec's prefix which is not present in its `requirements.md`.
3. KE-24 WHEN run with no gaps found for any ID-bearing spec, `scripts/spec-trace.mjs` SHALL exit 0; WHEN any gap is found, THE command SHALL exit 1 and print the gaps grouped by spec.
4. KE-25 THE repository SHALL contain a `.kiro/hooks/spec-trace.json` `PostFileSave` hook matching `.kiro/specs/**` and test files, running `scripts/spec-trace.mjs` through `scripts/kiro-hook.sh` as a warning: its exit code SHALL NOT be treated as a block (the hook action always reports success to Kiro regardless of the script's exit code).
5. KE-26 THE `m10-kiro-gate` spec's `requirements.md` and its tests SHALL carry requirement IDs (`KG-1`, `KG-2`, ...) as the first spec migrated to IDs, with zero gaps reported by `scripts/spec-trace.mjs` for that spec.
6. KE-27 THE documentation SHALL say plainly that specs other than `m10-kiro-gate` and `m13-kiro-evidence` predate requirement IDs and are not covered by `spec-trace.mjs`.

### Requirement 6: Hooks this repository had not used yet
**User Story:** As a maintainer, I want Kiro to verify a finished task automatically and to keep a log of what each turn changed, so that the record updates itself instead of relying on memory.

#### Acceptance Criteria
1. KE-28 THE repository SHALL contain `.kiro/hooks/verify-after-task.json`, a `PostTaskExec` command hook that, through `scripts/kiro-hook.sh`, runs `pnpm -r typecheck` and the test files related to the files changed by the completed spec task.
2. KE-29 THE repository SHALL contain `.kiro/hooks/kiro-log.json`, a `Stop` agent hook named `kiro-log` whose prompt instructs the agent: when the turn changed any file, append one dated row to `docs/KIRO_LOG.md` naming the files changed and any spec task IDs completed, and edit no other file; when the turn changed no file, do nothing.
3. KE-30 THE `kiro-log` hook's prompt SHALL instruct the agent to describe only what the turn actually did, inventing no file, task ID or outcome.

### Requirement 7: Skills and the red-team agent's resources
**User Story:** As a contributor, I want a written procedure for adding a virus definition and for triaging a finding, so that the steps are repeatable and the red-team agent can read them.

#### Acceptance Criteria
1. KE-31 THE repository SHALL contain `.kiro/skills/add-virus-definition/SKILL.md` with documented front matter (`name`, `description`) and steps covering: the rule YAML, its unit test, a benchmark attack sample and a benign look-alike, the documentation to update and the facts to regenerate.
2. KE-32 THE repository SHALL contain `.kiro/skills/triage-finding/SKILL.md` with documented front matter and steps covering: how to decide a finding is a true or false positive, and how to suppress a finding with a reason or add it to a baseline.
3. KE-33 `.kiro/agents/exorcist-red-team.json` SHALL list both skills in its `resources` field using `skill://add-virus-definition` and `skill://triage-finding` URIs, as the custom agents reference documents resource URIs.

### Requirement 8: Steering inclusion modes
**User Story:** As a contributor, I want to see which inclusion mode each steering file uses and why, so that a new steering file is added with the right mode on the first try.

#### Acceptance Criteria
1. KE-34 WHERE a steering file's guidance applies only when cutting a release, THE repository SHALL contain a manual-inclusion steering file `release.md` covering that guidance.
2. KE-35 `apps/web/src/lib/how-kiro.ts` SHALL export a table listing every file under `.kiro/steering/`, each file's inclusion mode (`always`, `fileMatch` with its patterns, or `manual`) and a plain-language reason for that mode.
3. KE-36 THE table required by KE-35 SHALL list every file currently under `.kiro/steering/` with no omission, checked by comparing the table's file list against a directory listing of `.kiro/steering/`.

### Requirement 9: An auditor agent
**User Story:** As a maintainer, I want an agent that can audit one package against the security steering and write only a dated review, so that an audit can run without risking any other file.

#### Acceptance Criteria
1. KE-37 THE repository SHALL contain `.kiro/agents/exorcist-auditor.json`, a custom agent whose `permissions.rules` allow `fs_write` only under `docs/reviews/**` and deny it everywhere else.
2. KE-38 THE agent's `permissions.rules` SHALL allow `shell` only for read-only commands (for example `git log`, `git show`, `grep`, `ls`, `cat`) and for `pnpm vitest run`, and SHALL deny every other shell command.
3. KE-39 THE agent's prompt SHALL instruct it to audit one named package against `.kiro/steering/security.md` and write `docs/reviews/<date>-<package>-audit.md` containing, for each finding, a severity, a file:line reference, the evidence read from the repository and a suggested fix, inventing nothing not found in the repository.
4. KE-40 THE agent SHALL NOT be started by this spec's implementation; starting it is a separate, later action.

### Requirement 10: Finish
**User Story:** As a maintainer, I want this work itself recorded by the same pipeline it builds, so that the evidence export, the facts and the log stay consistent with what actually happened.

#### Acceptance Criteria
1. KE-41 WHEN all other tasks in this spec are complete, `node scripts/kiro-evidence.mjs` SHALL be run, and its output under `evidence/kiro-sessions/` SHALL be committed only if the safety rescan of Requirement 2 (KE-10) passes; IF the rescan fails, THEN THE output SHALL NOT be committed and the failure SHALL be reported instead.
2. KE-42 `docs/HOW_KIRO.md` SHALL be regenerated from `apps/web/src/lib/how-kiro.ts` after KE-35's table is added.
3. KE-43 `node scripts/facts.mjs --run-tests --docs` SHALL be run so that `docs/facts.json` and the documents in `scripts/facts.mjs`'s `DOCS` list reflect this work.
4. KE-44 `docs/KIRO_LOG.md` SHALL get one row recording this work, attributed to the Kiro IDE agent.
5. KE-45 `TASK-kiro-evidence.md` SHALL be moved to `docs/kiro-briefs/TASK-kiro-evidence.md`.
6. KE-46 `pnpm -r typecheck` and `pnpm vitest run` SHALL both pass before the work is committed.
7. KE-47 THE work SHALL be committed to git and SHALL NOT be pushed.

### Requirement 11: Redact personal and credential data missed by the first export
**User Story:** As a maintainer, I want JWTs, AWS account IDs, email addresses and sign-in output removed from the exported sessions, so that the committed evidence carries no personal or credential data.

#### Acceptance Criteria
1. KE-48 WHEN a string in an exported event contains a JWT-shaped token (three base64url segments separated by dots, the first two starting with `eyJ`), THE export SHALL replace the token with `[redacted jwt]`.
2. KE-49 WHEN a string in an exported event contains a 12-digit AWS account ID inside an `arn:aws...:` ARN or next to the word `Account` (as in `sts get-caller-identity` output, JSON or text), THE export SHALL replace the 12 digits with `[redacted account]`.
3. KE-50 WHEN a string in an exported event contains an email address, THE export SHALL replace the address with `[redacted email]`, except an address on a `.invalid` domain or on `example.com`, `example.org`, `example.net`, a subdomain of one of those, or `example.invalid`.
4. KE-51 WHEN an `execute_bash` tool call has a command containing `aws ` or `login`, or reading a dot-file ending `.out` in the home folder (`~/.*.out`), THE export SHALL replace the matching tool output with `[omitted: sign-in output]`.
5. KE-52 THE after-write rescan SHALL also detect JWT shapes and ARN account IDs, and SHALL fail the export in the same way as for other secret shapes.
6. KE-53 THE test suite SHALL contain at least one test for each of KE-48, KE-49, KE-50, KE-51 and KE-52, each using made-up values built at runtime.

### Requirement 12: Redact sign-in URLs and omit files read outside the workspace

**User Story:** As a maintainer, I want OAuth sign-in URLs removed and home-folder file reads omitted from the exported sessions, so that the committed evidence carries no sign-in material.

#### Acceptance Criteria

1. KE-54 WHEN any string of any event (tool results, assistant messages, user messages, or any other field) contains a URL whose query string has a parameter named `code_challenge`, `state`, `code`, `client_id` or `redirect_uri`, THE export SHALL replace the URL with `[redacted sign-in url]`, including in the serialized-line final pass, where the URL may appear with escaped characters.
2. KE-55 WHEN a `read_file` or `fs_read` tool result is for a path under the home folder (`~/` or the absolute home path) that is not inside the project workspace, THE export SHALL replace the result with `[omitted: file outside the workspace]`.
3. KE-56 THE after-write rescan SHALL also detect the sign-in URL shape and SHALL fail the export in the same way as for other secret shapes.
4. KE-57 THE test suite SHALL contain at least one test for each of KE-54, KE-55 and KE-56, each using made-up values built at runtime.

### Requirement 13: Drop model signature fields

**User Story:** As a maintainer, I want opaque model signature fields removed from the exported sessions, so that the committed evidence is readable and carries nothing that looks like a secret.

#### Acceptance Criteria

1. KE-58 THE export SHALL drop the `reasoningSignature` and `signature` fields, at any depth, from every event it writes, because they are opaque model signature blobs that are not useful to a reader and look like secrets.
