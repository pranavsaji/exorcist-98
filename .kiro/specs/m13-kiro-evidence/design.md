# Design: m13-kiro-evidence

## Overview
A pure extractor turns one session's parsed events into a redacted record; a thin export script walks `~/.kiro/sessions/` and calls it. A pure renderer turns the resulting `index.json` into `docs/KIRO_EVIDENCE.md`. `scripts/facts.mjs` gains keys read from that same `index.json` plus two pure counters over spec text. `scripts/spec-trace.mjs` is a pure diff between two ID sets wrapped in a small file-scanning CLI. The remaining work is configuration: two new hooks, two skills, one steering file, one table and one agent.

## Research: the real session format
The implementer MUST open a handful of real folders under `~/.kiro/sessions/<workspace-hash>/` for this project before writing the extractor, to confirm field names, because the format is not publicly documented and this design only describes its shape from the brief and from the Stop/PreToolUse hook behavior already encoded in `.kiro/steering/kiro-hooks.md`:
- `<workspace-hash>/.index/index.json`: one entry per session in that workspace, at least `id` and `workspacePath` (or equivalent); use it to resolve the workspace path for every session folder without re-reading every `session.json`.
- `<workspace-hash>/<session id>/session.json`: session-level metadata — expect `title`, `agentMode`, `startTime`, `endTime`, `model`, and the `autopilot`/`approveForMe` settings in effect; field names MUST be confirmed against a real file and corrected in the extractor if they differ from this guess.
- `<workspace-hash>/<session id>/messages.jsonl`: one JSON object per line, each with at least an event-type discriminant (`user`, `assistant`, `tool_call`, `tool_result`, `ContextualHookInvoked`, `usage_summary`, and possibly others not listed in the brief). The implementer MUST log the distinct event-type values actually seen and note any not already handled.
- `<workspace-hash>/<session id>/tool-outputs/`: large tool outputs kept out of `messages.jsonl`; a `tool_result` line references its own output file.
- A blocked hook: find a real transcript (or construct one from the existing `.kiro/hooks/exorcist-gate.json` / on-access hook behavior, which already document exit 2 blocking in `kiro-hooks.md`) where a `PreToolUse` hook's command exited 2. Confirm exactly how the blocked tool's `tool_result` carries the hook's stderr (a field name, not just prose) before writing `isHookBlock`.

Findings from this research MUST be written as code comments at the top of `packages/core/src/kiro-evidence.ts` (field names actually observed, and anything the brief predicted that turned out different), so later readers do not have to repeat the exploration.

**Implementation notes (task 2.1, real format wins over the guesses above):** the header comment of `kiro-evidence.ts` is authoritative. Events are envelopes `{ id, timestamp, payload }` with the type at `payload.type`; `parseEventLine` validates that envelope with zod and returns `null` for bad JSON or a missing envelope. Session workspace is `workspacePaths[]` (array), so `isThisProjectWorkspace` takes one path and the caller checks each entry. Session keys are `createdAt`/`lastModifiedAt`/`modelId`. Command hooks leave only a `ContextualHookInvoked` line, and a block is a `denied` `tool_result` preceded by that line, so `isHookBlock` takes the previous hook line, not `nextEvent` (task 3.1). `truncateToolPayload` removes `images`/`documents`/`image`/`imageData` keys, objects with an `image/*` `mimeType`, and base64 data-URL strings; the 2 KB cap includes the `…(truncated)` suffix.

## Architecture
```
~/.kiro/sessions/**            scripts/kiro-evidence.mjs        evidence/kiro-sessions/
  session.json/messages.jsonl --> packages/core/src/kiro-evidence.ts --> <id>.jsonl.gz, index.json
                                        (pure: filter, redact, extract, aggregate)

evidence/kiro-sessions/index.json --> scripts/kiro-evidence-md.ts --> docs/KIRO_EVIDENCE.md
                                  \--> scripts/facts.mjs --> docs/facts.json --> README.md etc.

.kiro/specs/**/requirements.md, test file names --> scripts/spec-trace.mjs --> stdout warning, exit code
```

## Components and Interfaces

### 1. Evidence export

**`packages/core/src/kiro-evidence.ts`** (pure, no `any`, no filesystem or network access):
- `isThisProjectWorkspace(workspacePath: string): boolean` — true when the final path segment is `exorcist-98` or matches `/^exorcist-98-wt-.+$/`. (KE-2)
- `redactHomePath(value: string, home: string): string` — replaces every occurrence of `home` with `~`. (KE-8)
- `redactSecretsDeep<T>(value: T): T` — walks an arbitrary JSON-shaped value and runs every string leaf through the existing `redact-secrets` function; arrays and objects are walked recursively. (KE-9)
- `truncateToolPayload(value: unknown, maxBytes = 2048): unknown` — for a `tool_call`/`tool_result` event, cuts any string field's UTF-8 byte length to `maxBytes` (with a `…(truncated)` suffix) and deletes any field recognised as an image or binary attachment (`image`, `imageData`, `mimeType` starting with `image/`, or a base64-looking data-URL field). (KE-3)
- `parseEventLine(line: string): KiroEvent | null` — `JSON.parse` wrapped so a malformed line returns `null` instead of throwing. (KE-6)
- `isHookRun(event): { hookName: string } | null` and `isHookBlock(event, nextEvent): { hookName: string } | null` — recognise, respectively, any hook invocation and specifically a `PreToolUse` command hook whose exit code was 2, from the event shape confirmed by the research step. (KE-12, KE-13)
- `extractSessionRecord(sessionJson, events: KiroEvent[]): SessionRecord` — builds the per-session `index.json` entry: id, title, agentMode, startTime, endTime, model, autopilot/approveForMe, `credits` (summed from `usage_summary` events), `toolCalls` (count by tool name), `hookRuns`/`hookBlocks` (count by hook name), `commits` (commit hashes found in tool outputs, best-effort, empty array when none found). (KE-4)
- `aggregateTotals(records: SessionRecord[], skippedCount: number): Totals` — sums every numeric field above across `records`, plus `sessionsKept`/`sessionsSkipped`. (KE-5)
- `redactEvent(event: KiroEvent, home: string): KiroEvent` composes `truncateToolPayload`, `redactHomePath` and `redactSecretsDeep` for one event, in that order (truncate first so redaction need not scan the discarded tail).
- `containsSecretShape(text: string): boolean` — re-exports the same patterns `redact-secrets` tests itself against, used for the post-write rescan.

**`scripts/kiro-evidence.mjs`** (thin I/O shell):
1. Resolve `~/.kiro/sessions/`; for each `<workspace-hash>/.index/index.json`, read the sessions it lists.
2. For each session, read `session.json` and `messages.jsonl`; apply `isThisProjectWorkspace` to its workspace path (KE-2) — on no match, increment a skipped counter and move on without writing anything.
3. For a kept session, parse every line with `parseEventLine`, drop nulls, map every event through `redactEvent`, and write `evidence/kiro-sessions/<id>.jsonl.gz` with one JSON line per surviving event (KE-1, KE-3, KE-6).
4. Immediately re-read the bytes just written, gunzip them, and run `containsSecretShape` over every string value found; on a hit, delete the file, print which file and which pattern, and exit 1 before writing anything else (KE-10).
5. Build each `SessionRecord` with `extractSessionRecord`, collect them, compute `Totals` with `aggregateTotals`, and write `evidence/kiro-sessions/index.json` (KE-4, KE-5, KE-14). Re-run the same rescan over the serialised JSON before leaving it on disk; same fail-closed behavior.
6. Never read or copy anything under `~/.kiro/settings/` (KE-11): the script's directory walk MUST NOT descend into `settings/` at all, not merely skip copying it, so a token file there is never opened.

### 2. Publishing

**`scripts/kiro-evidence-md.ts`**: pure render function `renderKiroEvidenceMd(index: EvidenceIndex): string` plus a CLI wrapper that writes `docs/KIRO_EVIDENCE.md`. Produces: a totals section (KE-15); one table row per session with a relative link to `evidence/kiro-sessions/<id>.jsonl.gz` (KE-16); a "Hook blocks" section that, only when `totals.hookBlocks` has at least one nonzero entry, narrates each block in prose naming its session id and time, read from the per-session records (KE-17).

**`scripts/facts.mjs`** additions: a `kiroEvidence()` reader that loads `evidence/kiro-sessions/index.json` (missing file → zeros, so facts still runs before the first export) and returns `kiroSessions`, `kiroCredits`, `kiroToolCalls` (sum across tool names), `hookRuns` (sum across hook names), `hookBlocks` (sum across hook names) (KE-18); wired into the `--docs` marker fill for `README.md` (KE-19). Two new pure counters, unit-testable without touching the filesystem beyond a fixture: `countShallLines(text: string): number` (counts lines matching `/\bSHALL\b/`, skipping fenced code blocks) used across every `.kiro/specs/**/requirements.md` (KE-20); `countTasks(text: string): { done: number; total: number }` (counts `- [ ]`/`- [x]`/`- [X]` checkbox lines) used across every `.kiro/specs/**/tasks.md` (KE-21).

### 3. Spec trace

**`packages/core/src/spec-trace.ts`** (pure):
- `extractRequirementIds(requirementsMd: string, prefix: string): Set<string>` — IDs of the form `<prefix>-<n>` found in a `requirements.md`.
- `extractTestedIds(testNames: string[], prefix: string): Set<string>` — IDs that a test name starts with.
- `diffIds(specIds: Set<string>, testIds: Set<string>): { missingTests: string[]; extraTests: string[] }` — `missingTests` = specIds − testIds, `extraTests` = testIds − specIds, both sorted (KE-22, KE-23).

**`scripts/spec-trace.mjs`**: for each `.kiro/specs/<name>/requirements.md` that contains at least one ID matching `/^[A-Z]{2,4}-\d+/`, derive its prefix, collect test names (`it(`/`test(` string literals) across the repository, call `diffIds`, and print a per-spec report. Exit 0 only when every ID-bearing spec has empty `missingTests` and empty `extraTests`; otherwise exit 1 (KE-24).

**`.kiro/hooks/spec-trace.json`**: `PostFileSave`, matcher `(^|/)(\\.kiro/specs/.+\\.md|.*\\.test\\.tsx?)$`, command action through `scripts/kiro-hook.sh` running `node scripts/spec-trace.mjs`. A command hook's exit code is only ever turned into a block for `PreToolUse`/`PromptSubmit` triggers (per `.kiro/steering/kiro-hooks.md`); `PostFileSave` has no blocking semantics at all, so running `spec-trace.mjs` here can only ever surface its stdout/stderr to the agent as information, never stop anything (KE-25).

**Migrating `m10-kiro-gate`**: rename its requirement numbering scheme to carry explicit IDs `KG-1`, `KG-2`, ... inline in `requirements.md` (one per acceptance criterion, same text), and prefix the matching test names in `gate.test.ts`, `gate.property.test.ts` and the CLI/hook tests with the same IDs, so `spec-trace.mjs` reports zero gaps for `m10-kiro-gate` (KE-26). `docs/KIRO_EVIDENCE.md` or `docs/REFERENCE.md` states plainly that every spec other than `m10-kiro-gate` and `m13-kiro-evidence` predates requirement IDs and is outside `spec-trace.mjs`'s coverage (KE-27).

### 4. New hooks

**`.kiro/hooks/verify-after-task.json`**: `PostTaskExec`, command action through `scripts/kiro-hook.sh`, running a small script that reads the event's changed-file list from stdin, maps each changed source file to its test file by the repository's existing naming convention (`foo.ts` → `foo.test.ts`, same directory), runs `pnpm -r typecheck` plus `pnpm exec vitest run <related test files>`, 120 s timeout (KE-28).

**`.kiro/hooks/kiro-log.json`**: `Stop`, action type `agent`, prompt text instructing the agent that when the turn changed any file it must append one dated row to `docs/KIRO_LOG.md` naming the files changed and any spec task IDs completed, edit no other file, and when the turn changed nothing it must do nothing; the prompt explicitly says to describe only what the turn actually did and invent no file, task ID or outcome (KE-29, KE-30).

### 5. Skills and resources

**`.kiro/skills/add-virus-definition/SKILL.md`**: front matter `name: add-virus-definition`, `description: ...`; body steps: write the rule YAML under `definitions/`, write its unit test, add a defanged benchmark attack sample and a benign look-alike (per `.kiro/steering/security.md`), update `docs/THREATS.md`/relevant docs, regenerate facts (KE-31).

**`.kiro/skills/triage-finding/SKILL.md`**: front matter plus steps for deciding true vs. false positive, and for suppressing a finding with a reason or adding it to a baseline (KE-32).

**`.kiro/agents/exorcist-red-team.json`** gains a `resources` array matching the two files above (KE-33). Per kiro.dev/docs/custom-agents/configuration-reference, `skill://` takes a file path or glob (e.g. `skill://.kiro/skills/**/SKILL.md`), not a bare skill name, so the entries are `skill://.kiro/skills/add-virus-definition/SKILL.md` and `skill://.kiro/skills/triage-finding/SKILL.md`. Skill front matter requires `name` (equal to the folder name) and `description`.

### 6. Steering modes

**`.kiro/steering/release.md`**: `inclusion: manual`, covering the steps and checks specific to cutting a release (version bump, changelog, tagging) — guidance that should not load on every file match, only when a maintainer explicitly includes it (KE-34).

**`apps/web/src/lib/how-kiro.ts`** gains `STEERING_TABLE: { file: string; mode: 'always' | 'fileMatch' | 'manual'; patterns?: string[]; reason: string }[]`, one row per file under `.kiro/steering/`, each row's `mode`/`patterns` read from that file's own front matter (or `always`/no front matter), and `reason` a short plain-language sentence (KE-35). A test enumerates `.kiro/steering/` and asserts the table's file list is the same set (KE-36).

### 7. Auditor agent

**`.kiro/agents/exorcist-auditor.json`**: `tools: ["read", "shell"]`; `permissions.rules`: `fs_write` allow only `docs/reviews/**`, deny `**` otherwise (KE-37); `shell` allow a short fixed list of read-only commands (`git log*`, `git show*`, `git diff*`, `grep*`, `ls*`, `cat*`, `find*`) plus exactly `pnpm vitest run*`, deny `*` otherwise (KE-38); prompt instructs it to audit one named package against `.kiro/steering/security.md` and write `docs/reviews/<date>-<package>-audit.md` with severity, `file:line`, evidence quoted from the repository, and a suggested fix, inventing nothing (KE-39). It is not registered anywhere that would auto-start it; the task list does not include a task that runs it (KE-40).

## Additional redactions (Requirement 11)

The new rules live in the export redaction in `packages/core/src/kiro-evidence.ts`, and run in the existing places: inside the same deep redaction (`redactSecretsDeep`, applied to every string leaf) and again in the final per-line pass over each serialised JSON line before it is written. Sign-in output omission (KE-51) is applied in `redactEvent`: it pairs each `execute_bash` `tool_call` with its `tool_result` (by call id) and replaces the result text with `[omitted: sign-in output]` when the command contains `aws ` or `login`, or reads a `~/.*.out` file.

- JWT (KE-48): `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`. Decision: the JWT pattern also goes into the shared secret patterns in the general `redact-secrets` module, because a JWT is a credential in every context and scanner findings on it are consistent with how other token shapes are treated.
- AWS account ID (KE-49): 12 digits inside `arn:aws[^:\s]*:...:` or after `Account` (`"Account": "123456789012"` and `Account: 123456789012`). Decision: export-only, to avoid changing scanner behaviour.
- Email (KE-50): a standard address pattern, with a pure allow-check that keeps `.invalid` domains and `example.com|org|net` (and their subdomains) and `example.invalid`. Decision: export-only, since scanned repositories legitimately contain addresses.
- Rescan (KE-52): `containsSecretShape` also matches the JWT shape and ARN account IDs, so the after-write check fails closed (KE-10).
- Tests (KE-53): test names start with the KE-ID; secret-looking values are assembled at runtime from fragments so no real-looking token is stored in the repository.

## Sign-in URLs and outside-workspace reads (Requirement 12)
Both rules live in `packages/core/src/kiro-evidence.ts`. KE-54 runs in the same deep redaction (every string leaf) and again in the final per-line pass over each serialised JSON line, where the pattern also matches escaped forms (`\u0026`, `\/`, `&amp;`). A URL is redacted when its query has a parameter named `code_challenge`, `state`, `code`, `client_id` or `redirect_uri`; the whole URL becomes `[redacted sign-in url]`. KE-55 is applied in `redactEvent`: it pairs each `read_file` or `fs_read` `tool_call` with its `tool_result` by tool-call id, as the sign-in output omission does, and replaces the result with `[omitted: file outside the workspace]` when the path is under the home folder (`~/` or the absolute home path) and not inside the session's `workspacePaths`. KE-56: `containsSecretShape` also matches the sign-in URL shape so the after-write rescan fails closed. KE-57: tests build URLs from fragments at runtime.
## Model signature fields (Requirement 13)
The `reasoningSignature` and `signature` fields (KE-58) are removed at any depth in the same pass that drops images, before redaction.

## Security review gaps (Requirement 14)
Order per event in `packages/core/src/kiro-evidence.ts`: (1) omit outputs of calls that name a path under home outside the workspace (KE-59), (2) redact the full strings, including the KE-60 key shapes, (3) truncate to 2 KB, (4) redact any partial known-prefix token left at the cut (KE-62), (5) the final per-line pass. A single path detector, shared by `read_file`, `fs_read`, `execute_bash`, `control_bash_process` and any tool with a command-bearing argument, matches `~/`, `$HOME`, `${HOME}` and the absolute home path outside `workspacePaths`; it replaces KE-55's read-only check. KE-61: `containsSecretShape` also matches the KE-60 shapes unless the value is already a redaction placeholder. KE-63: tests build values at runtime. Trade-off: the detector looks at the command text, so a command that merely mentions a home path drops its whole output (false positive); this is accepted because the alternative is leaking credential files.
## Data Models
- `KiroEvent`: discriminated union keyed by event type (`user`, `assistant`, `tool_call`, `tool_result`, `ContextualHookInvoked`, `usage_summary`, `unknown` fallback), fields confirmed during research.
- `SessionRecord`: `{ id, title, agentMode, startTime, endTime, model, autopilot, approveForMe, credits, toolCalls: Record<string, number>, hookRuns: Record<string, number>, hookBlocks: Record<string, number>, commits: string[] }`.
- `Totals`: `SessionRecord`'s numeric/record fields summed, plus `sessionsKept`, `sessionsSkipped`.
- `EvidenceIndex`: `{ sessions: SessionRecord[]; totals: Totals }`, the shape of `evidence/kiro-sessions/index.json`.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

Each property's `X.Y` reference is the acceptance criterion's position in requirements.md; the KE-ID of that same criterion is noted beside it in the property's own title.

### Property 1: Workspace filter is exhaustive and exclusive (KE-2, KE-7)
For any list of synthetic sessions each tagged with a workspace folder name, the set of sessions `isThisProjectWorkspace` accepts is exactly those whose name is `exorcist-98` or matches `exorcist-98-wt-<name>`, and every other session is counted as skipped, never kept.

**Validates: Requirements 2.2, 2.7**

### Property 2: Tool payloads never exceed the cap and never carry images (KE-3)
For any event object with randomly generated string fields (some long, some short) and randomly generated image-like fields, `truncateToolPayload` returns an object where every string field is at most 2048 UTF-8 bytes and no field recognised as an image or binary attachment remains.

**Validates: Requirements 1.3**

### Property 3: Totals equal the sum of kept sessions (KE-5, KE-14)
For any list of synthetic `SessionRecord`s and a skipped count, `aggregateTotals` produces a `Totals` whose every numeric and per-key record field equals the sum of that field across the input records, and whose `sessionsSkipped` equals the given skipped count.

**Validates: Requirements 1.5, 3.3**

### Property 4: Malformed lines never stop export (KE-6)
For any list of lines where some are valid JSON event lines and others are arbitrary non-JSON garbage interleaved at random positions, `parseEventLine` returns a non-null result for every valid line, `null` for every garbage line, and processing the whole list never throws.

**Validates: Requirements 1.6**

### Property 5: The home path never survives redaction (KE-8)
For any string built by embedding a given home-path value at a random position (start, middle, end, multiple times) inside other random text, `redactHomePath` returns a string containing zero occurrences of the home-path value.

**Validates: Requirements 2.2**

### Property 6: No secret shape survives deep redaction (KE-9)
For any JSON-shaped value built by embedding a secret-shaped string (matching one of `redact-secrets`'s own patterns) at a random path inside an object/array tree, `redactSecretsDeep` returns a value in which that secret-shaped string no longer appears anywhere.

**Validates: Requirements 2.3**

### Property 7: Hook run and hook block counting matches construction (KE-12, KE-13)
For any synthetic event sequence built from a known number of command-hook runs (with a known mix of exit codes and trigger types) and agent-hook invocations, the hook-run count by name equals the number of hook invocations constructed, and the hook-block count by name equals exactly the number of `PreToolUse` command-hook runs whose exit code was 2.

**Validates: Requirements 3.1, 3.2**

### Property 8: Every kept session gets exactly one evidence row (KE-16)
For any list of synthetic session records, `renderKiroEvidenceMd` produces a table with exactly one row per session, each linking that session's own transcript file.

**Validates: Requirements 4.2**

### Property 9: SHALL-line counting matches construction (KE-20)
For any generated markdown text built from a known number of lines containing the word `SHALL` (outside fenced code blocks) interspersed with a known number of unrelated lines, `countShallLines` returns exactly the constructed count.

**Validates: Requirements 4.6**

### Property 10: Task counting matches construction (KE-21)
For any generated markdown text built from a known number of `- [x]`/`- [X]` and `- [ ]` checkbox lines in random order and nesting, `countTasks` returns `done` and `total` equal to the constructed counts.

**Validates: Requirements 4.7**

### Property 11: Requirement/test ID diff is exact in both directions (KE-22, KE-23)
For any two randomly generated sets of IDs (one standing in for a spec's declared IDs, one for the IDs found in test names), `diffIds` returns `missingTests` exactly equal to the set difference spec-minus-tests and `extraTests` exactly equal to tests-minus-spec, both as sorted arrays with no duplicates.

**Validates: Requirements 5.1, 5.2**

### Property 12: Exit code reflects the diff (KE-24)
For any pair of ID sets passed through the same diff used by `spec-trace.mjs`, the script's exit code is 0 if and only if both `missingTests` and `extraTests` are empty for every ID-bearing spec.

**Validates: Requirements 5.3**

### Property 13: The steering table's completeness check is exact (KE-36)
For any synthetic pair of (a) a set of file names standing in for a directory listing and (b) a table covering some subset of them, the completeness-checking function reports as missing exactly those files in (a) not in (b), and reports as extra exactly those files in (b) not in (a).

**Validates: Requirements 8.3**

All thirteen are implemented with `fast-check`, one `fc.assert` call per property, minimum 100 runs, in `kiro-evidence.property.test.ts`, `facts.property.test.ts` and `spec-trace.property.test.ts` under `packages/core/src/__tests__/`.

## Error Handling
- A session folder missing `session.json` or `messages.jsonl`: skipped with a one-line stderr notice, export continues with the next session (never throws out of the whole run).
- `~/.kiro/sessions/` missing entirely: export prints "no Kiro sessions found" and exits 0, writing an empty `index.json` with `sessionsKept: 0`.
- The post-write secret rescan finding a hit (KE-10): delete the offending output file(s), print the file and the matched pattern name (never the matched text itself, to avoid printing a secret to the terminal), exit 1.
- `scripts/facts.mjs` reading a missing `evidence/kiro-sessions/index.json`: treat as zero totals rather than failing, so `facts.mjs` keeps working before the first export has ever run.
- `spec-trace.mjs` finding no ID-bearing specs at all: prints "no specs use requirement IDs yet" and exits 0.

## Testing Strategy
- **Unit tests** (`packages/core/src/__tests__/kiro-evidence.test.ts`): one worked example per extractor function using a small hand-built fixture session (a few `messages.jsonl` lines covering a `tool_call`/`tool_result` pair, a blocked `PreToolUse` pair, a `usage_summary`, and one malformed line); `scripts/__tests__/kiro-evidence-script.test.ts` runs the script end-to-end against a temporary fake `~/.kiro/sessions/` tree (KE-1, KE-4, KE-10 example, KE-11 example).
- **Property tests**: the thirteen properties above.
- **Unit tests** for publishing and facts (`kiro-evidence-md.test.ts`, extended `facts.test.ts`): KE-15, KE-17, KE-18, KE-19 as worked examples against a small fixed fixture.
- **Unit tests** for spec trace wiring (`spec-trace.test.ts`): KE-25 (hook JSON shape), KE-26 (run against the real `m10-kiro-gate` spec and its tests, assert zero gaps), KE-27 (doc text present).
- **Unit tests** for configuration (`repo-files.test.ts` or new `kiro-evidence-config.test.ts`): KE-28, KE-29, KE-30, KE-31, KE-32, KE-33, KE-34, KE-35 (table shape), KE-37, KE-38, KE-39 as schema/shape/content checks on the committed JSON and Markdown files, matching the pattern `kiro-config.test.ts` already uses for the two existing agents.
- **Finish-step checks** (KE-41 through KE-47) are process steps verified by running the actual commands (`node scripts/kiro-evidence.mjs`, `pnpm -r typecheck`, `pnpm vitest run`) during the final task, not by a unit test.
