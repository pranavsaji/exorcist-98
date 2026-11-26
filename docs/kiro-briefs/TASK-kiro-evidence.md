# Feature brief: show the Kiro work, with its own records

Write a Kiro spec in `.kiro/specs/m13-kiro-evidence/` (requirements, design,
tasks), then implement every task. Follow `.kiro/steering/`. Give every
requirement an ID (KE-1, KE-2, ...) and start the name of each test that checks
it with that ID.

## 1. Export the Kiro sessions for this project

Kiro keeps every agent session under `~/.kiro/sessions/`: one folder per
workspace hash with `.index/index.json`, and per session `session.json`,
`messages.jsonl` (events such as `user`, `assistant`, `tool_call`,
`tool_result`, `ContextualHookInvoked`, `usage_summary`) and `tool-outputs/`.
Look at a few to learn the format.

`scripts/kiro-evidence.mjs` writes:
- `evidence/kiro-sessions/<session id>.jsonl.gz`: the session's events, tool
  outputs cut to 2 KB each, images dropped.
- `evidence/kiro-sessions/index.json`: per session the id, title, agent mode,
  start and end time, model, autopilot and approve-for-me settings, credits
  (from `usage_summary`), tool calls by tool name, hook runs by hook name, and
  the commits made in it when that can be found. Plus totals.

Safety rules, each with a test:
- Only sessions whose workspace is this project (a folder named `exorcist-98`
  or `exorcist-98-wt-<name>`). Every other session is skipped and only
  counted.
- The home folder path becomes `~`. Every string goes through
  `redact-secrets`. After writing, scan the output again for secret shapes and
  fail, writing nothing, if anything is left.
- Never copy `~/.kiro/settings`, tokens or account data.

Find how a hook that blocked shows up in a transcript (a PreToolUse hook that
exited 2, then the tool result). Count runs and blocks per hook: those are
Exorcist 98's own numbers from guarding Kiro while it built this project.

## 2. Publish what they show

`docs/KIRO_EVIDENCE.md`, generated from `index.json`: totals (sessions,
credits, tool calls, hook runs, hook blocks), one row per session linking its
transcript, and the real blocks narrated with session and time. Add
`kiroSessions`, `kiroCredits`, `kiroToolCalls`, `hookRuns` and `hookBlocks`
to `scripts/facts.mjs` and use them in the README's Kiro section. Also count
EARS acceptance criteria (SHALL lines) and tasks done and total across
`.kiro/specs/` into facts.

## 3. Trace requirements to tests

`scripts/spec-trace.mjs`: for each spec that uses requirement IDs, list the
IDs that no test names, and the tests that name an ID the spec lacks. A
PostFileSave hook on `.kiro/specs/**` and test files runs it as a warning.
Add IDs to the m10-kiro-gate spec and its tests as the first example. Say
plainly in the docs that older specs predate IDs.

## 4. Hooks Kiro offers that this repo does not use yet

Read kiro.dev/docs/hooks/types.
- A PostTaskExec hook `verify-after-task`: after a spec task completes, run the
  typecheck and the tests related to the changed files.
- A Stop hook of the agent kind, `kiro-log`: when the turn changed files,
  append one dated row to `docs/KIRO_LOG.md` saying what this turn changed
  (files, spec task IDs). Only what was done; skip turns that changed nothing.
  It must not edit anything else.

## 5. Skills

Read kiro.dev/docs/skills. Add `.kiro/skills/add-virus-definition/SKILL.md`
(every step to add a rule: the YAML, tests, a benchmark attack and a benign
look-alike, docs, facts) and `.kiro/skills/triage-finding/SKILL.md` (how to
decide whether a finding is real, and how to suppress one with a reason or a
baseline). Add them to the red-team agent's `resources` with `skill://`
URIs as the custom agents reference describes.

## 6. Steering modes

Read the steering docs. Use each inclusion mode where it fits (for example a
manual `release.md` for cutting a release). Add a table to the HOW_KIRO
source (`apps/web/src/lib/how-kiro.ts`) with each steering file, its mode and
why.

## 7. An auditor agent

`.kiro/agents/exorcist-auditor.json`: may read the repository, may write only
`docs/reviews/**`, may run only read-only commands and `pnpm vitest run`.
Its job: audit one named package against `.kiro/steering/security.md` and
write `docs/reviews/<date>-<package>-audit.md` (severity, file:line,
evidence, suggested fix, nothing invented). Do not run it; it will be started
separately.

## 8. Finish

Run `node scripts/kiro-evidence.mjs` and commit its output only if the safety
scan passes. Regenerate `docs/HOW_KIRO.md`, run
`node scripts/facts.mjs --run-tests --docs`, add a row to `docs/KIRO_LOG.md`
for this work by the Kiro IDE agent, and move this brief to
`docs/kiro-briefs/`. Run `pnpm -r typecheck` and `pnpm vitest run` until they
pass. Commit. Do not push.
