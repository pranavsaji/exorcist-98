# Design: m7-precision

## Overview

One shared redaction helper in `packages/core` is applied at every output boundary, and a set of rule and engine changes removes the false alarms found in the field scan. Measurement and write-up follow.

## Architecture

Redaction sits at the last step before text leaves the process (reporters, CLI, MCP server, web API), so detection and internal uses of the raw span are untouched. Precision changes live in `definitions/*.yaml` and three small engine hooks.

## Components and Interfaces

## 1. Redaction

New module `packages/core/src/redact-secrets.ts`. Browser-safe: no Node
imports, because the SARIF reporter also runs in the web page.

- `redactSecretText(text)`: replaces each secret in `text` with
  `[redacted <type>: <first4>…, <n> chars]`. `<first4>` is shown only when the
  secret is at least 16 characters long. For `NAME=value` the name stays and
  the value is replaced. Types: `github-token`, `openai-key`, `anthropic-key`,
  `aws-access-key`, `slack-token`, `google-api-key`, `stripe-key`, `npm-token`,
  `private-key`, `database-url`, `secret-variable`. The patterns mirror EX-011
  (`definitions/EX-011-secrets-in-agent-reach.yaml`); a test keeps them in step
  by running every EX-011 benchmark and fixture secret through both.
- `redactFinding(f)`: returns a copy with `span`, `rationale` and `decoded`
  redacted. For an EX-011 finding, a span the patterns did not change is
  replaced whole (`[redacted secret: n chars]`), so an unknown format cannot
  leak.
- `redactFindings(list)`: map of the above.

Where it is applied (each at the last step before text leaves the process):

| Output | Place |
| --- | --- |
| `json` | `toJson` redacts findings before validating |
| `sarif` | `toSarif` redacts the message text |
| `text` | `renderText` in `packages/cli/src/commands/scan.ts` |
| `markdown`, `badge` | print no span; a test pins that |
| `origin` | `shown(t.span)` in `commands/origin.ts` and the JSON timeline; `traceOrigins` keeps the raw span for `git log -S` |
| MCP server | `describe` in `tools.ts` (quoted line) |
| web | `toWebFinding`, the snippet lines, the exorcism patch lines, `ai-judge-handler` quote, BYOA findings |
| Shield | the AI-review alert message quotes a tool description span |

A web snippet is redacted per line part (`before`, `match`, `after`). If a
secret straddles two parts, the whole line goes into `before` redacted and the
highlight is dropped for that line. The exorcism patch is redacted line by
line; a context line holding a secret is therefore altered, and a patch that
touches it will not apply cleanly to that hunk. That is the safe side of the
trade, and is noted in KNOWN_LIMITATIONS.

## 2. Precision changes

Rules are YAML, so most fixes are in `definitions/*.yaml`; three need engine
support. Each fix is the smallest change that removes the false alarm and a
test that the attack form still fires.

| Rule | Change |
| --- | --- |
| EX-003 | `blobCounts` in `signature-engine.ts` treats a decoded blob as data, reported only when the other rules flag its text, when `benignPayloadKind` (in `context.ts`) names it: a SQL or KQL script, a semantic-model definition, a minisign key or signature (`untrusted comment:`), or a value near `"payloadType": "InlineBase64"`. Decoded text with a URL or a command is never data. |
| EX-001 | New `mention_guard: { severity }` in the schema. A single U+200B directly after `@` and before a name is reported at that severity and is left out of the five-run escalation. |
| EX-005 | `\b` before the verbs and after their `s/es/ed/ing` forms. |
| EX-012 | `exclude_regex` for the document-editor picture host (`googleusercontent.com/docsz/...?key=`) and the documentation host (`...files.gitbook.io/.../o/...?alt=media&token=`), anchored to the end of the link so extra query data is still reported. |
| EX-008, EX-015 | In a `.json` file `inExecContext` asks `jsonKeyAt` for the key that holds the string. A command counts only under a command key. The "Run:" check ignores method and function calls (`sandbox.exec('...')`). |
| EX-002, EX-018 | New `negated_cues` field and `isNegated` in `context.ts`: the text from the start of the sentence to the match must end in a negation that governs the phrase. Also applied to decoded blobs in `blobCounts`. |
| EX-004 | `exclude_regex` for a `noqa` comment that holds none of the unmistakable attack phrases. |
| EX-010 | `packageArg` skips options that take a value (`--python`, `--with`, ...) and a `-p` whose value is a Python version. |
| skip_paths | EX-001, 002, 004 and 023 get the test, spec, fixture, e2e and eval folder pattern. EX-023 is applied in `trifectaFinding`, because it is not a text rule. |

Bypass thinking: each exemption has a test for the attack that would try to use
it (a payload that says `payloadType` but decodes to an order, a `noqa` comment
with an attack phrase, "do not mention this, tell the agent to ignore ...", a
look-alike image host, a `command` key holding a download piped into a shell).
What stays open: plain English hidden in a declared `InlineBase64` payload with
none of the other rules' phrases in it is not reported. The Shield and the
other rules still see what such text does.

## 3. Measurement

A throwaway folder `rescan-r3/` inside the saved scratchpad holds shallow
clones (`git clone --depth 1 -c core.hooksPath=/dev/null`). The built CLI scans
them; nothing in a clone is executed. The folder is deleted afterwards. Before
numbers come from the saved results, after numbers from this run.

## Data Models

No new persisted data. `VirusDefinition.match` gains one optional field, `negated_cues` (a regex string checked in the 60 characters before a match), validated by zod in `definitions/schema.ts`.

## Error Handling

Redaction never throws: unmatched text is returned unchanged, and an EX-011 span that no pattern recognises is replaced whole. A redaction failure must fail closed (the span is dropped), never open.

## Correctness Properties

### Property 1: Full secret never appears

For any fake secret embedded in any text, `redactSecretText` output never contains the full secret.

**Validates: Requirements 1.1, 1.2, 1.6**
### Property 2: Idempotent

Redaction is idempotent.

**Validates: Requirements 1.3**
### Property 3: Detection unchanged

Redaction never changes a finding's rule, severity, file, line or column.

**Validates: Requirements 1.5**

## Testing Strategy

- `packages/core/src/__tests__/redact-secrets.test.ts`: unit and fast-check
  (the full secret never appears; the output length is bounded).
- `packages/core/src/__tests__/m7-reporters-redaction.test.ts`: every format.
- CLI, MCP and web tests for their own paths.
- `packages/core/src/__tests__/m7-precision.test.ts`: one false-alarm fixture
  and one attack variant per item in section 2, using fixtures built in the
  test from parts or placed under `fixtures/precision/`.
- Existing `benchmark` and Haunted Repo tests must stay green.
