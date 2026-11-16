# Tasks: m1-engine

Each task is independently verifiable. Run `pnpm test` and `pnpm -r typecheck`
after each task before continuing.

---

## TASK-01 Central types and new dependencies

**Requirement**: REQ-01, REQ-03, REQ-05, REQ-06

### Step 1-A: add dependencies

Add to root `package.json` devDependencies:

```jsonc
"@aws-sdk/client-bedrock-runtime": "^3.600",
"@types/aws-lambda":               "^8.10",
"aws-lambda":                      "^1.0",
"jsonpath-plus":                   "^9.0",
"simple-git":                      "^3.25"
```

Run `pnpm install`.

### Step 1-B: `packages/core/src/types.ts`

Replace the stub `src/index.ts` export with real types. Create
`packages/core/src/types.ts` containing all shared types from design section 2:
`FileRole`, `Severity`, `RepoFile`, `SignatureFinding`, `HeuristicFinding`,
`Finding`, `ScanEvent`, `ScanStats`.

**Done when**: `pnpm -r typecheck` exits 0.

---

## TASK-02 File walker

**Requirement**: REQ-01

Create `packages/core/src/walker.ts` with:

- `classifyFile(rel: string): FileRole` — pure, exported
- `walkRepo(root: string): AsyncIterable<RepoFile>` — uses `fs.promises.opendir`
  for streaming

Classification table is the priority-ordered list in design section 3. Use
`micromatch` (add to dependencies) for glob matching, or implement the patterns
with simple string checks (avoid a heavy glob library on the hot path).

Write `packages/core/src/__tests__/walker.test.ts` with unit tests:

- `classifyFile` returns `instruction` for `README.md`
- `classifyFile` returns `mcp-config` for `.kiro/settings/mcp.json`
- `classifyFile` returns `manifest` for `packages/core/package.json`
- `classifyFile` returns `hook` for `.kiro/hooks/definition-save.yaml`
- Files over 1 MB are skipped
- Binary files (null byte in first 512 bytes) are skipped
- `node_modules/` path is not yielded

Write `packages/core/src/__tests__/walker.property.test.ts` with
PBT-WLK-01 through PBT-WLK-04.

**Done when**: all walker tests pass.

---

## TASK-03 Text normalizer

**Requirement**: REQ-02

Create `packages/core/src/normalizer.ts`. All functions are pure (no I/O).

Build the Unicode regex once at module load from the code-point ranges in design
section 4. Use `String.fromCodePoint` to build range arrays, then join into a
character class.

Write `packages/core/src/__tests__/normalizer.test.ts` with unit tests:

- A string containing `\u200B` produces one `hiddenUnicode` hit with class `zero-width`
- A string containing `\u202E` produces a `bidi-override` hit
- `<!-- hidden -->` produces `['hidden']` in `comments`
- `/* block */` produces `['block']` in `comments`
- An HTML entity `&amp;` decodes to `&` in `plain`
- A 40-char base64 string is included in `base64Candidates`
- A `sha256:` prefixed base64 string is excluded

Write `packages/core/src/__tests__/normalizer.property.test.ts` with
PBT-NRM-01 through PBT-NRM-04.

**Done when**: all normalizer tests pass.

---

## TASK-04 Signature engine

**Requirement**: REQ-03

Create `packages/core/src/scanner/signature-engine.ts`.

Key implementation details:

- Cache compiled regexes in a `Map<string, RegExp>` keyed by `ruleId` to avoid
  recompilation per file.
- Use `offsetToPosition` (pure helper in the same file) for line/col calculation.
- Cap span at 120 characters with `…` suffix if truncated.
- Skip disabled rules (`enabled === false`).
- Skip rules whose `applies_to` does not include the file's role.

Write `packages/core/src/__tests__/signature-engine.test.ts` with unit tests:

- A regex rule matching its pattern returns a `SignatureFinding` with correct line/col
- A disabled rule returns no findings
- A rule with `applies_to: ['docs']` does not fire on a `manifest` file
- `span` is never longer than 120 chars (use a 200-char match)
- `json_path` rule fires on a JSON file with the matching path

Write `packages/core/src/__tests__/signature-engine.property.test.ts` with
PBT-SIG-01 through PBT-SIG-04.

**Done when**: all signature engine tests pass.

---

## TASK-05 Twelve virus definitions (EX-001 to EX-012)

**Requirement**: REQ-04

EX-001 already exists. Create EX-002 through EX-012.

For each definition, the `match` strategy follows the design:

| ID     | Strategy    | Key pattern                                                                                                                                                                                   |
| ------ | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| EX-002 | `regex`     | `/(ignore previous instructions\|you are now\|as an ai\|your new (primary )?directive)/gi`                                                                                                    |
| EX-003 | `regex`     | `/(?<![A-Za-z0-9+\/=])[A-Za-z0-9+\/=]{40,}(?![A-Za-z0-9+\/=])/g` (long base64 blobs)                                                                                                          |
| EX-004 | `regex`     | `/<!--[\s\S]*?(ignore\|exfiltrate\|send.*to\|fetch\|curl\|you are)[\s\S]*?-->/gi`                                                                                                             |
| EX-005 | `regex`     | `/(before (responding\|answering\|using)\|do not (inform\|tell\|mention)\|this is required for)/gi` applied to `mcp-config` and `config` roles                                                |
| EX-006 | `json_path` | `$.after.description` (fires on the rug-pull fixture's `after.description` field) — note: real rug-pull detection is in the Shield (M3); this definition catches the pattern in static config |
| EX-007 | `json_path` | `$..autoApprove[*]` filtered for values matching `write_\|delete_\|run_\|execute_\|shell`                                                                                                     |
| EX-008 | `regex`     | `/(curl\|wget).*\|\s*(sh\|bash\|zsh\|fish)/gi` on `hook` and `config` roles                                                                                                                   |
| EX-009 | `json_path` | `$.scripts.postinstall` and `$.scripts.preinstall` — flag if value contains `http\|curl\|wget\|fetch\|require('http')`                                                                        |
| EX-010 | `json_path` | `$..args[*]` where the value matches `^@[\w-]+\/[\w-]+$` (bare package name, no `@version`)                                                                                                   |
| EX-011 | `regex`     | `/(AWS_SECRET_ACCESS_KEY\|GITHUB_TOKEN\|OPENAI_API_KEY\|DATABASE_URL)=(?!EXAMPLE_)[^\s]+/` on all roles                                                                                       |
| EX-012 | `regex`     | `/!\[.*?\]\(https?:\/\/[^)]+\?[^)]*\)/gi` (Markdown image with query string)                                                                                                                  |

Write `packages/core/src/__tests__/definitions-integration.test.ts`:

- For each EX-NNN definition, load it and run the signature engine against
  the corresponding `fixtures/haunted-repo/EX-NNN-*.{md,json,yaml,env}` file.
- Assert at least one finding with `ruleId === 'EX-NNN'`.

Update `docs/THREATS.md` with a row for each definition.

**Done when**: all 12 integration tests pass and `docs/THREATS.md` is updated.

---

## TASK-06 Bedrock client and fake

**Requirement**: REQ-05

### Step 6-A: `BedrockClient` interface

Add to `packages/core/src/types.ts`:

```ts
export interface BedrockClient {
  call(params: BedrockParams): Promise<BedrockResult>;
}
export type BedrockParams = {
  model: "haiku" | "sonnet";
  prompt: string;
  maxTokens: number;
};
export type BedrockResult =
  | { ok: true; raw: string }
  | { ok: false; error: string };
```

### Step 6-B: `llm/bedrock.ts`

Implement `BedrockClientImpl` using `@aws-sdk/client-bedrock-runtime`.
The class reads `AWS_REGION` from `process.env` at call time.
Only import and use the AWS SDK here; nowhere else in `packages/core`.

### Step 6-C: `llm/__tests__/fake-client.ts`

```ts
export class FakeBedrockClient implements BedrockClient {
  constructor(
    private readonly responses: BedrockResult[],
    public readonly calls: BedrockParams[] = [],
  ) {}
  async call(params: BedrockParams): Promise<BedrockResult> {
    this.calls.push(params);
    return this.responses.shift() ?? { ok: false, error: "no more responses" };
  }
}
```

### Step 6-D: `llm/prompts.ts`

Implement `buildHeuristicPrompt(span, context, relPath, nonce)` returning the
full prompt string from design section 6.

**Done when**: `pnpm -r typecheck` exits 0 and the fake client file exists.

---

## TASK-07 Heuristic engine

**Requirement**: REQ-05

Create `packages/core/src/scanner/heuristic-engine.ts`.

Write `packages/core/src/__tests__/heuristic-engine.test.ts`:

- A verdict with `quoted_span` not in the file is dropped
- A `benign` verdict produces no finding
- A `malicious` verdict with a valid span produces a `HeuristicFinding` with
  `confidence: 'high'`
- If the client returns `{ ok: false }`, the engine returns `[]` without throwing

Write `packages/core/src/__tests__/heuristic-engine.property.test.ts` with
PBT-HEU-01 through PBT-HEU-04.

**Done when**: all heuristic engine tests pass.

---

## TASK-08 Orchestrator

**Requirement**: REQ-06

Create `packages/core/src/scanner/orchestrator.ts` following the async-generator
pattern in design section 7.

Write `packages/core/src/__tests__/orchestrator.test.ts`:

- Scanning `fixtures/haunted-repo/` with all 12 definitions yields at least
  12 findings (one per fixture)
- `done` is always the last event
- Errors on a single file do not abort the scan
- File mtimes do not change after a scan (no mutation)

Write `packages/core/src/__tests__/orchestrator.property.test.ts` with
PBT-ORC-01 through PBT-ORC-03.

**Done when**: all orchestrator tests pass.

---

## TASK-09 JSON and SARIF reporters

**Requirement**: REQ-07

Create `packages/core/src/reporters/json-reporter.ts` and
`packages/core/src/reporters/sarif-reporter.ts`.

Write `packages/core/src/__tests__/reporters.test.ts`:

- `toJson` output validates against `ScanReportSchema`
- `toJson` with zero findings produces `findings: []` and correct `stats`
- `toSarif` with a critical finding produces `level: 'error'`
- `toSarif` with a medium finding produces `level: 'warning'`
- `toSarif` URIs are relative to `repoRoot`

**Done when**: all reporter tests pass.

---

## TASK-10 Lambda handler

**Requirement**: REQ-08

Create `packages/core/src/lambda/handler.ts`.

Write `packages/core/src/__tests__/handler.test.ts`:

- A request with a non-GitHub URL returns HTTP 400
- A request with an invalid JSON body returns HTTP 400
- Stack traces never appear in error response bodies
- The `Content-Type` header is `application/json` on success

Note: the handler's actual clone + scan path is integration-tested only in CI
(requires a network call). Unit tests mock `simple-git` and the orchestrator.

**Done when**: handler unit tests pass and `pnpm -r typecheck` exits 0.

---

## TASK-11 Public exports and final typecheck

**Requirement**: REQ-09

Replace `packages/core/src/index.ts` with the full re-export surface from
design section 1 (REQ-09 acceptance criteria).

Run the full suite:

```
pnpm install
pnpm -r build
pnpm test
pnpm -r typecheck
```

**Done when**: all commands exit 0 and the test count is ≥ 53
(34 from M0 + 19 new PBTs + unit tests).

---

## TASK-12 Update KIRO_LOG.md

Add rows to `docs/KIRO_LOG.md` for:

- This spec (m1-engine, 3 documents)
- Each new PBT suite (walker, normalizer, signature engine, heuristic engine,
  orchestrator)
- Bedrock model usage (Haiku triage, Sonnet judge)

Update counts: Specs: 2, PBTs: 30.

---

## TASK-13 Detection accuracy fixes (REQ-10)

Added after reviewing the first M1 implementation.

- Add `value_regex` to the match schema (requires `json_path`, must compile).
- Apply `value_regex` in the signature engine; locate JSON findings in the
  file; key the regex cache by pattern and flags.
- Restore EX-001 to `unicode_class`; regenerate the EX-001 fixture with real
  invisible characters carrying only a placeholder.
- Tighten EX-007, EX-009 and EX-010 as described in REQ-10.
- Add `definitions-accuracy.test.ts`.

**Done when**: `pnpm test` and `pnpm -r typecheck` exit 0 (146 tests).

---

## Task dependency order

```
TASK-01  Types + deps
   ↓
TASK-02  Walker          TASK-03  Normalizer
   ↓                        ↓
TASK-04  Signature engine  (needs 02 + 03)
   ↓
TASK-05  12 definitions   (needs 04)
TASK-06  Bedrock client   (needs 01, independent of 02–05)
   ↓
TASK-07  Heuristic engine (needs 04 + 06)
   ↓
TASK-08  Orchestrator     (needs 02–07)
   ↓
TASK-09  Reporters        (needs types)
TASK-10  Lambda handler   (needs 08 + 09)
   ↓
TASK-11  Public exports + final validation
   ↓
TASK-12  KIRO_LOG
```

---

## M1 completion checklist

- [ ] `pnpm install` exits 0
- [ ] `pnpm -r build` exits 0
- [ ] `pnpm test` exits 0, ≥ 53 tests passing
- [ ] `pnpm -r typecheck` exits 0
- [ ] `definitions/` contains EX-001 through EX-012
- [ ] `docs/THREATS.md` has 12 rows
- [ ] No `.env` tracked by git
- [ ] No AWS credentials in any source file
- [ ] `KIRO_LOG.md` counts: Specs 2, PBTs 30
