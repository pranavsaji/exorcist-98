# Spec: m1-engine

Milestone M1 (Nov 19–24). Builds the detection engine inside `packages/core`:
file walker, file-role classifier, text normalizer, signature runner, Bedrock
heuristic layer, finding scorer/deduplicator, JSON/SARIF reporters, and a Lambda
API handler that accepts a GitHub URL and returns findings. No UI is built here.

---

## Requirements

### REQ-01 File walker and classifier

**What**: A function that accepts a root directory path and returns every file the
engine should inspect, each annotated with its role.

**Acceptance criteria**:

1. `packages/core/src/walker.ts` exports:
   ```ts
   walkRepo(root: string): AsyncIterable<RepoFile>
   ```
   where `RepoFile` is:
   ```ts
   type RepoFile = {
     path: string;       // absolute path
     rel:  string;       // path relative to root
     role: FileRole;
     sizeBytes: number;
   };
   ```
2. `FileRole` is a string union exported from `packages/core/src/types.ts`:
   ```ts
   type FileRole =
     | 'instruction'   // .kiro/steering/**, AGENTS.md, CLAUDE.md, .cursorrules,
                       //   .github/copilot-instructions.md, SKILL.md, README*
     | 'mcp-config'    // mcp.json paths, claude_desktop_config.json
     | 'hook'          // .kiro/hooks/**, *.hook.yaml
     | 'manifest'      // package.json
     | 'definition'    // definitions/*.yaml
     | 'memory'        // MEMORY.md, .kiro/notes/**, agent-notes*
     | 'power'         // power/**
     | 'docs'          // *.md, *.txt not matched above
     | 'code'          // *.ts, *.js, *.py, *.sh
     | 'config'        // *.json, *.yaml, *.toml not matched above
     | 'unknown';
   ```
3. Files larger than 1 MB are skipped (not yielded).
4. Binary files (detected by the presence of a null byte in the first 512 bytes)
   are skipped.
5. The walker skips `node_modules/`, `.git/`, `dist/`, `.next/`, and `.pnpm-store/`.
6. Classification is determined by path pattern, in priority order: `instruction`
   > `mcp-config` > `hook` > `manifest` > `definition` > `memory` > `power` >
   `docs` > `code` > `config` > `unknown`.
7. The walker is an `AsyncIterable`, not a function that returns an array, so it
   can handle large repos without loading all paths into memory.

**Property-based tests (REQ-01-PBT)**:

Located in `packages/core/src/__tests__/walker.property.test.ts`.

| ID | Property | Strategy |
|----|----------|----------|
| PBT-WLK-01 | Every file yielded has `sizeBytes <= 1_048_576` | Collect all from `fixtures/haunted-repo/`; assert |
| PBT-WLK-02 | No yielded path contains `node_modules` or `.git` | Same corpus |
| PBT-WLK-03 | `classifyFile(rel)` is pure: same input always returns same role | `fc.constantFrom` over a fixed path list |
| PBT-WLK-04 | Every `FileRole` value is a non-empty string | `fc.constantFrom` over all role values |

---

### REQ-02 Text normalizer

**What**: A set of pure functions that transform raw file text into a form where
hidden payloads are visible to regex matching.

**Acceptance criteria**:

1. `packages/core/src/normalizer.ts` exports:
   ```ts
   normalize(text: string, role: FileRole): NormalizedText
   ```
   where:
   ```ts
   type NormalizedText = {
     original:   string;  // unchanged
     plain:      string;  // HTML entities decoded, comments extracted
     hiddenUnicode: UnicodeHit[];  // zero-width / bidi / tag chars found
     comments:   string[];         // extracted HTML/block comment bodies
     base64Candidates: string[];   // strings that look like base64 blobs (≥32 chars)
   };
   type UnicodeHit = { char: string; codePoint: number; offset: number };
   ```
2. `hiddenUnicode` detects at minimum:
   - Zero-width characters: U+200B, U+200C, U+200D, U+FEFF
   - Bidi overrides: U+202A–U+202E, U+2066–U+2069
   - Tag block: U+E0000–U+E007F
3. `comments` extracts the inner text of `<!-- … -->` HTML comments and
   `/* … */` block comments.
4. `base64Candidates` matches any run of `[A-Za-z0-9+/=]{32,}` not preceded by a
   common innocuous prefix (e.g. `data:image/`, `sha256:`, `sha512:`).
5. HTML entities (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&#NNN;`, `&#xHH;`) are
   decoded in `plain`.
6. The normalizer is a pure function with no I/O.

**Property-based tests (REQ-02-PBT)**:

Located in `packages/core/src/__tests__/normalizer.property.test.ts`.

| ID | Property | Strategy |
|----|----------|----------|
| PBT-NRM-01 | `normalize` is idempotent: `normalize(t,r).plain === normalize(normalize(t,r).plain, r).plain` | `fc.string()` |
| PBT-NRM-02 | A string containing a zero-width char always produces at least one `hiddenUnicode` hit | `fc.string()` with U+200B inserted at random position |
| PBT-NRM-03 | A string with no hidden Unicode chars produces an empty `hiddenUnicode` array | `fc.string()` filtered to printable ASCII |
| PBT-NRM-04 | `base64Candidates` never includes strings shorter than 32 chars | `fc.string({ maxLength: 31 })` |

---

### REQ-03 Signature engine

**What**: Runs the loaded `VirusDefinition` rules against a `NormalizedText` and
returns typed findings.

**Acceptance criteria**:

1. `packages/core/src/scanner/signature-engine.ts` exports:
   ```ts
   runSignatures(
     file: RepoFile,
     norm: NormalizedText,
     defs: VirusDefinition[],
   ): SignatureFinding[]
   ```
2. `SignatureFinding` is defined in `packages/core/src/types.ts`:
   ```ts
   type SignatureFinding = {
     source:     'signature';
     ruleId:     string;         // e.g. "EX-001"
     title:      string;
     severity:   Severity;
     file:       string;         // rel path
     line:       number;         // 1-based
     col:        number;         // 1-based
     span:       string;         // exact quoted substring, max 120 chars
     owasp:      string[];
     fix:        string;
   };
   type Severity = 'critical' | 'high' | 'medium' | 'low';
   ```
3. `match.regex` rules: compile the pattern and test against `norm.plain`. For
   each match, record line/col from the original text using the match offset.
4. `match.unicode_class` rules: check `norm.hiddenUnicode` for the named classes
   (`zero-width`, `bidi-override`, `tag-block`). Each hit produces one finding
   with `span` set to the Unicode character's hex escape.
5. `match.json_path` rules: parse the file as JSON (skip silently if not valid
   JSON), evaluate the JSON path expression, and flag the matched value.
6. `applies_to` filtering: only run a rule against a file whose `role` is listed
   in the rule's `applies_to` array.
7. Only rules with `enabled: true` (the default) are run.
8. `span` is capped at 120 characters; if the matched text is longer, truncate
   and append `…`.

**Property-based tests (REQ-03-PBT)**:

Located in `packages/core/src/__tests__/signature-engine.property.test.ts`.

| ID | Property | Strategy |
|----|----------|----------|
| PBT-SIG-01 | Running signatures on a file with no matching content returns an empty array | Generate random strings unlikely to match any real pattern; `fc.string()` with printable ASCII |
| PBT-SIG-02 | Scanning is idempotent: same file + same defs → same findings | `fc.constantFrom` over haunted-repo fixtures |
| PBT-SIG-03 | A disabled rule (`enabled: false`) never produces a finding | Build a def with `enabled: false` and known-matching content |
| PBT-SIG-04 | `span` is never longer than 120 characters | Assert on all findings from haunted-repo scan |

---

### REQ-04 First 12 virus definitions

**What**: YAML files for EX-001 to EX-012 (the 12 signatures the plan requires
for M1), all valid against `VirusDefinitionSchema`.

**Acceptance criteria**:

1. `definitions/EX-001-hidden-unicode.yaml` already exists from M0. Files
   EX-002 through EX-012 are added in M1.
2. Each definition covers exactly the threat in the plan's threat catalogue
   (section 4), using the correct `match` strategy for its threat type:
   - Unicode threats → `unicode_class`
   - Text-pattern threats (EX-002, EX-004, EX-008, EX-009, EX-012) → `regex`
   - JSON-structural threats (EX-007, EX-010) → `json_path`
3. Every definition passes `loadDefinitions()` without error.
4. Running the signature engine against the corresponding haunted-repo fixture
   produces at least one `SignatureFinding` for that rule ID.
5. `docs/THREATS.md` is updated to include a row for every definition that exists.

**Property-based tests (REQ-04-PBT)**:

Located in `packages/core/src/__tests__/definitions-integration.test.ts`
(unit + integration, not pure PBT — validates each definition fires on its fixture).

| ID | Test | What it checks |
|----|------|----------------|
| INT-DEF-01 | EX-001 fires on `EX-001-hidden-unicode.md` | At least one finding with `ruleId: 'EX-001'` |
| INT-DEF-02..12 | Same pattern for EX-002..EX-012 | One test per definition |

---

### REQ-05 Bedrock heuristic layer

**What**: A second detection pass that sends suspicious spans to Amazon Bedrock
Claude and validates the response before accepting it as a finding.

**Acceptance criteria**:

1. `packages/core/src/llm/bedrock.ts` exports:
   ```ts
   callBedrock(params: BedrockParams): Promise<BedrockResult>
   ```
   where:
   ```ts
   type BedrockParams = {
     model:   'haiku' | 'sonnet';
     prompt:  string;             // fully assembled, nonce-wrapped
     maxTokens: number;
   };
   type BedrockResult =
     | { ok: true;  raw: string }
     | { ok: false; error: string };
   ```
   This module is the **only** place in `packages/core` that calls AWS SDK.
2. `packages/core/src/scanner/heuristic-engine.ts` exports:
   ```ts
   runHeuristics(
     file: RepoFile,
     norm: NormalizedText,
     sigFindings: SignatureFinding[],
     client: BedrockClient,
   ): Promise<HeuristicFinding[]>
   ```
   where `BedrockClient` is an interface (not the concrete AWS class) so tests
   can inject a fake.
3. The heuristic engine escalates a span to Bedrock only if at least one of:
   - A signature finding already flagged the same file, or
   - The normalized text contains a `hiddenUnicode` hit, or
   - A `base64Candidate` decodes to a string containing `http` or a known
     instruction phrase.
4. The prompt sent to Bedrock **must**:
   - Wrap the untrusted span in `<<<NONCE_START_{{nonce}}>>>` /
     `<<<NONCE_END_{{nonce}}>>>` delimiters where `nonce` is a random 8-char
     hex string generated per call.
   - Ask for a strict JSON response matching:
     ```json
     {
       "verdict": "malicious|suspicious|benign",
       "threat_class": "string",
       "quoted_span": "exact substring from the file",
       "rationale": "one sentence"
     }
     ```
   - Instruct the model that it must not modify config, make tool calls, or
     produce any output outside the JSON object.
5. Response validation (all must pass or the verdict is dropped):
   - The raw response parses as valid JSON.
   - `verdict` is one of `malicious`, `suspicious`, `benign`.
   - `quoted_span` is found verbatim in `norm.original` (the security.md rule).
   - `rationale` is non-empty.
6. `HeuristicFinding` extends `SignatureFinding` with `source: 'heuristic'` and
   adds `rationale: string` and `confidence: 'high' | 'medium' | 'low'`
   (derived from verdict: malicious→high, suspicious→medium, benign is dropped).
7. If Bedrock is unavailable (network error, missing credentials), the engine
   returns an empty array and logs a warning — it never throws.
8. The concrete Bedrock client is never instantiated in test code. All heuristic
   tests use a `FakeBedrockClient` defined in
   `packages/core/src/llm/__tests__/fake-client.ts`.

**Property-based tests (REQ-05-PBT)**:

Located in `packages/core/src/__tests__/heuristic-engine.property.test.ts`.

| ID | Property | Strategy |
|----|----------|----------|
| PBT-HEU-01 | A verdict whose `quoted_span` is not in the file is always dropped | Inject a fake client that returns a span not present in the input |
| PBT-HEU-02 | A `benign` verdict never produces a finding | Fake client returns `verdict: 'benign'` for any input |
| PBT-HEU-03 | The nonce in the prompt is different for every call | Collect nonces from 100 calls; assert all distinct |
| PBT-HEU-04 | If the client returns invalid JSON, the finding is dropped and no exception propagates | Fake client returns `"not json"` |

---

### REQ-06 Scanner orchestrator

**What**: Ties walker → normalizer → signatures → heuristics into a single
`scanRepo` function that is the public API of `packages/core`.

**Acceptance criteria**:

1. `packages/core/src/scanner/orchestrator.ts` exports:
   ```ts
   scanRepo(
     root:    string,
     options: ScanOptions,
   ): AsyncIterable<ScanEvent>
   ```
   where:
   ```ts
   type ScanOptions = {
     definitionsDir: string;
     bedrockClient?: BedrockClient; // omit to skip heuristics
     maxFileSizeBytes?: number;     // default 1_048_576
   };
   type ScanEvent =
     | { type: 'file';    file: RepoFile }
     | { type: 'finding'; finding: Finding }
     | { type: 'error';   file: string; message: string }
     | { type: 'done';    stats: ScanStats };
   type ScanStats = {
     filesScanned: number;
     filesSkipped: number;
     findingsTotal: number;
     durationMs:   number;
   };
   type Finding = SignatureFinding | HeuristicFinding;
   ```
2. The orchestrator loads definitions once at startup, then walks the repo,
   normalising each file and running signatures (and heuristics if a client is
   provided) in order.
3. Errors on individual files are emitted as `type: 'error'` events, not thrown,
   so a single bad file doesn't abort the scan.
4. The orchestrator deduplicates findings by `(ruleId, file, line, col)` before
   emitting them.
5. A `type: 'done'` event is always the last event emitted.
6. A scan of `fixtures/haunted-repo/` with all 12 definitions must never mutate
   any file on disk (tested).

**Property-based tests (REQ-06-PBT)**:

| ID | Property | Strategy |
|----|----------|----------|
| PBT-ORC-01 | Scanning is idempotent: two sequential scans of the same directory produce the same findings in the same order | Run twice on haunted-repo; deep-equal the finding arrays |
| PBT-ORC-02 | No scan of haunted-repo mutates any file | Snapshot file mtimes before and after scan; assert unchanged |
| PBT-ORC-03 | `done` is always the last event | Collect all events; assert last `.type === 'done'` |

---

### REQ-07 JSON and SARIF reporters

**What**: Two functions that convert a `Finding[]` into standard output formats.

**Acceptance criteria**:

1. `packages/core/src/reporters/json-reporter.ts` exports:
   ```ts
   toJson(findings: Finding[], stats: ScanStats): ScanReport
   ```
   where `ScanReport` is a Zod-validated type with fields: `version: "1"`,
   `createdAt: string` (ISO 8601), `stats`, `findings`.
2. `packages/core/src/reporters/sarif-reporter.ts` exports:
   ```ts
   toSarif(findings: Finding[], repoRoot: string): SarifLog
   ```
   The output conforms to SARIF 2.1.0: a `runs[0].results` array where each
   result has `ruleId`, `level` (mapped from severity), `message.text`,
   `locations[0].physicalLocation` with `artifactLocation.uri` and
   `region.startLine`.
3. Both reporters are pure functions with no I/O.
4. `toJson` output validates against its own Zod schema (no runtime surprises).

---

### REQ-08 Lambda API handler

**What**: A thin AWS Lambda function that accepts a GitHub repo URL, clones it
to `/tmp`, runs `scanRepo`, and returns the JSON report.

**Acceptance criteria**:

1. `packages/core/src/lambda/handler.ts` exports:
   ```ts
   handler(event: APIGatewayProxyEventV2): Promise<APIGatewayProxyResultV2>
   ```
2. Input: JSON body `{ "repoUrl": "https://github.com/owner/repo" }`.
   - Validated with Zod; invalid input returns HTTP 400 with an error message.
   - Only `github.com` URLs are accepted; others return HTTP 400.
3. The handler clones with `git clone --depth 1 --single-branch` into a unique
   subdirectory of `/tmp` and removes it after the scan regardless of outcome.
4. The handler returns HTTP 200 with `Content-Type: application/json` and the
   `ScanReport` body on success.
5. Any unhandled error returns HTTP 500 with `{ "error": "internal" }` — no
   stack traces or file paths in the response body.
6. The handler never logs scanned file contents, only `repoUrl`, file count,
   finding count, and duration.
7. Credentials (AWS region, Bedrock model IDs) come from environment variables
   validated at cold-start with Zod; missing vars cause a descriptive startup
   error, not a silent misconfiguration.

---

### REQ-09 `packages/core` public exports

**What**: `packages/core/src/index.ts` becomes the package's public surface so
other packages can import without reaching into internal paths.

**Acceptance criteria**:

1. `src/index.ts` re-exports:
   - `scanRepo`, `ScanOptions`, `ScanEvent`, `ScanStats` from the orchestrator
   - `Finding`, `SignatureFinding`, `HeuristicFinding`, `FileRole`, `Severity` from types
   - `toJson`, `ScanReport` from the JSON reporter
   - `toSarif` from the SARIF reporter
   - `loadDefinitions`, `VirusDefinition`, `DefinitionLoadError` from definitions
2. Nothing internal (normalizer, walker, llm module internals) is exported.

---

## Out of scope for this spec

- The web UI (M2).
- The MCP proxy or Quarantine Vault (M3).
- ZIP upload handling (M2 API routes).
- GitHub authentication / private repos.
- EX-013 through EX-020 definitions (covered in later milestones where the
  corresponding detection logic lives: shield for EX-015–017, Power for EX-020).
