# Design: m1-engine

---

## 1. Package structure added in M1

```
packages/core/src/
├── types.ts                        ← FileRole, Severity, Finding, ScanEvent, …
├── walker.ts                       ← walkRepo, classifyFile
├── normalizer.ts                   ← normalize, NormalizedText, UnicodeHit
├── scanner/
│   ├── signature-engine.ts         ← runSignatures
│   ├── heuristic-engine.ts         ← runHeuristics
│   └── orchestrator.ts             ← scanRepo (public entry point)
├── llm/
│   ├── bedrock.ts                  ← callBedrock (only AWS SDK touch-point)
│   ├── prompts.ts                  ← buildHeuristicPrompt
│   └── __tests__/
│       └── fake-client.ts          ← FakeBedrockClient for tests
├── reporters/
│   ├── json-reporter.ts
│   └── sarif-reporter.ts
├── lambda/
│   └── handler.ts
├── definitions/                    ← schema.ts, loader.ts from M0
│   └── __tests__/
├── secrets-check.ts                ← from M0
└── index.ts                        ← public exports (REQ-09)

definitions/
├── EX-001-hidden-unicode.yaml      ← M0
├── EX-002-ai-instructions.yaml
├── EX-003-encoded-payload.yaml
├── EX-004-html-comment-smuggling.yaml
├── EX-005-tool-description-poisoning.yaml
├── EX-006-mcp-rug-pull.yaml
├── EX-007-overbroad-autoapprove.yaml
├── EX-008-remote-code-hook.yaml
├── EX-009-install-script-exfiltration.yaml
├── EX-010-unpinned-mcp-server.yaml
├── EX-011-secrets-in-agent-reach.yaml
└── EX-012-markdown-image-exfil.yaml
```

New dev dependencies added to root `package.json`:

- `@aws-sdk/client-bedrock-runtime` — Bedrock inference calls
- `@aws-lambda-powertools/logger` — structured Lambda logging (no file content)
- `aws-lambda` + `@types/aws-lambda` — Lambda handler types
- `jsonpath-plus` — JSON path evaluation for `match.json_path` rules
- `simple-git` — `git clone` in the Lambda handler

---

## 2. Central types (`packages/core/src/types.ts`)

All shared types live here. No circular imports — this file imports nothing from
the rest of `packages/core`.

```ts
export type FileRole =
  | "instruction"
  | "mcp-config"
  | "hook"
  | "manifest"
  | "definition"
  | "memory"
  | "power"
  | "docs"
  | "code"
  | "config"
  | "unknown";

export type Severity = "critical" | "high" | "medium" | "low";

export type RepoFile = {
  path: string;
  rel: string;
  role: FileRole;
  sizeBytes: number;
};

export type SignatureFinding = {
  source: "signature";
  ruleId: string;
  title: string;
  severity: Severity;
  file: string;
  line: number;
  col: number;
  span: string;
  owasp: string[];
  fix: string;
};

export type HeuristicFinding = SignatureFinding & {
  source: "heuristic";
  rationale: string;
  confidence: "high" | "medium" | "low";
};

export type Finding = SignatureFinding | HeuristicFinding;

export type ScanEvent =
  | { type: "file"; file: RepoFile }
  | { type: "finding"; finding: Finding }
  | { type: "error"; file: string; message: string }
  | { type: "done"; stats: ScanStats };

export type ScanStats = {
  filesScanned: number;
  filesSkipped: number;
  findingsTotal: number;
  durationMs: number;
};
```

---

## 3. File walker (`walker.ts`)

### Classification table (evaluated top-to-bottom, first match wins)

| Priority | Role          | Path patterns                                                                                                                             |
| -------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| 1        | `instruction` | `**/AGENTS.md`, `**/CLAUDE.md`, `**/.cursorrules`, `**/.github/copilot-instructions.md`, `**/SKILL.md`, `**/README*`, `.kiro/steering/**` |
| 2        | `mcp-config`  | `**/.kiro/settings/mcp.json`, `**/.cursor/mcp.json`, `**/.vscode/mcp.json`, `**/claude_desktop_config.json`                               |
| 3        | `hook`        | `.kiro/hooks/**`, `**/*.hook.yaml`                                                                                                        |
| 4        | `manifest`    | `**/package.json`                                                                                                                         |
| 5        | `definition`  | `definitions/*.yaml`                                                                                                                      |
| 6        | `memory`      | `**/MEMORY.md`, `.kiro/notes/**`, `**/agent-notes*`                                                                                       |
| 7        | `power`       | `power/**`                                                                                                                                |
| 8        | `docs`        | `**/*.md`, `**/*.txt`                                                                                                                     |
| 9        | `code`        | `**/*.ts`, `**/*.js`, `**/*.py`, `**/*.sh`                                                                                                |
| 10       | `config`      | `**/*.json`, `**/*.yaml`, `**/*.toml`                                                                                                     |
| 11       | `unknown`     | everything else                                                                                                                           |

`classifyFile(rel: string): FileRole` is exported separately so it can be tested
without I/O.

### Skip-list implementation

```ts
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  ".next",
  ".pnpm-store",
]);
```

Checked on each directory entry before recursing. The walker uses
`fs.promises.opendir` (streaming, no full readdir array) to handle large repos.

### Binary detection

Read the first 512 bytes of each file. If any byte is `0x00`, mark as binary
and skip. This is the same heuristic used by `git diff`.

---

## 4. Normalizer (`normalizer.ts`)

### Unicode detection

The hidden Unicode ranges, as code-point intervals:

| Class name      | Code points                    |
| --------------- | ------------------------------ |
| `zero-width`    | U+200B, U+200C, U+200D, U+FEFF |
| `bidi-override` | U+202A–U+202E, U+2066–U+2069   |
| `tag-block`     | U+E0000–U+E007F                |

A single regex built from these ranges at module load time (not per-call).

### HTML entity decoding

Handled with a small lookup map for named entities (`&amp;` → `&`, etc.) plus
`parseInt` for numeric forms. No external library needed for the small set
Exorcist 98 cares about.

### Base64 candidate filter

Pattern: `/(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{32,}(?![A-Za-z0-9+/=])/g`

Excluded prefixes (checked before adding to candidates):

- `data:image/`
- `sha256:`
- `sha512:`
- `sha1:`
- `md5:`

A candidate is worth escalating to heuristics if, when decoded with
`Buffer.from(s, 'base64').toString('utf8')`, the result:

- Is valid UTF-8 (no replacement characters), and
- Contains `http` or one of the phrases: `ignore previous`, `you are now`,
  `as an ai`, `system prompt`.

---

## 5. Signature engine (`scanner/signature-engine.ts`)

### `match.regex` execution

```
compile regex → test against norm.plain
→ for each match:
    offset = match.index in norm.plain
    line   = count \n chars before offset in norm.original + 1
    col    = offset - last \n before offset
    span   = norm.original.slice(offset, offset + match[0].length).slice(0, 120)
```

Regex flags: `gi` (global + case-insensitive). Each definition's regex is
compiled once and cached by rule ID to avoid recompilation per file.

### `match.unicode_class` execution

For each class name in the array, look up which `UnicodeHit` entries in
`norm.hiddenUnicode` belong to that class. Each hit → one finding. `span` is set
to the Unicode code point as `\uXXXX` or `\u{XXXXX}` notation.

### `match.json_path` execution

Parse the file text as JSON using `JSON.parse`. On parse failure, return no
findings (not an error). Evaluate the JSON path with `jsonpath-plus`. Each
matched value → one finding, with `line` set to 1 and `col` to 1 (JSON path
doesn't give line numbers; a future improvement can add them).

### Line number helper

```ts
function offsetToPosition(
  text: string,
  offset: number,
): { line: number; col: number };
```

Pure function. Count `\n` characters before `offset`.

---

## 6. Heuristic engine (`scanner/heuristic-engine.ts`)

### Escalation decision

A file is escalated if any of:

1. `sigFindings.some(f => f.file === file.rel)` — signatures already flagged it
2. `norm.hiddenUnicode.length > 0`
3. Any base64 candidate decodes to a suspicious string (see normalizer section)

If escalated, one Bedrock call is made per file (not per finding), sending the
top suspicious span (longest hidden Unicode sequence, or first sig finding span,
or first suspicious base64 decode, in that priority).

### Prompt structure (`llm/prompts.ts`)

```
You are a security classifier. Analyze the following text span for prompt
injection, tool poisoning, or other attacks against AI agents.

Span is delimited by <<<NONCE_START_{{nonce}}>>> and <<<NONCE_END_{{nonce}}}>>>.

<<<NONCE_START_{{nonce}}>>>
{{span_text}}
<<<NONCE_END_{{nonce}}>>>

Context (3 lines before and after, from file {{rel_path}}):
{{context_lines}}

Respond with ONLY a JSON object matching this exact schema:
{"verdict":"malicious|suspicious|benign","threat_class":"string","quoted_span":"exact substring","rationale":"one sentence"}

Do not produce any output outside the JSON object. Do not call any tools.
```

Model selection: Haiku for initial triage (verdict ≠ benign triggers re-check),
Sonnet for the final judge verdict. This matches the plan's "Haiku for triage,
Sonnet for the judge" rule.

### Span-verification step

After parsing the JSON response, run:

```ts
norm.original.includes(result.quoted_span);
```

If this is false, discard the entire verdict. This implements the security.md
rule "Drop any LLM verdict whose quoted span is not found verbatim in the
scanned file."

---

## 7. Orchestrator (`scanner/orchestrator.ts`)

### Async generator pattern

```ts
async function* scanRepo(root, options): AsyncIterable<ScanEvent> {
  const defs = await loadDefinitions(options.definitionsDir);
  const start = Date.now();
  let filesScanned = 0,
    filesSkipped = 0,
    findingsTotal = 0;

  for await (const file of walkRepo(root)) {
    yield { type: "file", file };
    try {
      const norm = normalize(await readFile(file.path, "utf8"), file.role);
      const sigs = runSignatures(file, norm, defs);
      const heurs = options.bedrockClient
        ? await runHeuristics(file, norm, sigs, options.bedrockClient)
        : [];
      const deduped = deduplicate([...sigs, ...heurs]);
      for (const f of deduped) {
        findingsTotal++;
        yield { type: "finding", finding: f };
      }
      filesScanned++;
    } catch (e) {
      filesSkipped++;
      yield { type: "error", file: file.rel, message: String(e) };
    }
  }

  yield {
    type: "done",
    stats: {
      filesScanned,
      filesSkipped,
      findingsTotal,
      durationMs: Date.now() - start,
    },
  };
}
```

### Deduplication key

`${finding.ruleId}:${finding.file}:${finding.line}:${finding.col}`

---

## 8. Bedrock client (`llm/bedrock.ts`)

Uses `@aws-sdk/client-bedrock-runtime` with `InvokeModelCommand`. Model IDs:

- Haiku: `anthropic.claude-3-haiku-20240307-v1:0`
- Sonnet: `anthropic.claude-3-5-sonnet-20241022-v2:0`

The module reads `AWS_REGION` from `process.env` at call time (not module load)
so it can be overridden in tests via `process.env`.

`BedrockClient` interface (used by heuristic engine):

```ts
interface BedrockClient {
  call(params: BedrockParams): Promise<BedrockResult>;
}
```

The concrete `BedrockClientImpl` and the `FakeBedrockClient` both implement this
interface. Tests always use `FakeBedrockClient`.

---

## 9. Lambda handler (`lambda/handler.ts`)

### Request validation

```ts
const BodySchema = z.object({
  repoUrl: z.string().url().startsWith("https://github.com/"),
});
```

### Clone and cleanup

```ts
const tmpDir = path.join("/tmp", crypto.randomUUID());
try {
  await git.clone(repoUrl, tmpDir, ["--depth", "1", "--single-branch"]);
  const events = collectAsync(scanRepo(tmpDir, options));
  // …
} finally {
  await rm(tmpDir, { recursive: true, force: true });
}
```

`collectAsync` drains the async iterable into arrays of findings and stats
without holding all events in memory simultaneously.

### Environment schema (validated at cold-start)

```ts
const EnvSchema = z.object({
  AWS_REGION: z.string().min(1),
  DEFINITIONS_S3_BUCKET: z.string().min(1).optional(),
  // If not set, definitions are loaded from the bundle path at build time
});
```

---

## 10. Reporters

### JSON reporter

Output shape (Zod-validated):

```ts
const ScanReportSchema = z.object({
  version: z.literal("1"),
  createdAt: z.string().datetime(),
  stats: ScanStatsSchema,
  findings: z.array(FindingSchema),
});
```

### SARIF reporter

Level mapping:
| Severity | SARIF level |
|----------|------------|
| `critical` | `error` |
| `high` | `error` |
| `medium` | `warning` |
| `low` | `note` |

Output uses `uri` relative to `repoRoot` for portability.

---

## 11. Property-based test strategy for M1

| Suite            | PBTs          | Key arbitraries                               |
| ---------------- | ------------- | --------------------------------------------- |
| Walker           | PBT-WLK-01–04 | `fc.constantFrom` over real file paths        |
| Normalizer       | PBT-NRM-01–04 | `fc.string()`, insertion of Unicode chars     |
| Signature engine | PBT-SIG-01–04 | `fc.constantFrom` over haunted-repo fixtures  |
| Heuristic engine | PBT-HEU-01–04 | `FakeBedrockClient` with controlled responses |
| Orchestrator     | PBT-ORC-01–03 | Full scan of haunted-repo; mtime snapshots    |

New PBTs in M1: 19. Running total: 30.

---

## 11b. Detection accuracy changes (REQ-10)

- `match.value_regex` is an optional case-insensitive filter over the values
  that `json_path` selects. Schema rule: it requires `json_path`, and both
  `regex` and `value_regex` must compile.
- `jsonpath-plus` supports `||` and `==` in filter expressions and unquoted
  unions such as `$.scripts[preinstall,install,postinstall]`. An earlier note
  that `||` was unsupported was wrong; that failure came from a filter being
  applied to string values.
- EX-010 inspects `args[0:2]` of package-runner servers. Known limit: a bare
  positional word in the first two args of such a server would be flagged.
- The EX-001 fixture is generated with a script so the invisible characters
  are exact; it is the only fixture with literal control characters.

## 12. What M1 does not build

- Next.js routes or UI components (M2).
- MCP proxy or hash-pin store (M3).
- The `exorcist scan` CLI body (M3).
- EX-013–EX-020 definitions (M2/M3).
- ZIP upload handling (M2).
- Actual AWS deployment infrastructure (M2).
