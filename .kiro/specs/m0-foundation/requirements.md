# Spec: m0-foundation

Milestone M0 (Nov 15–18). Establishes the monorepo skeleton, the Haunted Repo test
fixtures, and the agent hooks that support the rest of development. No production
detection logic is built here; this spec exists so every later spec has a working
foundation to build on.

---

## Requirements

### REQ-01 Monorepo skeleton

**What**: The repository must match the layout in `docs/PLAN.md` section 5 and the
`tech.md` steering rule "Layout: apps/web … definitions/ fixtures/ power/".

**Acceptance criteria**:

1. A `pnpm-workspace.yaml` at the root declares the following packages:
   `apps/web`, `packages/core`, `packages/shield`, `packages/mcp-server`,
   `packages/cli`.
2. Each package directory contains a `package.json` with `"name"` matching the
   directory path (e.g. `@exorcist-98/core`), `"private": true` (except `cli`),
   and `"type": "module"`.
3. A root `package.json` sets `"packageManager": "pnpm@9"` and `"engines":
   {"node": ">=20"}`.
4. A root `tsconfig.base.json` enables `"strict": true`, `"noUncheckedIndexedAccess":
   true`, and sets `"moduleResolution": "bundler"`. Each package has a
   `tsconfig.json` that extends it.
5. A root `vitest.workspace.ts` references all packages so `pnpm test` runs all
   test suites from the root.
6. `definitions/` and `fixtures/haunted-repo/` directories exist and each
   contains a `.gitkeep` until populated by REQ-02 and REQ-03.
7. `power/` directory exists with a `.gitkeep`.
8. `docs/THREATS.md` exists (empty skeleton with a header) so the hook in
   REQ-05-C can write to it.
9. Running `pnpm install` from the root completes without errors on Node 20.
10. Running `pnpm build` from the root completes without errors (each package
    may have an empty build step initially).

**Property-based tests**: none — this requirement is structural and verified by
the CI check in REQ-06.

---

### REQ-02 Haunted Repo fixtures

**What**: Twenty defanged attack samples that demonstrate all threat classes the
engine will later detect. They are the primary test corpus for every later spec.

**Acceptance criteria**:

1. All twenty files live under `fixtures/haunted-repo/`. Each file is named
   `EX-NNN-<short-slug>.<ext>` matching its threat ID in the plan's threat
   catalogue (EX-001 to EX-020).
2. Every file contains a comment `# DEFANGED` (or `<!-- DEFANGED -->` for HTML/
   Markdown) and uses `example.invalid` for any domain and
   `EXAMPLE_TOKEN_DO_NOT_USE` for any credential, per the `security.md` rule.
3. No fixture contains a reachable URL, working shell command, or real credential.
   This is verified by the property-based test in REQ-02-PBT.
4. Each fixture covers exactly the threat described in `docs/PLAN.md` section 4,
   row by row: EX-001 hidden Unicode, EX-002 AI-addressed instructions, …,
   EX-020 suspicious Power.
5. A `fixtures/haunted-repo/README.md` lists every fixture with its ID, file,
   and a one-sentence description of what attack it represents.
6. The fixture set is static (not generated at test time) and committed to the
   repo.

**Property-based tests (REQ-02-PBT)**:

Located in `fixtures/haunted-repo/__tests__/fixtures.property.test.ts`.

| ID | Property | fast-check strategy |
|----|----------|---------------------|
| PBT-FIX-01 | No fixture file contains a reachable domain (anything other than `*.invalid`, `localhost`, `127.0.0.1`, `0.0.0.0`) | Read each fixture as a string; `fc.constant` over the file list; assert no URL matches a live-domain pattern |
| PBT-FIX-02 | No fixture file contains a string that matches a real secret pattern (AWS key, GitHub token, generic `sk-…` OpenAI key) unless it also matches the placeholder pattern `EXAMPLE_.*_DO_NOT_USE` | `fc.constant` over file list; regex dual-check |
| PBT-FIX-03 | Every fixture file contains the literal string `DEFANGED` | `fc.constant` over file list |
| PBT-FIX-04 | The fixture file for each EX-NNN threat ID exists on disk | `fc.constantFrom(...ids)`; `fs.existsSync` |

---

### REQ-03 Virus definition schema and first stub

**What**: Establishes the YAML schema that all signature rules must follow, so the
engine spec (M1) has a contract to code against.

**Acceptance criteria**:

1. `definitions/schema.ts` (inside `packages/core/src/definitions/`) exports a
   Zod schema `VirusDefinitionSchema` with the following fields (all required
   unless noted):

   | Field | Type | Notes |
   |-------|------|-------|
   | `id` | `string` | Pattern `EX-\d{3}` |
   | `title` | `string` | Non-empty |
   | `severity` | `"critical" \| "high" \| "medium" \| "low"` | |
   | `applies_to` | `string[]` | File-role labels, min 1 |
   | `match` | object | See sub-fields below |
   | `owasp` | `string[]` | Min 1 reference |
   | `fix` | `string` | Non-empty |
   | `enabled` | `boolean` | Optional, defaults `true` |

   `match` sub-fields (at least one must be present):

   | Sub-field | Type |
   |-----------|------|
   | `regex` | `string` (optional) |
   | `unicode_class` | `string[]` (optional) |
   | `json_path` | `string` (optional) |

2. `definitions/EX-001-hidden-unicode.yaml` is a valid, complete rule using this
   schema (the first real signature; serves as the canonical example).
3. `packages/core/src/definitions/loader.ts` exports `loadDefinitions(dir: string):
   Promise<VirusDefinition[]>` that reads all `*.yaml` files from `dir`, parses
   them with `js-yaml`, validates each with `VirusDefinitionSchema`, and throws a
   typed `DefinitionLoadError` (not a raw `Error`) if any file fails validation.
4. Unit tests in `packages/core/src/definitions/__tests__/loader.test.ts` cover:
   - Loading a valid YAML file returns the correct typed object.
   - A YAML file missing `id` throws `DefinitionLoadError`.
   - A YAML file with an invalid severity value throws `DefinitionLoadError`.

**Property-based tests (REQ-03-PBT)**:

Located in `packages/core/src/definitions/__tests__/schema.property.test.ts`.

| ID | Property | fast-check strategy |
|----|----------|---------------------|
| PBT-DEF-01 | Any object satisfying `VirusDefinitionSchema` round-trips through `JSON.stringify` / `JSON.parse` without losing fields | `fc.record` matching the schema shape |
| PBT-DEF-02 | An `id` field not matching `EX-\d{3}` always fails validation | `fc.string()` filtered to exclude valid IDs |
| PBT-DEF-03 | A definition with no `match` sub-fields present always fails validation | `fc.record` with `match: {}` |

---

### REQ-04 Root CI workflow

**What**: A GitHub Actions workflow that runs on every push and pull request so
broken scaffolding is caught immediately.

**Acceptance criteria**:

1. `.github/workflows/ci.yml` exists with jobs:
   - `install`: runs `pnpm install --frozen-lockfile` on Node 20.
   - `build`: depends on `install`; runs `pnpm build`.
   - `test`: depends on `install`; runs `pnpm test`.
   - `typecheck`: depends on `install`; runs `pnpm tsc --noEmit` (or the
     per-package equivalent).
2. The workflow runs on `push` to `main` and on `pull_request`.
3. No secrets are referenced in the workflow; Bedrock credentials are not needed
   until M1.
4. The workflow uses `pnpm/action-setup@v4` (or later) and `actions/setup-node@v4`
   (or later).

**Property-based tests**: none — workflow correctness is validated by GitHub
Actions execution.

---

### REQ-05 Agent hooks

The plan (section 7) lists four hooks to create during M0. Each hook is defined in
`.kiro/hooks/` as a YAML file following Kiro hook conventions.

#### REQ-05-A — Definition save hook

**File**: `.kiro/hooks/definition-save.yaml`

**Trigger**: file save matching `definitions/**/*.yaml`.

**Action**: runs `pnpm --filter @exorcist-98/core test -- --run --reporter=verbose`
so signature tests execute immediately when a definition is edited.

**Acceptance criteria**:
1. The hook file is valid Kiro hook YAML.
2. The glob pattern matches any `.yaml` file anywhere under `definitions/`.
3. The command is a `pnpm` invocation (not `npm` or `yarn`), consistent with
   `tech.md`.
4. The hook only runs tests; it does not modify files or make network calls.

#### REQ-05-B — MCP config change hook

**File**: `.kiro/hooks/mcp-config-change.yaml`

**Trigger**: file save matching any of:
`**/.kiro/settings/mcp.json`, `**/.cursor/mcp.json`, `**/.vscode/mcp.json`,
`**/claude_desktop_config.json`.

**Action**: runs `pnpm --filter @exorcist-98/cli exec exorcist scan --config $FILE`
to re-scan the changed MCP config file.

**Acceptance criteria**:
1. The hook file is valid Kiro hook YAML.
2. All four MCP config path patterns are present.
3. The command passes `$FILE` (the saved file path) to the scanner, not a
   hardcoded path.
4. On M0 this hook is marked `enabled: false` (the CLI doesn't exist yet); it
   is enabled in the M3 spec.

#### REQ-05-C — Spec change hook

**File**: `.kiro/hooks/spec-change.yaml`

**Trigger**: file save matching `.kiro/specs/**/*.md`.

**Action**: a prompt-based hook that asks Kiro to update the threat descriptions
in `docs/THREATS.md` to stay consistent with the changed spec.

**Acceptance criteria**:
1. The hook file uses `type: prompt` (not a shell command).
2. The prompt instructs Kiro to read the changed spec file and update only the
   relevant rows in `docs/THREATS.md` without altering other content.
3. The prompt includes the instruction "Do not modify any file other than
   `docs/THREATS.md`."

#### REQ-05-D — Pre-commit secrets check hook

**File**: `.kiro/hooks/pre-commit-secrets.yaml`

**Trigger**: `preToolCall` on the `git_commit` tool (or equivalent Kiro
pre-commit hook event).

**Action**: runs `pnpm --filter @exorcist-98/core exec ts-node
src/secrets-check.ts --staged` and blocks the commit if exit code is non-zero.

**Acceptance criteria**:
1. The hook file is valid Kiro hook YAML with `blocking: true`.
2. The command only inspects staged files (`--staged` flag), not the full tree.
3. The check catches at minimum: AWS access key patterns (`AKIA[0-9A-Z]{16}`),
   GitHub tokens (`gh[ps]_[A-Za-z0-9]{36}`), and generic `sk-` prefixed keys.
4. The `src/secrets-check.ts` script lives in `packages/core/` and exits `0`
   when no secrets are found, `1` when any are found, printing the file and
   line number for each hit.
5. Placeholder values matching `EXAMPLE_.*_DO_NOT_USE` are explicitly excluded
   from flagging, so fixture files do not block commits.

**Property-based tests (REQ-05-PBT)**:

Located in `packages/core/src/__tests__/secrets-check.property.test.ts`.

| ID | Property | fast-check strategy |
|----|----------|---------------------|
| PBT-SEC-01 | Any string containing a valid AWS access key pattern is always flagged, regardless of surrounding content | `fc.string()` + template inserting `AKIA` + 16 uppercase alphanumeric chars at a random position |
| PBT-SEC-02 | Any string matching `EXAMPLE_.*_DO_NOT_USE` is never flagged, even if it embeds a key-shaped substring | `fc.string()` wrapped in the placeholder pattern |
| PBT-SEC-03 | The check is idempotent: running it twice on the same input returns the same result | `fc.string()` |
| PBT-SEC-04 | An empty string is never flagged | `fc.constant("")` |

---

### REQ-06 Scaffolding validation test

**What**: A single test that programmatically verifies the repo layout so CI
catches structural drift.

**Acceptance criteria**:

1. `packages/core/src/__tests__/scaffold.test.ts` checks that every path listed
   in REQ-01 (workspace packages, `definitions/`, `fixtures/haunted-repo/`,
   `power/`, `docs/THREATS.md`) exists on disk relative to the repo root.
2. The test uses `fs.existsSync` (not shell commands) so it is portable.
3. The test passes when run from the repo root with `pnpm test`.

---

### REQ-07 KIRO_LOG.md entries for M0

**What**: Every Kiro feature used in M0 must be recorded, per the plan's
instruction to "log everything in `docs/KIRO_LOG.md`."

**Acceptance criteria**:

1. `docs/KIRO_LOG.md` contains a row for each of the following M0 activities:
   - Steering files added (already present as of Nov 15).
   - This spec (`m0-foundation`) generated with Kiro Specs.
   - Each hook created (REQ-05-A through REQ-05-D) logged as a Hooks entry.
2. The "Counts" section at the bottom of `KIRO_LOG.md` is updated:
   `Specs: 1`, `Steering docs: 4`, `Hooks: 4`.
3. No count is left at its default blank value after M0 is complete.

---

## Out of scope for this spec

- Any detection logic (file walker, signature matching, Bedrock calls) — those
  are M1.
- The web UI — M2.
- The MCP proxy or Quarantine Vault — M3.
- Actual execution of the MCP-config-change hook (the CLI it calls does not exist
  yet).
