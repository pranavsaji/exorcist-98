# Tasks: m0-foundation

Each task maps to one or more requirements. Tasks are ordered so each one
builds on the last — no task requires a file that a later task creates.

A task is done when: the files it lists exist, `pnpm install` and `pnpm build`
still pass from the repo root, and all tests that can run at that point pass.

---

## TASK-01 Root config files

**Requirement**: REQ-01 (criteria 1–5, 9–10)

Create the five root config files that every other task depends on.

**Files to create**:

- `pnpm-workspace.yaml`
- `package.json` (root)
- `tsconfig.base.json`
- `vitest.workspace.ts`
- `.env.example` (empty, documents the pattern for future vars)

**`pnpm-workspace.yaml`**:
```yaml
packages:
  - 'apps/web'
  - 'packages/*'
```

**Root `package.json`** (key fields):
```jsonc
{
  "name": "exorcist-98",
  "private": true,
  "type": "module",
  "packageManager": "pnpm@9",
  "engines": { "node": ">=20" },
  "scripts": {
    "build":     "pnpm -r build",
    "test":      "vitest run",
    "typecheck": "pnpm -r typecheck"
  },
  "devDependencies": {
    "typescript":     "^5.4",
    "vitest":         "^1.6",
    "fast-check":     "^3.19",
    "zod":            "^3.23",
    "js-yaml":        "^4.1",
    "@types/js-yaml": "^4.0",
    "@types/node":    "^20",
    "tsx":            "^4.11"
  }
}
```

**`tsconfig.base.json`**:
```jsonc
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noEmit": true,
    "skipLibCheck": true,
    "esModuleInterop": true,
    "resolveJsonModule": true
  }
}
```

**`vitest.workspace.ts`**:
```ts
import { defineWorkspace } from 'vitest/config';

export default defineWorkspace([
  'packages/*/vitest.config.ts',
  'fixtures/haunted-repo/vitest.config.ts',
]);
```

**Done when**: `pnpm install` exits 0 from the repo root.

---

## TASK-02 Package skeletons

**Requirement**: REQ-01 (criteria 1–2, 4), REQ-01-10

Create the five package directories plus `apps/web`, each with a `package.json`,
`tsconfig.json`, and `vitest.config.ts`. Add a stub `src/index.ts` to each so
`tsc` has something to check.

**Packages and notable differences**:

| Package dir | `name` | `private` | Extra |
|-------------|--------|-----------|-------|
| `apps/web` | `@exorcist-98/web` | `true` | — |
| `packages/core` | `@exorcist-98/core` | `true` | — |
| `packages/shield` | `@exorcist-98/shield` | `true` | — |
| `packages/mcp-server` | `@exorcist-98/mcp-server` | `true` | — |
| `packages/cli` | `@exorcist-98/cli` | `false` | `"bin": {"exorcist": "./src/index.ts"}` |

Each `tsconfig.json`:
```jsonc
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "rootDir": "src",
    "outDir": "dist"
  },
  "include": ["src"]
}
```
(`apps/web` uses `"extends": "../../tsconfig.base.json"` with the same shape.)

Each `vitest.config.ts`:
```ts
import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: { globals: false },
});
```

Each `src/index.ts` stub:
```ts
// stub — populated in later milestones
export {};
```

`packages/cli/src/index.ts` stub:
```ts
#!/usr/bin/env node
// stub CLI — exits 0 until M3
process.exit(0);
```

**Done when**: `pnpm build` and `pnpm typecheck` exit 0 from the root.

---

## TASK-03 Placeholder directories and skeleton docs

**Requirement**: REQ-01 (criteria 6–8)

Create the directories that do not belong to any package but must exist before
later tasks write into them.

**Files to create**:

- `definitions/.gitkeep`
- `fixtures/.gitkeep` (parent; `haunted-repo/` is created in TASK-04)
- `power/.gitkeep`
- `docs/THREATS.md` with this content:

```markdown
# Threat catalogue

Generated from `definitions/*.yaml`. Updated automatically by the spec-change
hook when specs are edited.

| ID | Title | Severity | OWASP | File |
|----|-------|----------|-------|------|
```

**Done when**: all three directories and `docs/THREATS.md` exist on disk.

---

## TASK-04 Haunted Repo fixtures

**Requirement**: REQ-02

Create the `fixtures/haunted-repo/` directory, the twenty fixture files, the
index README, and the fixture test suite.

### Step 4-A: fixture files

Create all twenty files following the naming and defanging rules in design
section 7. For each file, the minimum content is:

1. The `<!-- DEFANGED -->` or `# DEFANGED` marker.
2. A comment identifying the threat ID and name.
3. The defanged payload representative of the threat (see design section 7,
   content table).

No fixture should contain:
- Any domain other than `example.invalid`, `localhost`, `127.0.0.1`, `0.0.0.0`.
- Any credential value other than `EXAMPLE_TOKEN_DO_NOT_USE`.
- Actual Unicode control characters for EX-001 (use `\uXXXX` in a comment).

### Step 4-B: fixture `README.md`

`fixtures/haunted-repo/README.md` must contain a table with columns:
`ID | File | Threat | Description`.

One row per fixture. Example row:
```
| EX-001 | EX-001-hidden-unicode.md | Hidden Unicode instructions | Markdown with zero-width and bidi-override characters described in comments. |
```

### Step 4-C: fixture `vitest.config.ts`

```ts
// fixtures/haunted-repo/vitest.config.ts
import { defineConfig } from 'vitest/config';
export default defineConfig({
  test: { globals: false },
});
```

### Step 4-D: property-based tests

Create `fixtures/haunted-repo/__tests__/fixtures.property.test.ts`.

The test file must import `fast-check` as `fc` and use `fc.assert` +
`fc.property`. Each PBT maps to one `it` block:

```ts
// PBT-FIX-01: no live domains
it('no fixture contains a live domain', () => {
  fc.assert(fc.property(fc.constantFrom(...fixtureFiles), (file) => {
    const text = fs.readFileSync(file, 'utf8');
    return !LIVE_DOMAIN_RE.test(text);
  }));
});
```

Where `LIVE_DOMAIN_RE` matches `https?://` followed by anything that is not
`example.invalid`, `localhost`, `127.0.0.1`, or `0.0.0.0`.

Implement all four PBTs: PBT-FIX-01, PBT-FIX-02, PBT-FIX-03, PBT-FIX-04.

**Done when**: `pnpm test` from the root runs the fixture tests and all four
PBTs pass.

---

## TASK-05 Virus definition schema and loader

**Requirement**: REQ-03

### Step 5-A: schema

Create `packages/core/src/definitions/schema.ts`.

Export `VirusDefinitionSchema` (Zod schema) and `VirusDefinition` (inferred
type). Implement the `match` refinement with `superRefine` to require at least
one of `regex`, `unicode_class`, or `json_path`.

```ts
import { z } from 'zod';

const MatchSchema = z.object({
  regex:         z.string().optional(),
  unicode_class: z.array(z.string()).optional(),
  json_path:     z.string().optional(),
}).superRefine((val, ctx) => {
  const hasAny = val.regex !== undefined
    || (val.unicode_class !== undefined && val.unicode_class.length > 0)
    || val.json_path !== undefined;
  if (!hasAny) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'match must contain at least one of: regex, unicode_class, json_path',
    });
  }
});

export const VirusDefinitionSchema = z.object({
  id:          z.string().regex(/^EX-\d{3}$/),
  title:       z.string().min(1),
  severity:    z.enum(['critical', 'high', 'medium', 'low']),
  applies_to:  z.array(z.string()).min(1),
  match:       MatchSchema,
  owasp:       z.array(z.string()).min(1),
  fix:         z.string().min(1),
  enabled:     z.boolean().optional().default(true),
});

export type VirusDefinition = z.infer<typeof VirusDefinitionSchema>;
```

### Step 5-B: `DefinitionLoadError`

Add to `packages/core/src/definitions/schema.ts` (or a sibling `errors.ts`):

```ts
import type { z } from 'zod';

export class DefinitionLoadError extends Error {
  constructor(
    public readonly file: string,
    public readonly issues: z.ZodIssue[],
  ) {
    super(`Invalid definition in ${file}: ${issues.map(i => i.message).join('; ')}`);
    this.name = 'DefinitionLoadError';
  }
}
```

### Step 5-C: loader

Create `packages/core/src/definitions/loader.ts`.

```ts
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import yaml from 'js-yaml';
import { VirusDefinitionSchema, DefinitionLoadError } from './schema.js';
import type { VirusDefinition } from './schema.js';

export async function loadDefinitions(dir: string): Promise<VirusDefinition[]> {
  const entries = await readdir(dir);
  const yamlFiles = entries.filter(f => f.endsWith('.yaml'));
  const results: VirusDefinition[] = [];
  for (const filename of yamlFiles) {
    const file = join(dir, filename);
    const raw = await readFile(file, 'utf8');
    const parsed = yaml.load(raw);
    const result = VirusDefinitionSchema.safeParse(parsed);
    if (!result.success) {
      throw new DefinitionLoadError(file, result.error.issues);
    }
    results.push(result.data);
  }
  return results;
}
```

### Step 5-D: unit tests

Create `packages/core/src/definitions/__tests__/loader.test.ts`.

Write three `it` blocks (using `vi.mocked` / temp dirs or inline fixtures) for
the three cases in REQ-03 acceptance criterion 4:
- Valid YAML → correct typed object returned.
- YAML missing `id` → `DefinitionLoadError` thrown.
- YAML with invalid severity → `DefinitionLoadError` thrown.

Use `import { tmpdir } from 'node:os'` and `import { mkdtemp, writeFile, rm }`
to create a temporary directory per test so tests are isolated and do not touch
the real `definitions/` folder.

### Step 5-E: property-based tests

Create `packages/core/src/definitions/__tests__/schema.property.test.ts`.

Implement PBT-DEF-01, PBT-DEF-02, PBT-DEF-03 using `fc.record`, `fc.string()`,
and `fc.constant`.

For PBT-DEF-01, generate a valid record:
```ts
const validRecord = fc.record({
  id:         fc.constantFrom('EX-001','EX-042','EX-999'),
  title:      fc.string({ minLength: 1 }),
  severity:   fc.constantFrom('critical','high','medium','low'),
  applies_to: fc.array(fc.string({ minLength: 1 }), { minLength: 1 }),
  match:      fc.record({ regex: fc.string({ minLength: 1 }) }),
  owasp:      fc.array(fc.string({ minLength: 1 }), { minLength: 1 }),
  fix:        fc.string({ minLength: 1 }),
});
```

**Done when**: `pnpm test` runs all loader and schema tests and they pass.

---

## TASK-06 First virus definition YAML

**Requirement**: REQ-03 (criterion 2)

Create `definitions/EX-001-hidden-unicode.yaml` with the content shown in design
section 6. Validate it passes `loadDefinitions` by adding a test case to
`loader.test.ts` that loads the real file.

**Done when**: the new test case passes and `pnpm test` exits 0.

---

## TASK-07 Secrets check script and property-based tests

**Requirement**: REQ-05-D (criteria 3–5)

### Step 7-A: `findSecrets` function and CLI

Create `packages/core/src/secrets-check.ts` with:

1. `findSecrets(text: string): SecretHit[]` — pure function, exported, described
   in design section 8.
2. CLI entry point: reads staged file paths when `--staged` is passed (via
   `execSync('git diff --name-only --cached')`), reads each file, calls
   `findSecrets`, prints hits, exits with the correct code.

The file uses `#!/usr/bin/env node` as its first line so it can be invoked
directly with `tsx`.

### Step 7-B: property-based tests

Create `packages/core/src/__tests__/secrets-check.property.test.ts`.

Implement PBT-SEC-01 through PBT-SEC-04. For PBT-SEC-01, build a string by
inserting a valid AWS key at a random position:

```ts
const awsKeyArb = fc.tuple(
  fc.string(),
  fc.stringOf(fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split('')), { minLength: 16, maxLength: 16 }),
  fc.string(),
).map(([prefix, keyBody, suffix]) => `${prefix}AKIA${keyBody}${suffix}`);
```

**Done when**: all four PBTs pass.

---

## TASK-08 Scaffolding validation test

**Requirement**: REQ-06

Create `packages/core/src/__tests__/scaffold.test.ts`.

The test resolves paths relative to `import.meta.url` walking up to the repo
root (four levels: `src/__tests__/` → `src/` → `packages/core/` → `packages/`
→ repo root). It uses `fs.existsSync` to check every path in REQ-01.

```ts
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../../../');

const required = [
  'pnpm-workspace.yaml',
  'tsconfig.base.json',
  'vitest.workspace.ts',
  'apps/web/package.json',
  'packages/core/package.json',
  'packages/shield/package.json',
  'packages/mcp-server/package.json',
  'packages/cli/package.json',
  'definitions',
  'fixtures/haunted-repo',
  'power',
  'docs/THREATS.md',
];

for (const rel of required) {
  it(`${rel} exists`, () => {
    expect(existsSync(resolve(root, rel))).toBe(true);
  });
}
```

**Done when**: all scaffold tests pass with `pnpm test`.

---

## TASK-09 Agent hooks

**Requirement**: REQ-05 (A–D)

Create the four hook files. Use the exact YAML shown in design section 9.

**Files to create**:
- `.kiro/hooks/definition-save.yaml`
- `.kiro/hooks/mcp-config-change.yaml` (with `enabled: false`)
- `.kiro/hooks/spec-change.yaml`
- `.kiro/hooks/pre-commit-secrets.yaml`

Verify each file is valid YAML by running:
```sh
node -e "import('js-yaml').then(({load})=>load(require('fs').readFileSync('.kiro/hooks/definition-save.yaml','utf8')))"
```
(or equivalent; just confirm no parse error).

**Done when**: all four files exist and are parseable YAML.

---

## TASK-10 CI workflow

**Requirement**: REQ-04

Create `.github/workflows/ci.yml`.

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 9
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
      - run: pnpm install --frozen-lockfile

  build:
    needs: install
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 9
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
      - run: pnpm install --frozen-lockfile
      - run: pnpm -r build

  test:
    needs: install
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 9
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
      - run: pnpm install --frozen-lockfile
      - run: pnpm test

  typecheck:
    needs: install
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
        with:
          version: 9
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'pnpm'
      - run: pnpm install --frozen-lockfile
      - run: pnpm -r typecheck
```

Note: each job re-runs `pnpm install --frozen-lockfile` after restoring from
the Node cache rather than passing artifacts between jobs, keeping the workflow
simple at the cost of a small redundancy. If build time becomes a concern in a
later milestone, switch to artifact upload/download.

**Done when**: the file exists and passes `yamllint` (or any YAML validator)
locally.

---

## TASK-11 Update `KIRO_LOG.md`

**Requirement**: REQ-07

Open `docs/KIRO_LOG.md` and add rows for:

| Date | Feature | What it did | Evidence |
|------|---------|-------------|----------|
| (today) | Specs | Generated m0-foundation spec (requirements, design, tasks) | `.kiro/specs/m0-foundation/` |
| (today) | Hooks | Created definition-save hook | `.kiro/hooks/definition-save.yaml` |
| (today) | Hooks | Created mcp-config-change hook (disabled) | `.kiro/hooks/mcp-config-change.yaml` |
| (today) | Hooks | Created spec-change hook | `.kiro/hooks/spec-change.yaml` |
| (today) | Hooks | Created pre-commit-secrets hook | `.kiro/hooks/pre-commit-secrets.yaml` |

Update the Counts section:
```
- Specs: 1
- Steering docs: 4
- Hooks: 4
```

**Done when**: the counts section has no blank values.

---

## Completion checklist

Run these from the repo root before declaring M0 done:

- [ ] `pnpm install` exits 0
- [ ] `pnpm build` exits 0
- [ ] `pnpm test` exits 0 (all 11 PBTs + unit tests pass)
- [ ] `pnpm typecheck` exits 0
- [ ] `ls fixtures/haunted-repo/EX-*.{md,json,yaml,env}` lists 20 files
- [ ] `ls .kiro/hooks/` lists 4 files
- [ ] `docs/KIRO_LOG.md` counts row shows `Specs: 1, Hooks: 4`
- [ ] No `.env` file is tracked by git (`git status` shows only `.env.example`)

---

## Task order summary

```
TASK-01  Root config
   ↓
TASK-02  Package skeletons
   ↓
TASK-03  Placeholder dirs + THREATS.md
   ↓
TASK-04  Haunted Repo fixtures        ← independent of TASK-05+
TASK-05  Schema + loader              ← independent of TASK-04
   ↓                                        ↓
TASK-06  First definition YAML   (needs TASK-05)
TASK-07  Secrets check           (needs TASK-02)
TASK-08  Scaffold test           (needs TASK-02 + TASK-03)
TASK-09  Hooks                   (independent)
TASK-10  CI workflow             (independent)
   ↓
TASK-11  KIRO_LOG.md             (last — after everything else)
```

TASK-04 and TASK-05 through TASK-08 can run in parallel once TASK-02 and
TASK-03 are done.
