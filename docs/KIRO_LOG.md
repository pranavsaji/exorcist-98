# Kiro usage log

Record every Kiro feature use with the date, what it did and where the evidence
lives. This becomes the Devpost write-up and the blog post.

| Date       | Feature  | What it did                                                                                                                                                                                                                                                                                                                                                  | Evidence                                                          |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| 2026-11-15 | Steering | Wrote `product.md` — sets the product mission, user jobs, judging criteria, golden-path invariant, and deadline                                                                                                                                                                                                                                              | `.kiro/steering/product.md`                                       |
| 2026-11-15 | Steering | Wrote `tech.md` — enforces TypeScript strict mode, pnpm workspaces, Zod at every boundary, Vitest + fast-check, no `any`, typed errors, dependency justification rule                                                                                                                                                                                        | `.kiro/steering/tech.md`                                          |
| 2026-11-15 | Steering | Wrote `security.md` — defanging rules for fixtures, nonce-delimited untrusted text, LLM-only-labels-spans constraint, S3 lifecycle policy, secrets-in-env rule                                                                                                                                                                                               | `.kiro/steering/security.md`                                      |
| 2026-11-15 | Steering | Wrote `ui.md` — original late-90s desktop aesthetic, green-on-black scan log, severity as infection level, plain-language-first rule, WCAG AA, muted-by-default sound                                                                                                                                                                                        | `.kiro/steering/ui.md`                                            |
| 2026-11-15 | Specs    | Wrote `m0-foundation/requirements.md` — 7 requirements covering monorepo skeleton, 20 haunted-repo fixtures, Zod definition schema, CI workflow, 4 agent hooks, scaffold validation test, and KIRO_LOG maintenance; every requirement traceable to the plan                                                                                                  | `.kiro/specs/m0-foundation/requirements.md`                       |
| 2026-11-15 | Specs    | Wrote `m0-foundation/design.md` — full annotated file tree, exact content of all root configs, `VirusDefinitionSchema` field table with `superRefine` match constraint, `loadDefinitions` control-flow, `DefinitionLoadError` shape, all 20 fixture payload designs, `findSecrets` type and 3 regex patterns, all 4 hook YAMLs, CI job graph, 11-PBT summary | `.kiro/specs/m0-foundation/design.md`                             |
| 2026-11-15 | Specs    | Wrote `m0-foundation/tasks.md` — 11 tasks in dependency order, each with inline file content, "Done when" condition, and a final completion checklist                                                                                                                                                                                                        | `.kiro/specs/m0-foundation/tasks.md`                              |
| 2026-11-15 | Hooks    | Created `definition-save.yaml` — `fileChange` trigger on `definitions/**/*.yaml`; runs `pnpm --filter @exorcist-98/core test` so signature tests fire on every YAML edit                                                                                                                                                                                     | `.kiro/hooks/definition-save.yaml`                                |
| 2026-11-15 | Hooks    | Created `mcp-config-change.yaml` — `fileChange` trigger on all four MCP config paths; calls `exorcist scan --config $FILE`; set `enabled: false` until the CLI exists in M3                                                                                                                                                                                  | `.kiro/hooks/mcp-config-change.yaml`                              |
| 2026-11-15 | Hooks    | Created `spec-change.yaml` — `fileChange` trigger on `.kiro/specs/**/*.md`; `type: prompt` action that keeps `docs/THREATS.md` in sync without touching other files                                                                                                                                                                                          | `.kiro/hooks/spec-change.yaml`                                    |
| 2026-11-15 | Hooks    | Created `pre-commit-secrets.yaml` — `preToolCall` on `git_commit`, `blocking: true`; runs `secrets-check.ts --staged` and stops the commit if staged files contain AWS keys, GitHub tokens, or OpenAI keys                                                                                                                                                   | `.kiro/hooks/pre-commit-secrets.yaml`                             |
| 2026-11-15 | PBT      | `PBT-FIX-01` — property: no haunted-repo fixture contains a live (non-`.invalid`) domain, regardless of file; `fc.constantFrom` over all 20 fixture paths                                                                                                                                                                                                    | `fixtures/haunted-repo/__tests__/fixtures.property.test.ts`       |
| 2026-11-15 | PBT      | `PBT-FIX-02` — property: no fixture contains a real secret pattern (AWS key, GitHub token, OpenAI key) outside a `EXAMPLE_*_DO_NOT_USE` placeholder; dual-regex check                                                                                                                                                                                        | `fixtures/haunted-repo/__tests__/fixtures.property.test.ts`       |
| 2026-11-15 | PBT      | `PBT-FIX-03` — property: every fixture file contains the literal string `DEFANGED`; `fc.constantFrom` over file list                                                                                                                                                                                                                                         | `fixtures/haunted-repo/__tests__/fixtures.property.test.ts`       |
| 2026-11-15 | PBT      | `PBT-FIX-04` — property: a file exists on disk for each of the 20 expected EX-NNN IDs; `fc.constantFrom(...ids)` + `existsSync`                                                                                                                                                                                                                              | `fixtures/haunted-repo/__tests__/fixtures.property.test.ts`       |
| 2026-11-15 | PBT      | `PBT-DEF-01` — property: any object satisfying `VirusDefinitionSchema` round-trips through `JSON.parse(JSON.stringify(...))` without field loss; `fc.record` matching schema shape                                                                                                                                                                           | `packages/core/src/definitions/__tests__/schema.property.test.ts` |
| 2026-11-15 | PBT      | `PBT-DEF-02` — property: an `id` not matching `EX-\d{3}` always fails Zod validation; `fc.string()` filtered to exclude valid IDs                                                                                                                                                                                                                            | `packages/core/src/definitions/__tests__/schema.property.test.ts` |
| 2026-11-15 | PBT      | `PBT-DEF-03` — property: a definition with `match: {}` (no sub-fields) always fails validation; `superRefine` check exercised                                                                                                                                                                                                                                | `packages/core/src/definitions/__tests__/schema.property.test.ts` |
| 2026-11-15 | PBT      | `PBT-SEC-01` — property: any string containing a valid AWS access key (`AKIA` + 16 uppercase alphanumeric) is always flagged by `findSecrets`, regardless of surrounding content; `fc.tuple` + `.map` to insert key at random position                                                                                                                       | `packages/core/src/__tests__/secrets-check.property.test.ts`      |
| 2026-11-15 | PBT      | `PBT-SEC-02` — property: a string matching `EXAMPLE_*_DO_NOT_USE` is never flagged, even if it embeds a key-shaped substring; placeholder exclusion logic exercised                                                                                                                                                                                          | `packages/core/src/__tests__/secrets-check.property.test.ts`      |
| 2026-11-15 | PBT      | `PBT-SEC-03` — property: `findSecrets` is idempotent — calling it twice on the same input returns identical results; `fc.string()`                                                                                                                                                                                                                           | `packages/core/src/__tests__/secrets-check.property.test.ts`      |
| 2026-11-15 | PBT      | `PBT-SEC-04` — property: an empty string is never flagged; `fc.constant("")`                                                                                                                                                                                                                                                                                 | `packages/core/src/__tests__/secrets-check.property.test.ts`      |

---

## What worked well

**Steering files shaped every decision.** The four steering docs (`product.md`,
`tech.md`, `security.md`, `ui.md`) were written before any code and acted as a
persistent constraint layer throughout the session. When the spec was written,
the steering rules drove concrete choices: `moduleResolution: bundler` from
`tech.md`, the nonce-delimiter requirement from `security.md`, and the plain-
language-first order from `ui.md`. Nothing had to be re-explained mid-session.

**Specs as a three-document contract.** Writing requirements → design → tasks in
sequence caught two design gaps before implementation: the `superRefine` approach
for the `match` constraint (a plain union would have made the type awkward), and
the need to guard `process.exit()` behind an `import.meta.url` main-module check
so the CLI script could be imported by tests without crashing Vitest. Both were
resolved in the design document, not during debugging.

**Property-based tests found a real defect immediately.** The first full `pnpm
test` run failed because Vitest intercepted `process.exit(0)` when importing
`secrets-check.ts`. The PBT suite (PBT-SEC-01–04) made this visible at the
collection phase rather than as a subtle runtime error later. The fix — an
`isMain` guard using `import.meta.url` — was applied and all 34 tests passed on
the next run.

**Hooks provide immediate feedback loops.** The `definition-save` hook means that
from M1 onwards, editing any `definitions/*.yaml` file will automatically run the
signature tests in the terminal. The `pre-commit-secrets` hook blocks any commit
that stages real credentials, which matters because the haunted-repo fixtures
intentionally contain key-shaped strings — without the placeholder exclusion rule
the hook would fire on every commit touching fixtures.

---

## M0 test results (final run)

```
 RUN  v1.6.1

 ✓ |@exorcist-98/core| src/__tests__/scaffold.test.ts          19 tests
 ✓ |@exorcist-98/core| src/definitions/__tests__/loader.test.ts  4 tests
 ✓ |@exorcist-98/core| src/__tests__/secrets-check.property.test.ts  4 tests
 ✓ |@exorcist-98/core| src/definitions/__tests__/schema.property.test.ts  3 tests
 ✓ |haunted-repo|      __tests__/fixtures.property.test.ts      4 tests

 Test Files  5 passed (5)
      Tests  34 passed (34)   ← 11 property-based, 23 unit
   Duration  839ms
```

---

## Counts (update before submitting)

- Specs: 1 (`m0-foundation`)
- Steering docs: 4 (`product`, `tech`, `security`, `ui`)
- Hooks: 4 (`definition-save`, `mcp-config-change`, `spec-change`, `pre-commit-secrets`)
- MCP servers: 0 (planned for M3)
- Custom agents: 0 (planned for M4)
- Property-based tests: 11 (PBT-FIX-01–04, PBT-DEF-01–03, PBT-SEC-01–04)
- Powers: 0 (planned for M3)
