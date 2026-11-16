# Kiro usage log

Record every Kiro feature use with the date, what it did and where the evidence
lives. This becomes the Devpost write-up and the blog post.

| Date       | Feature  | What it did                                                                                                                                                                                             | Evidence                                                                             |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| 2026-11-15 | Steering | Wrote `product.md` — product mission, user jobs, judging criteria, golden-path invariant, deadline                                                                                                      | `.kiro/steering/product.md`                                                          |
| 2026-11-15 | Steering | Wrote `tech.md` — TypeScript strict, pnpm workspaces, Zod at every boundary, Vitest + fast-check, no `any`, typed errors, dependency justification rule                                                 | `.kiro/steering/tech.md`                                                             |
| 2026-11-15 | Steering | Wrote `security.md` — defanging rules, nonce-delimited untrusted text, LLM-only-labels-spans constraint, S3 lifecycle policy, secrets-in-env rule                                                       | `.kiro/steering/security.md`                                                         |
| 2026-11-15 | Steering | Wrote `ui.md` — late-90s desktop aesthetic, green-on-black scan log, severity as infection level, plain-language-first, WCAG AA, muted-by-default sound                                                 | `.kiro/steering/ui.md`                                                               |
| 2026-11-15 | Specs    | Wrote `m0-foundation/requirements.md` — 7 requirements, 11 PBTs, monorepo skeleton, 20 fixtures, Zod schema, CI workflow, 4 hooks, scaffold test                                                        | `.kiro/specs/m0-foundation/requirements.md`                                          |
| 2026-11-15 | Specs    | Wrote `m0-foundation/design.md` — full file tree, root configs, `VirusDefinitionSchema` with `superRefine`, loader control-flow, all 20 fixture designs, `findSecrets` patterns, 4 hook YAMLs, CI graph | `.kiro/specs/m0-foundation/design.md`                                                |
| 2026-11-15 | Specs    | Wrote `m0-foundation/tasks.md` — 11 tasks in dependency order, inline file content, "Done when" conditions, completion checklist                                                                        | `.kiro/specs/m0-foundation/tasks.md`                                                 |
| 2026-11-15 | Hooks    | Created `definition-save.yaml` — `fileChange` on `definitions/**/*.yaml`; runs core tests on every YAML edit                                                                                            | `.kiro/hooks/definition-save.yaml`                                                   |
| 2026-11-15 | Hooks    | Created `mcp-config-change.yaml` — `fileChange` on all 4 MCP config paths; calls `exorcist scan --config $FILE`; `enabled: false` until M3                                                              | `.kiro/hooks/mcp-config-change.yaml`                                                 |
| 2026-11-15 | Hooks    | Created `spec-change.yaml` — `fileChange` on `.kiro/specs/**/*.md`; prompt-based, keeps `docs/THREATS.md` in sync                                                                                       | `.kiro/hooks/spec-change.yaml`                                                       |
| 2026-11-15 | Hooks    | Created `pre-commit-secrets.yaml` — `preToolCall` on `git_commit`, `blocking: true`; stops commits staging AWS keys, GitHub tokens, or OpenAI keys                                                      | `.kiro/hooks/pre-commit-secrets.yaml`                                                |
| 2026-11-15 | PBT      | PBT-FIX-01..04 — fixture safety: no live domains, no unwrapped secrets, DEFANGED marker present, all 20 IDs exist on disk                                                                               | `fixtures/haunted-repo/__tests__/fixtures.property.test.ts`                          |
| 2026-11-15 | PBT      | PBT-DEF-01..03 — schema validation: round-trip JSON, bad `id` always fails, empty `match` always fails                                                                                                  | `packages/core/src/definitions/__tests__/schema.property.test.ts`                    |
| 2026-11-15 | PBT      | PBT-SEC-01..04 — secrets check: AWS key always flagged, placeholder never flagged, idempotent, empty string safe                                                                                        | `packages/core/src/__tests__/secrets-check.property.test.ts`                         |
| 2026-11-19 | Specs    | Wrote `m1-engine/requirements.md` — 9 requirements, 19 PBTs, walker/normalizer/signature/heuristic/orchestrator/reporters/Lambda                                                                        | `.kiro/specs/m1-engine/requirements.md`                                              |
| 2026-11-19 | Specs    | Wrote `m1-engine/design.md` — full module layout, classification table, Unicode ranges, base64 filter, regex cache, Bedrock prompt structure with nonce delimiters, SARIF level mapping                 | `.kiro/specs/m1-engine/design.md`                                                    |
| 2026-11-19 | Specs    | Wrote `m1-engine/tasks.md` — 12 tasks in dependency order, each with implementation notes and "Done when" conditions                                                                                    | `.kiro/specs/m1-engine/tasks.md`                                                     |
| 2026-11-19 | PBT      | PBT-WLK-01..04 — walker: size limit enforced, skip dirs respected, `classifyFile` is pure, all `FileRole` values are non-empty strings                                                                  | `packages/core/src/__tests__/walker.property.test.ts`                                |
| 2026-11-19 | PBT      | PBT-NRM-01..04 — normalizer: idempotent on `plain`, hidden Unicode always detected, clean ASCII produces no hits, base64 candidates ≥32 chars                                                           | `packages/core/src/__tests__/normalizer.property.test.ts`                            |
| 2026-11-19 | PBT      | PBT-SIG-01..04 — signature engine: no false positives on non-matching rule, idempotent across runs, disabled rule never fires, span ≤120 chars                                                          | `packages/core/src/__tests__/signature-engine.property.test.ts`                      |
| 2026-11-19 | PBT      | PBT-HEU-01..04 — heuristic engine: unverifiable `quoted_span` dropped, `benign` verdict suppressed, nonce unique per call, bad JSON never throws                                                        | `packages/core/src/__tests__/heuristic-engine.property.test.ts`                      |
| 2026-11-19 | PBT      | PBT-ORC-01..03 — orchestrator: idempotent across two sequential scans, no file mutation, `done` is always last event                                                                                    | `packages/core/src/__tests__/orchestrator.test.ts`                                   |
| 2026-11-19 | MCP      | Amazon Bedrock wired: Claude Haiku for triage, Sonnet for judge; all tests use `FakeBedrockClient`; real client reads `AWS_REGION` at call time, never at module load                                   | `packages/core/src/llm/bedrock.ts`, `packages/core/src/llm/__tests__/fake-client.ts` |

---

## What worked well

**Steering files shaped every decision.** The four steering docs were written before any code and acted as a persistent constraint layer. `moduleResolution: bundler` from `tech.md`, the nonce-delimiter requirement from `security.md`, and the plain-language-first rule from `ui.md` were applied directly in the design documents without re-explanation.

**Specs as a three-document contract.** Writing requirements → design → tasks caught problems before implementation in both milestones. In M0: the `superRefine` approach for the `match` constraint and the `process.exit` guard. In M1: the `import.meta.url`-based `isMain` guard pattern was already established, the `jsonpath-plus` `||` filter limitation was caught during definition authoring (not at runtime), and the five-level vs. four-level `../` path depth was caught by the first test run rather than CI.

**Property-based tests found real defects immediately.** In M0, PBT-SEC-01 caught the `process.exit` crash on import. In M1, a unit test for the 120-char span cap exposed a regex-cache collision (two tests reused one `ruleId` with different patterns). Both were small fixes that the tests located precisely.

**`FakeBedrockClient` enables full heuristic engine coverage without AWS.** All four PBT-HEU properties — including nonce uniqueness across 20 calls — run in under 400ms with no network. The concrete Bedrock client is never touched in CI.

**Hooks.** The four hooks exist and are committed. No hook firing has been captured as evidence yet; record a clip before submission.

---

## M1 test results (final run)

```
 RUN  v1.6.1

 ✓ |@exorcist-98/core| src/__tests__/signature-engine.test.ts       8 tests
 ✓ |@exorcist-98/core| src/__tests__/heuristic-engine.test.ts       4 tests
 ✓ |@exorcist-98/core| src/definitions/__tests__/loader.test.ts     4 tests
 ✓ |@exorcist-98/core| src/__tests__/signature-engine.property.test.ts  4 tests
 ✓ |@exorcist-98/core| src/definitions/__tests__/schema.property.test.ts  3 tests
 ✓ |@exorcist-98/core| src/__tests__/heuristic-engine.property.test.ts  4 tests
 ✓ |@exorcist-98/core| src/__tests__/normalizer.test.ts            15 tests
 ✓ |@exorcist-98/core| src/__tests__/handler.test.ts                5 tests
 ✓ |@exorcist-98/core| src/__tests__/walker.test.ts                21 tests
 ✓ |@exorcist-98/core| src/__tests__/reporters.test.ts              8 tests
 ✓ |@exorcist-98/core| src/__tests__/walker.property.test.ts        4 tests
 ✓ |@exorcist-98/core| src/__tests__/secrets-check.property.test.ts  4 tests
 ✓ |@exorcist-98/core| src/__tests__/orchestrator.test.ts           5 tests
 ✓ |@exorcist-98/core| src/__tests__/scaffold.test.ts              19 tests
 ✓ |@exorcist-98/core| src/__tests__/normalizer.property.test.ts    4 tests
 ✓ |@exorcist-98/core| src/__tests__/definitions-integration.test.ts  12 tests
 ✓ |haunted-repo|      __tests__/fixtures.property.test.ts          4 tests

 Test Files  17 passed (17)
      Tests  128 passed (128)   ← 27 property-based, 101 unit/integration
   Duration  26.38s
```

---

## Counts (update before submitting)

- Specs: 2 (`m0-foundation`, `m1-engine`)
- Steering docs: 4 (`product`, `tech`, `security`, `ui`)
- Hooks: 4 (`definition-save`, `mcp-config-change`, `spec-change`, `pre-commit-secrets`)
- MCP servers: 0 (planned for M3)
- Custom agents: 0 (planned for M4)
- Property-based tests: 27 (PBT-FIX-01..04, PBT-DEF-01..03, PBT-SEC-01..04, PBT-WLK-01..04, PBT-NRM-01..04, PBT-SIG-01..04, PBT-HEU-01..04)
- Powers: 0 (planned for M3)
