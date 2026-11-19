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
| 2026-11-19 | Test | Orchestrator unit tests (not property-based): `done` is always the last event, no file mtime changes after a scan, scan completes on an empty repo. The planned idempotence property is not written yet. | `packages/core/src/__tests__/orchestrator.test.ts` |
| 2026-11-19 | PBT | PBT-SIG-05..08 - EX-001 detects a zero-width char at any position; EX-010 never flags pinned packages and always flags unpinned ones; EX-007 never flags read-only tools | `packages/core/src/__tests__/definitions-accuracy.test.ts` |
| 2026-11-19 | Specs | Added REQ-10 and TASK-13 to `m1-engine` (detection accuracy fixes) instead of a new spec, keeping one spec per milestone | `.kiro/specs/m1-engine/` |
| 2026-11-20 | Specs | Wrote `m2-ui` spec (requirements, design, tasks): streaming scan API, desktop shell, scan/results/detail windows, Threat Encyclopedia | `.kiro/specs/m2-ui/` |
| 2026-11-20 | PBT | PBT-WEB-01..05 (8 properties): NDJSON parsing under any byte chunking; hidden characters always revealed; snippet reconstructs the line; GitHub URL validator accepts only owner/repo and rejects every suffix and host; severity sort order | `apps/web/src/__tests__/` |
| 2026-11-20 | Test | Golden-path integration test: `POST /api/scan` on the Haunted Repo streams findings for all 12 shipped rules with snippets. It found a real bug: EX-009 never fired in a real scan because the walker classes the fixture as `config`, not `manifest`. | `apps/web/src/__tests__/route.test.ts` |
| 2026-11-20 | Test | A real run against a public GitHub repo exposed a broken clone (simple-git refuses to run with GIT_PAGER set). Fixed by giving git an allowlisted environment, with a test. | `apps/web/src/lib/scan-service.ts` |
| 2026-11-20 | Test | Real-browser test (`pnpm e2e`, Chrome 157 via playwright-core, axe-core): 20 steps and 0 accessibility violations. It found four real defects that unit tests missed: a stale form error, one EX-001 finding per hidden character (72 findings, now 36), two findings with no highlight, and windows running off a 390px screen. | `scripts/e2e-chrome.mjs` |
| 2026-11-20 | PBT | PBT-SIG-09: the number of EX-001 findings equals the number of runs of adjacent hidden characters, for any placement | `packages/core/src/__tests__/definitions-accuracy.test.ts` |
| 2026-11-20 | Specs | Wrote `m3-shield` (requirements, design, tasks): Shield, Vault, CLI, MCP server, Power, Action. Records the design decisions (one proxy per server, shared state folder, fail closed, no interactive prompt) | `.kiro/specs/m3-shield/` |
| 2026-11-20 | Hooks | **First real firing evidence.** The `spec-change` hook fired inside Kiro three times when the m3-shield spec files were saved (a `PostFileSave` event with `file_path`), and the agent updated only `docs/THREATS.md`. This only worked after the hooks were rewritten from invented YAML into the documented `.kiro/hooks/*.json` v1 format (checked against kiro.dev/docs/hooks). | `.kiro/hooks/*.json`, `docs/THREATS.md` |
| 2026-11-20 | Hooks | Added `exorcist hook-scan` and `guard-commit`, the helpers the hooks call. They read the Kiro event from stdin (`file_path` was seen in a real event). `pre-commit-secrets` now actually blocks: tested as a real process (exit 2, reason on stderr). | `packages/cli/src/commands/`, `packages/core/src/hook-guard.ts` |
| 2026-11-20 | PBT | PBT-SHD-01..06 and PBT-VLT-01..02: fingerprint ignores key order and changes on any edit; a secret at any depth is never forwarded; a changed tool is never listed or callable; pin store round-trips; stdio framing survives any byte split; an injection phrase in a result (any case or spacing) is never forwarded; quarantine then restore returns the exact bytes; wrap then unwrap returns the exact config. Plus a core property for injection phrases. 10 `fc.assert` properties. | `packages/shield/src/__tests__/`, `packages/core/src/__tests__/scan-text.test.ts` |
| 2026-11-20 | Test | **Golden path with real processes:** a benign tool is pinned and works; the fake server then changes the tool description; the agent no longer sees the tool, cannot call it, and the real backend's call log proves it never heard about the call; the alert carries a unified diff; auto-quarantine disables the server and restore returns the config byte for byte. Repeated through the real `exorcist shield` command and by `scripts/demo-rug-pull.mjs`. | `packages/shield/src/__tests__/proxy.integration.test.ts`, `packages/cli/src/__tests__/cli.test.ts` |
| 2026-11-20 | Test | **Mutation check:** I deliberately broke two protections (treat a changed hash as unchanged; never block secrets). The suite failed 11 and 5 tests, then passed 77/77 once restored. | n/a (one-off run) |
| 2026-11-20 | MCP | Built the `exorcist` MCP server on the official SDK (`scan_repo`, `scan_mcp_config`, `explain_finding`, `quarantine`), tested with the SDK's own client over real stdio. Its output deliberately leaves out quoted file text, so it cannot become an injection channel and passes through the Shield. **Not yet registered in Kiro**: writing `.kiro/settings/mcp.json` was blocked by a permission rule. | `packages/mcp-server/` |
| 2026-11-20 | Powers | Built the `exorcist` Power in the documented Agent Plugins layout (`plugin.json`, `mcp.json`, three skills). **Never installed in Kiro; the npm package it points at is not published.** | `power/` |
| 2026-11-20 | CLI | `exorcist scan | shield | wrap | unwrap | vault | approve | alerts | init | guard-commit | hook-scan`, bundled with esbuild into one file; tests run the built artifact. | `packages/cli/` |
| 2026-11-20 | CLI | GitHub Action (composite) and a workflow that scans this repo with it. The build and scan steps were rehearsed on a clean copy; the Action has not run on GitHub. | `action.yml`, `.github/workflows/exorcist.yml` |
| 2026-11-19 | Model      | Amazon Bedrock wired (not an MCP server): Claude Haiku for triage, Sonnet for judge; all tests use `FakeBedrockClient`; real client reads `AWS_REGION` at call time, never at module load                                   | `packages/core/src/llm/bedrock.ts`, `packages/core/src/llm/__tests__/fake-client.ts` |

---

## What worked well

**Steering files shaped every decision.** The four steering docs were written before any code and acted as a persistent constraint layer. `moduleResolution: bundler` from `tech.md`, the nonce-delimiter requirement from `security.md`, and the plain-language-first rule from `ui.md` were applied directly in the design documents without re-explanation.

**Specs as a three-document contract.** Writing requirements → design → tasks caught problems before implementation in both milestones. In M0: the `superRefine` approach for the `match` constraint and the `process.exit` guard. In M1: the `import.meta.url`-based `isMain` guard pattern was already established, the `jsonpath-plus` `||` filter limitation was caught during definition authoring (not at runtime), and the five-level vs. four-level `../` path depth was caught by the first test run rather than CI.

**Property-based tests found real defects immediately.** In M0, PBT-SEC-01 caught the `process.exit` crash on import. In M1, a unit test for the 120-char span cap exposed a regex-cache collision (two tests reused one `ruleId` with different patterns). Both were small fixes that the tests located precisely.

**`FakeBedrockClient` enables full heuristic engine coverage without AWS.** All four PBT-HEU properties — including nonce uniqueness across 20 calls — run in under 400ms with no network. The concrete Bedrock client is never touched in CI.

**Hooks.** The four hooks exist and are committed. No hook firing has been captured as evidence yet; record a clip before submission.

**M3: problems found by running things.** Four real defects surfaced by running the code, not by reading it. (1) The `isMain` guard I added to `secrets-check.ts` in M0 broke the moment the CLI was bundled: the bundle itself became the main module, so the library's CLI branch ran and tried to read `--version` as a filename. Library code no longer contains an entry point. (2) A scan with an empty definitions folder reported "no threats" and exited 0; the CLI and the Shield now refuse to run without definitions. (3) EX-003 flagged the integrity hashes in `pnpm-lock.yaml`, which would have failed this repo's own CI scan on every pull request (found by scanning the repo with its own scanner). (4) The `mcp-config-change` hook scanned a folder that does not exist and the wrong file for `.cursor/mcp.json`; a test that checks hook commands against real paths caught it, and the real hook event carries `file_path`, so it now scans exactly the saved file. Separately, I tightened EX-002 after reasoning (not testing) that it would withhold ordinary tool output such as "You are now logged in"; tests now pin that. One more failure was my own wrong test expectation (quotes of hidden characters are already escape text), not a code bug.

**Hooks finally fired.** The M0 hooks were written from memory in an invented YAML format and never ran. Fetching the real documentation showed the format was JSON with PascalCase triggers. After the rewrite, the `spec-change` hook fired in Kiro the first time a spec file was saved, which is the evidence the earlier log entries lacked.

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
      Tests  128 passed (128)   ← 27 property-based, 101 unit/integration (before the accuracy fixes; 146 total after)
   Duration  26.38s
```

---

## Counts (update before submitting)

- Specs: 4 (`m0-foundation`, `m1-engine`, `m2-ui`, `m3-shield`)
- Steering docs: 4 (`product`, `tech`, `security`, `ui`)
- Hooks: 4 in Kiro's JSON format (`definition-save`, `mcp-config-change`, `spec-change`, `pre-commit-secrets`); 1 seen firing (`spec-change`)
- MCP servers: 1 built and tested (`exorcist`); not yet registered in Kiro (the config write was blocked)
- Custom agents: 0 (planned for M4)
- Property-based tests: 49 `fc.assert` properties (core 28, fixtures 4, shield 9, web 8). PBT-HEU-03 is a loop, not a fast-check property, and is not counted.
- Tests passing: 392 in 34 files (last full run), plus 20 browser steps in `pnpm e2e` (0 accessibility violations)
- Powers: 1 built (`exorcist`); not installed in Kiro, npm packages not published
