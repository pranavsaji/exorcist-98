# Tasks: m5-ouija

- [x] 1. `packages/core/src/ouija.ts` with `decodeHidden`, exported from index and browser entries. Done when PBT-OUI-01..03 pass (`packages/core/src/__tests__/ouija.property.test.ts`, fast-check).
- [x] 2. `decoded` on EX-001 tag-block findings (core Finding type, signature engine, web protocol + toWebFinding). Done when a test scanning the existing EX-001 Haunted Repo sample shows a non-empty `decoded`.
- [x] 3. EX-021 definition YAML + engine support + fixture `EX-021-smuggled-bytes.md`; ordinary emoji (one FE0F) never fires. Done when definitions-integration and fixture tests pass with the new id.
- [ ] 4. Web `OuijaPanel` in FindingDetail; CLI pretty output line. Done when `pnpm --filter @exorcist-98/web typecheck` passes and a CLI test asserts the line.
- [ ] 5. `pnpm test` passes for the whole repo.
