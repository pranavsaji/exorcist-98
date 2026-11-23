# Tasks: m5-detonation

- [ ] 1. `packages/core/src/llm/detonation.ts`: sandbox prompt, fake tools, verdict logic; unit tests with a fake Bedrock client.
- [ ] 2. `exorcist scan --detonate` and `exorcist detonate <file>`; EX-024 definition.
- [ ] 3. `fixtures/detonation/` (defanged) and `scripts/detonation-eval.ts`; run it on real Bedrock only when the owner has credentials configured; otherwise leave the script and say so.
- [ ] 4. `pnpm test` passes for the whole repo.
