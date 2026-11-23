# Tasks: m5-on-access

- [ ] 1. `extractReadPaths` + `decideRead` in core with unit tests and PBT-ACC-01..03.
- [ ] 2. `exorcist on-access` and `exorcist allow-read` CLI commands, help text, CLI tests against the built bundle.
- [ ] 3. `scripts/hook-on-access.ts` and `.kiro/hooks/on-access-scan.json`; a test checks the hook command's paths exist (like the existing hook-path test).
- [ ] 4. `exorcist init` writes the on-access hook; its test updated.
- [ ] 5. `pnpm test` passes for the whole repo.
