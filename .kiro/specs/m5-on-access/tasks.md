# Tasks: m5-on-access

- [x] 1. `extractReadPaths` + `decideRead` in core with unit tests and PBT-ACC-01..03.
- [x] 2. `exorcist on-access` and `exorcist allow-read` CLI commands, help text, CLI tests against the built bundle.
- [x] 3. `scripts/hook-on-access.ts` and `.kiro/hooks/on-access-scan.json`; a test checks the hook command's paths exist (like the existing hook-path test).
- [x] 4. `exorcist init` writes the on-access hook; its test updated.
- [x] 5. `pnpm test` passes for the whole repo.
