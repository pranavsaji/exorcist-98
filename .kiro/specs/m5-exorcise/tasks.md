# Tasks: m5-exorcise

- [x] 1. `packages/core/src/exorcise.ts`: pure fixers per rule returning new text + list of changes; PBT-EXO-01..02.
- [x] 2. `exorcist exorcise` CLI (dry run diff, --write with vault backup, --only); PBT-EXO-03 against a temp copy of the Haunted Repo.
- [x] 3. Web: server builds the patch during a scan (new `patch` event at the end of the NDJSON stream, capped at 1 MB) and the results window offers the download. e2e step added.
- [x] 4. `pnpm test` passes for the whole repo.
