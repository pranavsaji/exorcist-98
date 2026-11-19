# Tasks: m3-shield

- [x] TASK-00 Fix hooks (real Kiro format) and the secrets guard (L-001, L-002, L-003). Done before this spec.
- [x] TASK-01 Core: `scanText`, `tool-result` role, exports, plain text moved to `@exorcist-98/core/plain`, EX-015, Markdown reporter, core dependencies. (REQ-01)
- [x] TASK-02 Shield pure modules: hash, jsonrpc, state, policy, inspect, engine, with PBT-SHD-01 to 06. (REQ-02 to REQ-05, REQ-07)
- [x] TASK-03 Vault and wrap with PBT-VLT-01 and 02. (REQ-08)
- [x] TASK-04 Proxy runtime and a fake MCP server; golden-path integration test. (REQ-06, REQ-12)
- [x] TASK-05 CLI commands, bundle build, exit-code tests. (REQ-09)
- [~] TASK-06 MCP server with SDK-client tests. Done. **`.kiro/settings/mcp.json` was not created: the write was blocked by a permission rule.** (REQ-10, part of REQ-11)
- [x] TASK-07 Power, `init`, GitHub Action, parse tests. (REQ-11)
- [x] TASK-08 Docs, full verification, commit. (REQ-13, REQ-14)

## Changes made while building (not in the original design)

- `exorcist hook-scan` and `guard-commit` were added: Kiro hook commands receive the event as JSON on stdin (the saved file is `file_path`), so a helper must read it.
- The command-line entry of the secrets check moved to `secrets-check-cli.ts`. An `isMain` check inside library code runs the wrong code once the CLI is bundled.
- `scan` and the Shield refuse to run with no definitions (a scan with none would report "clean").
- EX-002 was narrowed to injection-specific phrases, and EX-003 skips lockfile integrity hashes and data URIs, after dogfooding and false-positive review.
- `scripts/demo-rug-pull.mjs` plays the golden path without Kiro.

## Not verified here

Running inside Kiro (Shield, MCP server, Power), publishing to npm, and the GitHub Action on GitHub. See `docs/KNOWN_LIMITATIONS.md` section 7.
