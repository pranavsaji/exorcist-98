---
inclusion: fileMatch
fileMatchPattern: [".kiro/hooks/**", ".kiro/agents/**", "scripts/kiro-hook.sh", "scripts/hook-*.ts", "packages/cli/src/commands/init.ts", "packages/cli/src/kiro-hook-script.ts", "packages/cli/src/kiro-agent.ts", "packages/core/src/hook-guard.ts"]
---

# Kiro hooks and agents in this repository

What running them inside Kiro taught us (docs/KIRO_LOG.md, L-003, S-015):

- Hooks are `.kiro/hooks/*.json`: `{"version": "v1", "hooks": [...]}` with PascalCase
  triggers (`PreToolUse`, `PostToolUse`, `PostFileSave`, `Stop`). The M0 hooks were invented
  YAML and never fired; check new fields against kiro.dev/docs/hooks first.
- Kiro runs hook commands with `PATH=/usr/bin:/bin:/usr/sbin:/sbin`. A command hook always
  goes through `scripts/kiro-hook.sh` (in user projects `.exorcist/kiro-hook.sh`); never call
  `node`, `npx` or `pnpm` directly. `scripts/kiro-hook.sh` and `KIRO_HOOK_SCRIPT` must stay
  identical (a test checks).
- Exit 2 from a `PreToolUse` hook blocks the tool, with stderr as the reason. Exit 1 and
  "command not found" block nothing.
- The commit guard fails closed: if Node cannot be found, a `git commit` is blocked. The read
  hook fails open on input it cannot understand (bad JSON, no path, missing file: exit 0), so it
  never bricks the agent, but a high or critical rule that times out blocks the read.
- A hook must not call a CLI command that its CLI version lacks: an unknown command exits 2,
  which a `PreToolUse` hook turns into a block of every matching tool. `exorcist init` writes
  the on-access hook disabled under the published `@exorcist-98/cli@0.1.0`, which predates it.
- The shell event is `{hook_event_name, cwd, tool_name, tool_input: {command, ...}}`; a file
  save carries `file_path`.
- Agents in `.kiro/agents/` are JSON in the documented format (kiro.dev/docs/custom-agents).
  The reviewer may list only read-only tools of the exorcist MCP server; tests check this
  against the server's own tool annotations.
