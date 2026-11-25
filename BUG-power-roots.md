# Bug: the exorcist Power scans its own folder, not the project, in Kiro

Seen on 2026-11-24 in Kiro 1.5.11: the Power `exorcist` was installed through the
Powers panel from https://github.com/pranavsaji/exorcist-98/tree/main/power, its
MCP server connected (4 tools), and "scan this repo for prompt injection" made the
agent call `scan_repo` with path `.`. The result was "No threats found in 5 files".

Cause found: Kiro starts the Power's MCP server (`npx -y @exorcist-98/mcp-server@0.1.2`)
with its working folder set to the Power's install folder
`~/.kiro/powers/installed/power` (mcp.json, plugin.json, skills/). The server
resolves relative paths against `process.cwd()` and only allows paths inside
cwd plus extra roots (`EXORCIST_ROOTS`, and MCP `roots/list` if the client
supports roots; see packages/mcp-server/src/index.ts and tools.ts). So the
project is out of reach.

Investigate, then fix:
1. Find out what Kiro gives the server: does it advertise the MCP `roots`
   capability and answer `roots/list` with the workspace folder? Check Kiro's
   MCP logs (Output panel, the MCP Logs channel) and/or log the client
   capabilities to stderr temporarily. Does Kiro's MCP config for Powers support
   a working-folder setting or variable substitution such as a workspace-folder
   placeholder in args, env or cwd? Check kiro.dev docs for MCP configuration and
   Powers before relying on any of these.
2. Make the server work in that situation without weakening the S-018 path
   confinement: when the client shares roots, resolve relative paths (and the
   default `.`) against the first client root instead of cwd, and allow paths
   inside any shared root. When the start folder is not a project and no root is
   known, the tool should say so plainly (and how to fix it) instead of scanning
   the wrong folder and reporting "No threats".
3. Update power/mcp.json and the Power skills if Kiro offers a supported way to
   pass the workspace, and the README / power docs.
4. Tests: roots shared by the client become the base for "."; a path outside every
   root is still refused; with no roots and a cwd that holds no project, the tool
   reports the problem instead of a clean result.
5. A row in docs/KIRO_LOG.md: the Power was installed through the Powers panel for
   the first time, the agent used it, and this bug was found and fixed by the Kiro
   IDE agent.

Run `pnpm -r typecheck` and `pnpm vitest run`. Do not commit or push.

## Findings from a probe MCP server run inside Kiro 1.5.11 (2026-11-25)

- `initialize` from Kiro (clientInfo kiro 0.66.123, protocol 2025-11-25)
  advertises only `elicitation` (form and url). No `roots` capability, and a
  `roots/list` request from the server gets "Method not found". So Kiro never
  shares the workspace as an MCP root.
- No workspace placeholder is substituted in MCP config: `${workspaceFolder}`,
  `${workspaceRoot}`, `${cwd}`, `${env:HOME}` arrive literally in args and env.
  No workspace environment variable is set; `PWD` points at some other folder.
- Servers from the workspace `.kiro/settings/mcp.json` start with the workspace
  as their working folder. Power servers start in the Power's install folder.

## Follow-up fix (do this next)

Because roots never arrive in Kiro, the Power is still unusable. Use Kiro's
elicitation support instead, without weakening S-018:
- `scan_repo`, `scan_mcp_config` and `quarantine` accept an absolute path. If it
  is outside the start folder and every known root, and the client supports
  elicitation, the server asks the person (an elicitation form): "Allow
  Exorcist 98 to read <path> for this session?" with a clear yes/no. On yes, that
  folder becomes a session root (resolve symlinks; refuse `/`, the home folder
  itself and sensitive folders such as `~/.ssh`, `~/.aws`, `~/.gnupg`); on no,
  nothing is read. The agent cannot approve it; only the elicitation answer
  counts. Remember approvals for the session only.
- Without elicitation and without roots, keep the clear "no project known"
  error, and mention both fixes: `EXORCIST_ROOTS`, or `exorcist init --kiro`,
  which adds the server to the workspace config where it starts in the project.
- The scan-repo skill tells the agent to pass the absolute workspace path.
- Tests for: approval adds the root and the scan runs; decline reads nothing;
  sensitive folders are refused even when approved; no elicitation keeps the
  error; the existing confinement tests still pass.
