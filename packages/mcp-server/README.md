# @exorcist-98/mcp-server

An MCP server from [Exorcist 98](https://github.com/pranavsaji/exorcist-98),
an antivirus for AI coding agents. It lets your agent check a project before
trusting it.

Tools:

- `scan_repo`: scan a folder or file for attacks on AI agents (hidden
  instructions, poisoned tool descriptions, dangerous hooks, leaked secrets).
- `scan_mcp_config`: check an MCP config for risky servers.
- `explain_finding`: a plain-language explanation of a rule.
- `quarantine`: disable a server in an MCP config, with a backup to restore.

The tools only read inside the folder the server was started in, plus the
folders your client shares as MCP roots and the folders in `EXORCIST_ROOTS`
(separated like `PATH`). Relative paths, and `.`, start in the first folder the
client shares, else the first `EXORCIST_ROOTS` folder, else the start folder.
Some clients start the server in a folder that is not your project (Kiro does
this for a Power, in `~/.kiro/powers/installed/`). If the client shares no folder
and the start folder holds no project, the tools say so instead of reporting a
clean scan.

Kiro shares no roots but supports elicitation. When a tool gets an absolute path
outside every allowed folder, the server asks the person in a form ("Allow
Exorcist 98 to read this folder for this session?"). Yes adds the folder until the
server stops; no reads nothing. Only the form answer counts, never the agent. The
filesystem root, the home folder and the folders above it, `~/.ssh`, `~/.aws`,
`~/.gnupg` and similar credential folders, and system folders are refused without
asking. Without elicitation and roots, the fixes are `EXORCIST_ROOTS` in the
server's env, or adding the server to the workspace `.kiro/settings/mcp.json`,
where Kiro starts it in the project folder. Quoted text from scanned files is left
out of results unless you ask for it, and is then marked as untrusted.

## Use it

```json
{
  "mcpServers": {
    "exorcist": { "command": "npx", "args": ["-y", "@exorcist-98/mcp-server@0.2.0"] }
  }
}
```

Needs Node 20 or newer. Licence: Apache-2.0.
