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
folders your client shares as MCP roots. Quoted text from scanned files is left
out of results unless you ask for it, and is then marked as untrusted.

## Use it

```json
{
  "mcpServers": {
    "exorcist": { "command": "npx", "args": ["-y", "@exorcist-98/mcp-server@0.1.0"] }
  }
}
```

Needs Node 20 or newer. Licence: Apache-2.0.
