---
name: quarantine
description: Disable an infected MCP server, hook or steering file, keep a backup and a diff, and restore it later.
---

# Quarantine and restore

Use this after a scan or a shield alert shows that an MCP server, a hook or a steering file is dangerous.

## Steps

1. Tell the user what you found and ask before disabling anything. This changes their configuration.
2. For an MCP server, call the `quarantine` tool with the config path and the server name. It sets `disabled: true` for that one server and keeps a backup. For a hook or steering file, tell the user to run `exorcist vault quarantine-file <path>`.
3. Give the user the vault entry id and the restore command: `exorcist vault restore <id>`.
4. To show what changed since the backup: `exorcist vault diff <id>`.

## Rules

- Quarantine one thing at a time, and name it.
- Restoring puts the original back exactly. Do it only when the user asks.
- If the same server is already in the vault, say so instead of retrying.
