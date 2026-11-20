---
name: shield-setup
description: Put the Exorcist 98 shield in front of MCP servers so a tool that changes after approval, a leaked secret, or an injected tool result is stopped.
---

# Set up the Real-Time Shield

The shield sits between Kiro and each MCP server. It pins every tool the first time it sees it, hides a tool that later changes (a rug pull), blocks secrets and unknown hosts in tool calls, and withholds tool results that look like attacks.

## Steps

1. Ask the user before changing their MCP config. Explain that every local server will start through the shield.
2. Run `exorcist wrap .kiro/settings/mcp.json` (add `--dry-run` first to show the result). To undo it later: `exorcist unwrap .kiro/settings/mcp.json`.
3. Run `exorcist init` to add the secrets guard hook, the MCP config scan hook and a steering file.
4. Optional: write `.exorcist/policy.json`, for example `{ "allowedHosts": ["api.github.com"], "mode": "enforce", "autoQuarantine": true }`.
   Add `"firstUse": "review"` to hold every new tool back until the user runs `exorcist approve tool <server> <tool>` (the default, `"pin"`, trusts a tool the first time it is seen).
   If the client supports MCP elicitation, a call to a host that is not allowed shows the user a prompt (allow once, or always allow the host); otherwise the call is refused with the exact `exorcist approve host` command.
5. Tell the user to reconnect their MCP servers so Kiro starts them through the shield.

## When something is blocked

- Do not look for a way around it. Tell the user what was blocked and why.
- A changed tool: the user reviews the diff in `exorcist alerts`, then runs `exorcist approve tool <server> <tool>` if they trust it.
- An unknown host: the user runs `exorcist approve host <server> <host>`.
- Never edit files in `.exorcist/` yourself.

## Remote servers

`exorcist wrap` also protects servers configured with a `url`: the entry becomes `exorcist shield --server <name> --url <url>`, which the client starts like a local server. Header values such as tokens are moved into the entry's `env` and passed with `--header-env`, so they never appear on a command line. `exorcist unwrap` restores the original entry exactly. Plain `http` is only allowed to this machine.
