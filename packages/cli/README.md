# @exorcist-98/cli

The command line for [Exorcist 98](https://github.com/pranavsaji/exorcist-98):
an antivirus for AI coding agents. It scans the files an agent reads (READMEs,
steering files, MCP configs, hooks) for attacks such as hidden instructions and
poisoned tool descriptions, and runs MCP servers behind a firewall that hides a
tool the moment it changes after you approved it.

Needs Node 20 or newer.

## Scan a project

```sh
npx -y @exorcist-98/cli@0.1.0 scan .
```

Every finding shows the file, line, the exact text, how serious it is and how
to fix it. Other formats: `--format json|sarif|markdown|badge`. The command
exits 1 when it finds something at or above `--fail-on` (default `high`), so it
works in CI.

Add `--ai` to also ask an AI judge (Claude on Amazon Bedrock) about suspicious
text. It needs AWS credentials, `AWS_REGION` and
`npm install @aws-sdk/client-bedrock-runtime`; `--ai-max-calls` caps the cost.

## Protect your MCP servers

```sh
npx -y @exorcist-98/cli@0.1.0 wrap .kiro/settings/mcp.json
```

`wrap` puts every server in the file, local or remote, behind the Real-Time
Shield. It pins each tool, hides a tool that changes (a rug pull), blocks
secrets and unknown hosts in tool calls, and withholds tool results that try to
instruct your agent. `unwrap` restores the file exactly. See
`exorcist shield --help`, `exorcist approve --help` and `exorcist alerts`.

## Licence

Apache-2.0.
