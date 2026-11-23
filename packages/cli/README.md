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

## Map the haunted house

```sh
npx -y @exorcist-98/cli@0.1.0 map .
```

For every MCP config in the folder, lists which servers sit in the three rooms
of the "lethal trifecta": the Vault of Secrets (private data), the Open Door
(untrusted input) and the Escape Tunnel (a way out). A config that fills all
three is reported as EX-023 (critical when a tool on one of those servers is
auto-approved) and the command exits 1. `--format json` gives the same map as
data. The rules are in `definitions/capabilities.yaml`.

## Protect your MCP servers

```sh
npx -y @exorcist-98/cli@0.1.0 wrap .kiro/settings/mcp.json
```

`wrap` puts every server in the file, local or remote, behind the Real-Time
Shield. It pins each tool, hides a tool that changes (a rug pull), blocks
secrets and unknown hosts in tool calls, and withholds tool results that try to
instruct your agent. `unwrap` restores the file exactly. See
`exorcist shield --help`, `exorcist approve --help` and `exorcist alerts`.

## Share approved tools with your team: exorcist.lock

```sh
npx -y @exorcist-98/cli@0.1.0 lock           # write exorcist.lock, then commit it
npx -y @exorcist-98/cli@0.1.0 lock --check   # exit 1 if any tool or program changed
npx -y @exorcist-98/cli@0.1.0 lock --check --static   # starts nothing: names, programs, URLs only
```

`exorcist.lock` records the fingerprint of every tool your MCP servers list,
like a package lockfile for tool descriptions. Each teammate's Shield treats a
tool that differs from the lock as a rug pull, even on a machine that never
saw the tool before. The lock never approves anything by itself: a tool that
matches it still gets the Shield's first-use checks. `--from-shield` writes the lock from your local
pins without starting any server. In GitHub Actions, set `lock-check: true`.

`exorcist lock` and `lock --check` **start every server in the MCP config**
to list its tools. Only run them on a config you trust. On a pull request the
config is the author's: a changed `command` would run inside your CI with its
secrets and token. So the GitHub Action's `lock-check: true` always runs
`lock --check --static`, which starts nothing and compares the server names,
each server's program (command, arguments and argument files) and remote URLs
with the lock. `lock-check: live` also compares tool descriptions, and the
Action refuses it on `pull_request` and `pull_request_target` events and when
the head repository is a fork. Servers that `exorcist lock` does start get a
minimal environment (PATH, HOME, LANG, LC_*, TMPDIR) plus their own `env`
from the config, so tokens and keys in your shell are not passed on.

## Licence

Apache-2.0.
