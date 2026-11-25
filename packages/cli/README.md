# @exorcist-98/cli

The command line for [Exorcist 98](https://github.com/pranavsaji/exorcist-98):
an antivirus for AI coding agents. It scans the files an agent reads (READMEs,
steering files, MCP configs, hooks) for attacks such as hidden instructions and
poisoned tool descriptions, and runs MCP servers behind a firewall that hides a
tool the moment it changes after you approved it.

Needs Node 20 or newer.

## Scan a project

```sh
npx -y @exorcist-98/cli@0.1.3 scan .
```

Every finding shows the file, line, the exact text, how serious it is and how
to fix it. Other formats: `--format json|sarif|markdown|badge`. The command
exits 1 when it finds something at or above `--fail-on` (default `high`), so it
works in CI.

Add `--ai` to also ask an AI judge (Claude on Amazon Bedrock) about suspicious
text. It needs AWS credentials, `AWS_REGION` and
`npm install @aws-sdk/client-bedrock-runtime`; `--ai-max-calls` caps the cost.

## Adopt on an existing repo
```sh
exorcist baseline .                                  # writes .exorcist-baseline.json
exorcist scan . --baseline .exorcist-baseline.json   # reports new findings only
```
The baseline keeps a fingerprint of each finding, not its text. To silence one
rule on one line, write `exorcist-ignore EX-012: reason` in a comment on that
line or the line before (a reason is required; hidden characters, EX-001, and
secrets, EX-011, can never be silenced this way). Suppressions are listed in the
summary, and SARIF output marks them with `suppressions`. If the definitions are
more than 30 days old, `scan` prints one warning on stderr; it makes no network
request.

## Map the haunted house

```sh
npx -y @exorcist-98/cli@0.1.3 map .
```

For every MCP config in the folder, lists which servers sit in the three rooms
of the "lethal trifecta": the Vault of Secrets (private data), the Open Door
(untrusted input) and the Escape Tunnel (a way out). A config that fills all
three is reported as EX-023 (critical when a tool on one of those servers is
auto-approved) and the command exits 1. `--format json` gives the same map as
data. The rules are in `definitions/capabilities.yaml`.

## Disinfect (exorcise)

```sh
npx -y @exorcist-98/cli@0.1.3 exorcise .           # dry run: prints a unified diff
npx -y @exorcist-98/cli@0.1.3 exorcise . --write   # apply, with a vault backup first
```

Only threats with one safe, mechanical fix are repaired: hidden characters
(EX-001), runs of four or more variation selectors (EX-021), smuggled HTML comments (EX-002, EX-004), data-carrying remote images
(EX-012) and unpinned `npx`/`uvx` MCP servers (EX-010, pinned to the current
version on npm or PyPI; `--offline` skips the lookup). Everything else is
reported, never edited. `--only EX-001,EX-010` limits the fixes. After
`--write` the changed files are scanned again ("12 threats removed, 2 need a
human"), and `exorcist vault restore <id>` puts every file back byte for byte.

## Protect your MCP servers

```sh
npx -y @exorcist-98/cli@0.1.3 wrap .kiro/settings/mcp.json
```

`wrap` puts every server in the file, local or remote, behind the Real-Time
Shield. It pins each tool, hides a tool that changes (a rug pull), blocks
secrets and unknown hosts in tool calls, and withholds tool results that try to
instruct your agent. `unwrap` restores the file exactly. See
`exorcist shield --help`, `exorcist approve --help` and `exorcist alerts`.

## Share approved tools with your team: exorcist.lock

```sh
npx -y @exorcist-98/cli@0.1.3 lock           # write exorcist.lock, then commit it
npx -y @exorcist-98/cli@0.1.3 lock --check   # exit 1 if any tool or program changed
npx -y @exorcist-98/cli@0.1.3 lock --check --static   # starts nothing: names, programs, URLs only
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
each server's program (command, arguments, argument files, env and cwd) and
remote URLs with the lock. `lock-check: live` also compares tool descriptions;
the Action runs it only on `push`, `schedule` and `workflow_dispatch` to the
default branch, at the pushed commit, and refuses every other event. A server
`env` that changes how its program loads (`NODE_OPTIONS`, `LD_PRELOAD` and
similar) is reported as high (EX-025). Servers that `exorcist lock` does start get a
minimal environment (PATH, HOME, LANG, LC_*, TMPDIR) plus their own `env`
from the config, so tokens and keys in your shell are not passed on.

## Licence

Apache-2.0.
