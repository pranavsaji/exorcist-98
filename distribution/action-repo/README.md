# Exorcist 98 GitHub Action

Scan a repository for attacks on AI coding agents: hidden instructions in
READMEs, rules and steering files, poisoned MCP tool descriptions, dangerous
hooks and install scripts, and leaked secrets. Every pull request gets a
summary comment, and the check fails on threats at or above the level you set.

This action runs the published [`@exorcist-98/cli`](https://www.npmjs.com/package/@exorcist-98/cli)
at one pinned version, `0.2.0`. Before it runs, `npm audit signatures` checks
the package's npm provenance, which ties it to the commit and workflow in
[pranavsaji/exorcist-98](https://github.com/pranavsaji/exorcist-98) that built
it. Nothing is built and no install scripts run. The source, the rules and the
full documentation are in that repository.

## Usage

```yaml
name: Exorcist 98
on: [pull_request]
permissions:
  contents: read
  pull-requests: write   # only for the pull request comment
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pranavsaji/exorcist-98-action@v0.2.0
        with:
          fail-on: high
```

## Inputs

| Input | Default | What it does |
|---|---|---|
| `path` | `.` | Folder or file to scan, relative to the workspace. |
| `fail-on` | `high` | Fail the job on a finding at least this severe: `critical`, `high`, `medium`, `low` or `none`. |
| `ignore` | | Paths to skip, one per line (prefixes relative to the scanned folder). |
| `comment` | `true` | Post or update a summary comment on pull requests. |
| `upload-sarif` | `false` | Upload results to GitHub code scanning. |
| `lock-check` | `false` | `true` compares the MCP config with the committed `exorcist.lock` without starting anything. `live` also starts every server, so it runs only on push, schedule and workflow_dispatch, on the default branch, with `GITHUB_SHA` checked out; the action refuses it anywhere else. |
| `lock-config` | `.kiro/settings/mcp.json` | MCP config for `lock-check`, relative to the workspace. |

Output: `sarif-file`, the path of the SARIF report.

## Permissions and secrets

The action needs no secrets. It uses the job's own `GITHUB_TOKEN`, so give the
job only what the inputs you turn on need:

| Permission | Needed for |
|---|---|
| `contents: read` | Always (checking out and reading the repository). |
| `pull-requests: write` | `comment: true` on pull requests. Without it, leave `comment` at `false`. |
| `security-events: write` | `upload-sarif: true`. |

Leave every other permission off. Do not run it with `lock-check: live` on
`pull_request_target`; the action refuses that anyway, because a live check
starts the commands in the MCP config.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
