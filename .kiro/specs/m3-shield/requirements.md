# Spec: m3-shield

Milestone M3: the Real-Time Shield (MCP firewall), the Quarantine Vault, the
`exorcist` CLI, the `exorcist` MCP server, the Kiro Power and a GitHub Action.

Decisions that answer open questions from the plan review:

- **One proxy process per MCP server**, all sharing one state folder
  (`.exorcist/`). Kiro starts each wrapped server through `exorcist shield`.
- **Pins persist** in `.exorcist/pins.json` (atomic writes, validated with zod).
- **"Ask the user" without a UI**: the MCP stdio protocol gives a proxy no way
  to show a dialog. A risky call is blocked with a plain-words message that
  names the exact command that approves it (`exorcist approve ...`); the agent
  or user retries after approving. Protocol-level elicitation is out of scope.
- **Fail closed**: an unreadable pin store or policy stops the proxy instead of
  running unprotected.

Out of scope: remote (HTTP) MCP servers, OAuth, a GUI for approvals, Bedrock
heuristics inside the proxy, publishing to npm, EX-013/014/016-as-definition/
018/019/020 definitions.

---

## REQ-01 Core additions

1. `scanText(text, role, defs)` in `packages/core` returns signature findings
   for a string (normalize, then run signatures). `FileRole` gains
   `tool-result`.
2. `packages/core` exports what the other packages need: `scanText`,
   `findSecrets`, `redact`, `loadDefinitions`, `scanRepo`, the reporters and the
   types. Plain-language text moves to `@exorcist-98/core/plain`; the web app
   re-exports it.
3. New definition **EX-015 Shell in tool output** (applies to `tool-result` and
   `config`), with a Haunted Repo fixture hit, an encyclopedia entry and a
   plain-language entry. EX-001, EX-002, EX-004 and EX-008 also apply to
   `tool-result`.
4. `toMarkdown(findings, stats)` reporter for pull-request comments.
5. `packages/core/package.json` declares its own runtime dependencies (L-045).

## REQ-02 Shield engine (pure)

1. `ShieldEngine` takes parsed JSON-RPC messages and returns actions
   (`forward`, `reply`, `alert`, `persist`, `quarantine`). It does no I/O.
2. It tracks request ids so a response is matched to its method and tool.
3. Messages it does not need to inspect are forwarded unchanged.
4. A JSON-RPC batch array is rejected with a JSON-RPC error (batching is not
   part of the supported MCP revisions).

## REQ-03 Tool pinning and rug-pull detection

1. A tool's fingerprint is the SHA-256 of the canonical JSON of its name,
   description and input schema. Key order never changes it; changing any of
   the three always does.
2. First sight of a tool: its text is scanned with the signatures. If any
   finding is `critical` or `high`, the tool is **withheld and not pinned**
   (alert EX-005). Otherwise it is pinned (trust on first use).
3. A pinned tool whose fingerprint changes is a **rug pull** (EX-006): it is
   removed from the `tools/list` response sent to the agent, calls to it are
   refused, the change is stored as pending with the old and new description,
   and a critical alert with a unified diff of the description is raised.
4. With `autoQuarantine` on, a rug pull also disables the server in the MCP
   config through the Vault.
5. `exorcist approve tool <server> <tool>` accepts the pending version and
   re-pins it. A tool that disappears and returns unchanged is not an alert.

## REQ-04 Call inspection

1. Arguments are searched (deeply, to a depth limit) for secrets with
   `findSecrets`. A secret anywhere in the arguments **blocks** the call (EX-017)
   and the call is never forwarded.
2. URLs in arguments whose host is not in the allowlist, not localhost and not
   approved make the call **ask** (EX-016): it is refused with a plain message
   and the approve command. Allowlist entries may use a `*.` prefix.
3. In `monitor` mode nothing is blocked; findings become alerts.

## REQ-05 Result inspection

1. Text in `tools/call` results is scanned with the definitions as role
   `tool-result`. Any `critical` or `high` finding withholds the result and
   replaces it with an error result that explains, in plain words, what was
   found. Hidden Unicode in a result counts.
2. The replacement never contains the withheld text.

## REQ-06 Proxy runtime

1. `exorcist shield --server <name> [--config <mcp.json>] [--dir <state>] -- <command> [args]`
   spawns the real server and relays newline-delimited JSON-RPC both ways.
2. Only protocol messages are written to stdout. Alerts go to stderr and to
   `alerts.jsonl`. Logs contain tool names, rule ids and hash prefixes, never
   arguments or result text.
3. If the child exits, the proxy exits with its code. If the client closes
   stdin, the child is stopped.
4. Non-JSON lines from either side are dropped with an alert.

## REQ-07 State

1. `pins.json` and `policy.json` are validated with zod. A corrupt or invalid
   file stops the proxy with a clear error (fail closed).
2. Writes are atomic (temp file, then rename).
3. The policy has `allowedHosts`, `mode` (`enforce` or `monitor`) and
   `autoQuarantine`. Defaults: no extra hosts, `enforce`, `false`.

## REQ-08 Quarantine Vault

1. Quarantine an **MCP server** (set `disabled: true` in its config entry), a
   **hook** or a **steering file** (move it into the vault). A backup, a
   manifest (reason, time, sha256) and a unified diff are kept.
2. `restore` puts back the original exactly. For an MCP server only that
   server's entry is restored, so other edits to the config are kept.
3. Quarantining something already quarantined is refused and never overwrites
   the backup. Restore refuses to overwrite a file that has since changed,
   unless forced.

## REQ-09 CLI

`exorcist scan | shield | wrap | unwrap | vault | approve | init`, built to a
single runnable file.

- `scan <path>` supports `--format text|json|sarif|markdown`, `--fail-on`,
  `--ignore`, `--definitions`, `--output`. Exit code 1 when a finding meets
  `--fail-on`, 2 on usage or read errors.
- `wrap` rewrites an MCP config so each stdio server runs through the shield;
  `unwrap` restores it exactly.
- `init` writes the Kiro hooks and a steering file into a project.

## REQ-10 MCP server

`packages/mcp-server` exposes `scan_repo`, `scan_mcp_config`, `explain_finding`
and `quarantine` over stdio using the official MCP SDK, with zod input schemas.
`quarantine` is never auto-approved.

## REQ-11 Power and GitHub Action

1. `power/` follows the Agent Plugins layout (`plugin.json`, `mcp.json`,
   `skills/`).
2. A composite GitHub Action runs the scan, writes SARIF and a Markdown summary
   and comments on pull requests.
3. `.kiro/settings/mcp.json` registers the project's own MCP server for
   development.

## REQ-12 Golden path (live rug pull)

A test runs real processes: a fake MCP server behind the shield. It proves
that a benign tool is pinned and works; that after the server changes the tool
description the agent no longer sees the tool and cannot call it; that the
backend never received a blocked call; and that auto-quarantine disabled the
server with a restorable backup.

## REQ-13 Tests

Property-based tests (fast-check):

| ID | Property |
|----|----------|
| PBT-SHD-01 | The fingerprint ignores key order and changes whenever name, description or schema changes. |
| PBT-SHD-02 | For any arguments containing a secret at any depth, the engine never forwards the call. |
| PBT-SHD-03 | Once a tool's fingerprint differs from its pin, it never appears in a forwarded `tools/list` and calls to it are never forwarded. |
| PBT-SHD-04 | A pin store round-trips through save and load unchanged. |
| PBT-SHD-05 | Splitting the stdio stream at any byte boundary yields the same messages. |
| PBT-SHD-06 | A result containing an injection phrase (any case, any spacing) is never forwarded in `enforce` mode. |
| PBT-VLT-01 | Quarantine then restore returns the original bytes, for any file content. |
| PBT-VLT-02 | `wrap` then `unwrap` returns the original config for any server set. |

Plus integration tests with real processes (REQ-12), CLI exit codes, SDK-client
tests for the MCP server, and tests that every changed hook, Power and Action
file parses.

## REQ-14 Documentation

KIRO_LOG and KNOWN_LIMITATIONS updated, including what was not verified inside
Kiro itself.
