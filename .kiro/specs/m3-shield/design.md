# Design: m3-shield

## 1. Layout

```
packages/core/src/
  scanner/scan-text.ts          scanText(text, role, defs)
  plain.ts                      plain-language text (export "./plain")
  reporters/markdown-reporter.ts

packages/shield/src/
  hash.ts          canonicalJson, toolFingerprint
  jsonrpc.ts       zod schema, LineSplitter (byte-safe), error/result builders
  state.ts         zod schemas, loadState/saveState (atomic), approvals
  policy.ts        policy schema, host matching
  inspect.ts       inspectCall, inspectResult
  engine.ts        ShieldEngine (pure)
  proxy.ts         runProxy (spawn child, relay, persist, alert sinks)
  vault.ts         quarantine/restore/diff/list
  wrap.ts          wrapConfig / unwrapConfig (pure)
  index.ts

packages/cli/src/
  index.ts         command dispatch (node:util parseArgs, no extra dependency)
  commands/        scan, shield, wrap, vault, approve, init
  build.mjs        esbuild bundle to dist/index.mjs + copy definitions

packages/mcp-server/src/index.ts   McpServer + stdio
power/                              plugin.json, mcp.json, skills/
action.yml                          composite GitHub Action
```

## 2. Message flow

```
Kiro --stdin--> [LineSplitter] --> engine.onClient(msg) --> forward / reply
                                                              |
child stdout --> [LineSplitter] --> engine.onServer(msg) --> forward / replace / alert
```

`ShieldEngine` keeps `pending: Map<id, { method, tool? }>` and returns an action
list; `proxy.ts` is the only code that touches processes, files or streams.

## 3. Tool fingerprint

`canonicalJson` sorts object keys recursively and serialises with no
whitespace; arrays keep their order. `toolFingerprint = sha256(canonicalJson({
name, description ?? "", inputSchema ?? {} }))`.

## 4. tools/list handling

For each tool in the response:

| State | Action |
|-------|--------|
| not pinned, scan clean | pin (trust on first use), forward |
| not pinned, critical/high finding | withhold, do not pin, alert EX-005 |
| pinned, same fingerprint | forward |
| pinned, different fingerprint | withhold, store pending (old/new description), alert EX-006, optional quarantine |

The withheld tool names are kept for the process lifetime; `tools/call` for any
of them is refused. Paged lists are handled per page.

## 5. Call and result inspection

- `collectStrings(value)` walks arguments to a depth of 8 and 5,000 strings.
- Secrets: `findSecrets` over each string plus the JSON-encoded whole.
- Hosts: URLs matched with `https?://host`; compared with the allowlist, the
  loopback names and the approvals for this server.
- Results: text from `content[].text` and string values in `structuredContent`
  joined and scanned by `scanText(..., 'tool-result', defs)`.
- Replacement result: `{ isError: true, content: [{ type: "text", text }] }`
  with a plain explanation and rule ids only.

## 6. State files (`.exorcist/`)

| File | Content |
|------|---------|
| `pins.json` | per server: pinned tools (hash, description, pinnedAt), pending changes, approved hosts |
| `policy.json` | allowedHosts, mode, autoQuarantine |
| `alerts.jsonl` | one JSON alert per line (time, server, rule, tool, message) |
| `vault/<id>/` | manifest.json plus backup files |

## 7. Vault

- MCP server: backup = the entry's JSON. Quarantine sets `disabled: true`.
  Restore writes the original entry back into the current config.
- File: moved to `vault/<id>/files/<name>`; restore moves it back and refuses to
  overwrite a different file unless `--force`.
- Diff: unified diff of backup against current state using the `diff` package.

## 8. wrap

`wrapConfig(config, { bin, dir, configPath })` turns each stdio entry
`{ command, args }` into `{ command: bin, args: ["shield", "--server", name,
"--config", configPath, "--dir", dir, "--", command, ...args] }` and leaves
remote (`url`) entries and already-wrapped entries untouched. `unwrapConfig`
reverses it exactly.

## 9. Dependencies added (reason)

| Package | Where | Reason |
|---------|-------|--------|
| @modelcontextprotocol/sdk | mcp-server | the official MCP server and client, so the server is protocol-correct |
| diff | shield | unified diffs for the Vault and rug-pull alerts |
| esbuild | cli (dev) | bundle the CLI into one runnable file |

## 10. What cannot be verified here

The proxy is tested against a fake MCP server and the official SDK client. It
has not been run inside Kiro, and Kiro's handling of a blocked tool call and of
`autoApprove` interplay is unverified. The Power and Action have not been
installed or run in their real hosts.
