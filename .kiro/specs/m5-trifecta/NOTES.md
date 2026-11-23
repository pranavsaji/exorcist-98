# Notes: m5-trifecta (decisions made while building)

- **Where the rules live.** `definitions/capabilities.yaml` sits next to the
  virus definitions so the CLI bundle, the Shield's definitions lookup and the
  web app ship it with no new paths. `loadDefinitions` skips it by name.
  EX-023 is an ordinary definition (`definitions/EX-023-lethal-trifecta.yaml`)
  with a new `match.analysis: trifecta`, so it has a title, fix, OWASP list,
  plain-language text and an encyclopedia page like every other rule; the
  signature engine skips analysis rules and the orchestrator runs it after the
  walk (it needs the whole config and the pin file).
- **Built-in agent abilities** come only from Claude Code `permissions.allow`
  (`WebFetch`, `WebSearch`, `Bash(...)`, `Read(...)`). An allowed ability runs
  without asking, so it counts as auto-approved. Other agents have no
  per-ability allow list in their config files today. `mcp__server__tool`
  entries auto-approve that tool of that server.
- **GitHub-style servers** are untrusted input and a way out, not private
  data: the spec's private-data list (files outside the project, email,
  databases, password managers, cloud consoles) does not include code hosts,
  and treating every GitHub token as private data would flag most ordinary
  configs. An email server alone covers all three legs, which is correct.
- **"Outside the project"** means the filesystem root, a drive, a home
  folder, a personal folder in it (Documents, Downloads...), a system folder,
  a credentials folder anywhere (.ssh, .aws...) or a relative path that climbs
  out. A deeper absolute path such as `/home/me/code/app` is most likely the
  project and is not flagged (the existing benign benchmark case
  `known-mcp-packages` relies on this).
- **Critical.** REQ-02.2 is applied as: any server on a leg of the trifecta
  with at least one auto-approved tool (`autoApprove`, `alwaysAllow`,
  Gemini `trust: true`, Claude `permissions.allow`).
- **Generic JSON files** (role `config`, e.g. the Haunted Repo samples) count
  as MCP configs only with an `mcpServers` object holding a server; the
  VS Code `servers` key is read only in files at MCP config paths.
- **NDJSON.** A new `map` event is sent once, just before `done`, only when
  the scan found MCP configs. Every existing event is unchanged and a stream
  without `map` is still valid. The client parser stays strict (unknown event
  types are errors, as its tests require), so a browser tab holding a page
  older than the server would show a stream error for this one event.
