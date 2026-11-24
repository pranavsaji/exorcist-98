# Changelog

## 0.1.0 (2026-11-24)

First release.

- Live diagnostics for agent files (Kiro steering, specs, hooks and MCP
  configs, `AGENTS.md`, `CLAUDE.md`, rules files, Copilot instructions,
  READMEs, `CONTRIBUTING`, `package.json`, any JSON config with `mcpServers`),
  on open, edit, save and change on disk, with links to the encyclopedia.
- Lethal-trifecta check (EX-023) for MCP configs.
- Hidden characters drawn as visible markers, with a hover that names each
  character and decodes hidden messages (Ouija board).
- Quick fixes: remove hidden characters (EX-001, EX-021), remove a hidden HTML
  comment (EX-002, EX-004), replace a data-leaking image (EX-012).
- Status bar ghost count; `Scan workspace` command and startup scan.
- Settings: `enable`, `extraGlobs`, `minimumSeverity`, `showHiddenCharacters`,
  `scanWorkspaceOnStartup`. Runs read-only in Restricted Mode, where workspace
  values of the settings that could hide findings are ignored.
