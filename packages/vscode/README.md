# Exorcist 98 for Kiro

Antivirus for the files your AI coding agent obeys. Kiro steering and specs,
hooks, MCP configs, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`,
`.github/copilot-instructions.md` and READMEs can carry instructions written
for the agent rather than for you: invisible Unicode characters, hidden HTML
comments, text that tells the agent to drop the rules it was given, tool
servers that together can leak your secrets. This extension shows them where you work, in Kiro or VS Code.

It uses the same scanner and virus definitions as the
[Exorcist 98 CLI](https://www.npmjs.com/package/@exorcist-98/cli), bundled, offline.

## Features

**Live diagnostics.** Agent files are scanned as you open, edit (debounced) and
save them, and when an agent changes one on disk. Every finding appears in the
Problems view with a plain-language explanation and the fix. Critical and high
findings are errors, medium are warnings, low are information. The rule id (for
example `EX-001`) links to its page in the
[Exorcist 98 encyclopedia](https://exorcist-98.vercel.app/encyclopedia).

**Hidden characters made visible.** Zero-width characters, bidirectional
overrides, Unicode tag characters and smuggling runs of variation selectors get
a visible marker in the editor, such as `ZWSP×2`, `RLO` or `TAG×51`, and a mark
in the scroll bar. Hover a marker to see each character by name and, when the
characters spell out a hidden message, the decoded text (the Ouija board). The
decoded text is the attacker's: it is shown in a code block with every control
and direction character replaced by `[U+XXXX]`, so it cannot render, link or act.

Ordinary uses are left alone, exactly as in the CLI: emoji joiner sequences, a
single emoji variation selector, flag emoji, a byte-order mark at the start of
a file, and joining-script spelling in Persian, Arabic, Hindi and others.

**Quick fix: Exorcise.** *Exorcise: remove hidden characters* deletes every
hidden character the scanner reported in the file, as one ordinary edit: the
visible text does not change, and Undo puts the characters back. Hidden HTML
comments that address the agent and data-leaking remote images have their own
one-finding fixes. The fixes are the CLI's `exorcist exorcise` logic. The file
is not saved for you.

**Status bar.** A ghost count for the workspace (`👻 3`); click it to open the
Problems view.

**Scan workspace.** `Exorcist 98: Scan workspace` checks every agent file in
the workspace, not only open ones. It also runs once at startup (setting below).

## Which files are scanned

The files the Exorcist 98 scanner treats as agent files: instruction files
(Kiro steering, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`,
`.windsurfrules`, `.clinerules`, Cursor, Windsurf and Amazon Q rules,
`.github/copilot-instructions.md` and prompts, Claude Code commands, agents and
skills, `SKILL.md`, every `README*`), MCP configs (`.kiro/settings/mcp.json`,
`.cursor/mcp.json`, `.vscode/mcp.json`, `.mcp.json`, Claude and Gemini
settings, and any JSON config with an `mcpServers` object), hooks
(`.kiro/hooks/**`), agent memory (`MEMORY.md`, `.kiro/notes/**`), Kiro Powers,
and `package.json`. Also everything under `.kiro/` and `.cursor/`, and
`CONTRIBUTING*`. Add more with `exorcist98.extraGlobs`.

Outside a workspace folder (for example Kiro's user-level
`~/.kiro/settings/mcp.json`), a file is recognized by its path from the agent
folder on.

## Settings

| Setting | Default | |
|---|---|---|
| `exorcist98.enable` | `true` | Turn scanning on or off. |
| `exorcist98.extraGlobs` | `[]` | More files to scan, as workspace-relative globs, e.g. `docs/agents/**`. A glob without `/` matches the file name in any folder. |
| `exorcist98.minimumSeverity` | `low` | Lowest severity shown and counted: `low`, `medium`, `high` or `critical`. |
| `exorcist98.showHiddenCharacters` | `true` | Draw the hidden-character markers. |
| `exorcist98.scanWorkspaceOnStartup` | `true` | Scan all agent files when the editor starts. |

The marker colors are the theme colors `exorcist98.hiddenCharacterForeground`
and `exorcist98.hiddenCharacterBackground`.

## Safety and Restricted Mode

- **Read-only.** The extension reads files. It never runs a program, task,
  script or hook from the workspace, and never loads code from it.
- **No network.** No request is made, ever. The virus definitions are bundled.
  An encyclopedia link opens in your browser only when you click it.
- **Restricted Mode.** Because scanning only reads, the extension also runs in
  folders you have not trusted, which is where a hostile repository is most
  likely. There, Kiro and VS Code ignore the workspace's own values for
  `exorcist98.enable`, `exorcist98.minimumSeverity` and
  `exorcist98.showHiddenCharacters`, so a repository cannot switch the scanner
  off or hide its findings through `.vscode/settings.json`. The status bar
  tooltip says when this applies. Quick fixes edit the open document only when
  you choose them.

## What the editor does not do

The CLI's optional AI judge (Amazon Bedrock), canary-trap matching, Shield pin
checks and the EX-010 version-pinning fix (it looks versions up on npm or PyPI)
need a network or local records, so they are not part of the extension. Run
`npx @exorcist-98/cli scan` and `exorcise` for those.

## License

Apache-2.0, like the rest of the project. Exorcist 98 is a Kiroween 2026 hackathon project:
[github.com/pranavsaji/exorcist-98](https://github.com/pranavsaji/exorcist-98).
