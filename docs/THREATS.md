# Threat catalogue

Generated from `definitions/*.yaml`. Updated automatically by the spec-change
hook when specs are edited.

| ID     | Title                                     | Severity | OWASP                                              | File                                                  |
| ------ | ----------------------------------------- | -------- | -------------------------------------------------- | ----------------------------------------------------- |
| EX-001 | Hidden Unicode instructions               | Critical | LLM01:2025 Prompt Injection, ASI03                 | `definitions/EX-001-hidden-unicode.yaml`              |
| EX-002 | Instructions addressed to AI              | High     | LLM01:2025 Prompt Injection, ASI03                 | `definitions/EX-002-ai-instructions.yaml`             |
| EX-003 | Encoded payload                           | High     | LLM01:2025 Prompt Injection, ASI03                 | `definitions/EX-003-encoded-payload.yaml`             |
| EX-004 | HTML comment smuggling                    | High     | LLM01:2025 Prompt Injection, ASI03                 | `definitions/EX-004-html-comment-smuggling.yaml`      |
| EX-005 | Tool description poisoning                | Critical | MCP01 Tool Poisoning Attack, LLM01                 | `definitions/EX-005-tool-description-poisoning.yaml`  |
| EX-006 | MCP rug pull (description change pattern) | Critical | MCP02 Tool Rug-Pull, LLM01                         | `definitions/EX-006-mcp-rug-pull.yaml`                |
| EX-007 | Over-broad auto-approve                   | High     | ASI02 Inadequate Human-in-the-Loop, MCP05          | `definitions/EX-007-overbroad-autoapprove.yaml`       |
| EX-008 | Remote code in hook                       | Critical | ASI06 Prompt Injection via Indirect Content, LLM01 | `definitions/EX-008-remote-code-hook.yaml`            |
| EX-009 | Install-script exfiltration               | Critical | ASI07 Supply Chain Vulnerabilities, LLM01          | `definitions/EX-009-install-script-exfiltration.yaml` |
| EX-010 | Unpinned MCP server                       | Medium   | ASI07 Supply Chain Vulnerabilities, MCP04          | `definitions/EX-010-unpinned-mcp-server.yaml`         |
| EX-011 | Secrets in agent reach                    | High     | LLM02:2025 Sensitive Information Disclosure, ASI05 | `definitions/EX-011-secrets-in-agent-reach.yaml`      |
| EX-012 | Markdown image exfiltration               | High     | LLM02:2025 Sensitive Information Disclosure, ASI05 | `definitions/EX-012-markdown-image-exfil.yaml`        |
