---
inclusion: fileMatch
fileMatchPattern: ["packages/mcp-server/src/**", "packages/shield/src/byoa.ts", "apps/web/src/app/api/**", "apps/web/src/components/**", "packages/cli/src/commands/**", "packages/core/src/on-access.ts", "packages/core/src/ouija.ts", "packages/core/src/scanner/signature-engine.ts"]
---

# Quoting attacker text

Scanned files, tool descriptions, git history and pasted visitor text are all written by
someone else. How much of it we repeat, and where, is limited.

- To an agent: no quoted file text by default. The MCP server answers with rule id, file,
  line, plain-language headline and fix; quotes only with `includeQuotes: true`, hidden
  characters revealed as `[U+XXXX]` and marked untrusted. `EXORCIST_MCP_NO_QUOTES=1` turns
  quotes off entirely (the exorcist-reviewer agent's server runs with it). The on-access
  hook's block message never quotes the attacker, and a decoded hidden (Ouija) message is
  never handed to an agent.
- Spans: at most 120 characters (`MAX_SPAN` in the signature engine).
- Bring Your Own Attack: the visitor's text is never stored or logged, and the result repeats
  at most 200 consecutive characters of it (`MAX_QUOTE`, enforced last by `capQuotes`).
- Terminal: untrusted text is printed through `displayMessage` (core `ouija.ts`),
  `printable` (`lock.ts`), `terminalSafeJson` (`map.ts`) or `sanitizeGitText` (`origin.ts`),
  so control, bidi, zero-width and tag characters are shown escaped and cannot act on the
  terminal.
- Web: scanned text is rendered as React text only, never with `dangerouslySetInnerHTML`.
