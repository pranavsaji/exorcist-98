---
inclusion: fileMatch
fileMatchPattern: ["**/canary*.ts", "packages/cli/src/commands/check-staged.ts", "packages/core/src/secrets-check.ts"]
---

# Canary traps (EX-022)

- A token is `x98c_` plus 24 base32 characters (120 random bits from
  `crypto.getRandomValues`), unique per install. Never use `Math.random`.
- Detection is one function, `findCanaryInText` in `packages/core/src/canary.ts`, shared by
  the Shield, the scanner and the pre-commit check. Do not write a second detector. It finds
  raw, whitespace-split, percent-encoded and base64 (standard and URL-safe, any alignment)
  tokens; a base64 match must decode to the whole token.
- Never print, log or alert a full token. Use `maskToken` (prefix and two characters, then
  asterisks). Alerts say EX-022 and never repeat the token.
- Shield: a message from the agent that holds a token is refused in every mode, with a
  critical EX-022 alert. A tool result with a token is passed on with a medium alert.
- Traps live only in `.exorcist/canary/` and the records in `.exorcist/canaries.json`. Both
  are git-ignored, and `isCanaryHome` keeps the scanner from flagging them.
- `plant` never overwrites traps or records and never writes through a symlinked folder.
  `--remove` deletes only files `plant` wrote that still hold their recorded token; anything
  else is left with a warning and the records are kept.
