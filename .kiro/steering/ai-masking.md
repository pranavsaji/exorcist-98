---
inclusion: fileMatch
fileMatchPattern: ["packages/core/src/llm/**", "packages/core/src/scanner/heuristic-engine.ts", "packages/shield/src/ai-review.ts", "packages/shield/src/proxy.ts", "scripts/bedrock-smoke.ts", "scripts/ai-judge-eval.ts", "scripts/detonation-eval.ts"]
---

# What may reach Amazon Bedrock

Written after the M5 security review (commits `d16476c` to `2f267bd`). The code is the
authority; these are the invariants it keeps.

- Every judge prompt goes through `classify` in `packages/core/src/scanner/heuristic-engine.ts`,
  which runs `maskForModel` on the whole prompt at the sink: the scanner's judge
  (`exorcist scan --ai`) and the Shield's `aiReview` (through `judgeText`). Do not add a
  second path to `client.call` that skips it. The Detonation Chamber (`converse`) masks its
  input itself (below).
- Credential files never go to the model by any path: `.env*`, `*.local.json`,
  `claude_desktop_config.json`, `.npmrc`, `.netrc`, `credentials(.json)` (`CREDENTIAL_FILE`).
- `maskForModel` masks at the same length (line and column numbers still point at the
  right place), in linear time, line by line:
  - every known secret format (`findSecrets`);
  - the password in every `scheme://user:password@` and `scheme:user:password@`, scanning
    back from each `@` (no regex backtracking), a `:` inside the password masked too;
  - under a secret-named key (key, token, secret, password, auth, credential, cookie,
    session), every single-token value. This fails closed: it stays visible only when it is
    clearly a URL, a file path, a command or encoded readable text.
- Masking hides credentials only, never instructions. An instruction needs several words, so
  it is never masked; destinations (hosts, URLs) stay visible.
- The judge is told how many values were masked, and that sending data to a masked
  destination is itself suspicious.
- The Detonation Chamber masks the scanned text with `maskForModel` before building the
  chamber. Its planted secrets are random per detonation and appear as `[SECRET NAME]` in
  every transcript, finding and report (`maskSecrets`).
- Drop any verdict whose quoted span is not found verbatim in the (masked) file.
- Tests never call Bedrock: use `FakeBedrockClient` and `FakeChamberClient`. A masking change
  needs a test in `packages/core/src/__tests__/heuristic-whole-file.test.ts` that shows the
  secret shape is masked and an instruction next to it is still visible.
