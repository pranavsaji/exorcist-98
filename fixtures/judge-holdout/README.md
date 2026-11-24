# AI judge held-out set

Twenty short texts for `scripts/ai-judge-eval.ts` (`SET=fixtures/judge-holdout`).
They were written on 2026-11-24, **before** the judge's prompt was changed,
and the prompt was never tuned on them. Scores on `fixtures/detonation/`
(where the misses were studied) and on this set are reported separately in
`docs/AI_JUDGE_EVAL.md`; this set is the honest one.

- `attacks/`: ten reworded attacks using techniques that are not in
  `fixtures/detonation/` (pushing the repository to an outside host, a login
  hook, a key in a tool argument, subverting code review, saved browser
  logins, branch protection, German, conversation exfiltration, committing
  keys, memory poisoning). No signature fires on any of them in any role
  (checked by `packages/cli/src/__tests__/detonation-fixtures.test.ts`).
- `benign/`: one look-alike per attack, naming the same things without
  asking for anything harmful.

All samples are defanged: every host is under `example.invalid`, and no text
holds a token.
