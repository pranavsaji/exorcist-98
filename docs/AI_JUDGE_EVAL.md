# AI judge on reworded attacks: measured results

The AI judge (`judgeText` and `exorcist scan --ai`: Claude Haiku 4.5 triage,
then a Claude Sonnet judge, on Amazon Bedrock) is for attacks written in
ordinary words that no signature can catch. These are its measured results on
two labelled sets of 20 short texts, each judged whole.

| Set | What it is | Before the fix | After the fix |
|---|---|---|---|
| `fixtures/detonation/` | 10 reworded attacks, 10 look-alikes; its misses were studied | 6 of 10 caught, 0 false alarms | **10 of 10 caught, 0 false alarms** |
| `fixtures/judge-holdout/` | 10 attacks with different techniques, 10 look-alikes; written on 2026-11-24 before the fix and never tuned on | 9 of 10 caught, 0 false alarms | **10 of 10 caught, 0 false alarms** |

Signatures catch 0 of these 20 attacks by construction
(`packages/cli/src/__tests__/detonation-fixtures.test.ts` fails if one ever
does).

## What the fix was

Tracing the four misses showed that the models had **not** missed them: both
Haiku and Sonnet called all four malicious. The verdicts were then thrown away
by our own safety check, which keeps a verdict only if the text the model
quotes is really in the file. The check compared character for character, and
each of the four quotes covers a sentence that wraps onto the next line: the
model quoted the line break as a space.

`locateQuote` (in `packages/core/src/scanner/heuristic-engine.ts`) keeps the
safety rule, the quoted words must be in the file and in that order, but
lets whitespace differ. A quote of a masked credential (the model only ever
sees asterisks) is found in the masked text and shown masked. The same check
sat in the whole-repo scanner, so `exorcist scan --ai` was losing these
verdicts too. Tests: `packages/core/src/__tests__/locate-quote.test.ts`,
including a fast-check property. The prompt was not changed.

## Limits

- One run per set; model output varies from run to run. H06 on the held-out
  set was missed before the fix and caught after it, which may be the fix or
  may be that variation.
- 40 texts, all written by us. They show the judge is not fooled by plain
  rewording; they do not measure real-world recall.
- The judge costs money and needs your AWS account. The scanner's signatures
  stay the first line: fast, free and impossible to prompt-inject.

## Raw results

- [`ai-judge/detonation-before.md`](ai-judge/detonation-before.md): 6 of 10, 34 calls
- [`ai-judge/holdout-before.md`](ai-judge/holdout-before.md): 9 of 10, 34 calls
- [`ai-judge/detonation-after.md`](ai-judge/detonation-after.md): 10 of 10, 34 calls
- [`ai-judge/holdout-after.md`](ai-judge/holdout-after.md): 10 of 10, 42 calls

Reproduce: `AWS_PROFILE=<profile> AWS_REGION=us-east-2 SET=judge-holdout OUT=docs/ai-judge/holdout-again.md pnpm exec tsx scripts/ai-judge-eval.ts` (hard cap of 50 model calls per run).
