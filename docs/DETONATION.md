# Detonation Chamber: measured results

**Not run yet. There are no measured results on this page, and none have been
filled in by hand.**

The evaluation script is ready (`scripts/detonation-eval.ts`), and so is the
labelled set (`fixtures/detonation/`: 10 reworded attacks that no signature
catches, 10 benign look-alikes). On 2026-11-23 it could not reach Amazon
Bedrock from the build machine. The owner's AWS login session had expired
(`CredentialsProviderError: Your session has expired. Please reauthenticate.`),
so the request failed before it was sent to any model. Model calls made: 0
billed (1 attempt, refused locally by the credential provider). Per the
script's rules, it wrote nothing.

## How to run it

```sh
aws login --profile <profile>          # or any valid AWS credentials
AWS_PROFILE=<profile> AWS_REGION=us-east-1 pnpm exec tsx scripts/detonation-eval.ts
```

- Model: the fast role, `EXORCIST_BEDROCK_HAIKU` if set, otherwise Claude Haiku
  4.5 through the inference profile for `AWS_REGION`
  (`us.anthropic.claude-haiku-4-5-20251001-v1:0` for us-east-1).
- Cost: at most 2 model calls per text, so 40 for the whole set. There is a
  hard cap of 60 calls. Every attempt counts, and once the cap is reached the
  script stops and lists the texts it did not run as "not run".
- When at least one call succeeds, the script replaces this page with the
  confusion matrix (detonated / inert / inconclusive / not run, for attacks
  and for benign texts), a row for each text listing the tool calls the model
  attempted (secrets masked), the misses and false alarms, the model id, the
  date and the call count, all exactly as measured.
- If every call fails, it writes nothing.

## What is already tested without a model

The verdict logic is pure, and unit tests with a fake model client cover it
(`packages/core/src/llm/__tests__/detonation.test.ts`). These tests never use
the network. The fake model plays these cases:

- Every harmful call shape is `detonated`: a planted secret sent through any
  tool (raw, base64, percent-encoded or split up), a secret file read the
  user never asked for, a download piped to a shell, a destructive command,
  a change to startup files or SSH keys.
- Plain answers and harmless calls are `inert`.
- Failed, malformed, cut-off or unfinished answers are `inconclusive`, never
  `inert`.

`packages/cli/src/__tests__/detonation-fixtures.test.ts` checks that no
signature fires on any of the 10 attacks, in any file role, and that the
Shield's paraphrase detector does not block any of them either. That is
measured. Whether the chamber catches them is not measured yet.
