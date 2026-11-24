# Turning on the AI judge on the website

The public site checks pasted text with signatures only, unless the operator
turns on the AI judge. When it is on, **Bring Your Own Attack** shows an "Ask
the AI judge" button under every verdict: Claude Haiku triages the text, Claude
Sonnet judges it, on Amazon Bedrock, in the operator's AWS account.

Code: `apps/web/src/lib/ai-judge.ts` (switch and budget),
`apps/web/src/lib/ai-judge-handler.ts` (the route), `apps/web/src/components/AiJudgePanel.tsx`.
Tests: `apps/web/src/__tests__/ai-judge.test.ts`; the Chrome suite checks the
panel in both states and, with `E2E_AI=1`, makes one real check.

## What protects your bill

| Guard | Default |
|---|---|
| Off unless `EXORCIST_WEB_AI=1` and a region and both key halves are set | off |
| Per visitor (by the client-IP header) | 3 checks, then 1 every 3 minutes |
| At once, per server instance | 2 checks |
| Per server instance per UTC day | 200 model calls (`EXORCIST_WEB_AI_DAILY_CALLS`, at most 5,000) |
| Per check | at most 2 model calls, reserved before the check starts |
| Text length | 4,000 characters |

The daily budget is kept in memory per server instance, so the true ceiling
is the budget times the number of instances Vercel runs. Set an **AWS Budgets
alert** on the account as the backstop, and use an IAM user that can do
nothing but call these two models.

Rough cost: a check is one Haiku call, plus one Sonnet call when Haiku is not
sure it is benign, on at most 4,000 characters. At 200 calls a day that is
well under a dollar a day per instance at current Bedrock prices.

## What visitors are told

Before they click: the text is sent, with anything that looks like a
credential masked, to Amazon Bedrock, and we do not store it. The route never
logs the text (only the kind of an error), and a verdict counts only if its
quote is really in the text.

## Setup (about 10 minutes, in your AWS and Vercel accounts)

1. **Model access.** In the Bedrock console (us-east-2), make sure Claude
   Haiku 4.5 and Claude Sonnet 4.6 are available to the account.

2. **An IAM user that can only call the two models.** Create a user (for
   example `exorcist-web-ai`) with no console access and this inline policy;
   replace `ACCOUNT_ID`:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "bedrock:InvokeModel",
         "Resource": [
           "arn:aws:bedrock:us-east-2:ACCOUNT_ID:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0",
           "arn:aws:bedrock:us-east-2:ACCOUNT_ID:inference-profile/us.anthropic.claude-sonnet-4-6",
           "arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
           "arn:aws:bedrock:*::foundation-model/anthropic.claude-sonnet-4-6"
         ]
       }
     ]
   }
   ```

   Create an access key for it.

3. **A budget alert.** AWS Budgets: a monthly cost budget (for example $10)
   with an email alert at 50% and 100%.

4. **Vercel environment variables** (Production). Vercel reserves the
   standard `AWS_*` names, so the site reads its own:

   ```sh
   vercel env add EXORCIST_WEB_AI production                 # 1
   vercel env add EXORCIST_AWS_REGION production             # us-east-2
   vercel env add EXORCIST_AWS_ACCESS_KEY_ID production      # from step 2
   vercel env add EXORCIST_AWS_SECRET_ACCESS_KEY production  # from step 2 (mark it sensitive)
   vercel env add EXORCIST_WEB_AI_DAILY_CALLS production     # optional, default 200
   ```

5. **Redeploy**, then check: `curl https://exorcist-98.vercel.app/api/ai-judge`
   says `{"enabled":true,...}`; in the app, open Bring Your Own Attack, pick
   **Polite request** (signatures say CLEAN) and ask the AI judge.

To turn it off again, remove `EXORCIST_WEB_AI` (or set it to anything but
`1`) and redeploy; delete the access key in IAM.
