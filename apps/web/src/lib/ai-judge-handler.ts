import { z } from 'zod';
import { judgeText, MAX_JUDGED_CHARS, redactSecretText } from '@exorcist-98/core';
import type { BedrockClient, BedrockParams, BedrockResult } from '@exorcist-98/core';
import { BedrockClientImpl } from '@exorcist-98/core/llm';
import { BYOA_PLACEMENTS } from '@exorcist-98/shield/byoa';
import type { ByoaPlacement } from '@exorcist-98/shield/byoa';
import { aiJudgeConfig, CALLS_PER_JUDGEMENT, createDailyBudget } from '@/lib/ai-judge';
import { clientKey, limiter } from '@/lib/limits';
import { readCapped } from '@/lib/read-capped';
import { jsonError } from '@/lib/scan-response';

const RequestSchema = z
  .object({ placement: z.enum(BYOA_PLACEMENTS as [ByoaPlacement, ...ByoaPlacement[]]), text: z.string().min(1).max(MAX_JUDGED_CHARS) })
  .strict();
const MAX_BODY_BYTES = MAX_JUDGED_CHARS * 6 + 1_024;
const OFF = 'The AI judge is off on this public site, because every check costs money. Run exorcist scan --ai with your own AWS account to use it.';

export type AiJudgeResponse =
  | { verdict: 'malicious' | 'suspicious'; threatClass: string; quote: string; rationale: string; checkedChars: number }
  | { verdict: 'clean'; checkedChars: number }
  | { verdict: 'unavailable'; reason: string };

/** Test seam: the client the route uses. */
let makeClient: (opts: ConstructorParameters<typeof BedrockClientImpl>[0]) => BedrockClient = (opts) => new BedrockClientImpl(opts);
export function setClientFactoryForTests(f: typeof makeClient): void { makeClient = f; budget = null; }

let budget: ReturnType<typeof createDailyBudget> | null = null;

/** At most `max` characters, cut at a word boundary with an ellipsis. */
function clip(s: string, max: number): string {
  if (s.length <= max) return s;
  const cut = s.slice(0, max - 1);
  const at = cut.search(/\s\S*$/);
  return (at > max / 2 ? cut.slice(0, at) : cut).trimEnd() + '…';
}

const json = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });

/** GET /api/ai-judge -> { enabled } so the page can offer the button or explain why not. */
export async function handleAiJudgeGet(): Promise<Response> {
  const cfg = aiJudgeConfig();
  return json(cfg.enabled ? { enabled: true, maxChars: MAX_JUDGED_CHARS } : { enabled: false, reason: OFF });
}

/**
 * POST /api/ai-judge { placement, text } -> the AI judge's verdict (Claude
 * Haiku triage, then Claude Sonnet, on Amazon Bedrock). Credentials in the
 * text are masked before it leaves; the text is never stored or logged; a
 * verdict counts only if its quote is really in the text.
 */
export async function handleAiJudgePost(request: Request): Promise<Response> {
  const cfg = aiJudgeConfig();
  if (!cfg.enabled) return json({ verdict: 'unavailable', reason: OFF } satisfies AiJudgeResponse, 503);

  const declared = Number(request.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) return jsonError(413, `The AI judge reads at most ${MAX_JUDGED_CHARS.toLocaleString('en-US')} characters.`);
  const slot = limiter.acquire('ai', clientKey(request.headers));
  if (!slot.ok) return jsonError(slot.status, slot.error, { 'Retry-After': String(slot.retryAfterSeconds) });
  try {
    let body: unknown;
    try {
      const bytes = await readCapped(request, MAX_BODY_BYTES);
      if (bytes === null) return jsonError(413, `The AI judge reads at most ${MAX_JUDGED_CHARS.toLocaleString('en-US')} characters.`);
      body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
    } catch {
      return jsonError(400, 'The request body must be JSON.');
    }
    const parsed = RequestSchema.safeParse(body);
    if (!parsed.success) {
      const tooLong = parsed.error.issues.some((i) => i.path[0] === 'text' && i.code === 'too_big');
      return jsonError(400, tooLong ? `The AI judge reads at most ${MAX_JUDGED_CHARS.toLocaleString('en-US')} characters.` : 'Send { "placement": ..., "text": "..." }.');
    }

    budget ??= createDailyBudget(cfg.dailyCalls);
    if (!budget.reserve(CALLS_PER_JUDGEMENT)) {
      return json({ verdict: 'unavailable', reason: "Today's AI budget for this site is used up. It resets at midnight UTC; the signature check above still works." } satisfies AiJudgeResponse, 429);
    }
    const inner = makeClient(cfg.client);
    let made = 0;
    let failed = false;
    const client: BedrockClient = {
      async call(p: BedrockParams): Promise<BedrockResult> {
        if (made >= CALLS_PER_JUDGEMENT) return { ok: false, error: 'call limit' } as BedrockResult;
        made++;
        const r = await inner.call(p);
        if (!r.ok) failed = true;
        return r;
      },
    };
    try {
      const v = await judgeText(parsed.data.text, `pasted text (${parsed.data.placement})`, client);
      budget.refund(CALLS_PER_JUDGEMENT - made);
      if (!v && failed) return json({ verdict: 'unavailable', reason: 'The AI judge could not be reached. Try again later.' } satisfies AiJudgeResponse, 502);
      const checkedChars = parsed.data.text.length;
      if (!v) return json({ verdict: 'clean', checkedChars } satisfies AiJudgeResponse);
      return json({
        verdict: v.verdict === 'malicious' ? 'malicious' : 'suspicious',
        threatClass: v.threatClass.slice(0, 80),
        quote: clip(redactSecretText(v.span), 200),

        rationale: redactSecretText(v.rationale).slice(0, 300),
        checkedChars,
      } satisfies AiJudgeResponse);
    } catch (e) {
      budget.refund(CALLS_PER_JUDGEMENT - made);
      // Only the kind of error: a message could carry part of the pasted text.
      console.error('ai-judge failed:', e instanceof Error ? e.name : 'unknown error');
      return json({ verdict: 'unavailable', reason: 'The AI judge could not be reached. Try again later.' } satisfies AiJudgeResponse, 502);
    }
  } finally {
    slot.release();
  }
}
