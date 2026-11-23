import { z } from 'zod';
import { readCapped } from '@/lib/read-capped';
import { loadDefinitions } from '@exorcist-98/core';
import type { VirusDefinition } from '@exorcist-98/core';
import { BYOA_MAX_CHARS, BYOA_PLACEMENTS, judgeText } from '@exorcist-98/shield/byoa';
import type { ByoaPlacement } from '@exorcist-98/shield/byoa';
import { definitionsDir } from '@/lib/paths';
import { clientKey, limiter } from '@/lib/limits';
import { jsonError } from '@/lib/scan-response';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const ByoaRequestSchema = z
  .object({
    placement: z.enum(BYOA_PLACEMENTS as [ByoaPlacement, ...ByoaPlacement[]]),
    text: z.string().min(1).max(BYOA_MAX_CHARS),
  })
  .strict();

/**
 * Largest request body read. 20,000 characters can take up to 6 bytes each in
 * JSON (a \uXXXX escape), plus the placement and punctuation.
 */
const MAX_BODY_BYTES = BYOA_MAX_CHARS * 6 + 1_024;

let defsPromise: Promise<VirusDefinition[]> | null = null;

/**
 * POST /api/byoa { placement, text } -> what the real scanner and the real
 * Shield engine make of the text (m5-byoa).
 *
 * The text is judged in memory and dropped: it is never stored, logged or
 * sent anywhere, and the response quotes at most 200 consecutive characters
 * of it. Errors log only their kind, never the text.
 */
export async function POST(request: Request): Promise<Response> {
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) return jsonError(413, `Paste at most ${BYOA_MAX_CHARS.toLocaleString('en-US')} characters.`);

  // W-003: a per-visitor rate limit and a cap on checks running at once,
  // taken before the body is read so an oversized body costs nothing.
  const slot = limiter.acquire('byoa', clientKey(request.headers));
  if (!slot.ok) return jsonError(slot.status, slot.error, { 'Retry-After': String(slot.retryAfterSeconds) });
  try {
    return await judge(request);
  } finally {
    slot.release();
  }
}

async function judge(request: Request): Promise<Response> {
  let body: unknown;
  try {
    const bytes = await readCapped(request, MAX_BODY_BYTES);
    if (bytes === null) return jsonError(413, `Paste at most ${BYOA_MAX_CHARS.toLocaleString('en-US')} characters.`);
    body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    return jsonError(400, 'The request body must be JSON.');
  }
  const parsed = ByoaRequestSchema.safeParse(body);
  if (!parsed.success) {
    const tooLong = parsed.error.issues.some((i) => i.path[0] === 'text' && i.code === 'too_big');
    const empty = parsed.error.issues.some((i) => i.path[0] === 'text' && i.code === 'too_small');
    return jsonError(
      400,
      tooLong
        ? `Paste at most ${BYOA_MAX_CHARS.toLocaleString('en-US')} characters.`
        : empty
          ? 'Paste some text to check first.'
          : `Send { "placement": one of ${BYOA_PLACEMENTS.join(', ')}, "text": "..." }.`,
    );
  }

  try {
    defsPromise ??= loadDefinitions(definitionsDir());
    const result = judgeText(parsed.data.placement, parsed.data.text, await defsPromise);
    return new Response(JSON.stringify(result), {
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
    });
  } catch (e) {
    defsPromise = null;
    // Only the kind of error: a message could carry part of the pasted text.
    console.error('byoa failed:', e instanceof Error ? e.name : 'unknown error');
    return jsonError(500, 'The attack could not be checked. Try again.');
  }
}
