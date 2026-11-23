/**
 * Read a request body, stopping as soon as it passes `max` bytes: the reader
 * is cancelled at once, so an oversized or endless body is never buffered.
 * Returns null when the cap was passed.
 */
export async function readCapped(request: Request, max: number): Promise<Buffer | null> {
  if (!request.body) return Buffer.alloc(0);
  const reader = request.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > max) { await reader.cancel().catch(() => undefined); return null; }
    parts.push(value);
  }
  return Buffer.concat(parts);
}
