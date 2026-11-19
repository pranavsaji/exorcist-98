import { ScanEventSchema } from './protocol';
import type { ScanEventMsg } from './protocol';

export type ParseResult =
  | { ok: true;  event: ScanEventMsg }
  | { ok: false; error: string };

/**
 * Incremental NDJSON parser. Feed it bytes in any chunking; it returns the
 * events completed so far. Multi-byte characters split across chunks are
 * handled by a streaming TextDecoder.
 */
export class NdjsonParser {
  private readonly decoder = new TextDecoder('utf-8');
  private buffer = '';

  push(bytes: Uint8Array): ParseResult[] {
    this.buffer += this.decoder.decode(bytes, { stream: true });
    return this.drain(false);
  }

  /** Call once at end of stream to parse a final line without a newline. */
  flush(): ParseResult[] {
    this.buffer += this.decoder.decode();
    return this.drain(true);
  }

  private drain(final: boolean): ParseResult[] {
    const results: ParseResult[] = [];
    let nl = this.buffer.indexOf('\n');
    while (nl !== -1) {
      const line = this.buffer.slice(0, nl);
      this.buffer = this.buffer.slice(nl + 1);
      const r = parseLine(line);
      if (r) results.push(r);
      nl = this.buffer.indexOf('\n');
    }
    if (final && this.buffer.trim().length > 0) {
      const r = parseLine(this.buffer);
      this.buffer = '';
      if (r) results.push(r);
    }
    return results;
  }
}

function parseLine(line: string): ParseResult | null {
  const trimmed = line.trim();
  if (trimmed.length === 0) return null;
  let json: unknown;
  try {
    json = JSON.parse(trimmed);
  } catch {
    return { ok: false, error: 'A line in the scan stream was not valid JSON.' };
  }
  const parsed = ScanEventSchema.safeParse(json);
  if (!parsed.success) {
    return { ok: false, error: 'An event in the scan stream had an unexpected shape.' };
  }
  return { ok: true, event: parsed.data };
}

/** Read a fetch body to the end, yielding validated events. */
export async function* parseNdjsonStream(
  stream: ReadableStream<Uint8Array>,
): AsyncGenerator<ParseResult> {
  const reader = stream.getReader();
  const parser = new NdjsonParser();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      for (const r of parser.push(value)) yield r;
    }
    for (const r of parser.flush()) yield r;
  } finally {
    reader.releaseLock();
  }
}
