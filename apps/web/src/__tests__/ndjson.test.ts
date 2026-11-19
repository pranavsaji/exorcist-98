import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { NdjsonParser, parseNdjsonStream } from '@/lib/ndjson';
import type { ParseResult } from '@/lib/ndjson';
import type { ScanEventMsg } from '@/lib/protocol';

const events: ScanEventMsg[] = [
  { type: 'start', target: 'Haunted Repo' },
  { type: 'file', rel: 'EX-001-hidden-unicode.md', role: 'docs' },
  { type: 'error', file: 'a.md', message: 'caf\u00e9 \u{1F47B} ünïcode' },
  { type: 'done', stats: { filesScanned: 1, filesSkipped: 0, findingsTotal: 0, durationMs: 3 } },
];
const wire = events.map((e) => JSON.stringify(e)).join('\n') + '\n';
const bytes = new TextEncoder().encode(wire);

function parseWhole(): ParseResult[] {
  const p = new NdjsonParser();
  return [...p.push(bytes), ...p.flush()];
}

function parseSplit(cuts: number[]): ParseResult[] {
  const points = [...new Set(cuts.map((c) => c % (bytes.length + 1)))].sort((a, b) => a - b);
  const p = new NdjsonParser();
  const out: ParseResult[] = [];
  let prev = 0;
  for (const c of [...points, bytes.length]) {
    out.push(...p.push(bytes.slice(prev, c)));
    prev = c;
  }
  out.push(...p.flush());
  return out;
}

describe('NdjsonParser', () => {
  it('parses every event of a whole stream', () => {
    const r = parseWhole();
    expect(r.every((x) => x.ok)).toBe(true);
    expect(r.map((x) => (x.ok ? x.event : null))).toEqual(events);
  });

  it('reports a bad JSON line and an unexpected shape as typed errors, not exceptions', () => {
    const p = new NdjsonParser();
    const r = [
      ...p.push(new TextEncoder().encode('not json\n{"type":"nope"}\n')),
      ...p.flush(),
    ];
    expect(r).toHaveLength(2);
    expect(r.every((x) => !x.ok)).toBe(true);
  });

  it('parses a last line that has no trailing newline', () => {
    const p = new NdjsonParser();
    const r = [
      ...p.push(new TextEncoder().encode(JSON.stringify(events[0]))),
      ...p.flush(),
    ];
    expect(r).toHaveLength(1);
  });

  it('reads a ReadableStream end to end', async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        c.enqueue(bytes.slice(0, 7));
        c.enqueue(bytes.slice(7));
        c.close();
      },
    });
    const out: ParseResult[] = [];
    for await (const r of parseNdjsonStream(stream)) out.push(r);
    expect(out.map((x) => (x.ok ? x.event : null))).toEqual(events);
  });

  it('PBT-WEB-01: any byte-level chunking yields the same events as parsing the whole stream', () => {
    const whole = parseWhole();
    fc.assert(
      fc.property(fc.array(fc.nat(bytes.length), { maxLength: 12 }), (cuts) => {
        expect(parseSplit(cuts)).toEqual(whole);
        return true;
      }),
    );
  });
});
