/** m13-kiro-evidence: properties of the pure extractor functions (tasks 2.2 to 2.6). */
import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';
import {
  isThisProjectWorkspace,
  parseEventLine,
  redactHomePath,
  redactSecretsDeep,
  truncateToolPayload,
} from '../kiro-evidence.js';

const alnum = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split('');
const alnumStr = (min: number, max: number): fc.Arbitrary<string> =>
  fc.array(fc.constantFrom(...alnum), { minLength: min, maxLength: max }).map((a) => a.join(''));
const segment = alnumStr(1, 12);

describe('Property 1: workspace filter is exhaustive and exclusive', () => {
  const dirs = fc.array(segment, { maxLength: 4 }).map((a) => '/' + a.join('/') + (a.length > 0 ? '/' : ''));
  const sep = fc.constantFrom('', '/', '//');

  it('KE-2 accepts exorcist-98 and exorcist-98-wt-<name> under any parent path', () => {
    const accepted = fc.oneof(
      fc.constant('exorcist-98'),
      fc.string({ minLength: 1, maxLength: 20 }).filter((s) => !/[\\/]/.test(s)).map((n) => `exorcist-98-wt-${n}`),
    );
    fc.assert(
      fc.property(dirs, accepted, sep, (parent, name, trail) => {
        expect(isThisProjectWorkspace(`${parent}${name}${trail}`)).toBe(true);
      }),
    );
  });

  it('KE-2 KE-7 rejects every other final folder name', () => {
    const other = fc
      .string({ minLength: 1, maxLength: 24 })
      .filter((s) => !/[\\/]/.test(s) && s !== 'exorcist-98' && !/^exorcist-98-wt-.+$/.test(s));
    fc.assert(
      fc.property(dirs, other, sep, (parent, name, trail) => {
        expect(isThisProjectWorkspace(`${parent}${name}${trail}`)).toBe(false);
      }),
    );
  });

  it('KE-7 rejects near misses of the project name', () => {
    const near = fc.constantFrom(
      'exorcist-98-wt-', 'exorcist-98-wt', 'exorcist-98x', 'my-exorcist-98', 'Exorcist-98', 'exorcist-97', 'exorcist-98-old', '',
    );
    fc.assert(
      fc.property(dirs, near, (parent, name) => {
        expect(isThisProjectWorkspace(`${parent}${name}`)).toBe(false);
      }),
    );
  });

  it('KE-7 only the final segment counts, not a parent folder named exorcist-98', () => {
    fc.assert(
      fc.property(segment.filter((s) => s !== 'exorcist-98'), (child) => {
        expect(isThisProjectWorkspace(`/home/exorcist-98/${child}`)).toBe(child === 'exorcist-98');
      }),
    );
  });
});

describe('Property 2: tool payloads never exceed the cap and never carry images', () => {
  const IMAGE_KEYS = ['images', 'documents', 'image', 'imageData'];

  function walk(v: unknown, visit: (key: string | null, v: unknown) => void, key: string | null = null): void {
    visit(key, v);
    if (Array.isArray(v)) for (const x of v) walk(x, visit, null);
    else if (typeof v === 'object' && v !== null) for (const [k, x] of Object.entries(v)) walk(x, visit, k);
  }

  const imageish = fc.record({
    data: alnumStr(1, 50),
    mimeType: fc.constantFrom('image/png', 'IMAGE/JPEG', 'image/webp'),
  });
  const payload = fc.record({
    content: fc.string({ maxLength: 6000 }),
    nested: fc.array(fc.record({ text: fc.string({ maxLength: 3000 }) }), { maxLength: 4 }),
    images: fc.array(imageish, { maxLength: 3 }),
    documents: fc.array(fc.string({ maxLength: 20 }), { maxLength: 2 }),
    inline: fc.record({ image: alnumStr(1, 30), imageData: alnumStr(1, 30), note: fc.string({ maxLength: 50 }) }),
    attachments: fc.array(fc.oneof(imageish, fc.constant('data:image/png;base64,AAAA')), { maxLength: 3 }),
  });

  it('KE-3 every string is at most the cap in UTF-8 bytes', () => {
    fc.assert(
      fc.property(payload, fc.integer({ min: 16, max: 2048 }), (p, cap) => {
        const out = truncateToolPayload(p, cap);
        walk(out, (_k, v) => {
          if (typeof v === 'string') expect(Buffer.byteLength(v, 'utf8')).toBeLessThanOrEqual(cap);
        });
      }),
    );
  });

  it('KE-3 the default cap is 2 KB, also for multi-byte text', () => {
    fc.assert(
      fc.property(fc.string({ unit: 'binary', maxLength: 4000 }), (s) => {
        const out = truncateToolPayload({ content: s }) as { content: string };
        expect(Buffer.byteLength(out.content, 'utf8')).toBeLessThanOrEqual(2048);
      }),
    );
  });

  it('KE-3 no image or binary attachment field survives', () => {
    fc.assert(
      fc.property(payload, (p) => {
        const out = truncateToolPayload(p);
        walk(out, (k, v) => {
          if (k !== null) expect(IMAGE_KEYS).not.toContain(k);
          if (typeof v === 'string') expect(v).not.toMatch(/^data:[^;,]*;base64,/i);
          if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
            const mime = (v as Record<string, unknown>)['mimeType'];
            expect(typeof mime === 'string' && mime.toLowerCase().startsWith('image/')).toBe(false);
          }
        });
      }),
    );
  });

  it('KE-3 strings within the cap and non-image fields pass through unchanged', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), fc.integer(), fc.boolean(), (s, n, b) => {
        const input = { content: s, count: n, ok: b, list: [s] };
        expect(truncateToolPayload(input)).toEqual(input);
      }),
    );
  });
});

describe('Property 4: malformed lines never stop export', () => {
  const eventArb = fc.record({
    id: alnumStr(1, 12),
    timestamp: fc.constant('2026-01-01T00:00:00.000Z'),
    payload: fc.record({ type: fc.constantFrom('user', 'tool_call', 'tool_result', 'usage_summary'), n: fc.integer() }),
  });

  it('KE-6 parseEventLine never throws and returns null or a valid envelope', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 300 }), (line) => {
        const ev = parseEventLine(line);
        if (ev !== null) {
          expect(typeof ev.id).toBe('string');
          expect(typeof ev.timestamp).toBe('string');
          expect(typeof ev.payload.type).toBe('string');
        }
      }),
    );
  });

  it('KE-6 a valid envelope line round-trips', () => {
    fc.assert(
      fc.property(eventArb, (ev) => {
        expect(parseEventLine(JSON.stringify(ev))).toEqual(ev);
      }),
    );
  });

  it('KE-6 truncated JSON lines give null and do not hide the valid lines around them', () => {
    fc.assert(
      fc.property(fc.array(fc.tuple(eventArb, fc.boolean(), fc.nat()), { maxLength: 15 }), (items) => {
        const lines: string[] = [];
        const expected: unknown[] = [];
        for (const [ev, corrupt, cut] of items) {
          const text = JSON.stringify(ev);
          if (corrupt) lines.push(text.slice(0, cut % (text.length - 1)));
          else {
            lines.push(text);
            expected.push(ev);
          }
        }
        const kept = lines.map(parseEventLine).filter((e) => e !== null);
        expect(kept).toEqual(expected);
      }),
    );
  });

  it('KE-6 JSON that is not an event envelope gives null', () => {
    fc.assert(
      fc.property(fc.constantFrom('null', '42', '"text"', '[]', '{}', '{"id":"a"}', '{"id":1,"timestamp":"t","payload":{"type":"x"}}', '{"id":"a","timestamp":"t","payload":{}}', ''), (line) => {
        expect(parseEventLine(line)).toBeNull();
      }),
    );
  });
});

describe('Property 5: the home path never survives redaction', () => {
  const home = fc.array(segment, { minLength: 1, maxLength: 3 }).map((a) => '/' + a.join('/'));
  const filler = fc.array(fc.string({ maxLength: 15 }), { maxLength: 5 });

  it('KE-8 no whole copy of the home path remains in the output', () => {
    fc.assert(
      fc.property(home, filler, (h, parts) => {
        // each copy of home is followed by a segment boundary, so every one is a whole path
        const value = parts.map((p) => `${h}/${p}`).join(' | ') + h;
        expect(redactHomePath(value, h)).not.toContain(h);
      }),
    );
  });

  it('KE-8 home that is only the prefix of a longer segment is kept', () => {
    expect(redactHomePath('/R/Ra', '/R')).toBe('~/Ra');
    expect(redactHomePath('/Ra', '/R')).toBe('/Ra');
    expect(redactHomePath('cd /R; ls "/R" (/R)', '/R')).toBe('cd ~; ls "~" (~)');
  });

  it('KE-8 a path under home keeps its remainder behind a ~ prefix', () => {
    fc.assert(
      fc.property(home, fc.array(segment, { maxLength: 4 }), (h, rest) => {
        const tail = rest.map((s) => '/' + s).join('');
        expect(redactHomePath(`${h}${tail}`, h)).toBe(`~${tail}`);
      }),
    );
  });

  it('KE-8 a trailing slash on home is tolerated', () => {
    fc.assert(
      fc.property(home, segment, (h, s) => {
        expect(redactHomePath(`${h}/${s}`, `${h}/`)).toBe(`~/${s}`);
      }),
    );
  });

  it('KE-8 text without the home path is unchanged', () => {
    fc.assert(
      fc.property(home, fc.string({ maxLength: 60 }), (h, s) => {
        fc.pre(!s.includes(h));
        expect(redactHomePath(s, h)).toBe(s);
      }),
    );
  });

  it('KE-8 an empty or root home changes nothing', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 60 }), (s) => {
        expect(redactHomePath(s, '')).toBe(s);
        expect(redactHomePath(s, '/')).toBe(s);
      }),
    );
  });
});

describe('Property 6: no secret shape survives deep redaction', () => {
  const upperNum = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split('');
  const fixed = (chars: string[], n: number): fc.Arbitrary<string> =>
    fc.array(fc.constantFrom(...chars), { minLength: n, maxLength: n }).map((a) => a.join(''));
  const pem = ['PRIVATE', 'KEY'].join(' ');

  const secret = fc.oneof(
    fixed(alnum, 36).map((s) => `ghp_${s}`),
    fixed(upperNum, 16).map((s) => `AKIA${s}`),
    fixed(alnum, 36).map((s) => `npm_${s}`),
    alnumStr(24, 40).map((s) => `sk_live_${s}`),
    alnumStr(40, 60).map((s) => `sk-${s}`),
    fc.tuple(fc.constantFrom('RSA ', 'EC ', ''), alnumStr(10, 40)).map(
      ([k, body]) => `-----BEGIN ${k}${pem}-----\n${body}\n-----END ${k}${pem}-----`,
    ),
  );
  const around = fc.constantFrom('', 'token: ', 'Authorization seen at ', 'x\n');

  type Json = string | number | boolean | null | Json[] | { [k: string]: Json };
  /** Wrap a text in 0 to 3 levels of array / object nesting. */
  const wrap = (text: string, path: number[]): Json => {
    let v: Json = text;
    for (const p of path) v = p % 2 === 0 ? [v, 1, null] : { key: v, other: 'plain', n: p };
    return v;
  };

  it('KE-9 a secret string anywhere in a nested value is gone from the output', () => {
    fc.assert(
      fc.property(secret, around, fc.array(fc.nat(9), { maxLength: 3 }), (s, pre, path) => {
        const out = JSON.stringify(redactSecretsDeep(wrap(`${pre}${s} end`, path)));
        expect(out).not.toContain(s);
        expect(out).toContain('[redacted');
      }),
    );
  });

  it('KE-9 a secret variable assignment loses its value', () => {
    fc.assert(
      fc.property(fixed(alnum, 36), fc.constantFrom('GITHUB_TOKEN', 'OPENAI_API_KEY', 'NPM_TOKEN', 'GH_TOKEN'), (v, name) => {
        const out = redactSecretsDeep({ env: [`${name}=${v}`] });
        expect(JSON.stringify(out)).not.toContain(v);
      }),
    );
  });

  it('KE-9 keys, numbers and secret-free strings are kept', () => {
    fc.assert(
      fc.property(fc.dictionary(segment, fc.oneof(fc.integer(), fc.boolean(), alnumStr(0, 20))), (obj) => {
        expect(redactSecretsDeep(obj)).toEqual(obj);
      }),
    );
  });
});
