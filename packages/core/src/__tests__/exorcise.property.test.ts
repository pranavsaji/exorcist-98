import { beforeAll, describe, expect, it } from 'vitest';
import * as fc from 'fast-check';
import { loadDefinitions } from '../definitions/loader.js';
import { scanText } from '../scanner/scan-text.js';
import { isHiddenCodePoint } from '../normalizer.js';
import { exorciseFile, removeHiddenUnicode } from '../exorcise.js';
import type { VirusDefinition } from '../definitions/schema.js';
import type { FileRole } from '../types.js';
import { fromRoot } from './repo-root.js';

let defs: VirusDefinition[] = [];
beforeAll(async () => { defs = await loadDefinitions(fromRoot('definitions')); });

/** The text a reader sees: every zero-width, bidi-control and tag character taken out. */
const visible = (s: string): string => Array.from(s).filter((c) => !isHiddenCodePoint(c.codePointAt(0) ?? 0)).join('');

const HIDDEN = [
  '​', '‌', '‍', '﻿', '⁠', '⁡', '⁢', '⁣', '⁤', '᠎',
  '‪', '‫', '‬', '‭', '‮', '⁦', '⁧', '⁨', '⁩',
  '\u{E0001}', '\u{E0041}', '\u{E0067}', '\u{E007F}',
];
const EMOJI_SEQUENCES = [
  '\u{1F468}‍\u{1F469}‍\u{1F467}', // family
  '\u{1F3F3}️‍\u{1F308}',          // rainbow flag
  '\u{1F469}\u{1F3FD}‍\u{1F4BB}',       // technologist, skin tone
  '\u{1F9D1}‍\u{1F527}',                // mechanic
  '\u{1F441}️‍\u{1F5E8}️',    // eye in speech bubble
  '\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}', // England flag
];
const SINGLE_FE0F = ['❤️', '☺️', '✅', '#️⃣', '✨️'];
const SPELLING = ['می‌خواهم', 'क्‍ष']; // Persian, Devanagari

const hiddenArb = fc.constantFrom(...HIDDEN);
const segmentArb = fc.oneof(
  fc.string({ maxLength: 12 }),
  fc.fullUnicodeString({ maxLength: 6 }),
  hiddenArb,
  fc.array(hiddenArb, { minLength: 2, maxLength: 40 }).map((a) => a.join('')),
  fc.constantFrom(...EMOJI_SEQUENCES, ...SINGLE_FE0F, ...SPELLING, '\n', ' ', '<!-- -->', 'ب'),
);
const textArb = fc.array(segmentArb, { maxLength: 30 }).map((parts) => parts.join(''));
const roleArb = fc.constantFrom<FileRole>('docs', 'instruction', 'memory', 'config', 'hook');

describe('m5-exorcise EX-001 fixer (REQ-01.1)', () => {
  it('PBT-EXO-01: removing hidden characters leaves the visible text identical and no EX-001 finding', () => {
    fc.assert(fc.property(textArb, roleArb, (text, role) => {
      const r = removeHiddenUnicode(text);
      expect(visible(r.text)).toBe(visible(text));
      expect(scanText(r.text, role, defs).filter((f) => f.ruleId === 'EX-001')).toEqual([]);
      // Only hidden characters are ever taken out, and only once.
      expect(r.removed.every((h) => isHiddenCodePoint(h.codePoint))).toBe(true);
      expect(r.text.length + r.removed.reduce((n, h) => n + h.char.length, 0)).toBe(text.length);
      expect(removeHiddenUnicode(r.text).text).toBe(r.text);
    }), { numRuns: 300 });
  });

  it('PBT-EXO-01: the same holds through exorciseFile driven by a real scan', () => {
    fc.assert(fc.property(textArb, (text) => {
      const findings = scanText(text, 'docs', defs, 'NOTES.md');
      const r = exorciseFile({ file: 'NOTES.md', text, findings, only: new Set(['EX-001']) });
      expect(visible(r.after)).toBe(visible(text));
      expect(scanText(r.after, 'docs', defs).filter((f) => f.ruleId === 'EX-001')).toEqual([]);
    }), { numRuns: 200 });
  });

  it('PBT-EXO-02: an emoji ZWJ sequence or a single FE0F is never changed', () => {
    const protectedArb = fc.constantFrom(...EMOJI_SEQUENCES, ...SINGLE_FE0F, ...SPELLING);
    const around = fc.oneof(fc.string({ maxLength: 8 }), hiddenArb, fc.array(hiddenArb, { maxLength: 6 }).map((a) => a.join('')));
    fc.assert(fc.property(fc.array(fc.tuple(around, protectedArb), { minLength: 1, maxLength: 12 }), around, (pairs, tail) => {
      // Every protected sequence is separated from the next by a visible letter,
      // so the hidden characters around it are never part of it.
      const text = pairs.map(([a, p]) => `${a}x${p}x`).join('') + tail;
      const out = removeHiddenUnicode(text).text;
      let from = 0;
      for (const [, p] of pairs) {
        const i = out.indexOf(`x${p}x`, from);
        expect(i, `sequence ${JSON.stringify(p)} survives`).toBeGreaterThanOrEqual(0);
        from = i + p.length + 1;
      }
    }), { numRuns: 300 });
  });

  it('PBT-EXO-02: text with only emoji sequences, single FE0F and real spelling is returned unchanged', () => {
    const benignArb = fc.array(fc.oneof(
      fc.constantFrom(...EMOJI_SEQUENCES, ...SINGLE_FE0F, ...SPELLING, ' ', '\n'),
      fc.string({ maxLength: 10 }).filter((s) => Array.from(s).every((c) => !isHiddenCodePoint(c.codePointAt(0) ?? 0))),
    ), { maxLength: 20 }).map((a) => a.join(''));
    fc.assert(fc.property(benignArb, (text) => {
      const r = removeHiddenUnicode(text);
      expect(r.removed).toEqual([]);
      expect(r.text).toBe(text);
    }), { numRuns: 300 });
  });

  it('keeps a byte-order mark at the start of a file', () => {
    expect(removeHiddenUnicode('﻿# Title​').text).toBe('﻿# Title');
  });
});
