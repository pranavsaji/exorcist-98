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
/** Variation selectors: emoji (U+FE0F), text (U+FE0E), others and the ideographic supplement. */
const SELECTORS = ['\uFE0F', '\uFE0E', '\uFE00', '\uFE01', '\u{E0100}', '\u{E0101}', '\u{E01EF}'];
const selectorArb = fc.constantFrom(...SELECTORS);
/** A run of selectors long enough to carry bytes (EX-021). */
const smuggledArb = fc.array(selectorArb, { minLength: 4, maxLength: 40 }).map((a) => a.join(''));
/** One to three selectors after a base character: ordinary emoji or CJK presentation. */
const ordinarySelectorsArb = fc.tuple(fc.constantFrom('\u2764', '\u263A', '\u845B', '\u8FBB', 'A'), fc.array(selectorArb, { minLength: 1, maxLength: 3 }))
  .map(([base, vs]) => base + vs.join(''));
const segmentArb = fc.oneof(
  fc.string({ maxLength: 12 }),
  fc.fullUnicodeString({ maxLength: 6 }),
  hiddenArb,
  fc.array(hiddenArb, { minLength: 2, maxLength: 40 }).map((a) => a.join('')),
  smuggledArb,
  ordinarySelectorsArb,
  fc.constantFrom(...EMOJI_SEQUENCES, ...SINGLE_FE0F, ...SPELLING, '\n', ' ', '<!-- -->', 'ب'),
);
const textArb = fc.array(segmentArb, { maxLength: 30 }).map((parts) => parts.join(''));
const roleArb = fc.constantFrom<FileRole>('docs', 'instruction', 'memory', 'config', 'hook');

describe('m5-exorcise EX-001 fixer (REQ-01.1)', () => {
  it('PBT-EXO-01: removing hidden characters leaves the visible text identical and no EX-001 finding', () => {
    fc.assert(fc.property(textArb, roleArb, (text, role) => {
      const r = removeHiddenUnicode(text);
      expect(visible(r.text)).toBe(visible(text));
      expect(scanText(r.text, role, defs).filter((f) => f.ruleId === 'EX-001' || f.ruleId === 'EX-021')).toEqual([]);
      // Only hidden characters are ever taken out, and only once.
      expect(r.removed.every((h) => isHiddenCodePoint(h.codePoint))).toBe(true);
      expect(r.text.length + r.removed.reduce((n, h) => n + h.char.length, 0)).toBe(text.length);
      expect(removeHiddenUnicode(r.text).text).toBe(r.text);
    }), { numRuns: 300 });
  });

  it('PBT-EXO-01: the same holds through exorciseFile driven by a real scan', () => {
    fc.assert(fc.property(textArb, (text) => {
      const findings = scanText(text, 'docs', defs, 'NOTES.md');
      const r = exorciseFile({ file: 'NOTES.md', text, findings, only: new Set(['EX-001', 'EX-021']) });
      expect(visible(r.after)).toBe(visible(text));
      expect(scanText(r.after, 'docs', defs).filter((f) => f.ruleId === 'EX-001' || f.ruleId === 'EX-021')).toEqual([]);
    }), { numRuns: 200 });
  });

  it('PBT-EXO-02: an emoji ZWJ sequence or a single FE0F is never changed', () => {
    const protectedArb = fc.oneof(fc.constantFrom(...EMOJI_SEQUENCES, ...SINGLE_FE0F, ...SPELLING), ordinarySelectorsArb);
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
      ordinarySelectorsArb,
      fc.string({ maxLength: 10 }).filter((s) => Array.from(s).every((c) => !isHiddenCodePoint(c.codePointAt(0) ?? 0))),
    ), { maxLength: 20 }).map((a) => a.join(''));
    fc.assert(fc.property(benignArb, (text) => {
      const r = removeHiddenUnicode(text);
      expect(r.removed).toEqual([]);
      expect(r.text).toBe(text);
    }), { numRuns: 300 });
  });

  it('PBT-EXO-02: one to three variation selectors are never touched; a run of four or more is removed', () => {
    fc.assert(fc.property(fc.array(fc.tuple(ordinarySelectorsArb, smuggledArb), { minLength: 1, maxLength: 8 }), (pairs) => {
      const text = pairs.map(([ok, bad]) => `x${ok}x${bad}`).join('') + 'x';
      const r = removeHiddenUnicode(text);
      expect(r.text).toBe(pairs.map(([ok]) => `x${ok}x`).join('') + 'x');
      expect(r.removed.every((h) => h.class === 'variation-selector')).toBe(true);
    }), { numRuns: 300 });
  });

  it('keeps a byte-order mark at the start of a file', () => {
    expect(removeHiddenUnicode('﻿# Title​').text).toBe('﻿# Title');
  });
});
