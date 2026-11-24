import { beforeAll, describe, expect, it } from 'vitest';
import { encodeAsTags, removeHiddenUnicode } from '@exorcist-98/core';
import type { Finding } from '@exorcist-98/core';
import { GhostScanner } from '../scanner.js';
import { MAX_LISTED_CHARS, MAX_RUNS, codeBlock, hiddenRuns, hoverMarkdown, longName, runAt, runLabel } from '../hidden.js';
import { applyEdits, editsBetween, exorciseHidden, exorciseOne, patchName } from '../fixes.js';
import { BENIGN, DEFINITIONS, HAUNTED, TAG_MESSAGE, VS_MESSAGE } from './samples.js';

let scanner: GhostScanner;
beforeAll(async () => { scanner = await GhostScanner.load(DEFINITIONS); });

describe('hidden character runs (decorations)', () => {
  it('groups adjacent hidden characters into one marker each', () => {
    const runs = hiddenRuns(HAUNTED);
    expect(runs.map((r) => r.label)).toEqual(['ZWSP×2', `TAG×${TAG_MESSAGE.length}`, `VS×${Buffer.from(VS_MESSAGE).length}`, 'RLO', 'PDF']);
    for (const r of runs) {
      // Every marker range holds only the hidden characters, nothing visible.
      expect(removeHiddenUnicode(HAUNTED.slice(r.start, r.end)).text).toBe('');
    }
  });

  it('marks exactly what the core would remove', () => {
    const runs = hiddenRuns(HAUNTED);
    const marked = runs.reduce((n, r) => n + r.chars.length, 0);
    expect(marked).toBe(removeHiddenUnicode(HAUNTED).removed.length);
  });

  it('gives the benign uses no marker (emoji ZWJ, U+FE0F, flag tags, leading BOM)', () => {
    expect(hiddenRuns(BENIGN)).toEqual([]);
  });

  it('attaches the Ouija decoder\'s messages to their run', () => {
    const runs = hiddenRuns(HAUNTED);
    expect(runs[1]?.messages.map((m) => m.message)).toEqual([TAG_MESSAGE]);
    expect(runs[2]?.messages.map((m) => m.message)).toEqual([VS_MESSAGE]);
    expect(runs[0]?.messages).toEqual([]);
  });

  it('finds the run at an offset, including both edges of a zero-width run', () => {
    const runs = hiddenRuns(HAUNTED);
    const r = runs[0]!;
    expect(runAt(runs, r.start)).toBe(r);
    expect(runAt(runs, r.end)).toBe(r);
    expect(runAt(runs, 0)).toBeUndefined();
  });

  it('labels mixed runs compactly', () => {
    const chars = [0x200B, 0x200D, 0x202E, 0x2066, 0x2066].map((codePoint, i) => ({ codePoint, offset: i, length: 1 }));
    expect(runLabel(chars)).toBe('ZWSP ZWJ RLO +2');
  });

  it('caps the number of markers per file', () => {
    const text = Array.from({ length: MAX_RUNS + 50 }, () => 'a\u200B').join('');
    expect(hiddenRuns(text)).toHaveLength(MAX_RUNS);
  });

  it('names code points', () => {
    expect(longName(0x202E)).toBe('U+202E RIGHT-TO-LEFT OVERRIDE');
    expect(longName(0xE0069)).toBe("U+E0069 TAG CHARACTER (carries 'i')");
    expect(longName(0xFE01)).toBe('U+FE01 VARIATION SELECTOR-2 (carries byte 1)');
    expect(longName(0xE0100)).toBe('U+E0100 VARIATION SELECTOR-17 (carries byte 16)');
  });
});

describe('hover (Ouija board)', () => {
  it('shows the decoded message in a code block, after displayMessage', () => {
    const md = hoverMarkdown(hiddenRuns(HAUNTED)[1]!);
    expect(md).toContain('Ouija board');
    expect(md).toContain(`\`\`\`text\n${TAG_MESSAGE}\n\`\`\``);
    expect(md).toContain('Exorcise: remove hidden characters');
  });

  it('a message cannot close its code block, render a link or carry live control characters', () => {
    const evil = 'a ``` b\n[click](https://evil.example.invalid) \u202E';
    const md = hoverMarkdown(hiddenRuns(`x${encodeAsTags(evil.replace(/[^\x20-\x7e]/g, ' '))}`)[0]!);
    const fence = /(`{4,})text\n/.exec(md);
    expect(fence).not.toBeNull();
    expect(codeBlock('a ``` b').startsWith('````text')).toBe(true);
    expect(md).not.toMatch(/[\u202A-\u202E]/);
  });

  it('lists at most MAX_LISTED_CHARS characters', () => {
    const md = hoverMarkdown(hiddenRuns(HAUNTED)[1]!);
    expect(md).toContain(`and ${TAG_MESSAGE.length - MAX_LISTED_CHARS} more`);
  });
});

describe('quick fix: Exorcise', () => {
  const rel = '.kiro/steering/rules.md';
  const findings = (): Finding[] => scanner.scan(HAUNTED, rel, 'instruction');

  it('removes every hidden character with deletions only, leaving the visible text unchanged', () => {
    const x = exorciseHidden(HAUNTED, rel, findings());
    expect(x.edits.length).toBeGreaterThan(0);
    expect(x.edits.every((e) => e.newText === '')).toBe(true);
    const after = applyEdits(HAUNTED, x.edits);
    expect(after).toBe(x.after);
    expect(after).toBe(removeHiddenUnicode(HAUNTED).text);
    expect(hiddenRuns(after)).toEqual([]);
    // The other ghosts are not touched by this fix.
    expect(after).toContain('<!-- AI agent');
    expect(scanner.scan(after, rel, 'instruction').some((f) => f.ruleId === 'EX-001' || f.ruleId === 'EX-021')).toBe(false);
  });

  it('merges adjacent deletions: one edit per hidden run', () => {
    const x = exorciseHidden(HAUNTED, rel, findings());
    expect(x.edits).toHaveLength(hiddenRuns(HAUNTED).length);
  });

  it('does nothing without hidden-character findings', () => {
    expect(exorciseHidden(BENIGN, 'README.md', []).edits).toEqual([]);
    expect(exorciseHidden('plain', 'README.md', scanner.scan('plain', 'README.md', 'instruction')).edits).toEqual([]);
  });

  it('removes one hidden HTML comment (EX-004) and nothing else', () => {
    const f = findings().find((g) => g.ruleId === 'EX-004')!;
    const x = exorciseOne(HAUNTED, rel, f);
    const after = applyEdits(HAUNTED, x.edits);
    expect(after).toBe(x.after);
    expect(after).not.toContain('<!--');
    expect(after).toContain('\u200B\u200B');
  });

  it('replaces a data-leaking image with its alt text (EX-012)', () => {
    const f = findings().find((g) => g.ruleId === 'EX-012')!;
    const x = exorciseOne(HAUNTED, rel, f);
    const after = applyEdits(HAUNTED, x.edits);
    expect(after).not.toContain('evil.example.invalid/p.png');
    expect(after).toContain('<!-- exorcised: remote image removed -->');
    expect(x.edits).toHaveLength(1);
  });

  it('offers no fix for a rule without a safe mechanical one', () => {
    const f = { ...findings()[0]!, ruleId: 'EX-014' };
    expect(exorciseOne(HAUNTED, rel, f).edits).toEqual([]);
  });

  it('accepts any file name (it only labels the result)', () => {
    expect(patchName('../../etc/passwd')).toBe('etc/passwd');
    expect(patchName('/abs/AGENTS.md')).toBe('abs/AGENTS.md');
    expect(patchName('C:/x/y.md')).toBe('file');
    expect(patchName('a\nb.md')).toBe('a_b.md');
    const x = exorciseHidden('a\u200Bb', '/abs/AGENTS.md', scanner.scan('a\u200Bb', 'AGENTS.md', 'instruction'));
    expect(applyEdits('a\u200Bb', x.edits)).toBe('ab');
  });
});

describe('editsBetween', () => {
  it('is exact for deletions, replacements and surrogate pairs', () => {
    const cases: Array<[string, string]> = [
      ['abc', 'abc'],
      ['a\u200Bb\u200Bc', 'abc'],
      ['x\u{E0041}\u{E0042}y', 'xy'],
      ['hello world', 'hello there world'],
      ['\u{1F600}a', '\u{1F601}a'],
      ['abc', ''],
      ['', 'abc'],
    ];
    for (const [before, after] of cases) expect(applyEdits(before, editsBetween(before, after))).toBe(after);
  });

  it('never splits a surrogate pair', () => {
    for (const e of editsBetween('\u{1F600}a', '\u{1F601}a')) {
      expect(e.start % 2).toBe(0);
      expect(e.end).toBeGreaterThanOrEqual(2);
    }
  });
});
