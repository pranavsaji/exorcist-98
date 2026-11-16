import { describe, it, expect } from 'vitest';
import { normalize } from '../normalizer.js';

describe('normalize — hiddenUnicode', () => {
  it('detects U+200B zero-width space', () => {
    const result = normalize('hello\u200Bworld', 'docs');
    expect(result.hiddenUnicode).toHaveLength(1);
    expect(result.hiddenUnicode[0]?.class).toBe('zero-width');
    expect(result.hiddenUnicode[0]?.codePoint).toBe(0x200B);
  });

  it('detects U+202E bidi-override', () => {
    const result = normalize('a\u202Eb', 'docs');
    expect(result.hiddenUnicode.some(h => h.class === 'bidi-override')).toBe(true);
  });

  it('detects U+E0041 tag-block character', () => {
    const tagChar = String.fromCodePoint(0xE0041);
    const result = normalize(`hello${tagChar}world`, 'docs');
    expect(result.hiddenUnicode.some(h => h.class === 'tag-block')).toBe(true);
  });

  it('clean ASCII string has no hiddenUnicode hits', () => {
    const result = normalize('Hello, world! 123.', 'docs');
    expect(result.hiddenUnicode).toHaveLength(0);
  });
});

describe('normalize — comments', () => {
  it('extracts HTML comment body', () => {
    const result = normalize('before <!-- hidden text --> after', 'docs');
    expect(result.comments).toContain('hidden text');
  });

  it('extracts block comment body', () => {
    const result = normalize('code /* block comment */ more', 'code');
    expect(result.comments).toContain('block comment');
  });

  it('ignores empty HTML comments', () => {
    const result = normalize('<!---->', 'docs');
    expect(result.comments).toHaveLength(0);
  });
});

describe('normalize — entities', () => {
  it('decodes &amp; to &', () => {
    expect(normalize('a &amp; b', 'docs').plain).toBe('a & b');
  });
  it('decodes &lt; to <', () => {
    expect(normalize('&lt;tag&gt;', 'docs').plain).toBe('<tag>');
  });
  it('decodes &#65; to A', () => {
    expect(normalize('&#65;', 'docs').plain).toBe('A');
  });
  it('decodes &#x41; to A', () => {
    expect(normalize('&#x41;', 'docs').plain).toBe('A');
  });
});

describe('normalize — base64Candidates', () => {
  it('a 40-char base64 string is included as a candidate', () => {
    const b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn';
    const result = normalize(` ${b64} `, 'docs');
    expect(result.base64Candidates).toContain(b64);
  });

  it('a string shorter than 32 chars is NOT a candidate', () => {
    const short = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcde'; // 31 chars
    const result = normalize(` ${short} `, 'docs');
    expect(result.base64Candidates).toHaveLength(0);
  });

  it('a sha256: prefixed blob is excluded', () => {
    const b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn';
    const result = normalize(`sha256:${b64}`, 'docs');
    expect(result.base64Candidates).not.toContain(b64);
  });

  it('original text is preserved unchanged', () => {
    const text = 'Hello\u200Bworld';
    expect(normalize(text, 'docs').original).toBe(text);
  });
});
