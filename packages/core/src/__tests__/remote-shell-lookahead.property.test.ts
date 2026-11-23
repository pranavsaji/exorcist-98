import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
import { loadDefinitions } from '../definitions/loader.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { fromRoot } from './repo-root.js';

// EX-008 and EX-015 gained a lookahead right after "curl " that only checks a
// "| shell" follows within 1,200 characters. It is there for speed; these
// properties check it changes no match, against the patterns as they were.
const HOST = '(?:https?://|\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b|\\b[A-Za-z0-9-]{1,63}(?:\\.[A-Za-z0-9-]{1,63}){0,8}\\.[A-Za-z]{2,24}\\b)';
const SHELLS: Record<string, string> = { 'EX-008': 'sh|bash|zsh|fish|dash|python3?|node', 'EX-015': 'sh|bash|zsh|fish' };
const lookahead = (id: string): string => `(?=[^\\n]{0,1200}?\\|\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:${SHELLS[id] ?? ''})\\b)`;
const BEFORE: Record<string, string> = {
  'EX-008': `((?:curl|wget)\\s+[^\\n]{0,200}?${HOST}[^\\n]{0,400}?\\|\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:sh|bash|zsh|fish|dash|python3?|node)\\b(?!\\s+-[cemp]\\b)|base64\\s+(-d|--decode|-D)\\b[^\\n]*\\|\\s*(sh|bash|zsh|python3?|node)\\b)`,
  'EX-015': `(?:\\b(?:curl|wget)\\s+[^\\n]{0,200}?${HOST}[^\\n]{0,400}?\\|\\s*(?:sudo\\s+(?:-\\S+\\s+)*)?(?:sh|bash|zsh|fish)\\b(?!\\s+-c\\b)|\\bpowershell(?:\\.exe)?\\s+-e(?:nc|ncodedcommand)\\b|\\b(?:you\\s+must|always|now|first)\\s+run\\s+(?:the\\s+following|this)\\s+(?:command|script))`,
};

const matches = (pattern: string, text: string): Array<[number, string]> => {
  const re = new RegExp(pattern, 'gi');
  const out: Array<[number, string]> = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) { re.lastIndex++; continue; }
    out.push([m.index, m[0]]);
  }
  return out;
};

// Text built from the pieces these patterns care about, plus long filler so
// the 200/400/1,200 character windows are crossed both ways.
const piece = fc.oneof(
  fc.constantFrom('curl ', 'wget -qO- ', 'CURL\t', 'curl\n', ' | ', '|', '| sh', '| bash', '|sudo -E bash', '| python3', '| node -e x',
    '| sh -c', ' sh ', 'https://', 'example.invalid', 'a.b.example.invalid/x.sh', '10.0.0.1', 'base64 -d ', ' -c', '\n', ' ', '.', '-'),
  fc.stringMatching(/^[a-z .\-/]{0,30}$/),
  fc.integer({ min: 0, max: 700 }).map((n) => 'x'.repeat(n)),
  // A whole "download | shell" command with gaps around the window edges.
  fc.tuple(
    fc.constantFrom('curl ', 'wget ', ' curl -fsSL '),
    fc.constantFrom(0, 1, 150, 199, 200, 201, 250).map((n) => ' '.repeat(n)),
    fc.constantFrom('https://example.invalid/x.sh', 'example.invalid', '10.0.0.1', 'nohost'),
    fc.constantFrom(0, 1, 350, 399, 400, 401, 500).map((n) => 'y'.repeat(n)),
    fc.constantFrom(' | sh', '| bash', ' | sudo -E bash', ' | sh -c x', ' | python3', ' | node -e x', ' | cat'),
  ).map((parts) => parts.join('')),
);
const text = fc.array(piece, { maxLength: 30 }).map((p) => p.join(''));

let defs: VirusDefinition[] = [];
beforeAll(async () => { defs = await loadDefinitions(fromRoot('definitions')); });

describe('EX-008 / EX-015: the speed lookahead changes no match', () => {
  for (const id of ['EX-008', 'EX-015']) {
    it(`${id} matches exactly what the pattern without the lookahead matched`, () => {
      const now = defs.find((d) => d.id === id)?.match.regex ?? '';
      // The only change to the rule is the lookahead.
      expect(now).toContain(lookahead(id));
      const before = BEFORE[id] ?? '';
      expect(now.replace(lookahead(id), '')).toBe(before);
      // Still a detector: a far-away pipe (the full 1,200 characters) is caught.
      const far = `curl ${'x'.repeat(199)} a.example.invalid ${'y'.repeat(398)}| sh`;
      expect(matches(now, far)).toHaveLength(1);
      let hits = 0;
      fc.assert(fc.property(text, (t) => {
        const got = matches(now, t);
        hits += got.length;
        expect(got).toEqual(matches(before, t));
      }), { numRuns: 400 });
      expect(hits).toBeGreaterThan(0); // the generator does reach real matches
    });
  }
});
