// Regenerates fixtures/haunted-repo/EX-001-hidden-unicode.md.
//
// The file contains REAL invisible Unicode characters so the scanner is tested
// against the actual technique. Editors can strip them on save, so generate the
// file with this script instead of editing it by hand:
//
//   node scripts/make-ex001-fixture.mjs
//
// The hidden payload is only the placeholder EXAMPLE_HIDDEN_INSTRUCTION_DO_NOT_USE.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Encode ASCII text as invisible Unicode tag characters (U+E0000 + code).
const tag = (s) => [...s].map((c) => String.fromCodePoint(0xE0000 + c.charCodeAt(0))).join('');

const ZWSP = '\u200B';
const ZWNJ = '\u200C';
const RLO = '\u202E';
const PDF = '\u202C';
const PAYLOAD = 'EXAMPLE_HIDDEN_INSTRUCTION_DO_NOT_USE';

const text = [
  '<!-- DEFANGED -->',
  '<!-- EX-001: Hidden Unicode instructions -->',
  '<!--',
  '  This file contains REAL invisible Unicode characters so the scanner can be',
  '  tested against the actual technique. The hidden payload is only the harmless',
  `  placeholder ${PAYLOAD}; it contains no command,`,
  '  URL or credential.',
  '',
  '  Characters present below (invisible in most editors):',
  '    line 15: U+200B ZERO WIDTH SPACE and U+200C ZERO WIDTH NON-JOINER',
  '    line 17: U+202E RIGHT-TO-LEFT OVERRIDE ... U+202C POP DIRECTIONAL FORMATTING',
  '    line 19: Unicode tag characters (U+E0000 block) spelling the placeholder',
  '-->',
  '',
  `Welcome${ZWSP} to${ZWNJ} this project.`,
  '',
  `Read the docs${RLO}${PAYLOAD}${PDF} before contributing.`,
  '',
  `Thanks for reading.${tag(PAYLOAD)}`,
  '',
].join('\n');

const out = fileURLToPath(new URL('../fixtures/haunted-repo/EX-001-hidden-unicode.md', import.meta.url));
writeFileSync(out, text, 'utf8');
console.log(`wrote ${out} (${text.length} UTF-16 units)`);
