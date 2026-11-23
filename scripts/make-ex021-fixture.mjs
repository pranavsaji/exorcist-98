// Regenerates fixtures/haunted-repo/EX-021-smuggled-bytes.md.
//
// The file contains REAL variation selectors ("emoji smuggling") so the
// scanner is tested against the actual technique. Editors can strip them on
// save, so generate the file with this script instead of editing it by hand:
//
//   node scripts/make-ex021-fixture.mjs
//
// The hidden payload is only the placeholder "DEFANGED: placeholder message".
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Each byte rides on one variation selector: U+FE00-FE0F carry 0-15,
// U+E0100-E01EF carry 16-255 (the Ouija decoder reads them back).
const smuggle = (s) =>
  [...new TextEncoder().encode(s)].map((b) => String.fromCodePoint(b < 16 ? 0xFE00 + b : 0xE0100 + b - 16)).join('');

const PAYLOAD = 'DEFANGED: placeholder message';

const text = [
  '<!-- DEFANGED -->',
  '<!-- EX-021: Smuggled bytes in variation selectors -->',
  '<!--',
  '  This file carries REAL variation selectors so the scanner can be tested',
  '  against the actual technique. The hidden payload decodes to the harmless',
  `  placeholder text "${PAYLOAD}"; it contains no command,`,
  '  URL or credential.',
  '',
  '  The bytes ride on variation selectors after the star emoji on the last',
  '  line (invisible in most editors).',
  '-->',
  '',
  'Thanks for reading this file. The sentence is ordinary, and the emoji after it',
  `carries the payload: ⭐${smuggle(PAYLOAD)}`,
  '',
].join('\n');

const out = fileURLToPath(new URL('../fixtures/haunted-repo/EX-021-smuggled-bytes.md', import.meta.url));
writeFileSync(out, text, 'utf8');
console.log(`wrote ${out} (${text.length} UTF-16 units)`);
