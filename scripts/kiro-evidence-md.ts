// Write docs/KIRO_EVIDENCE.md from evidence/kiro-sessions/index.json (m13-kiro-evidence, KE-15 to KE-17).
//   node_modules/.bin/tsx scripts/kiro-evidence-md.ts
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { renderKiroEvidenceMd, type EvidenceIndex } from '../packages/core/src/kiro-evidence-md.ts';

const root = (p: string): string => fileURLToPath(new URL(`../${p}`, import.meta.url));
let index: EvidenceIndex;
try {
  index = JSON.parse(readFileSync(root('evidence/kiro-sessions/index.json'), 'utf8')) as EvidenceIndex;
} catch {
  process.stderr.write('kiro-evidence-md: evidence/kiro-sessions/index.json is missing or not JSON; run scripts/kiro-evidence.mjs first\n');
  process.exit(1);
}
if (!Array.isArray(index.sessions) || typeof index.totals !== 'object' || index.totals === null) {
  process.stderr.write('kiro-evidence-md: index.json does not have the expected shape\n');
  process.exit(1);
}
writeFileSync(root('docs/KIRO_EVIDENCE.md'), renderKiroEvidenceMd(index));
