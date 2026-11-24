// Write docs/HOW_KIRO.md from apps/web/src/lib/how-kiro.ts (the /how-kiro page's content).
//   node_modules/.bin/tsx scripts/how-kiro-md.ts
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { howKiroMarkdown } from '../apps/web/src/lib/how-kiro.ts';

writeFileSync(fileURLToPath(new URL('../docs/HOW_KIRO.md', import.meta.url)), howKiroMarkdown());
