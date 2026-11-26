/**
 * Writes apps/web/src/lib/chain-demo-data.ts: the scripted demo logs with
 * seq/prev/hash computed by the Shield's own eventHash.
 *
 *   pnpm exec tsx scripts/gen-chain-demo.ts
 *
 * A web test regenerates the data and fails if the committed file differs.
 */
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { chainDemoSource } from '../apps/web/src/lib/chain-demo-gen';

const out = fileURLToPath(new URL('../apps/web/src/lib/chain-demo-data.ts', import.meta.url));
writeFileSync(out, chainDemoSource());
console.log(`wrote ${out}`);
