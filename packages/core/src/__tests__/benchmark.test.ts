import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepo } from '../scanner/orchestrator.js';
import type { Finding } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const BENCH = join(ROOT, 'fixtures/benchmark');
const DEFS = join(ROOT, 'definitions');
const labels = JSON.parse(readFileSync(join(BENCH, 'labels.json'), 'utf8')) as { attacks: Record<string, string[]>; benign: string[] };

async function findings(dir: string): Promise<Finding[]> {
  const out: Finding[] = [];
  for await (const ev of scanRepo(dir, { definitionsDir: DEFS })) if (ev.type === 'finding') out.push(ev.finding);
  return out;
}

describe('BENCH: labelled detection corpus (fixtures/benchmark)', () => {
  for (const [name, rules] of Object.entries(labels.attacks)) {
    it(`attack ${name} is caught by ${rules.join(' and ')}`, async () => {
      const got = new Set((await findings(join(BENCH, 'attacks', name))).map((f) => f.ruleId));
      for (const r of rules) expect([...got], `${name} should trigger ${r}`).toContain(r);
    });
  }
  for (const name of labels.benign) {
    it(`benign ${name} produces no findings`, async () => {
      const got = await findings(join(BENCH, 'benign', name));
      expect(got.map((f) => `${f.ruleId} ${f.file}:${f.line} ${f.span}`)).toEqual([]);
    });
  }
});
