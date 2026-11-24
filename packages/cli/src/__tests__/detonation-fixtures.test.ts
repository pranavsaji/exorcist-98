import { describe, expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDefinitions, scanRepo, scanText } from '@exorcist-98/core';
import type { FileRole } from '@exorcist-98/core';
import { PLACEMENTS } from '@exorcist-98/core/llm';
import { detectParaphrase } from '@exorcist-98/shield';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const DEFS = join(ROOT, 'definitions');

type Entry = { file: string; placement: string };
const ALL_ROLES: FileRole[] = ['instruction', 'docs', 'memory', 'tool-result', 'mcp-config', 'config', 'code', 'unknown'];
const ROLES_FOR: Record<string, FileRole[]> = { file: ['instruction', 'docs', 'memory'], 'tool-result': ['tool-result'], 'tool-description': ['tool-result'] };

// fixtures/detonation: the evidence set (its misses were studied to improve the judge).
// fixtures/judge-holdout: written before the judge's prompt changed, never tuned on.
for (const setName of ['detonation', 'judge-holdout']) {
const SET = join(ROOT, 'fixtures', setName);
const labels = JSON.parse(readFileSync(join(SET, 'labels.json'), 'utf8')) as { attacks: Entry[]; benign: Entry[] };
describe(`REQ-03.1 the ${setName} evidence set`, () => {
  it('has 10 attacks and 10 benign look-alikes, every file labelled once with a valid placement', () => {
    expect(labels.attacks).toHaveLength(10);
    expect(labels.benign).toHaveLength(10);
    const onDisk = ['attacks', 'benign'].flatMap((d) => readdirSync(join(SET, d)).map((f) => `${d}/${f}`)).sort();
    expect([...labels.attacks, ...labels.benign].map((e) => e.file).sort()).toEqual(onDisk);
    for (const e of [...labels.attacks, ...labels.benign]) expect(PLACEMENTS).toContain(e.placement);
  });

  it('is defanged: only example.invalid hosts, no token shapes', () => {
    for (const e of [...labels.attacks, ...labels.benign]) {
      const t = readFileSync(join(SET, e.file), 'utf8');
      for (const m of t.matchAll(/https?:\/\/([\w.-]+)/g)) expect(m[1], e.file).toMatch(/(^|\.)example\.invalid$/);
      expect(t, e.file).not.toMatch(/AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}|BEGIN [A-Z ]*PRIVATE KEY/);
    }
  });

  it('no signature catches any attack, in any file role (they are reworded on purpose)', async () => {
    const defs = await loadDefinitions(DEFS);
    for (const e of labels.attacks) {
      const t = readFileSync(join(SET, e.file), 'utf8');
      const hits = ALL_ROLES.flatMap((role) => scanText(t, role, defs, e.file).map((f) => `${f.ruleId} as ${role}`));
      expect(hits, `${e.file} is now caught by a signature; replace it with another reworded attack`).toEqual([]);
    }
  });

  it('the Shield paraphrase detector does not block any attack either', () => {
    for (const e of labels.attacks) expect(detectParaphrase(readFileSync(join(SET, e.file), 'utf8')).level, e.file).not.toBe('block');
  });

  it('a full scan of the set finds nothing, and the benign files are clean where they are placed', async () => {
    const found: string[] = [];
    for await (const ev of scanRepo(SET, { definitionsDir: DEFS })) if (ev.type === 'finding') found.push(`${ev.finding.ruleId} ${ev.finding.file}`);
    expect(found).toEqual([]);
    const defs = await loadDefinitions(DEFS);
    for (const e of labels.benign) {
      const t = readFileSync(join(SET, e.file), 'utf8');
      const hits = (ROLES_FOR[e.placement] ?? []).flatMap((role) => scanText(t, role, defs, e.file).map((f) => f.ruleId));
      expect(hits, e.file).toEqual([]);
    }
  });
});
}
