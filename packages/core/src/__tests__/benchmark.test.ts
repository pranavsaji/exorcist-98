import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanRepo } from '../scanner/orchestrator.js';
import type { Finding } from '../types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = fromRoot();
const BENCH = join(ROOT, 'fixtures/benchmark');
const DEFS = join(ROOT, 'definitions');
const labels = JSON.parse(readFileSync(join(BENCH, 'labels.json'), 'utf8')) as { attacks: Record<string, string[]>; benign: string[] };

/**
 * A case name is one plain kebab-case word and must resolve inside its folder.
 * labels.json may be written by an agent (.kiro/agents/exorcist-red-team.json),
 * so a name such as "../../.env" must never make this test read a file
 * outside fixtures/benchmark.
 */
const SAFE_CASE = /^[a-z0-9][a-z0-9-]{0,80}$/;
function caseDir(kind: 'attacks' | 'benign', name: string): string {
  const base = resolve(BENCH, kind);
  const dir = resolve(base, name);
  if (!SAFE_CASE.test(name) || dirname(dir) !== base) throw new Error(`unsafe benchmark case name in labels.json: ${JSON.stringify(name).slice(0, 60)}`);
  return dir;
}

async function findings(dir: string): Promise<Finding[]> {
  const out: Finding[] = [];
  for await (const ev of scanRepo(dir, { definitionsDir: DEFS })) if (ev.type === 'finding') out.push(ev.finding);
  return out;
}

describe('BENCH: labelled detection corpus (fixtures/benchmark)', () => {
  for (const [name, rules] of Object.entries(labels.attacks)) {
    it(`attack ${name} is caught by ${rules.join(' and ')}`, async () => {
      const got = new Set((await findings(caseDir('attacks', name))).map((f) => f.ruleId));
      for (const r of rules) expect([...got], `${name} should trigger ${r}`).toContain(r);
    });
  }
  for (const name of labels.benign) {
    it(`benign ${name} produces no findings`, async () => {
      const got = await findings(caseDir('benign', name));
      // Rule, file and line only: never the matched text.
      expect(got.map((f) => `${f.ruleId} ${f.file}:${f.line}`)).toEqual([]);
    });
  }
});

import { fetchGithubRepo, isSafeRef } from '../remote/tarball.js';
import { fromRoot } from './repo-root.js';
describe('W-020: fetching a ref', () => {
  it('asks GitHub for that ref, and refuses unsafe ones without a request', async () => {
    const urls: string[] = [];
    const fetchImpl = (async (u: string) => { urls.push(u); return { status: 404, ok: false, body: null }; }) as never;
    await fetchGithubRepo({ owner: 'acme', repo: 'widget', dir: '/tmp/x98-ref', ref: 'release/2.0', fetchImpl });
    expect(urls).toEqual(['https://codeload.github.com/acme/widget/tar.gz/release/2.0']);
    const bad = await fetchGithubRepo({ owner: 'acme', repo: 'widget', dir: '/tmp/x98-ref', ref: '../../etc', fetchImpl });
    expect(bad.ok).toBe(false);
    expect(urls).toHaveLength(1);
    expect(isSafeRef('v1.2.3')).toBe(true);
  });
});

describe('benchmark case names are confined to fixtures/benchmark', () => {
  it('rejects traversal and odd names, accepts kebab-case', () => {
    for (const bad of ['../../.env', '..', 'a/b', '.hidden', 'UPPER', 'x'.repeat(90), '']) expect(() => caseDir('attacks', bad)).toThrow(/unsafe benchmark case name/);
    expect(caseDir('benign', 'plain-readme')).toBe(resolve(BENCH, 'benign', 'plain-readme'));
  });
  it('every name in labels.json is safe', () => {
    for (const n of Object.keys(labels.attacks)) expect(() => caseDir('attacks', n)).not.toThrow();
    for (const n of labels.benign) expect(() => caseDir('benign', n)).not.toThrow();
  });
});
