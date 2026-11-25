import { describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { fromRoot } from './repo-root.js';

// docs/facts.json is the one source for every number the documents quote
// (scripts/facts.mjs). These tests fail when a document or the web copy
// disagrees with it, or when the file no longer matches the repository.
interface FactsModule {
  DOCS: string[];
  compute: (args?: string[]) => Record<string, unknown>;
  disagreements: (text: string, facts: Record<string, unknown>) => Array<{ key: string; found: string; expected: string }>;
}
const modulePath = pathToFileURL(fromRoot('scripts/facts.mjs')).href;
const load = async (): Promise<FactsModule> => (await import(/* @vite-ignore */ modulePath)) as FactsModule;
const read = (rel: string): string => readFileSync(fromRoot(rel), 'utf8');
const facts = (): Record<string, unknown> => JSON.parse(read('docs/facts.json')) as Record<string, unknown>;

describe('FACTS: one source for every number', () => {
  it('docs/facts.json matches what can be counted in the repository (run `node scripts/facts.mjs` to refresh)', async () => {
    const m = await load();
    expect(facts()).toEqual(m.compute([]));
  });

  it('the web app imports an identical copy', () => {
    expect(read('apps/web/src/lib/facts.json')).toBe(read('docs/facts.json'));
  });

  it('only passing runs are recorded: scripts/facts.mjs refuses a test report or a browser log with failures', async () => {
    const m = (await load()) as FactsModule & { fromReport: (p: string) => unknown; fromE2eLog: (p: string) => unknown };
    const dir = mkdtempSync(join(tmpdir(), 'x98-facts-test-'));
    try {
      const report = join(dir, 'r.json');
      const ok = { fullName: 'a passes', status: 'passed' };
      writeFileSync(report, JSON.stringify({ numPassedTests: 1, numFailedTests: 1, testResults: [{ assertionResults: [ok, { fullName: 'b fails', status: 'failed' }] }] }));
      expect(() => m.fromReport(report)).toThrow(/failing/);
      writeFileSync(report, JSON.stringify({ numPassedTests: 1, numFailedTests: 0, testResults: [{ assertionResults: [ok] }] }));
      expect(m.fromReport(report)).toMatchObject({ tests: 1, testFiles: 1 });
      const log = join(dir, 'e2e.log');
      writeFileSync(log, 'PASS  one\nFAIL  two\naxe violation types: 0\n');
      expect(() => m.fromE2eLog(log)).toThrow(/failing/);
      writeFileSync(log, 'PASS  one\nPASS  two\naxe violation types: 0\n');
      expect(m.fromE2eLog(log)).toEqual({ browserSteps: 2, browserAxeViolationTypes: 0 });
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('every number marked in a document equals the fact', async () => {
    const m = await load();
    const bad: string[] = [];
    for (const d of m.DOCS) for (const x of m.disagreements(read(d), facts())) bad.push(`${d}: ${x.key} says ${x.found}, facts say ${x.expected}`);
    expect(bad).toEqual([]);
  });

  it('the README, the submission text and the video script have no unmarked count of tests, definitions, specs, steering files or hooks', () => {
    const counted = /\b\d[\d,]*\+?\s+(?:[a-z-]+\s+){0,2}(?:tests|passing|properties|property-based|fast-check|definitions|signatures|specs|steering files|hooks)\b/gi;
    const bad: string[] = [];
    for (const d of ['README.md', 'docs/SUBMISSION.md', 'docs/VIDEO_SCRIPT.md', 'docs/REFERENCE.md']) {
      const text = read(d).replace(/<!--f:[^>]*-->[^]*?<!--\/f-->/g, '');
      for (const m of text.matchAll(counted)) bad.push(`${d}: "${m[0]}"`);
    }
    expect(bad).toEqual([]);
  });

  it('the documents do not repeat numbers known to be stale', () => {
    const stale = [/\b421 (?:public|real)/, /two held-out rounds/, /1,500\+/, /1%2C500/, /about 1,600/, /1,755/, /\b71 (?:fast-check|property)/, /Seventy-one/];
    const bad: string[] = [];
    for (const d of ['README.md', 'docs/SUBMISSION.md', 'docs/VIDEO_SCRIPT.md', 'docs/REFERENCE.md', 'docs/BLOG.md', 'docs/SOCIAL.md']) {
      for (const re of stale) if (re.test(read(d))) bad.push(`${d}: ${re}`);
    }
    expect(bad).toEqual([]);
  });

  it('the Haunted Repo count and the field report totals have one value', () => {
    const f = facts();
    const fr = f['fieldReport'] as { rounds: number; repos: number; round1Repos: number; round2Repos: number; round3Repos: number };
    expect(fr.rounds).toBe(3);
    expect(fr.repos).toBe(fr.round1Repos + fr.round2Repos + fr.round3Repos);
    expect(f['benchmarkAttacksCaught']).toBe(f['benchmarkAttacks']);
    expect(f['benchmarkBenignClean']).toBe(f['benchmarkBenign']);
  });
});
