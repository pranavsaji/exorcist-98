import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { activeDefinitions } from '@exorcist-98/core';
import { resetStaleWarning, setStaleClock, usesCustomDefinitions, warnIfStale } from '../stale.js';
import { scanCommand } from '../commands/scan.js';

// Requirement 5 (m9-adoption). `now` is always injected: the real clock moves past any bundled date.
const DAY = 86_400_000;
const dirs: string[] = [];
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-stale-')); dirs.push(d); return d; };
const collect = () => {
  const out: string[] = [];
  const err: string[] = [];
  return { out, err, io: { out: (s: string) => void out.push(s), err: (s: string) => void err.push(s) } };
};

let savedHome: string | undefined;
let savedDefs: string | undefined;
beforeEach(() => {
  resetStaleWarning();
  savedHome = process.env['EXORCIST_DEFINITIONS_HOME'];
  savedDefs = process.env['EXORCIST_DEFINITIONS'];
  // An empty home: only the bundled definitions are active.
  process.env['EXORCIST_DEFINITIONS_HOME'] = tmp();
  delete process.env['EXORCIST_DEFINITIONS'];
});
afterEach(() => {
  setStaleClock(null);
  vi.unstubAllGlobals();
  if (savedHome === undefined) delete process.env['EXORCIST_DEFINITIONS_HOME']; else process.env['EXORCIST_DEFINITIONS_HOME'] = savedHome;
  if (savedDefs === undefined) delete process.env['EXORCIST_DEFINITIONS']; else process.env['EXORCIST_DEFINITIONS'] = savedDefs;
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const bundledMs = (): number => Date.parse(activeDefinitions().date);
const at = (days: number): Date => new Date(bundledMs() + days * DAY);

describe('warnIfStale', () => {
  it('warns at 31 days with the age, the date and the update command', () => {
    const c = collect();
    warnIfStale(c.io, { custom: false, now: at(31) });
    expect(c.err).toHaveLength(1);
    expect(c.err[0]).toContain('31 days old');
    expect(c.err[0]).toContain(activeDefinitions().date);
    expect(c.err[0]).toContain('exorcist update --from');
    expect(c.out).toEqual([]);
  });
  it('does not warn at exactly 30 days', () => {
    const c = collect();
    warnIfStale(c.io, { custom: false, now: at(30) });
    expect(c.err).toEqual([]);
  });
  it('warns once per run', () => {
    const c = collect();
    warnIfStale(c.io, { custom: false, now: at(40) });
    warnIfStale(c.io, { custom: false, now: at(40) });
    expect(c.err).toHaveLength(1);
  });
  it('does not warn for a custom definitions folder', () => {
    const c = collect();
    warnIfStale(c.io, { custom: true, now: at(400) });
    expect(c.err).toEqual([]);
    expect(usesCustomDefinitions('/x')).toBe(true);
    expect(usesCustomDefinitions(undefined, { EXORCIST_DEFINITIONS: '/x' })).toBe(true);
    expect(usesCustomDefinitions(undefined, {})).toBe(false);
  });
  it('makes no network call', () => {
    const fetchStub = vi.fn(() => { throw new Error('network is not allowed'); });
    vi.stubGlobal('fetch', fetchStub);
    const c = collect();
    warnIfStale(c.io, { custom: false, now: at(90) });
    expect(c.err).toHaveLength(1);
    expect(fetchStub).not.toHaveBeenCalled();
  });
});

describe('scan with stale definitions', () => {
  it('keeps stdout valid JSON and puts the warning on stderr only', async () => {
    const d = tmp();
    writeFileSync(join(d, 'a.md'), '# hello\n');
    setStaleClock(() => at(45));
    const fetchStub = vi.fn(() => { throw new Error('network is not allowed'); });
    vi.stubGlobal('fetch', fetchStub);
    const c = collect();
    await scanCommand([d, '--format', 'json'], c.io);
    expect(() => JSON.parse(c.out.join('\n'))).not.toThrow();
    expect(c.out.join('\n')).not.toContain('days old');
    expect(c.err.filter((l) => l.includes('days old'))).toHaveLength(1);
    expect(fetchStub).not.toHaveBeenCalled();
  });
  it('prints no warning with --definitions', async () => {
    const d = tmp();
    writeFileSync(join(d, 'a.md'), '# hello\n');
    setStaleClock(() => at(45));
    const c = collect();
    await scanCommand([d, '--format', 'json', '--definitions', join(process.cwd(), '../../definitions')], c.io);
    expect(c.err.join('\n')).not.toContain('days old');
  });
});
