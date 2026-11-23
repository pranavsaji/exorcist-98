import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import * as fc from 'fast-check';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadDefinitions } from '../definitions/loader.js';
import { decideRead } from '../on-access.js';
import { addAllowedRead, readAllowedReads, sha256File } from '../allowed-reads.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { fromRoot } from './repo-root.js';

let defs: VirusDefinition[] = [];
beforeAll(async () => {
  defs = await loadDefinitions(fromRoot('definitions'));
});

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-on-access-pbt-')); dirs.push(d); return d; };

const event = (cwd: string, tool_input: unknown): string =>
  JSON.stringify({ hook_event_name: 'PreToolUse', cwd, tool_name: 'read', tool_input });

/** The critical Haunted Repo sample: the hidden-Unicode fixture (EX-001, critical). */
const CRITICAL_SAMPLE = () => readFileSync(fromRoot('fixtures/haunted-repo/EX-001-hidden-unicode.md'), 'utf8');

// PBT-ACC-01: any event whose tool_input has no path-like value is allowed.
describe('PBT-ACC-01: no path-like value means allowed', () => {
  const nonPathKeys = fc
    .string({ minLength: 1, maxLength: 12 })
    .filter((k) => !['path', 'file_path', 'filePath', 'paths', 'uri'].includes(k));

  const value = fc.oneof(
    fc.string({ maxLength: 40 }),
    fc.integer(),
    fc.boolean(),
    fc.constant(null),
    fc.array(fc.string({ maxLength: 20 }), { maxLength: 3 }),
  );

  it('allows the read for every such event', () => {
    fc.assert(
      fc.property(fc.uniqueArray(nonPathKeys, { minLength: 0, maxLength: 4 }), fc.array(value, { minLength: 0, maxLength: 4 }), (keys, vals) => {
        const input: Record<string, unknown> = {};
        keys.forEach((k, i) => { input[k] = vals[i % Math.max(1, vals.length)]; });
        const d = decideRead(event('/definitely/not/a/real/cwd', input), defs);
        return d.exitCode === 0;
      }),
      { numRuns: 100 },
    );
  });
});

// PBT-ACC-02: a critical sample at any position inside random benign text is blocked.
describe('PBT-ACC-02: a hidden critical sample is always blocked', () => {
  // Plain prose only: no backticks (fenced code is scanned differently) and no
  // hidden Unicode of its own, so only the sample can fire.
  const benign = fc.stringMatching(/^[A-Za-z0-9 .,\n;:!?"'()\-]{0,400}$/);

  it('blocks the read wherever the sample sits', () => {
    fc.assert(
      fc.property(benign, benign, fc.nat(50), (before, after, _) => {
        const d = tmp();
        writeFileSync(join(d, 'README.md'), `${before}\n${CRITICAL_SAMPLE()}\n${after}`);
        const r = decideRead(event(d, { path: 'README.md' }), defs, { cwd: d });
        return r.exitCode === 2;
      }),
      { numRuns: 25 },
    );
  });
});

// PBT-ACC-03: after allow-read the same bytes pass; any one-byte change is checked again.
describe('PBT-ACC-03: allow-read passes the same bytes only', () => {
  const benignText = fc.stringMatching(/^[A-Za-z0-9 .,\n;:!?"'()\-]{200,2000}$/);

  it('allows the allowed bytes and re-checks any one-byte change', () => {
    fc.assert(
      fc.property(benignText, (text) => {
        const d = tmp();
        const body = `${text}\n${CRITICAL_SAMPLE()}`;
        const file = join(d, 'README.md');
        writeFileSync(file, body);
        const stateDir = join(d, '.exorcist');
        const first = decideRead(event(d, { path: 'README.md' }), defs, { cwd: d, allowed: readAllowedReads(stateDir) });
        if (first.exitCode !== 2) return false;
        const add = addAllowedRead(stateDir, file);
        if (!add.ok) return false;
        const allowed = readAllowedReads(stateDir);
        if (decideRead(event(d, { path: 'README.md' }), defs, { cwd: d, allowed }).exitCode !== 0) return false;
        // One byte changed: the hash no longer matches, so the file is scanned again.
        const mutated = Buffer.from(body, 'utf8');
        mutated[0] = mutated[0] === 0x62 ? 0x63 : 0x62;
        writeFileSync(file, mutated);
        const again = decideRead(event(d, { path: 'README.md' }), defs, { cwd: d, allowed });
        return again.exitCode === 2 && sha256File(file) !== add.hash;
      }),
      { numRuns: 15 },
    );
  });
});
