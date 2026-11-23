import { describe, it, expect, beforeAll, afterAll } from 'vitest';
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
let root = '';
beforeAll(async () => {
  defs = await loadDefinitions(fromRoot('definitions'));
  root = mkdtempSync(join(tmpdir(), 'exorcist-on-access-pbt-'));
});
afterAll(() => { rmSync(root, { recursive: true, force: true }); });
// One fresh folder per property run, all removed at the end.
const fresh = (): string => mkdtempSync(join(root, 'run-'));

const READ_KEYS = ['path', 'file_path', 'filePath', 'paths', 'uri'];
const event = (cwd: string, tool_input: unknown): string =>
  JSON.stringify({ hook_event_name: 'PreToolUse', cwd, tool_name: 'read', tool_input });

/** The critical Haunted Repo sample: the hidden-Unicode fixture (EX-001, critical). */
const CRITICAL_SAMPLE = (): string => readFileSync(fromRoot('fixtures/haunted-repo/EX-001-hidden-unicode.md'), 'utf8');
const EX2_SAMPLE = (): string => readFileSync(fromRoot('fixtures/haunted-repo/EX-002-ai-instructions.md'), 'utf8');

// Plain prose only: no backticks (fenced code is scanned differently) and no
// hidden Unicode of its own, so only the planted sample can fire.
const benign = (min: number, max: number) => fc.stringMatching(new RegExp(`^[A-Za-z0-9 .,\\n;:!?"'()\\-]{${min},${max}}$`));

// PBT-ACC-01: any event whose tool_input has no path-like value is allowed.
describe('PBT-ACC-01: no path-like value means allowed', () => {
  // Any JSON-ish value, at any depth, whose object keys are never a path key.
  const key = fc.string({ maxLength: 12 }).filter((k) => !READ_KEYS.includes(k));
  const input = fc.oneof(
    fc.anything({ key, maxDepth: 4 }),
    // Values that name a haunted file, under keys that are not path keys.
    fc.dictionary(key, fc.constantFrom('CONTRIBUTING.md', './CONTRIBUTING.md', ['CONTRIBUTING.md'])),
  );

  it('allows the read for every such event, even when the folder holds a haunted file', () => {
    const d = fresh();
    writeFileSync(join(d, 'CONTRIBUTING.md'), EX2_SAMPLE());
    // Sanity: the same file named through a path key is blocked.
    expect(decideRead(event(d, { path: 'CONTRIBUTING.md' }), defs).exitCode).toBe(2);
    fc.assert(
      fc.property(input, (tool_input) => {
        expect(decideRead(event(d, tool_input), defs).exitCode).toBe(0);
      }),
      { numRuns: 300 },
    );
  });
});

// PBT-ACC-02: a critical sample at any position inside random benign text is blocked.
describe('PBT-ACC-02: a hidden critical sample is always blocked', () => {
  it('blocks the read wherever the sample sits, in any agent-facing Markdown file', () => {
    const sample = CRITICAL_SAMPLE();
    fc.assert(
      fc.property(
        benign(0, 600),
        fc.nat(),
        fc.constantFrom('README.md', 'CONTRIBUTING.md', 'AGENTS.md', 'notes.md'),
        (text, at, name) => {
          const i = text.length === 0 ? 0 : at % (text.length + 1);
          const d = fresh();
          // Any character offset, not only a line boundary.
          writeFileSync(join(d, name), `${text.slice(0, i)}${sample}${text.slice(i)}`);
          const r = decideRead(event(d, { path: name }), defs);
          expect(r.exitCode).toBe(2);
          expect(r.message).toContain('EX-001');
        },
      ),
      { numRuns: 40 },
    );
  });
});

// PBT-ACC-03: after allow-read the same bytes pass; any one-byte change is checked again.
describe('PBT-ACC-03: allow-read passes the same bytes only', () => {
  it('allows the allowed bytes, and any one-byte change gets the same decision as a fresh scan', () => {
    fc.assert(
      fc.property(benign(0, 400), fc.nat(), fc.integer({ min: 1, max: 255 }), (text, at, delta) => {
        const d = fresh();
        const body = Buffer.from(`${text}\n${CRITICAL_SAMPLE()}`, 'utf8');
        const file = join(d, 'README.md');
        writeFileSync(file, body);
        const stateDir = join(d, '.exorcist');
        const ev = event(d, { path: 'README.md' });
        expect(decideRead(ev, defs, { allowed: readAllowedReads(stateDir) }).exitCode).toBe(2);

        const add = addAllowedRead(stateDir, file);
        expect(add.ok).toBe(true);
        const allowed = readAllowedReads(stateDir);
        expect(decideRead(ev, defs, { allowed })).toEqual({ exitCode: 0, message: '' });

        // Change one byte anywhere, to any other value.
        const mutated = Buffer.from(body);
        const i = at % mutated.length;
        mutated[i] = ((mutated[i] ?? 0) + delta) % 256;
        writeFileSync(file, mutated);
        expect(add.ok && sha256File(file) !== add.hash).toBe(true);
        // The allowance no longer applies: the decision is exactly a fresh scan's.
        expect(decideRead(ev, defs, { allowed })).toEqual(decideRead(ev, defs, { allowed: new Set() }));

        // Put the bytes back and the allowance holds again.
        writeFileSync(file, body);
        expect(decideRead(ev, defs, { allowed }).exitCode).toBe(0);
      }),
      { numRuns: 30 },
    );
  });
});
