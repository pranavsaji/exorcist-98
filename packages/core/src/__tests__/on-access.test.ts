import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadDefinitions } from '../definitions/loader.js';
import { decideRead, extractReadPaths, isReadTool } from '../on-access.js';
import { addAllowedRead, readAllowedReads, sha256File } from '../allowed-reads.js';
import { VirusDefinitionSchema } from '../definitions/schema.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { fromRoot } from './repo-root.js';

let defs: VirusDefinition[] = [];
beforeAll(async () => {
  defs = await loadDefinitions(fromRoot('definitions'));
});

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-on-access-')); dirs.push(d); return d; };

const event = (cwd: string, tool_input: unknown, tool_name = 'read'): string =>
  JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 's', cwd, tool_name, tool_input });

const EX2_BODY = () => readFileSync(fromRoot('fixtures/haunted-repo/EX-002-ai-instructions.md'), 'utf8');

describe('extractReadPaths', () => {
  const cwd = '/repo';
  it('collects every path-like key, arrays and file:// URIs', () => {
    const paths = extractReadPaths(
      { path: 'a.md', file_path: 'b.md', filePath: 'c.md', paths: ['d.md', 'e.md'], uri: 'file:///repo/f.md', other: 'nope' },
      cwd,
    );
    expect(paths).toEqual(['/repo/a.md', '/repo/b.md', '/repo/c.md', '/repo/d.md', '/repo/e.md', '/repo/f.md']);
  });

  it('ignores other URIs and non-strings', () => {
    expect(extractReadPaths({ uri: 'https://example.invalid/x', path: 42, paths: [null, '', 'g.md'] }, cwd)).toEqual([`${cwd}/g.md`]);
  });

  it('finds path keys nested in a list of read operations, but not too deep', () => {
    expect(extractReadPaths({ operations: [{ mode: 'Line', path: 'a.md' }, { mode: 'Line', path: 'b.md' }] }, cwd))
      .toEqual(['/repo/a.md', '/repo/b.md']);
    expect(extractReadPaths({ a: { b: { c: { d: { e: { path: 'deep.md' } } } } } }, cwd)).toEqual([]);
  });

  it('deduplicates and tolerates unknown shapes', () => {
    expect(extractReadPaths({ path: 'a.md', file_path: 'a.md' }, cwd)).toEqual([`${cwd}/a.md`]);
    expect(extractReadPaths('nonsense', cwd)).toEqual([]);
    expect(extractReadPaths({ paths: ['README.md'] }, '/absent')).toEqual(['/absent/README.md']);
  });
});

describe('decideRead (REQ-01)', () => {
  it('blocks a file with a critical or high finding and never quotes the attacker text', () => {
    const d = tmp();
    writeFileSync(join(d, 'CONTRIBUTING.md'), EX2_BODY());
    const r = decideRead(event(d, { path: 'CONTRIBUTING.md' }), defs, { cwd: d });
    expect(r.exitCode).toBe(2);
    expect(r.message).toContain('CONTRIBUTING.md');
    expect(r.message).toContain('EX-002');
    expect(r.message).toContain('lines 11, 12, 14  EX-002 Instructions addressed to AI (high)');
    expect(r.message.match(/fix:/g)).toHaveLength(1); // one fix per rule, not per line
    expect(r.message).toContain('fix:');
    expect(r.message).toContain('exorcist allow-read');
    // The agent reads this message; the attacker's words must not be in it.
    expect(r.message).not.toContain('Ignore previous instructions');
    expect(r.message).not.toContain('maintenance mode');
  });

  it('blocks a critical hidden-Unicode file named through a file:// URI', () => {
    const d = tmp();
    writeFileSync(join(d, 'README.md'), `Welcome!\nRead this\u202E carefully.\n`);
    const r = decideRead(event(d, { uri: `file://${join(d, 'README.md')}` }), defs, { cwd: d });
    expect(r.exitCode).toBe(2);
    expect(r.message).toContain('EX-001');
  });

  it('lists every blocked file with rule, title, line and fix (REQ-01.4)', () => {
    const d = tmp();
    writeFileSync(join(d, 'CONTRIBUTING.md'), EX2_BODY());
    mkdirSync(join(d, 'docs'));
    writeFileSync(join(d, 'docs/setup.md'), 'Setup\n\nStep one\u202E done.\n');
    writeFileSync(join(d, 'README.md'), '# Clean\n');
    const r = decideRead(event(d, { paths: ['CONTRIBUTING.md', 'docs/setup.md', 'README.md'] }), defs);
    expect(r.exitCode).toBe(2);
    expect(r.message).toMatch(/^CONTRIBUTING\.md$/m);
    expect(r.message).toMatch(/^docs\/setup\.md$/m);
    expect(r.message).toMatch(/line 3 {2}EX-001 /);
    expect(r.message).not.toMatch(/^README\.md$/m);
    // No hidden character from the file is echoed back to the agent.
    expect(r.message).not.toMatch(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069]|[\u{E0000}-\u{E007F}]/u);
  });

  it('blocks a read operation nested in a list (fs_read style input)', () => {
    const d = tmp();
    writeFileSync(join(d, 'CONTRIBUTING.md'), EX2_BODY());
    const r = decideRead(event(d, { operations: [{ mode: 'Line', path: 'CONTRIBUTING.md' }] }, 'fs_read'), defs);
    expect(r.exitCode).toBe(2);
  });

  it('only decides reads: a non-read tool naming a haunted file is not blocked', () => {
    const d = tmp();
    writeFileSync(join(d, 'CONTRIBUTING.md'), EX2_BODY());
    for (const t of ['read', 'readFile', 'read_file', 'readCode', 'fs_read', 'readMultipleFiles']) expect(isReadTool(t), t).toBe(true);
    for (const t of ['fs_write', 'execute_bash', 'web_fetch', 42, null]) expect(isReadTool(t), String(t)).toBe(false);
    expect(decideRead(event(d, { path: 'CONTRIBUTING.md' }, 'fs_write'), defs).exitCode).toBe(0);
    // No tool name at all: the path keys decide.
    expect(decideRead(JSON.stringify({ cwd: d, tool_input: { path: 'CONTRIBUTING.md' } }), defs).exitCode).toBe(2);
  });

  it('allows a folder read and uses the event cwd when no cwd option is given', () => {
    const d = tmp();
    writeFileSync(join(d, 'CONTRIBUTING.md'), EX2_BODY());
    expect(decideRead(event(d, { path: '.' }), defs).exitCode).toBe(0);
    expect(decideRead(event(d, { path: 'CONTRIBUTING.md' }), defs).exitCode).toBe(2);
  });

  it('allows a clean file silently', () => {
    const d = tmp();
    writeFileSync(join(d, 'README.md'), '# Hello\n\nA normal project.\n');
    expect(decideRead(event(d, { path: 'README.md' }), defs, { cwd: d })).toEqual({ exitCode: 0, message: '' });
  });

  it('allows with a one-line warning when the worst finding is medium (a short zero-width run)', () => {
    const d = tmp();
    writeFileSync(join(d, 'notes.md'), 'fine\na\u200Bb\nfine\n');
    const r = decideRead(event(d, { path: 'notes.md' }), defs, { cwd: d });
    expect(r.exitCode).toBe(0);
    expect(r.message).toContain('warning');
    expect(r.message).toContain('notes.md');
  });

  it('never bricks the agent: bad JSON, unknown shapes, missing files all allow', () => {
    const d = tmp();
    expect(decideRead('not json', defs)).toEqual({ exitCode: 0, message: '' });
    expect(decideRead('[]', defs)).toEqual({ exitCode: 0, message: '' });
    expect(decideRead(event(d, { query: 'hello' }), defs, { cwd: d }).exitCode).toBe(0);
    expect(decideRead(event(d, { path: 'missing.md' }), defs, { cwd: d }).exitCode).toBe(0);
    expect(decideRead({ tool_name: 'read', tool_input: null }, defs).exitCode).toBe(0);
  });

  it('a rule that runs out of time is a medium warning, worded as such (never "clean")', () => {
    const d = tmp();
    writeFileSync(join(d, 'notes.md'), `${'a'.repeat(40)}!\n`);
    const slow = VirusDefinitionSchema.parse({ id: 'EX-901', title: 'Slow rule', severity: 'high', applies_to: ['docs'], match: { regex: '(a+)+$' }, owasp: ['x'], fix: 'Fix it.' });
    const r = decideRead(event(d, { path: 'notes.md' }), [slow]);
    expect(r.exitCode).toBe(0);
    expect(r.message).toContain('could not be fully checked (EX-901 ran out of time)');
  }, 20_000);

  it('allows a file larger than 1 MB, with a note (REQ-01.3)', () => {
    const d = tmp();
    writeFileSync(join(d, 'huge.log'), 'a'.repeat(1_048_577));
    const r = decideRead(event(d, { path: 'huge.log' }), defs, { cwd: d });
    expect(r.exitCode).toBe(0);
    expect(r.message).toContain('huge.log');
    expect(r.message).toContain('1 MB');
  });

  it('honours an allowed hash, and an edit invalidates it (REQ-03)', () => {
    const d = tmp();
    const file = join(d, 'CONTRIBUTING.md');
    writeFileSync(file, EX2_BODY());
    const stateDir = join(d, '.exorcist');
    expect(decideRead(event(d, { path: 'CONTRIBUTING.md' }), defs, { cwd: d, allowed: readAllowedReads(stateDir) }).exitCode).toBe(2);
    const add = addAllowedRead(stateDir, file);
    expect(add.ok).toBe(true);
    if (add.ok) expect(add.hash).toBe(sha256File(file));
    const allowed = readAllowedReads(stateDir);
    expect(allowed.size).toBe(1);
    expect(decideRead(event(d, { path: 'CONTRIBUTING.md' }), defs, { cwd: d, allowed }).exitCode).toBe(0);
    writeFileSync(file, `${EX2_BODY()}\nchanged\n`);
    expect(decideRead(event(d, { path: 'CONTRIBUTING.md' }), defs, { cwd: d, allowed }).exitCode).toBe(2);
  });

  it('decides on a 100 KB file in well under 300 ms (REQ-04, generous bound)', () => {
    const d = tmp();
    writeFileSync(join(d, 'README.md'), `${'A perfectly ordinary line of project text.\n'.repeat(2500)}`);
    const t0 = performance.now();
    const r = decideRead(event(d, { path: 'README.md' }), defs, { cwd: d });
    const ms = performance.now() - t0;
    expect(r.exitCode).toBe(0);
    // The requirement is 300 ms on a laptop; CI can be slower, so the bound is generous.
    expect(ms).toBeLessThan(1000);
  });
});
