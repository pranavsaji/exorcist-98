import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readAllowedReads, sha256File } from '@exorcist-98/core';
import { allowReadCommand, confirmationCode, confirms } from '../commands/on-access.js';
import type { Terminal } from '../commands/on-access.js';

const dirs: string[] = [];
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-allow-read-')); dirs.push(d); return d; };
let saved: string | undefined;
let store = '';
beforeEach(() => { saved = process.env['EXORCIST_DIR']; store = tmp(); process.env['EXORCIST_DIR'] = store; });
afterEach(() => {
  if (saved === undefined) delete process.env['EXORCIST_DIR']; else process.env['EXORCIST_DIR'] = saved;
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

const io = () => {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (s: string) => void out.push(s), err: (s: string) => void err.push(s) }, out, err };
};
const terminal = (interactive: boolean, answer: (shown: string) => string): Terminal & { asked: string[] } => {
  const asked: string[] = [];
  return { interactive, asked, ask: async (prompt) => { asked.push(prompt); return answer(prompt); } };
};

describe('exorcist allow-read: only a person at a terminal can allow a file', () => {
  it('refuses without a TTY, before asking anything, and writes nothing', async () => {
    const d = tmp();
    const file = join(d, 'CONTRIBUTING.md');
    writeFileSync(file, 'x\n');
    const t = terminal(false, () => confirmationCode(sha256File(file) ?? ''));
    const r = io();
    expect(await allowReadCommand([file], r.io, t)).toBe(1);
    expect(t.asked).toEqual([]);
    expect(r.err.join('\n')).toContain('the user must review the file and run it themselves');
    expect(existsSync(join(store, 'allowed-reads'))).toBe(false);
  });

  it('allows only after the user types the first 6 characters of the SHA-256 shown', async () => {
    const d = tmp();
    const file = join(d, 'CONTRIBUTING.md');
    writeFileSync(file, 'x\n');
    const hash = sha256File(file) ?? '';
    const r = io();
    expect(await allowReadCommand([file], r.io, terminal(true, () => ` ${hash.slice(0, 6).toUpperCase()} `))).toBe(0);
    expect(r.out.join('\n')).toContain(hash);
    expect(readAllowedReads(process.cwd()).size).toBe(1);
  });

  it('a wrong answer allows nothing', async () => {
    const d = tmp();
    const file = join(d, 'CONTRIBUTING.md');
    writeFileSync(file, 'x\n');
    expect(await allowReadCommand([file], io().io, terminal(true, () => 'yes'))).toBe(1);
    expect(existsSync(join(store, 'allowed-reads')) ? readdirSync(join(store, 'allowed-reads')) : []).toEqual([]);
  });

  it('if the file changes while the user confirms, nothing is allowed', async () => {
    const d = tmp();
    const file = join(d, 'CONTRIBUTING.md');
    writeFileSync(file, 'x\n');
    const hash = sha256File(file) ?? '';
    const t = terminal(true, () => { writeFileSync(file, 'swapped\n'); return confirmationCode(hash); });
    const r = io();
    expect(await allowReadCommand([file], r.io, t)).toBe(1);
    expect(r.err.join('\n')).toContain('changed while you were confirming');
    expect(readAllowedReads(process.cwd()).size).toBe(0);
  });

  it('confirms matches only the code, trimmed and case-insensitive', () => {
    const h = 'abcdef0123'.padEnd(64, '0');
    expect(confirms('abcdef', h)).toBe(true);
    expect(confirms(' ABCDEF\n', h)).toBe(true);
    expect(confirms('abcde', h)).toBe(false);
    expect(confirms('', h)).toBe(false);
  });
});
