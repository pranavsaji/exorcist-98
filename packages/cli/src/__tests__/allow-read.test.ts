import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readAllowedReads, sha256File } from '@exorcist-98/core';
import { allowReadCommand, dialogText, confirms } from '../commands/on-access.js';
import type { DialogAnswer, Terminal } from '../commands/on-access.js';

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
type T = Terminal & { asked: string[]; dialogs: string[] };
const terminal = (o: { interactive: boolean; answer?: (prompt: string) => string; dialog?: DialogAnswer; nonce?: string }): T => {
  const asked: string[] = [];
  const dialogs: string[] = [];
  return {
    interactive: o.interactive, asked, dialogs,
    ask: async (prompt) => { asked.push(prompt); return (o.answer ?? (() => ''))(prompt); },
    dialog: async (m) => { dialogs.push(m); return o.dialog ?? 'unavailable'; },
    nonce: () => o.nonce ?? 'c0ffee',
  };
};
const file = (content = 'x\n'): string => { const f = join(tmp(), 'CONTRIBUTING.md'); writeFileSync(f, content); return f; };
const stored = () => (existsSync(join(store, 'allowed-reads')) ? readdirSync(join(store, 'allowed-reads')) : []);

describe('exorcist allow-read: only a person can allow a file', () => {
  it('refuses without a TTY, before asking anything, and writes nothing', async () => {
    const t = terminal({ interactive: false, dialog: 'allow' });
    const r = io();
    expect(await allowReadCommand([file()], r.io, t)).toBe(1);
    expect(t.asked).toEqual([]);
    expect(t.dialogs).toEqual([]);
    expect(r.err.join('\n')).toContain('the user must review the file and run it themselves');
    expect(stored()).toEqual([]);
  });

  it('a click on Allow in the native dialog allows the file, without any typed code', async () => {
    const t = terminal({ interactive: true, dialog: 'allow' });
    expect(await allowReadCommand([file()], io().io, t)).toBe(0);
    expect(t.asked).toEqual([]);
    expect(t.dialogs[0]).toContain('Allow your AI agent to read this file?');
    expect(readAllowedReads(process.cwd()).size).toBe(1);
  });

  it('Deny in the dialog (or giving up) allows nothing and never falls back to typing', async () => {
    const t = terminal({ interactive: true, dialog: 'deny', answer: () => 'c0ffee' });
    expect(await allowReadCommand([file()], io().io, t)).toBe(1);
    expect(t.asked).toEqual([]);
    expect(stored()).toEqual([]);
  });

  it('without a dialog, a random code (not derived from the file) must be typed back', async () => {
    const f = file();
    const hash = sha256File(f) ?? '';
    const r = io();
    const t = terminal({ interactive: true, nonce: 'a1b2c3', answer: () => ' A1B2C3 ' });
    expect(await allowReadCommand([f], r.io, t)).toBe(0);
    expect(r.out.join('\n')).toContain('Confirmation code: a1b2c3');
    expect(r.out.join('\n')).toContain(hash);
    // The hash prefix is not the code.
    const r2 = io();
    expect(await allowReadCommand([file('y\n')], r2.io, terminal({ interactive: true, nonce: 'a1b2c3', answer: () => hash.slice(0, 6) }))).toBe(1);
  });

  it('a wrong answer allows nothing', async () => {
    expect(await allowReadCommand([file()], io().io, terminal({ interactive: true, answer: () => 'yes' }))).toBe(1);
    expect(stored()).toEqual([]);
  });

  it('if the file changes while the user confirms, nothing is allowed', async () => {
    const f = file();
    const t = terminal({ interactive: true, answer: () => { writeFileSync(f, 'swapped\n'); return 'c0ffee'; } });
    const r = io();
    expect(await allowReadCommand([f], r.io, t)).toBe(1);
    expect(r.err.join('\n')).toContain('changed while you were confirming');
    expect(readAllowedReads(process.cwd()).size).toBe(0);
  });

  it('confirms matches only the code, trimmed and case-insensitive; short codes never match', () => {
    expect(confirms('c0ffee', 'c0ffee')).toBe(true);
    expect(confirms(' C0FFEE\n', 'c0ffee')).toBe(true);
    expect(confirms('c0ffe', 'c0ffee')).toBe(false);
    expect(confirms('', '')).toBe(false);
  });

  it('dialog text has no control or direction characters and is bounded (it is passed as an argument, never as script)', () => {
    const t = dialogText(`a"b\\c\u001b[31m\nd\u202ee${'x'.repeat(2000)}`);
    expect(t).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u202e]/);
    expect(t.startsWith('a"b\\c')).toBe(true);
    expect(t.length).toBe(600);
  });
});
