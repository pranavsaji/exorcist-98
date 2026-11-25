import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readAllowedReads } from '@exorcist-98/core';
import { macOsAuth } from '@exorcist-98/shield';
import type { OsAuth, OsVerdict } from '@exorcist-98/shield';
import { allowReadCommand, askOwner, personConfirms } from '../commands/on-access.js';
import type { DialogAnswer, Terminal } from '../commands/on-access.js';
import { guardMcpWriteCommand } from '../commands/guard-mcp-write.js';
import type { GuardDeps } from '../commands/guard-mcp-write.js';
const dirs: string[] = [];
const tmp = (): string => { const d = realpathSync(mkdtempSync(join(tmpdir(), 'exorcist-osv-'))); dirs.push(d); return d; };
let saved: string | undefined;
beforeEach(() => { saved = process.env['EXORCIST_DIR']; process.env['EXORCIST_DIR'] = tmp(); });
afterEach(() => {
  if (saved === undefined) delete process.env['EXORCIST_DIR']; else process.env['EXORCIST_DIR'] = saved;
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
/** A fake OsAuth that records what it was asked. */
const fakeAuth = (o: { available?: boolean; verdict?: OsVerdict; throws?: boolean }) => {
  const reasons: string[] = [];
  const auth: OsAuth = {
    available: async () => { if (o.throws) throw new Error('boom'); return o.available ?? true; },
    verify: async (reason) => { reasons.push(reason); if (o.throws) throw new Error('boom'); return o.verdict ?? 'ok'; },
  };
  return { auth, reasons };
};
const io = () => {
  const out: string[] = [];
  const err: string[] = [];
  return { io: { out: (s: string) => void out.push(s), err: (s: string) => void err.push(s) }, out, err };
};
const term = (o: { interactive?: boolean; auth?: OsAuth; dialog?: DialogAnswer | 'none'; typed?: string }) => {
  const asked: string[] = [];
  const dialogs: string[] = [];
  const dlg = o.dialog === undefined || o.dialog === 'none' ? 'unavailable' : o.dialog;
  const t: Terminal = {
    interactive: o.interactive ?? true,
    ask: async (p) => { asked.push(p); return o.typed ?? ''; },
    ...(o.dialog === 'none' ? {} : { dialog: async (m: string): Promise<DialogAnswer> => { dialogs.push(m); return dlg; } }),
    nonce: () => 'abc123',
    ...(o.auth ? { osAuth: o.auth } : {}),
  };
  return { t, asked, dialogs };
};
describe('OS verification for every person-only confirmation', () => {
  it('uses the OS prompt when available: ok allows, with no dialog and no typed code', async () => {
    const f = fakeAuth({ verdict: 'ok' });
    const x = term({ auth: f.auth, dialog: 'deny' });
    expect(await personConfirms(x.t, io().io, 'long message', 'Allow X')).toBe(true);
    expect(f.reasons).toEqual(['Allow X']);
    expect(x.dialogs).toEqual([]);
    expect(x.asked).toEqual([]);
  });
  it.each<OsVerdict>(['denied', 'error', 'timeout'])('a %s verdict allows nothing and never falls back to a weaker channel', async (verdict) => {
    const f = fakeAuth({ verdict });
    const x = term({ auth: f.auth, dialog: 'allow', typed: 'abc123' });
    expect(await personConfirms(x.t, io().io, 'm', 'r')).toBe(false);
    expect(x.dialogs).toEqual([]);
    expect(x.asked).toEqual([]);
  });
  it('falls back to the dialog, then the typed code, when the OS prompt is not available', async () => {
    const f = fakeAuth({ available: false });
    const a = term({ auth: f.auth, dialog: 'allow' });
    expect(await personConfirms(a.t, io().io, 'm', 'r')).toBe(true);
    expect(a.dialogs).toEqual(['m']);
    const b = term({ auth: f.auth, dialog: 'unavailable', typed: 'abc123' });
    expect(await personConfirms(b.t, io().io, 'm', 'r')).toBe(true);
    expect(b.asked.length).toBe(1);
    expect(f.reasons).toEqual([]);
  });
  it('an OsAuth that throws counts as not available before the prompt and as a deny after it', async () => {
    const x = term({ auth: fakeAuth({ throws: true }).auth, dialog: 'allow' });
    expect(await askOwner(x.t, 'm', 'r')).toBe('allow');
    const y = term({ auth: { available: async () => true, verify: async () => { throw new Error('x'); } }, dialog: 'allow' });
    expect(await askOwner(y.t, 'm', 'r')).toBe('deny');
  });
  it('cleans the reason before the OS sees it (hidden characters, newlines, length)', async () => {
    const f = fakeAuth({});
    await askOwner(term({ auth: f.auth }).t, 'm', `Allow\nthis\u202e${'x'.repeat(400)}\u{E0048}`);
    expect(f.reasons[0]).not.toMatch(/[\n\u202e\u{E0000}-\u{E007F}]/u);
    expect(f.reasons[0]?.length).toBeLessThanOrEqual(200);
  });
  it('the real macOsAuth is never available under VITEST, so the old behaviour stays in tests', async () => {
    expect(process.env['VITEST']).toBeTruthy();
    expect(await macOsAuth().available()).toBe(false);
    const x = term({ dialog: 'allow' });
    expect(await personConfirms(x.t, io().io, 'm', 'r')).toBe(true);
    expect(x.dialogs).toEqual(['m']);
  });
  it('allow-read names the file and a hash prefix in the OS prompt, and records the allow on ok', async () => {
    const f = join(tmp(), 'CONTRIBUTING.md');
    writeFileSync(f, 'x\n');
    const a = fakeAuth({ verdict: 'ok' });
    expect(await allowReadCommand([f], io().io, term({ auth: a.auth }).t)).toBe(0);
    expect(a.reasons[0]).toContain('Allow your AI agent to read');
    expect(a.reasons[0]).toContain('CONTRIBUTING.md');
    expect(a.reasons[0]).toMatch(/SHA-256 [0-9a-f]{12}/);
    expect(readAllowedReads(process.cwd()).size).toBe(1);
  });
  it('allow-read records nothing when the OS prompt is denied', async () => {
    const f = join(tmp(), 'OTHER.md');
    writeFileSync(f, 'y\n');
    const before = readAllowedReads(process.cwd()).size;
    expect(await allowReadCommand([f], io().io, term({ auth: fakeAuth({ verdict: 'denied' }).auth }).t)).toBe(1);
    expect(readAllowedReads(process.cwd()).size).toBe(before);
  });
});
describe('the MCP config write guard uses the OS prompt too', () => {
  const world = () => {
    const root = tmp();
    const home = join(root, 'home');
    mkdirSync(join(home, '.kiro', 'settings'), { recursive: true });
    writeFileSync(join(home, '.kiro', 'settings', 'mcp.json'), '{}');
    return home;
  };
  const event = (home: string) => ({ hook_event_name: 'PreToolUse', cwd: home, tool_name: 'fs_write', tool_input: { path: '.kiro/settings/mcp.json' } });
  const deps = (home: string, x: ReturnType<typeof term>): GuardDeps => ({ term: x.t, promptIo: { out: () => undefined, err: () => undefined }, home, timeoutMs: 1000 });
  const run = async (home: string, x: ReturnType<typeof term>) => {
    const err: string[] = [];
    const code = await guardMcpWriteCommand(JSON.stringify(event(home)), { out: () => undefined, err: (s) => void err.push(s) }, deps(home, x));
    return { code, err: err.join('\n') };
  };
  it('without a terminal: ok allows (exit 0) and the prompt names the file', async () => {
    const home = world();
    const f = fakeAuth({ verdict: 'ok' });
    const x = term({ interactive: false, auth: f.auth, dialog: 'none' });
    expect((await run(home, x)).code).toBe(0);
    expect(f.reasons[0]).toContain('change the MCP config');
    expect(f.reasons[0]).toContain('mcp.json');
  });
  it('denied blocks (exit 2) and never shows the weaker dialog', async () => {
    const home = world();
    const x = term({ interactive: false, auth: fakeAuth({ verdict: 'denied' }).auth, dialog: 'allow' });
    const r = await run(home, x);
    expect(r.code).toBe(2);
    expect(r.err).toContain('you did not confirm it');
    expect(x.dialogs).toEqual([]);
  });
  it('with a terminal, the OS prompt also decides', async () => {
    const home = world();
    const f = fakeAuth({ verdict: 'ok' });
    expect((await run(home, term({ interactive: true, auth: f.auth, typed: 'nope' }))).code).toBe(0);
    expect((await run(home, term({ interactive: true, auth: fakeAuth({ verdict: 'timeout' }).auth, dialog: 'allow' }))).code).toBe(2);
  });
  it('without OS verification it behaves as before (dialog, or nobody to ask)', async () => {
    const home = world();
    const off = fakeAuth({ available: false }).auth;
    expect((await run(home, term({ interactive: false, auth: off, dialog: 'allow' }))).code).toBe(0);
    expect((await run(home, term({ interactive: false, auth: off, dialog: 'deny' }))).code).toBe(2);
    expect((await run(home, term({ interactive: false, auth: off, dialog: 'none' }))).code).toBe(2);
  });
});
