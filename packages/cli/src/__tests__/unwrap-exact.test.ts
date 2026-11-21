import { mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { wrapCommand } from '../commands/config.js';
import type { Io } from '../util.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = () => { const d = realpathSync(mkdtempSync(join(tmpdir(), 'x98-unwrap-'))); dirs.push(d); return d; };
const io = (): Io & { errs: string[] } => { const errs: string[] = []; return { errs, out: () => undefined, err: (s) => { errs.push(s); } }; };

const HAND_WRITTEN = `{
  "mcpServers": {
    "notes":  { "command": "node", "args": ["notes.js"] },
    "remote": { "url": "https://mcp.example.invalid/mcp", "headers": { "Authorization": "Bearer EXAMPLE_TOKEN_DO_NOT_USE" } }
  },
  "other": 1
}
`;

describe('unwrap restores the file byte for byte', () => {
  it('a hand-formatted file comes back exactly, and the copy is removed', async () => {
    const d = tmp();
    const f = join(d, 'mcp.json');
    writeFileSync(f, HAND_WRITTEN);
    expect(await wrapCommand([f, '--dir', join(d, '.exorcist')], io(), 'wrap')).toBe(0);
    expect(readFileSync(f, 'utf8')).not.toBe(HAND_WRITTEN);
    const o = io();
    expect(await wrapCommand([f], o, 'unwrap')).toBe(0);
    expect(readFileSync(f, 'utf8')).toBe(HAND_WRITTEN);
    expect(o.errs.join(' ')).toContain('byte for byte');
    expect(readdirSync(join(d, '.exorcist', 'wrap-backups'))).toEqual([]);
  });

  it('the kept copy can hold tokens, so only the owner can read it', async () => {
    const d = tmp();
    const f = join(d, 'mcp.json');
    writeFileSync(f, HAND_WRITTEN);
    await wrapCommand([f, '--dir', join(d, '.exorcist')], io(), 'wrap');
    const [copy] = readdirSync(join(d, '.exorcist', 'wrap-backups'));
    expect(statSync(join(d, '.exorcist', 'wrap-backups', copy ?? '')).mode & 0o077).toBe(0);
  });

  it('a file edited after wrap gets its commands back, keeps the edit, and says formatting may differ', async () => {
    const d = tmp();
    const f = join(d, 'mcp.json');
    writeFileSync(f, HAND_WRITTEN);
    await wrapCommand([f, '--dir', join(d, '.exorcist')], io(), 'wrap');
    const edited = JSON.parse(readFileSync(f, 'utf8')) as { other: number };
    edited.other = 2;
    writeFileSync(f, JSON.stringify(edited, null, 2));
    const o = io();
    await wrapCommand([f], o, 'unwrap');
    const back = JSON.parse(readFileSync(f, 'utf8')) as { other: number; mcpServers: Record<string, Record<string, unknown>> };
    expect(back.other).toBe(2);
    expect(back.mcpServers['notes']).toEqual({ command: 'node', args: ['notes.js'] });
    expect(back.mcpServers['remote']?.['url']).toBe('https://mcp.example.invalid/mcp');
    expect(o.errs.join(' ')).toMatch(/edited after wrap/);
  });

  it('any formatting of any small config round-trips exactly', async () => {
    const entry = fc.oneof(
      fc.record({ command: fc.constantFrom('node', 'npx', 'python3'), args: fc.array(fc.constantFrom('a.js', '-y', 'pkg@1.0.0'), { maxLength: 3 }) }),
      fc.record({ url: fc.constantFrom('https://a.example.invalid/mcp', 'http://127.0.0.1:9000/mcp') }),
    );
    await fc.assert(fc.asyncProperty(
      fc.dictionary(fc.stringMatching(/^[a-z]{1,6}$/), entry, { minKeys: 1, maxKeys: 3 }),
      fc.constantFrom(0, 2, 4, '\t'),
      fc.boolean(),
      async (servers, indent, trailingNewline) => {
        const d = tmp();
        const f = join(d, 'mcp.json');
        const text = JSON.stringify({ mcpServers: servers }, null, indent) + (trailingNewline ? '\n' : '');
        writeFileSync(f, text);
        await wrapCommand([f, '--dir', join(d, '.exorcist')], io(), 'wrap');
        await wrapCommand([f], io(), 'unwrap');
        expect(readFileSync(f, 'utf8')).toBe(text);
      },
    ), { numRuns: 25 });
  });
});
