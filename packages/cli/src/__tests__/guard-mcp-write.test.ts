import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decideMcpWrite } from '@exorcist-98/core';
import { guardMcpWriteCommand } from '../commands/guard-mcp-write.js';
import type { GuardDeps } from '../commands/guard-mcp-write.js';
import type { DialogAnswer } from '../commands/on-access.js';

const dirs: string[] = [];
let savedDir: string | undefined;
// The guard records each approval outcome in the state folder: keep that in a temp folder.
beforeEach(() => { savedDir = process.env['EXORCIST_DIR']; process.env['EXORCIST_DIR'] = mkdtempSync(join(tmpdir(), 'exorcist-mcpguard-state-')); dirs.push(process.env['EXORCIST_DIR']); });
afterEach(() => {
  if (savedDir === undefined) delete process.env['EXORCIST_DIR']; else process.env['EXORCIST_DIR'] = savedDir;
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});
const tmp = (): string => { const d = realpathSync(mkdtempSync(join(tmpdir(), 'exorcist-mcpguard-'))); dirs.push(d); return d; };

/** A home and a project, each with a real .kiro/settings/mcp.json. */
function world() {
  const root = tmp();
  const home = join(root, 'home');
  const proj = join(root, 'proj');
  for (const base of [home, proj]) {
    mkdirSync(join(base, '.kiro', 'settings'), { recursive: true });
    writeFileSync(join(base, '.kiro', 'settings', 'mcp.json'), '{}');
  }
  return { root, home, proj };
}
const write = (cwd: string, tool_input: Record<string, unknown>, tool_name = 'fs_write') =>
  ({ hook_event_name: 'PreToolUse', cwd, tool_name, tool_input });

const fakeDeps = (o: { interactive?: boolean; dialog?: DialogAnswer | 'none'; typed?: string; timeoutMs?: number; home?: string; hang?: boolean }) => {
  const dialogs: string[] = [];
  const shown: string[] = [];
  const deps: GuardDeps = {
    term: {
      interactive: o.interactive ?? false,
      ask: async () => o.typed ?? '',
      ...(o.dialog === 'none' ? {} : {
        dialog: async (m: string): Promise<DialogAnswer> => { dialogs.push(m); if (o.hang) await new Promise(() => undefined); return o.dialog === undefined || o.dialog === 'none' ? 'unavailable' : o.dialog; },
      }),
      nonce: () => 'abc123',
    },
    promptIo: { out: (s) => void shown.push(s), err: (s) => void shown.push(s) },
    home: o.home ?? '/nonexistent-home',
    timeoutMs: o.timeoutMs ?? 1000,
  };
  return { deps, dialogs, shown };
};
const run = async (event: unknown, deps: GuardDeps) => {
  const err: string[] = [];
  const code = await guardMcpWriteCommand(typeof event === 'string' ? event : JSON.stringify(event), { out: () => undefined, err: (s) => void err.push(s) }, deps);
  return { code, err: err.join('\n') };
};

describe('decideMcpWrite: spellings', () => {
  it('finds the project config by relative path, ../ and ~', () => {
    const w = world();
    const real = join(w.proj, '.kiro', 'settings', 'mcp.json');
    expect(decideMcpWrite(write(w.proj, { path: '.kiro/settings/mcp.json' }), w.home, '/')).toEqual({ target: 'mcp-config', path: real });
    expect(decideMcpWrite(write(join(w.proj, 'src'), { file_path: '../.kiro/settings/mcp.json' }), w.home, '/').target).toBe('mcp-config');
    expect(decideMcpWrite(write(w.proj, { path: '~/.kiro/settings/mcp.json' }), w.home, '/')).toEqual({ target: 'mcp-config', path: join(w.home, '.kiro', 'settings', 'mcp.json') });
    expect(decideMcpWrite(write(w.proj, { path: '$HOME/.kiro/./settings/../settings/mcp.json' }), w.home, '/').target).toBe('mcp-config');
  });
  it('finds a config reached through a symlink, and through any key', () => {
    const w = world();
    symlinkSync(join(w.home, '.kiro'), join(w.proj, 'innocent'));
    symlinkSync(join(w.home, '.kiro', 'settings', 'mcp.json'), join(w.proj, 'notes.txt'));
    expect(decideMcpWrite(write(w.proj, { path: 'innocent/settings/mcp.json' }), w.home, '/').target).toBe('mcp-config');
    expect(decideMcpWrite(write(w.proj, { weird_new_key: 'notes.txt' }), w.home, '/').target).toBe('mcp-config');
    expect(decideMcpWrite(write(w.proj, { nested: { list: ['x', '.kiro/settings/mcp.json'] } }), w.home, '/').target).toBe('mcp-config');
  });
  it('ignores other files and non-events', () => {
    const w = world();
    expect(decideMcpWrite(write(w.proj, { path: 'src/index.ts', content: 'mcp.json' }), w.home, '/').target).toBe('other');
    expect(decideMcpWrite(write(w.proj, { path: '.kiro/settings/cli.json' }), w.home, '/').target).toBe('other');
    expect(decideMcpWrite('text', w.home, '/').target).toBe('other');
    expect(decideMcpWrite({ cwd: w.proj }, w.home, '/').target).toBe('other');
  });
});

describe('decideMcpWrite: shell write forms', () => {
  const cmds = [
    'echo {} > ~/.kiro/settings/mcp.json',
    'echo {} >> .kiro/settings/mcp.json',
    'echo {}>.kiro/settings/mcp.json',
    'cat x | tee -a "$HOME/.kiro/settings/mcp.json"',
    "sed -i '' 's/a/b/' ~/.kiro/settings/mcp.json",
    'sed --in-place s/a/b/ .kiro/settings/mcp.json',
    'cp /tmp/evil.json ~/.kiro/settings/mcp.json',
    'mv evil.json .kiro/settings/mcp.json',
    'ls && cp /tmp/mcp.json ~/.kiro/settings/',
    "cp -t ~/.kiro/settings /tmp/mcp.json",
  ];
  for (const command of cmds) {
    it(`sees: ${command}`, () => {
      const w = world();
      expect(decideMcpWrite(write(w.proj, { command }, 'execute_bash'), w.home, '/').target).toBe('mcp-config');
    });
  }
  it('leaves reads and unrelated writes alone', () => {
    const w = world();
    for (const command of ['cat ~/.kiro/settings/mcp.json', 'cp ~/.kiro/settings/mcp.json /tmp/backup.json', 'echo hi > out.txt', 'sed -n 1p .kiro/settings/mcp.json']) {
      expect(decideMcpWrite(write(w.proj, { command }, 'execute_bash'), w.home, '/').target).toBe('other');
    }
  });
});

describe('exorcist guard-mcp-write', () => {
  it('a click on Allow confirms: exit 0, file named, content never shown', async () => {
    const w = world();
    const f = fakeDeps({ dialog: 'allow', home: w.home });
    const r = await run(write(w.proj, { path: '.kiro/settings/mcp.json', content: 'SECRET_PAYLOAD_EXAMPLE' }), f.deps);
    expect(r.code).toBe(0);
    expect(f.dialogs).toHaveLength(1);
    expect(f.dialogs[0]).toContain('mcp.json');
    expect(f.dialogs[0]).not.toContain('SECRET_PAYLOAD_EXAMPLE');
  });
  it('Deny blocks with exit 2 and a message that never quotes the content', async () => {
    const w = world();
    const f = fakeDeps({ dialog: 'deny', home: w.home });
    const r = await run(write(w.proj, { path: '.kiro/settings/mcp.json', content: 'SECRET_PAYLOAD_EXAMPLE' }), f.deps);
    expect(r.code).toBe(2);
    expect(r.err).toContain('mcp.json');
    expect(r.err).toContain('edit the file in your own editor');
    expect(r.err).not.toContain('SECRET_PAYLOAD_EXAMPLE');
  });
  it('with no dialog and no terminal it blocks', async () => {
    const w = world();
    for (const f of [fakeDeps({ dialog: 'none', home: w.home }), fakeDeps({ dialog: 'unavailable', home: w.home })]) {
      const r = await run(write(w.proj, { path: '.kiro/settings/mcp.json' }), f.deps);
      expect(r.code).toBe(2);
      expect(r.err).toContain('no dialog or terminal');
    }
  });
  it('at a terminal without a dialog, the right typed code allows and a wrong one blocks; the code goes to the terminal, not stdout', async () => {
    const w = world();
    const ok = fakeDeps({ interactive: true, dialog: 'unavailable', typed: 'abc123', home: w.home });
    expect((await run(write(w.proj, { path: '.kiro/settings/mcp.json' }), ok.deps)).code).toBe(0);
    expect(ok.shown.join('\n')).toContain('abc123');
    const bad = fakeDeps({ interactive: true, dialog: 'unavailable', typed: 'nope', home: w.home });
    expect((await run(write(w.proj, { path: '.kiro/settings/mcp.json' }), bad.deps)).code).toBe(2);
  });
  it('a prompt nobody answers times out and blocks', async () => {
    const w = world();
    const f = fakeDeps({ dialog: 'allow', hang: true, timeoutMs: 20, home: w.home });
    const r = await run(write(w.proj, { path: '.kiro/settings/mcp.json' }), f.deps);
    expect(r.code).toBe(2);
    expect(r.err).toContain('in time');
  });
  it('allows other writes, other events and unparseable input without asking', async () => {
    const w = world();
    const f = fakeDeps({ dialog: 'deny', home: w.home });
    expect((await run(write(w.proj, { path: 'src/a.ts', content: 'x' }), f.deps)).code).toBe(0);
    expect((await run({ hook_event_name: 'PostToolUse', cwd: w.proj }, f.deps)).code).toBe(0);
    expect((await run('{ not json', f.deps)).code).toBe(0);
    expect((await run('', f.deps)).code).toBe(0);
    expect(f.dialogs).toEqual([]);
  });
});
