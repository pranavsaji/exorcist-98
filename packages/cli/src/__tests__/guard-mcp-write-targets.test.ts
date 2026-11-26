import { describe, it, expect, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { guardMcpWriteCommand } from '../commands/guard-mcp-write.js';
import type { GuardDeps } from '../commands/guard-mcp-write.js';
import type { DialogAnswer } from '../commands/on-access.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
function world() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'exorcist-ctg-')));
  dirs.push(root);
  const home = join(root, 'home');
  const proj = join(root, 'proj');
  for (const d of [home, join(proj, '.kiro', 'hooks'), join(proj, '.kiro', 'settings'), join(proj, '.vscode')]) mkdirSync(d, { recursive: true });
  writeFileSync(join(proj, '.kiro', 'settings', 'mcp.json'), '{}');
  return { home, proj };
}
const ev = (cwd: string, tool_input: Record<string, unknown>, tool_name = 'fs_write') => ({ hook_event_name: 'PreToolUse', cwd, tool_name, tool_input });
const PAYLOAD = 'SECRET_PAYLOAD_EXAMPLE';
const trustedWrite = (cwd: string) => ev(cwd, { command: 'create', path: '.vscode/settings.json', file_text: `{"kiroAgent.trustedCommands": ["*"], "x": "${PAYLOAD}"}` });
const guardWrite = (cwd: string) => ev(cwd, { command: 'create', path: '.kiro/hooks/x.json', file_text: PAYLOAD });

function fake(answer: DialogAnswer, home: string) {
  const dialogs: { message: string; reason?: string }[] = [];
  const deps: GuardDeps = {
    term: { interactive: false, ask: async () => '', dialog: async (m: string): Promise<DialogAnswer> => { dialogs.push({ message: m }); return answer; }, nonce: () => 'abc123' },
    promptIo: { out: () => undefined, err: () => undefined },
    home, timeoutMs: 1000,
  };
  return { deps, dialogs };
}
const run = async (event: unknown, deps: GuardDeps) => {
  const err: string[] = [];
  const code = await guardMcpWriteCommand(JSON.stringify(event), { out: () => undefined, err: (s) => void err.push(s) }, deps);
  return { code, err: err.join('\n') };
};

describe('guard-mcp-write: trusted commands and guard files', () => {
  it('CT-5: a trusted-commands write asks a person, names the file, never shows the content', async () => {
    const w = world();
    const f = fake('allow', w.home);
    expect((await run(trustedWrite(w.proj), f.deps)).code).toBe(0);
    expect(f.dialogs).toHaveLength(1);
    expect(f.dialogs[0]?.message).toContain('settings.json');
    expect(f.dialogs[0]?.message).toContain('without asking');
    expect(f.dialogs[0]?.message).not.toContain(PAYLOAD);
  });
  it('CT-5: refusing a trusted-commands write blocks with exit 2 and no content', async () => {
    const w = world();
    const r = await run(trustedWrite(w.proj), fake('deny', w.home).deps);
    expect(r.code).toBe(2);
    expect(r.err).toContain('settings.json');
    expect(r.err).not.toContain(PAYLOAD);
    const none = await run(trustedWrite(w.proj), fake('unavailable', w.home).deps);
    expect(none.code).toBe(2);
    expect(none.err).toContain('no dialog or terminal');
  });
  it('CT-5: a write to settings.json that changes no trusted command is not asked about', async () => {
    const w = world();
    const f = fake('deny', w.home);
    const r = await run(ev(w.proj, { command: 'create', path: '.vscode/settings.json', file_text: '{"editor.tabSize": 2}' }), f.deps);
    expect(r.code).toBe(0);
    expect(f.dialogs).toHaveLength(0);
  });
  it('CT-6: a guard-file write asks a person with its own text and never shows the content', async () => {
    const w = world();
    const f = fake('allow', w.home);
    expect((await run(guardWrite(w.proj), f.deps)).code).toBe(0);
    expect(f.dialogs[0]?.message).toContain('x.json');
    expect(f.dialogs[0]?.message).toContain('guard files');
    expect(f.dialogs[0]?.message).not.toContain(PAYLOAD);
  });
  it('CT-6: refusing a guard-file write, or a shell delete of one, blocks with exit 2', async () => {
    const w = world();
    const r = await run(guardWrite(w.proj), fake('deny', w.home).deps);
    expect(r.code).toBe(2);
    expect(r.err).toContain('x.json');
    expect(r.err).not.toContain(PAYLOAD);
    expect((await run(ev(w.proj, { command: 'rm .kiro/hooks/x.json' }, 'execute_bash'), fake('deny', w.home).deps)).code).toBe(2);
  });
  it('CT-6: a write to another .kiro file is not asked about', async () => {
    const w = world();
    const f = fake('deny', w.home);
    expect((await run(ev(w.proj, { command: 'create', path: '.kiro/specs/a/tasks.md', file_text: 'x' }), f.deps)).code).toBe(0);
    expect(f.dialogs).toHaveLength(0);
  });
  it('CT-7: the MCP config keeps its own text and still blocks on refusal', async () => {
    const w = world();
    const f = fake('deny', w.home);
    const r = await run(ev(w.proj, { path: '.kiro/settings/mcp.json', content: PAYLOAD }), f.deps);
    expect(r.code).toBe(2);
    expect(f.dialogs[0]?.message).toContain('MCP configuration file');
    expect(r.err).toContain('An MCP config can start programs on your computer');
    expect(r.err).not.toContain(PAYLOAD);
  });
});
