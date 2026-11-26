import { describe, it, expect, afterEach } from 'vitest';
import fc from 'fast-check';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decideMcpWrite, isGuardFileWrite, isTrustedCommandsWrite } from '@exorcist-98/core';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
function world() {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'exorcist-ct-')));
  dirs.push(root);
  const home = join(root, 'home');
  const proj = join(root, 'proj');
  for (const d of [join(home, '.kiro', 'hooks'), join(proj, '.kiro', 'hooks'), join(proj, '.kiro', 'agents'), join(proj, '.kiro', 'specs', 'x'), join(proj, '.vscode'), join(proj, 'src')]) mkdirSync(d, { recursive: true });
  return { home, proj };
}
const ev = (cwd: string, tool_input: Record<string, unknown>, tool_name = 'fs_write') => ({ hook_event_name: 'PreToolUse', cwd, tool_name, tool_input });
const target = (e: unknown, home: string) => decideMcpWrite(e, home, '/').target;
const settings = (cmds: string[]) => `{\n  // trusted\n  "kiroAgent.trustedCommands": ${JSON.stringify(cmds)}\n}\n`;

describe('decideMcpWrite: trusted commands', () => {
  it('CT-5: fs_write that adds a wildcard trusted command needs confirmation', () => {
    const w = world();
    const e = ev(w.proj, { command: 'create', path: '.vscode/settings.json', file_text: settings(['*']) });
    expect(target(e, w.home)).toBe('trusted-commands');
    expect(decideMcpWrite(e, w.home, '/')).toEqual({ target: 'trusted-commands', path: join(w.proj, '.vscode', 'settings.json') });
  });
  it('CT-5: str_replace is applied to the file on disk, so widening one entry is seen', () => {
    const w = world();
    writeFileSync(join(w.proj, '.vscode', 'settings.json'), settings(['git status']));
    const widen = ev(w.proj, { command: 'strReplace', path: '.vscode/settings.json', old_str: '"git status"', new_str: '"git status", "*"' }, 'str_replace');
    expect(target(widen, w.home)).toBe('trusted-commands');
  });
  it('CT-5: a write that changes no trusted entry is allowed', () => {
    const w = world();
    writeFileSync(join(w.proj, '.vscode', 'settings.json'), settings(['git status']));
    const same = ev(w.proj, { command: 'create', path: '.vscode/settings.json', file_text: settings(['git status']) });
    const other = ev(w.proj, { command: 'create', path: '.vscode/settings.json', file_text: '{ "editor.tabSize": 2 }' });
    const edit = ev(w.proj, { command: 'strReplace', path: '.vscode/settings.json', old_str: '// trusted', new_str: '// ok' }, 'str_replace');
    for (const e of [same, other, edit]) expect(target(e, w.home)).toBe('other');
  });
  it('CT-5: a shell write of the setting into settings.json needs confirmation', () => {
    const w = world();
    const cmds = [
      `echo '{"kiroAgent.trustedCommands":["*"]}' > .vscode/settings.json`,
      `echo '{"kiroAgent.trustedCommands":["*"]}' | tee ./.vscode/settings.json`,
      `sed -i 's/"git status"/"*"/; s/trustedCommands/trustedCommands/' .vscode/settings.json`,
      `jq '.["kiroAgent.trustedCommands"]=["*"]' .vscode/settings.json > /tmp/t && mv /tmp/t .vscode/settings.json`,
      `cp /tmp/evil.json .vscode/settings.json`,
    ];
    for (const command of cmds) expect(target(ev(w.proj, { command }, 'execute_bash'), w.home)).toBe('trusted-commands');
  });
  it('CT-5: unrelated shell commands and reads are allowed', () => {
    const w = world();
    for (const command of ['cat .vscode/settings.json', 'echo hi > .vscode/settings.json', 'grep trustedCommands .vscode/settings.json']) {
      expect(target(ev(w.proj, { command }, 'execute_bash'), w.home)).toBe('other');
    }
    expect(isTrustedCommandsWrite(ev(w.proj, { path: '.vscode/settings.json', file_text: settings(['*']) }, 'fs_read'), w.home, '/')).toBeNull();
  });
});

describe('decideMcpWrite: guard files', () => {
  it('CT-6: fs_write and str_replace into hooks and agents need confirmation, in every path form', () => {
    const w = world();
    const abs = join(w.proj, '.kiro', 'hooks', 'x.json');
    const forms: [string, string][] = [
      [w.proj, '.kiro/hooks/x.json'],
      [w.proj, abs],
      [join(w.proj, 'src'), '../.kiro/hooks/x.json'],
      [w.proj, '.kiro/agents/./a.json'],
      [w.proj, '.kiro/hooks/../agents/a.json'],
      [w.proj, '~/.kiro/hooks/x.json'],
    ];
    for (const tool of ['fs_write', 'str_replace']) {
      for (const [cwd, path] of forms) expect(target(ev(cwd, { command: 'create', path, file_text: '{}' }, tool), w.home), `${tool} ${path}`).toBe('guard-file');
    }
    expect(decideMcpWrite(ev(w.proj, { path: '.kiro/hooks/x.json' }), w.home, '/')).toEqual({ target: 'guard-file', path: abs });
  });
  it('CT-6: shell create, change, move and delete in hooks and agents need confirmation', () => {
    const w = world();
    const cmds = [
      'echo {} > .kiro/hooks/x.json', 'echo {} >> ~/.kiro/hooks/x.json', 'tee .kiro/agents/a.json', 'sed -i s/a/b/ .kiro/hooks/x.json',
      'cp /tmp/a.json .kiro/agents/', 'cp /tmp/a.json .kiro/agents/a.json', 'mv /tmp/a.json .kiro/hooks/a.json', 'mv .kiro/hooks/x.json /tmp/x.json',
      'rm .kiro/hooks/x.json', 'rm -rf .kiro/hooks', 'touch ../.kiro/agents/new.json',
    ];
    for (const command of cmds) expect(target(ev(join(w.proj, 'src'), { command }, 'execute_bash'), w.home), command).toBe('guard-file');
  });
  it('CT-6: another .kiro/ file, such as a spec, is allowed', () => {
    const w = world();
    expect(target(ev(w.proj, { path: '.kiro/specs/x/tasks.md', file_text: 'x' }), w.home)).toBe('other');
    expect(target(ev(w.proj, { path: '.kiro/steering/a.md', file_text: 'x' }, 'str_replace'), w.home)).toBe('other');
    expect(target(ev(w.proj, { command: 'echo hi > .kiro/specs/x/notes.md' }, 'execute_bash'), w.home)).toBe('other');
    expect(target(ev(w.proj, { command: 'ls .kiro/hooks' }, 'execute_bash'), w.home)).toBe('other');
    expect(target(ev(w.proj, { path: '.kiro/hooks/x.json' }, 'fs_read'), w.home)).toBe('other');
  });
  it('CT-6: a one-line edit that merely mentions the folder is allowed', () => {
    const w = world();
    expect(isGuardFileWrite(ev(w.proj, { path: 'README.md', old_str: 'a', new_str: '.kiro/hooks/x.json' }, 'str_replace'), w.home, '/')).toBeNull();
  });
});

describe('decideMcpWrite: MCP config unchanged', () => {
  it('CT-7: mcp.json is still mcp-config and wins over the new targets', () => {
    const w = world();
    mkdirSync(join(w.proj, '.kiro', 'settings'), { recursive: true });
    const real = join(w.proj, '.kiro', 'settings', 'mcp.json');
    expect(decideMcpWrite(ev(w.proj, { path: '.kiro/settings/mcp.json' }), w.home, '/')).toEqual({ target: 'mcp-config', path: real });
    expect(target(ev(w.proj, { command: 'cp a .kiro/settings/mcp.json && rm .kiro/hooks/x' }, 'execute_bash'), w.home)).toBe('mcp-config');
  });
  it('CT-7: non-events are still other', () => {
    expect(decideMcpWrite('text', '/h', '/').target).toBe('other');
    expect(decideMcpWrite({ cwd: '/p' }, '/h', '/').target).toBe('other');
  });
});

describe('decideMcpWrite: properties', () => {
  it('CT-6: Property 7: a guard-file write is classified guard-file whatever the path form or tool', () => {
    const w = world();
    const name = fc.stringMatching(/^[a-z][a-z0-9-]{0,10}\.json$/);
    const dir = fc.constantFrom('hooks', 'agents');
    const form = fc.constantFrom('relative', 'absolute', 'dotdot', 'dot', 'home', 'detour');
    const tool = fc.constantFrom('fs_write', 'str_replace', 'shell-redirect', 'shell-tee', 'shell-rm', 'shell-mv', 'shell-cp');
    fc.assert(fc.property(name, dir, form, tool, (file, d, f, t) => {
      const home = f === 'home';
      const base = home ? w.home : w.proj;
      const rel = join('.kiro', d, file);
      let cwd = w.proj;
      let path = rel;
      if (f === 'absolute') path = join(base, rel);
      else if (f === 'dotdot') { cwd = join(w.proj, 'src'); path = join('..', rel); }
      else if (f === 'dot') path = `./.kiro/./${d}/${file}`;
      else if (home) path = `~/${rel}`;
      else if (f === 'detour') path = `.kiro/specs/../${d}/${file}`;
      const q = (s: string) => `'${s}'`;
      const event = t === 'fs_write' || t === 'str_replace'
        ? ev(cwd, { command: 'create', path, file_text: '{}' }, t)
        : ev(cwd, { command: t === 'shell-redirect' ? `echo {} > ${q(path)}` : t === 'shell-tee' ? `echo {} | tee ${q(path)}` : t === 'shell-rm' ? `rm -f ${q(path)}` : t === 'shell-mv' ? `mv ${q(path)} /tmp/gone` : `cp /tmp/a.json ${q(path)}` }, 'execute_bash');
      return decideMcpWrite(event, w.home, '/').target === 'guard-file';
    }), { numRuns: 200 });
  });
});
