/**
 * `exorcist init --kiro`: wire a Kiro project in one command (hooks,
 * steering, the exorcist-reviewer custom agent, optional Shield wrapping of
 * .kiro/settings/mcp.json) and print what it did.
 */
import { afterEach, describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { isWrapped } from '@exorcist-98/shield';
import { DEFAULT_BIN, DEFAULT_MCP_BIN, initCommand, splitCommand } from '../commands/init.js';
import { wrapCommand } from '../commands/config.js';
import { REVIEWER_PROMPT, REVIEWER_TOOLS } from '../kiro-agent.js';
import type { Io } from '../util.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = realpathSync(mkdtempSync(join(tmpdir(), 'x98-init-kiro-'))); dirs.push(d); return d; };
const capture = (): Io & { outs: string[]; errs: string[]; all: () => string } => {
  const outs: string[] = [];
  const errs: string[] = [];
  return { outs, errs, out: (s) => { outs.push(s); }, err: (s) => { errs.push(s); }, all: () => [...outs, ...errs].join('\n') };
};
const json = (path: string): Record<string, unknown> => JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
type HookFile = { version: string; hooks: Array<{ name: string; trigger: string; matcher: string; enabled?: boolean; action: { type: string; command: string } }> };
const hookOf = (d: string, name: string): HookFile['hooks'][number] => {
  const h = (json(join(d, '.kiro/hooks', `${name}.json`)) as unknown as HookFile).hooks[0];
  if (!h) throw new Error(`no hook in ${name}`);
  return h;
};

const MCP = `{
  "mcpServers": {
    "notes": { "command": "node", "args": ["notes.js"] },
    "docs":  { "command": "uvx", "args": ["docs-server==1.2.3"], "env": { "DOCS_TOKEN": "\${DOCS_TOKEN}" } }
  }
}
`;

describe('exorcist init --kiro', () => {
  it('writes the hooks, steering and the reviewer agent, and prints what it did', async () => {
    const d = tmp();
    const io = capture();
    expect(await initCommand([d, '--kiro'], io)).toBe(0);
    for (const f of [
      '.kiro/hooks/exorcist-secrets.json', '.kiro/hooks/exorcist-mcp-scan.json', '.kiro/hooks/exorcist-on-access.json',
      '.kiro/steering/exorcist.md', '.kiro/agents/exorcist-reviewer.json', '.exorcist/kiro-hook.sh', '.githooks/pre-commit',
    ]) expect(existsSync(join(d, f)), f).toBe(true);

    // Kiro's documented hook format: v1, PascalCase triggers, command actions through the PATH wrapper.
    expect(hookOf(d, 'exorcist-secrets').trigger).toBe('PreToolUse');
    expect(hookOf(d, 'exorcist-mcp-scan').trigger).toBe('PostFileSave');
    expect(hookOf(d, 'exorcist-on-access').trigger).toBe('PreToolUse');
    for (const n of ['exorcist-secrets', 'exorcist-mcp-scan', 'exorcist-on-access']) {
      expect(hookOf(d, n).action.command.startsWith('sh .exorcist/kiro-hook.sh ')).toBe(true);
    }
    // Steering front matter is the first thing in the file (kiro.dev/docs/steering).
    expect(readFileSync(join(d, '.kiro/steering/exorcist.md'), 'utf8').startsWith('---\ninclusion: always\n---\n')).toBe(true);

    const agent = json(join(d, '.kiro/agents/exorcist-reviewer.json')) as {
      name: string; prompt: string; tools: string[]; includeMcpJson: boolean;
      mcpServers: { exorcist: { command: string; args: string[]; env: Record<string, string> } };
      permissions: { rules: Array<{ capability: string; match: string[]; effect: string }> };
    };
    expect(agent.name).toBe('exorcist-reviewer');
    expect(agent.prompt).toBe(REVIEWER_PROMPT);
    expect(agent.tools).toEqual([...REVIEWER_TOOLS]);
    expect(agent.includeMcpJson).toBe(false);
    expect([agent.mcpServers.exorcist.command, ...agent.mcpServers.exorcist.args].join(' ')).toBe(DEFAULT_MCP_BIN);
    expect(agent.mcpServers.exorcist.env['EXORCIST_MCP_NO_QUOTES']).toBe('1');
    expect(agent.permissions.rules).toContainEqual({ capability: 'shell', match: ['*'], effect: 'deny' });
    expect(agent.permissions.rules).toContainEqual({ capability: 'mcp', match: ['exorcist/quarantine'], effect: 'deny' });

    const out = io.all();
    for (const s of ['exorcist-secrets.json', 'exorcist-mcp-scan.json', 'exorcist-on-access.json', 'exorcist-reviewer.json',
      'no .kiro/settings/mcp.json yet', 'Shield: not applied', 'git config core.hooksPath .githooks', 'trust the workspace']) {
      expect(out).toContain(s);
    }
  });

  it('under the default command (0.1.2, which has on-access) every hook is on', async () => {
    const d = tmp();
    const io = capture();
    expect(await initCommand([d, '--kiro'], io)).toBe(0);
    expect(hookOf(d, 'exorcist-on-access').enabled).toBeUndefined();
    expect(hookOf(d, 'exorcist-on-access').action.command).toContain(DEFAULT_BIN);
    expect(io.all()).not.toContain('WRITTEN DISABLED');
    expect(hookOf(d, 'exorcist-secrets').enabled).toBeUndefined();
    expect(hookOf(d, 'exorcist-mcp-scan').enabled).toBeUndefined();

    const local = tmp();
    expect(await initCommand([local, '--kiro', '--bin', '"/opt/node 22/bin/node" /opt/x98/cli.mjs'], capture())).toBe(0);
    expect(hookOf(local, 'exorcist-on-access').enabled).toBeUndefined();
    expect(hookOf(local, 'exorcist-on-access').action.command).toBe('sh .exorcist/kiro-hook.sh "/opt/node 22/bin/node" /opt/x98/cli.mjs on-access');
  });

  it('--no-agent leaves the agent out; --no-agent alone and a bad --bin are usage errors', async () => {
    const d = tmp();
    const io = capture();
    expect(await initCommand([d, '--kiro', '--no-agent'], io)).toBe(0);
    expect(existsSync(join(d, '.kiro/agents'))).toBe(false);
    expect(io.all()).toContain('not installed (--no-agent)');
    expect(await initCommand([tmp(), '--no-agent'], capture())).toBe(2);
    expect(await initCommand([tmp(), '--bin', '"unclosed'], capture())).toBe(2);
    expect(await initCommand([tmp(), '--kiro', '--mcp-bin', '   '], capture())).toBe(2);
    expect(await initCommand([tmp(), tmp()], capture())).toBe(2);
  });

  it('plain init (no --kiro) is unchanged: no agent, no summary, never touches mcp.json', async () => {
    const d = tmp();
    mkdirSync(join(d, '.kiro/settings'), { recursive: true });
    writeFileSync(join(d, '.kiro/settings/mcp.json'), MCP);
    const io = capture();
    expect(await initCommand([d], io)).toBe(0);
    expect(existsSync(join(d, '.kiro/agents/exorcist-reviewer.json'))).toBe(false);
    expect(readFileSync(join(d, '.kiro/settings/mcp.json'), 'utf8')).toBe(MCP);
    expect(io.all()).not.toContain('Exorcist 98 for Kiro');
  });

  it('--kiro without --shield reports the MCP config but leaves it alone', async () => {
    const d = tmp();
    mkdirSync(join(d, '.kiro/settings'), { recursive: true });
    writeFileSync(join(d, '.kiro/settings/mcp.json'), MCP);
    const io = capture();
    expect(await initCommand([d, '--kiro'], io)).toBe(0);
    expect(readFileSync(join(d, '.kiro/settings/mcp.json'), 'utf8')).toBe(MCP);
    expect(io.all()).toContain('.kiro/settings/mcp.json: 2 servers, 0 behind the Shield');
  });

  it('--shield puts every server behind the Shield with the --bin command, and unwrap restores the file byte for byte', async () => {
    const d = tmp();
    const cfg = join(d, '.kiro/settings/mcp.json');
    mkdirSync(join(d, '.kiro/settings'), { recursive: true });
    writeFileSync(cfg, MCP);
    const io = capture();
    expect(await initCommand([d, '--shield', '--bin', '"/opt/node 22/bin/node" /opt/x98/cli.mjs'], io)).toBe(0);
    const wrapped = json(cfg) as { mcpServers: Record<string, { command: string; args: string[] }> };
    for (const name of ['notes', 'docs']) {
      const e = wrapped.mcpServers[name];
      expect(e && isWrapped(e), name).toBe(true);
      expect(e?.command).toBe('/opt/node 22/bin/node');
      expect(e?.args.slice(0, 4)).toEqual(['/opt/x98/cli.mjs', 'shield', '--server', name]);
      expect(e?.args).toContain(join(d, '.exorcist'));
    }
    expect(io.all()).toContain('Wrapped: notes, docs.');
    expect(io.all()).toContain('Undo: exorcist unwrap .kiro/settings/mcp.json');
    expect(io.all()).toContain('2 servers, 2 behind the Shield');
    // --shield implies --kiro.
    expect(existsSync(join(d, '.kiro/agents/exorcist-reviewer.json'))).toBe(true);

    // Reversible: unwrap (from any folder) finds the backup through --dir and restores the exact bytes.
    const un = capture();
    expect(await wrapCommand([cfg], un, 'unwrap')).toBe(0);
    expect(readFileSync(cfg, 'utf8')).toBe(MCP);
    expect(un.all()).toContain('byte for byte');
  });

  it('--shield running twice wraps nothing new; without an MCP config it writes the rest and exits 1', async () => {
    const d = tmp();
    mkdirSync(join(d, '.kiro/settings'), { recursive: true });
    writeFileSync(join(d, '.kiro/settings/mcp.json'), MCP);
    expect(await initCommand([d, '--shield'], capture())).toBe(0);
    const once = readFileSync(join(d, '.kiro/settings/mcp.json'), 'utf8');
    const again = capture();
    expect(await initCommand([d, '--shield'], again)).toBe(0);
    expect(readFileSync(join(d, '.kiro/settings/mcp.json'), 'utf8')).toBe(once);
    expect(again.all()).toContain('Nothing to wrap.');
    expect(again.all()).toContain('Kept existing .kiro/agents/exorcist-reviewer.json');

    const empty = tmp();
    const io = capture();
    expect(await initCommand([empty, '--shield'], io)).toBe(1);
    expect(io.all()).toContain('there is no .kiro/settings/mcp.json to wrap');
    expect(existsSync(join(empty, '.kiro/hooks/exorcist-secrets.json'))).toBe(true);
    expect(existsSync(join(empty, '.kiro/settings/mcp.json'))).toBe(false);
  });

  it('never overwrites without --force, and --force replaces', async () => {
    const d = tmp();
    expect(await initCommand([d, '--kiro'], capture())).toBe(0);
    writeFileSync(join(d, '.kiro/agents/exorcist-reviewer.json'), '{"name":"mine"}\n');
    const io = capture();
    expect(await initCommand([d, '--kiro'], io)).toBe(1);
    expect(readFileSync(join(d, '.kiro/agents/exorcist-reviewer.json'), 'utf8')).toBe('{"name":"mine"}\n');
    expect(io.all()).toContain('kept  .kiro/agents/exorcist-reviewer.json');
    expect(await initCommand([d, '--kiro', '--force'], capture())).toBe(0);
    expect((json(join(d, '.kiro/agents/exorcist-reviewer.json')) as { name: string }).name).toBe('exorcist-reviewer');
  });
});

describe('splitCommand (how --bin and --mcp-bin become a command and its arguments)', () => {
  it('splits on whitespace and groups quotes', () => {
    expect(splitCommand(DEFAULT_BIN)).toEqual(['npx', '-y', '@exorcist-98/cli@0.1.2']);
    expect(splitCommand(`"/a b/node" '/c d/cli.mjs'  x`)).toEqual(['/a b/node', '/c d/cli.mjs', 'x']);
    expect(splitCommand('""')).toEqual(['']);
    expect(splitCommand('  ')).toBeNull();
    expect(splitCommand('"open')).toBeNull();
  });

  it('PBT-INIT-01: any list of words, each double-quoted and joined by spaces, splits back to the same list', () => {
    const word = fc.string({ minLength: 0, maxLength: 12 }).filter((w) => !w.includes('"'));
    fc.assert(fc.property(fc.array(word, { minLength: 1, maxLength: 6 }), (words) => {
      expect(splitCommand(words.map((w) => `"${w}"`).join(' '))).toEqual(words);
    }));
  });
});
