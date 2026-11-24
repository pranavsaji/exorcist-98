import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { unwrapConfig, wrapConfig } from '@exorcist-98/shield';
import type { McpConfig } from '@exorcist-98/shield';
import { DEFAULT_DIR, stateDir, parse, str, strs } from '../util.js';
import type { Io } from '../util.js';

export const WRAP_HELP = `Usage: exorcist wrap <mcp.json> [options]
       exorcist unwrap <mcp.json>

wrap   Run every MCP server in the file, local or remote, through the shield.
       The original file text is kept in the state folder.
unwrap Put the original file back byte for byte, if it was not edited since
       wrap; otherwise put the original commands back (formatting may differ).

Options (wrap):
  --bin <command>       Command that runs the shield (default: exorcist)
  --bin-arg <arg>       Argument before "shield" (repeatable), e.g. --bin npx --bin-arg -y --bin-arg @exorcist-98/cli@0.1.1
  --dir <folder>        State folder (default: ${DEFAULT_DIR})
  --dry-run             Show the result without writing the file
`;

/** Where `wrap` keeps the original text of one config file. */
function backupPath(dir: string, configPath: string): string {
  return join(dir, 'wrap-backups', `${createHash('sha256').update(configPath).digest('hex').slice(0, 32)}.json`);
}

type Backup = { path: string; original: string; wrapped: string };

function readBackup(file: string): Backup | null {
  try {
    const b = JSON.parse(readFileSync(file, 'utf8')) as Partial<Backup>;
    return typeof b.original === 'string' && typeof b.wrapped === 'string' && typeof b.path === 'string' ? (b as Backup) : null;
  } catch {
    return null;
  }
}

/** The state folders named by `--dir` in wrapped entries, where their backups are. */
function dirsInConfig(cfg: McpConfig): string[] {
  const out: string[] = [];
  for (const e of Object.values(cfg.mcpServers ?? {})) {
    const args = e['args'];
    if (!Array.isArray(args)) continue;
    const i = args.indexOf('--dir');
    const d = i === -1 ? undefined : args[i + 1];
    if (typeof d === 'string' && !out.includes(d)) out.push(d);
  }
  return out;
}

function readConfig(path: string, io: Io): McpConfig | null {
  if (!existsSync(path)) { io.err(`File not found: ${path}`); return null; }
  try {
    const json = JSON.parse(readFileSync(path, 'utf8')) as unknown;
    if (!json || typeof json !== 'object' || Array.isArray(json)) throw new Error('not an object');
    return json as McpConfig;
  } catch {
    io.err(`${path} is not a valid JSON object.`);
    return null;
  }
}

export async function wrapCommand(argv: string[], io: Io, mode: 'wrap' | 'unwrap'): Promise<number> {
  const p = parse(argv, {
    bin: { type: 'string' }, 'bin-arg': { type: 'string', multiple: true }, dir: { type: 'string' },
    'dry-run': { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${WRAP_HELP}`); return 2; }
  if (p.values['help']) { io.out(WRAP_HELP); return 0; }
  const file = p.positionals[0];
  if (!file || p.positionals.length > 1) { io.err(`Give exactly one MCP config file.\n\n${WRAP_HELP}`); return 2; }

  const path = resolve(file);
  const cfg = readConfig(path, io);
  if (!cfg) return 2;
  const text = readFileSync(path, 'utf8');

  let next: McpConfig;
  let names: string[];
  if (mode === 'wrap') {
    const r = wrapConfig(cfg, {
      bin: str(p.values['bin']) ?? 'exorcist',
      binArgs: strs(p.values['bin-arg']),
      dir: stateDir(str(p.values['dir'])),
      configPath: path,
    });
    next = r.config;
    names = r.wrapped;
  } else {
    const r = unwrapConfig(cfg);
    next = r.config;
    names = r.unwrapped;
  }

  if (p.values['dry-run']) {
    io.out(JSON.stringify(next, null, 2));
  } else if (names.length > 0) {
    const out = `${JSON.stringify(next, null, 2)}\n`;
    if (mode === 'wrap') {
      writeFileSync(path, out, 'utf8');
      // Keep the original text so unwrap can restore it exactly. It may hold
      // tokens (the original file did too), so only the owner may read it.
      const b = backupPath(stateDir(str(p.values['dir'])), path);
      try {
        mkdirSync(join(b, '..'), { recursive: true, mode: 0o700 });
        writeFileSync(b, JSON.stringify({ path, original: text, wrapped: out } satisfies Backup), { mode: 0o600 });
      } catch {
        io.err('Could not save a copy of the original file; unwrap will still restore the original commands.');
      }
    } else {
      const candidates = [...new Set([...dirsInConfig(cfg), stateDir(str(p.values['dir']))])].map((d) => backupPath(d, path));
      const found = candidates.map((f) => ({ f, b: readBackup(f) })).find((x) => x.b !== null && x.b.path === path);
      if (found?.b && found.b.wrapped === text) {
        writeFileSync(path, found.b.original, 'utf8');
        rmSync(found.f, { force: true });
        io.err(`Unwrapped: ${names.join(', ')}. The original file was restored byte for byte.`);
        return 0;
      }
      writeFileSync(path, out, 'utf8');
      if (found) {
        rmSync(found.f, { force: true });
        io.err('The file was edited after wrap, so the original commands were put back but its formatting may differ.');
      }
    }
  }
  io.err(names.length === 0 ? `Nothing to ${mode}.` : `${mode === 'wrap' ? 'Wrapped' : 'Unwrapped'}: ${names.join(', ')}.`);
  return 0;
}
