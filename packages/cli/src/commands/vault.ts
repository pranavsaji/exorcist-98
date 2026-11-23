import { resolve } from 'node:path';
import { diffEntry, listEntries, quarantineFile, quarantineServer, restoreEntry, vaultPath } from '@exorcist-98/shield';
import { DEFAULT_DIR, stateDir, parse, str } from '../util.js';
import type { Io } from '../util.js';

export const VAULT_HELP = `Usage: exorcist vault <command> [--dir <folder>]

Commands:
  list                                   Show everything in the vault
  quarantine-server <mcp.json> <server>  Disable an MCP server (keeps a backup)
  quarantine-file <path>                 Move a hook or steering file into the vault
  diff <id>                              What changed since the backup
  restore <id> [--force]                 Put the original back (also undoes exorcise --write)

Options:
  --reason <text>   Why (for quarantine commands)
  --dir <folder>    State folder (default: ${DEFAULT_DIR})
`;

export async function vaultCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, {
    dir: { type: 'string' }, reason: { type: 'string' }, force: { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${VAULT_HELP}`); return 2; }
  const [sub, ...args] = p.positionals;
  if (p.values['help'] || !sub) { io.out(VAULT_HELP); return sub || p.values['help'] ? 0 : 2; }

  const vault = vaultPath(stateDir(str(p.values['dir'])));
  const reason = str(p.values['reason']) ?? 'quarantined by hand';
  const fail = (e: string): number => { io.err(e); return 1; };

  switch (sub) {
    case 'list': {
      const entries = listEntries(vault);
      if (entries.length === 0) { io.out('The vault is empty.'); return 0; }
      for (const e of entries) {
        io.out(`${e.id}  ${e.status.padEnd(11)}  ${e.kind === 'mcp-server' ? `server ${e.serverName}` : e.kind === 'exorcise' ? `exorcism of ${e.files?.length ?? 0} file(s) in` : 'file'}  ${e.target}  (${e.reason})`);
      }
      return 0;
    }
    case 'quarantine-server': {
      const [config, server] = args;
      if (!config || !server) { io.err('Give the MCP config file and the server name.'); return 2; }
      const r = quarantineServer({ configPath: config, serverName: server, reason, vaultDir: vault });
      if (!r.ok) return fail(r.error);
      io.out(`Quarantined "${server}". Vault entry: ${r.value.id}\nRestore with: exorcist vault restore ${r.value.id}`);
      return 0;
    }
    case 'quarantine-file': {
      const [file] = args;
      if (!file) { io.err('Give the file to quarantine.'); return 2; }
      const r = quarantineFile({ filePath: file, reason, vaultDir: vault });
      if (!r.ok) return fail(r.error);
      io.out(`Moved ${r.value.target} into the vault. Vault entry: ${r.value.id}\nRestore with: exorcist vault restore ${r.value.id}`);
      return 0;
    }
    case 'diff': {
      const [id] = args;
      if (!id) { io.err('Give the vault entry id.'); return 2; }
      const r = diffEntry(vault, id);
      if (!r.ok) return fail(r.error);
      io.out(r.value);
      return 0;
    }
    case 'restore': {
      const [id] = args;
      if (!id) { io.err('Give the vault entry id.'); return 2; }
      const r = restoreEntry(vault, id, { force: p.values['force'] === true });
      if (!r.ok) return fail(r.error);
      io.out(`Restored ${r.value.kind === 'mcp-server' ? `server "${r.value.serverName}"` : r.value.kind === 'exorcise' ? `${r.value.files?.length ?? 0} file(s) in ${r.value.target} to their original bytes` : r.value.target}.`);
      return 0;
    }
    default:
      io.err(`Unknown vault command "${sub}".\n\n${VAULT_HELP}`);
      return 2;
  }
}
