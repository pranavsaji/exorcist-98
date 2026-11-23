import { decideCommitGuard } from '@exorcist-98/core';
import { approveCommand, alertsCommand } from './commands/approve.js';
import { canaryCommand } from './commands/canary.js';
import { wrapCommand } from './commands/config.js';
import { checkStagedCommand } from './commands/check-staged.js';
import { exorciseCommand } from './commands/exorcise.js';
import { hookScanCommand } from './commands/hook-scan.js';
import { initCommand } from './commands/init.js';
import { lockCommand } from './commands/lock.js';
import { mapCommand } from './commands/map.js';
import { onAccessCommand, allowReadCommand } from './commands/on-access.js';
import { originCommand } from './commands/origin.js';
import { scanCommand } from './commands/scan.js';
import { shieldCommand } from './commands/shield.js';
import { updateCommand } from './commands/update.js';
import { vaultCommand } from './commands/vault.js';
import { stdio } from './util.js';

const VERSION = '0.1.0';

const HELP = `Exorcist 98 ${VERSION}: antivirus for AI coding agents

Usage: exorcist <command> [options]

Commands:
  scan <path>        Scan a folder or file for attacks on AI agents
  map [dir]          Draw the Haunted House Map: which MCP servers read secrets,
                     take in untrusted text, or can send data out (EX-023)
  update             LiveUpdate: verify and install signed definitions
                     (exorcist update --from <https-url-or-file>, or --status)
  exorcise [path]    Disinfect: fix what has one safe fix (dry run; --write applies)
  shield             Run an MCP server behind the Real-Time Shield
  wrap <mcp.json>    Run every local MCP server in a config through the shield
  unwrap <mcp.json>  Undo wrap
  lock               Write exorcist.lock, the team's record of its MCP tools; with
                     --check, exit 1 if a tool changed (see: exorcist lock --help)
  vault <command>    Quarantine and restore MCP servers, hooks and steering files
  approve <kind>     Approve a changed tool or a host (see: exorcist approve --help)
  alerts             Show recent shield alerts
  init [folder]      Add hooks and steering to a Kiro project
  canary <command>   Plant, list (--list) or remove (--remove) canary traps (EX-022)
  on-access          Hook helper: block a read of a file that hides instructions for the AI
  allow-read <file>  Let one file be read once (by its content hash)
  origin [dir]       Scan, then trace each threat to the commit that added it
  guard-commit       Hook helper: block git commit while secrets are staged
  hook-scan          Hook helper: scan the file named in a Kiro "file saved" event
  check-staged       Git pre-commit helper: exit 1 if staged files contain secrets or canary tokens

Run "exorcist <command> --help" for details.
`;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

export async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  switch (cmd) {
    case undefined:
    case '--help':
    case '-h':
    case 'help':
      stdio.out(HELP);
      return cmd === undefined ? 2 : 0;
    case '--version':
    case '-v':
      stdio.out(VERSION);
      return 0;
    case 'scan':   return await scanCommand(rest, stdio);
    case 'map':    return await mapCommand(rest, stdio);
    case 'update': return await updateCommand(rest, stdio);
    case 'exorcise': return await exorciseCommand(rest, stdio);
    case 'shield': return await shieldCommand(rest, stdio);
    case 'canary': return await canaryCommand(rest, stdio);
    case 'wrap':   return await wrapCommand(rest, stdio, 'wrap');
    case 'unwrap': return await wrapCommand(rest, stdio, 'unwrap');
    case 'lock':   return await lockCommand(rest, stdio);
    case 'vault':  return await vaultCommand(rest, stdio);
    case 'approve': return await approveCommand(rest, stdio);
    case 'alerts': return await alertsCommand(rest, stdio);
    case 'init':   return await initCommand(rest, stdio);
    case 'origin': return await originCommand(rest, stdio);
    case 'hook-scan': return await hookScanCommand(await readStdin(), stdio);
    case 'on-access': return await onAccessCommand(await readStdin(), stdio);
    case 'allow-read': return await allowReadCommand(rest, stdio);
    case 'check-staged': return await checkStagedCommand(stdio);
    case 'guard-commit': {
      const d = decideCommitGuard(await readStdin());
      if (d.message) stdio.err(d.message);
      return d.exitCode;
    }
    default:
      stdio.err(`Unknown command "${cmd}".\n\n${HELP}`);
      return 2;
  }
}

/**
 * Exit only after stdout and stderr are flushed. Writes to a pipe are
 * asynchronous, so process.exit() straight away cut JSON reports at 64 KB
 * when another program read them (found on large real repositories).
 */
function exitAfterFlush(code: number): void {
  process.exitCode = code;
  process.stdout.write('', () => process.stderr.write('', () => process.exit(code)));
}
main(process.argv.slice(2)).then(
  (code) => exitAfterFlush(code),
  (err: unknown) => {
    stdio.err(`Unexpected error: ${String(err).split('\n')[0]}`);
    exitAfterFlush(1);
  },
);
