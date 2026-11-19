import { existsSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanCommand } from './scan.js';
import type { Io } from '../util.js';

/**
 * Kiro "file saved" hook helper. Kiro sends the event as JSON on stdin; the
 * saved file is in `file_path` (seen in a real PostFileSave event). The file is
 * scanned and a finding at or above `high` exits 1, so Kiro reports it.
 * Anything it cannot read is not an error: a hook must not break saving.
 */
export async function hookScanCommand(stdin: string, io: Io): Promise<number> {
  let event: { file_path?: unknown; cwd?: unknown };
  try {
    event = JSON.parse(stdin) as typeof event;
  } catch {
    return 0;
  }
  if (typeof event.file_path !== 'string' || event.file_path === '') return 0;
  const base = typeof event.cwd === 'string' && event.cwd ? event.cwd : process.cwd();
  const file = resolve(base, event.file_path);
  if (!existsSync(file) || !statSync(file).isFile()) return 0;
  // On failure Kiro shows the agent stderr (stdout is only used on success),
  // so the report goes to stderr.
  return await scanCommand([file, '--fail-on', 'high'], { out: io.err, err: io.err });
}
