import { statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { applyInline, buildBaseline, plural } from '@exorcist-98/core';
import { makeRootReader, runScan } from './scan.js';
import { parse, str, strs } from '../util.js';
import type { Io } from '../util.js';

export const BASELINE_FILE = '.exorcist-baseline.json';

export const BASELINE_HELP = `Usage: exorcist baseline [folder] [options]
Scan a folder and write a baseline: the list of findings your team accepts for now.
Later, "exorcist scan <folder> --baseline ${BASELINE_FILE}" shows and fails on new findings only.
The file holds the rule, file, line and a fingerprint of each finding. It holds no text
from your files and no secret. Findings silenced by an inline exorcist-ignore comment
are not written to it.
Options:
  --output <file>         Where to write the baseline (default: ${BASELINE_FILE} in the folder)
  --ignore <path>         Skip a path prefix (repeatable). A .exorcistignore file in the folder lists more.
  --definitions <dir>     Folder of virus definitions (YAML)
`;

export async function baselineCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, {
    output: { type: 'string' }, ignore: { type: 'string', multiple: true },
    definitions: { type: 'string' }, help: { type: 'boolean', short: 'h' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${BASELINE_HELP}`); return 2; }
  if (p.values['help']) { io.out(BASELINE_HELP); return 0; }
  if (p.positionals.length > 1) { io.err(`Give one folder at most.\n\n${BASELINE_HELP}`); return 2; }
  const target = p.positionals[0] ?? '.';
  try {
    if (!statSync(resolve(target)).isDirectory()) { io.err(`${target} is a file. Give a folder to baseline.`); return 2; }
  } catch {
    io.err(`Folder not found: ${target}`);
    return 2;
  }
  const result = await runScan({ target, definitions: str(p.values['definitions']), ignore: strs(p.values['ignore']) }, io);
  if (!result.ok) return result.code;
  const { findings, root } = result.run;
  const { active } = applyInline(findings, makeRootReader(root));
  const baseline = buildBaseline(active);
  const out = str(p.values['output']) ?? join(root, BASELINE_FILE);
  try {
    writeFileSync(out, `${JSON.stringify(baseline, null, 2)}\n`, 'utf8');
  } catch {
    io.err(`Could not write the baseline to ${out}.`);
    return 2;
  }
  io.out(`Wrote ${plural(baseline.entries.length, 'entry', 'entries')} to ${out}`);
  return 0;
}
