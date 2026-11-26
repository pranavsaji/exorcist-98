#!/usr/bin/env node
// Runs after a spec task finishes (m13-kiro-evidence, KE-28): the workspace
// typecheck, then the vitest files related to the files git reports as changed.
// No shell is involved: every command runs with an argument array, and a file
// name is only ever passed as one argument after `--`.
// Exit 0 when both pass, 1 otherwise (Kiro hands stderr to the agent).
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SOURCE = /\.(?:ts|tsx|mts|mjs|js)$/;

function run(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  return { code: r.status ?? 1, out: `${r.stdout ?? ''}${r.stderr ?? ''}`, missing: r.error?.code === 'ENOENT' };
}

/** Changed and untracked source files that still exist, as repo-relative paths. */
export function changedSourceFiles() {
  const lists = [
    run('git', ['diff', '--name-only', '-z', 'HEAD']),
    run('git', ['ls-files', '--others', '--exclude-standard', '-z']),
  ];
  const names = lists.flatMap((l) => (l.code === 0 ? l.out.split('\0') : []));
  const seen = new Set(names.filter((n) => n && !n.startsWith('-') && SOURCE.test(n) && existsSync(join(ROOT, n))));
  return [...seen].sort();
}

function tail(text, lines = 40) {
  return text.trimEnd().split('\n').slice(-lines).join('\n');
}

function main() {
  const failures = [];
  const tc = run('pnpm', ['-r', 'typecheck']);
  if (tc.missing) {
    process.stderr.write('verify-after-task: pnpm was not found, so nothing was checked.\n');
    return 1;
  }
  if (tc.code !== 0) failures.push(`pnpm -r typecheck failed:\n${tail(tc.out)}`);

  const files = changedSourceFiles();
  if (files.length > 0) {
    const t = run('pnpm', ['exec', 'vitest', 'related', '--run', '--passWithNoTests', '--', ...files]);
    if (t.code !== 0) failures.push(`vitest related failed:\n${tail(t.out)}`);
  }
  if (failures.length > 0) {
    process.stderr.write(`${failures.join('\n\n')}\nFix these before moving to the next task.\n`);
    return 1;
  }
  process.stdout.write(`verify-after-task: typecheck passed; ${files.length} changed file(s) checked.\n`);
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exit(main());
