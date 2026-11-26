#!/usr/bin/env node
// Traces requirement IDs to test names (m13-kiro-evidence, KE-22 to KE-24).
//
//   node scripts/spec-trace.mjs [--root <dir>] [--spec <name>]... [--warn]
//
// For each .kiro/specs/<name>/requirements.md whose acceptance criteria start
// with an ID such as KG-1, it lists the IDs no test name starts with and the
// test names that start with an ID the spec does not have. Specs without IDs
// are not covered. Exit 0 when no gap is found, 1 otherwise; with --warn the
// gaps are still printed but the exit code is always 0 (used by the save hook).
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { register } from 'tsx/esm/api';
register();
const HERE = join(dirname(fileURLToPath(import.meta.url)), '..');
const { detectIdPrefix, extractRequirementIds, extractTestedIds, diffIds, specTraceExitCode } = await import(
  pathToFileURL(join(HERE, 'packages/core/src/spec-trace.ts')).href
);
const { values } = parseArgs({
  options: { root: { type: 'string' }, spec: { type: 'string', multiple: true }, warn: { type: 'boolean' } },
  strict: true,
});
const ROOT = resolve(values.root ?? HERE);
const SKIP = new Set(['node_modules', '.git', '.next', 'dist', 'coverage', 'evidence']);

function testFiles(dir, out = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name) || e.isSymbolicLink()) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) testFiles(p, out);
    else if (/\.test\.tsx?$/.test(e.name)) out.push(p);
  }
  return out;
}

// it('x'), test('x'), it.skip('x') and it.each([...])('x'): only titles that start with an ID matter.
const TITLE = /(?:\b(?:it|test)(?:\.(?:skip|only|concurrent))?|\))\(\s*(['"`])((?:\\.|(?!\1)[^\\\n])*)\1/g;
function testNames() {
  const names = [];
  for (const f of testFiles(ROOT)) {
    const text = readFileSync(f, 'utf8');
    for (const m of text.matchAll(TITLE)) {
      if (m[2] && /^\s*[A-Z]{2,4}-\d+/.test(m[2])) names.push(m[2]);
    }
  }
  return names;
}

const specsDir = join(ROOT, '.kiro/specs');
const wanted = values.spec ?? [];
const specs = existsSync(specsDir)
  ? readdirSync(specsDir).filter((n) => existsSync(join(specsDir, n, 'requirements.md')) && (wanted.length === 0 || wanted.includes(n))).sort()
  : [];
const names = testNames();
const diffs = [];
let traced = 0;
for (const spec of specs) {
  const md = readFileSync(join(specsDir, spec, 'requirements.md'), 'utf8');
  const prefix = detectIdPrefix(md);
  if (!prefix) continue;
  traced++;
  const ids = extractRequirementIds(md, prefix);
  const diff = diffIds(ids, extractTestedIds(names, prefix));
  diffs.push(diff);
  if (diff.missingTests.length === 0 && diff.extraTests.length === 0) {
    console.log(`${spec}: ok (${ids.size} requirement IDs, each with a test)`);
    continue;
  }
  console.log(`${spec} (${prefix}):`);
  if (diff.missingTests.length) console.log(`  no test starts with: ${diff.missingTests.join(', ')}`);
  if (diff.extraTests.length) console.log(`  a test starts with an ID the spec lacks: ${diff.extraTests.join(', ')}`);
}
if (traced === 0) console.log('no specs use requirement IDs yet');
const code = specTraceExitCode(diffs);
if (code !== 0) console.log('spec-trace: gaps found');
process.exit(values.warn ? 0 : code);
