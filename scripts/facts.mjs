#!/usr/bin/env node
// One source for every number the README, the submission text, the Kiro log and
// the web pages quote. It reads the repository and writes docs/facts.json (and a
// copy at apps/web/src/lib/facts.json, which the web app imports).
//
//   node scripts/facts.mjs                      recompute from the repository; keep the cached test and browser numbers
//   node scripts/facts.mjs --run-tests          also run `vitest run` (a few minutes) and take the test numbers from it
//   node scripts/facts.mjs --tests report.json  take the test numbers from a vitest JSON report you already have
//   node scripts/facts.mjs --e2e e2e.log        take the browser step count from the output of `pnpm e2e`
//   node scripts/facts.mjs --docs               also rewrite the <!--f:key-->value<!--/f--> markers in the documents
//   node scripts/facts.mjs --check              change nothing; exit 1 if docs/facts.json or a document disagrees
//
// What it counts, and how:
//   tests, testFiles, benchmark *Caught/*Clean  from a vitest JSON report (cached in facts.json between runs)
//   browserSteps, browserAxeViolationTypes      from the log of the browser suite (cached the same way)
//   propertyTests                               `fc.assert(` calls in the test files
//   definitions, specs, steering, hooks, agents files in definitions/, .kiro/specs, .kiro/steering, .kiro/hooks, .kiro/agents
//   hauntedRepoFindings                         `exorcist scan fixtures/haunted-repo` with the built CLI
//   benchmark*                                  the case folders in fixtures/benchmark, and how many passed in the report
//   fieldReport                                 the tables in docs/FIELD_REPORT.md
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const FACTS_PATH = join(ROOT, 'docs/facts.json');
const WEB_COPY = join(ROOT, 'apps/web/src/lib/facts.json');
/** Documents whose numbers are written by --docs and checked by --check. */
export const DOCS = ['README.md', 'docs/SUBMISSION.md', 'docs/KIRO_LOG.md', 'docs/VIDEO_SCRIPT.md', 'docs/KNOWN_LIMITATIONS.md', 'docs/REFERENCE.md', 'docs/BLOG.md', 'docs/SOCIAL.md', 'docs/BENCHMARK.md'];
const SKIP_DIRS = new Set(['node_modules', '.git', '.next', 'dist', 'e2e-output', 'out', 'coverage']);

function walk(dir, keep, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p, keep, out);
    else if (keep(p)) out.push(p);
  }
  return out;
}
const countDir = (rel, keep = () => true) => readdirSync(join(ROOT, rel)).filter(keep).length;

function propertyTests() {
  const files = walk(ROOT, (p) => /\.test\.tsx?$/.test(p));
  let n = 0;
  for (const f of files) n += (readFileSync(f, 'utf8').match(/\bfc\.assert\(/g) ?? []).length;
  return n;
}

function hauntedRepoFindings() {
  const cli = join(ROOT, 'packages/cli/dist/index.mjs');
  if (!existsSync(cli)) throw new Error('packages/cli/dist/index.mjs is missing: run `pnpm --filter @exorcist-98/cli build` first');
  const out = execFileSync('node', [cli, 'scan', join(ROOT, 'fixtures/haunted-repo'), '--format', 'json', '--fail-on', 'none'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return JSON.parse(out).findings.length;
}

const num = (s) => Number(String(s).replace(/,/g, ''));
/** Totals from the tables and headline of docs/FIELD_REPORT.md. */
function fieldReport() {
  const md = readFileSync(join(ROOT, 'docs/FIELD_REPORT.md'), 'utf8');
  const repos = /\| Repositories \(all different\) \| ([\d,]+) \| ([\d,]+) \|/.exec(md);
  const files = /\| Files scanned \| ([\d,]+) \| ([\d,]+) \|/.exec(md);
  const r3 = /\*\*([\d,]+) repositories\*\*[^]*?\*\*([\d,]+)\s+files\*\*/.exec(md);
  if (!repos || !files || !r3) throw new Error('docs/FIELD_REPORT.md no longer has the tables facts.mjs reads');
  const r = [num(repos[1]), num(repos[2]), num(r3[1])];
  const f = [num(files[1]), num(files[2]), num(r3[2])];
  return { rounds: 3, round1Repos: r[0], round2Repos: r[1], round3Repos: r[2], repos: r[0] + r[1] + r[2], files: f[0] + f[1] + f[2] };
}

/** Test numbers from a vitest JSON report. */
export function fromReport(path) {
  const j = JSON.parse(readFileSync(path, 'utf8'));
  const all = j.testResults.flatMap((f) => f.assertionResults);
  if (j.numFailedTests > 0) {
    const names = all.filter((t) => t.status === 'failed').map((t) => '  ' + t.fullName).join('\n');
    throw new Error(`${path} has ${j.numFailedTests} failing test(s); facts are only taken from a passing run:\n${names}`);
  }
  const bench = all.filter((t) => t.fullName.includes('BENCH: labelled detection corpus'));
  const ok = (t) => t.status === 'passed';
  return {
    tests: j.numPassedTests,
    testFiles: j.testResults.length,
    benchmarkAttacksCaught: bench.filter((t) => / attack /.test(t.fullName) && ok(t)).length,
    benchmarkBenignClean: bench.filter((t) => / benign /.test(t.fullName) && ok(t)).length,
  };
}

export function fromE2eLog(path) {
  const lines = readFileSync(path, 'utf8').split('\n');
  const steps = lines.filter((l) => /^(PASS|FAIL)  /.test(l));
  const axe = /axe violation types: (\d+)/.exec(lines.join('\n'));
  if (steps.length === 0 || !axe) throw new Error(`${path} does not look like the output of the browser suite`);
  if (steps.some((l) => l.startsWith('FAIL')) || Number(axe[1]) > 0) throw new Error(`${path} has failing browser steps or axe violations; facts are only taken from a passing run`);
  return { browserSteps: steps.length, browserAxeViolationTypes: Number(axe[1]) };
}

export function compute(args = []) {
  const prev = existsSync(FACTS_PATH) ? JSON.parse(readFileSync(FACTS_PATH, 'utf8')) : {};
  let report = null;
  const ti = args.indexOf('--tests');
  if (ti >= 0) report = args[ti + 1];
  if (args.includes('--run-tests')) {
    const dir = mkdtempSync(join(tmpdir(), 'x98-facts-'));
    report = join(dir, 'vitest.json');
    try { execFileSync('pnpm', ['vitest', 'run', '--reporter=json', `--outputFile=${report}`], { cwd: ROOT, stdio: 'ignore', maxBuffer: 1 << 28 }); } catch { /* a failing run still writes the report */ }
  }
  const e2i = args.indexOf('--e2e');
  const cachedTests = {
    tests: prev.tests, testFiles: prev.testFiles,
    benchmarkAttacksCaught: prev.benchmarkAttacksCaught, benchmarkBenignClean: prev.benchmarkBenignClean,
  };
  const cachedE2e = { browserSteps: prev.browserSteps, browserAxeViolationTypes: prev.browserAxeViolationTypes };
  const labels = JSON.parse(readFileSync(join(ROOT, 'fixtures/benchmark/labels.json'), 'utf8'));
  return {
    note: 'Written by scripts/facts.mjs. Do not edit by hand. Test and browser numbers come from the last run given to the script (--run-tests, --tests, --e2e); everything else is counted from the repository.',
    ...(report ? fromReport(report) : cachedTests),
    ...(e2i >= 0 ? fromE2eLog(args[e2i + 1]) : cachedE2e),
    propertyTests: propertyTests(),
    definitions: countDir('definitions', (n) => /^EX-\d{3}-.*\.yaml$/.test(n)),
    specs: countDir('.kiro/specs', (n) => statSync(join(ROOT, '.kiro/specs', n)).isDirectory()),
    steering: countDir('.kiro/steering', (n) => n.endsWith('.md')),
    hooks: countDir('.kiro/hooks', (n) => n.endsWith('.json')),
    agents: countDir('.kiro/agents', (n) => n.endsWith('.json')),
    hauntedRepoFindings: hauntedRepoFindings(),
    benchmarkAttacks: Object.keys(labels.attacks).length,
    benchmarkBenign: labels.benign.length,
    fieldReport: fieldReport(),
  };
}

// ── Markers in documents: <!--f:tests-->2,028<!--/f--> ────────────────────────
const MARK = /<!--f:([A-Za-z0-9_.]+)-->([^]*?)<!--\/f-->/g;
const lookup = (facts, key) => key.split('.').reduce((o, k) => (o == null ? undefined : o[k]), facts);
export const show = (v) => (typeof v === 'number' ? v.toLocaleString('en-US') : String(v));

/** Every marker in `text` that has no matching fact or a different value. */
export function disagreements(text, facts) {
  const bad = [];
  for (const m of text.matchAll(MARK)) {
    const v = lookup(facts, m[1]);
    if (v === undefined) bad.push({ key: m[1], found: m[2], expected: '(no such fact)' });
    else if (show(v) !== m[2]) bad.push({ key: m[1], found: m[2], expected: show(v) });
  }
  return bad;
}
export const rewrite = (text, facts) => text.replace(MARK, (all, key, old) => { const v = lookup(facts, key); return v === undefined ? all : `<!--f:${key}-->${show(v)}<!--/f-->`; });

function main() {
  const args = process.argv.slice(2);
  const facts = compute(args);
  const json = JSON.stringify(facts, null, 2) + '\n';
  if (args.includes('--check')) {
    let bad = 0;
    const cur = existsSync(FACTS_PATH) ? readFileSync(FACTS_PATH, 'utf8') : '';
    // Test and browser numbers are cached, so this compares what can be recounted.
    if (cur !== json) { console.error('docs/facts.json is out of date: run `node scripts/facts.mjs`'); bad++; }
    if (!existsSync(WEB_COPY) || readFileSync(WEB_COPY, 'utf8') !== cur) { console.error('apps/web/src/lib/facts.json differs from docs/facts.json'); bad++; }
    for (const d of DOCS) for (const x of disagreements(readFileSync(join(ROOT, d), 'utf8'), facts)) { console.error(`${d}: ${x.key} says ${x.found}, facts say ${x.expected}`); bad++; }
    process.exit(bad ? 1 : 0);
  }
  writeFileSync(FACTS_PATH, json);
  writeFileSync(WEB_COPY, json);
  if (args.includes('--docs')) {
    for (const d of DOCS) {
      const p = join(ROOT, d);
      const t = readFileSync(p, 'utf8');
      const n = rewrite(t, facts);
      if (n !== t) writeFileSync(p, n);
    }
  }
  console.log(relative(ROOT, FACTS_PATH), 'written');
}
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
