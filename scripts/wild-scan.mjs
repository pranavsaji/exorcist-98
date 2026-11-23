#!/usr/bin/env node
// Field Report: scan real public MCP servers and agent-config repositories.
//
//   node scripts/wild-scan.mjs select [--date YYYY-MM-DD] [--seed <s>] [--plan <json>]
//        [--exclude-sets <dir,dir>]
//        Builds <set>/targets.json from public lists (see SOURCES). --seed changes
//        the seeded-random order; --exclude-sets leaves out the targets of
//        earlier sets, so a new held-out set shares no repository with them.
//   Every command takes --set <dir> (default fixtures/wild-scan): the folder
//   that holds targets.json, results.json and triage.json.
//   node scripts/wild-scan.mjs run --tmp <empty-scratch-dir> [--concurrency 4]
//        [--cli <dist/index.mjs>] [--definitions <dir>] [--only owner/repo] [--retry]
//        Downloads every target at its pinned commit, scans it, records results
//        in fixtures/wild-scan/results.json (resumable), deletes the download.
//   node scripts/wild-scan.mjs summary
//        Prints counts from results.json (and triage.json, if present).
//   node scripts/wild-scan.mjs report --set <set> [--previous <set>] [--dev <set>]
//        Writes apps/web/src/lib/field-report.json from targets, results and
//        triage of <set> (triage.json is written by hand), with the headline
//        numbers of an earlier round (--previous) and of a development re-run
//        (--dev) alongside.
//
// Downloads use the core GitHub tarball helper (codeload.github.com, one
// request per repository). The GitHub API is used only by `select`, with
// `gh auth token` when available. The token is held in memory and never
// printed or written.
import { execFileSync, execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { register } from 'tsx/esm/api';

register();

// WILD_SCAN_DOH=1: resolve host names over DNS-over-HTTPS (Cloudflare, by IP)
// instead of the system resolver. Only for networks whose DNS is down.
if (process.env.WILD_SCAN_DOH === '1') {
  const dns = (await import('node:dns')).default;
  const https = (await import('node:https')).default;
  const original = dns.lookup;
  const cache = new Map();
  const doh = (host) => new Promise((res, rej) => {
    https.get({ host: '1.1.1.1', servername: 'cloudflare-dns.com', path: `/dns-query?name=${encodeURIComponent(host)}&type=A`, headers: { accept: 'application/dns-json' }, timeout: 10_000 }, (r) => {
      let body = '';
      r.on('data', (c) => { body += c; });
      r.on('end', () => { try { const a = JSON.parse(body).Answer?.filter((x) => x.type === 1).map((x) => x.data) ?? []; a.length ? res(a) : rej(new Error(`no A record for ${host}`)); } catch (e) { rej(e); } });
    }).on('error', rej).on('timeout', function () { this.destroy(new Error('DoH timeout')); });
  });
  dns.lookup = (host, options, cb) => {
    if (typeof options === 'function') { cb = options; options = {}; }
    if (typeof options === 'number') options = { family: options };
    if (/^[\d.]+$/.test(host) || host === 'localhost') return original(host, options, cb);
    const hit = cache.get(host);
    const p = hit && hit.until > Date.now() ? Promise.resolve(hit.addrs) : doh(host).then((addrs) => { cache.set(host, { addrs, until: Date.now() + 300_000 }); return addrs; });
    p.then((addrs) => (options?.all ? cb(null, addrs.map((address) => ({ address, family: 4 }))) : cb(null, addrs[0], 4)), (e) => cb(Object.assign(e, { code: 'ENOTFOUND' })));
  };
}
const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const SET_ARG = (() => { const i = process.argv.indexOf('--set'); return i > 0 ? process.argv[i + 1] : null; })();
const OUT_DIR = resolve(ROOT, SET_ARG ?? 'fixtures/wild-scan');
const TARGETS = join(OUT_DIR, 'targets.json');
const RESULTS = join(OUT_DIR, 'results.json');
const TRIAGE = join(OUT_DIR, 'triage.json');

// The 20 repositories in docs/BENCHMARK.md (tuning set and three held-out rounds).
// None of them is scanned again here, so this set stays independent of it.
const BENCHMARK_REPOS = [
  'modelcontextprotocol/servers', 'github/github-mcp-server', 'openai/codex', 'anthropics/claude-code-action', 'cline/cline',
  'modelcontextprotocol/python-sdk', 'openai/openai-agents-python', 'github/awesome-copilot', 'PatrickJS/awesome-cursorrules', 'punkpeye/awesome-mcp-servers',
  'microsoft/playwright-mcp', 'upstash/context7', 'jlowin/fastmcp', 'steipete/agent-rules', 'hesreallyhim/awesome-claude-code',
  'punkpeye/fastmcp', 'wong2/awesome-mcp-servers', 'anthropics/claude-code', 'microsoft/vscode-copilot-chat', 'ComposioHQ/awesome-claude-skills',
].map((s) => s.toLowerCase());

// Lists the targets are drawn from, pinned to the commit read.
const SOURCES = {
  awesomeMcp: { repo: 'punkpeye/awesome-mcp-servers', sha: '9dbadb400a592289ec0f0dd97ee44632840c3c2b', path: 'README.md',
    note: 'GitHub repository links under "## Server Implementations" (everything after that heading).' },
  awesomeClaudeCode: { repo: 'hesreallyhim/awesome-claude-code', sha: '049f6c672df566513a40e1b0156a1f8dd7802d51', path: 'README.md',
    note: 'Every GitHub repository link (skills, hooks, CLAUDE.md collections, commands, configs).' },
  mcpServersReadme: { repo: 'modelcontextprotocol/servers', sha: 'c799c8552b0f27b7a33a7b9233773da144dddcf5', path: 'README.md',
    note: 'Checked, not used: at this commit the README no longer carries the community or official-integrations lists (they moved to the MCP Registry).' },
};
const TOPICS = ['cursorrules', 'cursor-rules', 'claude-md', 'agents-md', 'kiro-steering', 'kiro', 'copilot-instructions', 'windsurf-rules'];
let PLAN = { mcpTop: 60, mcpTail: 70, topicTopEach: 8, accTop: 15, accTail: 15 };
let SEED = 'exorcist-98-wild-scan-2026-11-22';
const MAX_DISK_KB = 250_000; // repositories larger than this on GitHub are left out (recorded)

// ── helpers ──────────────────────────────────────────────────────────────────
function token() {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
  try { return execFileSync('gh', ['auth', 'token'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || null; } catch { return null; }
}
const TOKEN = process.argv[2] === 'select' ? token() : null;
async function gh(url, init = {}) {
  const headers = { 'user-agent': 'exorcist-98-wild-scan', accept: 'application/vnd.github+json', ...(TOKEN ? { authorization: `bearer ${TOKEN}` } : {}), ...init.headers };
  for (let attempt = 0; ; attempt++) {
    let res;
    try { res = await fetch(url, { ...init, headers }); } catch (err) {
      if (attempt < 8) { await sleep(10_000 * (attempt + 1)); continue; }
      throw err;
    }
    if (res.ok) return res;
    if ((res.status === 403 || res.status === 429 || res.status >= 500) && attempt < 4) { await sleep(15_000 * (attempt + 1)); continue; }
    throw new Error(`GitHub ${res.status} for ${url.replace(/\?.*/, '')}`);
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const key = (s) => s.toLowerCase();
const rank = (name) => createHash('sha256').update(`${SEED}:${key(name)}`).digest('hex');
function writeJson(file, value) {
  const tmp = `${file}.tmp-${process.pid}`;
  writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`);
  renameSync(tmp, file);
}
function repoLinks(md) {
  const out = new Set();
  for (const m of md.matchAll(/https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/g)) {
    const owner = m[1];
    const repo = m[2].replace(/\.git$/, '').replace(/[.]+$/, '');
    if (['sponsors', 'topics', 'orgs', 'features', 'apps', 'marketplace', 'settings', 'user-attachments'].includes(owner.toLowerCase())) continue;
    if (!repo) continue;
    out.add(`${owner}/${repo}`);
  }
  return [...out];
}

// GraphQL: metadata for up to 100 repositories per request. Missing ones come back null.
async function metadata(names) {
  const meta = new Map();
  for (let i = 0; i < names.length; i += 80) {
    const chunk = names.slice(i, i + 80);
    const fields = chunk.map((n, j) => {
      const [o, r] = n.split('/');
      return `r${j}: repository(owner: ${JSON.stringify(o)}, name: ${JSON.stringify(r)}) { nameWithOwner stargazerCount isFork isArchived isPrivate diskUsage defaultBranchRef { name target { oid } } }`;
    }).join('\n');
    const res = await gh('https://api.github.com/graphql', { method: 'POST', body: JSON.stringify({ query: `query {\n${fields}\n}` }) });
    const body = await res.json();
    chunk.forEach((n, j) => meta.set(key(n), body.data?.[`r${j}`] ?? null));
    process.stderr.write(`  metadata ${Math.min(i + 80, names.length)}/${names.length}\r`);
  }
  process.stderr.write('\n');
  return meta;
}

// ── select ───────────────────────────────────────────────────────────────────
async function select(date, opts = {}) {
  if (opts.seed) SEED = opts.seed;
  if (opts.plan) PLAN = { ...PLAN, ...JSON.parse(opts.plan) };
  const excludeSets = (opts.excludeSets ?? '').split(',').filter(Boolean).map((d) => resolve(ROOT, d));
  const earlier = excludeSets.flatMap((d) => JSON.parse(readFileSync(join(d, 'targets.json'), 'utf8')).targets.map((t) => key(`${t.owner}/${t.repo}`)));
  const raw = async (s) => (await (await gh(`https://raw.githubusercontent.com/${s.repo}/${s.sha}/${s.path}`)).text());
  const awesome = await raw(SOURCES.awesomeMcp);
  const serverSection = awesome.slice(awesome.indexOf('## Server Implementations'));
  const mcpCandidates = repoLinks(serverSection);
  const accCandidates = repoLinks(await raw(SOURCES.awesomeClaudeCode));
  const topicHits = {};
  for (const t of TOPICS) {
    const res = await gh(`https://api.github.com/search/repositories?q=${encodeURIComponent(`topic:${t}`)}&sort=stars&order=desc&per_page=30`);
    topicHits[t] = (await res.json()).items.map((it) => it.full_name);
    await sleep(2500); // search API: 30 requests a minute
  }
  const all = [...new Set([...mcpCandidates, ...accCandidates, ...Object.values(topicHits).flat()].map(key))];
  console.error(`candidates: awesome-mcp ${mcpCandidates.length}, awesome-claude-code ${accCandidates.length}, topics ${Object.values(topicHits).flat().length}, unique ${all.length}`);
  const meta = await metadata(all);

  const excluded = [];
  const taken = new Set([...BENCHMARK_REPOS, ...earlier]);
  const targets = [];
  const eligible = (name) => {
    const m = meta.get(key(name));
    const why = !m ? 'not found (deleted, renamed away or private)'
      : m.isPrivate ? 'private'
      : m.isFork ? 'fork'
      : !m.defaultBranchRef ? 'empty repository'
      : m.diskUsage > MAX_DISK_KB ? `larger than ${MAX_DISK_KB / 1000} MB on GitHub`
      : null;
    return { m, why };
  };
  const take = (name, pool, how) => {
    const { m, why } = eligible(name);
    const canonical = m ? key(m.nameWithOwner) : key(name);
    if (taken.has(canonical) || taken.has(key(name))) return false;
    if (why) { excluded.push({ repo: name, pool, reason: why }); taken.add(key(name)); return false; }
    taken.add(canonical);
    const [owner, repo] = m.nameWithOwner.split('/');
    targets.push({ owner, repo, sha: m.defaultBranchRef.target.oid, branch: m.defaultBranchRef.name, stars: m.stargazerCount, archived: m.isArchived, diskKb: m.diskUsage, pool, how });
    return true;
  };
  const byStars = (names) => [...names].sort((a, b) => (meta.get(key(b))?.stargazerCount ?? -1) - (meta.get(key(a))?.stargazerCount ?? -1) || key(a).localeCompare(key(b)));
  const bySeed = (names) => [...names].sort((a, b) => rank(a).localeCompare(rank(b)));
  const fill = (ordered, n, pool, how) => { let got = 0; for (const name of ordered) { if (got >= n) break; if (take(name, pool, how)) got++; } };

  fill(byStars(mcpCandidates), PLAN.mcpTop, 'mcp-server', 'most-starred');
  fill(bySeed(mcpCandidates), PLAN.mcpTail, 'mcp-server', 'seeded-random');
  for (const t of TOPICS) fill(topicHits[t], PLAN.topicTopEach, 'agent-config', `topic:${t}`);
  fill(byStars(accCandidates), PLAN.accTop, 'agent-config', 'awesome-claude-code most-starred');
  fill(bySeed(accCandidates), PLAN.accTail, 'agent-config', 'awesome-claude-code seeded-random');

  mkdirSync(OUT_DIR, { recursive: true });
  writeJson(TARGETS, {
    title: excludeSets.length ? 'Exorcist 98 Field Report targets (fresh held-out set)' : 'Exorcist 98 Field Report targets',
    selectedOn: date,
    method: {
      summary: 'Public GitHub repositories of MCP servers and agent configuration, drawn from public lists, pinned to the default-branch commit on the selection date.',
      sources: SOURCES,
      topicSearch: { topics: TOPICS, query: 'GitHub search API: topic:<t>, sorted by stars, first 30 results; the first N eligible are taken' },
      plan: PLAN,
      seededRandom: `Order candidates by sha256("${SEED}:" + lowercase owner/repo) and take the first eligible ones.`,
      excludedAlways: 'The 20 repositories in docs/BENCHMARK.md, forks, private, empty, missing, and repositories over 250 MB on GitHub.',
      excludedSets: excludeSets.map((d) => d.slice(ROOT.length + 1)),
      excludedFromEarlierSets: earlier.length,
      order: 'Pools are filled in the order listed in plan; a repository is taken once, by the first pool that reaches it.',
    },
    counts: { candidatesUnique: all.length, targets: targets.length, excluded: excluded.length },
    targets,
    excluded,
  });
  console.error(`wrote ${targets.length} targets (${excluded.length} candidates excluded on the way)`);
}

// ── run ──────────────────────────────────────────────────────────────────────
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
// Zero-width, bidi and tag characters, written as code points so this file stays plain ASCII.
const INVISIBLE = new RegExp(`[${[[0x200b, 0x200f], [0x2060, 0x2064], [0xfeff, 0xfeff], [0x202a, 0x202e], [0x2066, 0x2069], [0xe0000, 0xe007f]]
  .map(([a, b]) => `${String.fromCodePoint(a)}-${String.fromCodePoint(b)}`).join('')}]`, 'gu');
function shortSpan(f) {
  let s = String(f.span ?? '').replace(/\s+/g, ' ').trim();
  // Never store a possible secret, even a short one.
  if (f.ruleId === 'EX-011') return `[redacted: ${s.length} characters]`;
  // Make invisible characters visible.
  s = s.replace(INVISIBLE, (c) => `<U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}>`);
  return s.length > 120 ? `${s.slice(0, 117)}...` : s;
}
function execNode(args, timeoutMs) {
  return new Promise((res) => {
    execFile(process.execPath, args, { timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024, killSignal: 'SIGKILL' }, (err, stdout, stderr) => res({ err, stdout, stderr }));
  });
}
async function scanOne(t, opts, core) {
  const started = Date.now();
  const name = `${t.owner}/${t.repo}`;
  const dir = mkdtempSync(join(opts.tmp, `${t.owner}__${t.repo}__`.slice(0, 80)));
  try {
    const dl = await core.fetchGithubRepo({ owner: t.owner, repo: t.repo, ref: t.sha, dir: join(dir, 'src'), timeoutMs: 180_000,
      limits: { maxFiles: 60_000, maxStoredBytes: 400 * 1024 * 1024, maxCompressedBytes: 300 * 1024 * 1024, maxUnpackedBytes: 2000 * 1024 * 1024 } });
    if (!dl.ok) return { repo: name, sha: t.sha, status: 'download-failed', error: dl.error, ms: Date.now() - started };
    const roles = {};
    let agentFiles = 0;
    const agentFileList = [];
    for await (const f of core.walkRepo(join(dir, 'src'))) {
      roles[f.role] = (roles[f.role] ?? 0) + 1;
      const agent = (f.role === 'instruction' && !/^README/i.test(f.rel.split('/').pop())) || f.role === 'mcp-config' || f.role === 'hook';
      if (agent) { agentFiles++; if (agentFileList.length < 25) agentFileList.push(f.rel); }
    }
    const report = join(dir, 'report.json');
    const r = await execNode([opts.cli, 'scan', join(dir, 'src'), '--format', 'json', '--fail-on', 'none', '--definitions', opts.definitions, '--output', report], 600_000);
    if (r.err || !existsSync(report)) return { repo: name, sha: t.sha, status: 'scan-failed', error: String(r.err?.message ?? r.stderr).split('\n')[0].slice(0, 300), ms: Date.now() - started };
    const json = JSON.parse(readFileSync(report, 'utf8'));
    const findings = json.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, source: f.source, title: f.title, file: f.file, line: f.line, span: shortSpan(f) }));
    return { repo: name, sha: t.sha, status: 'ok', filesDownloaded: dl.files, filesScanned: json.stats.filesScanned, filesSkipped: json.stats.filesSkipped,
      roles, agentFiles, agentFileSample: agentFileList, scanMs: json.stats.durationMs, ms: Date.now() - started, findings };
  } catch (err) {
    return { repo: name, sha: t.sha, status: 'error', error: String(err?.message ?? err).slice(0, 300), ms: Date.now() - started };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
async function run(opts) {
  if (!opts.tmp) throw new Error('--tmp <dir> is required: an empty scratch folder outside this repository.');
  opts.tmp = resolve(opts.tmp);
  if (opts.tmp.startsWith(ROOT)) throw new Error('--tmp must be outside the repository.');
  mkdirSync(opts.tmp, { recursive: true });
  opts.cli = resolve(opts.cli ?? join(ROOT, 'packages/cli/dist/index.mjs'));
  opts.definitions = resolve(opts.definitions ?? join(ROOT, 'packages/cli/definitions'));
  const core = {
    ...(await import(join(ROOT, 'packages/core/src/remote/tarball.ts'))),
    ...(await import(join(ROOT, 'packages/core/src/walker.ts'))),
  };
  const { targets } = JSON.parse(readFileSync(TARGETS, 'utf8'));
  const defsHash = createHash('sha256');
  for (const f of readdirSync(opts.definitions).filter((f) => f.endsWith('.yaml')).sort()) defsHash.update(readFileSync(join(opts.definitions, f)));
  const defsSha = defsHash.digest('hex');
  let gitCommit = null;
  try { gitCommit = execFileSync('git', ['-C', ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { /* not a git checkout */ }
  const cliVersion = (await execNode([opts.cli, '--version'], 30_000)).stdout.trim();
  const prev = existsSync(RESULTS) ? JSON.parse(readFileSync(RESULTS, 'utf8')) : null;
  const state = prev ?? { scanner: { cli: cliVersion, exorcistCommit: gitCommit, definitionsSha256: defsSha }, startedAt: new Date().toISOString(), repos: {} };
  if (prev && prev.scanner.definitionsSha256 !== defsSha) {
    throw new Error('The virus definitions changed since this results file was started. Finish with the same definitions, or move results.json away to start over.');
  }
  const todo = targets.filter((t) => {
    const name = `${t.owner}/${t.repo}`;
    if (opts.only && key(opts.only) !== key(name)) return false;
    const done = state.repos[name];
    return !done || (opts.retry && done.status !== 'ok') || (done.sha !== t.sha);
  });
  console.error(`${todo.length} to scan, ${Object.keys(state.repos).length} already recorded`);
  let next = 0;
  let n = 0;
  const save = () => { state.updatedAt = new Date().toISOString(); writeJson(RESULTS, state); };
  const worker = async () => {
    while (next < todo.length) {
      const t = todo[next++];
      const r = await scanOne(t, opts, core);
      state.repos[r.repo] = r;
      n++;
      const hc = r.findings?.filter((f) => f.severity === 'critical' || f.severity === 'high').length ?? 0;
      console.error(`[${n}/${todo.length}] ${r.repo} ${r.status}${r.error ? ` (${r.error})` : ''} files=${r.filesScanned ?? '-'} findings=${r.findings?.length ?? '-'} high+=${hc} ${Math.round(r.ms / 1000)}s`);
      save();
    }
  };
  await Promise.all(Array.from({ length: Number(opts.concurrency ?? 4) }, worker));
  state.finishedAt = new Date().toISOString();
  save();
}

// ── summary ──────────────────────────────────────────────────────────────────
function summary() {
  const state = JSON.parse(readFileSync(RESULTS, 'utf8'));
  const repos = Object.values(state.repos);
  const ok = repos.filter((r) => r.status === 'ok');
  const bySev = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  const byRule = {};
  let files = 0;
  for (const r of ok) {
    files += r.filesScanned;
    for (const f of r.findings) {
      bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;
      byRule[f.ruleId] ??= Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
      byRule[f.ruleId][f.severity]++;
    }
  }
  const out = { repos: repos.length, scanned: ok.length, failed: repos.filter((r) => r.status !== 'ok').map((r) => `${r.repo}: ${r.status} ${r.error ?? ''}`),
    files, withFindings: ok.filter((r) => r.findings.length).length, bySeverity: bySev, byRule };
  if (existsSync(TRIAGE)) {
    const tri = JSON.parse(readFileSync(TRIAGE, 'utf8'));
    const labels = {};
    for (const l of tri.labels) labels[l.label] = (labels[l.label] ?? 0) + 1;
    out.triage = labels;
  }
  console.log(JSON.stringify(out, null, 2));
}

// ── report ───────────────────────────────────────────────────────────────────
// Hand-written summaries of the findings the triage marked true (all of them)
// and a few debatable ones. Ids are "<owner>/<repo>#<finding index>" as in triage.json.
const HIGHLIGHTS = {
  'Jia-Ethan/grok-keysmith#0': 'An 18.7 KB system prompt is stored as base64 in the installer script and written into Grok Build as standing instructions. Decoded, it tells the agent that every request is an authorised task and that earlier refusals are drafts to overwrite: a jailbreak a reader of the source cannot see without decoding it.',
  'withheld#0': 'A GitHub fine-grained personal access token is quoted in full in an archived code-review note (it had been hardcoded in the MCP server when the review was written). We did not test it; it may already be revoked. It should be reported to the maintainer privately.',
  'dagger/container-use#1': 'The agent environment setup pipes install scripts into a shell each time an environment is created, one of them from the moving master branch of another project. Official sources, but unpinned code execution inside the agent sandbox.',
  'gkhantyln/kiro-professional-toolkit#0': 'A shared Kiro MCP config auto-approves the memory server\'s write tools, so an injected prompt could store whatever it wants in long-term memory without the user seeing a prompt.',
  'trailofbits/skills#0': 'Zero-width spaces before code fences in an agent skill resource keep nested fences from closing. Harmless formatting, but the text the model reads differs from the text a reviewer sees.',
  // Round 2 (fixtures/wild-scan-round2): no true positives; notable debatable ones.
  'vmoranv/jshookmcp#0': 'An MCP server stores Windows process-memory API signatures (OpenProcess, ReadProcessMemory, WriteProcessMemory) as base64 in a file named obfuscated-strings.ts. Not instructions to an AI, but deliberately hidden from anyone reading the source.',
  'can4hou6joeng4/boss-agent-cli#0': 'The dev container pipes the official uv installer into sh every time the environment is created. Real fetch-and-run inside the agent environment, from an official source.',
  'Avinash-jetwani/jevmem#16': 'A value in Google API key format sits in an evaluation case for a guard. Probably synthetic test data; we did not test it and do not reproduce it.',
};
const FP_PATTERNS = {
  'placeholder-or-reference': 'Placeholders and documented example values (your-key-here, the AWS EXAMPLE key, user:pass@localhost) and code that reads a key from the environment.',
  'base64-of-own-files': 'Base64 copies of a repository\'s own skill files inside a benchmark record.',
  'stray-zero-width-in-prose': 'Stray zero-width spaces and word joiners left by translation or copy-paste in prose and UI strings.',
  'defensive-quote-of-injection-phrase': 'Agent instructions that quote "ignore previous instructions" in order to tell the agent never to obey it.',
  'security-tool-rules-and-tests': 'Detection rules and test cases of other security tools.',
  'persian-zwnj-mixed-script': 'Persian zero-width non-joiners next to a Latin word, digit or space (normal Persian spelling).',
  'base64-svg-xml-pdf': 'Base64-embedded SVG icons, Office XML, PDF and JSON test bodies.',
  'install-command-as-data': 'Install commands listed as data or documentation, which nothing runs as a hook.',
  'html-comment-for-humans': 'HTML comments written for people (template hints, metadata, maintainer notes) that name an AI product or mention exfiltration but give the AI no order.',
  'autonomy-wording': 'Agent guidance such as "proceed without asking when the choice is resolved", which does not switch off tool approvals.',
  'curl-piped-to-parser': 'curl output piped into a JSON parser (node -e, python -c) in recorded transcripts, not into a shell.',
  // Round 2
  'test-fixture-for-a-defence': 'Attack samples kept as test data or saved benchmark results of a defence (labelled "malicious", "blocked": true).',
  'security-docs-quoting-attacks': 'Example payloads listed in prompt-injection testing guides, plain and base64-encoded.',
  'base64-pem-certificates-and-keys': 'Base64 certificates and public keys (kubeconfigs in saved test output, release-signing keys).',
  'copied-vendor-docs': 'Copied vendor documentation that warns against, or describes, bypassing safety checks.',
  'descriptive-risk-note': 'Risk notes saying that something "could bypass safety checks".',
  'changelog-cli-flag': 'Changelog lines about a CLI flag that skips a confirmation prompt.',
  'unicode-in-code-handling-it': 'Bidi characters inside code that strips them, quoted in a plan document.',
  'tool-usage-guidance': 'Ordinary "Before calling this tool, check ..." guidance in a tool description.',
  'ordinary-agent-guidance': 'Ordinary agent prompt wording such as "your new instructions may be brief".',
  'defensive-mention-unquoted': 'A defence rule that names the phrase it forbids, without quotation marks.',
};
function loadSet(dir) {
  const targets = JSON.parse(readFileSync(join(dir, 'targets.json'), 'utf8'));
  const state = JSON.parse(readFileSync(join(dir, 'results.json'), 'utf8'));
  const tri = existsSync(join(dir, 'triage.json')) ? JSON.parse(readFileSync(join(dir, 'triage.json'), 'utf8')) : null;
  const repos = Object.values(state.repos).filter((r) => r.status === 'ok');
  const bySeverity = Object.fromEntries(SEVERITIES.slice(0, 4).map((s) => [s, 0]));
  const byRule = {};
  for (const r of repos) for (const f of r.findings) { bySeverity[f.severity]++; byRule[f.ruleId] = (byRule[f.ruleId] ?? 0) + 1; }
  const highCriticalFindings = repos.reduce((a, r) => a + r.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').length, 0);
  const tally = (xs) => xs.reduce((m, x) => ((m[x] = (m[x] ?? 0) + 1), m), { 'true-positive': 0, debatable: 0, 'false-positive': 0 });
  let triage = null;
  if (tri) {
    const groups = new Map();
    for (const l of tri.labels) { const k = `${l.repo}|${l.ruleId}|${l.file}`; if (!groups.has(k)) groups.set(k, l.label); }
    triage = { labels: tri.labels, perFinding: tally(tri.labels.map((l) => l.label)), perIssue: tally([...groups.values()]), issues: groups.size, tally };
  }
  return {
    targets, state, repos, triage,
    summary: {
      date: targets.selectedOn,
      scanner: { version: state.scanner.cli, commit: state.scanner.exorcistCommit ? state.scanner.exorcistCommit.slice(0, 7) : null, definitionsSha256: state.scanner.definitionsSha256 },
      repos: repos.length,
      reposByPool: Object.fromEntries(['mcp-server', 'agent-config'].map((p) => [p, targets.targets.filter((t) => t.pool === p).length])),
      reposWithFindings: repos.filter((r) => r.findings.length).length,
      files: repos.reduce((a, r) => a + r.filesScanned, 0),
      agentFiles: repos.reduce((a, r) => a + r.agentFiles, 0),
      findings: { total: repos.reduce((a, r) => a + r.findings.length, 0), bySeverity, byRule },
      highCriticalFindings,
    },
  };
}
const pct = (a, b) => (b ? Math.round((1000 * a) / b) / 10 : 0);

// `report --set <round-2 set> --previous <round-1 set> [--dev <round-1 set re-run with the new rules>]`
function report(opts) {
  const cur = loadSet(OUT_DIR);
  const tri = cur.triage;
  if (!tri) throw new Error(`${TRIAGE} is missing: triage every high and critical finding first`);
  if (tri.labels.length !== cur.summary.highCriticalFindings) throw new Error(`triage has ${tri.labels.length} labels for ${cur.summary.highCriticalFindings} high and critical findings`);
  const { perFinding, perIssue, issues, tally } = tri;
  const byId = new Map(tri.labels.map((l) => [l.id, l]));
  const url = (l) => `https://github.com/${l.repo}/blob/${l.sha}/${l.file.split('/').map(encodeURIComponent).join('/')}#L${l.line}`;
  const item = (id) => {
    const l = byId.get(id);
    const f = cur.state.repos[l.repo].findings[Number(id.split('#')[1])];
    return { repo: l.repo, file: l.file, fileUrl: url(l), ruleId: l.ruleId, severity: l.severity, title: f.title, label: l.label, description: HIGHLIGHTS[id] };
  };
  const ids = Object.keys(HIGHLIGHTS).filter((id) => byId.has(id));
  const topTrue = ids.filter((id) => byId.get(id).label === 'true-positive').map(item);
  const notableDebatable = ids.filter((id) => byId.get(id).label === 'debatable').map(item);
  const missing = tri.labels.filter((l) => l.label === 'true-positive' && !topTrue.some((t) => t.repo === l.repo && t.file === l.file && t.ruleId === l.ruleId));
  if (missing.length) throw new Error(`true positives without a highlight: ${[...new Set(missing.map((l) => `${l.repo} ${l.file}`))].join(', ')}`);
  const patterns = Object.entries(tally(tri.labels.filter((l) => l.label === 'false-positive').map((l) => `${l.ruleId}|${l.pattern ?? ''}`)))
    .filter(([k, n]) => n > 0 && FP_PATTERNS[k.split('|')[1]]).sort((a, b) => b[1] - a[1]).slice(0, 8)
    .map(([k, n]) => ({ ruleId: k.split('|')[0], findings: n, description: FP_PATTERNS[k.split('|')[1]] }));
  const n = tri.labels.length;
  const out = {
    title: 'Field Report: Exorcist 98 on public MCP servers and agent-config repositories',
    round: 2,
    heldOut: true,
    ...cur.summary,
    source: 'docs/FIELD_REPORT.md',
    highCritical: { findings: n, triaged: n, perFinding, issues, perIssue },
    precision: {
      value: pct(perIssue['true-positive'], issues),
      withDebatable: pct(perIssue['true-positive'] + perIssue.debatable, issues),
      perFinding: pct(perFinding['true-positive'], n),
      perFindingWithDebatable: pct(perFinding['true-positive'] + perFinding.debatable, n),
      unit: 'issue (one rule in one file)',
      note: `Round 2: a fresh held-out set scanned once with the fixed rules. Of ${issues} high or critical issues, ${perIssue['true-positive']} were real and ${perIssue.debatable} debatable (${n} findings: ${perFinding['true-positive']} real, ${perFinding.debatable} debatable).`,
    },
    topTrue,
    notableDebatable,
    falsePositivePatterns: patterns,
  };
  delete out.highCriticalFindings;
  if (opts.previous) {
    const prev = loadSet(resolve(ROOT, opts.previous));
    const t = prev.triage;
    out.round1 = {
      note: 'Round 1: a different held-out set, scanned with the rules before these fixes. Kept here for honesty.',
      date: prev.summary.date, scanner: prev.summary.scanner, repos: prev.summary.repos, files: prev.summary.files,
      findings: { total: prev.summary.findings.total, bySeverity: prev.summary.findings.bySeverity },
      highCritical: { findings: t.labels.length, issues: t.issues, perIssue: t.perIssue, perFinding: t.perFinding },
      precision: { value: pct(t.perIssue['true-positive'], t.issues), withDebatable: pct(t.perIssue['true-positive'] + t.perIssue.debatable, t.issues), perFinding: pct(t.perFinding['true-positive'], t.labels.length) },
    };
  }
  if (opts.dev) {
    const dev = loadSet(resolve(ROOT, opts.dev));
    out.round1DevRerun = {
      note: 'The round-1 repositories scanned again with the fixed rules. The fixes were designed by looking at these repositories, so this is a development set, not a measure of precision.',
      scanner: dev.summary.scanner, repos: dev.summary.repos,
      findings: { total: dev.summary.findings.total, bySeverity: dev.summary.findings.bySeverity },
      highCriticalFindings: dev.summary.highCriticalFindings,
    };
  }
  const file = join(ROOT, 'apps/web/src/lib/field-report.json');
  writeFileSync(file, `${JSON.stringify(out, null, 2)}\n`);
  console.error(`wrote ${file} (${Buffer.byteLength(JSON.stringify(out, null, 2))} bytes)`);
}

// ── main ─────────────────────────────────────────────────────────────────────
const [cmd, ...rest] = process.argv.slice(2);
const { values } = parseArgs({ args: rest, options: {
  tmp: { type: 'string' }, concurrency: { type: 'string' }, cli: { type: 'string' }, definitions: { type: 'string' },
  only: { type: 'string' }, retry: { type: 'boolean' }, date: { type: 'string' },
  set: { type: 'string' }, seed: { type: 'string' }, plan: { type: 'string' }, 'exclude-sets': { type: 'string' },
  previous: { type: 'string' }, dev: { type: 'string' },
} });
if (cmd === 'select') await select(values.date ?? new Date().toISOString().slice(0, 10), { seed: values.seed, plan: values.plan, excludeSets: values['exclude-sets'] });
else if (cmd === 'run') await run(values);
else if (cmd === 'summary') summary();
else if (cmd === 'report') report(values);
else { console.error('usage: node scripts/wild-scan.mjs select|run|summary|report  (see the comment at the top of this file)'); process.exit(2); }
