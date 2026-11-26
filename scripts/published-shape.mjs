#!/usr/bin/env node
// Installs what we publish, the way a user gets it, and checks that it works.
//
//   node scripts/published-shape.mjs             build (if needed), pack, install, check
//   node scripts/published-shape.mjs --no-build  use the dist/ folders already built
//   node scripts/published-shape.mjs --keep      leave the temporary folder in place and print its path
//
// It packs @exorcist-98/cli and @exorcist-98/mcp-server into tarballs, installs the
// tarballs into an empty temporary project (no workspace links, nothing from this
// checkout on the module path) and checks:
//   FF-4.1  `exorcist --version` equals the version in packages/cli/package.json
//   FF-4.2  scanning fixtures/haunted-repo exits non-zero and prints "Verdict: POSSESSED"
//   FF-4.3  scanning a clean temporary folder exits 0 and prints "Verdict: CLEAN"
//   FF-4.4  the MCP server answers `initialize` and `tools/list` over stdio with the expected tools
// It also checks that the installed packages are real folders, not links (FF-4.5).
// The child processes get a temporary HOME and EXORCIST_DIR, so a run never touches
// your own ~/.exorcist.
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
/** The tools the MCP server must list, by name. */
export const EXPECTED_TOOLS = ['explain_finding', 'quarantine', 'scan_mcp_config', 'scan_repo'];
const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));

/** One check result. `detail` says what was seen, so a failure can be read without re-running. */
const check = (id, name, ok, detail) => ({ id, name, ok, detail });

/** A child-process environment with no state of ours in it. */
export function cleanEnv(home) {
  const keep = ['PATH', 'Path', 'SystemRoot', 'TMPDIR', 'TEMP', 'TMP'];
  const env = {};
  for (const k of keep) if (process.env[k] !== undefined) env[k] = process.env[k];
  return { ...env, HOME: home, USERPROFILE: home, EXORCIST_DIR: join(home, '.exorcist'), EXORCIST_NOTIFY: '0', EXORCIST_OFFLINE: '1', NO_COLOR: '1' };
}

/** Builds a package's dist/ unless it is already there (or `build` is false and it is missing: an error). */
function ensureBuilt(pkgDir, build) {
  if (existsSync(join(pkgDir, 'dist/index.mjs'))) return;
  if (!build) throw new Error(`${pkgDir}/dist/index.mjs is missing and --no-build was given`);
  execFileSync(process.execPath, [join(pkgDir, 'build.mjs')], { cwd: pkgDir, stdio: 'pipe' });
}

/**
 * Packs one package into `dest` and returns the tarball path. Scripts are skipped
 * (the build is done above), as scripts/release.sh does. A parallel test run can
 * rebuild dist/ while it is read, so a failed pack is tried again.
 */
export function packPackage(pkgDir, dest) {
  let lastError = '';
  for (let attempt = 0; attempt < 3; attempt++) {
    const r = spawnSync(NPM, ['pack', '--json', '--ignore-scripts', '--pack-destination', dest], { cwd: pkgDir, encoding: 'utf8', timeout: 120_000, shell: process.platform === 'win32' });
    if (r.status === 0) {
      try {
        const out = JSON.parse(r.stdout);
        return join(dest, out[0].filename.replace(/^@/, '').replace('/', '-'));
      } catch (e) {
        lastError = 'npm pack printed something that is not JSON';
      }
    } else lastError = (r.stderr || '').trim().split('\n').slice(-3).join(' | ');
  }
  throw new Error(`npm pack failed in ${pkgDir}: ${lastError}`);
}

/** Sends JSON-RPC lines to a stdio MCP server and returns the responses by id. */
export function talkToMcpServer(command, args, options, requests, timeoutMs = 30_000) {
  return new Promise((resolveP) => {
    const child = spawn(command, args, { ...options, stdio: ['pipe', 'pipe', 'pipe'] });
    const wanted = new Set(requests.filter((r) => r.id !== undefined).map((r) => r.id));
    const got = new Map();
    let buf = '';
    let stderr = '';
    let done = false;
    const finish = (error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      child.kill();
      resolveP({ responses: got, error, stderr: stderr.slice(0, 500) });
    };
    const timer = setTimeout(() => finish('timed out waiting for the server'), timeoutMs);
    child.on('error', (e) => finish(`could not start: ${e.message}`));
    child.on('exit', (code) => finish(wanted.size > got.size ? `exited with code ${code} before answering` : undefined));
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdout.on('data', (d) => {
      buf += d;
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line);
          if (msg.id !== undefined) got.set(msg.id, msg);
        } catch { /* not a JSON line: ignored */ }
      }
      if (got.size >= wanted.size) finish(undefined);
    });
    for (const r of requests) child.stdin.write(JSON.stringify({ jsonrpc: '2.0', ...r }) + '\n');
  });
}

/** Pure judgement of the MCP answers: easy to test without a server. */
export function judgeMcpAnswers(responses, expectedVersion) {
  const init = responses.get(1);
  const list = responses.get(2);
  const out = [];
  const serverName = init?.result?.serverInfo?.name;
  out.push(check('FF-4.4a', 'MCP server answers initialize', Boolean(init?.result?.protocolVersion) && serverName === 'exorcist' && init.result.serverInfo.version === expectedVersion,
    init ? `server ${serverName ?? '?'} ${init.result?.serverInfo?.version ?? '?'}, protocol ${init.result?.protocolVersion ?? '?'}` : 'no answer'));
  const names = Array.isArray(list?.result?.tools) ? list.result.tools.map((t) => t.name).sort() : [];
  out.push(check('FF-4.4b', 'MCP server lists the expected tools', JSON.stringify(names) === JSON.stringify(EXPECTED_TOOLS), list ? `tools: ${names.join(', ') || '(none)'}` : 'no answer'));
  return out;
}

/** True when the path is a real folder, not a symbolic link. */
function isRealFolder(p) {
  try { return lstatSync(p).isDirectory() && !lstatSync(p).isSymbolicLink(); } catch { return false; }
}

/**
 * Runs the whole check. Returns { ok, checks, dir }; never throws for a failed
 * check (a thrown error means the check itself could not run, and is reported as a failed check).
 */
export async function runPublishedShapeCheck({ root = ROOT, build = true, keep = false, log = () => {} } = {}) {
  const checks = [];
  const work = realpathSync(mkdtempSync(join(tmpdir(), 'exorcist-published-')));
  try {
    const cliDir = join(root, 'packages/cli');
    const mcpDir = join(root, 'packages/mcp-server');
    const cliPkg = readJson(join(cliDir, 'package.json'));
    const mcpPkg = readJson(join(mcpDir, 'package.json'));
    ensureBuilt(cliDir, build);
    ensureBuilt(mcpDir, build);

    const tarballs = join(work, 'tarballs');
    const project = join(work, 'project');
    const home = join(work, 'home');
    const clean = join(work, 'clean-folder');
    for (const d of [tarballs, project, home, clean]) mkdirSync(d, { recursive: true });

    log('packing');
    const cliTgz = packPackage(cliDir, tarballs);
    const mcpTgz = packPackage(mcpDir, tarballs);
    writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'published-shape-consumer', version: '0.0.0', private: true }));
    writeFileSync(join(clean, 'notes.md'), '# Notes\n\nNothing here talks to an AI agent.\n');

    log('installing the tarballs into an empty project');
    const env = cleanEnv(home);
    const inst = spawnSync(NPM, ['install', '--no-audit', '--no-fund', '--ignore-scripts', '--no-package-lock', cliTgz, mcpTgz], { cwd: project, env, encoding: 'utf8', timeout: 180_000, shell: process.platform === 'win32' });
    if (inst.status !== 0) throw new Error('npm install of the tarballs failed: ' + (inst.stderr || '').trim().split('\n').slice(-3).join(' | '));

    const cliHome = join(project, 'node_modules/@exorcist-98/cli');
    const mcpHome = join(project, 'node_modules/@exorcist-98/mcp-server');
    checks.push(check('FF-4.5', 'Installed packages are real folders, not workspace links', isRealFolder(cliHome) && isRealFolder(mcpHome), `cli ${isRealFolder(cliHome) ? 'folder' : 'link or missing'}, mcp-server ${isRealFolder(mcpHome) ? 'folder' : 'link or missing'}`));
    const cliBin = join(cliHome, cliPkg.bin.exorcist);
    const mcpBin = join(mcpHome, mcpPkg.bin['exorcist-mcp']);
    const run = (args, cwd) => spawnSync(process.execPath, [cliBin, ...args], { cwd, env, encoding: 'utf8', timeout: 120_000 });

    log('exorcist --version');
    const v = run(['--version'], project);
    checks.push(check('FF-4.1', 'exorcist --version matches package.json', v.status === 0 && v.stdout.trim() === cliPkg.version, `printed "${(v.stdout || '').trim()}", package.json says ${cliPkg.version}`));

    log('scanning the Haunted Repo');
    const h = run(['scan', join(root, 'fixtures/haunted-repo')], project);
    checks.push(check('FF-4.2', 'Haunted Repo exits non-zero and prints "Verdict: POSSESSED"', h.status !== 0 && h.status !== null && h.stdout.includes('Verdict: POSSESSED'), `exit ${h.status}, ${h.stdout.includes('Verdict: POSSESSED') ? 'verdict POSSESSED' : 'no POSSESSED verdict'}`));

    log('scanning a clean folder');
    const c = run(['scan', clean], project);
    checks.push(check('FF-4.3', 'Clean folder exits 0 and prints "Verdict: CLEAN"', c.status === 0 && c.stdout.includes('Verdict: CLEAN'), `exit ${c.status}, ${c.stdout.includes('Verdict: CLEAN') ? 'verdict CLEAN' : 'no CLEAN verdict'}`));

    log('asking the MCP server');
    const answers = await talkToMcpServer(process.execPath, [mcpBin], { cwd: clean, env }, [
      { id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'published-shape', version: '0.0.0' } } },
      { method: 'notifications/initialized' },
      { id: 2, method: 'tools/list', params: {} },
    ]);
    if (answers.error) checks.push(check('FF-4.4', 'MCP server talks over stdio', false, `${answers.error}${answers.stderr ? ` (stderr: ${answers.stderr})` : ''}`));
    checks.push(...judgeMcpAnswers(answers.responses, mcpPkg.version));
  } catch (e) {
    checks.push(check('FF-4.0', 'The check could run', false, e instanceof Error ? e.message : String(e)));
  } finally {
    if (!keep) rmSync(work, { recursive: true, force: true });
  }
  return { ok: checks.length > 0 && checks.every((c) => c.ok), checks, dir: keep ? work : undefined };
}

const isMain = process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
if (isMain) {
  const args = process.argv.slice(2);
  const result = await runPublishedShapeCheck({ build: !args.includes('--no-build'), keep: args.includes('--keep'), log: (m) => console.log(`... ${m}`) });
  for (const c of result.checks) console.log(`${c.ok ? 'PASS' : 'FAIL'} ${c.id} ${c.name}: ${c.detail}`);
  if (result.dir) console.log(`kept: ${result.dir}`);
  console.log(result.ok ? 'The published shape works.' : 'The published shape is broken.');
  process.exit(result.ok ? 0 : 1);
}
