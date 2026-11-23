/**
 * Refuse repositories whose own git config could run commands.
 *
 * `exorcist origin` may be pointed at a folder the user downloaded: an
 * unpacked zip or tarball can carry its own .git/config, and keys such as
 * filter.<x>.clean, diff.<x>.textconv or core.fsmonitor name programs git
 * runs on its own. Before any git command touches such a repository, its
 * config files are read here, without git, and the run is refused if any of
 * those keys is set. A second pass asks git itself to list the same files
 * (`git config --file ... --no-includes --list -z`, with no repository, which
 * executes nothing) so a file our parser reads differently from git cannot
 * slip through.
 */

import { execFile } from 'node:child_process';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';

export type ConfigEntry = { section: string; subsection: string | null; key: string; value: string };
export type ParseResult = { ok: true; entries: ConfigEntry[] } | { ok: false; line: number };

/** Strip a trailing comment outside quotes; report whether the value continues on the next line. */
function stripComment(s: string): { text: string; continues: boolean } {
  let inQuote = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\') { if (i === s.length - 1) return { text: s.slice(0, i), continues: true }; i++; continue; }
    if (c === '"') inQuote = !inQuote;
    else if (!inQuote && (c === '#' || c === ';')) return { text: s.slice(0, i), continues: false };
  }
  return { text: s, continues: false };
}

const SECTION = /^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]/;
const KEY = /^([A-Za-z][A-Za-z0-9-]*)\s*(?:=(.*))?$/;

/**
 * A conservative reader of git's config format. Anything it does not
 * understand is a parse error, and a parse error means "refuse".
 */
export function parseGitConfig(text: string): ParseResult {
  const entries: ConfigEntry[] = [];
  let section = '';
  let subsection: string | null = null;
  let current: ConfigEntry | null = null;
  let continuing = false;
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/);
  for (let n = 0; n < lines.length; n++) {
    const raw = lines[n] ?? '';
    if (continuing) {
      const { text: t, continues } = stripComment(raw);
      if (current) current.value += t;
      continuing = continues;
      continue;
    }
    let rest = raw.trim();
    const header = SECTION.exec(rest);
    if (header) {
      const name = header[1] ?? '';
      if (header[2] !== undefined) {
        section = name.toLowerCase();
        subsection = header[2].replace(/\\(.)/g, '$1');
      } else {
        const dot = name.indexOf('.');
        section = (dot < 0 ? name : name.slice(0, dot)).toLowerCase();
        subsection = dot < 0 ? null : name.slice(dot + 1).toLowerCase();
      }
      rest = rest.slice(header[0].length).trim();
    } else if (rest.startsWith('[')) {
      return { ok: false, line: n + 1 };
    }
    const { text: body, continues } = stripComment(rest);
    const line = body.trim();
    if (line === '') { continuing = false; continue; }
    if (section === '') return { ok: false, line: n + 1 };
    const kv = KEY.exec(line);
    if (!kv) return { ok: false, line: n + 1 };
    // A key with no "=" is boolean true in git.
    current = { section, subsection, key: (kv[1] ?? '').toLowerCase(), value: kv[2] === undefined ? 'true' : kv[2].trim() };
    entries.push(current);
    continuing = continues;
  }
  return { ok: true, entries };
}

const FALSE_VALUES = new Set(['false', 'no', 'off', '0', '']);

/** Why this config key could make git run a command, or null when it cannot. */
export function dangerousKey(e: ConfigEntry): string | null {
  const name = `${e.section}${e.subsection !== null ? `.${e.subsection}` : ''}.${e.key}`;
  if (e.section === 'filter') return name;
  if (e.section === 'diff' && e.subsection !== null && (e.key === 'command' || e.key === 'textconv')) return name;
  if (e.section === 'diff' && e.subsection === null && e.key === 'external') return name;
  if (e.section === 'include' || e.section === 'includeif') return name;
  if (e.section === 'gpg' && e.key === 'program') return name;
  if (e.section === 'core') {
    if (e.key === 'fsmonitor') return FALSE_VALUES.has(e.value.replace(/^"|"$/g, '').toLowerCase()) ? null : name;
    if (['sshcommand', 'gitproxy', 'hookspath'].includes(e.key)) return name;
  }
  return null;
}

export type RepoLocation = { workTree: string; gitDir: string; configFiles: string[] };

/** Find the enclosing repository the way git would, without running git. */
export function locateRepo(start: string): RepoLocation | null {
  let dir: string;
  try { dir = realpathSync(start); } catch { return null; }
  for (;;) {
    const dotGit = join(dir, '.git');
    if (existsSync(dotGit)) {
      let gitDir: string | null = null;
      try {
        if (statSync(dotGit).isDirectory()) gitDir = dotGit;
        else {
          const m = /^gitdir:\s*(.+?)\s*$/m.exec(readFileSync(dotGit, 'utf8'));
          if (m?.[1]) gitDir = isAbsolute(m[1]) ? m[1] : resolve(dir, m[1]);
        }
      } catch { return null; }
      if (!gitDir || !existsSync(gitDir)) return null;
      let commonDir = gitDir;
      const commonFile = join(gitDir, 'commondir');
      if (existsSync(commonFile)) {
        const c = readFileSync(commonFile, 'utf8').trim();
        commonDir = isAbsolute(c) ? c : resolve(gitDir, c);
      }
      const configFiles = [join(commonDir, 'config'), join(gitDir, 'config.worktree')].filter((f, i, all) => all.indexOf(f) === i && existsSync(f));
      return { workTree: dir, gitDir, configFiles };
    }
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

export type GuardResult =
  | { ok: true; repo: RepoLocation }
  | { ok: false; kind: 'not-a-repo' | 'unsafe-config' | 'unreadable-config'; message: string; keys: string[] };

const MAX_CONFIG_BYTES = 1024 * 1024;

/** Ask git to list one config file, with no repository and no includes (runs nothing). */
function gitListConfig(file: string): Promise<ConfigEntry[] | null> {
  return new Promise((done) => {
    execFile(
      'git',
      ['config', '--file', file, '--no-includes', '--list', '-z'],
      {
        cwd: tmpdir(), encoding: 'utf8', timeout: 5_000, killSignal: 'SIGKILL', maxBuffer: 4 * 1024 * 1024, windowsHide: true,
        env: { ...process.env, GIT_DIR: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_ATTR_NOSYSTEM: '1' },
      },
      (err, stdout) => {
        if (err) { done(null); return; }
        done(stdout.split('\u0000').filter((r) => r !== '').map((r) => {
          const nl = r.indexOf('\n');
          const name = nl < 0 ? r : r.slice(0, nl);
          const first = name.indexOf('.');
          const last = name.lastIndexOf('.');
          return {
            section: name.slice(0, first).toLowerCase(),
            subsection: last > first ? name.slice(first + 1, last) : null,
            key: name.slice(last + 1).toLowerCase(),
            value: nl < 0 ? 'true' : r.slice(nl + 1),
          };
        }));
      },
    );
  });
}

const advice = 'Its own git config could make git run commands. Clone it fresh (git clone <url>) and run exorcist origin on the clone, or use "exorcist scan", which never runs git.';

/**
 * Check the repository around `target` before any git command runs in it.
 * Refuses when there is no repository, when a config file cannot be read
 * safely, or when it sets a key that names a program.
 */
export async function guardRepoConfig(target: string): Promise<GuardResult> {
  const repo = locateRepo(target);
  if (!repo) return { ok: false, kind: 'not-a-repo', message: 'not inside a git repository', keys: [] };
  const keys: string[] = [];
  for (const file of repo.configFiles) {
    let text: string;
    try {
      if (statSync(file).size > MAX_CONFIG_BYTES) return { ok: false, kind: 'unreadable-config', message: `${file} is too large to check. ${advice}`, keys: [] };
      text = readFileSync(file, 'utf8');
    } catch {
      return { ok: false, kind: 'unreadable-config', message: `${file} could not be read. ${advice}`, keys: [] };
    }
    const parsed = parseGitConfig(text);
    if (!parsed.ok) return { ok: false, kind: 'unreadable-config', message: `${file} could not be checked (line ${parsed.line}). ${advice}`, keys: [] };
    for (const e of parsed.entries) { const k = dangerousKey(e); if (k) keys.push(k); }
    if (keys.length === 0) {
      // Second opinion from git's own parser (nothing is executed by --list).
      const listed = await gitListConfig(file);
      if (listed === null) return { ok: false, kind: 'unreadable-config', message: `git could not read ${file}. ${advice}`, keys: [] };
      for (const e of listed) { const k = dangerousKey(e); if (k) keys.push(k); }
    }
  }
  if (keys.length > 0) {
    const shown = [...new Set(keys)].slice(0, 5).map((k) => k.replace(/[^\x20-\x7e]/g, '?').slice(0, 80));
    return { ok: false, kind: 'unsafe-config', message: `the repository's git config sets ${shown.join(', ')}. ${advice}`, keys: shown };
  }
  return { ok: true, repo };
}
