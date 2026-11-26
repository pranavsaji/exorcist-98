/**
 * Spec m14-first-five-minutes (.kiro/specs/m14-first-five-minutes). Every test
 * name starts with the ID of the criterion it checks (FF-n.m); the last test
 * fails if a criterion in requirements.md has no test.
 *
 * What a judge reads first is checked here: the README opening, docs/START-HERE.md,
 * and the comparison table in docs/REFERENCE.md. The CI job and its script are
 * checked in published-shape.test.ts; the site footer in apps/web.
 */
import { beforeAll, describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('.', import.meta.url)), '../../../..');
const read = (rel: string): string => readFileSync(join(ROOT, rel), 'utf8');
const README = read('README.md');
const START = read('docs/START-HERE.md');
const REFERENCE = read('docs/REFERENCE.md');
const CLI = join(ROOT, 'packages/cli/dist/index.mjs');
const LIVE = 'https://exorcist-98.vercel.app';
const GIF = 'docs/media/rug-pull-demo.gif';

beforeAll(() => {
  // The CLI build swaps its file in place, so a parallel test file never sees it missing.
  execFileSync(process.execPath, [join(ROOT, 'packages/cli/build.mjs')], { cwd: join(ROOT, 'packages/cli'), stdio: 'pipe' });
}, 60_000);

const scan = (target: string): { status: number | null; out: string } => {
  const r = spawnSync(process.execPath, [CLI, 'scan', target], { cwd: ROOT, encoding: 'utf8', timeout: 60_000, env: { ...process.env, EXORCIST_NOTIFY: '0' } });
  return { status: r.status, out: r.stdout };
};

/** The text between a `## heading` and the next `## ` heading. */
function section(md: string, heading: string): string {
  const start = md.indexOf(`\n## ${heading}`);
  if (start < 0) return '';
  const next = md.indexOf('\n## ', start + 4);
  return md.slice(start, next < 0 ? undefined : next);
}
const links = (md: string): string[] => [...md.replace(/<!--[\s\S]*?-->/g, '').matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1] ?? '');
const slug = (h: string): string => h.trim().toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, '').replace(/\s/g, '-');
const anchors = (md: string): Set<string> => new Set([...md.matchAll(/^#{1,6}\s+(.+)$/gm)].map((m) => slug((m[1] ?? '').replace(/`/g, ''))));

/** The first lines of the README that hold something, in order. */
const readmeLines = README.split('\n');
const pitchAt = readmeLines.findIndex((l) => l.startsWith('**The 90s antivirus'));
const nonEmptyAfter = (n: number): string[] => readmeLines.slice(pitchAt + 1).filter((l) => l.trim() !== '').slice(0, n);

describe('FF-1 the README opens with a moving picture', () => {
  it('FF-1.1 the recording is the first thing under the one-line pitch', () => {
    expect(pitchAt).toBeGreaterThan(0);
    expect(nonEmptyAfter(1)[0]).toMatch(/^!\[[^\]]+\]\(docs\/media\/rug-pull-demo\.gif\)$/);
  });

  it('FF-1.2 the alt text says what happens in it', () => {
    const alt = /^!\[([^\]]+)\]/.exec(nonEmptyAfter(1)[0] ?? '')?.[1] ?? '';
    expect(alt.length).toBeGreaterThan(120);
    for (const word of ['rug pull', 'description', 'Shield', 'compromised', 'protected']) expect(alt).toContain(word);
  });

  it('FF-1.3 a caption under it links the live rug-pull demo', () => {
    const caption = nonEmptyAfter(2)[1] ?? '';
    expect(caption.startsWith('*')).toBe(true);
    expect(caption).toContain(`(${LIVE}/?demo=rug-pull)`);
    expect(caption).toContain('Result: protected');
  });

  it('FF-1.4 the Touch ID placeholder comment and the other image are still there, in order', () => {
    const comment = README.indexOf('<!-- PLACEHOLDER FOR THE OWNER');
    const image = README.indexOf('![The Shield console while the Session Guard holds a message');
    expect(comment).toBeGreaterThan(0);
    expect(README).toContain('docs/media/session-guard-touchid.gif');
    expect(image).toBeGreaterThan(comment);
  });

  it('FF-1.5 the README stays short', () => {
    expect(readmeLines.length).toBeLessThanOrEqual(115);
  });

  it('FF-1.6 our own scan of the README (and of START-HERE) is CLEAN', () => {
    for (const f of ['README.md', 'docs/START-HERE.md']) {
      const r = scan(f);
      expect(r.out, f).toContain('Verdict: CLEAN');
      expect(r.status, f).toBe(0);
    }
  });

  it('FF-1.7 the recording is a real GIF of at most 2.5 MB', () => {
    const path = join(ROOT, GIF);
    expect(existsSync(path)).toBe(true);
    expect(readFileSync(path).subarray(0, 4).toString('latin1')).toBe('GIF8');
    expect(statSync(path).size).toBeLessThanOrEqual(2_500_000);
  });
});

describe('FF-2 docs/START-HERE.md', () => {
  it('FF-2.1 the page exists and the README links it from its top', () => {
    expect(START.startsWith('# Start here')).toBe(true);
    const top = readmeLines.slice(0, 14).join('\n');
    expect(top).toContain('(docs/START-HERE.md)');
  });

  it('FF-2.2 the 60-second part has the three live links, each with what to look for', () => {
    const s = section(START, '60 seconds, nothing to install');
    for (const demo of ['haunted', 'rug-pull', 'trifecta']) expect(s).toContain(`${LIVE}/?demo=${demo}`);
    const rows = s.split('\n').filter((l) => l.startsWith('| [') && l.includes(LIVE));
    expect(rows).toHaveLength(3);
    for (const r of rows) expect((r.split('|')[2] ?? '').trim().length).toBeGreaterThan(60);
    expect(s).toContain('POSSESSED');
    expect(s).toContain('Result: protected');
    expect(s).toContain('EX-027');
  });

  it('FF-2.3 the 5-minute part has the scan command, the Power import URL and init --kiro', () => {
    const s = section(START, '5 minutes on your own machine');
    expect(s).toContain('npx -y @exorcist-98/cli scan .');
    expect(s).toContain('https://github.com/pranavsaji/exorcist-98/tree/main/power');
    expect(s).toContain('exorcist-98/cli init --kiro');
  });

  it('FF-2.4 the scenario table gives an expected result per row, and the Haunted Repo and clean rows match the real CLI', () => {
    const s = section(START, 'Check each claim');
    const rows = s.split('\n').filter((l) => l.startsWith('|') && !l.startsWith('|---') && !l.startsWith('| Scenario'));
    expect(rows.length).toBeGreaterThanOrEqual(8);
    for (const r of rows) {
      const cells = r.split('|').slice(1, -1).map((c) => c.trim());
      expect(cells, r).toHaveLength(4);
      for (const c of cells) expect(c.length, r).toBeGreaterThan(0);
    }
    // The claims for the two rows we can run in a test, checked against the built CLI.
    const facts = JSON.parse(read('docs/facts.json')) as { hauntedRepoFindings: number };
    const haunted = scan('fixtures/haunted-repo');
    expect(haunted.status).toBe(1);
    expect(haunted.out).toContain('Verdict: POSSESSED');
    expect(haunted.out).toContain(`${facts.hauntedRepoFindings} threats`);
    expect(s).toContain(`<!--f:hauntedRepoFindings-->${facts.hauntedRepoFindings}<!--/f--> threats`);
    expect(s).toContain('"Verdict: POSSESSED"');
    expect(s).toContain('"Verdict: CLEAN"');
    expect(s).toContain('"Result: protected."');
  });

  it('FF-2.5 each judging question has links, and every linked path exists', () => {
    const s = section(START, 'Where to look for each judging question');
    const rows = s.split('\n').filter((l) => l.startsWith('| **'));
    expect(rows.map((r) => /^\| \*\*([^:*]+)/.exec(r)?.[1])).toEqual(['Potential impact', 'How Kiro was used', 'Design', 'What is new']);
    for (const r of rows) {
      const own = links(r).filter((l) => !l.startsWith('http'));
      expect(own.length, r).toBeGreaterThanOrEqual(2);
      for (const l of own) expect(existsSync(resolve(ROOT, 'docs', (l.split('#')[0] ?? ''))), `${l} in ${r}`).toBe(true);
    }
  });

  it('FF-2.6 the honest limits are three lines and link KNOWN_LIMITATIONS.md', () => {
    const s = section(START, 'The honest limits');
    const bullets = s.split('\n').filter((l) => l.startsWith('- '));
    expect(bullets).toHaveLength(3);
    expect(s).toContain('(KNOWN_LIMITATIONS.md)');
  });

  it('FF-2.7 every relative link in README, START-HERE and REFERENCE leads somewhere that exists', () => {
    const docs: Record<string, string> = { 'README.md': README, 'docs/START-HERE.md': START, 'docs/REFERENCE.md': REFERENCE };
    const bad: string[] = [];
    for (const [file, md] of Object.entries(docs)) {
      for (const l of links(md)) {
        if (/^(https?:|mailto:|#)/.test(l)) {
          if (l.startsWith('#') && !anchors(md).has(l.slice(1))) bad.push(`${file}: ${l}`);
          continue;
        }
        const [pathPart, anchor] = l.split('#');
        const target = resolve(ROOT, dirname(file), pathPart ?? '');
        if (!existsSync(target)) { bad.push(`${file}: ${l}`); continue; }
        if (anchor && target.endsWith('.md') && !anchors(readFileSync(target, 'utf8')).has(anchor)) bad.push(`${file}: ${l}`);
      }
    }
    expect(bad).toEqual([]);
  });

  it('FF-2.9 START-HERE is one of the documents whose numbers scripts/facts.mjs checks', () => {
    expect(read('scripts/facts.mjs')).toMatch(/export const DOCS = \[[^\]]*'docs\/START-HERE\.md'/);
    expect(START).toMatch(/<!--f:[A-Za-z.]+-->/);
  });
});

describe('FF-3 how this differs from tools that already exist', () => {
  const sec = section(REFERENCE, 'How this differs from tools that already exist');
  const tableRows = sec.split('\n').filter((l) => l.startsWith('| **'));
  const cells = (row: string): string[] => row.split('|').slice(1, -1).map((c) => c.trim());

  it('FF-3.1 the table names Exorcist 98 and at least six existing tools, covering each kind in the brief', () => {
    expect(tableRows.length).toBeGreaterThanOrEqual(7);
    const names = tableRows.map((r) => cells(r)[0] ?? '').join(' ');
    for (const n of ['Exorcist 98', 'Snyk Agent Scan', 'Lakera Guard', 'semgrep-rules-mcp', 'GitHub secret scanning']) expect(names).toContain(n);
    // At least two MCP proxies or firewalls.
    expect(['Invariant Guardrails', 'MCPTrust', 'mcp-fence'].filter((n) => names.includes(n)).length).toBeGreaterThanOrEqual(2);
  });

  it('FF-3.2 every row links its source, and no source is a link back to this repository except our own row', () => {
    for (const r of tableRows) {
      const c = cells(r);
      expect(c).toHaveLength(6);
      const last = c[5] ?? '';
      if (c[0]?.startsWith('**Exorcist 98**')) { expect(last).toContain('](../README.md)'); continue; }
      expect(last, r).toMatch(/\]\(https:\/\/[^)]+\)/);
      expect(last, r).not.toContain('pranavsaji');
    }
  });

  it('FF-3.3 a feature that is not confirmed says "not documented", and no cell is empty or a guess', () => {
    expect(sec).toContain('Not documented');
    for (const r of tableRows) for (const c of cells(r)) { expect(c.length).toBeGreaterThan(0); expect(c).not.toMatch(/\?|TBD|probably|maybe|unknown/i); }
    expect(sec).toContain('"Not documented" means we did not find it');
  });

  it('FF-3.4 it says what Exorcist 98 adds and where another tool does more', () => {
    const adds = section(sec.replace(/\n### /g, '\n## '), 'What Exorcist 98 adds');
    const more = section(sec.replace(/\n### /g, '\n## '), 'Where another tool does more');
    expect(adds.split('\n').filter((l) => l.startsWith('- ')).length).toBeGreaterThanOrEqual(3);
    expect(more.split('\n').filter((l) => l.startsWith('- ')).length).toBeGreaterThanOrEqual(5);
  });

  it('FF-3.5 the README summarises it in two lines and links the section', () => {
    const at = readmeLines.findIndex((l) => l.startsWith('How this differs from tools that already exist'));
    expect(at).toBeGreaterThan(0);
    expect(readmeLines[at + 1]).toContain('](docs/REFERENCE.md#how-this-differs-from-tools-that-already-exist)');
    expect(readmeLines[at + 2]?.trim() ?? '').toBe('');
    expect(anchors(REFERENCE).has('how-this-differs-from-tools-that-already-exist')).toBe(true);
  });

  it('FF-3.6 the old unsourced claim of what other scanners do is gone', () => {
    expect(REFERENCE).not.toContain('as far as we can tell from those projects');
    expect(REFERENCE).not.toContain('## How it compares to other MCP scanners');
  });
});

describe('FF-5 finish', () => {
  it('FF-5.1 docs/KIRO_LOG.md has a row for this work by the Kiro IDE agent', () => {
    const rows = read('docs/KIRO_LOG.md').split('\n').filter((l) => l.includes('m14-first-five-minutes'));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toContain('Kiro IDE agent');
    expect(rows[0]).toContain('TASK-judges.md');
  });

  it('FF-5.2 the brief has moved to docs/kiro-briefs/', () => {
    expect(existsSync(join(ROOT, 'docs/kiro-briefs/TASK-judges.md'))).toBe(true);
    expect(existsSync(join(ROOT, 'TASK-judges.md'))).toBe(false);
  });

  it('FF-5.3 the spec has all three documents and the last task is the commit', () => {
    for (const f of ['requirements.md', 'design.md', 'tasks.md']) expect(existsSync(join(ROOT, '.kiro/specs/m14-first-five-minutes', f)), f).toBe(true);
    expect(read('.kiro/specs/m14-first-five-minutes/tasks.md')).toMatch(/Commit \(do not push\)/);
  });

  it('FF-5.5 the numbers in every document agree with docs/facts.json (scripts/facts.mjs --check)', () => {
    const r = spawnSync(process.execPath, [join(ROOT, 'scripts/facts.mjs'), '--check'], { cwd: ROOT, encoding: 'utf8', timeout: 120_000 });
    expect(r.stderr).toBe('');
    expect(r.status).toBe(0);
  }, 130_000);

  it('FF-5.4 every criterion in requirements.md has a test whose name starts with its ID', () => {
    const req = read('.kiro/specs/m14-first-five-minutes/requirements.md');
    const ids = [...new Set([...req.matchAll(/^(FF-\d+\.\d+)\s/gm)].map((m) => m[1] ?? ''))];
    expect(ids.length).toBeGreaterThanOrEqual(30);
    const testFiles = [
      'packages/cli/src/__tests__/first-five-minutes.test.ts',
      'packages/cli/src/__tests__/published-shape.test.ts',
      'apps/web/src/__tests__/site-footer.test.tsx',
    ];
    const titles = testFiles.flatMap((f) => [...read(f).matchAll(/\bit\(\s*['"`]([^'"`]+)['"`]/g)].map((m) => m[1] ?? ''));
    const missing = ids.filter((id) => !titles.some((t) => new RegExp(`(^|\\s)${id.replace('.', '\\.')}(\\s|$|:)`).test(t) && t.trimStart().startsWith('FF-')));
    expect(missing).toEqual([]);
    const strays = titles.filter((t) => t.startsWith('FF-') && !/^FF-\d+\.\d+/.test(t));
    expect(strays).toEqual([]);
    // Nothing in the spec folder besides the three documents and the task metadata.
    expect(readdirSync(join(ROOT, '.kiro/specs/m14-first-five-minutes')).filter((f) => !/^(requirements|design|tasks)\.md$|^tasks\.meta\.json$/.test(f))).toEqual([]);
  });
});
