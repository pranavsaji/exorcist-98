/**
 * m13-kiro-evidence: the release steering file (KE-34), the auditor agent never
 * being started by the repository (KE-40), and the finish steps (KE-41 to KE-47).
 *
 * The finish-step tests check the artefacts those steps leave behind, so they
 * fail until task 19 of the spec has been run: KE-41, KE-43, KE-44, KE-45, KE-47.
 */
import { describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { z } from 'zod';
import { containsSecretShape } from '@exorcist-98/core';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const read = (p: string): string => readFileSync(join(ROOT, p), 'utf8');
const EVIDENCE = 'evidence/kiro-sessions';

const IndexSchema = z.object({
  sessions: z.array(z.object({ id: z.string().min(1) }).passthrough()),
  totals: z.object({ sessionsKept: z.number().int().nonnegative() }).passthrough(),
});

function frontMatter(text: string): Record<string, string> {
  const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
  const fm: Record<string, string> = {};
  for (const line of (m?.[1] ?? '').split('\n')) {
    const kv = /^([A-Za-z]+):\s*(.*)$/.exec(line);
    if (kv !== null) fm[kv[1] ?? ''] = (kv[2] ?? '').trim();
  }
  return fm;
}

/** Every file under a folder, as repository-relative paths (missing folder: none). */
function filesUnder(rel: string): string[] {
  const abs = join(ROOT, rel);
  if (!existsSync(abs)) return [];
  return readdirSync(abs, { recursive: true, encoding: 'utf8' })
    .map((name) => join(rel, name))
    .filter((f) => statSync(join(ROOT, f)).isFile());
}

describe('m13-kiro-evidence: steering and auditor', () => {
  it('KE-34 release.md is a manual-inclusion steering file with the release guidance', () => {
    const text = read('.kiro/steering/release.md');
    expect(frontMatter(text).inclusion).toBe('manual');
    for (const s of ['scripts/release.sh', '.github/workflows/release.yml', 'docs/PUBLISH.md', 'npm publish']) expect(text).toContain(s);
  });

  it('KE-40 nothing in the repository starts the exorcist-auditor agent', () => {
    expect(existsSync(join(ROOT, '.kiro/agents/exorcist-auditor.json'))).toBe(true);
    const starters = [
      ...filesUnder('.kiro/hooks'), ...filesUnder('.github/workflows'), ...filesUnder('scripts'),
      'package.json', ...readdirSync(join(ROOT, 'packages')).map((p) => `packages/${p}/package.json`),
    ].filter((f) => existsSync(join(ROOT, f)));
    expect(starters.length).toBeGreaterThan(5);
    for (const f of starters) expect(read(f), f).not.toContain('exorcist-auditor');
  });
});

describe('m13-kiro-evidence: finish', () => {
  it('KE-41 the exported sessions are in evidence/kiro-sessions/ and pass the safety rescan', () => {
    const index = IndexSchema.parse(JSON.parse(read(`${EVIDENCE}/index.json`)));
    expect(index.sessions.length).toBe(index.totals.sessionsKept);
    expect(index.sessions.length).toBeGreaterThan(0);
    expect(containsSecretShape(read(`${EVIDENCE}/index.json`))).toBe(false);
    for (const s of index.sessions) {
      const file = join(ROOT, EVIDENCE, `${encodeURIComponent(s.id)}.jsonl.gz`);
      expect(existsSync(file), s.id).toBe(true);
      expect(containsSecretShape(gunzipSync(readFileSync(file)).toString('utf8')), s.id).toBe(false);
    }
  });

  it('KE-42 docs/HOW_KIRO.md has the steering table, one row per steering file', () => {
    const md = read('docs/HOW_KIRO.md');
    expect(md).toMatch(/^## Steering files$/m);
    const files = readdirSync(join(ROOT, '.kiro/steering')).filter((f) => f.endsWith('.md'));
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const mode = frontMatter(read(`.kiro/steering/${f}`)).inclusion;
      expect(md, f).toContain(`| \`${f}\` | ${mode} |`);
    }
  });

  it('KE-43 docs/facts.json carries the Kiro evidence totals from evidence/kiro-sessions/index.json', () => {
    const facts = z.object({ kiroSessions: z.number(), hookRuns: z.number(), tests: z.number() }).passthrough()
      .parse(JSON.parse(read('docs/facts.json')));
    const index = IndexSchema.parse(JSON.parse(read(`${EVIDENCE}/index.json`)));
    expect(facts.kiroSessions).toBe(index.totals.sessionsKept);
    expect(facts.kiroSessions).toBeGreaterThan(0);
    expect(facts.tests).toBeGreaterThan(0);
  });

  it('KE-44 docs/KIRO_LOG.md has a row for this work, attributed to the Kiro IDE agent', () => {
    const rows = read('docs/KIRO_LOG.md').split('\n')
      .filter((l) => /^\| \d{4}-\d{2}-\d{2} \|/.test(l) && l.includes('m13-kiro-evidence'));
    expect(rows.some((r) => r.includes('Kiro IDE agent'))).toBe(true);
  });

  it('KE-45 the brief lives in docs/kiro-briefs/, not at the repository root', () => {
    expect(existsSync(join(ROOT, 'docs/kiro-briefs/TASK-kiro-evidence.md'))).toBe(true);
    expect(existsSync(join(ROOT, 'TASK-kiro-evidence.md'))).toBe(false);
  });

  it('KE-46 pnpm -r typecheck passes (the vitest half is this run)', () => {
    const r = spawnSync('pnpm', ['-r', 'typecheck'], { cwd: ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    expect(r.status, (r.stdout + r.stderr).slice(-2000)).toBe(0);
  }, 300_000);

  it('KE-47 the m13 work is committed to git', () => {
    const committed = [
      '.kiro/specs/m13-kiro-evidence/requirements.md', '.kiro/specs/m13-kiro-evidence/tasks.md',
      'packages/core/src/kiro-evidence.ts', 'scripts/kiro-evidence.mjs', 'scripts/spec-trace.mjs',
      '.kiro/agents/exorcist-auditor.json', '.kiro/steering/release.md', `${EVIDENCE}/index.json`,
      'docs/kiro-briefs/TASK-kiro-evidence.md',
    ];
    for (const f of committed) {
      expect(() => execFileSync('git', ['cat-file', '-e', `HEAD:${f}`], { cwd: ROOT, stdio: 'ignore' }), f).not.toThrow();
    }
  });
});
