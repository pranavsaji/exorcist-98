import { describe, it, expect, afterEach } from 'vitest';
import * as fc from 'fast-check';
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  CanariesFileSchema, base64Needles, findCanaryInText, findStagedCanaries, isCanaryHome, isCanaryToken,
  loadCanariesFile, maskToken, newToken,
} from '../canary.js';
import type { Canary } from '../canary.js';
import { canaryFindings, scanRepo } from '../scanner/orchestrator.js';
import type { Finding } from '../types.js';
import { REPO_ROOT } from './repo-root.js';

const DEFS = resolve(REPO_ROOT, 'definitions');
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-canary-core-')); dirs.push(d); return d; };

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.split('');
const tokenArb = fc.array(fc.constantFrom(...B32), { minLength: 24, maxLength: 24 }).map((cs) => `x98c_${cs.join('')}`);
const trap = (token: string, name = '.env.canary'): Canary => ({ token, file: `.exorcist/canary/${name}` });

/** Write a project with planted records (tokens made here, at run time). */
function project(tokens: string[]): string {
  const d = tmp();
  mkdirSync(join(d, '.exorcist/canary'), { recursive: true });
  const names = ['.env.canary', 'NOTES.md', 'config.json'];
  const canaries = tokens.map((token, i) => ({ token, file: `.exorcist/canary/${names[i]}`, created: '2026-11-20T10:00:00.000Z' }));
  for (const c of canaries) writeFileSync(join(d, c.file), `DEPLOY_TOKEN=${c.token}\n`);
  writeFileSync(join(d, '.exorcist/canaries.json'), JSON.stringify({ version: 1, canaries }));
  return d;
}

async function scan(root: string): Promise<{ findings: Finding[]; errors: string[] }> {
  const findings: Finding[] = [];
  const errors: string[] = [];
  for await (const ev of scanRepo(root, { definitionsDir: DEFS })) {
    if (ev.type === 'finding') findings.push(ev.finding);
    if (ev.type === 'error') errors.push(`${ev.file}: ${ev.message}`);
  }
  return { findings, errors };
}

describe('canary tokens', () => {
  it('newToken is x98c_ + 24 base32 characters and never repeats', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      const t = newToken();
      expect(t).toMatch(/^x98c_[A-Z2-7]{24}$/);
      expect(isCanaryToken(t)).toBe(true);
      seen.add(t);
    }
    expect(seen.size).toBe(2000);
  });

  it('every base32 character shows up (the random part is not biased toward a few letters)', () => {
    const chars = new Set(Array.from({ length: 200 }, () => newToken().slice(5)).join(''));
    expect(chars.size).toBe(32);
  });

  it('maskToken hides the random part', () => {
    const t = newToken();
    expect(maskToken(t)).toBe(`${t.slice(0, 7)}${'*'.repeat(22)}`);
  });

  it('the trap folder and the records file are the only homes', () => {
    expect(isCanaryHome('.exorcist/canary/NOTES.md')).toBe(true);
    expect(isCanaryHome('.exorcist/canaries.json')).toBe(true);
    expect(isCanaryHome('.exorcist/alerts.jsonl')).toBe(false);
    expect(isCanaryHome('docs/.exorcist/canary-notes.md')).toBe(false);
    expect(isCanaryHome('README.md')).toBe(false);
  });
});

describe('the records file', () => {
  it('a missing file is an empty list; broken JSON or a bad record is an error', () => {
    const d = tmp();
    expect(loadCanariesFile(join(d, 'none.json'))).toEqual({ ok: true, canaries: [], madeDirs: [] });
    writeFileSync(join(d, 'bad.json'), '{');
    expect(loadCanariesFile(join(d, 'bad.json')).ok).toBe(false);
    writeFileSync(join(d, 'short.json'), JSON.stringify({ version: 1, canaries: [{ token: 'x98c_SHORT', file: '.exorcist/canary/a', created: 'x' }] }));
    expect(loadCanariesFile(join(d, 'short.json')).ok).toBe(false);
  });

  it('a trap path must stay inside .exorcist/canary/', () => {
    const rec = (file: string) => CanariesFileSchema.safeParse({ version: 1, canaries: [{ token: newToken(), file, created: 'x' }] }).success;
    expect(rec('.exorcist/canary/NOTES.md')).toBe(true);
    for (const bad of ['../etc/passwd', '/etc/passwd', '.exorcist/canary/../../x', 'src/index.ts', '.exorcist/canary/', '.exorcist\\canary\\x']) {
      expect(rec(bad), bad).toBe(false);
    }
  });
});

describe('findCanaryInText', () => {
  it('reports the exact span, the shape and the trap for each disguise', () => {
    const t = newToken();
    const c = [trap(t)];
    const b64 = Buffer.from(`key=${t};`).toString('base64');
    const cases: Array<[string, string, string]> = [
      [`a ${t} b`, 'raw', t],
      [`a ${[...t].join(' ')} b`, 'whitespace-split', [...t].join(' ')],
      [`a ${t.slice(0, 9)}\n${t.slice(9)} b`, 'whitespace-split', `${t.slice(0, 9)}\n${t.slice(9)}`],
      [`?k=${[...t].map((ch) => `%${ch.charCodeAt(0).toString(16)}`).join('')}&x`, 'percent-encoded', [...t].map((ch) => `%${ch.charCodeAt(0).toString(16)}`).join('')],
    ];
    for (const [text, shape, span] of cases) {
      const [h] = findCanaryInText(text, c);
      expect(h?.shape, text).toBe(shape);
      expect(text.slice(h!.index, h!.end)).toBe(span);
      expect(h?.canary.file).toBe('.exorcist/canary/.env.canary');
    }
    const [h] = findCanaryInText(`blob: ${b64}`, c);
    expect(h?.shape).toBe('base64');
    expect(b64).toContain(`blob: ${b64}`.slice(h!.index, h!.end));
  });

  it('finds base64 of base64, and base64 of a whitespace-split token', () => {
    const t = newToken();
    const twice = Buffer.from(Buffer.from(`x${t}`).toString('base64')).toString('base64');
    expect(findCanaryInText(twice, [trap(t)])[0]?.shape).toBe('base64');
    const split = Buffer.from([...t].join(' ')).toString('base64');
    expect(findCanaryInText(split, [trap(t)])[0]?.shape).toBe('base64');
  });

  it('there are needles for all three byte alignments', () => {
    expect(base64Needles(newToken()).length).toBeGreaterThanOrEqual(3);
  });

  it('PBT: the base64 of any text holding a token is found, at any alignment, wrapped or not', () => {
    fc.assert(fc.property(tokenArb, fc.string({ maxLength: 40 }), fc.string({ maxLength: 40 }), fc.boolean(), fc.boolean(), (t, before, after, url, wrap) => {
      let enc = Buffer.from(`${before}${t}${after}`, 'utf8').toString(url ? 'base64url' : 'base64');
      if (wrap) enc = (enc.match(/.{1,19}/g) ?? []).join('\r\n');
      expect(findCanaryInText(`payload: ${enc} end`, [trap(t)]).map((h) => h.shape)).toEqual(['base64']);
    }), { numRuns: 400 });
  });

  it('PBT: text without the token finds nothing, even with an unrelated token in it', () => {
    fc.assert(fc.property(tokenArb, tokenArb, fc.fullUnicodeString({ maxLength: 200 }), (planted, other, text) => {
      fc.pre(planted !== other);
      const mixed = `${text} ${other} ${Buffer.from(other).toString('base64')} ${encodeURIComponent(text)}`;
      expect(findCanaryInText(mixed, [trap(planted)])).toEqual([]);
    }), { numRuns: 400 });
  });
});

describe('scan: EX-022 for a token copied out of its trap', () => {
  it('reports copies outside the trap (raw and base64), not the traps or the records', async () => {
    const t = [newToken(), newToken()];
    const d = project(t);
    writeFileSync(join(d, 'README.md'), `# Demo\n\nThe deploy key is ${t[1]}\n`);
    mkdirSync(join(d, 'src'));
    writeFileSync(join(d, 'src/leak.ts'), `export const blob = "${Buffer.from(`k=${t[0]}`).toString('base64')}";\n`);
    const { findings, errors } = await scan(d);
    expect(errors).toEqual([]);
    const ex022 = findings.filter((f) => f.ruleId === 'EX-022').sort((a, b) => a.file.localeCompare(b.file));
    expect(ex022.map((f) => [f.file, f.line, f.severity])).toEqual([['README.md', 3, 'critical'], ['src/leak.ts', 1, 'critical']]);
    expect(ex022[0]?.span).toBe(t[1]);
    expect(ex022[0]?.fix).toContain('copied out of its trap');
    expect(ex022[0]?.fix).toContain('.exorcist/canary/NOTES.md');
    expect(ex022[1]?.fix).toContain('.exorcist/canary/.env.canary');
    expect(ex022[0]?.owasp).toContain('LLM02:2025 Sensitive Information Disclosure');
    // Every finding quotes text that is really in the file.
    for (const f of ex022) expect(f.span.length).toBeGreaterThan(0);
    // The traps themselves are not findings of any rule.
    expect(findings.filter((f) => f.file.startsWith('.exorcist/'))).toEqual([]);
  });

  it('a project with no records gets no EX-022, and a broken records file is reported, not ignored', async () => {
    const d = tmp();
    writeFileSync(join(d, 'README.md'), `key ${newToken()}\n`);
    expect((await scan(d)).findings.filter((f) => f.ruleId === 'EX-022')).toEqual([]);
    mkdirSync(join(d, '.exorcist'));
    writeFileSync(join(d, '.exorcist/canaries.json'), '{"version":2}');
    expect((await scan(d)).errors.some((e) => e.startsWith('.exorcist/canaries.json'))).toBe(true);
  });

  it('canaryFindings skips only the homes', () => {
    const t = newToken();
    expect(canaryFindings(t, '.exorcist/canary/NOTES.md', [trap(t)])).toEqual([]);
    expect(canaryFindings(t, '.exorcist/canaries.json', [trap(t)])).toEqual([]);
    expect(canaryFindings(t, '.exorcist/notes.md', [trap(t)])).toHaveLength(1);
  });
});

describe('pre-commit: findStagedCanaries', () => {
  function repo(tokens: string[]) {
    const d = project(tokens);
    const git = (...a: string[]) => execFileSync('git', a, { cwd: d, stdio: 'pipe' });
    git('init', '-q');
    git('config', 'user.email', 't@example.invalid');
    git('config', 'user.name', 't');
    return { d, git };
  }

  it('finds a token staged outside the trap folder, and allows the traps and records', () => {
    const t = newToken();
    const { d, git } = repo([t]);
    git('add', '.exorcist');
    expect(findStagedCanaries(d)).toEqual({ ok: true, hits: [] });
    writeFileSync(join(d, 'notes.txt'), `line one\n${encodeURIComponent('x')} ${[...t].join(' ')}\n`);
    git('add', 'notes.txt');
    const r = findStagedCanaries(d);
    expect(r).toEqual({ ok: true, hits: [{ file: 'notes.txt', line: 2, trap: '.exorcist/canary/.env.canary', redacted: maskToken(t) }] });
  });

  it('checks what is staged, not the working copy', () => {
    const t = newToken();
    const { d, git } = repo([t]);
    writeFileSync(join(d, 'a.md'), `copied: ${t}\n`);
    git('add', 'a.md');
    writeFileSync(join(d, 'a.md'), 'cleaned up, but not staged\n');
    expect(findStagedCanaries(d).ok && (findStagedCanaries(d) as { hits: unknown[] }).hits).toHaveLength(1);
  });

  it('with no records there is nothing to find; outside a repository it is an error', () => {
    const d = tmp();
    execFileSync('git', ['init', '-q'], { cwd: d });
    writeFileSync(join(d, 'a.md'), newToken());
    execFileSync('git', ['add', 'a.md'], { cwd: d });
    expect(findStagedCanaries(d)).toEqual({ ok: true, hits: [] });
    expect(findStagedCanaries(tmp()).ok).toBe(false);
  });
});
