/**
 * The /how-kiro page and docs/HOW_KIRO.md say the same thing, and every claim
 * they point at can be checked: cited files exist, cited commits are in the
 * repository.
 */
import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderToStaticMarkup } from 'react-dom/server';
import HowKiroPage from '@/app/how-kiro/page';
import {
  CHECK_COMMANDS, HOW_KIRO_INTRO, HOW_KIRO_TITLE, STEERING_TABLE, SURFACES, SURPRISES, USER_SETUP, howKiroMarkdown,
} from '@/lib/how-kiro';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '../../../..');
const CREW = resolve(ROOT, '../exorcist-98-crew');
const MD = readFileSync(join(ROOT, 'docs/HOW_KIRO.md'), 'utf8');

/** The page's text with tags removed and entities decoded, so it can be compared with the Markdown. */
function pageText(): string {
  return renderToStaticMarkup(<HowKiroPage />)
    .replace(/<[^>]+>/g, '')
    .replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
}
const plain = (s: string): string => s.replace(/`/g, '');

const allText = (): string[] => [
  ...HOW_KIRO_INTRO, USER_SETUP.text,
  ...SURFACES.flatMap((s) => [...s.did, ...s.evidence, s.status]),
  ...SURPRISES.flatMap((s) => [s.story, ...s.evidence]),
];

describe('docs/HOW_KIRO.md and the /how-kiro page', () => {
  it('the Markdown is exactly what the page content generates (run scripts/how-kiro-md.ts after editing lib/how-kiro.ts)', () => {
    expect(MD).toBe(howKiroMarkdown());
  });

  it('both have every key heading', () => {
    const text = pageText();
    const headings = [
      HOW_KIRO_TITLE, 'Kiro features at a glance', ...SURFACES.map((s) => s.title), USER_SETUP.title,
      'Where Kiro surprised us', ...SURPRISES.map((s) => s.title), 'Steering files', 'Check it yourself',
    ];
    for (const h of headings) {
      expect(MD, `Markdown heading: ${h}`).toMatch(new RegExp(`^#{1,3} ${h.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'm'));
      expect(text, `page heading: ${h}`).toContain(h);
    }
    // Every Markdown heading comes from the page content (nothing only in one of them).
    for (const m of MD.matchAll(/^#{1,3} (.+)$/gm)) expect(headings).toContain(m[1]);
  });

  it('both make the key claims, word for word', () => {
    const text = pageText();
    const claims = [
      'Kiro caches the MCP tool list',
      'PATH=/usr/bin:/bin:/usr/sbin:/sbin',
      '8/8 tasks passed',
      'monthly usage limit',
      'ends its turn when the model narrates',
      'Kiro did not write them',
      'Kiro CLI stopped there',
      'not yet recorded firing inside Kiro',
      'has not yet been repeated inside Kiro',
    ];
    for (const c of claims) {
      expect(MD, c).toContain(c);
      expect(text, c).toContain(c);
    }
    for (const t of allText()) expect(text, t.slice(0, 60)).toContain(plain(t));
    for (const c of CHECK_COMMANDS) expect(text).toContain(c);
  });

  it('KE-35: the page renders every steering file with its mode, patterns and reason', () => {
    const text = pageText();
    for (const r of STEERING_TABLE) {
      expect(text, r.file).toContain(`${r.file}${r.mode}`);
      for (const p of r.patterns) expect(text, `${r.file} ${p}`).toContain(p);
      expect(text, r.file).toContain(r.reason);
    }
  });

  it('every file the page cites exists', () => {
    const cited = [
      ...SURFACES.flatMap((s) => s.files), ...USER_SETUP.files,
      // Paths quoted inside the text, too.
      ...allText().flatMap((t) => [...t.matchAll(/`((?:\.kiro|\.githooks|docs|packages|apps|scripts|power|fixtures)\/[^`\s]*)`/g)].map((m) => m[1] ?? '')),
    ];
    expect(cited.length).toBeGreaterThan(30);
    // Named as places in a user's project, not files in this repository: the local MCP config
    // (S-003: kept out of git) and what `exorcist init` writes.
    const notInRepo = new Set(['.kiro/settings/mcp.json', '.kiro/steering/exorcist.md']);
    for (const f of cited) {
      if (notInRepo.has(f) || f.includes('*')) continue;
      if (f.startsWith('exorcist-98-crew/')) {
        // The Crew app is its own repository; checked when it sits next to this one.
        if (existsSync(CREW)) expect(existsSync(join(CREW, f.slice('exorcist-98-crew/'.length))), f).toBe(true);
        continue;
      }
      expect(existsSync(join(ROOT, f)), f).toBe(true);
    }
  });

  it('every commit the page cites is in the repository', () => {
    let shallow = true;
    try {
      shallow = execFileSync('git', ['rev-parse', '--is-shallow-repository'], { cwd: ROOT, encoding: 'utf8' }).trim() !== 'false';
    } catch { /* no git: nothing to check against */ }
    const ids = allText().flatMap((t) => [...t.matchAll(/`([0-9a-f]{7,12})`/g)].map((m) => ({ id: m[1] ?? '', crew: t.includes('exorcist-98-crew') })));
    expect(ids.length).toBeGreaterThan(10);
    for (const { id, crew } of ids) {
      const repo = crew ? CREW : ROOT;
      if ((crew && !existsSync(CREW)) || (!crew && shallow)) continue;
      expect(() => execFileSync('git', ['cat-file', '-e', `${id}^{commit}`], { cwd: repo, stdio: 'ignore' }), `${crew ? 'Crew ' : ''}commit ${id}`).not.toThrow();
    }
  });

  it('renders text only, from static content (no file reads at run time, no raw HTML)', () => {
    const src = readFileSync(join(ROOT, 'apps/web/src/app/how-kiro/page.tsx'), 'utf8') + readFileSync(join(ROOT, 'apps/web/src/lib/how-kiro.ts'), 'utf8');
    expect(src).not.toContain('dangerouslySetInnerHTML');
    expect(src).not.toMatch(/from 'node:fs'|readFile/);
    const html = renderToStaticMarkup(<HowKiroPage />);
    expect(html.match(/<h1[\s>]/g)?.length).toBe(1);
    // Anchors in the overview point at sections that exist.
    for (const s of SURFACES) {
      expect(html).toContain(`href="#${s.id}"`);
      expect(html).toContain(`id="${s.id}"`);
    }
  });
});
