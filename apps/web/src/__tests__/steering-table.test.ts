/** m13-kiro-evidence: the steering table in lib/how-kiro.ts matches .kiro/steering/ (task 15.5). */
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareSteeringTable } from '@exorcist-98/core';
import { STEERING_TABLE, howKiroMarkdown } from '@/lib/how-kiro';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const DIR = join(ROOT, '.kiro/steering');
const files = readdirSync(DIR).filter((f) => f.endsWith('.md'));

function frontMatter(file: string): { inclusion?: string; patterns: string[] } {
  const m = /^---\n([\s\S]*?)\n---/.exec(readFileSync(join(DIR, file), 'utf8'));
  const body = m?.[1] ?? '';
  const inclusion = /^inclusion:\s*(\S+)/m.exec(body)?.[1];
  const raw = /^fileMatchPattern:\s*(.+)$/m.exec(body)?.[1]?.trim();
  let patterns: string[] = [];
  if (raw) patterns = raw.startsWith('[') ? (JSON.parse(raw) as string[]) : [raw.replace(/^"|"$/g, '')];
  return { inclusion, patterns };
}

describe('steering table', () => {
  it('KE-35: has one row per file under .kiro/steering/, each with a reason', () => {
    for (const r of STEERING_TABLE) expect(r.reason.length, r.file).toBeGreaterThan(10);
  });

  it('KE-36: the table lists exactly the files in the directory', () => {
    const d = compareSteeringTable(files, STEERING_TABLE.map((r) => r.file));
    expect(d).toEqual({ missing: [], extra: [], duplicated: [], complete: true });
  });

  it('KE-35: each row\'s mode and patterns equal the file\'s front matter', () => {
    for (const r of STEERING_TABLE) {
      const fm = frontMatter(r.file);
      expect(fm.inclusion, r.file).toBe(r.mode);
      expect(fm.patterns, r.file).toEqual(r.patterns);
    }
  });

  it('KE-35: the generated Markdown lists every steering file', () => {
    const md = howKiroMarkdown();
    for (const r of STEERING_TABLE) expect(md).toContain(`| \`${r.file}\` | ${r.mode} |`);
  });
});
