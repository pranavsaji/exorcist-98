/** m13-kiro-evidence tasks 10.6 and 11.2, and the m10-kiro-gate criteria that are about records and docs. */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../../..');
const read = (p: string): string => readFileSync(join(ROOT, p), 'utf8');

describe('.kiro/hooks/spec-trace.json', () => {
  const hook = (JSON.parse(read('.kiro/hooks/spec-trace.json')) as {
    version: string;
    hooks: Array<{ name: string; trigger: string; matcher: string; timeout?: number; action: { type: string; command: string } }>;
  }).hooks[0]!;

  it('KE-25 is a PostFileSave command hook through scripts/kiro-hook.sh, in warning-only mode', () => {
    expect(hook.trigger).toBe('PostFileSave');
    expect(hook.action.type).toBe('command');
    expect(hook.action.command.startsWith('sh scripts/kiro-hook.sh ')).toBe(true);
    expect(hook.action.command).not.toMatch(/(^|\s)(pnpm|npx|node)(\s|$)/);
    expect(hook.action.command).toContain('scripts/spec-trace.mjs');
    expect(hook.action.command).toMatch(/--warn$/);
  });

  it('KE-25 its matcher selects spec files and test files and nothing else', () => {
    const re = new RegExp(hook.matcher);
    for (const f of ['.kiro/specs/m10-kiro-gate/requirements.md', '/w/.kiro/specs/x/tasks.md', 'packages/core/src/__tests__/a.test.ts', 'apps/web/src/__tests__/b.test.tsx']) {
      expect(re.test(f), f).toBe(true);
    }
    for (const f of ['packages/core/src/spec-trace.ts', 'docs/THREATS.md', '.kiro/hooks/spec-trace.json']) expect(re.test(f), f).toBe(false);
  });

  it('KE-25 never fails the save: --warn exits 0 even when a spec has gaps', () => {
    const root = mkdtempSync(join(tmpdir(), 'trace-'));
    try {
      mkdirSync(join(root, '.kiro/specs/x'), { recursive: true });
      writeFileSync(join(root, '.kiro/specs/x/requirements.md'), '1. ZZ-1 THE thing SHALL work.\n');
      const strict = spawnSync('node_modules/.bin/tsx', ['scripts/spec-trace.mjs', '--root', root], { cwd: ROOT, encoding: 'utf8' });
      expect(strict.status).toBe(1);
      const warn = spawnSync('node_modules/.bin/tsx', ['scripts/spec-trace.mjs', '--warn', '--root', root], { cwd: ROOT, encoding: 'utf8' });
      expect(warn.stdout).toContain('no test starts with: ZZ-1');
      expect(warn.status).toBe(0);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 60_000);

  it('KE-22 KE-23 a spec that only mentions EX-001 rule lines is not traced and exits 0', () => {
    const root = mkdtempSync(join(tmpdir(), 'trace-'));
    try {
      mkdirSync(join(root, '.kiro/specs/old'), { recursive: true });
      writeFileSync(join(root, '.kiro/specs/old/requirements.md'), 'EX-001 hidden unicode\n- EX-002 rule\n1. EX-003 THE scanner SHALL x.\n');
      const r = spawnSync('node_modules/.bin/tsx', ['scripts/spec-trace.mjs', '--root', root], { cwd: ROOT, encoding: 'utf8' });
      expect(r.stdout).not.toContain('old');
      expect(r.status).toBe(0);
    } finally { rmSync(root, { recursive: true, force: true }); }
  }, 60_000);
});

describe('m10-kiro-gate records and docs', () => {
  it('KG-26 spec-trace finds zero gaps for m10-kiro-gate, so every requirement maps to a test', () => {
    const r = spawnSync('node_modules/.bin/tsx', ['scripts/spec-trace.mjs', '--spec', 'm10-kiro-gate'], { cwd: ROOT, encoding: 'utf8' });
    expect(r.stdout).toContain('m10-kiro-gate: ok (27 requirement IDs');
    expect(r.status).toBe(0);
  }, 60_000);

  it('KE-26 every acceptance criterion of m10-kiro-gate carries an ID, KG-1 to KG-27, in order', () => {
    const ids = [...read('.kiro/specs/m10-kiro-gate/requirements.md').matchAll(/^\d+\. (KG-\d+) /gm)].map((m) => m[1]);
    expect(ids).toEqual(Array.from({ length: 27 }, (_, i) => `KG-${i + 1}`));
  });

  it('KG-24 the documentation says how to start each agent in Kiro IDE and in Kiro CLI', () => {
    const doc = read('docs/HOW_KIRO.md');
    expect(doc).toContain('agent picker');
    expect(doc).toContain('kiro-cli chat --agent exorcist-reviewer');
    expect(doc).toContain('exorcist-red-team');
  });

  it('KG-27 the root package defines the typecheck and test commands the criterion names (CI runs them; this checks they exist)', () => {
    const scripts = (JSON.parse(read('package.json')) as { scripts: Record<string, string> }).scripts;
    expect(scripts.typecheck).toBe('pnpm -r typecheck');
    expect(scripts.test).toBe('vitest run');
  });
});
