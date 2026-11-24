import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { MAX_GLOB_LENGTH, agentRelativePath, compileGlobs, decideScan, compileGlob } from '../roles.js';

const scans = (rel: string, extra: string[] = [], text?: string): boolean | 'needs-content' =>
  decideScan(rel, compileGlobs(extra).patterns, text).scan;

describe('decideScan: the files agents obey', () => {
  it.each([
    '.kiro/steering/product.md',
    '.kiro/specs/m1-engine/requirements.md',
    '.kiro/hooks/pre-commit.kiro.hook',
    '.kiro/settings/mcp.json',
    'AGENTS.md',
    'CLAUDE.md',
    'packages/app/CLAUDE.md',
    '.cursorrules',
    '.cursor/rules/style.mdc',
    '.cursor/mcp.json',
    '.cursor/notes/todo.txt',
    '.github/copilot-instructions.md',
    '.vscode/mcp.json',
    '.mcp.json',
    'README.md',
    'docs/README.md',
    'CONTRIBUTING.md',
    'packages/x/CONTRIBUTING.md',
    'MEMORY.md',
    'power/POWER.md',
    'package.json',
  ])('scans %s', (rel) => {
    expect(scans(rel)).toBe(true);
  });

  it.each([
    'src/index.ts',
    'docs/guide.md',
    'tsconfig.json',
    'notes.txt',
    'definitions/EX-001-hidden-unicode.yaml',
    'image.png',
  ])('does not scan %s', (rel) => {
    expect(scans(rel)).toBe(false);
  });

  it('uses the core classifier for the role', () => {
    expect(decideScan('.kiro/steering/a.md').role).toBe('instruction');
    expect(decideScan('.kiro/settings/mcp.json').role).toBe('mcp-config');
    expect(decideScan('.kiro/hooks/a.json').role).toBe('hook');
    expect(decideScan('.kiro/specs/a/design.md')).toEqual({ scan: true, role: 'docs', reason: 'builtin' });
  });

  it('scans a generic JSON config only when the core reads it as an MCP config', () => {
    const mcp = JSON.stringify({ mcpServers: { fs: { command: 'npx', args: ['-y', 'some-server@1.0.0'] } } });
    expect(decideScan('config/servers.json', [], mcp)).toEqual({ scan: true, role: 'config', reason: 'mcp-content' });
    expect(scans('config/servers.json', [], '{"name":"x"}')).toBe(false);
    // Without the text (workspace scan before reading), only a name mentioning MCP is a candidate.
    expect(scans('config/my-mcp.json')).toBe('needs-content');
    expect(scans('config/servers.json')).toBe(false);
  });

  it('adds the user\'s extra globs', () => {
    expect(scans('docs/guide.md', ['docs/**'])).toBe(true);
    expect(scans('docs/a/b/guide.md', ['docs/**/*.md'])).toBe(true);
    expect(scans('prompts/review.prompt.md', ['*.prompt.md'])).toBe(true);
    expect(scans('src/index.ts', ['docs/**'])).toBe(false);
  });

  it('never scans virus definitions, even through an extra glob (they quote attacks on purpose)', () => {
    expect(scans('definitions/EX-002-ai-instructions.yaml', ['**/*.yaml'])).toBe(false);
  });
});

describe('compileGlob', () => {
  it('handles **, *, ?, braces and classes', () => {
    expect(compileGlob('**/*.md').test('a/b/c.md')).toBe(true);
    expect(compileGlob('**/*.md').test('c.md')).toBe(true);
    expect(compileGlob('docs/*.md').test('docs/a.md')).toBe(true);
    expect(compileGlob('docs/*.md').test('docs/x/a.md')).toBe(false);
    expect(compileGlob('docs/*.md').test('other/docs/a.md')).toBe(false);
    expect(compileGlob('a?.txt').test('x/ab.txt')).toBe(true);
    expect(compileGlob('**/*.{md,mdc}').test('r/x.mdc')).toBe(true);
    expect(compileGlob('**/*.{md,mdc}').test('r/x.mdx')).toBe(false);
    expect(compileGlob('v[0-9].md').test('v1.md')).toBe(true);
    expect(compileGlob('./notes/**').test('notes/a/b')).toBe(true);
  });

  it('treats regex characters literally', () => {
    expect(compileGlob('a+b(c).md').test('a+b(c).md')).toBe(true);
    expect(compileGlob('a.md').test('aXmd')).toBe(false);
  });

  it('negated classes, collapsed stars and repeated globstars', () => {
    expect(compileGlob('v[!0-9].md').test('va.md')).toBe(true);
    expect(compileGlob('v[!0-9].md').test('v1.md')).toBe(false);
    expect(compileGlob('docs/***.md').test('docs/a.md')).toBe(true);
    expect(compileGlob('**/**/**/x.md').test('x.md')).toBe(true);
    expect(compileGlob('**/**/**/x.md').test('a/b/x.md')).toBe(true);
  });

  it('is linear: hostile globs from workspace settings cannot hang the editor', () => {
    const path = `${'a'.repeat(250)}/${'a'.repeat(250)}`;
    const hostile = ['*a*a*a*a*a*a*a*a*a*a*a*a*b', '**/**a**a**a**a**a**a**a**b', `${'?*'.repeat(40)}b`, '{*a*a*a*b,*a*a*a*c}'];
    const t0 = performance.now();
    for (const g of hostile) expect(compileGlob(g).test(path)).toBe(false);
    expect(performance.now() - t0).toBeLessThan(250);
  });

  it('refuses globs that are too long, nested or explode into too many alternatives', () => {
    expect(() => compileGlob('a'.repeat(MAX_GLOB_LENGTH + 1))).toThrow();
    expect(() => compileGlob('{a,{b,c}}')).toThrow();
    expect(() => compileGlob('{a,b,c,d}{a,b,c,d}{a,b,c,d}{a,b}')).toThrow();
    expect(compileGlobs(['{a,{b,c}}', 'ok.md']).invalid).toEqual(['{a,{b,c}}']);
  });

  it('agrees with a reference regular expression on random globs and paths', () => {
    // The reference is the textbook translation; safe here because inputs are tiny.
    const ref = (g: string): RegExp => {
      let x = g;
      if (!x.includes('/')) x = `**/${x}`;
      let re = '';
      for (let i = 0; i < x.length; i++) {
        const c = x[i]!;
        if (c === '*') {
          let j = i; while (x[j + 1] === '*') j++;
          if (j > i && x[j + 1] === '/') { re += '(?:.*/)?'; i = j + 1; } else if (j > i) { re += '.*'; i = j; } else { re += '[^/]*'; }
        } else if (c === '?') re += '[^/]';
        else re += c.replace(/[.+^$()|\\[\]{}]/g, '\\$&');
      }
      return new RegExp(`^${re}$`);
    };
    const glob = fc.stringOf(fc.constantFrom('a', 'b', '/', '*', '?', '.'), { minLength: 1, maxLength: 8 })
      .filter((g) => !g.startsWith('./') && !g.startsWith('/'));
    const path = fc.stringOf(fc.constantFrom('a', 'b', '/', '.'), { maxLength: 8 });
    fc.assert(fc.property(glob, path, (g, p) => compileGlob(g).test(p) === ref(g).test(p)), { numRuns: 3000 });
  });

  it('compileGlobs drops empty entries', () => {
    expect(compileGlobs(['', '  ', 'docs/**']).patterns).toHaveLength(1);
  });
});

describe('agentRelativePath (files outside every workspace folder)', () => {
  it('starts at the last agent folder', () => {
    expect(agentRelativePath('/Users/me/.kiro/settings/mcp.json')).toBe('.kiro/settings/mcp.json');
    expect(agentRelativePath('/home/me/proj/.cursor/rules/a.mdc')).toBe('.cursor/rules/a.mdc');
    expect(agentRelativePath('C:\\Users\\me\\.kiro\\steering\\x.md')).toBe('.kiro/steering/x.md');
  });
  it('falls back to the file name', () => {
    expect(agentRelativePath('/tmp/AGENTS.md')).toBe('AGENTS.md');
    expect(decideScan(agentRelativePath('/Users/me/.kiro/settings/mcp.json')).role).toBe('mcp-config');
  });
});
