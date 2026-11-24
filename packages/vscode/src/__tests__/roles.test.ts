import { describe, expect, it } from 'vitest';
import { agentRelativePath, compileGlobs, decideScan, globToRegExp } from '../roles.js';

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

describe('globToRegExp', () => {
  it('handles **, *, ?, braces and classes', () => {
    expect(globToRegExp('**/*.md').test('a/b/c.md')).toBe(true);
    expect(globToRegExp('**/*.md').test('c.md')).toBe(true);
    expect(globToRegExp('docs/*.md').test('docs/a.md')).toBe(true);
    expect(globToRegExp('docs/*.md').test('docs/x/a.md')).toBe(false);
    expect(globToRegExp('docs/*.md').test('other/docs/a.md')).toBe(false);
    expect(globToRegExp('a?.txt').test('x/ab.txt')).toBe(true);
    expect(globToRegExp('**/*.{md,mdc}').test('r/x.mdc')).toBe(true);
    expect(globToRegExp('**/*.{md,mdc}').test('r/x.mdx')).toBe(false);
    expect(globToRegExp('v[0-9].md').test('v1.md')).toBe(true);
    expect(globToRegExp('./notes/**').test('notes/a/b')).toBe(true);
  });

  it('treats regex characters literally', () => {
    expect(globToRegExp('a+b(c).md').test('a+b(c).md')).toBe(true);
    expect(globToRegExp('a.md').test('aXmd')).toBe(false);
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
