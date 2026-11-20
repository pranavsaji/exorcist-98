import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { KNOWN_MCP_PACKAGES, editDistance, typosquatOf } from '../known-packages.js';

describe('EX-013 typosquat check', () => {
  it('catches the classic look-alikes', () => {
    expect(typosquatOf('@modelcontextprotocol/server-filesytem@1.0.0')).toBe('@modelcontextprotocol/server-filesystem');
    expect(typosquatOf('@modelcontextprotocoI/server-github')).toBe('@modelcontextprotocol/server-github');
    expect(typosquatOf('@playwrlght/mcp')).toBe('@playwright/mcp');
  });
  it('PBT-TYPO-01: a well-known package, with or without a version, is never flagged', () => {
    fc.assert(fc.property(fc.constantFrom(...KNOWN_MCP_PACKAGES), fc.option(fc.stringMatching(/^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}$/)), (name, v) => {
      expect(typosquatOf(v ? `${name}@${v}` : name)).toBeNull();
    }));
  });
  it('PBT-TYPO-02: one edit to a long well-known name is flagged', () => {
    const long = KNOWN_MCP_PACKAGES.filter((n) => n.length >= 14);
    fc.assert(fc.property(fc.constantFrom(...long), fc.nat(), fc.constantFrom('a', 'e', 'x', 'z'), fc.constantFrom('swap', 'drop', 'add'), (name, n, ch, kind) => {
      const i = 1 + (n % (name.length - 2));
      const changed = kind === 'drop' ? name.slice(0, i) + name.slice(i + 1)
        : kind === 'add' ? name.slice(0, i) + ch + name.slice(i)
        : name.slice(0, i) + (name[i] === ch ? 'q' : ch) + name.slice(i + 1);
      if (KNOWN_MCP_PACKAGES.includes(changed)) return;
      expect(typosquatOf(changed)).not.toBeNull();
    }));
  });
  it('ordinary arguments are not packages that look like anything', () => {
    for (const a of ['-y', '/home/user/projects', '.', 'stdio', '--port', 'my-own-mcp-server@1.0.0']) expect(typosquatOf(a)).toBeNull();
    expect(editDistance('kitten', 'sitting')).toBe(3);
  });
});
