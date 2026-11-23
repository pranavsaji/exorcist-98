import { describe, it, expect, beforeAll } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  classifyCapabilities, exampleServer, isOutsideProject, loadCapabilityRules, parseCapabilityRules,
  pathArguments, ruleEvidence, serverIdentities, stripVersion, unwrapLaunch,
} from '../capabilities.js';
import type { CapabilityRule } from '../capabilities.js';
import { loadDefinitions } from '../definitions/loader.js';
import { fromRoot } from './repo-root.js';

const DEFS = fromRoot('definitions');
let rules: CapabilityRule[] = [];
beforeAll(async () => {
  const r = await loadCapabilityRules(DEFS);
  if (!r.ok) throw new Error(r.error);
  rules = r.rules;
});

describe('REQ-01.2: capability rules are data, and every rule has a working example', () => {
  it('definitions/capabilities.yaml loads and covers all three legs', () => {
    expect(rules.length).toBeGreaterThanOrEqual(15);
    for (const c of ['private-data', 'untrusted-input', 'exfiltration']) expect(rules.some((r) => r.capability === c), c).toBe(true);
  });

  it('every rule has at least one example it matches', () => {
    for (const r of rules) expect(r.examples.some((e) => e.expect), r.id).toBe(true);
  });

  it('every example gives the result it states (expect: true matches, expect: false does not)', () => {
    const wrong: string[] = [];
    for (const r of rules) {
      for (const e of r.examples) {
        const got = ruleEvidence(r, exampleServer(e)) !== null;
        if (got !== e.expect) wrong.push(`${r.id}: ${JSON.stringify(e)} gave ${got}`);
      }
    }
    expect(wrong).toEqual([]);
  });

  it('the virus definition loader skips capabilities.yaml', async () => {
    const defs = await loadDefinitions(DEFS);
    expect(defs.some((d) => d.id === 'EX-023' && d.match.analysis === 'trifecta')).toBe(true);
  });

  it('rejects a rule without examples, a rule whose examples all say false, a bad regex and duplicate ids', () => {
    const base = { id: 'CAP-900', capability: 'exfiltration', label: 'x', match: { tool: '^send$' } };
    expect(parseCapabilityRules({ version: 1, rules: [{ ...base, examples: [] }] }).ok).toBe(false);
    expect(parseCapabilityRules({ version: 1, rules: [{ ...base, examples: [{ ability: 'x', expect: false }] }] }).ok).toBe(false);
    expect(parseCapabilityRules({ version: 1, rules: [{ ...base, match: { tool: '(' }, examples: [{ expect: true }] }] }).ok).toBe(false);
    const ok = { ...base, examples: [{ tools: [{ name: 'send' }], expect: true }] };
    expect(parseCapabilityRules({ version: 1, rules: [ok] }).ok).toBe(true);
    expect(parseCapabilityRules({ version: 1, rules: [ok, ok] }).ok).toBe(false);
    expect(parseCapabilityRules({ version: 2, rules: [ok] }).ok).toBe(false);
  });

  it('a missing file is reported as missing; invalid YAML as an error, never thrown', async () => {
    const d = mkdtempSync(join(tmpdir(), 'exorcist-cap-'));
    const missing = await loadCapabilityRules(d);
    expect(missing).toMatchObject({ ok: false, missing: true });
    writeFileSync(join(d, 'capabilities.yaml'), 'version: [1');
    expect(await loadCapabilityRules(d)).toMatchObject({ ok: false, missing: false });
  });
});

describe('REQ-01.1: server names', () => {
  it('strips npm, python and docker versions', () => {
    expect(stripVersion('@scope/pkg@1.2.3')).toBe('@scope/pkg');
    expect(stripVersion('pkg@latest')).toBe('pkg');
    expect(stripVersion('mcp-server-fetch==2025.4.7')).toBe('mcp-server-fetch');
    expect(stripVersion('npm:@x/y@2')).toBe('@x/y');
  });

  it('finds the package behind npx, uvx --from, pnpm dlx, docker run, python -m and a remote URL', () => {
    expect(serverIdentities({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@1.0.0'] })).toEqual(['@modelcontextprotocol/server-github']);
    expect(serverIdentities({ command: 'uvx', args: ['--from', 'mcp-server-fetch==1', 'mcp-server-fetch'] })).toContain('mcp-server-fetch');
    expect(serverIdentities({ command: 'pnpm', args: ['dlx', 'firecrawl-mcp'] })).toEqual(['firecrawl-mcp']);
    expect(serverIdentities({ command: 'docker', args: ['run', '-i', '--rm', '-e', 'TOKEN', '-v', '/a:/b', 'ghcr.io/github/github-mcp-server:v1'] }))
      .toEqual(['ghcr.io/github/github-mcp-server']);
    expect(serverIdentities({ command: 'python3', args: ['-m', 'mcp_server_git'] })).toEqual(['mcp_server_git']);
    expect(serverIdentities({ url: 'https://mcp.notion.com/mcp' })).toEqual(['mcp.notion.com/mcp']);
    expect(serverIdentities({ command: '/usr/local/bin/github-mcp-server', args: ['stdio'] })).toEqual(['github-mcp-server']);
  });

  it('looks through a Shield wrapper and a shell wrapper', () => {
    const wrapped = { command: 'exorcist', args: ['shield', '--server', 'gh', '--dir', '.exorcist', '--', 'npx', '-y', '@modelcontextprotocol/server-github'] };
    expect(serverIdentities(wrapped)).toEqual(['@modelcontextprotocol/server-github']);
    expect(unwrapLaunch('npx', ['-y', '@exorcist-98/cli', 'shield', '--server', 'r', '--url', 'https://mcp.linear.app/sse']).url).toBe('https://mcp.linear.app/sse');
    expect(serverIdentities({ command: 'bash', args: ['-c', 'npx -y mcp-server-fetch'] })).toEqual(['mcp-server-fetch']);
    // The shell itself is not a shell MCP server.
    expect(classifyCapabilities({ command: 'bash', args: ['-c', 'npx -y @modelcontextprotocol/server-memory'] }, rules).capabilities).toEqual([]);
  });
});

describe('REQ-01.1: paths outside the project (no false alarms on project-scoped servers)', () => {
  it.each([
    ['/', true], ['/**', true], ['~', true], ['~/**', true], ['~/', true], ['$HOME', true], ['%USERPROFILE%', true], ['C:\\', true], ['C:\\Users\\alice', true],
    ['/Users/alice', true], ['/home/bob', true], ['/home/bob/Documents', true], ['~/Downloads', true], ['~/.ssh', true],
    ['/home/bob/code/app/.aws', true], ['/etc', true], ['/var/lib/x', true], ['../..', true], ['../sibling', true],
    ['.', false], ['./src', false], ['src/../docs', false], ['${workspaceFolder}', false], ['${workspaceFolder}/data', false],
    ['/home/user/projects', false], ['/Users/alice/code/app', false], ['C:\\Projects\\app', false], ['~/code/app', false],
  ])('%s -> %s', (p, want) => {
    expect(isOutsideProject(p)).toBe(want);
  });

  it('takes path arguments, --flag=path values and docker mount sources, not the package or URLs', () => {
    expect(pathArguments({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '.', '--root=/'] })).toEqual(['.', '/']);
    expect(pathArguments({ command: 'docker', args: ['run', '--mount', 'type=bind,src=/Users/a,dst=/projects', 'mcp/filesystem', '/projects'] }))
      .toEqual(['/Users/a', '/projects']);
    expect(pathArguments({ command: 'npx', args: ['@modelcontextprotocol/server-postgres', 'postgresql://localhost/db'] })).toEqual([]);
  });

  it('a filesystem server limited to the project is not private data; one rooted at home is', () => {
    const fs = (dir: string) => classifyCapabilities({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2025.1.14', dir] }, rules).capabilities;
    expect(fs('.')).toEqual([]);
    expect(fs('${workspaceFolder}')).toEqual([]);
    expect(fs('/home/user/projects')).toEqual([]);
    expect(fs('~')).toEqual(['private-data']);
    expect(fs('/')).toEqual(['private-data']);
  });
});

describe('REQ-01.1: classification', () => {
  const caps = (s: Parameters<typeof classifyCapabilities>[0]) => classifyCapabilities(s, rules).capabilities;

  it('ordinary servers have no risky capability', () => {
    for (const pkg of ['@modelcontextprotocol/server-memory', '@modelcontextprotocol/server-sequential-thinking', '@upstash/context7-mcp', 'mcp-server-git', '@modelcontextprotocol/server-everything', 'mcp-server-time']) {
      expect(caps({ command: 'npx', args: ['-y', pkg] }), pkg).toEqual([]);
    }
  });

  it('labels the well-known servers on the right legs', () => {
    expect(caps({ command: 'uvx', args: ['mcp-server-fetch'] })).toEqual(['untrusted-input', 'exfiltration']);
    expect(caps({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'] })).toEqual(['untrusted-input', 'exfiltration']);
    expect(caps({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-brave-search'] })).toEqual(['untrusted-input']);
    expect(caps({ command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres', 'postgresql://localhost/app'] })).toEqual(['private-data']);
    // An email server alone covers all three legs.
    expect(caps({ command: 'npx', args: ['@gongrzhe/server-gmail-autoauth-mcp'] })).toEqual(['private-data', 'untrusted-input', 'exfiltration']);
  });

  it('uses tool names and descriptions from the pin file when the package says nothing', () => {
    expect(caps({ command: 'node', args: ['dist/server.js'] })).toEqual([]);
    expect(caps({ command: 'node', args: ['dist/server.js'], tools: [{ name: 'send_email' }] })).toEqual(['exfiltration']);
    expect(caps({ command: 'node', args: ['dist/server.js'], tools: [{ name: 'get', description: 'Fetches the contents of a URL.' }] })).toEqual(['untrusted-input']);
    expect(caps({ command: 'node', args: ['dist/server.js'], tools: [{ name: 'read_file', description: 'Read a file in the project.' }] })).toEqual([]);
  });

  it('built-in abilities: WebFetch, an unrestricted shell, reads outside the project', () => {
    expect(caps({ ability: 'WebFetch' })).toEqual(['untrusted-input', 'exfiltration']);
    expect(caps({ ability: 'WebSearch' })).toEqual(['untrusted-input']);
    expect(caps({ ability: 'Bash' })).toEqual(['private-data', 'exfiltration']);
    expect(caps({ ability: 'Bash(npm run test:*)' })).toEqual([]);
    expect(caps({ ability: 'Read(~/**)' })).toEqual(['private-data']);
    expect(caps({ ability: 'Read(./src/**)' })).toEqual([]);
    expect(caps({ ability: 'Edit' })).toEqual([]);
  });

  it('every reason names the rule, a plain label and what matched', () => {
    const r = classifyCapabilities({ command: 'uvx', args: ['mcp-server-fetch'] }, rules).reasons;
    expect(r.map((x) => x.ruleId)).toEqual(['CAP-010', 'CAP-020']);
    expect(r[0]).toMatchObject({ capability: 'untrusted-input', label: 'reads web pages', evidence: 'mcp-server-fetch' });
  });
});
