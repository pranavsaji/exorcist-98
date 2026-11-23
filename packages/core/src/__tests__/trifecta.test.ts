import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { loadCapabilityRules } from '../capabilities.js';
import type { CapabilityRule } from '../capabilities.js';
import { loadDefinitions } from '../definitions/loader.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { analyzeConfig, parseMcpConfig, parsePins, stripJsonc, trifectaFinding } from '../trifecta.js';
import { mapRepo, scanRepo } from '../scanner/orchestrator.js';
import type { FileRole, ScanEvent } from '../types.js';
import { fromRoot } from './repo-root.js';

const DEFS = fromRoot('definitions');
let rules: CapabilityRule[] = [];
let defs: VirusDefinition[] = [];
beforeAll(async () => {
  const r = await loadCapabilityRules(DEFS);
  if (!r.ok) throw new Error(r.error);
  rules = r.rules;
  defs = await loadDefinitions(DEFS);
});

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
function repo(files: Record<string, string>): string {
  const d = mkdtempSync(join(tmpdir(), 'exorcist-tri-'));
  dirs.push(d);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(d, rel)), { recursive: true });
    writeFileSync(join(d, rel), text);
  }
  return d;
}

const FS_HOME = { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2025.1.14', '~'] };
const FS_PROJECT = { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2025.1.14', '.'] };
const FETCH = { command: 'uvx', args: ['mcp-server-fetch@2025.4.7'] };
const GITHUB = { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@2025.4.8'] };
const SEARCH = { command: 'npx', args: ['-y', '@modelcontextprotocol/server-brave-search@0.6.2'] };
const PG = { command: 'npx', args: ['-y', '@modelcontextprotocol/server-postgres@0.6.2', 'postgresql://localhost/app'] };

function check(rel: string, role: FileRole, doc: unknown) {
  const text = JSON.stringify(doc, null, 2);
  const cfg = parseMcpConfig(rel, role, text);
  if (!cfg) return { cfg, map: null, finding: null };
  const map = analyzeConfig(cfg, rules);
  return { cfg, map, finding: trifectaFinding(cfg, map, defs) };
}

describe('REQ-02: the lethal trifecta in one config (EX-023)', () => {
  it('private data + untrusted input + a way out is EX-023 (high), once, naming each leg', () => {
    const { map, finding } = check('.kiro/settings/mcp.json', 'mcp-config', { mcpServers: { home: FS_HOME, web: FETCH } });
    expect(map?.trifecta).toBe(true);
    expect(map?.legs).toEqual({ 'private-data': ['home'], 'untrusted-input': ['web'], exfiltration: ['web'] });
    expect(finding).toMatchObject({ ruleId: 'EX-023', severity: 'high', file: '.kiro/settings/mcp.json', line: 2, col: 3, span: '"mcpServers"' });
    expect(finding?.fix).toContain('private data from home; untrusted text from web; a way out through web');
  });

  it('an auto-approved tool on any leg makes it critical (REQ-02.2)', () => {
    const { finding } = check('.kiro/settings/mcp.json', 'mcp-config', { mcpServers: { home: { ...FS_HOME, autoApprove: ['read_file'] }, web: FETCH } });
    expect(finding?.severity).toBe('critical');
    expect(finding?.fix).toContain('Tools on home are auto-approved');
    const trusted = check('.gemini/settings.json', 'mcp-config', { mcpServers: { home: FS_HOME, web: { ...FETCH, trust: true } } });
    expect(trusted.finding?.severity).toBe('critical');
    const cline = check('mcp.json', 'mcp-config', { mcpServers: { home: FS_HOME, web: { ...FETCH, alwaysAllow: ['fetch'] } } });
    expect(cline.finding?.severity).toBe('critical');
  });

  it('no false alarm on ordinary configs: a project-scoped filesystem, GitHub, search and memory', () => {
    const { map, finding } = check('.cursor/mcp.json', 'mcp-config', {
      mcpServers: { files: FS_PROJECT, github: GITHUB, search: SEARCH, memory: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-memory@2025.4.25'] } },
    });
    expect(map?.trifecta).toBe(false);
    expect(map?.legs['private-data']).toEqual([]);
    expect(finding).toBeNull();
  });

  it('two legs are not enough: a database with search but no way out', () => {
    expect(check('.mcp.json', 'mcp-config', { mcpServers: { db: PG, search: SEARCH } }).finding).toBeNull();
  });

  it('a disabled server does not count (Kiro "disabled", VS Code "enabled": false)', () => {
    expect(check('.kiro/settings/mcp.json', 'mcp-config', { mcpServers: { home: FS_HOME, web: { ...FETCH, disabled: true } } }).finding).toBeNull();
    expect(check('.kiro/settings/mcp.json', 'mcp-config', { mcpServers: { home: { ...FS_HOME, enabled: false }, web: FETCH } }).finding).toBeNull();
  });

  it('reads VS Code "servers" with comments and trailing commas, and remote URL servers', () => {
    const text = `{
  // My servers
  "servers": {
    "db": { "type": "stdio", "command": "npx", "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2", "postgresql://localhost/app"] },
    /* remote */
    "linear": { "type": "http", "url": "https://mcp.linear.app/sse", },
  },
}`;
    const cfg = parseMcpConfig('.vscode/mcp.json', 'mcp-config', text);
    expect(cfg?.entries.map((e) => e.name)).toEqual(['db', 'linear']);
    const map = cfg ? analyzeConfig(cfg, rules) : null;
    expect(map?.trifecta).toBe(true);
    expect(cfg?.anchor).toMatchObject({ line: 3, span: '"servers"' });
  });

  it('a generic JSON file counts only with an mcpServers object holding a server; "servers" alone is not enough', () => {
    expect(parseMcpConfig('config/app.json', 'config', JSON.stringify({ servers: { a: FETCH } }))).toBeNull();
    expect(parseMcpConfig('config/app.json', 'config', JSON.stringify({ mcpServers: {} }))).toBeNull();
    expect(parseMcpConfig('config/app.json', 'config', JSON.stringify({ mcpServers: { a: FETCH } }))?.entries).toHaveLength(1);
    expect(parseMcpConfig('README.md', 'docs', JSON.stringify({ mcpServers: { a: FETCH } }))).toBeNull();
    expect(parseMcpConfig('.cursor/mcp.json', 'mcp-config', 'not json')).toBeNull();
  });

  it('Claude Code permissions.allow: built-in abilities are ghosts, mcp__server__tool auto-approves that server', () => {
    const { cfg, map, finding } = check('.claude/settings.json', 'mcp-config', { permissions: { allow: ['WebFetch', 'Bash', 'Bash(npm test:*)'] } });
    expect(cfg?.entries.map((e) => `${e.kind}:${e.name}`)).toEqual(['ability:WebFetch', 'ability:Bash', 'ability:Bash(npm test:*)']);
    expect(map?.trifecta).toBe(true);
    expect(finding?.severity).toBe('critical');
    expect(finding?.span).toBe('"allow"');

    const safe = check('.claude/settings.json', 'mcp-config', { permissions: { allow: ['WebFetch(domain:docs.example.invalid)', 'Bash(npm run lint)', 'Read(./src/**)'] } });
    expect(safe.finding).toBeNull();

    const mcp = check('.mcp.json', 'mcp-config', { mcpServers: { home: FS_HOME, web: FETCH }, permissions: { allow: ['mcp__web__fetch'] } });
    expect(mcp.cfg?.entries.find((e) => e.name === 'web')?.autoApprove).toEqual(['fetch']);
    expect(mcp.finding?.severity).toBe('critical');
  });

  it('a disabled EX-023 definition reports nothing but the map still has the trifecta', () => {
    const { cfg, map } = check('mcp.json', 'mcp-config', { mcpServers: { home: FS_HOME, web: FETCH } });
    if (!cfg || !map) throw new Error('no config');
    expect(trifectaFinding(cfg, map, defs.map((d) => (d.id === 'EX-023' ? { ...d, enabled: false } : d)))).toBeNull();
    expect(map.trifecta).toBe(true);
  });

  it('uses the Shield pin file: tools of an unknown server can put it on a leg', () => {
    const cfg = parseMcpConfig('.kiro/settings/mcp.json', 'mcp-config', JSON.stringify({ mcpServers: { home: FS_HOME, web: FETCH, mailer: { command: 'node', args: ['mailer.js'] } } }));
    if (!cfg) throw new Error('no config');
    const pins = parsePins({ version: 1, servers: { mailer: { tools: { send_email: { hash: 'x', description: 'Send an email', pinnedAt: 'now' } } } } });
    const ghost = analyzeConfig(cfg, rules, pins).ghosts.find((g) => g.name === 'mailer');
    expect(ghost?.capabilities).toEqual(['exfiltration']);
    expect(ghost?.reasons[0]?.evidence).toBe('tool send_email');
    expect(parsePins({ nonsense: true }).size).toBe(0);
    expect(parsePins('not an object').size).toBe(0);
  });

  it('stripJsonc keeps // inside strings', () => {
    expect(JSON.parse(stripJsonc('{"u": "https://x.example.invalid/a", // c\n "b": [1,],}'))).toEqual({ u: 'https://x.example.invalid/a', b: [1] });
  });
});

describe('REQ-02 in a scan: EX-023 and the map event', () => {
  it('scanRepo reports EX-023 once per config and sends one map event just before done', async () => {
    const root = repo({
      '.kiro/settings/mcp.json': JSON.stringify({ mcpServers: { home: FS_HOME, web: FETCH } }, null, 2),
      '.cursor/mcp.json': JSON.stringify({ mcpServers: { files: FS_PROJECT, github: GITHUB } }, null, 2),
      'README.md': '# Hello\n',
    });
    const events: ScanEvent[] = [];
    for await (const ev of scanRepo(root, { definitionsDir: DEFS })) events.push(ev);
    const tri = events.filter((e) => e.type === 'finding' && e.finding.ruleId === 'EX-023');
    expect(tri).toHaveLength(1);
    const types = events.map((e) => e.type);
    expect(types.filter((t) => t === 'map')).toHaveLength(1);
    expect(types.indexOf('map')).toBe(types.length - 2);
    const map = events.find((e) => e.type === 'map');
    if (map?.type !== 'map') throw new Error('no map');
    expect(map.map.configs.map((c) => [c.file, c.trifecta])).toEqual([['.cursor/mcp.json', false], ['.kiro/settings/mcp.json', true]]);
    const done = events[events.length - 1];
    if (done?.type !== 'done') throw new Error('no done');
    expect(done.stats.findingsTotal).toBe(events.filter((e) => e.type === 'finding').length);
  });

  it('no MCP config, no map event', async () => {
    const root = repo({ 'README.md': '# Hello\n' });
    const types: string[] = [];
    for await (const ev of scanRepo(root, { definitionsDir: DEFS })) types.push(ev.type);
    expect(types).not.toContain('map');
  });

  it('reads the pin file at .exorcist/pins.json', async () => {
    const root = repo({
      '.kiro/settings/mcp.json': JSON.stringify({ mcpServers: { home: FS_HOME, reader: { command: 'node', args: ['r.js'] } } }),
      '.exorcist/pins.json': JSON.stringify({ version: 1, servers: { reader: { tools: { fetch_url: { hash: 'a'.repeat(64), description: 'Fetch a URL', pinnedAt: 'now' } } } } }),
    });
    const r = await mapRepo(root, { definitionsDir: DEFS });
    if (!r.ok) throw new Error(r.error);
    expect(r.findings.map((f) => f.ruleId)).toEqual(['EX-023']);
  });

  it('mapRepo without capability rules is a typed error, not a throw', async () => {
    const empty = repo({ 'EX-001.yaml': '' });
    const r = await mapRepo(empty, { definitionsDir: empty });
    expect(r.ok).toBe(false);
  });

  it('the Haunted Repo EX-023 sample is a critical trifecta with three rooms filled', async () => {
    const r = await mapRepo(fromRoot('fixtures/haunted-repo'), { definitionsDir: DEFS });
    if (!r.ok) throw new Error(r.error);
    const m = r.map.configs.find((c) => c.file === 'EX-023-lethal-trifecta.json');
    expect(m?.trifecta).toBe(true);
    expect(m?.severity).toBe('critical');
    expect(m?.legs).toEqual({ 'private-data': ['home-files'], 'untrusted-input': ['team-chat', 'web-reader'], exfiltration: ['team-chat', 'web-reader'] });
    expect(m?.ghosts.find((g) => g.name === 'scratchpad')?.capabilities).toEqual([]);
    // The other planted MCP configs do not form a trifecta.
    expect(r.findings.map((f) => f.file)).toEqual(['EX-023-lethal-trifecta.json']);
  });
});
