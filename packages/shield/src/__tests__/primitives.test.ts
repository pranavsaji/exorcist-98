import { describe, it, expect, afterEach } from 'vitest';
import * as fc from 'fast-check';
import { mkdtempSync, rmSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { canonicalJson, toolFingerprint } from '../hash.js';
import { LineSplitter } from '../jsonrpc.js';
import { hostAllowed, loadPolicy } from '../policy.js';
import { approveHost, approveTool, emptyState, loadState, saveState, serverState, StateSchema } from '../state.js';
import type { State } from '../state.js';
import { isWrapped, unwrapConfig, wrapConfig } from '../wrap.js';
import type { McpConfig } from '../wrap.js';

const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const tmp = (): string => { const d = mkdtempSync(join(tmpdir(), 'exorcist-shield-')); dirs.push(d); return d; };

// ── fingerprint ────────────────────────────────────────────────────────────────

const safeKey = fc.string({ maxLength: 8 }).filter((k) => k !== '__proto__');
const schemaArb = fc.dictionary(safeKey, fc.jsonValue(), { maxKeys: 5 });

/** Same data with every object's keys in the opposite order. */
function reverseKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(reverseKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v as object).reverse().map(([k, x]) => [k, reverseKeys(x)]));
  return v;
}

describe('toolFingerprint', () => {
  it('is a 64-character hex SHA-256', () => {
    expect(toolFingerprint({ name: 'a' })).toMatch(/^[0-9a-f]{64}$/);
  });

  it('treats a missing description and schema as empty', () => {
    expect(toolFingerprint({ name: 'a' })).toBe(toolFingerprint({ name: 'a', description: '', inputSchema: {} }));
  });

  it('PBT-SHD-01: ignores key order', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), schemaArb, (name, description, inputSchema) => {
        expect(toolFingerprint({ name, description, inputSchema })).toBe(
          toolFingerprint({ name, description, inputSchema: reverseKeys(inputSchema) }),
        );
        return true;
      }),
    );
  });

  it('PBT-SHD-01: changes whenever the name, description or schema changes', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), schemaArb, fc.string({ minLength: 1 }), (name, description, inputSchema, extra) => {
        const base = toolFingerprint({ name, description, inputSchema });
        expect(toolFingerprint({ name: name + extra, description, inputSchema })).not.toBe(base);
        expect(toolFingerprint({ name, description: description + extra, inputSchema })).not.toBe(base);
        expect(toolFingerprint({ name, description, inputSchema: { ...inputSchema, [`added_${extra}`]: 1 } })).not.toBe(base);
        return true;
      }),
    );
  });

  it('canonicalJson sorts keys and keeps array order', () => {
    expect(canonicalJson({ b: 1, a: [2, 1] })).toBe('{"a":[2,1],"b":1}');
  });
});

// ── stdio framing ──────────────────────────────────────────────────────────────

describe('LineSplitter', () => {
  const messages = [
    { jsonrpc: '2.0', id: 1, method: 'ping' },
    { jsonrpc: '2.0', id: 2, result: { text: 'caf\u00e9 \u{1F47B} \u200B' } },
    { jsonrpc: '2.0', method: 'notifications/x', params: { a: 'line\\nbreak' } },
  ];
  const bytes = new TextEncoder().encode(messages.map((m) => JSON.stringify(m)).join('\n') + '\n');

  function split(cuts: number[]): string[] {
    const pts = [...new Set(cuts.map((c) => c % (bytes.length + 1)))].sort((a, b) => a - b);
    const s = new LineSplitter();
    const out: string[] = [];
    let prev = 0;
    for (const c of [...pts, bytes.length]) { out.push(...s.push(bytes.slice(prev, c))); prev = c; }
    out.push(...s.flush());
    return out;
  }

  it('returns each line once', () => {
    expect(split([]).map((l) => JSON.parse(l))).toEqual(messages);
  });

  it('PBT-SHD-05: any byte-level split yields the same lines', () => {
    const whole = split([]);
    fc.assert(
      fc.property(fc.array(fc.nat(bytes.length), { maxLength: 15 }), (cuts) => {
        expect(split(cuts)).toEqual(whole);
        return true;
      }),
    );
  });

  it('skips blank lines and handles CRLF', () => {
    const s = new LineSplitter();
    expect([...s.push(new TextEncoder().encode('{"a":1}\r\n\r\n{"b":2}\r\n')), ...s.flush()]).toEqual(['{"a":1}', '{"b":2}']);
  });
});

// ── state and policy ───────────────────────────────────────────────────────────

const hex64 = fc.hexaString({ minLength: 64, maxLength: 64 });
const stateArb: fc.Arbitrary<State> = fc.record({
  version: fc.constant(1 as const),
  servers: fc.dictionary(
    fc.constantFrom('github', 'notes', 'db'),
    fc.record({
      tools: fc.dictionary(fc.constantFrom('read', 'write', 'list'), fc.record({ hash: hex64, description: fc.string(), pinnedAt: fc.constant('2026-11-20T00:00:00.000Z') })),
      pending: fc.dictionary(fc.constantFrom('read', 'write'), fc.record({ hash: hex64, oldHash: hex64, oldDescription: fc.string(), newDescription: fc.string(), seenAt: fc.constant('2026-11-20T00:00:00.000Z') })),
      unreviewed: fc.dictionary(fc.constantFrom('new', 'extra'), fc.record({ hash: hex64, description: fc.string(), seenAt: fc.constant('2026-11-20T00:00:00.000Z') })),
      approvedHosts: fc.array(fc.constantFrom('a.example.invalid', '*.b.example.invalid'), { maxLength: 2 }),
    }),
  ),
});

describe('state', () => {
  it('PBT-SHD-04: save then load returns the same state', () => {
    const dir = tmp();
    fc.assert(
      fc.property(stateArb, (state) => {
        const p = join(dir, 'pins.json');
        saveState(p, state);
        const r = loadState(p);
        expect(r.ok && r.state).toEqual(state);
        return true;
      }),
      { numRuns: 40 },
    );
  });

  it('a missing file is an empty state; a corrupt or invalid file is an error (fail closed)', () => {
    const dir = tmp();
    expect(loadState(join(dir, 'none.json'))).toEqual({ ok: true, state: emptyState() });
    writeFileSync(join(dir, 'bad.json'), '{not json');
    expect(loadState(join(dir, 'bad.json')).ok).toBe(false);
    writeFileSync(join(dir, 'wrong.json'), JSON.stringify({ version: 2, servers: {} }));
    expect(loadState(join(dir, 'wrong.json')).ok).toBe(false);
    writeFileSync(join(dir, 'hash.json'), JSON.stringify({ version: 1, servers: { s: { tools: { t: { hash: 'short', description: '', pinnedAt: 'x' } } } } }));
    expect(loadState(join(dir, 'hash.json')).ok).toBe(false);
  });

  it('writes atomically: no temp files are left behind', () => {
    const dir = tmp();
    saveState(join(dir, 'pins.json'), emptyState());
    saveState(join(dir, 'pins.json'), emptyState());
    expect(readdirSync(dir)).toEqual(['pins.json']);
  });

  it('approveTool pins the pending version and clears it', () => {
    const st = emptyState();
    const s = serverState(st, 'notes');
    s.pending['read'] = { hash: 'b'.repeat(64), oldHash: 'a'.repeat(64), oldDescription: 'old', newDescription: 'new', seenAt: 't' };
    expect(approveTool(st, 'notes', 'read').ok).toBe(true);
    expect(s.tools['read']?.hash).toBe('b'.repeat(64));
    expect(s.tools['read']?.description).toBe('new');
    expect(s.pending['read']).toBeUndefined();
    expect(approveTool(st, 'notes', 'read').ok).toBe(false);
    expect(StateSchema.safeParse(st).success).toBe(true);
  });

  it('approveHost normalises, de-duplicates and rejects junk', () => {
    const st = emptyState();
    expect(approveHost(st, 'n', 'API.Example.invalid').ok).toBe(true);
    expect(approveHost(st, 'n', 'api.example.invalid').ok).toBe(true);
    expect(st.servers['n']?.approvedHosts).toEqual(['api.example.invalid']);
    expect(approveHost(st, 'n', 'bad host/with;chars').ok).toBe(false);
  });
});

describe('policy', () => {
  it('uses defaults when there is no file, and rejects unknown keys', () => {
    const dir = tmp();
    const none = loadPolicy(join(dir, 'policy.json'));
    expect(none.ok && none.policy).toEqual({ allowedHosts: [], mode: 'enforce', autoQuarantine: false, firstUse: 'pin', notify: true });
    writeFileSync(join(dir, 'policy.json'), JSON.stringify({ mode: 'monitor', surprise: true }));
    expect(loadPolicy(join(dir, 'policy.json')).ok).toBe(false);
  });

  it('matches exact hosts, *. wildcards and always allows local names', () => {
    const allow = ['api.example.invalid', '*.corp.example.invalid'];
    expect(hostAllowed('API.example.invalid', allow)).toBe(true);
    expect(hostAllowed('x.corp.example.invalid', allow)).toBe(true);
    expect(hostAllowed('corp.example.invalid', allow)).toBe(false);
    expect(hostAllowed('evilcorp.example.invalid', allow)).toBe(false);
    expect(hostAllowed('localhost', [])).toBe(true);
    expect(hostAllowed('127.0.0.1', [])).toBe(true);
    expect(hostAllowed('collect.example.invalid', allow)).toBe(false);
  });
});

// ── wrap / unwrap ──────────────────────────────────────────────────────────────

const word = fc.stringMatching(/^[a-z0-9._@/-]{1,12}$/);
const entryArb = fc.oneof(
  fc.record({ command: word, args: fc.array(fc.oneof(word, fc.constantFrom('--', 'shield', '--server', '-y')), { minLength: 1, maxLength: 5 }) }),
  fc.record({ command: word }),
  fc.record({ command: word, args: fc.array(word, { minLength: 1, maxLength: 3 }), env: fc.constant({ K: 'v' }), autoApprove: fc.constant(['read']), disabled: fc.boolean() }),
  fc.record({ url: fc.constant('https://mcp.example.invalid/sse') }),
  // Remote servers with any mix of type, headers and env (S-005).
  fc.record(
    {
      url: fc.constantFrom('https://mcp.example.invalid/mcp', 'http://127.0.0.1:8080/mcp'),
      type: fc.constantFrom('http', 'streamable-http', 'sse'),
      headers: fc.dictionary(fc.constantFrom('Authorization', 'X-Api-Key', 'X-Team'), fc.string({ maxLength: 30 }), { maxKeys: 3 }),
      env: fc.dictionary(fc.constantFrom('A', 'B'), fc.string({ maxLength: 10 }), { maxKeys: 2 }),
    },
    { requiredKeys: ['url'] },
  ),
);
const configArb: fc.Arbitrary<McpConfig> = fc.record({
  mcpServers: fc.dictionary(fc.stringMatching(/^[a-z][a-z0-9-]{0,8}$/), entryArb, { maxKeys: 4 }),
});

describe('wrap and unwrap', () => {
  const opts = { bin: 'exorcist', dir: '.exorcist', configPath: '.kiro/settings/mcp.json' };

  it('wraps a stdio server directly and a remote server through --url (S-005)', () => {
    const { config, wrapped } = wrapConfig({ mcpServers: { a: { command: 'npx', args: ['-y', 'x@1.0.0'] }, r: { url: 'https://x.example.invalid' } } }, opts);
    expect(wrapped).toEqual(['a', 'r']);
    expect(config.mcpServers?.['a']).toEqual({
      command: 'exorcist',
      args: ['shield', '--server', 'a', '--config', '.kiro/settings/mcp.json', '--dir', '.exorcist', '--', 'npx', '-y', 'x@1.0.0'],
    });
    expect(config.mcpServers?.['r']).toEqual({
      command: 'exorcist',
      args: ['shield', '--server', 'r', '--config', '.kiro/settings/mcp.json', '--dir', '.exorcist', '--url', 'https://x.example.invalid', '--remote-env', 'none', '--remote-keys', '["url"]'],
    });
  });

  it('moves remote header values into env, never into the arguments', () => {
    const token = ['Bearer ', 'EXAMPLE_TOKEN_DO_NOT_USE'].join('');
    const { config } = wrapConfig({ mcpServers: { r: { type: 'http', url: 'https://x.example.invalid/mcp', headers: { Authorization: token } } } }, opts);
    const e = config.mcpServers?.['r'] ?? {};
    expect(JSON.stringify(e['args'])).not.toContain('EXAMPLE_TOKEN');
    expect(e['args']).toContain('Authorization=EXORCIST_REMOTE_HEADER_1');
    expect(e['env']).toEqual({ EXORCIST_REMOTE_HEADER_1: token });
    expect(e['url']).toBeUndefined();
    expect(isWrapped(e)).toBe(true);
    expect(wrapConfig(config, opts).wrapped).toEqual([]);
  });

  it('does not wrap twice', () => {
    const once = wrapConfig({ mcpServers: { a: { command: 'node', args: ['s.js'] } } }, opts).config;
    expect(wrapConfig(once, opts).wrapped).toEqual([]);
  });

  it('works through npx with a binArgs prefix and unwraps exactly', () => {
    const original: McpConfig = { mcpServers: { a: { command: 'node', args: ['s.js'], env: { A: '1' } } } };
    const wrapped = wrapConfig(original, { bin: 'npx', binArgs: ['-y', '@exorcist-98/cli@0.1.0'] }).config;
    expect(wrapped.mcpServers?.['a']?.['args']).toEqual(['-y', '@exorcist-98/cli@0.1.0', 'shield', '--server', 'a', '--', 'node', 's.js']);
    expect(unwrapConfig(wrapped).config).toEqual(original);
  });

  it('PBT-VLT-02: unwrap(wrap(config)) equals the original config', () => {
    fc.assert(
      fc.property(configArb, (cfg) => {
        const { config } = wrapConfig(cfg, opts);
        expect(unwrapConfig(config).config).toEqual(cfg);
        // Same JSON text too: key order is kept, so a config file comes back byte for byte.
        expect(JSON.stringify(unwrapConfig(config).config)).toBe(JSON.stringify(cfg));
        return true;
      }),
    );
  });

  it('does not modify its input', () => {
    const cfg: McpConfig = { mcpServers: { a: { command: 'node', args: ['s.js'] } } };
    const copy = structuredClone(cfg);
    wrapConfig(cfg, opts);
    expect(cfg).toEqual(copy);
    expect(existsSync('/nonexistent-never-created')).toBe(false);
  });
});
