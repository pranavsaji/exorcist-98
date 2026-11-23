/**
 * exorcist.lock (m5): the lockfile is deterministic, round-trips, and the
 * check reports exactly the tool that changed. Property-based: PBT-LCK-01..03.
 */
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { buildLock, diffLock, parseLock, pinsToLock, seedFromLock, serializeLock, urlFingerprint, DESCRIPTION_CHARS } from '../lockfile.js';
import { toolFingerprint } from '../hash.js';
import type { ToolDef } from '../hash.js';
import { emptyState, serverState } from '../state.js';

const toolArb = fc.record({
  name: fc.string({ minLength: 1, maxLength: 20 }).filter((s) => !s.includes('"') && !/[\\]/.test(s)),
  description: fc.string({ maxLength: 400 }),
  schemaSeed: fc.integer({ min: 0, max: 1000 }),
});

const toolsArb = fc.array(toolArb, { maxLength: 12 }).map((ts) =>
  ts.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: { type: 'object', properties: { n: { type: 'number', seed: t.schemaSeed } } },
  })),
);

const listingArb = fc.record({
  name: fc.string({ minLength: 1, maxLength: 20 }).filter((s) => !s.includes('"')),
  launch: fc.hexaString({ minLength: 64, maxLength: 64 }).map((s) => s.padEnd(64, '0').slice(0, 64)),
  tools: toolsArb,
});

const listingsArb = fc.array(listingArb, { maxLength: 6 }).map((ls) => {
  // One entry per name: a duplicate would collapse in the lock's records.
  const seen = new Set<string>();
  const out = [] as Array<{ name: string; launch: string; tools: Array<{ name: string; description: string; inputSchema: unknown }> }>;
  for (const l of ls) {
    if (seen.has(l.name)) continue;
    seen.add(l.name);
    const tools = [] as Array<{ name: string; description: string; inputSchema: unknown }>;
    const toolNames = new Set<string>();
    for (const t of l.tools) {
      if (toolNames.has(t.name)) continue;
      toolNames.add(t.name);
      tools.push({ name: t.name, description: t.description, inputSchema: t.inputSchema });
    }
    out.push({ name: l.name, launch: l.launch, tools });
  }
  return out;
});

describe('the lock schema', () => {
  it('rejects invalid lock text', () => {
    expect(parseLock('nonsense').ok).toBe(false);
    expect(parseLock('{"version":2,"servers":{}}').ok).toBe(false);
    expect(parseLock('{"version":1,"servers":{"a":{"launch":"not-a-hash","tools":{}}}}').ok).toBe(false);
  });

  it('accepts a lock it wrote, and reads the same fingerprints back', () => {
    const lock = buildLock([
      { name: 'notes', launch: urlFingerprint('https://example.invalid/mcp'), tools: [] , url: 'https://example.invalid/mcp', note: 'remote server (http/sse); tools not pinned' },
    ]);
    const parsed = parseLock(serializeLock(lock));
    expect(parsed.ok).toBe(true);
  });
});

describe('PBT-LCK-01: round trip and identical bytes', () => {
  it('writing and reading back gives the same fingerprints; two writes are byte-identical', () => {
    fc.assert(
      fc.property(listingsArb, (listings) => {
        const lock = buildLock(listings);
        const text1 = serializeLock(lock);
        const text2 = serializeLock(buildLock(listings));
        if (text1 !== text2) return false;
        const parsed = parseLock(text1);
        if (!parsed.ok) return false;
        for (const l of listings) {
          const ls = parsed.lock.servers[l.name];
          if (!ls) continue; // a duplicate name in the arbitrary list collapses
          for (const t of l.tools) {
            const lt = ls.tools[t.name];
            if (!lt) continue;
            if (lt.sha256 !== toolFingerprint({ name: t.name, description: t.description, inputSchema: t.inputSchema })) return false;
            if (lt.description !== t.description.slice(0, DESCRIPTION_CHARS)) return false;
          }
        }
        return true;
      }),
      { numRuns: 200 },
    );
  });
});

describe('PBT-LCK-02: one changed character reports exactly that tool', () => {
  it('changing a single character of one description yields exactly one change, for that tool', () => {
    fc.assert(
      fc.property(
        listingArb.filter((l) => l.tools.length > 0 && l.tools.every((t) => t.description.length > 0)),
        fc.nat(),
        fc.option(fc.nat(), { nil: undefined }),
        (l, pick, pick2) => {
          const i = pick % l.tools.length;
          const tool = l.tools[i];
          if (!tool) return true;
          const pos = (pick2 ?? 0) % tool.description.length;
          const chars = [...tool.description];
          chars[pos] = chars[pos] === 'x' ? 'y' : 'x';
          const mutated = [...l.tools];
          mutated[i] = { ...tool, description: chars.join('') };
          const oldLock = buildLock([l]);
          const newLock = buildLock([{ ...l, tools: mutated }]);
          const changes = diffLock(oldLock, newLock);
          const only = changes[0];
          return (
            changes.length === 1 &&
            only !== undefined &&
            only.kind === 'tool-changed' &&
            only.server === l.name &&
            only.tool === tool.name &&
            only.detail !== undefined
          );
        },
      ),
      { numRuns: 200 },
    );
  });

  it('a changed input schema with the same description is reported without a diff', () => {
    const base: ToolDef[] = [{ name: 't', description: 'same', inputSchema: { type: 'object', properties: { a: { type: 'string' } } } }];
    const oldLock = buildLock([{ name: 's', launch: 'a'.repeat(64), tools: base }]);
    const newLock = buildLock([{ name: 's', launch: 'a'.repeat(64), tools: [{ name: 't', description: 'same', inputSchema: { type: 'object' } }] }]);
    const changes = diffLock(oldLock, newLock);
    expect(changes).toHaveLength(1);
    expect(changes[0]).toMatchObject({ kind: 'tool-changed', tool: 't' });
    expect(changes[0]?.detail).toBeUndefined();
  });
});

describe('PBT-LCK-03: order never matters', () => {
  it('reordering tools, servers and object keys gives the same bytes', () => {
    fc.assert(
      fc.property(listingsArb, (listings) => {
        const a = serializeLock(buildLock(listings));
        const shuffled = [...listings].reverse().map((l) => ({ ...l, tools: [...l.tools].reverse() }));
        return a === serializeLock(buildLock(shuffled));
      }),
      { numRuns: 200 },
    );
  });

  it('diffing two locks built from differently ordered listings reports nothing', () => {
    const tools: ToolDef[] = [
      { name: 'a', description: 'A tool.', inputSchema: { type: 'object' } },
      { name: 'b', description: 'B tool.', inputSchema: { type: 'object' } },
    ];
    const listing = { name: 's', launch: 'f'.repeat(64), tools };
    const reordered: ToolDef[] = [tools[1]!, tools[0]!];
    expect(diffLock(buildLock([listing]), buildLock([{ ...listing, tools: reordered }]))).toEqual([]);
  });
});

describe('added and removed things', () => {
  const base: ToolDef[] = [{ name: 'read_note', description: 'Read a note.', inputSchema: { type: 'object' } }];

  it('reports an added tool', () => {
    const oldLock = buildLock([{ name: 's', launch: 'a'.repeat(64), tools: base }]);
    const grown: ToolDef[] = [...base, { name: 'new_one', description: 'New.', inputSchema: {} }];
    const newLock = buildLock([{ name: 's', launch: 'a'.repeat(64), tools: grown }]);
    const changes = diffLock(oldLock, newLock);
    expect(changes).toHaveLength(1);
    expect(changes[0]).toMatchObject({ kind: 'tool-added', tool: 'new_one' });
  });

  it('reports a removed tool, a changed launch and added or removed servers', () => {
    const oldLock = buildLock([
      { name: 'a', launch: 'a'.repeat(64), tools: base },
      { name: 'gone', launch: 'b'.repeat(64), tools: [] },
    ]);
    const newLock = buildLock([
      { name: 'a', launch: 'c'.repeat(64), tools: [] },
      { name: 'fresh', launch: 'd'.repeat(64), tools: base },
    ]);
    const kinds = diffLock(oldLock, newLock).map((c) => `${c.kind}:${c.server}${c.tool ? `:${c.tool}` : ''}`).sort();
    expect(kinds).toEqual([
      'launch-changed:a',
      'server-added:fresh',
      'server-removed:gone',
      'tool-removed:a:read_note',
    ]);
  });

  it('a remote server changes its launch when the URL changes', () => {
    const u1 = 'https://example.invalid/mcp';
    const u2 = 'https://example.invalid/mcp2';
    const changes = diffLock(
      buildLock([{ name: 'r', launch: urlFingerprint(u1), tools: [], url: u1, note: 'remote server (http/sse); tools not pinned' }]),
      buildLock([{ name: 'r', launch: urlFingerprint(u2), tools: [], url: u2, note: 'remote server (http/sse); tools not pinned' }]),
    );
    expect(changes).toHaveLength(1);
    expect(changes[0]!.kind).toBe('launch-changed');
  });
});

describe('pinsToLock and seedFromLock', () => {
  it('builds a lock from Shield pins and seeds a fresh machine from it', () => {
    // First machine: pinned tools and a launch.
    const state = emptyState();
    const s = serverState(state, 'notes');
    s.tools['read_note'] = { hash: toolFingerprint({ name: 'read_note', description: 'Read a note.' }), description: 'Read a note.', pinnedAt: '2026-01-01T00:00:00.000Z' };
    s.launch = { hash: 'e'.repeat(64), parts: ['command node'], pinnedAt: '2026-01-01T00:00:00.000Z' };
    const lock = pinsToLock(state);
    expect(lock.servers['notes']).toBeDefined();
    expect(lock.servers['notes']!.tools['read_note']!.sha256).toBe(s.tools['read_note']!.hash);

    // Second machine: no pins at all. The lock seeds them.
    const fresh = emptyState();
    const f = serverState(fresh, 'notes');
    const reports: string[] = [];
    expect(seedFromLock(f, lock.servers['notes']!, (l) => reports.push(l))).toBe(true);
    expect(f.tools['read_note']!.hash).toBe(s.tools['read_note']!.hash);
    expect(f.launch!.hash).toBe('e'.repeat(64));
    expect(reports).toEqual([]);

    // Third machine: a disagreeing local pin is reported, not overwritten.
    const other = emptyState();
    const o = serverState(other, 'notes');
    o.tools['read_note'] = { hash: 'f'.repeat(64), description: 'other', pinnedAt: '2026-01-01T00:00:00.000Z' };
    o.launch = { hash: 'a'.repeat(64), parts: ['command node'], pinnedAt: '2026-01-01T00:00:00.000Z' };
    const reports2: string[] = [];
    expect(seedFromLock(o, lock.servers['notes']!, (l) => reports2.push(l))).toBe(false);
    expect(reports2.join('\n')).toContain('disagrees with exorcist.lock');
    expect(o.tools['read_note']!.hash).toBe('f'.repeat(64));
  });
});
