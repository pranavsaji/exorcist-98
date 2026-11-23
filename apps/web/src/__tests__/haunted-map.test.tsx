import { describe, it, expect, vi } from 'vitest';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { renderToStaticMarkup } from 'react-dom/server';
import { HauntedHouseMap, mapSummary, orderConfigs } from '@/components/HauntedHouseMap';
import { ResultsWindow } from '@/components/ResultsWindow';
import { NdjsonParser } from '@/lib/ndjson';
import { initialScanState, scanReducer } from '@/lib/scan-state';
import { scanTarget, toWebMap } from '@/lib/scan-service';
import { HauntedMapSchema } from '@/lib/protocol';
import type { ConfigMapMsg, HauntedMapMsg, ScanEventMsg } from '@/lib/protocol';

vi.spyOn(console, 'log').mockImplementation(() => undefined);

const lethal: ConfigMapMsg = {
  file: '.kiro/settings/mcp.json',
  ghosts: [
    { name: 'home-files', kind: 'server', capabilities: ['private-data'], reasons: [{ capability: 'private-data', ruleId: 'CAP-001', label: 'reads files outside the project', evidence: 'x ~' }], autoApproved: false },
    { name: 'web-reader', kind: 'server', capabilities: ['untrusted-input', 'exfiltration'], reasons: [
      { capability: 'untrusted-input', ruleId: 'CAP-010', label: 'reads web pages', evidence: 'mcp-server-fetch' },
      { capability: 'exfiltration', ruleId: 'CAP-020', label: 'makes web requests to any address', evidence: 'mcp-server-fetch' },
    ], autoApproved: true },
    { name: 'scratchpad', kind: 'server', capabilities: [], reasons: [], autoApproved: false },
  ],
  legs: { 'private-data': ['home-files'], 'untrusted-input': ['web-reader'], exfiltration: ['web-reader'] },
  trifecta: true,
  severity: 'critical',
};
const calm: ConfigMapMsg = {
  file: '.cursor/mcp.json',
  ghosts: [{ name: 'github', kind: 'server', capabilities: ['untrusted-input', 'exfiltration'], reasons: [], autoApproved: false }],
  legs: { 'private-data': [], 'untrusted-input': ['github'], exfiltration: ['github'] },
  trifecta: false,
  severity: null,
};
const map: HauntedMapMsg = { configs: [calm, lethal] };

describe('REQ-03.2: the Haunted House Map view', () => {
  it('draws an SVG with an accessible name and three named rooms, plus a text list of every ghost', () => {
    const html = renderToStaticMarkup(<HauntedHouseMap map={map} />);
    expect(html).toContain('<svg');
    expect(html).toContain('role="img"');
    expect(html).toMatch(/<title id="[^"]+">Haunted House Map of \.kiro\/settings\/mcp\.json<\/title>/);
    for (const room of ['VAULT OF SECRETS', 'OPEN DOOR', 'ESCAPE TUNNEL']) expect(html).toContain(room);
    for (const room of ['Vault of Secrets', 'Open Door', 'Escape Tunnel']) expect(html).toContain(`<span class="font-bold">${room}</span>`);
    expect(html).toContain('aria-label="Rooms of the Haunted House Map, .kiro/settings/mcp.json"');
    expect(html).toContain('home-files');
    expect(html).toContain('reads web pages; makes web requests to any address');
    expect(html).toContain('Quiet ghosts');
    expect(html).toContain('data-trifecta-path="true"');
  });

  it('severity is never colour alone: a text label and a shape, and AUTO-APPROVED in words', () => {
    const html = renderToStaticMarkup(<HauntedHouseMap map={map} />);
    expect(html).toContain('CRITICAL');
    expect(html).toContain('data-shape="diamond"');
    expect(html).toContain('Lethal trifecta: all three rooms are haunted.');
    expect(html).toContain('AUTO-APPROVED');
  });

  it('shows trifecta configs first and lets you pick another config', () => {
    expect(orderConfigs(map.configs).map((c) => c.file)).toEqual(['.kiro/settings/mcp.json', '.cursor/mcp.json']);
    const html = renderToStaticMarkup(<HauntedHouseMap map={map} />);
    expect(html).toContain('<select');
    expect(html).toContain('(LETHAL TRIFECTA, CRITICAL)');
    expect(html).toContain('(no trifecta)');
  });

  it('a config without the trifecta says which rooms are empty, in words', () => {
    const html = renderToStaticMarkup(<HauntedHouseMap map={{ configs: [calm] }} />);
    expect(html).toContain('NO TRIFECTA');
    expect(html).toContain('data-shape="check"');
    expect(html).toContain('the Vault of Secrets room is empty');
    expect(html).toContain('no ghost here');
    expect(html).not.toContain('<select');
    expect(mapSummary(calm)).toBe('No trifecta in .cursor/mcp.json: the Vault of Secrets room is empty.');
  });

  it('the results window offers the map only when there is one, and keeps the list as the default view', () => {
    const none = renderToStaticMarkup(<ResultsWindow findings={[]} selectedId={null} onSelect={() => undefined} scanDone />);
    expect(none).not.toContain('Haunted House Map');
    const withMap = renderToStaticMarkup(<ResultsWindow findings={[]} selectedId={null} onSelect={() => undefined} scanDone map={map} />);
    expect(withMap).toContain('aria-pressed="true">Threat list');
    expect(withMap).toContain('Haunted House Map (1 trifecta)');
    expect(withMap).toContain('Clean. No threats found');
    const mapView = renderToStaticMarkup(<ResultsWindow findings={[]} selectedId={null} onSelect={() => undefined} scanDone map={map} initialView="map" />);
    expect(mapView).toContain('role="img"');
  });
});

describe('the map event in the stream and the page state', () => {
  it('parses a map event; rejects a malformed one as a typed error', () => {
    const p = new NdjsonParser();
    const good = JSON.stringify({ type: 'map', map });
    const bad = JSON.stringify({ type: 'map', map: { configs: [{ file: 'x' }] } });
    const r = [...p.push(new TextEncoder().encode(`${good}\n${bad}\n`)), ...p.flush()];
    expect(r[0]).toEqual({ ok: true, event: { type: 'map', map } });
    expect(r[1]?.ok).toBe(false);
  });

  it('stores the map, logs a summary line, and a new scan clears it', () => {
    let s = scanReducer(initialScanState, { type: 'reset', target: 't' });
    s = scanReducer(s, { type: 'event', event: { type: 'map', map } });
    expect(s.map).toEqual(map);
    expect(s.log.at(-1)?.text).toBe('Haunted House Map: 2 MCP configs mapped, 1 with the lethal trifecta.');
    expect(scanReducer(s, { type: 'reset', target: 'u' }).map).toBeNull();
  });

  it('toWebMap bounds only the drawing: a padded trifecta keeps its verdict and its dangerous ghosts', () => {
    const quiet = Array.from({ length: 1000 }, (_, i) => ({ name: `filler-${i}`, kind: 'server' as const, capabilities: [], reasons: [], autoApproved: false }));
    const padded = { ...lethal, ghosts: [...quiet, ...lethal.ghosts] };
    const web = toWebMap({ configs: [padded] }, () => true);
    const c = web?.configs[0];
    expect(c?.trifecta).toBe(true);
    expect(c?.severity).toBe('critical');
    expect(c?.ghosts).toHaveLength(100);
    expect(c?.ghosts.slice(0, 2).map((g) => g.name)).toEqual(['home-files', 'web-reader']);
    expect(c?.omitted).toBe(903);
    expect(HauntedMapSchema.safeParse(web).success).toBe(true);
    const html = renderToStaticMarkup(<HauntedHouseMap map={web as HauntedMapMsg} />);
    expect(html).toContain('903 more servers are not listed here. Every one was checked');
  });

  it('toWebMap keeps only shown configs, trifectas first', () => {
    expect(toWebMap(map, (f) => f.startsWith('.kiro'))?.configs.map((c) => c.file)).toEqual(['.kiro/settings/mcp.json']);
    expect(toWebMap(map, () => false)).toBeNull();
    expect(toWebMap(map, () => true)?.configs[0]?.trifecta).toBe(true);
  });
});

describe('scanTarget: the map event (m5-trifecta)', () => {
  it('the Haunted Repo scan sends EX-023 with a snippet and one map event right before done', async () => {
    const events: ScanEventMsg[] = [];
    for await (const ev of scanTarget({ kind: 'haunted-repo', display: 'Haunted Repo' })) events.push(ev);
    expect(events.at(-1)?.type).toBe('done');
    expect(events.at(-2)?.type).toBe('map');
    const m = events.at(-2);
    if (m?.type !== 'map') throw new Error('no map');
    expect(m.map.configs[0]).toMatchObject({ file: 'EX-023-lethal-trifecta.json', trifecta: true, severity: 'critical' });
    for (const c of m.map.configs) expect(c.file).toMatch(/^EX-\d{3}-/);
    const tri = events.flatMap((e) => (e.type === 'finding' && e.finding.ruleId === 'EX-023' ? [e] : []));
    expect(tri).toHaveLength(1);
    expect(tri[0]?.snippet.lines.find((l) => l.n === 4)?.match).toBe('"mcpServers"');
  }, 120_000);

  it('a repository with an ordinary MCP config gets a map and no EX-023', async () => {
    const events: ScanEventMsg[] = [];
    for await (const ev of scanTarget({ kind: 'github', display: 'o/r', owner: 'o', repo: 'r' }, {
      clone: async (_t, dir) => {
        await mkdir(join(dir, '.cursor'), { recursive: true });
        await writeFile(join(dir, '.cursor/mcp.json'), JSON.stringify({ mcpServers: {
          files: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@2025.1.14', '.'] },
          github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github@2025.4.8'] },
        } }));
      },
    })) events.push(ev);
    const m = events.find((e) => e.type === 'map');
    expect(m?.type === 'map' ? m.map.configs.map((c) => [c.file, c.trifecta]) : null).toEqual([['.cursor/mcp.json', false]]);
    expect(events.some((e) => e.type === 'finding' && e.finding.ruleId === 'EX-023')).toBe(false);
  }, 120_000);
});
