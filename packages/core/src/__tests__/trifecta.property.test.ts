import { describe, it, expect, beforeAll } from 'vitest';
import * as fc from 'fast-check';
import { exampleServer, loadCapabilityRules, CAPABILITIES } from '../capabilities.js';
import type { CapabilityRule } from '../capabilities.js';
import { loadDefinitions } from '../definitions/loader.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { analyzeConfig, trifectaFinding } from '../trifecta.js';
import type { ConfigEntry, ParsedMcpConfig } from '../trifecta.js';
import { fromRoot } from './repo-root.js';

const DEFS = fromRoot('definitions');
let rules: CapabilityRule[] = [];
let defs: VirusDefinition[] = [];
let pool: Array<Omit<ConfigEntry, 'name'>> = [];
beforeAll(async () => {
  const r = await loadCapabilityRules(DEFS);
  if (!r.ok) throw new Error(r.error);
  rules = r.rules;
  defs = await loadDefinitions(DEFS);
  // Every example in the rule file (positive and negative) is a possible server.
  pool = rules.flatMap((rule) => rule.examples.map((e) => {
    const s = exampleServer(e);
    const ability = s.ability;
    return ability !== undefined
      ? { kind: 'ability' as const, ability, disabled: false, autoApprove: ['*'] }
      : { kind: 'server' as const, ...s, disabled: false, autoApprove: (s.tools ?? []).map((t) => t.name) };
  }));
});

/** A server drawn from the pool, or a made-up package, maybe auto-approved, maybe disabled. */
const entryArb = (): fc.Arbitrary<Omit<ConfigEntry, 'name'>> => fc.oneof(
  fc.nat({ max: 10_000 }).map((i) => pool[i % pool.length] as Omit<ConfigEntry, 'name'>),
  fc.record({
    pkg: fc.stringMatching(/^[a-z][a-z0-9-]{0,20}$/),
    dir: fc.constantFrom('.', '~', '/', './src', '${workspaceFolder}', '/home/me/code/app'),
    auto: fc.boolean(),
    disabled: fc.boolean(),
  }).map(({ pkg, dir, auto, disabled }) => ({
    kind: 'server' as const, command: 'npx', args: ['-y', pkg, dir], disabled, autoApprove: auto ? ['*'] : [],
  })),
);

/** A config of up to 8 entries with unique names. */
const configArb = (): fc.Arbitrary<ParsedMcpConfig> =>
  fc.uniqueArray(fc.tuple(fc.stringMatching(/^[a-z][a-z0-9_-]{0,12}$/), entryArb()), { maxLength: 8, selector: ([n]) => n })
    .map((pairs) => ({
      file: '.kiro/settings/mcp.json',
      entries: pairs.map(([name, e]) => ({ ...e, name, autoApprove: [...e.autoApprove] })),
      anchor: { line: 2, col: 3, span: '"mcpServers"' },
    }));

const withEntries = (c: ParsedMcpConfig, entries: ConfigEntry[]): ParsedMcpConfig => ({ ...c, entries });

describe('PBT-TRI: lethal trifecta properties', () => {
  it('PBT-TRI-01a: adding a server never removes a leg (each leg only gains names)', () => {
    fc.assert(fc.property(configArb(), entryArb(), fc.stringMatching(/^new-[a-z]{1,6}$/), (cfg, extra, name) => {
      const before = analyzeConfig(cfg, rules);
      const after = analyzeConfig(withEntries(cfg, [...cfg.entries, { ...extra, name, autoApprove: [...extra.autoApprove] }]), rules);
      for (const c of CAPABILITIES) for (const n of before.legs[c]) expect(after.legs[c]).toContain(n);
      if (before.trifecta) expect(after.trifecta).toBe(true);
    }), { numRuns: 300 });
  });

  it('PBT-TRI-01b: removing every server on one leg always clears EX-023', () => {
    fc.assert(fc.property(configArb(), fc.constantFrom(...CAPABILITIES), (cfg, leg) => {
      const map = analyzeConfig(cfg, rules);
      const onLeg = new Set(map.legs[leg]);
      const rest = withEntries(cfg, cfg.entries.filter((e) => !onLeg.has(e.name)));
      const after = analyzeConfig(rest, rules);
      expect(after.legs[leg]).toEqual([]);
      expect(after.trifecta).toBe(false);
      expect(trifectaFinding(rest, after, defs)).toBeNull();
    }), { numRuns: 300 });
  });

  it('PBT-TRI-01c: the generator does reach the trifecta (the properties are not vacuous)', () => {
    const hits = fc.sample(configArb(), 400).filter((c) => analyzeConfig(c, rules).trifecta).length;
    expect(hits).toBeGreaterThan(10);
  });

  it('PBT-TRI-02: server order never changes the result', () => {
    fc.assert(fc.property(configArb().chain((c) => fc.tuple(fc.constant(c), fc.shuffledSubarray(c.entries, { minLength: c.entries.length, maxLength: c.entries.length }))), ([cfg, shuffled]) => {
      const a = analyzeConfig(cfg, rules);
      const b = analyzeConfig(withEntries(cfg, shuffled), rules);
      expect(b).toEqual(a);
      expect(trifectaFinding(withEntries(cfg, shuffled), b, defs)).toEqual(trifectaFinding(cfg, a, defs));
    }), { numRuns: 300 });
  });
});
