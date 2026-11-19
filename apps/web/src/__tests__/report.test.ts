import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { badgeStatus, toBadgeSvg } from '@exorcist-98/core/browser';
import { badgeMarkdown, buildReport, toEngineFinding } from '@/lib/report';
import { CUES } from '@/lib/sound';
import type { Severity, WebFinding } from '@/lib/protocol';

const f = (severity: Severity, ruleId = 'EX-001', file = 'README.md', line = 3): WebFinding => ({
  source: 'signature', ruleId, title: 'Hidden Unicode instructions', severity, file, line, col: 2,
  span: '\\u200B', owasp: ['LLM01'], fix: 'Remove it.',
});
const stats = { filesScanned: 5, filesSkipped: 0, findingsTotal: 2, durationMs: 9 };

describe('reports built in the page', () => {
  it('SARIF is 2.1.0 with one result per finding and relative paths', () => {
    const r = buildReport('sarif', [f('critical'), f('medium', 'EX-010', 'cfg/mcp.json', 1)], stats, 'o/r');
    expect(r.filename).toBe('exorcist-o-r.sarif');
    const sarif = JSON.parse(r.body) as { version: string; runs: Array<{ results: Array<{ level: string; locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }> }> };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.results.map((x) => x.level)).toEqual(['error', 'warning']);
    expect(sarif.runs[0]?.results[1]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe('cfg/mcp.json');
  });

  it('Markdown leads with plain language; JSON keeps the target and findings', () => {
    expect(buildReport('markdown', [f('high')], stats, 'Haunted Repo').body).toContain('This file hides instructions for your AI');
    const json = JSON.parse(buildReport('json', [f('high')], stats, 'o/r').body) as { target: string; findings: unknown[] };
    expect(json.target).toBe('o/r');
    expect(json.findings).toHaveLength(1);
  });

  it('heuristic findings convert to the engine type with their rationale', () => {
    const h = toEngineFinding({ ...f('high'), source: 'heuristic', rationale: 'why', confidence: 'high' });
    expect(h).toMatchObject({ source: 'heuristic', rationale: 'why', confidence: 'high' });
  });
});

describe('badge', () => {
  it('says exorcised when clean and names the worst level otherwise', () => {
    expect(badgeStatus([]).message).toBe('exorcised');
    expect(badgeStatus([f('low'), f('high'), f('high')]).message).toBe('possessed: 2 high');
    expect(badgeMarkdown([])).toBe('![Exorcist 98: exorcised](./exorcist-badge.svg)');
  });

  it('is a well-formed, self-contained SVG with an accessible label', () => {
    const svg = toBadgeSvg([f('critical')]);
    expect(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg"')).toBe(true);
    expect(svg).toContain('role="img"');
    expect(svg).toContain('aria-label="Exorcist 98: possessed: 1 critical"');
    expect(svg).not.toMatch(/href=|<image|@import|url\(/);
  });

  it('PBT-WEB-06: the badge always reflects the worst severity present', () => {
    const order: Severity[] = ['critical', 'high', 'medium', 'low'];
    fc.assert(
      fc.property(fc.array(fc.constantFrom<Severity>(...order), { maxLength: 20 }), (sevs) => {
        const b = badgeStatus(sevs.map((s) => ({ severity: s })));
        const worst = order.find((s) => sevs.includes(s));
        expect(b.worst).toBe(worst ?? 'clean');
        if (worst) expect(b.message).toBe(`possessed: ${sevs.filter((s) => s === worst).length} ${worst}`);
        return true;
      }),
    );
  });
});

describe('sound cues', () => {
  it('every cue is short and quiet', () => {
    for (const [name, notes] of Object.entries(CUES)) {
      const end = Math.max(...notes.map((n) => n.start + n.dur));
      expect(end, name).toBeLessThan(1);
      for (const n of notes) expect(n.gain ?? 0.1, name).toBeLessThanOrEqual(0.2);
    }
  });
});
