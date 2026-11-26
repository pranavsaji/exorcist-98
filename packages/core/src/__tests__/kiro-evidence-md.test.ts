/** m13-kiro-evidence: the evidence document (tasks 7.2, 7.3). */
import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';
import { aggregateTotals, type SessionRecord } from '../kiro-evidence.js';
import { renderKiroEvidenceMd } from '../kiro-evidence-md.js';

const rec = (over: Partial<SessionRecord> & { id: string }): SessionRecord => ({
  title: null, agentMode: null, startTime: null, endTime: null, model: null, autopilot: null,
  approveForMe: null, credits: 0, toolCalls: {}, hookRuns: {}, hookBlocks: {}, hookBlockEvents: [], commits: [], eventsDroppedUnparseable: 0,
  ...over,
});
const render = (sessions: SessionRecord[], skipped = 0): string =>
  renderKiroEvidenceMd({ sessions, totals: aggregateTotals(sessions, skipped) });

const fixture = [
  rec({
    id: 'sess_a', title: 'Build the scanner', agentMode: 'spec', startTime: '2026-11-01T10:00:00.000Z',
    credits: 1.5, toolCalls: { read_file: 3, fs_write: 1 }, hookRuns: { 'on-access-scan': 4 },
    hookBlocks: { 'on-access-scan': 1 },
    hookBlockEvents: [{ hookName: 'on-access-scan', toolName: 'read_file', timestamp: '2026-11-01T10:05:00.000Z' }],
  }),
  rec({ id: 'sess_b', title: null, agentMode: 'vibe', startTime: '2026-11-02T09:00:00.000Z', credits: 0.25, toolCalls: { read_file: 2 } }),
];

describe('Property 8: every kept session gets exactly one evidence row', () => {
  it('KE-16 renders one row per session, each linking its own transcript', () => {
    const ids = fc.uniqueArray(fc.stringMatching(/^sess_[a-z0-9]{1,12}$/), { maxLength: 12 });
    const text = fc.string({ maxLength: 30 });
    fc.assert(
      fc.property(ids, text, (idList, title) => {
        const sessions = idList.map((id) => rec({ id, title, agentMode: 'vibe', startTime: '2026-11-01T00:00:00.000Z' }));
        const md = render(sessions);
        const rows = md.split('\n').filter((l) => l.includes('](../evidence/kiro-sessions/'));
        expect(rows).toHaveLength(sessions.length);
        for (const id of idList) {
          expect(rows.filter((l) => l.includes(`(../evidence/kiro-sessions/${id}.jsonl.gz)`))).toHaveLength(1);
        }
      }),
    );
  });
});

describe('totals section', () => {
  it('KE-15 shows sessions, credits, tool calls, hook runs and hook blocks', () => {
    const md = render(fixture, 2);
    expect(md).toContain('| Sessions kept | 2 |');
    expect(md).toContain('| Sessions skipped (other projects) | 2 |');
    expect(md).toContain('| Credits | 1.75 |');
    expect(md).toContain('| Tool calls | 6 |');
    expect(md).toContain('| Hook runs | 4 |');
    expect(md).toContain('| Hook blocks | 1 |');
  });

  it('KE-16 gives title, mode, start time and a transcript link per row', () => {
    const md = render(fixture);
    expect(md).toContain('| Build the scanner | spec | 2026-11-01T10:00:00.000Z | [sess_a.jsonl.gz](../evidence/kiro-sessions/sess_a.jsonl.gz) |');
    expect(md).toContain('| untitled | vibe | 2026-11-02T09:00:00.000Z | [sess_b.jsonl.gz](../evidence/kiro-sessions/sess_b.jsonl.gz) |');
  });

  it('KE-16 keeps a hostile title inside its table row', () => {
    const md = render([rec({ id: 'sess_x', title: 'a | b\n# injected' })]);
    const row = md.split('\n').find((l) => l.includes('sess_x.jsonl.gz')) ?? '';
    expect(row).toContain('a \\| b # injected');
    expect(md).not.toContain('\n# injected');
  });
});

describe('hook-block narration', () => {
  it('KE-17 narrates each real block with session id, time, hook and tool', () => {
    const md = render(fixture);
    expect(md).toContain('## Hook blocks');
    expect(md).toContain(
      'On 2026-11-01T10:05:00.000Z, in session `sess_a`, the `on-access-scan` hook blocked the `read_file` tool call.',
    );
  });

  it('KE-17 has no hook-blocks section when nothing was blocked', () => {
    expect(render([fixture[1] as SessionRecord])).not.toContain('## Hook blocks');
  });
});

describe('spec coverage statement', () => {
  it('KE-27 says older specs predate requirement IDs', () => {
    expect(render([])).toContain(
      'Every spec other than `m10-kiro-gate` and `m13-kiro-evidence` predates requirement IDs and is outside the coverage of `scripts/spec-trace.mjs`.',
    );
  });
});
