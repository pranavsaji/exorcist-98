import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { fromRoot } from './repo-root.js';

interface FactsModule {
  kiroEvidence: (root?: string) => Record<string, number>;
  countShallLines: (text: string) => number;
  countTasks: (text: string) => { done: number; total: number };
  specCounts: (root?: string) => Record<string, number>;
  rewrite: (text: string, facts: Record<string, unknown>) => string;
  disagreements: (text: string, facts: Record<string, unknown>) => Array<{ key: string }>;
}
const modulePath = pathToFileURL(fromRoot('scripts/facts.mjs')).href;
const load = async (): Promise<FactsModule> => (await import(/* @vite-ignore */ modulePath)) as FactsModule;

// Lines that never contain the word SHALL, nor look like a fence or a checkbox.
const plain = fc.stringMatching(/^[a-z ]{0,30}$/).filter((s) => !/shall/i.test(s));
const shallLine = plain.map((s) => `${s} SHALL ${s}`);
const interleave = <T>(a: T[], b: T[], order: boolean[]): T[] => {
  const out: T[] = [];
  let i = 0, j = 0;
  for (const pickA of order) { if (pickA && i < a.length) out.push(a[i++] as T); else if (j < b.length) out.push(b[j++] as T); else if (i < a.length) out.push(a[i++] as T); }
  while (i < a.length) out.push(a[i++] as T);
  while (j < b.length) out.push(b[j++] as T);
  return out;
};

describe('KE-20 SHALL lines', () => {
  it('KE-20 countShallLines returns exactly the constructed number of SHALL lines, ignoring fenced code', async () => {
    const m = await load();
    await fc.assert(
      fc.asyncProperty(fc.array(shallLine, { maxLength: 20 }), fc.array(plain, { maxLength: 20 }), fc.array(shallLine, { maxLength: 5 }), fc.array(fc.boolean(), { maxLength: 40 }), async (shall, other, fenced, order) => {
        const lines = interleave(shall, other, order);
        const text = [...lines, '```', ...fenced, '```'].join('\n');
        expect(m.countShallLines(text)).toBe(shall.length);
      }),
      { numRuns: 100 },
    );
  });
});

describe('KE-21 task counts', () => {
  it('KE-21 countTasks returns exactly the constructed done and total, at any nesting', async () => {
    const m = await load();
    const task = fc.record({ done: fc.boolean(), upper: fc.boolean(), depth: fc.integer({ min: 0, max: 3 }), label: plain });
    await fc.assert(
      fc.asyncProperty(fc.array(task, { maxLength: 30 }), fc.array(plain, { maxLength: 10 }), async (tasks, other) => {
        const taskLines = tasks.map((t) => `${'  '.repeat(t.depth)}- [${t.done ? (t.upper ? 'X' : 'x') : ' '}] ${t.label}`);
        const text = interleave(taskLines, other, tasks.map((_, i) => i % 2 === 0)).join('\n');
        expect(m.countTasks(text)).toEqual({ done: tasks.filter((t) => t.done).length, total: tasks.length });
      }),
      { numRuns: 100 },
    );
  });
});

describe('KE-18 and KE-19 facts keys', () => {
  const withTree = (fn: (root: string) => void): void => {
    const root = mkdtempSync(join(tmpdir(), 'x98-facts-ke-'));
    try { fn(root); } finally { rmSync(root, { recursive: true, force: true }); }
  };

  it('KE-18 kiroEvidence reads totals from index.json and sums the per-name records', async () => {
    const m = await load();
    withTree((root) => {
      mkdirSync(join(root, 'evidence/kiro-sessions'), { recursive: true });
      const totals = { sessionsKept: 3, sessionsSkipped: 9, credits: 12.3456, toolCalls: { fs_read: 4, shell: 2 }, hookRuns: { a: 5, b: 1 }, hookBlocks: { a: 1 } };
      writeFileSync(join(root, 'evidence/kiro-sessions/index.json'), JSON.stringify({ sessions: [], totals }));
      expect(m.kiroEvidence(root)).toEqual({ kiroSessions: 3, kiroCredits: 12.35, kiroToolCalls: 6, hookRuns: 6, hookBlocks: 1 });
    });
  });

  it('KE-18 kiroEvidence gives zeros when index.json is absent or unreadable', async () => {
    const m = await load();
    const zero = { kiroSessions: 0, kiroCredits: 0, kiroToolCalls: 0, hookRuns: 0, hookBlocks: 0 };
    withTree((root) => {
      expect(m.kiroEvidence(root)).toEqual(zero);
      mkdirSync(join(root, 'evidence/kiro-sessions'), { recursive: true });
      writeFileSync(join(root, 'evidence/kiro-sessions/index.json'), '{not json');
      expect(m.kiroEvidence(root)).toEqual(zero);
    });
  });

  it('KE-20 KE-21 specCounts totals SHALL lines and tasks across every spec folder', async () => {
    const m = await load();
    withTree((root) => {
      for (const [name, req, tasks] of [['a', 'x SHALL y\nz\n', '- [x] 1\n- [ ] 2\n'], ['b', '1. SHALL\n2. SHALL\n', '- [X] 1\n']] as const) {
        mkdirSync(join(root, '.kiro/specs', name), { recursive: true });
        writeFileSync(join(root, '.kiro/specs', name, 'requirements.md'), req);
        writeFileSync(join(root, '.kiro/specs', name, 'tasks.md'), tasks);
      }
      expect(m.specCounts(root)).toEqual({ shallLines: 3, tasksDone: 2, tasksTotal: 3 });
    });
  });

  it('KE-19 README markers for the Kiro keys are filled from the facts and --check semantics see a stale value', async () => {
    const m = await load();
    const text = 'ran <!--f:hookRuns-->0<!--/f--> times, <!--f:kiroCredits-->0<!--/f--> credits, <!--f:kiroSessions-->0<!--/f--> sessions';
    const facts = { hookRuns: 1234, kiroCredits: 12.5, kiroSessions: 7 };
    expect(m.disagreements(text, facts).map((d) => d.key)).toEqual(['hookRuns', 'kiroCredits', 'kiroSessions']);
    const filled = m.rewrite(text, facts);
    expect(filled).toBe('ran <!--f:hookRuns-->1,234<!--/f--> times, <!--f:kiroCredits-->12.5<!--/f--> credits, <!--f:kiroSessions-->7<!--/f--> sessions');
    expect(m.disagreements(filled, facts)).toEqual([]);
  });
});
