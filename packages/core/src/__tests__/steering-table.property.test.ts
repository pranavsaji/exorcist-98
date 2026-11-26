/** m13-kiro-evidence: Property 13, the steering table's completeness check is exact (task 15.3). */
import { describe, expect, it } from 'vitest';
import * as fc from 'fast-check';
import { compareSteeringTable } from '../steering-table.js';

const name = fc.stringMatching(/^[a-z]{1,6}\.md$/);
const names = fc.uniqueArray(name, { maxLength: 8 });

describe('Property 13: the steering table check is exact', () => {
  it('KE-36: complete exactly when the table lists each directory file once and nothing else', () => {
    fc.assert(
      fc.property(names, names, (dir, table) => {
        const d = compareSteeringTable(dir, table);
        const same = dir.length === table.length && dir.every((f) => table.includes(f));
        expect(d.complete).toBe(same);
      }),
    );
  });

  it('KE-36: missing, extra and duplicated report exactly the differences, whatever the order', () => {
    fc.assert(
      fc.property(names, names, fc.nat(3), (dir, table, dups) => {
        const withDups = [...table, ...table.slice(0, dups)];
        const shuffled = [...withDups].reverse();
        const d = compareSteeringTable(dir, withDups);
        expect(d.missing).toEqual(dir.filter((f) => !table.includes(f)).sort());
        expect(d.extra).toEqual(table.filter((f) => !dir.includes(f)).sort());
        expect(d.duplicated).toEqual(table.slice(0, dups).sort());
        expect(compareSteeringTable(dir, shuffled)).toEqual(d);
      }),
    );
  });
});
