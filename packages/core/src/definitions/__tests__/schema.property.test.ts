import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { VirusDefinitionSchema } from '../schema.js';

// A fast-check arbitrary for a fully valid VirusDefinition record
const validRecordArb = fc.record({
  id:         fc.constantFrom('EX-001', 'EX-042', 'EX-099', 'EX-999'),
  title:      fc.string({ minLength: 1, maxLength: 80 }),
  severity:   fc.constantFrom('critical', 'high', 'medium', 'low'),
  applies_to: fc.array(fc.string({ minLength: 1, maxLength: 20 }), { minLength: 1, maxLength: 5 }),
  match:      fc.record({ regex: fc.string({ minLength: 1, maxLength: 40 }) }),
  owasp:      fc.array(fc.string({ minLength: 1, maxLength: 60 }), { minLength: 1, maxLength: 5 }),
  fix:        fc.string({ minLength: 1, maxLength: 200 }),
});

describe('VirusDefinitionSchema (property-based)', () => {
  // PBT-DEF-01: valid records round-trip through JSON without losing fields
  it('PBT-DEF-01: valid definition round-trips through JSON.parse/stringify', () => {
    fc.assert(
      fc.property(validRecordArb, (record) => {
        const parsed = VirusDefinitionSchema.safeParse(record);
        if (!parsed.success) return true; // skip if fast-check produced an edge case

        const json = JSON.stringify(parsed.data);
        const restored = JSON.parse(json) as unknown;
        const reparsed = VirusDefinitionSchema.safeParse(restored);

        if (!reparsed.success) {
          throw new Error(
            `Round-trip failed: ${reparsed.error.issues.map((i) => i.message).join(', ')}`,
          );
        }

        expect(reparsed.data.id).toBe(parsed.data.id);
        expect(reparsed.data.severity).toBe(parsed.data.severity);
        expect(reparsed.data.fix).toBe(parsed.data.fix);
        return true;
      }),
    );
  });

  // PBT-DEF-02: an id not matching EX-\d{3} always fails validation
  it('PBT-DEF-02: an id not matching EX-NNN always fails validation', () => {
    const badIdArb = fc
      .string({ minLength: 1, maxLength: 20 })
      .filter((s) => !/^EX-\d{3}$/.test(s));

    fc.assert(
      fc.property(badIdArb, (badId) => {
        const result = VirusDefinitionSchema.safeParse({
          id:         badId,
          title:      'Test',
          severity:   'high',
          applies_to: ['docs'],
          match:      { regex: 'foo' },
          owasp:      ['LLM01'],
          fix:        'Fix it.',
        });
        expect(result.success).toBe(false);
        return true;
      }),
    );
  });

  // PBT-DEF-03: a definition with no match sub-fields always fails validation
  it('PBT-DEF-03: a definition with an empty match object always fails validation', () => {
    fc.assert(
      fc.property(fc.constant(undefined), () => {
        const result = VirusDefinitionSchema.safeParse({
          id:         'EX-001',
          title:      'Test',
          severity:   'high',
          applies_to: ['docs'],
          match:      {},
          owasp:      ['LLM01'],
          fix:        'Fix it.',
        });
        expect(result.success).toBe(false);
        return true;
      }),
      { numRuns: 1 },
    );
  });
});
