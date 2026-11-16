import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runSignatures } from '../scanner/signature-engine.js';
import { normalize } from '../normalizer.js';
import type { RepoFile } from '../types.js';
import type { VirusDefinition } from '../definitions/schema.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = resolve(__dirname, '../../../../fixtures/haunted-repo');

const fixtureFiles = readdirSync(FIXTURE_DIR)
  .filter(f => /^EX-\d{3}-/.test(f))
  .map(f => join(FIXTURE_DIR, f));

function makeFile(absPath: string, rel: string): RepoFile {
  return { path: absPath, rel, role: 'docs', sizeBytes: 100 };
}

function makeDisabledDef(): VirusDefinition {
  return {
    id: 'EX-999', title: 'disabled', severity: 'low',
    applies_to: ['docs'], match: { regex: '.' },
    owasp: ['LLM01'], fix: 'n/a', enabled: false,
  };
}

describe('Signature engine property-based tests', () => {
  // PBT-SIG-01: random printable ASCII that doesn't match real patterns → no findings
  it('PBT-SIG-01: random safe strings produce no findings from a non-matching rule', () => {
    const safeDef: VirusDefinition = {
      id: 'EX-998', title: 'safe', severity: 'low',
      applies_to: ['docs'], match: { regex: '__NEVER_MATCHES_XYZZY__' },
      owasp: ['LLM01'], fix: 'n/a', enabled: true,
    };
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), (text) => {
        const file = makeFile('/repo/README.md', 'README.md');
        const norm = normalize(text, 'docs');
        const findings = runSignatures(file, norm, [safeDef]);
        expect(findings).toHaveLength(0);
        return true;
      }),
    );
  });

  // PBT-SIG-02: scanning is idempotent — same file + same defs → same findings
  it('PBT-SIG-02: scanning is idempotent', () => {
    const matchingDef: VirusDefinition = {
      id: 'EX-997', title: 'test', severity: 'high',
      applies_to: ['docs'], match: { regex: 'DEFANGED' },
      owasp: ['LLM01'], fix: 'n/a', enabled: true,
    };
    fc.assert(
      fc.property(fc.constantFrom(...fixtureFiles), (fp) => {
        const text = readFileSync(fp, 'utf8');
        const file = makeFile(fp, fp.split('/').pop() ?? fp);
        const norm = normalize(text, 'docs');
        const r1 = runSignatures(file, norm, [matchingDef]);
        const r2 = runSignatures(file, norm, [matchingDef]);
        expect(r1).toEqual(r2);
        return true;
      }),
      { numRuns: fixtureFiles.length },
    );
  });

  // PBT-SIG-03: a disabled rule never produces a finding
  it('PBT-SIG-03: a disabled rule never fires', () => {
    fc.assert(
      fc.property(fc.constantFrom(...fixtureFiles), (fp) => {
        const text = readFileSync(fp, 'utf8');
        const file = makeFile(fp, fp.split('/').pop() ?? fp);
        const norm = normalize(text, 'docs');
        const findings = runSignatures(file, norm, [makeDisabledDef()]);
        expect(findings).toHaveLength(0);
        return true;
      }),
      { numRuns: fixtureFiles.length },
    );
  });

  // PBT-SIG-04: span is never longer than 120 chars (+1 for '…')
  it('PBT-SIG-04: span length never exceeds 121 characters', () => {
    const wideDef: VirusDefinition = {
      id: 'EX-996', title: 'wide', severity: 'low',
      applies_to: ['docs'], match: { regex: 'DEFANGED[\\s\\S]{0,500}' },
      owasp: ['LLM01'], fix: 'n/a', enabled: true,
    };
    fc.assert(
      fc.property(fc.constantFrom(...fixtureFiles), (fp) => {
        const text = readFileSync(fp, 'utf8');
        const file = makeFile(fp, fp.split('/').pop() ?? fp);
        const norm = normalize(text, 'docs');
        const findings = runSignatures(file, norm, [wideDef]);
        for (const f of findings) {
          expect(f.span.length).toBeLessThanOrEqual(121);
        }
        return true;
      }),
      { numRuns: fixtureFiles.length },
    );
  });
});
