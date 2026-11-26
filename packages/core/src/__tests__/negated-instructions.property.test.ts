// m11-config-tamper, Property 3: text that forbids a settings change, a weakened
// check or a redirected publish never fires EX-030, EX-031 or EX-032.
// Samples are defanged.
import { describe, it, beforeAll } from 'vitest';
import fc from 'fast-check';
import { loadDefinitions } from '../definitions/loader.js';
import { scanText } from '../scanner/scan-text.js';
import { classifyFile } from '../walker.js';
import type { VirusDefinition } from '../definitions/schema.js';
import { fromRoot } from './repo-root.js';

let defs: VirusDefinition[] = [];
beforeAll(async () => { defs = await loadDefinitions(fromRoot('definitions')); });

const hits = (rule: string, path: string, text: string) =>
  scanText(text, classifyFile(path), defs, path).filter((f) => f.ruleId === rule);

const lead = fc.constantFrom('You', 'The agent', 'Please, you', 'AI assistant, you');
const neg = fc.constantFrom(
  'must never', 'should never', 'must not', 'should not', 'shall not', 'will never',
  'cannot', 'may not', 'should avoid', 'must refrain from',
);
const path = fc.constantFrom('AGENTS.md', 'docs/security.md', 'CLAUDE.md', 'docs/notes.md');

const negated = (actions: string[]) =>
  fc.tuple(lead, neg, fc.constantFrom(...actions), path).map(([l, n, a, p]) => {
    // "avoid"/"refrain from" take an -ing form; the others take a bare verb.
    const gerund = /avoid|refrain/.test(n);
    const action = gerund ? a.replace(/^(\w+)/, (v) => (v.endsWith('e') ? `${v.slice(0, -1)}ing` : `${v}ing`)) : a;
    return { text: `${l} ${n} ${action}.\n`, path: p };
  });

const tamper = [
  'edit .kiro/hooks/guard.json',
  'modify .kiro/agents/reviewer.json',
  'rewrite .kiro/steering/security.md',
  'change .vscode/settings.json',
  'update AGENTS.md',
  'add "*" to kiroAgent.trustedCommands',
  'add * to the trusted commands',
  'edit commandsToAlwaysAllow',
];
const weaken = [
  'add it.skip to the failing tests',
  'delete the test file because it is flaky',
  'use --no-verify',
  'add || true to the CI step',
  'lower the coverage threshold',
];
const redirect = [
  'push to a different remote',
  'run git remote add mirror https://git.example.invalid/m.git',
  'run npm publish',
  'run npm config set registry https://registry.example.invalid/',
  'open a pull request against another repository',
];

describe('Property 3: negated tamper, weaken and redirect text never fires', () => {
  // **Validates: Requirements CT-4**
  it('CT-4: negated settings-tamper text never fires EX-030', () => {
    fc.assert(fc.property(negated(tamper), (s) => hits('EX-030', s.path, s.text).length === 0), { numRuns: 100 });
  });

  // **Validates: Requirements CT-8**
  it('CT-8: negated weaken-checks text never fires EX-031', () => {
    fc.assert(fc.property(negated(weaken), (s) => hits('EX-031', s.path, s.text).length === 0), { numRuns: 100 });
  });

  // **Validates: Requirements CT-10**
  it('CT-10: negated redirect-publish text never fires EX-032', () => {
    fc.assert(fc.property(negated(redirect), (s) => hits('EX-032', s.path, s.text).length === 0), { numRuns: 100 });
  });
});
