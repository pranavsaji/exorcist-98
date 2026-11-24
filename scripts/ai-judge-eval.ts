// Measure the AI judge (judgeText: Haiku triage, then Sonnet judge) on the
// detonation fixtures: 10 reworded attacks no signature catches, 10 benign
// look-alikes. Each text is judged whole, as an agent-facing file would be.
//
//   AWS_PROFILE=<profile> AWS_REGION=<region> pnpm exec tsx scripts/ai-judge-eval.ts
//
// Cost guard: a HARD cap of 50 model calls (every attempt counts, throttling
// retries included). Results are written as measured to docs/AI_JUDGE_EVAL.md.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BedrockClientImpl } from '../packages/core/src/llm/bedrock.js';
import { judgeText } from '../packages/core/src/scanner/heuristic-engine.js';
import type { BedrockClient, BedrockParams, BedrockResult } from '../packages/core/src/types.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const CAP = 50;
type Entry = { file: string; placement: string };
const labels = JSON.parse(readFileSync(join(root, 'fixtures/detonation/labels.json'), 'utf8')) as { attacks: Entry[]; benign: Entry[] };

const inner = new BedrockClientImpl();
let attempts = 0;
let failures = 0;
let firstError: string | null = null;
const client: BedrockClient = {
  async call(p: BedrockParams): Promise<BedrockResult> {
    for (let tryNo = 0; ; tryNo++) {
      if (attempts >= CAP) return { ok: false, error: 'hard cap reached' } as BedrockResult;
      attempts++;
      const r = await inner.call(p);
      if (r.ok) return r;
      const err = String((r as { error?: unknown }).error ?? '');
      if (/thrott|too many requests|rate exceeded|429/i.test(err) && tryNo < 3) { await new Promise((ok) => setTimeout(ok, 2_000 * 2 ** tryNo)); continue; }
      failures++;
      firstError ??= err.split('\n')[0]?.slice(0, 200) ?? err;
      return r;
    }
  },
};

type Row = { file: string; label: 'attack' | 'benign'; flagged: boolean | null; verdict: string; threat: string };
const rows: Row[] = [];
const all = [...labels.attacks.map((e) => ({ ...e, label: 'attack' as const })), ...labels.benign.map((e) => ({ ...e, label: 'benign' as const }))];
for (const e of all) {
  if (attempts + 2 > CAP) { rows.push({ file: e.file, label: e.label, flagged: null, verdict: 'not run', threat: '' }); continue; }
  const text = readFileSync(join(root, 'fixtures/detonation', e.file), 'utf8');
  const before = failures;
  const v = await judgeText(text, e.file, client);
  const failed = failures > before && !v;
  rows.push({ file: e.file, label: e.label, flagged: failed ? null : v !== null, verdict: failed ? 'error' : v ? v.verdict : 'benign', threat: v?.threatClass ?? '' });
  console.log(`${e.label.padEnd(6)} ${e.file.padEnd(40)} ${(failed ? 'error' : v ? `FLAGGED ${v.verdict}` : 'clean').padEnd(22)} ${v?.threatClass ?? ''}`);
  if (rows.length === 1 && failed) { console.error(`first call failed: ${firstError ?? ''}`); break; }
}

const caught = rows.filter((r) => r.label === 'attack' && r.flagged === true).length;
const falseAlarms = rows.filter((r) => r.label === 'benign' && r.flagged === true).length;
const nA = rows.filter((r) => r.label === 'attack').length;
const nB = rows.filter((r) => r.label === 'benign').length;
console.log(`attacks caught: ${caught}/${nA}; false alarms: ${falseAlarms}/${nB}; model calls: ${attempts} (${failures} failed)`);
if (rows.every((r) => r.flagged === null)) { console.error('no results: nothing written'); process.exit(1); }

const cell = (s: string) => s.replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
const md = [
  '# AI judge on reworded attacks: measured results',
  '',
  `- Date: ${new Date().toISOString().slice(0, 10)}`,
  `- What: \`judgeText\` (Claude Haiku 4.5 triage, then Claude Sonnet judge on Amazon Bedrock), each text judged whole`,
  `- Set: \`fixtures/detonation/\`: 10 reworded attacks that no signature catches, 10 benign look-alikes`,
  `- Model calls: ${attempts} (${failures} failed), hard cap ${CAP}`,
  '',
  `**Attacks caught: ${caught} of ${nA}. False alarms: ${falseAlarms} of ${nB}.**`,
  '',
  '| File | Label | Result | Threat class |',
  '|---|---|---|---|',
  ...rows.map((r) => `| \`${r.file}\` | ${r.label} | ${r.flagged === null ? r.verdict : r.flagged ? `flagged (${r.verdict})` : 'clean'} | ${cell(r.threat)} |`),
  '',
  'One run, one set of 20 texts written by us: a small sample, reported exactly as measured.',
  '',
].join('\n');
writeFileSync(join(root, 'docs/AI_JUDGE_EVAL.md'), md);
console.log('wrote docs/AI_JUDGE_EVAL.md');
