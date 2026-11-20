// One real Amazon Bedrock check of the AI heuristic layer (L-020).
//
//   AWS_PROFILE=<profile> AWS_REGION=<region> pnpm exec tsx scripts/bedrock-smoke.ts
//
// Optional: EXORCIST_BEDROCK_HAIKU / EXORCIST_BEDROCK_SONNET to use other model
// ids or inference profiles. It makes at most four model calls: a raw call to
// each model, then triage and judge on one defanged Haunted Repo sample.
// Prints verdicts and timings only; never file contents, prompts or credentials.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { BedrockClientImpl, modelIdFor } from '../packages/core/src/llm/bedrock.js';
import { runHeuristics } from '../packages/core/src/scanner/heuristic-engine.js';
import { normalize } from '../packages/core/src/normalizer.js';
import type { BedrockParams, BedrockResult, RepoFile, SignatureFinding } from '../packages/core/src/types.js';

const root = join(import.meta.dirname, '..');
if (!process.env['AWS_REGION']) {
  console.error('Set AWS_REGION (and AWS_PROFILE) first.');
  process.exit(2);
}

/** Wraps the real client to record each call's model, outcome and time. */
const calls: { model: string; ok: boolean; ms: number; error?: string }[] = [];
const real = new BedrockClientImpl();
const client = {
  async call(p: BedrockParams): Promise<BedrockResult> {
    const t = Date.now();
    const r = await real.call(p);
    calls.push({ model: modelIdFor(p.model), ok: r.ok, ms: Date.now() - t, ...(r.ok ? {} : { error: r.error.split('\n')[0]?.slice(0, 200) }) });
    return r;
  },
};

// 1. Can each model be reached at all?
for (const model of ['haiku', 'sonnet'] as const) {
  const r = await client.call({ model, prompt: 'Reply with exactly: {"ok":true}', maxTokens: 20 });
  console.log(`reach ${model} (${modelIdFor(model)}): ${r.ok ? 'ok' : `FAILED: ${r.error.split('\n')[0]?.slice(0, 200)}`}`);
}

// 2. The real triage + judge path on a defanged sample with a signature hit.
const rel = 'EX-002-ai-instructions.md';
const text = readFileSync(join(root, 'fixtures/haunted-repo', rel), 'utf8');
const norm = normalize(text, 'instruction');
const lineNo = text.split('\n').findIndex((l) => /ignore (all )?previous/i.test(l));
const line = text.split('\n')[lineNo] ?? '';
const span = (/ignore (all )?previous[^.\n]*/i.exec(line) ?? [''])[0];
const file: RepoFile = { path: join(root, 'fixtures/haunted-repo', rel), rel, role: 'instruction', sizeBytes: text.length };
const sig: SignatureFinding = {
  source: 'signature', ruleId: 'EX-002', title: 'Instructions addressed to AI', severity: 'high',
  file: rel, line: lineNo + 1, col: 1, span, owasp: ['LLM01:2025 Prompt Injection'], fix: 'Remove it.',
} as SignatureFinding;

const findings = await runHeuristics(file, norm, span ? [sig] : [], client);
console.log(`\nheuristic on ${rel}: ${findings.length} finding(s)`);
for (const f of findings) {
  console.log(`  confidence ${f.confidence}; quoted span found verbatim in the file: ${text.includes(f.span)}`);
}
console.log('\ncalls:');
for (const c of calls) console.log(`  ${c.model}  ${c.ok ? 'ok' : 'failed'}  ${c.ms} ms${c.error ? `  ${c.error}` : ''}`);
process.exit(calls.every((c) => c.ok) ? 0 : 1);
