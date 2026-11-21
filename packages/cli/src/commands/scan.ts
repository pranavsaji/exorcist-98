import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { loadDefinitions, plainFor, scanRepo, toBadgeSvg, toJson, toMarkdown, toSarif } from '@exorcist-98/core';
import type { Finding, ScanStats } from '@exorcist-98/core';
import { MAX_SPANS_PER_FILE } from '@exorcist-98/core/llm';
import type { BedrockClient } from '@exorcist-98/core/llm';
import { findDefinitionsDir, parse, str, strs } from '../util.js';
import type { Io } from '../util.js';

const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const FORMATS = ['text', 'json', 'sarif', 'markdown', 'badge'] as const;
type Format = (typeof FORMATS)[number];

export const MAX_AI_CALLS_PER_FILE = 2 * MAX_SPANS_PER_FILE;
export const DEFAULT_AI_CALLS = 100;

export const SCAN_HELP = `Usage: exorcist scan <path> [options]

Scan a folder or file for attacks on AI coding agents.

Options:
  --format <text|json|sarif|markdown|badge>
                                        Output format (default: text). "badge" writes an
                                        SVG README badge: "exorcised" or "possessed".
  --fail-on <critical|high|medium|low|none>
                                        Exit 1 if a finding is at least this bad (default: high)
  --ignore <path>                       Skip a path prefix (repeatable). A .exorcistignore
                                        file in the scanned folder lists more, one per line.
  --definitions <dir>                   Folder of virus definitions (YAML)
  --output <file>                       Write the report to a file instead of stdout
  --ai                                  Also ask an AI judge (Claude on Amazon Bedrock) about
                                        suspicious spans. Needs AWS credentials and AWS_REGION.
                                        Each flagged file costs up to ${MAX_AI_CALLS_PER_FILE} model calls.
  --ai-max-calls <n>                    Stop asking the AI after n model calls (default ${DEFAULT_AI_CALLS})
`;

function readIgnoreFile(root: string): string[] {
  const file = join(root, '.exorcistignore');
  if (!existsSync(file)) return [];
  return readFileSync(file, 'utf8')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

export function isIgnored(rel: string, prefixes: readonly string[]): boolean {
  return prefixes.some((p) => {
    const clean = p.replace(/^\.\//, '').replace(/\/+$/, '');
    return clean !== '' && (rel === clean || rel.startsWith(`${clean}/`));
  });
}

function renderText(findings: Finding[], stats: ScanStats): string {
  if (findings.length === 0) return `No threats found in ${stats.filesScanned} files.\n`;
  const sorted = [...findings].sort(
    (a, b) => (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9) || a.file.localeCompare(b.file) || a.line - b.line,
  );
  const lines: string[] = [];
  for (const f of sorted) {
    lines.push(`${f.severity.toUpperCase().padEnd(8)} ${f.file}:${f.line}:${f.col}  ${plainFor(f.ruleId, f.title).headline} (${f.ruleId})`);
    lines.push(`         found: ${f.span}`);
    lines.push(`         fix:   ${f.fix.replace(/\s+/g, ' ').trim()}`);
  }
  const counts = (['critical', 'high', 'medium', 'low'] as const)
    .map((s) => ({ s, n: findings.filter((f) => f.severity === s).length }))
    .filter((c) => c.n > 0)
    .map((c) => `${c.n} ${c.s}`)
    .join(', ');
  lines.push('', `${findings.length} threat${findings.length === 1 ? '' : 's'} in ${stats.filesScanned} files (${counts}).`);
  return `${lines.join('\n')}\n`;
}


type AiClient = { client: BedrockClient; summary: () => string };

/**
 * The AI judge for `--ai` (S-020): the real Bedrock client behind a call
 * budget, so a large repository cannot run up an unbounded bill. Returns
 * false (after printing why) when it cannot run.
 */
export async function makeAiClient(rawMax: string | undefined, io: Io, real?: BedrockClient & { counts?: { haiku: number; sonnet: number; failed: number } }): Promise<AiClient | false> {
  const max = rawMax === undefined ? DEFAULT_AI_CALLS : Number(rawMax);
  if (!Number.isInteger(max) || max < 1 || max > 10_000) { io.err('--ai-max-calls must be a whole number from 1 to 10000.'); return false; }
  if (!real && !process.env['AWS_REGION'] && !process.env['AWS_DEFAULT_REGION']) {
    io.err('--ai needs AWS_REGION (for example us-east-1) and AWS credentials (AWS_PROFILE, or keys in the environment).');
    return false;
  }
  let inner = real;
  if (!inner) {
    try {
      await import('@aws-sdk/client-bedrock-runtime'); // loaded lazily later; check it exists now
      const { BedrockClientImpl } = await import('@exorcist-98/core/llm');
      inner = new BedrockClientImpl();
    } catch {
      io.err('The AI judge needs the AWS SDK: npm install @aws-sdk/client-bedrock-runtime');
      return false;
    }
  }
  const client = inner;
  let used = 0;
  let skipped = 0;
  let firstError: string | null = null;
  const budgeted: BedrockClient = {
    async call(params) {
      if (used >= max) { skipped++; return { ok: false, error: 'AI call budget used up' }; }
      used++;
      const r = await client.call(params);
      if (!r.ok && firstError === null) firstError = r.error.split('\n')[0]?.slice(0, 200) ?? r.error;
      return r;
    },
  };
  return {
    client: budgeted,
    summary: () => {
      const c = client.counts;
      let line = `AI judge: ${used} model call${used === 1 ? '' : 's'}`;
      if (c) line += ` (${c.haiku} triage, ${c.sonnet} judge, ${c.failed} failed)`;
      if (skipped > 0) line += `; ${skipped} more skipped by --ai-max-calls ${max}`;
      if (firstError) line += `; first error: ${firstError}`;
      return `${line}.`;
    },
  };
}

export async function scanCommand(argv: string[], io: Io): Promise<number> {
  const p = parse(argv, {
    format: { type: 'string' }, 'fail-on': { type: 'string' }, ignore: { type: 'string', multiple: true },
    definitions: { type: 'string' }, output: { type: 'string' }, help: { type: 'boolean', short: 'h' },
    ai: { type: 'boolean' }, 'ai-max-calls': { type: 'string' },
  });
  if (!p.ok) { io.err(`${p.error}\n\n${SCAN_HELP}`); return 2; }
  if (p.values['help']) { io.out(SCAN_HELP); return 0; }

  const target = p.positionals[0];
  if (!target || p.positionals.length > 1) { io.err(`Give exactly one path to scan.\n\n${SCAN_HELP}`); return 2; }

  const format = (str(p.values['format']) ?? 'text') as Format;
  if (!FORMATS.includes(format)) { io.err(`Unknown format "${format}". Use one of: ${FORMATS.join(', ')}.`); return 2; }
  const failOn = str(p.values['fail-on']) ?? 'high';
  if (failOn !== 'none' && !(failOn in RANK)) { io.err(`Unknown --fail-on "${failOn}". Use critical, high, medium, low or none.`); return 2; }

  const abs = resolve(target);
  if (!existsSync(abs)) { io.err(`Path not found: ${target}`); return 2; }
  const isFile = statSync(abs).isFile();
  const root = isFile ? dirname(abs) : abs;
  const only = isFile ? basename(abs) : null;

  const defsDir = findDefinitionsDir(str(p.values['definitions']));
  if (!defsDir) { io.err('Could not find the virus definitions. Pass --definitions <dir> or set EXORCIST_DEFINITIONS.'); return 2; }

  // A scan with no definitions would report "clean" for everything. Refuse.
  try {
    if ((await loadDefinitions(defsDir)).length === 0) {
      io.err(`No virus definitions were found in ${defsDir}, so the scan would find nothing. Check --definitions.`);
      return 2;
    }
  } catch (err) {
    io.err(`Could not load the virus definitions from ${defsDir}: ${String(err).split('\n')[0]}`);
    return 2;
  }

  const ignore = [...strs(p.values['ignore']), ...readIgnoreFile(root)];
  const findings: Finding[] = [];
  let stats: ScanStats = { filesScanned: 0, filesSkipped: 0, findingsTotal: 0, durationMs: 0 };
  let counted = 0;
  const ai = p.values['ai'] === true ? await makeAiClient(str(p.values['ai-max-calls']), io) : null;
  if (ai === false) return 2;
  try {
    for await (const ev of scanRepo(root, { definitionsDir: defsDir, ...(ai ? { bedrockClient: ai.client } : {}) })) {
      if (ev.type === 'finding') {
        if (only !== null && ev.finding.file !== only) continue;
        if (isIgnored(ev.finding.file, ignore)) continue;
        findings.push(ev.finding);
      } else if (ev.type === 'file') {
        if ((only === null || ev.file.rel === only) && !isIgnored(ev.file.rel, ignore)) counted++;
      } else if (ev.type === 'done') {
        stats = ev.stats;
      }
    }
  } catch (err) {
    io.err(`The scan failed: ${String(err).split('\n')[0]}`);
    return 2;
  }
  stats = { ...stats, filesScanned: counted, findingsTotal: findings.length };
  if (ai) io.err(ai.summary());

  const body =
    format === 'json' ? `${JSON.stringify(toJson(findings, stats, { target }), null, 2)}\n`
    : format === 'sarif' ? `${JSON.stringify(toSarif(findings, root), null, 2)}\n`
    : format === 'markdown' ? toMarkdown(findings, stats)
    : format === 'badge' ? toBadgeSvg(findings)
    : renderText(findings, stats);

  const outFile = str(p.values['output']);
  if (outFile) writeFileSync(outFile, body, 'utf8');
  else io.out(body);

  if (failOn === 'none') return 0;
  const limit = RANK[failOn] ?? 0;
  return findings.some((f) => (RANK[f.severity] ?? 9) <= limit) ? 1 : 0;
}
