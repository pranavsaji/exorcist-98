import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { displayMessage } from '@exorcist-98/core';
import type { Finding, HeuristicFinding, Severity } from '@exorcist-98/core';
import { MAX_TURNS, PLACEMENTS, detonate, modelIdFor } from '@exorcist-98/core/llm';
import type { ChamberClient, DetonationReport, Placement } from '@exorcist-98/core/llm';
import { parse, str } from '../util.js';
import type { Io } from '../util.js';

/** Files detonated by `scan --detonate` unless --detonate-max says otherwise. */
export const DEFAULT_DETONATE_MAX = 10;
export const EX024 = 'EX-024';
const MAX_FILE_BYTES = 1_048_576;

export const DETONATE_HELP = `Usage: exorcist detonate <file> [options]

The Detonation Chamber. Gives the file's text to a sandboxed AI model (Claude
on Amazon Bedrock) that has only fake tools (read_file, run_shell, http_post,
send_message) and planted fake secrets, and shows every tool call the text made
it try. Nothing is ever executed. Behaviour, not wording: it catches reworded
attacks that no signature matches.

Needs AWS credentials and AWS_REGION. Costs at most ${MAX_TURNS} model calls.

Options:
  --as <file|tool-description|tool-result>
                    Where the text is placed in the sandbox (default: file)
  --format <text|json>
                    Output format (default: text)

Exit codes: 0 inert, 1 detonated, 2 usage or setup error, 3 inconclusive.
`;

type Counted = ChamberClient & { counts?: { haiku: number; sonnet: number; failed: number } };

/**
 * The real Bedrock client for the chamber, or false (after saying why) when it
 * cannot run. A test passes its own fake as `real`.
 */
export async function makeChamberClient(io: Io, flag: string, real?: ChamberClient): Promise<ChamberClient | false> {
  if (real) return real;
  if (!process.env['AWS_REGION'] && !process.env['AWS_DEFAULT_REGION']) {
    io.err(`${flag} needs AWS_REGION (for example us-east-1) and AWS credentials (AWS_PROFILE, or keys in the environment).`);
    return false;
  }
  try {
    await import('@aws-sdk/client-bedrock-runtime'); // loaded lazily later; check it exists now
    const { BedrockClientImpl } = await import('@exorcist-98/core/llm');
    return new BedrockClientImpl() as Counted;
  } catch {
    io.err('The Detonation Chamber needs the AWS SDK: npm install @aws-sdk/client-bedrock-runtime');
    return false;
  }
}

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export type Target = { file: string; anchor: Finding };

/**
 * Which files `scan --detonate` sends to the chamber (REQ-02.1): every file
 * with a medium-or-worse finding or an AI (heuristic) finding, worst first,
 * at most `max`. Each keeps its worst finding as the place to report EX-024.
 */
export function pickTargets(findings: readonly Finding[], max: number): { targets: Target[]; skipped: number } {
  const best = new Map<string, Finding>();
  for (const f of findings) {
    if (f.ruleId === EX024) continue;
    if (!(RANK[f.severity] <= RANK.medium || f.source === 'heuristic')) continue;
    const cur = best.get(f.file);
    if (!cur || RANK[f.severity] < RANK[cur.severity] || (RANK[f.severity] === RANK[cur.severity] && f.line < cur.line)) best.set(f.file, f);
  }
  const all = [...best.entries()]
    .map(([file, anchor]) => ({ file, anchor }))
    .sort((a, b) => RANK[a.anchor.severity] - RANK[b.anchor.severity] || a.file.localeCompare(b.file));
  return { targets: all.slice(0, max), skipped: Math.max(0, all.length - max) };
}

/** The attempted calls in one line each, for a finding's rationale. Attacker-influenced, so shown with displayMessage. */
function attemptedLine(r: DetonationReport): string {
  const calls = r.calls.map((c) => `${c.harmful ? 'HARMFUL ' : ''}${c.tool} ${c.args}`).join('; ');
  return `${r.reason} Attempted: ${calls || 'none'}`.slice(0, 1_000);
}

/** The EX-024 finding for a detonated file, placed on its worst existing finding. */
export function detonationFinding(t: Target, r: DetonationReport, def: { title: string; owasp: string[]; fix: string }): HeuristicFinding {
  return {
    source: 'heuristic',
    ruleId: EX024,
    title: def.title,
    severity: 'critical',
    file: t.file,
    line: t.anchor.line,
    col: t.anchor.col,
    span: t.anchor.span,
    owasp: def.owasp,
    fix: def.fix,
    rationale: attemptedLine(r),
    confidence: 'high',
  };
}

export type DetonationRun = { findings: HeuristicFinding[]; summary: string; reports: Array<{ file: string; report: DetonationReport }> };

/** `scan --detonate`: detonate each target file and turn detonations into EX-024 findings. */
export async function runDetonations(
  root: string,
  findings: readonly Finding[],
  client: ChamberClient,
  max: number,
  def: { title: string; owasp: string[]; fix: string },
): Promise<DetonationRun> {
  const { targets, skipped } = pickTargets(findings, max);
  const out: HeuristicFinding[] = [];
  const reports: DetonationRun['reports'] = [];
  let calls = 0;
  const tally = { detonated: 0, inert: 0, inconclusive: 0 };
  for (const t of targets) {
    let text: string;
    try {
      text = readFileSync(join(root, t.file), 'utf8');
    } catch {
      tally.inconclusive++;
      continue;
    }
    const r = await detonate(text, 'file', client, { fileName: basename(t.file) });
    calls += r.modelCalls;
    tally[r.verdict]++;
    reports.push({ file: t.file, report: r });
    if (r.verdict === 'detonated') out.push(detonationFinding(t, r, def));
  }
  let summary = `Detonation Chamber: ${targets.length} file${targets.length === 1 ? '' : 's'} (${tally.detonated} detonated, ${tally.inert} inert, ${tally.inconclusive} inconclusive); ${calls} model call${calls === 1 ? '' : 's'}`;
  if (skipped > 0) summary += `; ${skipped} more file${skipped === 1 ? '' : 's'} skipped by --detonate-max ${max}`;
  const firstInconclusive = reports.find((x) => x.report.verdict === 'inconclusive');
  if (firstInconclusive) summary += `; first inconclusive: ${firstInconclusive.file}: ${firstInconclusive.report.reason}`;
  return { findings: out, summary: `${summary}. No tool call was executed.`, reports };
}

/** Parses --detonate-max: a whole number from 1 to 1000. */
export function parseDetonateMax(raw: string | undefined): number | null {
  if (raw === undefined) return DEFAULT_DETONATE_MAX;
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 && n <= 1_000 ? n : null;
}

/** The transcript of one detonation, for the terminal. Every model-written string goes through displayMessage. */
export function renderTranscript(label: string, r: DetonationReport): string {
  const lines = [`DETONATION CHAMBER  ${displayMessage(label)}  (placed as ${r.placement === 'file' ? 'a file' : r.placement === 'tool-result' ? 'a tool result' : 'a tool description'})`, ''];
  if (r.calls.length === 0) lines.push('  No tool calls attempted.');
  for (const c of r.calls) {
    lines.push(`  turn ${c.turn}  ${displayMessage(c.tool)} ${displayMessage(c.args)}`);
    lines.push(c.harmful ? `          HARMFUL (${c.kind}): ${displayMessage(c.why ?? '')}` : '          harmless');
  }
  lines.push('', `Verdict: ${r.verdict.toUpperCase()}. ${displayMessage(r.reason)}`);
  lines.push(`Model calls: ${r.modelCalls} (${modelIdFor('haiku')}). No tool call was executed; planted secrets are masked.`);
  return `${lines.join('\n')}\n`;
}

export async function detonateCommand(argv: string[], io: Io, deps: { client?: ChamberClient } = {}): Promise<number> {
  const p = parse(argv, { as: { type: 'string' }, format: { type: 'string' }, help: { type: 'boolean', short: 'h' } });
  if (!p.ok) { io.err(`${p.error}\n\n${DETONATE_HELP}`); return 2; }
  if (p.values['help']) { io.out(DETONATE_HELP); return 0; }
  const target = p.positionals[0];
  if (!target || p.positionals.length > 1) { io.err(`Give exactly one file to detonate.\n\n${DETONATE_HELP}`); return 2; }
  const placement = (str(p.values['as']) ?? 'file') as Placement;
  if (!PLACEMENTS.includes(placement)) { io.err(`Unknown --as "${placement}". Use one of: ${PLACEMENTS.join(', ')}.`); return 2; }
  const format = str(p.values['format']) ?? 'text';
  if (format !== 'text' && format !== 'json') { io.err(`Unknown format "${format}". Use text or json.`); return 2; }
  const abs = resolve(target);
  if (!existsSync(abs) || !statSync(abs).isFile()) { io.err(`File not found: ${target}`); return 2; }
  if (statSync(abs).size > MAX_FILE_BYTES) { io.err(`${target} is larger than 1 MB; detonate a smaller part of it.`); return 2; }

  const client = await makeChamberClient(io, 'exorcist detonate', deps.client);
  if (client === false) return 2;
  const report = await detonate(readFileSync(abs, 'utf8'), placement, client, { fileName: basename(abs) });

  if (format === 'json') io.out(`${JSON.stringify({ file: target, model: modelIdFor('haiku'), ...report }, null, 2)}\n`);
  else io.out(renderTranscript(target, report));
  return report.verdict === 'detonated' ? 1 : report.verdict === 'inert' ? 0 : 3;
}
