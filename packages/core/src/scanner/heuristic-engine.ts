import { z } from 'zod';
import { buildHeuristicPrompt, generateNonce } from '../llm/prompts.js';
import type { RepoFile, SignatureFinding, HeuristicFinding, BedrockClient } from '../types.js';
import type { NormalizedText } from '../normalizer.js';

const SUSPICIOUS_PHRASES = ['ignore previous', 'you are now', 'as an ai', 'system prompt'];

const VerdictSchema = z.object({
  verdict:     z.enum(['malicious', 'suspicious', 'benign']),
  threat_class: z.string().min(1),
  quoted_span: z.string().min(1),
  rationale:   z.string().min(1),
});

function base64DecodesAsSuspicious(blob: string): boolean {
  try {
    const decoded = Buffer.from(blob, 'base64').toString('utf8');
    if (decoded.includes('\uFFFD')) return false; // replacement chars → not valid UTF-8
    const lower = decoded.toLowerCase();
    return lower.includes('http') || SUSPICIOUS_PHRASES.some(p => lower.includes(p));
  } catch {
    return false;
  }
}

function shouldEscalate(
  file: RepoFile,
  norm: NormalizedText,
  sigFindings: SignatureFinding[],
): boolean {
  if (sigFindings.some(f => f.file === file.rel)) return true;
  if (norm.hiddenUnicode.length > 0) return true;
  if (norm.base64Candidates.some(base64DecodesAsSuspicious)) return true;
  return false;
}

function topSpan(norm: NormalizedText, sigFindings: SignatureFinding[]): string {
  // Priority: longest hidden-unicode sequence → sig finding span → suspicious base64 decode
  if (norm.hiddenUnicode.length > 0) {
    return norm.hiddenUnicode.map(h => h.char).join('');
  }
  const sigSpan = sigFindings[0]?.span;
  if (sigSpan) return sigSpan;
  const b64 = norm.base64Candidates.find(base64DecodesAsSuspicious);
  if (b64) return Buffer.from(b64, 'base64').toString('utf8').slice(0, 120);
  return norm.original.slice(0, 120);
}

function contextLines(original: string, span: string, windowLines = 3): string {
  const idx = original.indexOf(span);
  if (idx === -1) return '';
  const lines = original.split('\n');
  let charCount = 0;
  let spanLine = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? '';
    charCount += line.length + 1;
    if (charCount > idx) { spanLine = i; break; }
  }
  const start = Math.max(0, spanLine - windowLines);
  const end   = Math.min(lines.length, spanLine + windowLines + 1);
  return lines.slice(start, end).join('\n');
}

export async function runHeuristics(
  file:        RepoFile,
  norm:        NormalizedText,
  sigFindings: SignatureFinding[],
  client:      BedrockClient,
): Promise<HeuristicFinding[]> {
  if (!shouldEscalate(file, norm, sigFindings)) return [];

  const span    = topSpan(norm, sigFindings);
  const context = contextLines(norm.original, span);
  const nonce   = generateNonce();
  const prompt  = buildHeuristicPrompt(span, context, file.rel, nonce);

  // Step 1: triage with Haiku
  const triageResult = await client.call({ model: 'haiku', prompt, maxTokens: 512 });
  if (!triageResult.ok) return [];

  const triageParsed = VerdictSchema.safeParse(safeParseJson(triageResult.raw));
  if (!triageParsed.success) return [];
  if (triageParsed.data.verdict === 'benign') return [];

  // Step 2: judge with Sonnet (only if triage was not benign)
  const judgeResult = await client.call({ model: 'sonnet', prompt, maxTokens: 512 });
  if (!judgeResult.ok) return [];

  const judgeParsed = VerdictSchema.safeParse(safeParseJson(judgeResult.raw));
  if (!judgeParsed.success) return [];

  const verdict = judgeParsed.data;
  if (verdict.verdict === 'benign') return [];

  // Security rule: drop if quoted_span is not verbatim in the original text
  if (!norm.original.includes(verdict.quoted_span)) return [];

  const baseSig = sigFindings[0];
  const confidence = verdict.verdict === 'malicious' ? 'high' : 'medium';

  const finding: HeuristicFinding = {
    source:      'heuristic',
    ruleId:      baseSig?.ruleId ?? 'HEU-000',
    title:       baseSig?.title  ?? verdict.threat_class,
    severity:    baseSig?.severity ?? 'high',
    file:        file.rel,
    line:        baseSig?.line ?? 1,
    col:         baseSig?.col  ?? 1,
    span:        verdict.quoted_span.slice(0, 120),
    owasp:       baseSig?.owasp ?? [],
    fix:         baseSig?.fix   ?? 'Review and remove the flagged content.',
    rationale:   verdict.rationale,
    confidence,
  };

  return [finding];
}

function safeParseJson(raw: string): unknown {
  try {
    // Extract the first JSON object if the model wrapped it in prose
    const match = raw.match(/\{[\s\S]*\}/);
    return match ? JSON.parse(match[0]) : null;
  } catch {
    return null;
  }
}
