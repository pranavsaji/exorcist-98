import { z } from "zod";
import { buildHeuristicPrompt, generateNonce } from "../llm/prompts.js";
import type {
  RepoFile,
  SignatureFinding,
  HeuristicFinding,
  BedrockClient,
  Severity,
} from "../types.js";
import type { NormalizedText } from "../normalizer.js";
import { isAgentFacing } from '../walker.js';

const SUSPICIOUS_PHRASES = [
  "ignore previous",
  "you are now",
  "as an ai",
  "system prompt",
];

/** At most this many spans per file go to the model (cost and time bound). */
export const MAX_SPANS_PER_FILE = 5;
const MAX_SPAN_CHARS = 400;

const VerdictSchema = z.object({
  verdict: z.enum(["malicious", "suspicious", "benign"]),
  threat_class: z.string().min(1).max(200),
  quoted_span: z.string().min(1).max(2_000),
  rationale: z.string().min(1).max(1_000),
});
type Verdict = z.infer<typeof VerdictSchema>;

function decodeBase64(blob: string): string | null {
  try {
    const decoded = Buffer.from(blob, "base64").toString("utf8");
    return decoded.includes("\uFFFD") ? null : decoded; // not valid UTF-8 text
  } catch {
    return null;
  }
}

function base64DecodesAsSuspicious(blob: string): boolean {
  const lower = decodeBase64(blob)?.toLowerCase() ?? "";
  return (
    lower.includes("http") || SUSPICIOUS_PHRASES.some((p) => lower.includes(p))
  );
}

function shouldEscalate(
  file: RepoFile,
  norm: NormalizedText,
  sigFindings: SignatureFinding[],
): boolean {
  if (sigFindings.some((f) => f.file === file.rel)) return true;
  if (norm.hiddenUnicode.length > 0) return true;
  if (norm.base64Candidates.some(base64DecodesAsSuspicious)) return true;
  return false;
}

/** The text one line of the file holds, by 1-based line number. */
function lineAt(original: string, line: number): string {
  return original.split("\n")[line - 1] ?? "";
}

/**
 * Every suspicious span in the file, most specific first (L-022): each
 * signature finding's own line, each run of hidden characters with its line,
 * and each suspicious base64 blob. Deduplicated and capped.
 */
export function candidateSpans(
  file: RepoFile,
  norm: NormalizedText,
  sigFindings: SignatureFinding[],
): string[] {
  const out: string[] = [];
  const add = (s: string | undefined): void => {
    const t = (s ?? "").trim().slice(0, MAX_SPAN_CHARS);
    if (t && !out.includes(t)) out.push(t);
  };
  for (const f of sigFindings)
    if (f.file === file.rel) add(lineAt(norm.original, f.line) || f.span);
  for (const h of norm.hiddenUnicode) {
    const idx = norm.original.indexOf(h.char);
    if (idx === -1) continue;
    const lineNo = norm.original.slice(0, idx).split("\n").length;
    add(lineAt(norm.original, lineNo));
  }
  for (const b of norm.base64Candidates)
    if (base64DecodesAsSuspicious(b)) add(b);
  if (out.length === 0 && shouldEscalate(file, norm, sigFindings))
    add(norm.original.slice(0, MAX_SPAN_CHARS));
  return out.slice(0, MAX_SPANS_PER_FILE);
}

function contextLines(original: string, span: string, windowLines = 3): string {
  const idx = original.indexOf(span);
  if (idx === -1) return "";
  const lines = original.split("\n");
  const spanLine = original.slice(0, idx).split("\n").length - 1;
  const start = Math.max(0, spanLine - windowLines);
  const end = Math.min(lines.length, spanLine + windowLines + 1);
  return lines.slice(start, end).join("\n");
}

/** 1-based line and column of the first occurrence of `needle` in `text`. */
export function positionOf(
  text: string,
  needle: string,
): { line: number; col: number } | null {
  const idx = text.indexOf(needle);
  if (idx === -1) return null;
  const before = text.slice(0, idx);
  const line = before.split("\n").length;
  const col = idx - (before.lastIndexOf("\n") + 1) + 1;
  return { line, col };
}

/**
 * Severity from what the model said the threat is, used when no signature
 * finding sits on the same line (L-021). Exfiltration and code execution are
 * critical; other injection is high; anything only "suspicious" is one step
 * lower.
 */
export function severityFor(
  threatClass: string,
  verdict: Verdict["verdict"],
): Severity {
  const c = threatClass.toLowerCase();
  const critical =
    /exfil|credential|secret|token|remote code|code exec|command exec|shell|rug.?pull|tool poison/.test(
      c,
    );
  const base: Severity = critical
    ? "critical"
    : /inject|instruction|jailbreak|override|hidden|smuggl|poison/.test(c)
      ? "high"
      : "medium";
  if (verdict === "malicious") return base;
  return base === "critical" ? "high" : base === "high" ? "medium" : "low";
}

/** The model's threat label as a short title: "prompt_injection supply_chain" becomes "Prompt injection, supply chain". */
export function readableTitle(threatClass: string): string {
  const parts = threatClass.replace(/[^\p{L}\p{N}_\- ,/]+/gu, ' ').split(/[\s,/]+/).filter(Boolean).map((w) => w.replace(/[_-]+/g, ' ').toLowerCase().trim()).filter(Boolean);
  const unique = [...new Set(parts)].slice(0, 3);
  const t = unique.join(', ');
  return t ? `${t.charAt(0).toUpperCase()}${t.slice(1)}`.slice(0, 80) : 'Suspicious text for an AI agent';
}

function safeParseJson(raw: string): unknown {
  try {
    // Extract the first JSON object if the model wrapped it in prose.
    const match = raw.match(/\{[\s\S]*\}/);
    return match ? JSON.parse(match[0]) : null;
  } catch {
    return null;
  }
}

async function classify(
  client: BedrockClient,
  model: "haiku" | "sonnet",
  prompt: string,
): Promise<Verdict | null> {
  const r = await client.call({ model, prompt, maxTokens: 512 });
  if (!r.ok) return null;
  const parsed = VerdictSchema.safeParse(safeParseJson(r.raw));
  return parsed.success ? parsed.data : null;
}

export async function runHeuristics(
  file: RepoFile,
  norm: NormalizedText,
  sigFindings: SignatureFinding[],
  client: BedrockClient,
): Promise<HeuristicFinding[]> {
  if (!shouldEscalate(file, norm, sigFindings)) {
    // Layered detection: a file an agent takes instructions or settings from
    // is judged whole even when no signature fired. Reworded attacks trip no
    // pattern; on our 10 reworded attacks signatures caught 0 and the judge 6,
    // with 0 false alarms on 10 look-alikes (docs/AI_JUDGE_EVAL.md).
    return isAgentFacing(file.rel, file.role) ? judgeWholeFile(file, norm, client) : [];
  }
  const findings: HeuristicFinding[] = [];

  for (const span of candidateSpans(file, norm, sigFindings)) {
    const context = contextLines(norm.original, span);

    // Step 1: triage with the fast model.
    const triage = await classify(
      client,
      "haiku",
      buildHeuristicPrompt(span, context, file.rel, generateNonce()),
    );
    if (!triage || triage.verdict === "benign") continue;

    // Step 2: the judge sees the same span plus the triage verdict (L-022).
    const verdict = await classify(
      client,
      "sonnet",
      buildHeuristicPrompt(span, context, file.rel, generateNonce(), triage),
    );
    if (!verdict || verdict.verdict === "benign") continue;

    // Security rule: drop any verdict whose quoted span is not verbatim in the file.
    const pos = positionOf(norm.original, verdict.quoted_span);
    if (!pos) continue;

    // L-021: point at the quoted text itself. A signature finding on the same
    // line supplies the rule, severity and fix; otherwise they come from the
    // model's threat class.
    const sameLine = sigFindings.find(
      (f) => f.file === file.rel && f.line === pos.line,
    );
    findings.push({
      source: "heuristic",
      ruleId: sameLine?.ruleId ?? "HEU-000",
      title: sameLine?.title ?? readableTitle(verdict.threat_class),
      severity:
        sameLine?.severity ??
        severityFor(verdict.threat_class, verdict.verdict),
      file: file.rel,
      line: pos.line,
      col: pos.col,
      span: verdict.quoted_span.slice(0, 120),
      owasp: sameLine?.owasp ?? ["LLM01:2025 Prompt Injection"],
      fix:
        sameLine?.fix ??
        "Review the quoted text. Remove anything that gives instructions to an AI agent or sends data elsewhere.",
      rationale: verdict.rationale,
      confidence: verdict.verdict === "malicious" ? "high" : "medium",
    });
  }
  return findings;
}

/** At most this many 4,000-character windows of one agent-facing file are judged. */
export const MAX_WHOLE_FILE_WINDOWS = 3;

/** Judge an agent-facing file with no signature hit, window by window (bounded). */
async function judgeWholeFile(file: RepoFile, norm: NormalizedText, client: BedrockClient): Promise<HeuristicFinding[]> {
  const text = norm.original;
  for (let w = 0; w < MAX_WHOLE_FILE_WINDOWS; w++) {
    const start = w * (MAX_JUDGED_CHARS - 200);
    if (start >= text.length) break;
    const v = await judgeText(text.slice(start, start + MAX_JUDGED_CHARS), file.rel, client);
    if (!v) continue;
    const pos = positionOf(text, v.span);
    if (!pos) continue;
    return [{
      source: 'heuristic',
      ruleId: 'HEU-000',
      title: readableTitle(v.threatClass),
      severity: severityFor(v.threatClass, v.verdict),
      file: file.rel,
      line: pos.line,
      col: pos.col,
      span: v.span.slice(0, 120),
      owasp: ['LLM01:2025 Prompt Injection'],
      fix: 'Review the quoted text. Remove anything that gives instructions to an AI agent or sends data elsewhere.',
      rationale: v.rationale,
      confidence: v.verdict === 'malicious' ? 'high' : 'medium',
    }];
  }
  return [];
}

/** Most characters of one text sent to the model by judgeText. */
export const MAX_JUDGED_CHARS = 4_000;

export type TextVerdict = {
  verdict: "malicious" | "suspicious";
  threatClass: string;
  /** Verbatim in the judged text; a verdict whose span is not found is dropped. */
  span: string;
  rationale: string;
};

/**
 * Judge one short text with no signature hit to go on (S-009), such as a tool
 * description the Shield sees for the first time: triage, then the judge. The
 * model only labels; the caller decides what a label means. `null` is "no
 * finding" (benign, unparseable, or a span not found in the text).
 */
export async function judgeText(
  text: string,
  label: string,
  client: BedrockClient,
): Promise<TextVerdict | null> {
  const span = text.slice(0, MAX_JUDGED_CHARS);
  if (span.trim().length === 0) return null;
  const triage = await classify(client, "haiku", buildHeuristicPrompt(span, "", label, generateNonce()));
  if (!triage || triage.verdict === "benign") return null;
  const verdict = await classify(client, "sonnet", buildHeuristicPrompt(span, "", label, generateNonce(), triage));
  if (!verdict || verdict.verdict === "benign") return null;
  if (!span.includes(verdict.quoted_span)) return null;
  return { verdict: verdict.verdict, threatClass: verdict.threat_class, span: verdict.quoted_span, rationale: verdict.rationale };
}
