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
import { findSecrets, redact } from '../secrets-check.js';

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
  maskedUpstream = 0,
): Promise<Verdict | null> {
  // The sink: whatever path built the prompt, no secret leaves in it, and
  // the judge is told when values were masked (masking is itself a signal).
  const masked = maskForModel(prompt);
  const runs = maskedUpstream + countMaskedRuns(prompt, masked);
  const note = runs > 0
    ? `Note from the scanner: ${runs} credential-like value${runs === 1 ? ' was' : 's were'} replaced by asterisks of the same length before you saw this text. Judge the rest as usual; masked values are not evidence either way.\n\n`
    : '';
  const r = await client.call({ model, prompt: note + masked, maxTokens: 512 });
  if (!r.ok) return null;
  const parsed = VerdictSchema.safeParse(safeParseJson(r.raw));
  return parsed.success ? parsed.data : null;
}

/** Files that hold credentials by design: never sent whole to the model. */
const CREDENTIAL_FILE = /(^|\/)(\.env(\..*)?|[^/]*\.local\.json|claude_desktop_config\.json|\.npmrc|\.netrc|credentials(\.json)?)$/i;
const SECRET_KEY_WORD = /(?:key|token|secret|password|passwd|pwd|auth|credential|cookie|session)/i;
/** A key is one identifier-like token: `API_KEY`, `apiKey`, `//registry.npmjs.org/:_authToken`. No spaces. */
const KEY_TOKEN = /^[A-Za-z0-9_.\-\/:@]{1,128}$/;

/**
 * Under a secret-named key, every single-token value is masked (fail closed),
 * whatever its length or characters. It stays visible only when it is clearly
 * prose or a command, so masking can never hide an instruction from the judge.
 */
export function looksLikeSecretValue(v: string): boolean {
  if (v.length < 4) return false;
  if (/\s/.test(v)) return false;                                         // prose: an instruction needs words
  if (/^[a-z][a-z0-9+.\-]*:\/\//i.test(v)) return false;                   // a URL: its userinfo is masked separately
  if (/^(~|\/|\.\.?\/|[A-Za-z]:\\)/.test(v)) return false;               // file paths
  if (/[|;&$`<>()]/.test(v)) return false;                                // shell syntax
  if (decodesToText(v)) return false;                                     // encoded readable content, not a key
  return true;                                                            // any other single token: fail closed
}

/** user:password@ in any URL, masked wherever it appears (same length). */
const URL_USERINFO = /\b([a-z][a-z0-9+.\-]{0,20}:\/\/)([^\s\/@:"']{1,256}):([^\s\/@"']{1,512})@/gi;

/** True for base64 or hex that decodes to readable words: content the judge must see. */
function decodesToText(v: string): boolean {
  let bytes: Buffer | null = null;
  if (/^[A-Za-z0-9+\/]{16,}={0,2}$/.test(v) && v.length % 4 === 0) bytes = Buffer.from(v, 'base64');
  else if (/^(?:[0-9a-f]{2}){12,}$/i.test(v)) bytes = Buffer.from(v, 'hex');
  if (!bytes || bytes.length < 12) return false;
  let printable = 0;
  for (const b of bytes) if ((b >= 0x20 && b < 0x7f) || b === 0x0a) printable++;
  return printable / bytes.length > 0.9 && /[A-Za-z]{3,}\s+[A-Za-z]{2,}/.test(bytes.toString('latin1'));
}

const isSecretKey = (k: string): boolean => KEY_TOKEN.test(k) && SECRET_KEY_WORD.test(k);
const stars = (n: number): string => '*'.repeat(n);

/** Strip one pair of surrounding quotes; returns the inner value and its offset. */
function unquote(v: string): { value: string; at: number } {
  const q = v[0];
  if ((q === '"' || q === "'") && v.length >= 2 && v.endsWith(q)) return { value: v.slice(1, -1), at: 1 };
  return { value: v, at: 0 };
}

/** Mask every credential-looking assignment on one line, in place and at the same length. Linear. */
function maskAssignmentLine(line: string): string {
  // Most lines have nothing to mask: only split into characters when needed.
  if (!SECRET_KEY_WORD.test(line)) return line;
  let chars: string[] | null = null;
  const maskRange = (from: number, len: number): void => {
    chars ??= line.split('');
    for (let i = from; i < from + len; i++) chars[i] = '*';
  };

  // 1. "key": "value" pairs (JSON), any number per line, scanned with indexOf.
  let from = 0;
  for (;;) {
    const colon = line.indexOf('":', from);
    if (colon === -1) break;
    from = colon + 2;
    const keyStart = line.lastIndexOf('"', colon - 1);
    if (keyStart === -1) continue;
    let i = colon + 2;
    while (i < line.length && (line[i] === ' ' || line[i] === '\t')) i++;
    if (line[i] !== '"') continue;
    const valEnd = line.indexOf('"', i + 1);
    if (valEnd === -1) break;
    const key = line.slice(keyStart + 1, colon);
    const value = line.slice(i + 1, valEnd);
    if (isSecretKey(key) && looksLikeSecretValue(value)) maskRange(i + 1, value.length);
    from = valEnd + 1;
  }

  // 2. KEY=value tokens anywhere on the line (env, shell, .npmrc, ini).
  const tokenRe = /\S+/g;
  let m: RegExpExecArray | null;
  while ((m = tokenRe.exec(line)) !== null) {
    const tok = m[0];
    const eq = tok.indexOf('=');
    if (eq <= 0) continue;
    const key = tok.slice(0, eq).replace(/^export$/, '');
    const { value, at } = unquote(tok.slice(eq + 1));
    if (isSecretKey(key) && looksLikeSecretValue(value)) maskRange(m.index + eq + 1 + at, value.length);
  }

  // 3. YAML / ini "key: value" or "key:value" at the start of the line.
  const lead = line.length - line.trimStart().length;
  const body = line.slice(lead);
  const colon = body.indexOf(':');
  const eqFirst = body.indexOf('=');
  if (colon > 0 && (eqFirst === -1 || eqFirst > colon)) {
    const key = body.slice(0, colon).replace(/^- /, '');
    let i = colon + 1;
    while (i < body.length && body[i] === ' ') i++;
    const raw = body.slice(i).replace(/\s+#.*$/, '').trimEnd();
    const { value, at } = unquote(raw);
    if (isSecretKey(key) && looksLikeSecretValue(value)) maskRange(lead + i + at, value.length);
  }
  return chars ? (chars as string[]).join('') : line;
}

/** How many separate runs of characters masking replaced. */
export function countMaskedRuns(before: string, after: string): number {
  let runs = 0;
  let inRun = false;
  for (let i = 0; i < after.length; i++) {
    const changed = after[i] !== before[i];
    if (changed && !inRun) runs++;
    inRun = changed;
  }
  return runs;
}

/**
 * The text as the model may see it: every known secret format, and the value
 * of every credential-looking assignment, masked at the same length so line
 * and column numbers still point at the right place. Linear time.
 */
export function maskForModel(text: string): string {
  let out = text;
  for (const h of findSecrets(text)) {
    out = out.slice(0, h.offset) + redact(h.match).slice(0, h.match.length).padEnd(h.match.length, '*') + out.slice(h.offset + h.match.length);
  }
  if (out.includes('://')) out = out.replace(URL_USERINFO, (_m, scheme: string, user: string, pass: string) => `${scheme}${user}:${'*'.repeat(pass.length)}@`);
  return out.split('\n').map(maskAssignmentLine).join('\n');
}

export async function runHeuristics(
  file: RepoFile,
  rawNorm: NormalizedText,
  sigFindings: SignatureFinding[],
  client: BedrockClient,
): Promise<HeuristicFinding[]> {
  // Credential files never go to the model by any path.
  if (CREDENTIAL_FILE.test(file.rel)) return [];
  // Masked here so spans, context and quotes point into masked text; the
  // prompt itself is masked again at the sink (classify) for every path.
  const norm: NormalizedText = { ...rawNorm, original: maskForModel(rawNorm.original) };
  const maskedRuns = countMaskedRuns(rawNorm.original, norm.original);
  if (!shouldEscalate(file, norm, sigFindings)) {
    // Layered detection: a file an agent takes instructions or settings from
    // is judged whole even when no signature fired. Reworded attacks trip no
    // pattern; on our 10 reworded attacks signatures caught 0 and the judge 6,
    // with 0 false alarms on 10 look-alikes (docs/AI_JUDGE_EVAL.md).
    return isAgentFacing(file.rel, file.role) ? judgeWholeFile(file, norm, client, maskedRuns) : [];
  }
  const findings: HeuristicFinding[] = [];

  for (const span of candidateSpans(file, norm, sigFindings)) {
    const context = contextLines(norm.original, span);

    // Step 1: triage with the fast model.
    const triage = await classify(
      client,
      "haiku",
      buildHeuristicPrompt(span, context, file.rel, generateNonce()),
      maskedRuns,
    );
    if (!triage || triage.verdict === "benign") continue;

    // Step 2: the judge sees the same span plus the triage verdict (L-022).
    const verdict = await classify(
      client,
      "sonnet",
      buildHeuristicPrompt(span, context, file.rel, generateNonce(), triage),
      maskedRuns,
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
async function judgeWholeFile(file: RepoFile, norm: NormalizedText, client: BedrockClient, maskedRuns = 0): Promise<HeuristicFinding[]> {
  const text = norm.original;
  for (let w = 0; w < MAX_WHOLE_FILE_WINDOWS; w++) {
    const start = w * (MAX_JUDGED_CHARS - 200);
    if (start >= text.length) break;
    const v = await judgeText(text.slice(start, start + MAX_JUDGED_CHARS), file.rel, client, maskedRuns);
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
  maskedUpstream = 0,
): Promise<TextVerdict | null> {
  const span = text.slice(0, MAX_JUDGED_CHARS);
  if (span.trim().length === 0) return null;
  const triage = await classify(client, "haiku", buildHeuristicPrompt(span, "", label, generateNonce()), maskedUpstream);
  if (!triage || triage.verdict === "benign") return null;
  const verdict = await classify(client, "sonnet", buildHeuristicPrompt(span, "", label, generateNonce(), triage), maskedUpstream);
  if (!verdict || verdict.verdict === "benign") return null;
  if (!span.includes(verdict.quoted_span)) return null;
  return { verdict: verdict.verdict, threatClass: verdict.threat_class, span: verdict.quoted_span, rationale: verdict.rationale };
}
