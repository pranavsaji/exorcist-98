/**
 * AI review of new tool descriptions (S-009). The fixed patterns and the
 * paraphrase layer miss attacks worded in ways they do not cover; with
 * `aiReview: true` in the policy, the Shield asks the AI judge about every
 * tool it has not pinned yet, once per version, before the tool list reaches
 * the agent.
 *
 * The model only labels text. This module turns a label into a decision with
 * fixed rules: "malicious" with a span found verbatim in the description
 * hides the tool, "suspicious" raises an alert and keeps it. A failed or slow
 * call changes nothing (the signature checks still run) and is retried the
 * next time the tool list is read.
 */
import { redactSecretText } from '@exorcist-98/core';
import { toolFingerprint } from './hash.js';
import type { ToolDef } from './hash.js';
import type { Reason } from './inspect.js';

export type AiLabel = { verdict: 'malicious' | 'suspicious'; threatClass: string; span: string };
/** Ask the model about one description. `null` means nothing found. Throws or rejects on failure. */
export type AiJudge = (text: string, label: string) => Promise<AiLabel | null>;
export type AiFindings = { block: Reason[]; warn: Reason[] };

const NONE: AiFindings = { block: [], warn: [] };

export type AiReviewOptions = {
  /** Longest wait for one description (ms). */
  timeoutMs?: number;
  /** Most descriptions judged at once. */
  concurrency?: number;
  /** Most descriptions judged per Shield process, to bound cost. */
  maxJudged?: number;
  log?: (s: string) => void;
};

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`no answer within ${ms} ms`)), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, (e: unknown) => { clearTimeout(t); reject(e instanceof Error ? e : new Error(String(e))); });
  });
}

/** What a label means for the Shield. Pure, so the rules are easy to test. */
export function findingsFor(tool: ToolDef, label: AiLabel | null): AiFindings {
  if (!label) return NONE;
  const description = tool.description ?? '';
  if (!description.includes(label.span)) return NONE; // security rule: drop a span not found verbatim
  const reason: Reason = {
    ruleId: 'AI-JUDGE',
    message: `An AI review found instructions for your AI in its description: "${redactSecretText(label.span).slice(0, 160)}" (${label.threatClass.replace(/[^\w ,./-]/g, '').slice(0, 60)}).`,
  };
  return label.verdict === 'malicious' ? { block: [reason], warn: [] } : { block: [], warn: [reason] };
}

export class AiReview {
  private readonly cache = new Map<string, AiFindings>();
  private judged = 0;
  private warnedLimit = false;
  constructor(private readonly judge: AiJudge, private readonly o: AiReviewOptions = {}) {}

  /** The findings for one tool version, if it has been judged. */
  findings(fingerprint: string): AiFindings {
    return this.cache.get(fingerprint) ?? NONE;
  }

  /**
   * If `line` is a tool-list result, judge every tool in it that `isPinned`
   * says is new. Resolves when all answers are in (or timed out).
   */
  async prepare(line: string, isPinned: (name: string, fingerprint: string) => boolean): Promise<void> {
    let msg: unknown;
    try { msg = JSON.parse(line); } catch { return; }
    const tools = (msg as { result?: { tools?: unknown } } | null)?.result?.tools;
    if (!Array.isArray(tools)) return;
    const todo: Array<{ tool: ToolDef; fp: string }> = [];
    for (const raw of tools) {
      const tool = raw as ToolDef;
      if (!tool || typeof tool.name !== 'string' || typeof tool.description !== 'string' || tool.description.trim() === '') continue;
      const fp = toolFingerprint(tool);
      if (this.cache.has(fp) || isPinned(tool.name, fp)) continue;
      if (this.judged + todo.length >= (this.o.maxJudged ?? 200)) {
        if (!this.warnedLimit) { this.o.log?.('AI review limit reached for this session; further new tools get the signature checks only.'); this.warnedLimit = true; }
        break;
      }
      todo.push({ tool, fp });
    }
    const width = Math.max(1, this.o.concurrency ?? 4);
    for (let i = 0; i < todo.length; i += width) {
      await Promise.all(todo.slice(i, i + width).map(async ({ tool, fp }) => {
        try {
          const label = await withTimeout(this.judge(tool.description ?? '', `tool description: ${tool.name}`), this.o.timeoutMs ?? 30_000);
          this.judged++;
          this.cache.set(fp, findingsFor(tool, label));
        } catch (err) {
          this.o.log?.(`AI review of "${tool.name}" failed (${err instanceof Error ? err.message : String(err)}); the signature checks still apply.`);
        }
      }));
    }
  }
}
