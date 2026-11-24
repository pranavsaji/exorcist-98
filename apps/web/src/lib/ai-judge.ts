/**
 * The AI judge on the public site: off unless the operator turns it on.
 *
 *   EXORCIST_WEB_AI=1                       turn it on
 *   EXORCIST_AWS_REGION                     e.g. us-east-2 (Vercel reserves AWS_REGION)
 *   EXORCIST_AWS_ACCESS_KEY_ID              an IAM user that may only call
 *   EXORCIST_AWS_SECRET_ACCESS_KEY            bedrock:InvokeModel on the two models
 *   EXORCIST_AWS_SESSION_TOKEN              optional, for short-lived credentials
 *   EXORCIST_WEB_AI_DAILY_CALLS             model calls per server instance per UTC day
 *                                           (default 200, at most 5,000)
 *
 * Every judgement reserves 2 model calls (Haiku triage, Sonnet judge) before
 * it starts, so the budget can never be overrun by calls already in flight.
 */
import type { BedrockClientOptions } from '@exorcist-98/core/llm';

export type AiJudgeConfig = { enabled: false } | { enabled: true; client: BedrockClientOptions; dailyCalls: number };

export const DEFAULT_DAILY_CALLS = 200;
export const MAX_DAILY_CALLS = 5_000;
export const CALLS_PER_JUDGEMENT = 2;

export function aiJudgeConfig(env: Record<string, string | undefined> = process.env): AiJudgeConfig {
  if (env['EXORCIST_WEB_AI'] !== '1') return { enabled: false };
  const region = env['EXORCIST_AWS_REGION'] ?? '';
  const accessKeyId = env['EXORCIST_AWS_ACCESS_KEY_ID'] ?? '';
  const secretAccessKey = env['EXORCIST_AWS_SECRET_ACCESS_KEY'] ?? '';
  if (!/^[a-z]{2}(-[a-z]+)+-\d$/.test(region) || !accessKeyId || !secretAccessKey) return { enabled: false };
  const raw = Number(env['EXORCIST_WEB_AI_DAILY_CALLS'] ?? DEFAULT_DAILY_CALLS);
  const dailyCalls = Number.isFinite(raw) && raw >= CALLS_PER_JUDGEMENT ? Math.min(Math.floor(raw), MAX_DAILY_CALLS) : DEFAULT_DAILY_CALLS;
  const sessionToken = env['EXORCIST_AWS_SESSION_TOKEN'] || undefined;
  return { enabled: true, client: { region, credentials: sessionToken ? { accessKeyId, secretAccessKey, sessionToken } : { accessKeyId, secretAccessKey } }, dailyCalls };
}

/** A per-process budget of model calls per UTC day. */
export function createDailyBudget(limit: number, now: () => number = () => Date.now()) {
  let day = '';
  let used = 0;
  const today = () => new Date(now()).toISOString().slice(0, 10);
  return {
    /** Reserve `n` calls; false (and nothing reserved) if that would pass the limit. */
    reserve(n: number): boolean {
      const d = today();
      if (d !== day) { day = d; used = 0; }
      if (used + n > limit) return false;
      used += n;
      return true;
    },
    /** Give back calls that were reserved but not made. */
    refund(n: number): void { used = Math.max(0, used - n); },
    used: () => used,
  };
}
