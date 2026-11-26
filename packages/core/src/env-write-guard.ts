/**
 * env-write-guard.ts (CT-14)
 *
 * Pure decision for the `fs_write` / `str_replace` PreToolUse hook: does the
 * agent want to write a value copied from a `.env*` file into a file that is
 * not itself a `.env*` file? Writing into a `.env*` file is allowed: that is
 * where those values belong.
 *
 * The result holds the destination path only, never the value.
 */
import { z } from 'zod';
import { PATH_KEYS } from './mcp-write-guard.js';
export type EnvWriteDecision = { block: false } | { block: true; path: string };
const EventSchema = z.object({
  tool_name: z.string().optional(),
  tool_input: z.record(z.unknown()),
});
/** Keys that carry the text to be written (the same keys `mcp-write-guard` reads). `old_str` is not written. */
const NEW_TEXT_KEYS = ['file_text', 'fileText', 'content', 'contents', 'text', 'new_str', 'newStr', 'new_string', 'newText', 'insert_text', 'data', 'body'];
const MAX_TEXT_CHARS = 2 * 1024 * 1024;
const MAX_PATH_CHARS = 512;
/** `.env`, `.env.local`, `.env.production`, ... A name like `.envoy.yaml` is not one. */
const ENV_FILE = /^\.env(\..*)?$/i;
/** The last part of a path, with either separator. */
export function baseName(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? '';
}
export function isEnvFilePath(path: string): boolean {
  return ENV_FILE.test(baseName(path));
}
function firstPath(input: Record<string, unknown>): string | undefined {
  for (const k of PATH_KEYS) {
    const v = input[k];
    if (typeof v === 'string' && v !== '') return v;
  }
  return undefined;
}
function newTexts(input: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const k of NEW_TEXT_KEYS) {
    const v = input[k];
    if (typeof v === 'string') out.push(v.slice(0, MAX_TEXT_CHARS));
  }
  return out;
}
/** Decide one write event (already JSON-parsed). Anything not recognisable is allowed. */
export function decideEnvWrite(event: unknown, envValues: readonly string[]): EnvWriteDecision {
  const parsed = EventSchema.safeParse(event);
  if (!parsed.success || envValues.length === 0) return { block: false };
  const { tool_name: tool, tool_input: input } = parsed.data;
  if (tool !== undefined && tool !== '' && !/write|replace|edit|create|append|insert/i.test(tool)) return { block: false };
  const path = firstPath(input);
  if (path !== undefined && isEnvFilePath(path)) return { block: false };
  const texts = newTexts(input);
  const hit = envValues.some((v) => v !== '' && texts.some((t) => t.includes(v)));
  if (!hit) return { block: false };
  return { block: true, path: path ?? '' };
}
/** One plain line for stderr. Names the path (never the value). */
export function envWriteBlockMessage(d: { path: string }, envValues: readonly string[] = []): string {
  const clean = d.path.replace(/[\r\n]+/g, ' ').slice(0, MAX_PATH_CHARS);
  const safe = clean === '' || envValues.some((v) => v !== '' && clean.includes(v)) ? 'a file' : clean;
  return `Exorcist 98 blocked a write to ${safe}: it contains a value from your .env file. Secrets stay in .env files. If you want this write, make it yourself.`;
}
