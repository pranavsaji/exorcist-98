import { existsSync, readFileSync } from 'node:fs';
import { z } from 'zod';

export const PolicySchema = z
  .object({
    allowedHosts:   z.array(z.string().min(1)).default([]),
    mode:           z.enum(['enforce', 'monitor']).default('enforce'),
    autoQuarantine: z.boolean().default(false),
  })
  .strict();

export type Policy = z.infer<typeof PolicySchema>;

export const DEFAULT_POLICY: Policy = { allowedHosts: [], mode: 'enforce', autoQuarantine: false };

export type PolicyResult = { ok: true; policy: Policy } | { ok: false; error: string };

/** A missing file means the defaults. A present but invalid file is an error (fail closed). */
export function loadPolicy(path: string): PolicyResult {
  if (!existsSync(path)) return { ok: true, policy: DEFAULT_POLICY };
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    return { ok: false, error: `The policy file ${path} is not valid JSON.` };
  }
  const parsed = PolicySchema.safeParse(json);
  if (!parsed.success) {
    return { ok: false, error: `The policy file ${path} is invalid: ${parsed.error.issues[0]?.message ?? 'unknown problem'}` };
  }
  return { ok: true, policy: parsed.data };
}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Local names are always fine; entries may be exact hosts or `*.example.com`. */
export function hostAllowed(host: string, allowed: readonly string[]): boolean {
  const h = host.toLowerCase();
  if (LOCAL_HOSTS.has(h)) return true;
  for (const raw of allowed) {
    const a = raw.toLowerCase();
    if (a === h) return true;
    if (a.startsWith('*.') && h.endsWith(a.slice(1)) && h.length > a.length - 1) return true;
  }
  return false;
}
