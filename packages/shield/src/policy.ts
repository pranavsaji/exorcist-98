import { existsSync, readFileSync } from 'node:fs';
import { z } from 'zod';

export const PolicySchema = z
  .object({
    allowedHosts:   z.array(z.string().min(1)).default([]),
    mode:           z.enum(['enforce', 'monitor']).default('enforce'),
    autoQuarantine: z.boolean().default(false),
    /**
     * What happens the first time a tool is seen (S-006). `pin` trusts it and
     * pins its fingerprint (trust on first use). `review` holds it back until
     * `exorcist approve tool <server> <tool>`.
     */
    firstUse:       z.enum(['pin', 'review']).default('pin'),
    /** Show a desktop notification for critical and high alerts (S-012). */
    notify:         z.boolean().default(true),
    /**
     * Before each tool call, re-read the server's tool list and check the
     * tool still matches its pin (S-026). Needed because a client may cache
     * the tool list and never fetch it again, so a changed tool would never
     * be seen otherwise.
     */
    verifyCalls:    z.boolean().default(true),
    /**
     * What happens when the program behind a server changes since it was
     * pinned (S-006): `block` does not start it until `exorcist approve server`,
     * `warn` starts it with an alert, `off` does not pin the program.
     */
    launchPin:      z.enum(['block', 'warn', 'off']).default('block'),
    /**
     * Ask the AI judge (Amazon Bedrock) about every tool description the
     * Shield has not pinned yet, before the agent sees it (S-009). Needs
     * AWS_REGION and AWS credentials. Off by default: it costs money and adds
     * a few seconds to the first tool list.
     */
    aiReview:       z.boolean().default(false),
    /**
     * Path to the canary records (EX-022), absolute or relative to the state
     * folder. Default: `canaries.json` inside the state folder, which is
     * `<project>/.exorcist/canaries.json` where `exorcist canary plant` writes
     * it. `plant` sets this itself when the state folder is somewhere else.
     */
    canaries:       z.string().min(1).optional(),
    /**
     * Session Guard (EX-027): the lethal trifecta, enforced at run time. Once
     * this agent session has really taken in untrusted text AND read private
     * data (on any of its servers), a call that could send data out is:
     * `hold`: held for your answer in an approval prompt, or refused with how
     *   to approve when the client cannot show prompts;
     * `block`: refused, with how to approve;
     * `monitor`: sent, with an alert;
     * `off`: not checked.
     * Default `hold`: it only ever acts after both legs have actually happened,
     * which ordinary use rarely does, and then a single question is cheap next
     * to a leaked key. `mode: monitor` makes it monitor too.
     */
    sessionGuard:   z.enum(['hold', 'block', 'monitor', 'off']).default('hold'),
  })
  .strict();

export type Policy = z.infer<typeof PolicySchema>;

export const DEFAULT_POLICY: Policy = { allowedHosts: [], mode: 'enforce', autoQuarantine: false, firstUse: 'pin', notify: true, verifyCalls: true, launchPin: 'block', aiReview: false, sessionGuard: 'hold' };

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
