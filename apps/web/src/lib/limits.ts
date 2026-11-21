/**
 * Abuse limits for the public scan endpoint (W-003). In memory, per server
 * process: enough for one container. Two limits:
 *
 * - **Per visitor:** a token bucket per client address, separately for GitHub
 *   scans (each downloads a repository) and for the bundled Haunted Repo.
 * - **At once:** a cap on scans running at the same time, so a burst cannot
 *   fill the disk or the CPU.
 *
 * The client address comes only from a header the host's proxy sets
 * (`EXORCIST_CLIENT_IP_HEADER`, default `fly-client-ip`). If that header is
 * missing, every request shares one bucket: stricter, never looser.
 */

export type ScanKind = 'github' | 'haunted-repo' | 'upload';

type Bucket = { tokens: number; updated: number };
type Policy = { capacity: number; refillPerMs: number };

const MINUTE = 60_000;
export const POLICIES: Record<ScanKind, Policy> = {
  // 6 GitHub scans at once, then 1 more every 2 minutes.
  github: { capacity: 6, refillPerMs: 1 / (2 * MINUTE) },
  // The Haunted Repo is local and small: 20 at once, then 1 every 10 seconds.
  'haunted-repo': { capacity: 20, refillPerMs: 1 / 10_000 },
  // Uploaded ZIP files (L-032): like GitHub scans, they unpack to disk.
  upload: { capacity: 6, refillPerMs: 1 / (2 * MINUTE) },
};
export const MAX_CONCURRENT: Record<ScanKind, number> = { github: 3, 'haunted-repo': 8, upload: 3 };
const MAX_BUCKETS = 10_000;

export type Decision =
  | { ok: true; release: () => void }
  | { ok: false; status: 429 | 503; retryAfterSeconds: number; error: string };

export function createLimiter(o: { policies?: Partial<Record<ScanKind, Policy>>; maxConcurrent?: Partial<Record<ScanKind, number>>; now?: () => number } = {}) {
  const policies: Record<ScanKind, Policy> = { ...POLICIES, ...o.policies };
  const maxConcurrent: Record<ScanKind, number> = { ...MAX_CONCURRENT, ...o.maxConcurrent };
  const now = o.now ?? (() => Date.now());
  const buckets = new Map<string, Bucket>();
  const running: Record<ScanKind, number> = { github: 0, 'haunted-repo': 0, upload: 0 };

  function take(key: string, p: Policy, t: number): number {
    let b = buckets.get(key);
    if (!b) {
      if (buckets.size >= MAX_BUCKETS) {
        // Drop full buckets first; they carry no state worth keeping.
        for (const [k, v] of buckets) if (Math.min(p.capacity, v.tokens + (t - v.updated) * p.refillPerMs) >= p.capacity) buckets.delete(k);
        if (buckets.size >= MAX_BUCKETS) buckets.clear();
      }
      b = { tokens: p.capacity, updated: t };
      buckets.set(key, b);
    }
    b.tokens = Math.min(p.capacity, b.tokens + (t - b.updated) * p.refillPerMs);
    b.updated = t;
    if (b.tokens >= 1) { b.tokens -= 1; return 0; }
    return Math.ceil((1 - b.tokens) / p.refillPerMs / 1000);
  }

  return {
    acquire(kind: ScanKind, client: string): Decision {
      if (running[kind] >= maxConcurrent[kind]) {
        return { ok: false, status: 503, retryAfterSeconds: 15, error: 'The scanner is busy with other scans. Try again in a few seconds.' };
      }
      const wait = take(`${kind}:${client}`, policies[kind], now());
      if (wait > 0) {
        const mins = Math.ceil(wait / 60);
        return {
          ok: false, status: 429, retryAfterSeconds: wait,
          error: kind === 'github'
            ? `You have scanned a lot of repositories in a short time. Try again in ${mins} minute${mins === 1 ? '' : 's'}, or run the Exorcist 98 CLI on your own machine.`
            : `Too many scans in a short time. Try again in ${wait} seconds.`,
        };
      }
      running[kind]++;
      let released = false;
      return { ok: true, release: () => { if (!released) { released = true; running[kind]--; } } };
    },
    /** For tests and diagnostics. */
    running: () => ({ ...running }),
  };
}

/** The client address, from the one header the hosting proxy sets. */
export function clientKey(headers: Headers, env: Record<string, string | undefined> = process.env): string {
  const name = (env['EXORCIST_CLIENT_IP_HEADER'] ?? 'fly-client-ip').toLowerCase();
  const raw = headers.get(name)?.split(',')[0]?.trim() ?? '';
  return /^[0-9a-fA-F:.]{2,45}$/.test(raw) ? raw : 'shared';
}

/** One limiter per server process. */
export const limiter = createLimiter();
