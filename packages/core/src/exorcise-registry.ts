/**
 * Current-version lookups for the EX-010 fix (pin `npx pkg` / `uvx pkg`).
 * The only network calls exorcise makes: one GET per package to a fixed host
 * (the npm registry or PyPI), with a time limit. The package name is checked
 * against the same pattern EX-010 uses before it goes into a URL, and the
 * answer is validated before it goes into a file.
 */
import { z } from 'zod';
import type { PinRequest, VersionAnswer, VersionLookup } from './exorcise.js';

export type FetchFn = (url: string, init: { signal: AbortSignal; headers: Record<string, string> }) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}>;

export type RegistryOptions = {
  fetch?: FetchFn;
  /** Per lookup (default 5000 ms). */
  timeoutMs?: number;
  /** Answers already found, kept for `cacheMs` (default 10 minutes). Shared between calls when given. */
  cache?: Map<string, { at: number; answer: VersionAnswer }>;
  cacheMs?: number;
  now?: () => number;
};

const NAME = /^(@[a-z0-9._-]+\/)?[a-z0-9][a-z0-9._-]*$/i;
const NPM_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PYPI_VERSION = /^\d[0-9A-Za-z.!+_-]{0,63}$/;
const NpmLatest = z.object({ version: z.string().max(100) });
const PypiProject = z.object({ info: z.object({ version: z.string().max(100) }) });

export function registryUrl(r: PinRequest): string {
  if (r.ecosystem === 'pypi') return `https://pypi.org/pypi/${encodeURIComponent(r.name)}/json`;
  const name = r.name.startsWith('@') ? `@${encodeURIComponent(r.name.slice(1))}` : encodeURIComponent(r.name);
  return `https://registry.npmjs.org/${name}/latest`;
}

/** A VersionLookup that asks the public registries. Never throws. */
export function registryLookup(opts: RegistryOptions = {}): VersionLookup {
  const doFetch: FetchFn = opts.fetch ?? ((url, init) => fetch(url, init));
  const timeoutMs = opts.timeoutMs ?? 5000;
  const cacheMs = opts.cacheMs ?? 10 * 60_000;
  const now = opts.now ?? Date.now;
  return async (r: PinRequest): Promise<VersionAnswer> => {
    const where = r.ecosystem === 'npm' ? 'npm' : 'PyPI';
    if (!NAME.test(r.name)) return { ok: false, reason: `"${r.name.slice(0, 80)}" is not a plain package name` };
    const key = `${r.ecosystem}:${r.name}`;
    const hit = opts.cache?.get(key);
    if (hit && now() - hit.at < cacheMs) return hit.answer;
    let answer: VersionAnswer;
    try {
      const res = await doFetch(registryUrl(r), { signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/json' } });
      if (res.status === 404) answer = { ok: false, reason: `"${r.name}" was not found on ${where}` };
      else if (!res.ok) answer = { ok: false, reason: `${where} answered HTTP ${res.status} for "${r.name}"` };
      else {
        const body: unknown = await res.json();
        const parsed = r.ecosystem === 'npm' ? NpmLatest.safeParse(body) : PypiProject.safeParse(body);
        const version = parsed.success ? ('version' in parsed.data ? parsed.data.version : parsed.data.info.version) : null;
        const valid = version !== null && (r.ecosystem === 'npm' ? NPM_VERSION : PYPI_VERSION).test(version);
        answer = !valid || version === null
          ? { ok: false, reason: `${where} gave an unexpected answer for "${r.name}"` }
          // npm replaces a package that was removed for malware with a
          // "0.0.1-security" placeholder. Pinning to it would hide the problem.
          : r.ecosystem === 'npm' && /-security$/.test(version)
            ? { ok: false, reason: `npm has replaced "${r.name}" with a security placeholder (${version}), which usually means the package was removed for malware. Remove this server` }
            : { ok: true, version };
      }
    } catch {
      return { ok: false, reason: `could not reach ${where} to look up "${r.name}" (offline or timed out)` };
    }
    opts.cache?.set(key, { at: now(), answer });
    return answer;
  };
}
