export type GithubRepo = {
  owner:    string;
  repo:     string;
  cloneUrl: string;
  /** Branch, tag or commit from a /tree/<ref> or /commit/<sha> link (W-020). */
  ref?:     string;
};

const GITHUB_URL =
  /^https:\/\/github\.com\/([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?(?:\/(?:tree|commit)\/([A-Za-z0-9._/-]{1,200}?))?\/?$/;

/** Same rule as isSafeRef in @exorcist-98/core (kept here so this file stays browser-safe). */
function isSafeRef(ref: string): boolean {
  return /^[A-Za-z0-9._/-]{1,200}$/.test(ref) && !ref.includes('..') && !ref.startsWith('/') && !ref.startsWith('-') && !ref.endsWith('/') && !ref.includes('//');
}

function isDotsOnly(s: string): boolean {
  return /^\.+$/.test(s);
}

/**
 * Accept only https://github.com/<owner>/<repo> (optional .git or trailing
 * slash), optionally followed by /tree/<branch-or-tag> or /commit/<sha>. No
 * credentials, query, fragment, other paths or other hosts.
 */
export function parseGithubUrl(input: string): GithubRepo | null {
  const m = GITHUB_URL.exec(input.trim());
  if (!m) return null;
  const owner = m[1];
  const repo = m[2];
  if (owner === undefined || repo === undefined) return null;
  if (isDotsOnly(owner) || isDotsOnly(repo)) return null;
  if (owner.startsWith('-') || repo.startsWith('-')) return null;
  const ref = m[3];
  if (ref !== undefined && !isSafeRef(ref)) return null;
  const out: GithubRepo = { owner, repo, cloneUrl: `https://github.com/${owner}/${repo}.git` };
  if (ref !== undefined) out.ref = ref;
  return out;
}
