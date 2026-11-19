export type GithubRepo = {
  owner:    string;
  repo:     string;
  cloneUrl: string;
};

const GITHUB_URL =
  /^https:\/\/github\.com\/([A-Za-z0-9_.-]{1,100})\/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?\/?$/;

function isDotsOnly(s: string): boolean {
  return /^\.+$/.test(s);
}

/**
 * Accept only https://github.com/<owner>/<repo> (optional .git or trailing
 * slash). No credentials, query, fragment, extra path or other hosts.
 */
export function parseGithubUrl(input: string): GithubRepo | null {
  const m = GITHUB_URL.exec(input.trim());
  if (!m) return null;
  const owner = m[1];
  const repo = m[2];
  if (owner === undefined || repo === undefined) return null;
  if (isDotsOnly(owner) || isDotsOnly(repo)) return null;
  if (owner.startsWith('-') || repo.startsWith('-')) return null;
  return { owner, repo, cloneUrl: `https://github.com/${owner}/${repo}.git` };
}
