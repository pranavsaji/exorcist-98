import { parseGithubUrl } from './github';

/**
 * Shareable links into the desktop. Every parameter is checked strictly and
 * anything unexpected is ignored, so a link can never start something the
 * page would not let a visitor start by hand.
 *
 *   /?repo=owner/name[/tree/ref]   scan that public GitHub repository
 *   /?demo=haunted                 scan the Haunted Repo
 *   /?demo=<scenario>              open the Possession Lab and play that attack
 *   /?open=byoa|field|map          open Bring Your Own Attack, the Field Report,
 *                                  or the Haunted House Map (after a Haunted Repo scan)
 */

/** The Possession Lab scenarios a link may name (same ids as the Shield simulator). */
export const LAB_SCENARIOS = ['rug-pull', 'poisoned-tool', 'secret-leak', 'unknown-host', 'poisoned-result', 'canary'] as const;
export type LabScenario = (typeof LAB_SCENARIOS)[number];

export const OPEN_TARGETS = ['byoa', 'field', 'map'] as const;
export type OpenTarget = (typeof OPEN_TARGETS)[number];

export type DeepLink =
  | { kind: 'repo'; url: string; label: string }
  | { kind: 'haunted' }
  | { kind: 'lab'; scenario: LabScenario }
  | { kind: 'open'; target: OpenTarget };

/** owner/name plus an optional /tree/<ref> or /commit/<sha>: the same rule as the scan form. */
const REPO_PARAM = /^[A-Za-z0-9._/-]{3,420}$/;

function one(params: URLSearchParams, key: string): string | null {
  const all = params.getAll(key);
  // Two values for one key is ambiguous: ignore the key.
  return all.length === 1 ? all[0]! : null;
}

/** The GitHub link for a ?repo= value, or null when it is not a valid public repository path. */
export function repoFromParam(value: string): { url: string; label: string } | null {
  if (!REPO_PARAM.test(value)) return null;
  const url = `https://github.com/${value}`;
  const repo = parseGithubUrl(url);
  if (!repo) return null;
  return { url, label: `${repo.owner}/${repo.repo}${repo.ref ? `@${repo.ref}` : ''}` };
}

/** Read a deep link from a query string. Returns null when there is none or it is invalid. */
export function parseDeepLink(search: string): DeepLink | null {
  if (search.length > 600) return null;
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(search);
  } catch {
    return null;
  }
  const repo = one(params, 'repo');
  if (repo !== null) {
    const r = repoFromParam(repo);
    if (r) return { kind: 'repo', ...r };
  }
  const demo = one(params, 'demo');
  if (demo !== null) {
    if (demo === 'haunted') return { kind: 'haunted' };
    if ((LAB_SCENARIOS as readonly string[]).includes(demo)) return { kind: 'lab', scenario: demo as LabScenario };
  }
  const open = one(params, 'open');
  if (open !== null && (OPEN_TARGETS as readonly string[]).includes(open)) return { kind: 'open', target: open as OpenTarget };
  return null;
}

/**
 * The query string that reproduces a scan, for the address bar. A ZIP upload
 * cannot be shared, so it clears the query.
 */
export function shareQuery(scan: { kind: 'haunted' } | { kind: 'repo'; url: string } | { kind: 'zip' }): string {
  if (scan.kind === 'haunted') return '?demo=haunted';
  if (scan.kind === 'zip') return '';
  const repo = parseGithubUrl(scan.url);
  if (!repo) return '';
  // Only [A-Za-z0-9._/-] can reach here, so the value needs no escaping and stays readable.
  return `?repo=${repo.owner}/${repo.repo}${repo.ref ? `/tree/${repo.ref}` : ''}`;
}
