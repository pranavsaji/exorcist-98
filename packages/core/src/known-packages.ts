/**
 * Well-known MCP server packages, used by EX-013 to spot typosquats: a name
 * one or two edits away from one of these, or equal after swapping look-alike
 * characters, is probably an impostor. Exact matches are fine.
 */
export const KNOWN_MCP_PACKAGES: readonly string[] = [
  '@modelcontextprotocol/server-filesystem', '@modelcontextprotocol/server-github', '@modelcontextprotocol/server-gitlab',
  '@modelcontextprotocol/server-memory', '@modelcontextprotocol/server-fetch', '@modelcontextprotocol/server-git',
  '@modelcontextprotocol/server-everything', '@modelcontextprotocol/server-postgres', '@modelcontextprotocol/server-sqlite',
  '@modelcontextprotocol/server-puppeteer', '@modelcontextprotocol/server-brave-search', '@modelcontextprotocol/server-slack',
  '@modelcontextprotocol/server-google-maps', '@modelcontextprotocol/server-sequential-thinking', '@modelcontextprotocol/server-time',
  '@modelcontextprotocol/server-redis', '@modelcontextprotocol/server-gdrive', '@modelcontextprotocol/server-aws-kb-retrieval',
  '@modelcontextprotocol/inspector', '@playwright/mcp', '@upstash/context7-mcp', '@notionhq/notion-mcp-server',
  '@supabase/mcp-server-supabase', '@stripe/mcp', '@sentry/mcp-server', '@cloudflare/mcp-server-cloudflare',
  '@azure/mcp', '@heroku/mcp-server', '@browserbasehq/mcp', 'firecrawl-mcp', 'mcp-remote',
  'mcp-server-fetch', 'mcp-server-git', 'mcp-server-time', 'mcp-server-sqlite', 'awslabs.aws-documentation-mcp-server',
];

/** Look-alike characters attackers swap in. */
function fold(s: string): string {
  return s.toLowerCase().replace(/rn/g, 'm').replace(/[1i]/g, 'l').replace(/0/g, 'o').replace(/vv/g, 'w').replace(/[-_.]/g, '');
}

/** Damerau-Levenshtein distance (optimal string alignment), capped for speed. */
export function editDistance(a: string, b: string, cap = 3): number {
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) (d[0] as number[])[j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const row = d[i] as number[];
      const prev = d[i - 1] as number[];
      let v = Math.min((prev[j] as number) + 1, (row[j - 1] as number) + 1, (prev[j - 1] as number) + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, ((d[i - 2] as number[])[j - 2] as number) + 1);
      row[j] = v;
    }
  }
  return (d[a.length] as number[])[b.length] as number;
}

/** The package name without a version (`@scope/name@1.2.3` -> `@scope/name`). */
export function packageName(spec: string): string {
  const s = spec.trim();
  const at = s.lastIndexOf('@');
  return at > 0 ? s.slice(0, at) : s;
}

/** The well-known package `spec` impersonates, or null. */
export function typosquatOf(spec: string): string | null {
  const name = packageName(spec);
  if (name.length < 6 || KNOWN_MCP_PACKAGES.includes(name)) return null;
  for (const known of KNOWN_MCP_PACKAGES) {
    if (fold(name) === fold(known)) return known;
    const limit = known.length >= 14 ? 2 : 1;
    const dist = editDistance(name.toLowerCase(), known.toLowerCase(), limit);
    if (dist > 0 && dist <= limit) return known;
  }
  return null;
}
