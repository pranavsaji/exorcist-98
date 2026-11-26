/** AC-28: nothing the MCP server exposes can approve or release anything. */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

const read = (f: string): string => readFileSync(new URL(`../${f}`, import.meta.url), 'utf8');

describe('the MCP server cannot grant an approval', () => {
  it('AC-28: it registers exactly the four known tools, none of which approves or releases', () => {
    const names = [...read('index.ts').matchAll(/registerTool\(\s*'([^']+)'/g)].map((m) => m[1]);
    expect(names).toEqual(['scan_repo', 'scan_mcp_config', 'explain_finding', 'quarantine']);
    for (const n of names) expect(n).not.toMatch(/approv|allow|release|grant|verify|trust/i);
  });
  it('AC-28: its source never imports an approval, release or allow-list function', () => {
    const src = `${read('index.ts')}\n${read('tools.ts')}`;
    for (const fn of ['approveHost', 'approveTool', 'approveServer', 'grantSession', 'resolveRelease', 'macOsAuth', 'addAllowedRead', 'onOwnerVerified', 'personConfirms']) {
      expect(src, fn).not.toContain(fn);
    }
  });
});
