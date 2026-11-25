/**
 * FF-4: scripts/published-shape.mjs packs the CLI and the MCP server, installs the
 * tarballs into an empty project and checks what a user would get. The full run is
 * slow-ish (a few seconds) and uses the real built bundles; the pure parts are
 * tested on their own so a failure says which part broke.
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EXPECTED_TOOLS, cleanEnv, judgeMcpAnswers, runPublishedShapeCheck, type McpResponse } from '../../../../scripts/published-shape.mjs';

const ROOT = resolve(fileURLToPath(new URL('.', import.meta.url)), '../../../..');
const SCRIPT = join(ROOT, 'scripts/published-shape.mjs');

const goodAnswers = (version: string): Map<number, McpResponse> => new Map<number, McpResponse>([
  [1, { result: { protocolVersion: '2025-03-26', serverInfo: { name: 'exorcist', version } } }],
  [2, { result: { tools: [...EXPECTED_TOOLS].reverse().map((name) => ({ name })) } }],
]);

describe('scripts/published-shape.mjs', () => {
  it('FF-4.1 FF-4.2 FF-4.3 FF-4.4 FF-4.5: the packed tarballs, installed with no workspace links, pass every check', async () => {
    const r = await runPublishedShapeCheck({ build: true });
    const failed = r.checks.filter((c) => !c.ok).map((c) => `${c.id}: ${c.detail}`);
    expect(failed).toEqual([]);
    expect(r.ok).toBe(true);
    const ids = r.checks.map((c) => c.id);
    for (const id of ['FF-4.1', 'FF-4.2', 'FF-4.3', 'FF-4.4a', 'FF-4.4b', 'FF-4.5']) expect(ids).toContain(id);
  }, 180_000);

  it('FF-4.6 the script runs on its own, prints one line per check and exits 0', () => {
    const r = spawnSync(process.execPath, [SCRIPT, '--no-build'], { encoding: 'utf8', timeout: 170_000 });
    expect(r.stdout).toContain('PASS FF-4.1');
    expect(r.stdout).toContain('The published shape works.');
    expect(r.status).toBe(0);
  }, 180_000);

  it('FF-4.4 the MCP judge accepts the real tool names in any order and the matching version', () => {
    expect(judgeMcpAnswers(goodAnswers('0.2.0'), '0.2.0').every((c) => c.ok)).toBe(true);
  });

  it('FF-4.4 the MCP judge fails on a missing tool, an extra tool, a wrong version and no answer', () => {
    const missing = goodAnswers('0.2.0');
    missing.set(2, { result: { tools: [{ name: 'scan_repo' }] } });
    expect(judgeMcpAnswers(missing, '0.2.0').find((c) => c.id === 'FF-4.4b')?.ok).toBe(false);
    const extra = goodAnswers('0.2.0');
    extra.set(2, { result: { tools: [...EXPECTED_TOOLS, 'run_shell'].map((name) => ({ name })) } });
    expect(judgeMcpAnswers(extra, '0.2.0').find((c) => c.id === 'FF-4.4b')?.ok).toBe(false);
    expect(judgeMcpAnswers(goodAnswers('0.1.2'), '0.2.0').find((c) => c.id === 'FF-4.4a')?.ok).toBe(false);
    expect(judgeMcpAnswers(new Map(), '0.2.0').every((c) => !c.ok)).toBe(true);
  });

  it('FF-4.4 the expected tool names are the ones the server source registers', () => {
    const src = readFileSync(join(ROOT, 'packages/mcp-server/src/index.ts'), 'utf8');
    const registered = [...src.matchAll(/registerTool\(\s*'([a-z_]+)'/g)].map((m) => m[1]).sort();
    expect(registered).toEqual([...EXPECTED_TOOLS].sort());
  });

  it('FF-4.7 a missing build is reported as a failed check, never as a pass, and nothing is left behind', async () => {
    const empty = mkdtempSync(join(tmpdir(), 'exorcist-empty-root-'));
    try {
      const r = await runPublishedShapeCheck({ root: empty, build: false });
      expect(r.ok).toBe(false);
      expect(r.checks.some((c) => !c.ok)).toBe(true);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  it('FF-4.8 the child processes get a temporary HOME and none of our state', () => {
    const env = cleanEnv('/tmp/somewhere');
    expect(env.HOME).toBe('/tmp/somewhere');
    expect(env.EXORCIST_DIR).toBe(join('/tmp/somewhere', '.exorcist'));
    expect(Object.keys(env).filter((k) => /TOKEN|SECRET|AWS_|NPM_/.test(k))).toEqual([]);
  });

  it('FF-4.9 CI runs the script in its own job', () => {
    const ci = readFileSync(join(ROOT, '.github/workflows/ci.yml'), 'utf8');
    expect(ci).toMatch(/\n  published-shape:\n/);
    expect(ci).toContain('node scripts/published-shape.mjs');
  });
});
