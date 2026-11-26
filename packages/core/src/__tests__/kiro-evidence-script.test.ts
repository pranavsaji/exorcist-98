/** m13-kiro-evidence: scripts/kiro-evidence.mjs run against a temporary fake ~/.kiro tree (task 5.3). */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { fromRoot } from './repo-root.js';

const SCRIPT = fromRoot('scripts/kiro-evidence.mjs');
// Built at run time so this file holds no secret-shaped text.
const TOKEN = `ghp_${'a1B2c3D4e5'.repeat(4).slice(0, 36)}`;

let base: string;
let home: string;
let sessions: string;
let out: string;

const envelope = (n: number, payload: Record<string, unknown>): string =>
  JSON.stringify({ id: `m${n}`, timestamp: `2026-01-01T10:00:00.${String(n).padStart(3, '0')}Z`, payload });

function addSession(hash: string, id: string, workspace: string, messages: string[], extraKeys: Record<string, unknown> = {}): void {
  const dir = join(sessions, hash, id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'session.json'),
    JSON.stringify({ id, title: `Title ${id}`, agentMode: 'spec', createdAt: '2026-01-01T10:00:00.000Z', lastModifiedAt: '2026-01-01T11:00:00.000Z', workspacePaths: [workspace], ...extraKeys }),
  );
  writeFileSync(join(dir, 'messages.jsonl'), messages.join('\n') + '\n');
}

function run(): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [SCRIPT, '--sessions', sessions, '--home', home, '--out', out], { encoding: 'utf8', timeout: 60_000 });
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}
const readIndex = (): { sessions: Array<{ id: string; title: string }>; totals: Record<string, unknown> } =>
  JSON.parse(readFileSync(join(out, 'index.json'), 'utf8')) as { sessions: Array<{ id: string; title: string }>; totals: Record<string, unknown> };
const outFiles = (): string[] => (existsSync(out) ? readdirSync(out).sort() : []);

const goodMessages = (): string[] => [
  envelope(1, { type: 'tool_call', toolCallId: 'c1', toolName: 'read_file' }),
  envelope(2, { type: 'tool_result', toolCallId: 'c1', status: 'completed', content: `see ${home}/proj/file.ts` }),
  envelope(3, { type: 'usage_summary', promptTurnSummaries: [{ unit: 'credit', usage: 2 }] }),
];

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'ke-script-'));
  home = join(base, 'home');
  sessions = join(home, '.kiro', 'sessions');
  out = join(base, 'out');
  mkdirSync(sessions, { recursive: true });
  // A settings folder next to the sessions, and one inside it, both holding a token and made unreadable.
  for (const dir of [join(home, '.kiro', 'settings'), join(sessions, 'settings', 'sess_settings')]) {
    mkdirSync(dir, { recursive: true });
    for (const name of ['mcp.json', 'session.json', 'messages.jsonl']) {
      const f = join(dir, name);
      writeFileSync(f, name === 'session.json' ? JSON.stringify({ id: 'sess_settings', workspacePaths: ['/x/exorcist-98'] }) : `${TOKEN}\n`);
      chmodSync(f, 0o000);
    }
  }
});

afterEach(() => {
  for (const dir of [join(home, '.kiro', 'settings'), join(sessions, 'settings', 'sess_settings')]) {
    for (const name of ['mcp.json', 'session.json', 'messages.jsonl']) {
      try { chmodSync(join(dir, name), 0o600); } catch { /* already gone */ }
    }
  }
  rmSync(base, { recursive: true, force: true });
});

describe('scripts/kiro-evidence.mjs against a fake sessions tree', () => {
  it('KE-1: reads every session under every workspace-hash folder and writes one transcript each', () => {
    addSession('aaaaaaaaaaaaaaaa', 'sess_one', '/Users/a/exorcist-98', goodMessages());
    addSession('bbbbbbbbbbbbbbbb', 'sess_two', '/Users/a/exorcist-98-wt-evidence', goodMessages());
    const r = run();
    expect(r.status).toBe(0);
    expect(outFiles()).toEqual(['index.json', 'sess_one.jsonl.gz', 'sess_two.jsonl.gz']);
    expect(readIndex().totals).toMatchObject({ sessionsKept: 2, sessionsSkipped: 0, credits: 4 });
  });

  it('KE-7: a session of another workspace is counted as skipped and never appears in any output file', () => {
    addSession('aaaaaaaaaaaaaaaa', 'sess_keep', '/Users/a/exorcist-98', goodMessages());
    addSession('aaaaaaaaaaaaaaaa', 'sess_other', '/Users/a/other-project', goodMessages(), { title: 'OTHER-SECRET-TITLE' });
    expect(run().status).toBe(0);
    expect(outFiles()).toEqual(['index.json', 'sess_keep.jsonl.gz']);
    const index = readIndex();
    expect(index.totals).toMatchObject({ sessionsKept: 1, sessionsSkipped: 1 });
    expect(JSON.stringify(index)).not.toContain('sess_other');
    expect(JSON.stringify(index)).not.toContain('OTHER-SECRET-TITLE');
  });

  it('KE-1: the home path becomes ~ and a malformed line does not stop the session', () => {
    addSession('aaaaaaaaaaaaaaaa', 'sess_one', '/Users/a/exorcist-98', [...goodMessages(), 'not json at all {']);
    expect(run().status).toBe(0);
    const text = gunzipSync(readFileSync(join(out, 'sess_one.jsonl.gz'))).toString('utf8');
    expect(text.trim().split('\n')).toHaveLength(3);
    expect(text).toContain('~/proj/file.ts');
    expect(text).not.toContain(home);
  });

  it('KE-11: nothing under a settings folder is read or copied, even when it holds a token and looks like a session', () => {
    addSession('aaaaaaaaaaaaaaaa', 'sess_one', '/Users/a/exorcist-98', goodMessages());
    const r = run(); // the settings files are mode 000, so a read would fail the run
    expect(r.status).toBe(0);
    expect(outFiles()).toEqual(['index.json', 'sess_one.jsonl.gz']);
    for (const f of outFiles()) expect(readFileSync(join(out, f)).toString('latin1')).not.toContain(TOKEN);
    expect(readIndex().sessions.map((s) => s.id)).toEqual(['sess_one']);
  });

  it('KE-10: a secret shape that survives redaction deletes the output and exits 1 naming the file and pattern, not the secret', () => {
    addSession('aaaaaaaaaaaaaaaa', 'sess_clean', '/Users/a/exorcist-98', goodMessages());
    // Redaction rewrites string values, not object keys, so a token used as a tool name becomes a key of
    // the per-tool counts in index.json and reaches the rescan.
    addSession('aaaaaaaaaaaaaaaa', 'sess_leaky', '/Users/a/exorcist-98', [envelope(1, { type: 'tool_call', toolCallId: 'c1', toolName: TOKEN })]);
    const r = run();
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/index\.json: github-token x\d+/);
    expect(r.stderr).toContain('github-token');
    expect(r.stderr).not.toContain(TOKEN);
    expect(r.stdout).not.toContain(TOKEN);
    expect(outFiles()).toEqual([]);
  });
  it('KE-48: a planted JWT is redacted, trips nothing, and the report holds no values', () => {
    const j = ['eyJ' + 'a1B2c3D4'.repeat(3), 'eyJ' + 'e5F6g7H8'.repeat(3), 'i9J0k1L2'.repeat(3)].join('.');
    addSession('aaaaaaaaaaaaaaaa', 'sess_one', '/Users/a/exorcist-98', [envelope(1, { type: 'tool_result', toolCallId: 'c1', content: `jwt ${j}` })]);
    const r = run();
    expect(r.status).toBe(0);
    const text = gunzipSync(readFileSync(join(out, 'sess_one.jsonl.gz'))).toString('utf8');
    expect(text).toContain('[redacted jwt]');
    expect(text).not.toContain(j);
  });

  it('KE-58: no written line carries a reasoningSignature or signature key', () => {
    const sig = ['made', 'up', 'sig'].join('-');
    addSession('aaaaaaaaaaaaaaaa', 'sess_sig', '/Users/a/exorcist-98', [
      envelope(1, { type: 'assistant', reasoningSignature: sig, content: [{ type: 'reasoning', text: 'hi', signature: sig }] }),
      envelope(2, { type: 'tool_call', toolCallId: 'c1', toolName: 'read_file', args: { signature: sig, path: 'a.ts' } }),
      envelope(3, { type: 'tool_result', toolCallId: 'c1', content: 'ok', signatures: ['kept'] }),
    ]);
    expect(run().status).toBe(0);
    const text = gunzipSync(readFileSync(join(out, 'sess_sig.jsonl.gz'))).toString('utf8');
    const lines = text.trim().split('\n');
    expect(lines).toHaveLength(3);
    expect(text).not.toContain(sig);
    const hasKey = (v: unknown): boolean =>
      Array.isArray(v) ? v.some(hasKey)
        : typeof v === 'object' && v !== null
          ? Object.entries(v).some(([k, x]) => k === 'reasoningSignature' || k === 'signature' || hasKey(x))
          : false;
    for (const l of lines) expect(hasKey(JSON.parse(l))).toBe(false);
    expect(text).toContain('"signatures"');
  });

  it('KE-52: a JWT that survives redaction (in a key) fails the run with counts only', () => {
    const j = ['eyJ' + 'a1B2c3D4'.repeat(3), 'eyJ' + 'e5F6g7H8'.repeat(3), 'i9J0k1L2'.repeat(3)].join('.');
    addSession('aaaaaaaaaaaaaaaa', 'sess_leaky', '/Users/a/exorcist-98', [envelope(1, { type: 'tool_call', toolCallId: 'c1', toolName: j })]);
    const r = run();
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/index\.json: jwt x\d+/);
    expect(r.stderr).not.toContain(j);
    expect(outFiles()).toEqual([]);
  });

  it('KE-54 KE-55: a sign-in URL in a message and an outside-workspace read leave no URL in the output', () => {
    const url = `https://auth.example.invalid/authorize?client_id=${['c', 'id1'].join('')}&state=${['s', 'tate9'].join('')}&code_challenge=${['ch', 'al7'].join('')}`;
    addSession('aaaaaaaaaaaaaaaa', 'sess_url', '/Users/a/exorcist-98', [
      envelope(1, { type: 'assistant', content: `Open ${url} to sign in.` }),
      envelope(2, { type: 'tool_call', toolCallId: 'r1', toolName: 'read_file', args: { path: `${home}/.k.out` } }),
      envelope(3, { type: 'tool_result', toolCallId: 'r1', status: 'completed', content: `visit ${url}` }),
    ]);
    const r = run();
    expect(r.status).toBe(0);
    const text = gunzipSync(readFileSync(join(out, 'sess_url.jsonl.gz'))).toString('utf8');
    expect(text).not.toContain('auth.example.invalid');
    expect(text).toContain('[redacted sign-in url]');
    expect(text).toContain('[omitted: file outside the workspace]');
  });
  it('KE-59 KE-62: a cat of ~/.npmrc is omitted, a token at the 2 KB cut is redacted, and the run exits 0', () => {
    const tok = `npm_${'aB3dE5gH7jK9mN1pQ3sT5vX7zB9dF1hJ3lN5'}`;
    const text = 'lorem ipsum '.repeat(200).slice(0, 2048 - 14 - 9) + ' ' + tok + ' and more';
    addSession('aaaaaaaaaaaaaaaa', 'sess_ke59', '/Users/a/exorcist-98', [
      envelope(1, { type: 'tool_call', toolCallId: 'c1', toolName: 'execute_bash', args: { command: 'cat ~/.npmrc' } }),
      envelope(2, { type: 'tool_result', toolCallId: 'c1', status: 'completed', content: `//registry.example.invalid/:_authToken=${tok}` }),
      envelope(3, { type: 'tool_call', toolCallId: 'c2', toolName: 'execute_bash', args: { command: 'ls' } }),
      envelope(4, { type: 'tool_result', toolCallId: 'c2', status: 'completed', content: text }),
    ]);
    const r = run();
    expect(r.status).toBe(0);
    const written = gunzipSync(readFileSync(join(out, 'sess_ke59.jsonl.gz'))).toString('utf8');
    expect(written).toContain('[omitted: file outside the workspace]');
    expect(written).not.toContain(tok);
    expect(written).not.toContain('npm_aB3');
    expect(written).not.toContain('_authToken');
    expect(written.trim().split('\n')).toHaveLength(4);
    for (const l of written.trim().split('\n')) expect(() => JSON.parse(l)).not.toThrow();
  });
});
