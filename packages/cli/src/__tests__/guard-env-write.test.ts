import { describe, it, expect, afterEach } from 'vitest';
import fc from 'fast-check';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decideEnvWrite } from '@exorcist-98/core';
import { guardEnvWriteCommand } from '../commands/guard-env-write.js';
const dirs: string[] = [];
afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
const ENV_VALUE = 'EXAMPLE_TOKEN_DO_NOT_USE_0123456789';
function project(env: string | null = `API_KEY=${ENV_VALUE}\nDEBUG=true\n`): string {
  const dir = mkdtempSync(join(tmpdir(), 'exorcist-ew-'));
  dirs.push(dir);
  if (env !== null) writeFileSync(join(dir, '.env'), env);
  return dir;
}
const event = (cwd: string, tool_name: string, tool_input: Record<string, unknown>) =>
  JSON.stringify({ hook_event_name: 'PreToolUse', cwd, tool_name, tool_input });
function run(stdin: string) {
  let err = '';
  const code = guardEnvWriteCommand(stdin, { out: () => undefined, err: (s) => { err += s; } });
  return { code, err };
}
describe('guard-env-write', () => {
  it('CT-14: blocks fs_write of an .env value into another file, naming the path but not the value', () => {
    const dir = project();
    const r = run(event(dir, 'fs_write', { command: 'create', path: 'src/config.ts', file_text: `export const k = "${ENV_VALUE}";` }));
    expect(r.code).toBe(2);
    expect(r.err).toContain('src/config.ts');
    expect(r.err).toContain('.env');
    expect(r.err).not.toContain(ENV_VALUE);
    expect(r.err.trim().split('\n')).toHaveLength(1);
  });
  it('CT-14: blocks str_replace whose new_str holds an .env value', () => {
    const dir = project();
    expect(run(event(dir, 'str_replace', { path: 'a.ts', old_str: 'x', new_str: `k=${ENV_VALUE}` })).code).toBe(2);
  });
  it('CT-14: allows the same write into .env files', () => {
    const dir = project();
    for (const path of ['.env', '.env.local', 'app/.env.production', '/abs/dir/.env']) {
      expect(run(event(dir, 'fs_write', { path, file_text: `K=${ENV_VALUE}` })).code, path).toBe(0);
    }
  });
  it('CT-14: does not treat a look-alike name as an .env file', () => {
    const dir = project();
    expect(run(event(dir, 'fs_write', { path: '.envoy.yaml', file_text: ENV_VALUE })).code).toBe(2);
  });
  it('CT-14: an .env value only in old_str (text removed) is allowed', () => {
    const dir = project();
    expect(run(event(dir, 'str_replace', { path: 'a.ts', old_str: ENV_VALUE, new_str: 'process.env.K' })).code).toBe(0);
  });
  it('CT-14: allows content without an .env value, short values, and other tools', () => {
    const dir = project();
    expect(run(event(dir, 'fs_write', { path: 'a.ts', file_text: 'const debug = true;' })).code).toBe(0);
    expect(run(event(dir, 'fs_read', { path: 'a.ts', file_text: ENV_VALUE })).code).toBe(0);
  });
  it('CT-14: allows on unparsable input, missing tool_input and no .env file', () => {
    expect(run('not json').code).toBe(0);
    expect(run('').code).toBe(0);
    expect(run('{"tool_name":"fs_write"}').code).toBe(0);
    expect(run(event(project(null), 'fs_write', { path: 'a.ts', file_text: ENV_VALUE })).code).toBe(0);
  });
});
describe('guard-env-write properties', () => {
  // Property 6: Env-value write guard round trip. Validates: Requirements CT-14
  const valueArb = fc.stringMatching(/^[A-Za-z0-9]{12,32}$/).map((v) => `Zq${v}`);
  const nameArb = fc.stringMatching(/^[a-z]{1,8}$/);
  const dirArb = fc.constantFrom('', 'src/', 'a/b/', '/tmp/x/');
  it('CT-14: an env value written to a non-.env path is blocked, to a .env* path is allowed', () => {
    fc.assert(fc.property(
      valueArb, nameArb, dirArb, fc.constantFrom('.env', '.env.local', '.env.production'), fc.constantFrom('fs_write', 'str_replace'),
      (value, name, dir, envName, tool) => {
        const key = tool === 'fs_write' ? 'file_text' : 'new_str';
        const body = `x=${value}\n`;
        const other = decideEnvWrite({ tool_name: tool, tool_input: { path: `${dir}${name}.ts`, [key]: body } }, [value]);
        expect(other.block).toBe(true);
        const env = decideEnvWrite({ tool_name: tool, tool_input: { path: `${dir}${envName}`, [key]: body } }, [value]);
        expect(env.block).toBe(false);
        const clean = decideEnvWrite({ tool_name: tool, tool_input: { path: `${dir}${name}.ts`, [key]: `x=${name}` } }, [value]);
        expect(clean.block).toBe(false);
      },
    ), { numRuns: 100 });
  });
});
