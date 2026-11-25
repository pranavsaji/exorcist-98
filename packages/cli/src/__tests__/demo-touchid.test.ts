/**
 * scripts/demo-touchid.mjs opens a real system prompt, so it must refuse to run
 * under a test. This is the only thing checked here: the demo itself is run by a person.
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const script = fileURLToPath(new URL('../../../../scripts/demo-touchid.mjs', import.meta.url));
describe('scripts/demo-touchid.mjs', () => {
  it('refuses to run under VITEST and starts nothing', () => {
    const r = spawnSync(process.execPath, [script], { env: { ...process.env, VITEST: 'true' }, encoding: 'utf8', timeout: 10000 });
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('refuses to run');
    expect(r.stderr).toContain('VITEST');
    expect(r.stdout).toBe('');
  });
});
