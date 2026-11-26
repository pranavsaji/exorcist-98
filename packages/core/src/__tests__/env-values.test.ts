import { describe, it, expect, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadEnvValues, parseEnvValues } from '../env-values.js';

const dirs: string[] = [];
function workspace(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'x98-env-'));
  dirs.push(dir);
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  return dir;
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe('loadEnvValues', () => {
  it('CT-13: collects values from every .env* file in the root', () => {
    const dir = workspace({
      '.env': 'API_TOKEN=EXAMPLE_TOKEN_DO_NOT_USE\n',
      '.env.local': 'DB_PASSWORD=EXAMPLE_PASSWORD_DO_NOT_USE\n',
      '.env.production': 'OTHER=EXAMPLE_SECRET_DO_NOT_USE\n',
      'notes.txt': 'NOT_ENV=EXAMPLE_IGNORED_FILE_VALUE\n',
    });
    expect(loadEnvValues(dir).sort()).toEqual([
      'EXAMPLE_PASSWORD_DO_NOT_USE', 'EXAMPLE_SECRET_DO_NOT_USE', 'EXAMPLE_TOKEN_DO_NOT_USE',
    ]);
  });

  it('CT-14: returns an empty list when there is no .env* file or no such folder', () => {
    expect(loadEnvValues(workspace({ 'README.md': 'hello' }))).toEqual([]);
    expect(loadEnvValues(join(tmpdir(), 'x98-env-does-not-exist'))).toEqual([]);
  });

  it('CT-14: does not read .env* files from subfolders', () => {
    const dir = workspace({});
    mkdirSync(join(dir, 'sub'));
    writeFileSync(join(dir, 'sub', '.env'), 'A_KEY=EXAMPLE_TOKEN_DO_NOT_USE\n');
    expect(loadEnvValues(dir)).toEqual([]);
  });

  it('CT-14: drops values that repeat across files', () => {
    const dir = workspace({ '.env': 'A=EXAMPLE_TOKEN_DO_NOT_USE\n', '.env.test': 'B=EXAMPLE_TOKEN_DO_NOT_USE\n' });
    expect(loadEnvValues(dir)).toEqual(['EXAMPLE_TOKEN_DO_NOT_USE']);
  });
});

describe('parseEnvValues', () => {
  it('CT-14: drops short and common values', () => {
    const text = [
      'A=short', 'B=true', 'C=false', 'D=localhost', 'E=123456789012', 'F=development',
      'G=http://localhost:3000', 'H=127.0.0.1', 'KEEP=EXAMPLE_TOKEN_DO_NOT_USE',
    ].join('\n');
    expect(parseEnvValues(text)).toEqual(['EXAMPLE_TOKEN_DO_NOT_USE']);
  });

  it('CT-13: handles quotes, export, comments and blank values', () => {
    const text = [
      '# COMMENT=EXAMPLE_COMMENT_VALUE_ONE',
      'export A="EXAMPLE_DOUBLE_QUOTED_VALUE" # trailing comment',
      "B='EXAMPLE_SINGLE_QUOTED_VALUE'",
      'C=EXAMPLE_UNQUOTED_VALUE # note',
      'D=',
      'E = EXAMPLE_SPACED_VALUE',
      'not an assignment',
      'F="EXAMPLE # hash inside quotes"',
    ].join('\r\n');
    expect(parseEnvValues(text)).toEqual([
      'EXAMPLE_DOUBLE_QUOTED_VALUE', 'EXAMPLE_SINGLE_QUOTED_VALUE', 'EXAMPLE_UNQUOTED_VALUE',
      'EXAMPLE_SPACED_VALUE', 'EXAMPLE # hash inside quotes',
    ]);
  });
});
