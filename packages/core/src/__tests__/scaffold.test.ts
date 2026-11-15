import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
// packages/core/src/__tests__/ → packages/core/src/ → packages/core/ → packages/ → root
const root = resolve(__dirname, '../../../../');

const required: string[] = [
  'pnpm-workspace.yaml',
  'tsconfig.base.json',
  'vitest.workspace.ts',
  'package.json',
  '.env.example',
  'apps/web/package.json',
  'apps/web/tsconfig.json',
  'packages/core/package.json',
  'packages/core/tsconfig.json',
  'packages/shield/package.json',
  'packages/shield/tsconfig.json',
  'packages/mcp-server/package.json',
  'packages/mcp-server/tsconfig.json',
  'packages/cli/package.json',
  'packages/cli/tsconfig.json',
  'definitions',
  'fixtures/haunted-repo',
  'power',
  'docs/THREATS.md',
];

describe('REQ-06: repo scaffold', () => {
  for (const rel of required) {
    it(`${rel} exists`, () => {
      expect(existsSync(resolve(root, rel)), `missing: ${rel}`).toBe(true);
    });
  }
});
