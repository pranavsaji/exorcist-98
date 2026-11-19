import { defineWorkspace } from 'vitest/config';

export default defineWorkspace([
  'packages/*/vitest.config.ts',
  'apps/web/vitest.config.ts',
  'fixtures/haunted-repo/vitest.config.ts',
]);
