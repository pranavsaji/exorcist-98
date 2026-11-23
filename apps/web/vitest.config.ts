import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  esbuild: { jsx: 'automatic' },
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  // No registry lookups for the exorcism patch's EX-010 pins in tests.
  test: { globals: false, environment: 'node', env: { EXORCIST_OFFLINE: '1' } },
});
