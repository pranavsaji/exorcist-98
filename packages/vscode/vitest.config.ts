import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  resolve: {
    // The editor provides `vscode` at run time; tests use a small fake of the parts the glue touches.
    alias: { vscode: fileURLToPath(new URL('./src/__tests__/vscode-mock.ts', import.meta.url)) },
  },
  test: { globals: false },
});
