import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Never pop real desktop notifications while testing (S-012).
    env: { EXORCIST_NOTIFY: '0' }, globals: false },
});
