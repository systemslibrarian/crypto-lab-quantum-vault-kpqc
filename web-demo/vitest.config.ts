import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Node environment gives us globalThis.crypto (WebCrypto) without a browser
    environment: 'node',
    globals: true,
    // Resolve bare imports the same way Vite does
    root: '.',
  },
});
