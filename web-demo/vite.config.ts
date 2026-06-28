import { defineConfig, createLogger } from 'vite';

// The committed Emscripten loaders (src/crypto/wasm/*.js) contain dead Node.js
// code paths (`node:fs`, `node:module`) and a `new URL('*.wasm', import.meta.url)`
// fallback. None of it runs in the browser: smaug.ts / haetae.ts fetch the .wasm
// binary explicitly and pass it via `wasmBinary`, and override `locateFile`.
// The bundler still *sees* those references and emits cosmetic warnings, so we
// filter exactly those two known-benign messages — every other warning passes
// through untouched.
const logger = createLogger();
const baseWarn = logger.warn;
const baseWarnOnce = logger.warnOnce;
const BENIGN_WARNINGS = [
  'has been externalized for browser compatibility',
  "doesn't exist at build time, it will remain unchanged",
];
const isBenign = (msg: string): boolean =>
  BENIGN_WARNINGS.some((fragment) => msg.includes(fragment));
logger.warn = (msg, options) => {
  if (isBenign(msg)) return;
  baseWarn(msg, options);
};
logger.warnOnce = (msg, options) => {
  if (isBenign(msg)) return;
  baseWarnOnce(msg, options);
};

export default defineConfig({
  // Must match the GitHub repository name exactly for GitHub Pages
  base: '/crypto-lab-quantum-vault-kpqc/',
  customLogger: logger,
  build: {
    outDir: 'dist',
    // Enable source maps for easier debugging of production builds
    sourcemap: true,
  },
  // Enable high-resolution performance.now() for timing analysis
  // These headers are required for Cross-Origin Isolation
  server: {
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
});
