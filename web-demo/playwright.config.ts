import { defineConfig } from '@playwright/test';

const CI = !!process.env.CI;

// Optional escape hatch: point at a specific Chromium/headless-shell binary.
// Handy when the Playwright-managed build is unavailable (e.g. corporate
// antivirus quarantines the downloaded executable). Unset in CI.
const chromiumExecutable = process.env.PW_CHROMIUM_EXECUTABLE;

export default defineConfig({
  testDir: './e2e',
  // Each seal/open runs genuine PBKDF2 (600k iters × 3) + KpqC WASM + reveal
  // animation, so allow generous per-test time.
  timeout: 60_000,
  expect: { timeout: 30_000 },
  // Real crypto is CPU-bound; serialise on CI so parallel pages don't starve
  // each other into timeouts. Locally, let Playwright pick a worker count.
  workers: CI ? 1 : undefined,
  retries: CI ? 2 : 0,
  reporter: CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://localhost:4213/crypto-lab-quantum-vault-kpqc/',
    headless: true,
    screenshot: 'only-on-failure',
    trace: 'on-first-retry',
    launchOptions: {
      ...(chromiumExecutable ? { executablePath: chromiumExecutable } : {}),
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-gpu', '--disable-dev-shm-usage'],
    },
  },
  webServer: {
    command: 'npm run dev -- --port 4213 --strictPort',
    port: 4213,
    reuseExistingServer: !CI,
    timeout: 60_000,
  },
});
