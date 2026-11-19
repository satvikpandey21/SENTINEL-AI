import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './e2e',
  testMatch:
    process.env.SENTINEL_E2E_PRODUCTION === '1'
      ? ['**/dashboard.spec.ts', '**/production.spec.ts']
      : '**/*.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 60000,
  expect: { timeout: 15000 },
  reporter: 'list',
  retries: 0,
  use: {
    baseURL:
      process.env.SENTINEL_E2E_PRODUCTION === '1'
        ? 'https://localhost:8443'
        : 'http://localhost:5173',
    // Only the isolated local test CA is untrusted; public acceptance must verify public TLS.
    ignoreHTTPSErrors: process.env.SENTINEL_E2E_PRODUCTION === '1',
    browserName: 'chromium',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  webServer:
    process.env.SENTINEL_E2E_PRODUCTION === '1'
      ? undefined
      : {
          command: 'npm run preview',
          url: 'http://localhost:5173',
          reuseExistingServer: !process.env.CI,
          timeout: 60000,
        },
});
