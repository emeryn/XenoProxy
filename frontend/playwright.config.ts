import { defineConfig, devices } from '@playwright/test';

/**
 * The screenshot suite runs against a live stack, seeded with the fixtures in
 * `e2e/fixtures/`. XENOPROXY_BASE_URL points at the proxy. Captures use the dark
 * theme because that is what the application ships with.
 */
export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.XENOPROXY_BASE_URL ?? 'http://localhost:8099',
    viewport: { width: 1440, height: 900 },
    colorScheme: 'dark',
    locale: 'en-GB',
    timezoneId: 'UTC',
    ignoreHTTPSErrors: false,
    screenshot: 'off',
    video: 'off',
    trace: 'off',
  },
  // The device preset carries its own 1280x720 viewport, and a project-level
  // `use` beats the top-level one, so the size has to be restated after the
  // spread or the captures come out at the preset's size.
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
  ],
});
