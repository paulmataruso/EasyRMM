import { defineConfig, devices } from "@playwright/test";

// The README's screenshots (screenshots/readme.spec.ts): the production build of this console in Chromium, its API
// answered from fictional data. No server runs: `vite preview` proxies /api to a port nothing listens on, and the
// spec answers every request before it gets there. Run with `npm run screenshots` after `npm run build`.

const webPort = Number(process.env.EASYRMM_SCREENSHOTS_PORT ?? 4198);

export default defineConfig({
  testDir: "./screenshots",
  outputDir: "./screenshots/.results",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: "list",
  use: {
    ...devices["Desktop Chrome"],
    baseURL: `http://127.0.0.1:${webPort}`,
    launchOptions: process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {},
  },
  webServer: {
    command: `npx vite preview --host 127.0.0.1 --port ${webPort} --strictPort`,
    url: `http://127.0.0.1:${webPort}/`,
    env: { EASYRMM_DEV_API: "http://127.0.0.1:9" },
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
