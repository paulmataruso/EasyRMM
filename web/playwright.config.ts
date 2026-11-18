import { defineConfig, devices } from "@playwright/test";

// Browser end-to-end tests against a real EasyRMM server and PostgreSQL.
//
// Playwright starts two processes:
//   1. scripts/e2e/start-server.sh: a throwaway server on a fresh database (offload mode, plain HTTP);
//   2. `vite preview`: the production build of this console, proxying /api to that server with the
//      public Host and Origin, the way the TLS edge does in production.
// Run with `make e2e` (builds everything first), or `npx playwright test` after `make build web`.

const apiPort = Number(process.env.EASYRMM_E2E_PORT ?? 18180);
const webPort = Number(process.env.EASYRMM_E2E_WEB_PORT ?? 4173);
const ci = Boolean(process.env.CI);

export default defineConfig({
  testDir: "./e2e",
  outputDir: "./e2e/.results",
  // One shared server and database: the suite is a single ordered story.
  fullyParallel: false,
  workers: 1,
  forbidOnly: ci,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: ci ? [["list"], ["html", { open: "never", outputFolder: "./e2e/.report" }]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${webPort}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    ...devices["Desktop Chrome"],
    launchOptions: process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {},
  },
  webServer: [
    {
      command: "../scripts/e2e/start-server.sh",
      url: `http://127.0.0.1:${apiPort + 11}/readyz`,
      env: { EASYRMM_E2E_PORT: String(apiPort) },
      reuseExistingServer: false,
      timeout: 60_000,
      stdout: "pipe",
      stderr: "pipe",
    },
    {
      command: `npx vite preview --host 127.0.0.1 --port ${webPort} --strictPort`,
      url: `http://127.0.0.1:${webPort}/`,
      env: { EASYRMM_DEV_API: `http://127.0.0.1:${apiPort}` },
      reuseExistingServer: false,
      timeout: 30_000,
    },
  ],
});
