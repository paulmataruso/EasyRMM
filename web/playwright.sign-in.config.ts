import { defineConfig, devices } from "@playwright/test";

// Signing in once across EasyRMM and EasyPatch (integration plan, P4). scripts/e2e/sign-in-across.sh
// (make e2e-sign-in) starts both servers behind TLS on different registrable domains, then runs this.
// Chromium accepts the run's certificate by its public key, and nothing else.

const spki = process.env.EASYRMM_SIGNIN_SPKI;
const ci = Boolean(process.env.CI);

export default defineConfig({
  testDir: "./e2e-sign-in",
  outputDir: "./e2e-sign-in/.results",
  // One story across two servers.
  fullyParallel: false,
  workers: 1,
  forbidOnly: ci,
  retries: 0,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: ci ? [["list"], ["html", { open: "never", outputFolder: "./e2e-sign-in/.report" }]] : "list",
  use: {
    baseURL: process.env.EASYRMM_SIGNIN_RMM_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    ...devices["Desktop Chrome"],
    launchOptions: {
      args: spki ? [`--ignore-certificate-errors-spki-list=${spki}`] : [],
      ...(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {}),
    },
  },
});
