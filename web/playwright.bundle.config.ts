import { defineConfig, devices } from "@playwright/test";

// The bundle test (one-product plan, B8). scripts/e2e/bundle.sh (make e2e-bundle) brings up
// deploy/docker-compose.yml with the patching engine, addressed by IP with EasyRMM's own
// certificate authority, and a Linux machine on the host's network, then runs this. Chromium
// accepts the server's certificate by its public key, and nothing else.

const spki = process.env.EASYRMM_BUNDLE_SPKI;
const ci = Boolean(process.env.CI);

export default defineConfig({
  testDir: "./e2e-bundle",
  outputDir: "./e2e-bundle/.results",
  // One story on one deployment.
  fullyParallel: false,
  workers: 1,
  forbidOnly: ci,
  retries: 0,
  // Installing the EasyPatch agent, a scan and an install each wait for agents to check in.
  timeout: 600_000,
  expect: { timeout: 15_000 },
  reporter: ci ? [["list"], ["html", { open: "never", outputFolder: "./e2e-bundle/.report" }]] : "list",
  use: {
    baseURL: process.env.EASYRMM_BUNDLE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    ...devices["Desktop Chrome"],
    launchOptions: {
      args: spki ? [`--ignore-certificate-errors-spki-list=${spki}`] : [],
      ...(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {}),
    },
  },
});
