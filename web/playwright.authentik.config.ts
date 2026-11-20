import { defineConfig, devices } from "@playwright/test";

// The Authentik test (one-product plan, A; ADR-0044). scripts/e2e/authentik.sh (make e2e-authentik)
// brings up deploy/docker-compose.yml set up with setup.sh --with-authentik, addressed by IP with
// EasyRMM's own certificate authority, then runs this. Authentik's name resolves nowhere, so
// Chromium is told it is 127.0.0.1, and accepts the edge's certificate by its public key.

const spki = process.env.EASYRMM_AUTHENTIK_SPKI;
const signIn = process.env.EASYRMM_AUTHENTIK_SIGNIN_HOST;
const ci = Boolean(process.env.CI);

const args: string[] = [];
if (spki) args.push(`--ignore-certificate-errors-spki-list=${spki}`);
if (signIn) args.push(`--host-resolver-rules=MAP ${signIn} 127.0.0.1`);

export default defineConfig({
  testDir: "./e2e-authentik",
  outputDir: "./e2e-authentik/.results",
  // One story on one deployment.
  fullyParallel: false,
  workers: 1,
  forbidOnly: ci,
  retries: 0,
  // Authentik answers some steps of its flows in seconds, and the test waits for it to start again.
  timeout: 300_000,
  expect: { timeout: 30_000 },
  reporter: ci ? [["list"], ["html", { open: "never", outputFolder: "./e2e-authentik/.report" }]] : "list",
  use: {
    baseURL: process.env.EASYRMM_AUTHENTIK_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    navigationTimeout: 60_000,
    ...devices["Desktop Chrome"],
    launchOptions: {
      args,
      ...(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {}),
    },
  },
});
