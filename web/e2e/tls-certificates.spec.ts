// ADR-0055, slice 5a: Settings > Certificates, in the browser. The console and server are the real ones: the server here
// does not obtain certificates, and the page says so from the server's own answer. What an acme install would show
// (a failing name, Retry now, the banner) is answered by the test, which also catches the call the console sends.

import { expect, test, type Page, type Route } from "@playwright/test";
import { nextCode } from "./authenticator";

const ADMIN = { email: "alex@example.com", password: "harbor lantern quietly 42" };

let admin: Page;
test.describe.configure({ mode: "serial" });
test.beforeAll(async ({ browser }) => {
  admin = await (await browser.newContext()).newPage();
  await admin.goto("/login");
  await admin.getByLabel(/^Email/).fill(ADMIN.email);
  await admin.getByLabel(/^Password/).fill(ADMIN.password);
  await admin.getByRole("button", { name: "Sign in" }).click();
  await admin.getByLabel(/^Verification code/).fill(await nextCode(admin, ADMIN.email));
  await admin.getByRole("button", { name: "Verify" }).click();
  await expect(admin).toHaveURL(/\/$/);
});
test.afterAll(async () => {
  await admin.context().close();
});

const json = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body) });

test("the page says where this server's certificates come from", async () => {
  await admin.goto("/settings?tab=certificates");
  await expect(admin.getByRole("heading", { name: "Certificates" }).first()).toBeVisible();
  await expect(admin.getByText(/TLS mode:/)).toBeVisible();
});

test("a failing name shows the CA's answer, the banner is across the console, and Retry now is sent", async () => {
  const retried: string[] = [];
  const status = {
    mode: "acme",
    managed: true,
    status: {
      directory: "https://acme-v02.api.letsencrypt.org/directory",
      email: "",
      account: true,
      held: false,
      warnings: [],
      now: new Date().toISOString(),
      names: [
        {
          name: "rmm.example.test",
          state: "failing",
          imported: false,
          failures: 2,
          failingSince: new Date(Date.now() - 3600_000).toISOString(),
          lastError: "urn:ietf:params:acme:error:unauthorized: could not validate",
          alert: "warning",
          alertReason: "no certificate for an hour: orders are failing",
        },
      ],
    },
  };
  await admin.route("**/api/v1/settings/certificates", (r) => json(r, status));
  await admin.route("**/api/v1/settings/certificates/*/retry", async (r) => {
    retried.push(r.request().url());
    await json(r, { status: "started" }, 202);
  });
  await admin.goto("/settings?tab=certificates");
  await expect(admin.getByText("Failing", { exact: true })).toBeVisible();
  await expect(admin.getByText(/could not validate/)).toBeVisible();
  await expect(admin.getByTestId("certificate-banner")).toContainText("rmm.example.test");
  await admin.getByRole("button", { name: /Retry now/ }).click();
  await expect.poll(() => retried.length).toBe(1);
  expect(retried[0]).toContain("/settings/certificates/rmm.example.test/retry");
  // The banner shows on other pages too.
  await admin.goto("/");
  await expect(admin.getByTestId("certificate-banner")).toBeVisible();
});
