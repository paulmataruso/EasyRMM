// ADR-0081, slice 3: the keystore's console pages, in the browser. The console and server are the real ones (the server
// console.spec.ts leaves behind; no keystore runs there). The organization's own switch is answered by the real server,
// including its refusal to turn the two-person rule on without two approvers and the step-up it asks for. The alert and
// notice lists are answered by the test, which also catches the resolve call: what is checked is what the console sends.

import { expect, test, type Page, type Route } from "@playwright/test";
import { nextCode } from "./authenticator";

const ADMIN = {
  email: "alex@example.com",
  password: "harbor lantern quietly 42",
};

let admin: Page;
test.describe.configure({ mode: "serial" });
test.beforeAll(async ({ browser }) => {
  admin = await (await browser.newContext()).newPage();
  await admin.goto("/login");
  await admin.getByLabel(/^Email/).fill(ADMIN.email);
  await admin.getByLabel(/^Password/).fill(ADMIN.password);
  await admin.getByRole("button", { name: "Sign in" }).click();
  await admin
    .getByLabel(/^Verification code/)
    .fill(await nextCode(admin, ADMIN.email));
  await admin.getByRole("button", { name: "Verify" }).click();
  await expect(admin).toHaveURL(/\/$/);
});
test.afterAll(async () => {
  await admin.context().close();
});

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });

test("Settings > Keystore says the keystore is away and lists nothing to resolve", async () => {
  const page = admin;
  await page.goto("/settings?tab=keystore");
  await expect(page.getByRole("heading", { name: "Keystore" }).first()).toBeVisible();
  await expect(page.getByText("unavailable")).toBeVisible();
  await expect(page.getByText("No open keystore alerts")).toBeVisible();
});

test("an alert is resolved from the console", async () => {
  const page = admin;
  const resolved: string[] = [];
  let open = true;
  await page.route("**/api/v1/keystore/alerts", (route) =>
    json(route, {
      alerts: open
        ? [
            {
              id: "5c1f0000-0000-4000-8000-000000000001",
              kind: "keystore_sealed",
              subject: "keystore",
              severity: "critical",
              detail: "The keystore has been sealed for more than 15 minutes.",
              openedAt: new Date().toISOString(),
            },
          ]
        : [],
    }),
  );
  await page.route("**/api/v1/keystore/alerts/*/resolve", (route) => {
    resolved.push(new URL(route.request().url()).pathname);
    open = false;
    return route.fulfill({ status: 204 });
  });
  await page.goto("/settings?tab=keystore");
  await page
    .getByRole("button", { name: "Resolve: The keystore is sealed" })
    .click();
  await expect(page.getByText("No open keystore alerts")).toBeVisible();
  expect(resolved).toEqual([
    "/api/v1/keystore/alerts/5c1f0000-0000-4000-8000-000000000001/resolve",
  ]);
});

test("the organization's Recovery keys tab shows the switch off and the real server refuses it without two approvers", async () => {
  const page = admin;
  await page.goto("/organizations");
  await page.getByRole("link", { name: "Contoso Dental Group" }).first().click();
  await expect(page).toHaveURL(/\/organizations\/[0-9a-f-]{36}$/);
  await page.getByRole("tab", { name: "Recovery keys" }).click();
  await expect(page).toHaveURL(/\?tab=recovery-keys$/);
  const sw = page.getByRole("checkbox", {
    name: /Ask a second person to approve each read/,
  });
  await expect(sw).not.toBeChecked();
  await expect(page.getByText(/We recommend turning it on/)).toBeVisible();
  await expect(page.getByText("No recovery key has been read")).toBeVisible();

  await sw.click();
  const stepUp = page.getByRole("dialog", { name: "Confirm it is you" });
  await stepUp
    .getByLabel(/Code from your authenticator app/)
    .fill(await nextCode(page, ADMIN.email));
  await stepUp.getByRole("button", { name: "Confirm" }).click();
  await expect(
    page.getByText(/at least two people in this organization/),
  ).toBeVisible();
  await expect(sw).not.toBeChecked();
});
