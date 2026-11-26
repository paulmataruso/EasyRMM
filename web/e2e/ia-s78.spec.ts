// ADR-0072 slices S7 and S8, in the browser, against the server console.spec.ts leaves behind: alert policies at three
// levels (shared in Settings, an organization's and a site's on their pages), the Alerts link and old URL, and the
// Patching settings that moved to the organization and site pages with their old URLs redirecting.

import { expect, test, type Page } from "@playwright/test";
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

let orgUrl = "";
let siteUrl = "";

test("Settings lists the shared alert policies, and Alerts links to them at Everything", async () => {
  const page = admin;
  await page.goto("/settings?tab=alert-policies");
  await expect(
    page.getByRole("heading", { name: "Alert policies", level: 1 }),
  ).toBeVisible();
  await expect(page.getByRole("table").getByRole("row").nth(1)).toBeVisible();
  await expect(page.getByRole("button", { name: "New policy" })).toBeVisible();
  // Only shared policies are listed here.
  await expect(
    page.getByRole("cell", { name: "Every device" }).first(),
  ).toBeVisible();

  await page.goto("/alerts");
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await expect(page).toHaveURL(/\/settings\?tab=alert-policies$/);
  await expect(page.getByRole("tab", { name: "Policies" })).toHaveCount(0);
});

test("an organization's page adds and lists its own alert policy, and the old Alerts address leads there", async () => {
  const page = admin;
  await page.goto("/organizations");
  await page
    .getByRole("link", { name: "Contoso Dental Group" })
    .first()
    .click();
  await expect(page).toHaveURL(/\/organizations\/[0-9a-f-]{36}$/);
  orgUrl = page.url();
  await page.getByRole("tab", { name: "Alert policies" }).click();
  await expect(page).toHaveURL(/\?tab=alert-policies$/);
  await page.getByRole("button", { name: "New policy" }).click();
  const dialog = page.getByRole("dialog", { name: "New alert policy" });
  await expect(dialog.getByText("Contoso Dental Group")).toBeVisible();
  await expect(dialog.getByLabel("Applies to")).toHaveCount(0);
  await dialog.getByLabel(/Name/).fill("Contoso memory watch");
  await dialog.getByRole("button", { name: "Add policy" }).click();
  await expect(
    page.getByRole("table").getByText("Contoso memory watch"),
  ).toBeVisible();
  await expect(
    page.getByRole("table").getByText("Contoso Dental Group").first(),
  ).toBeVisible();

  // Alerts narrowed to the organization link to its policies; the old tab address goes there too.
  const id = orgUrl.split("/").pop()!;
  await page.goto(`/alerts?organizationId=${id}`);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await expect(page).toHaveURL(
    new RegExp(`/organizations/${id}\\?tab=alert-policies$`),
  );
  await page.goto(`/alerts?tab=policies&organizationId=${id}`);
  await expect(page).toHaveURL(
    new RegExp(`/organizations/${id}\\?tab=alert-policies$`),
  );
  await expect(
    page.getByRole("table").getByText("Contoso memory watch"),
  ).toBeVisible();
});

test("a site's page has its own alert policies, apart from the organization's", async () => {
  const page = admin;
  await page.goto(orgUrl);
  await page.getByRole("link", { name: "Downtown clinic" }).first().click();
  await expect(page).toHaveURL(/\/sites\/[0-9a-f-]{36}$/);
  siteUrl = page.url();
  await page.getByRole("tab", { name: "Alert policies" }).click();
  await expect(
    page.getByRole("table").getByText("Contoso memory watch"),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "New policy" }).first().click();
  const dialog = page.getByRole("dialog", { name: "New alert policy" });
  await expect(dialog.getByText("Downtown clinic")).toBeVisible();
  await dialog.getByLabel(/Name/).fill("Downtown disks");
  await dialog.getByRole("button", { name: "Add policy" }).click();
  await expect(
    page.getByRole("table").getByText("Downtown disks"),
  ).toBeVisible();

  const siteId = siteUrl.split("/").pop()!;
  await page.goto(`/alerts?siteId=${siteId}`);
  await page.getByRole("link", { name: "Policies", exact: true }).click();
  await expect(page).toHaveURL(
    new RegExp(`/sites/${siteId}\\?tab=alert-policies$`),
  );
});

test("the Patching settings are on the organization and site, and Settings keeps the server-wide ones", async () => {
  const page = admin;
  await page.goto(orgUrl);
  const patching = page.getByRole("tab", { name: "Patching" });
  // The tab shows once the patching engine's stand-in is set up.
  if ((await patching.count()) > 0) {
    await patching.click();
    await expect(page).toHaveURL(/\?tab=patching$/);
    await expect(
      page
        .getByRole("checkbox", { name: /Install automatically/ })
        .or(page.getByText(/being created in the patching engine/)),
    ).toBeVisible();
    await page.goto(siteUrl);
    await expect(page.getByRole("tab", { name: "Patching" })).toBeVisible();
  }

  await page.goto("/settings?tab=patching");
  await expect(
    page.getByRole("heading", { name: "Patching", level: 1 }),
  ).toBeVisible();
  await expect(
    page.getByRole("radio", { name: "Report schedules" }),
  ).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Patching engine" })).toHaveCount(
    0,
  );

  // The old addresses.
  await page.goto("/settings?tab=easypatch");
  await expect(page).toHaveURL(/\/settings\?tab=patching&view=engine$/);
  const id = orgUrl.split("/").pop()!;
  await page.goto(`/settings?tab=patching&view=reports&organizationId=${id}`);
  await expect(page).toHaveURL(
    new RegExp(`/organizations/${id}\\?tab=patching$`),
  );
  await page.goto("/settings?tab=patching&view=reports");
  await expect(page).toHaveURL(/\/organizations$/);
});
