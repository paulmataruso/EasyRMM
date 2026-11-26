// ADR-0072 slices S5 and S6, in the browser, against the server console.spec.ts leaves behind: the Install tab at the
// organization and the site (its token form fixed to the scope), the People tab, and the old URLs that now land on them.

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

async function openOrganization(page: Page) {
  await page.goto("/organizations");
  await page
    .getByRole("link", { name: "Contoso Dental Group" })
    .first()
    .click();
  await expect(page).toHaveURL(/\/organizations\/[0-9a-f-]{36}$/);
  return page.url();
}

test("the organization's Install tab makes a token for one of its sites", async () => {
  const page = admin;
  const orgUrl = await openOrganization(page);
  await page.getByRole("tab", { name: "Install" }).click();
  await expect(page).toHaveURL(/\?tab=install$/);
  await expect(page.getByRole("heading", { name: "Deployment tokens" })).toBeVisible();
  // Only this organization's sites are offered, and there is no approval choice.
  const site = page.getByLabel(/^Site/);
  await expect(site).toBeVisible();
  await expect(
    site.locator("option", { hasText: "Downtown clinic" }),
  ).toHaveCount(1);
  await expect(page.getByRole("radio", { name: "Wait for approval" })).toHaveCount(0);
  await site.selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Token name/).fill("S56 rollout");
  await page.getByRole("button", { name: "Create token" }).click();
  await expect(page.getByRole("heading", { name: "Install the agent" })).toBeVisible();
  await page.reload();
  await expect(page.getByRole("tab", { name: "Install" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  expect(orgUrl).toBeTruthy();
});

test("the site's Install tab fixes the site, and /devices/add?siteId= lands on it", async () => {
  const page = admin;
  await openOrganization(page);
  await page.getByRole("link", { name: "Downtown clinic" }).first().click();
  await expect(page).toHaveURL(/\/sites\/[0-9a-f-]{36}$/);
  const siteUrl = page.url();
  const siteId = siteUrl.split("/").pop()!;
  await page.getByRole("tab", { name: "Install" }).click();
  await expect(page).toHaveURL(/\?tab=install$/);
  await expect(page.getByLabel(/^Site/)).toHaveCount(0);
  await expect(page.getByText("S56 rollout").first()).toBeVisible();

  await page.goto(`/devices/add?siteId=${siteId}`);
  await expect(page).toHaveURL(new RegExp(`/sites/${siteId}\\?tab=install$`));
  await expect(page.getByRole("tab", { name: "Install" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  // No scope: the picker page stays.
  await page.goto("/devices/add");
  await expect(page.getByLabel(/^Site/)).toBeVisible();
});

test("the People tab lists the organization's people, and the old Users link lands on it", async () => {
  const page = admin;
  const orgUrl = await openOrganization(page);
  const orgId = orgUrl.split("/").pop()!;
  await page.getByRole("tab", { name: "People" }).click();
  await expect(page).toHaveURL(/\?tab=people$/);
  await expect(page.getByRole("button", { name: "Invite user" })).toBeVisible();
  // The scope is fixed: no organization filter.
  await expect(page.getByLabel("Organization", { exact: true })).toHaveCount(0);

  await page.goto(`/settings?tab=users&organizationId=${orgId}`);
  await expect(page).toHaveURL(new RegExp(`/organizations/${orgId}\\?tab=people$`));
  await expect(page.getByRole("tab", { name: "People" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  // Settings > Users stays the list of everyone.
  await page.goto("/settings?tab=users");
  await expect(page).toHaveURL(/\/settings\?tab=users$/);
  await expect(page.getByLabel("Organization", { exact: true })).toBeVisible();
});

test("the site's strip has no People tab", async () => {
  const page = admin;
  await openOrganization(page);
  await page.getByRole("link", { name: "Downtown clinic" }).first().click();
  await expect(page.getByRole("tab", { name: "People" })).toHaveCount(0);
});

test("the session says where permissions hold, none platform-wide for a super administrator", async () => {
  const res = await admin.request.get("/api/v1/auth/session");
  const view = await res.json();
  expect(view.scopedPermissions).toEqual({});
  expect(view.globalPermissions).toContain("enrollment.manage");
});
