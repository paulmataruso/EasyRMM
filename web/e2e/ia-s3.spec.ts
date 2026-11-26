// ADR-0072 slice S3, in the browser, against the server console.spec.ts leaves behind (it sorts first): a group row
// opens the group's page, the Organizations tree shows with the group selected, the old URL redirects, the group is
// renamed, and group-wide verbose logging is switched on its Settings tab. The organization, site and group are the ones
// that story creates.

import { expect, test, type Page } from "@playwright/test";
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

test("a group row opens the group's page, with the Organizations tree and its old URL redirecting", async () => {
  const page = admin;
  await page.goto("/organizations");
  await page.getByRole("link", { name: "Contoso Dental Group" }).first().click();
  await page.getByRole("link", { name: "Downtown clinic" }).first().click();
  await expect(page).toHaveURL(/\/sites\/[0-9a-f-]{36}$/);
  const siteUrl = page.url();
  await page.getByRole("link", { name: "Reception" }).click();
  await expect(page).toHaveURL(/\/groups\/[0-9a-f-]{36}$/);
  const groupId = page.url().split("/").pop() ?? "";
  await expect(page.getByRole("heading", { name: "Reception", level: 1 })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("tab", { name: "Settings" })).toBeVisible();
  await expect(page.getByRole("link", { name: "dt-reception-01" })).toBeVisible();
  // The Organizations section's tree, with the group highlighted.
  await expect(page.getByRole("tree")).toBeVisible();
  await expect(page.getByRole("treeitem", { name: /^Reception/ })).toHaveAttribute("aria-selected", "true");

  // The old link opens the same page.
  await page.goto(`${siteUrl}?groupId=${groupId}`);
  await expect(page).toHaveURL(new RegExp(`/groups/${groupId}$`));
  await expect(page.getByRole("heading", { name: "Reception", level: 1 })).toBeVisible();
});

test("group-wide verbose logging is switched on the Settings tab and shown, read-only, on the device's Logs", async () => {
  const page = admin;
  await page.getByRole("tab", { name: "Settings" }).click();
  await expect(page).toHaveURL(/\?tab=settings$/);
  await page.getByRole("button", { name: "Turn on" }).click();
  await expect(page.getByText("Verbose logging is on", { exact: true })).toBeVisible();
  const settings = page.url();

  // The device's Logs says the group's setting is on, and links back; it cannot turn it off there.
  await page.getByRole("tab", { name: "Overview" }).click();
  await page.getByRole("link", { name: "dt-reception-01" }).click();
  await page.getByRole("tab", { name: "Logs", exact: true }).click();
  await expect(page.getByText(/set on the group\./)).toBeVisible();
  await expect(page.getByRole("button", { name: "Turn off" })).toHaveCount(0);
  await page.getByRole("link", { name: /Change it on the group Reception/ }).click();
  await expect(page).toHaveURL(settings);
  await page.getByRole("button", { name: "Turn off" }).click();
  await expect(page.getByText("Verbose logging is on", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Turn on" })).toBeVisible();
});

test("the group is renamed from its page and the tree follows", async () => {
  const page = admin;
  await page.getByRole("tab", { name: "Overview" }).click();
  await page.getByRole("button", { name: "Rename" }).click();
  const dialog = page.getByRole("dialog", { name: "Edit device group" });
  await dialog.getByLabel(/^Name/).fill("Front desk");
  await dialog.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByRole("heading", { name: "Front desk", level: 1 })).toBeVisible();
  // Put it back, so the suite's later stories find what they expect.
  await page.getByRole("button", { name: "Rename" }).click();
  await dialog.getByLabel(/^Name/).fill("Reception");
  await dialog.getByRole("button", { name: "Save changes" }).click();
  await expect(page.getByRole("heading", { name: "Reception", level: 1 })).toBeVisible();
});
