// ADR-0053, slice 4: device alert rules in the browser, against the real server and database. An organization's
// administrator adds an email channel, makes a rule that sends the organization's offline alerts to it after a wait,
// adds a maintenance window to a site, and turns the rule off and deletes it. Whether the alerts then arrive is
// verified against the database and Mailpit by the server's integration tests.

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

test("a rule is created with its filters, timing and channel, turned off and deleted", async () => {
  const page = admin;
  await page.goto("/organizations");
  await page.getByRole("link", { name: "Northwind Traders" }).first().click();
  await page.getByRole("tab", { name: "Notifications" }).click();

  await page.getByRole("button", { name: /Add channel/ }).click();
  let dialog = page.getByRole("dialog");
  await dialog.getByLabel(/^Name/).fill("Rules desk");
  await dialog.getByLabel(/^Recipients/).fill("rules@example.com");
  await dialog.getByRole("button", { name: "Add channel" }).click();
  await expect(page.getByRole("cell", { name: /Rules desk/ })).toBeVisible();

  await page.getByRole("button", { name: "Add rule" }).click();
  dialog = page.getByRole("dialog");
  await dialog.getByLabel(/^Name/).fill("E2E offline servers");
  await dialog.getByRole("radiogroup", { name: "Kind of device: any or a list" }).getByRole("radio", { name: "List" }).click();
  await dialog.getByRole("checkbox", { name: "Servers" }).check();
  await dialog.getByRole("radiogroup", { name: "Condition: any or a list" }).getByRole("radio", { name: "List" }).click();
  await dialog.getByRole("checkbox", { name: "Offline" }).check();
  await dialog.getByLabel(/Wait before telling/).fill("10");
  await dialog.getByLabel(/Remind every/).fill("4");
  await dialog.getByRole("checkbox", { name: /Rules desk/ }).check();
  await dialog.getByRole("button", { name: "Add rule" }).click();

  const row = page.getByRole("row", { name: /E2E offline servers/ });
  await expect(row).toBeVisible();
  await expect(row).toContainText("kinds: server; conditions: offline");
  await expect(row).toContainText("After 10 min, reminders every 4 h");

  // A name used twice is refused in EasyRMM's words.
  await page.getByRole("button", { name: "Add rule" }).click();
  dialog = page.getByRole("dialog");
  await dialog.getByLabel(/^Name/).fill("e2e offline servers");
  await dialog.getByRole("checkbox", { name: /Rules desk/ }).check();
  await dialog.getByRole("button", { name: "Add rule" }).click();
  await expect(dialog.getByText("Another rule of this owner has that name.").first()).toBeVisible();
  await dialog.getByRole("button", { name: "Cancel" }).click();

  await row.getByRole("button", { name: "Turn off" }).click();
  await expect(row.getByText("Off", { exact: true })).toBeVisible();
  await row.getByRole("button", { name: "Delete" }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete rule" }).click();
  await expect(page.getByRole("row", { name: /E2E offline servers/ })).toHaveCount(0);
});

test("a maintenance window is added to a site", async () => {
  const page = admin;
  await page.goto("/organizations");
  await page.getByRole("link", { name: "Northwind Traders" }).first().click();
  await page.getByRole("tab", { name: "Notifications" }).click();
  const add = page.getByRole("button", { name: "Add window" });
  // The organization may have no site in this suite's data; the window needs one.
  if ((await add.count()) === 0) test.skip();
  await add.click();
  const dialog = page.getByRole("dialog");
  if ((await dialog.getByLabel("Site").locator("option").count()) === 0) {
    await dialog.getByRole("button", { name: "Cancel" }).click();
    test.skip();
  }
  await dialog.getByLabel(/^Name/).fill("E2E nightly");
  await dialog.getByRole("checkbox", { name: "Mon" }).check();
  await dialog.getByRole("button", { name: "Add window" }).click();
  await expect(page.getByRole("cell", { name: /E2E nightly/ })).toBeVisible();
  await expect(page.getByText(/Sat, Mon at 22:00 for 4 h/)).toBeVisible();
});
