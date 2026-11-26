// ADR-0072 slice S4, in the browser, against the server console.spec.ts leaves behind: the organization's and the
// site's tab strips from the shared registry, in order, with ?tab= round-tripping, hidden tabs falling back to Overview,
// and the old tab URLs still working. The patching engine's stand-in may or may not be set up by now, so Patch policy
// is asserted wherever it shows.

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

test("the organization's strip lists its tabs in order and ?tab= round-trips", async () => {
  const page = admin;
  await page.goto("/organizations");
  await page
    .getByRole("link", { name: "Contoso Dental Group" })
    .first()
    .click();
  await expect(page).toHaveURL(/\/organizations\/[0-9a-f-]{36}$/);
  const orgUrl = page.url();
  const names = async () =>
    (await page.getByRole("tab").allInnerTexts()).map((n) => n.trim());
  await expect(page.getByRole("tab", { name: "Contacts" })).toBeVisible();
  const list = await names();
  expect(list.slice(0, 2)).toEqual(["Overview", "Contacts"]);
  expect(["Overview,Contacts", "Overview,Contacts,Patch policy"]).toContain(
    list.join(","),
  );
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute(
    "aria-selected",
    "true",
  );

  await page.getByRole("tab", { name: "Contacts" }).click();
  await expect(page).toHaveURL(/\?tab=contacts$/);
  await expect(page.getByRole("tab", { name: "Contacts" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await page.reload();
  await expect(page.getByRole("tab", { name: "Contacts" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await page.getByRole("tab", { name: "Overview" }).click();
  await expect(page).toHaveURL(orgUrl);

  if (list.includes("Patch policy")) {
    await page.goto(`${orgUrl}?tab=patch-policy`);
    await expect(
      page.getByRole("tab", { name: "Patch policy" }),
    ).toHaveAttribute("aria-selected", "true");
  }
  // An unknown tab falls back to Overview.
  await page.goto(`${orgUrl}?tab=nope`);
  await expect(page.getByRole("tab", { name: "Overview" })).toHaveAttribute(
    "aria-selected",
    "true",
  );
});

test("the site's strip has no Contacts tab; a hidden ?tab= falls back to Overview", async () => {
  const page = admin;
  await page.goto("/organizations");
  await page
    .getByRole("link", { name: "Contoso Dental Group" })
    .first()
    .click();
  await page.getByRole("link", { name: "Downtown clinic" }).first().click();
  await expect(page).toHaveURL(/\/sites\/[0-9a-f-]{36}$/);
  const siteUrl = page.url();
  await expect(
    page.getByRole("heading", { name: "Downtown clinic", level: 1 }),
  ).toBeVisible();
  await expect(page.getByRole("tab", { name: "Contacts" })).toHaveCount(0);
  const list = (await page.getByRole("tab").allInnerTexts()).map((n) =>
    n.trim(),
  );
  expect(["", "Overview,Patch policy"]).toContain(list.join(","));
  if (list.length > 0) {
    await page.getByRole("tab", { name: "Patch policy" }).click();
    await expect(page).toHaveURL(/\?tab=patch-policy$/);
    await page.reload();
    await expect(
      page.getByRole("tab", { name: "Patch policy" }),
    ).toHaveAttribute("aria-selected", "true");
  }
  await page.goto(`${siteUrl}?tab=contacts`);
  await expect(
    page.getByRole("heading", { name: "Downtown clinic", level: 1 }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Device groups" }),
  ).toBeVisible();
});
