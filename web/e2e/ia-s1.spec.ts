// ADR-0072 slices S1 and S2, in the browser, against the server console.spec.ts leaves behind (it sorts first):
// Patching at every level of the tree, the old ?deviceId= link, and the labels on Add devices and the invitation
// dialog. The organization, site, group and device are the ones that story creates.

import { expect, test, type Page } from "@playwright/test";
import { nextCode } from "./authenticator";

const ADMIN = { email: "alex@example.com", password: "harbor lantern quietly 42" };
const TREE = "Patching: organizations, sites, groups and devices";

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

/** Opens a row's children when it is closed. */
async function open(row: ReturnType<Page["getByRole"]>) {
  if ((await row.getAttribute("aria-expanded")) === "false") {
    await row.focus();
    await admin.keyboard.press("ArrowRight");
  }
}

test("Patching narrows to the organization, the site and the group, and a device has its own page", async () => {
  const page = admin;
  await page.goto("/patching");
  const tree = page.getByRole("tree", { name: TREE });
  await expect(page.getByRole("heading", { name: "Patching", level: 1, exact: true })).toBeVisible();

  // Organization: the same page, narrowed.
  await tree.getByRole("treeitem", { name: /^Contoso Dental Group/ }).click();
  await expect(page).toHaveURL(/\/patching\?organizationId=[0-9a-f-]{36}$/);
  await expect(page.getByRole("heading", { name: "Patching · Contoso Dental Group", level: 1 })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Updates" })).toBeVisible();

  // Site, and the tab strip keeps it.
  await tree.getByRole("treeitem", { name: /^Downtown clinic/ }).click();
  await expect(page).toHaveURL(/\/patching\?organizationId=[0-9a-f-]{36}&siteId=[0-9a-f-]{36}$/);
  await expect(page.getByRole("heading", { name: "Patching · Downtown clinic", level: 1 })).toBeVisible();
  await page.getByRole("tab", { name: "Devices" }).click();
  await expect(page).toHaveURL(/siteId=[0-9a-f-]{36}&tab=devices|tab=devices.*siteId=[0-9a-f-]{36}/);
  await expect(page.getByRole("link", { name: "Up to Contoso Dental Group" })).toBeVisible();

  // Group: Devices narrows; the other tabs say they show the site.
  await open(tree.getByRole("treeitem", { name: /^Downtown clinic/ }));
  await tree.getByRole("treeitem", { name: /^Reception/ }).click();
  await expect(page).toHaveURL(/groupId=[0-9a-f-]{36}/);
  await expect(page.getByRole("heading", { name: "Patching · Reception", level: 1 })).toBeVisible();
  await page.getByRole("tab", { name: "Updates" }).click();
  await expect(page.getByText(/counts updates, jobs and alerts for a whole site, so this tab shows the site of the group you chose/)).toBeVisible();

  // Device: its own page, in the Patching section; the tree stays on Patching with the device highlighted.
  await open(tree.getByRole("treeitem", { name: /^Reception/ }));
  const row = tree.getByRole("treeitem", { name: /^dt-reception-01/ });
  await row.click();
  await expect(page).toHaveURL(/\/patching\/devices\/[0-9a-f-]{36}$/);
  await expect(page.getByRole("heading", { name: "Patching · dt-reception-01", level: 1 })).toBeVisible();
  await expect(page.getByRole("tree", { name: TREE })).toBeVisible();
  await expect(page.getByRole("treeitem", { name: /^dt-reception-01/ })).toHaveAttribute("aria-selected", "true");
  // Only that device: the fleet's tabs are not here.
  await expect(page.getByRole("tab", { name: "Updates" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Open the device page" })).toBeVisible();

  // The old link goes to the same page.
  const id = page.url().split("/").pop() ?? "";
  await page.goto(`/patching?deviceId=${id}`);
  await expect(page).toHaveURL(new RegExp(`/patching/devices/${id}$`));
  await expect(page.getByRole("heading", { name: "Patching · dt-reception-01", level: 1 })).toBeVisible();
});

test("Add devices names the show-again button, and the invitation dialog says a link will be shown", async () => {
  const page = admin;
  await page.goto("/devices/add");
  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Token name/).fill("Labels check");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByRole("button", { name: "Create another token" }).click();
  const row = page.getByRole("row", { name: /Labels check/ });
  const show = row.getByRole("button", { name: "Show install commands for Labels check" });
  await expect(show).toBeVisible();
  await expect(show).toHaveText("Show install commands");
  await expect(show).toBeEnabled();

  // This server has no mail server, so the invitation is a link.
  await page.goto("/settings?invite=1");
  const invite = page.getByRole("dialog", { name: "Invite user" });
  await expect(invite.getByRole("button", { name: "Create user" })).toBeVisible();
  await expect(invite.getByText(/No mail server is set up, so nothing is emailed. A sign-up link is shown next/)).toBeVisible();
  await expect(invite.getByRole("button", { name: "Send invitation" })).toHaveCount(0);
});
