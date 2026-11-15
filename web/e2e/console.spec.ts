// The technician console, end to end, against a real server and database: first-run setup,
// mandatory two-factor enrollment, tenancy, invitations, scoped access and the audit trail.
// The suite is one ordered story because each step builds on the server state of the last.

import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";
import { totp } from "./totp";

const ADMIN = { name: "Alex Rivera", email: "alex@example.com", password: "harbor lantern quietly 42" };
const TECH = { name: "Riley Chen", email: "riley@example.com", password: "copper meadow steadily 77" };

/** Authenticator state per person: the secret and the last time step the server accepted. */
const authenticators = new Map<string, { secret: string; step: number }>();

const currentStep = () => Math.floor(Date.now() / 30_000);

/** A code the server will accept: never a step it has already seen (replay protection). */
async function nextCode(page: Page, email: string): Promise<string> {
  const a = authenticators.get(email);
  if (!a) throw new Error(`no authenticator for ${email}`);
  let step = Math.max(currentStep(), a.step + 1);
  // The server accepts at most one step ahead of now; wait for the clock otherwise.
  while (step > currentStep() + 1) {
    await page.waitForTimeout(1_000);
    step = Math.max(currentStep(), a.step + 1);
  }
  a.step = step;
  return totp(a.secret, step - currentStep());
}

/** Scans the "QR code" by reading the secret key printed under it, and confirms a code. */
async function enrollAuthenticator(page: Page, email: string) {
  const secret = (await page.getByText("Secret key", { exact: true }).locator("xpath=following-sibling::p[1]").innerText()).replace(/\s+/g, "");
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  await expect(page.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  authenticators.set(email, { secret, step: currentStep() - 1 });
  await page.getByLabel(/^Verification code/).fill(await nextCode(page, email));
  await page.getByRole("button", { name: "Turn on two-factor authentication" }).click();

  // Recovery codes are shown once; leaving needs an explicit acknowledgement.
  await expect(page.getByText("I have saved these recovery codes")).toBeVisible();
  const codes = await page.locator("ul li.select-all").allInnerTexts();
  expect(codes).toHaveLength(10);
  const done = page.getByRole("button", { name: "Continue" });
  await expect(done).toBeDisabled();
  await page.getByLabel("I have saved these recovery codes").check();
  await done.click();
}

async function signIn(page: Page, who: { email: string; password: string }) {
  await page.getByLabel(/^Email/).fill(who.email);
  await page.getByLabel(/^Password/).fill(who.password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test.describe.configure({ mode: "serial" });

let inviteLink = "";
let northwindId = "";

// The administrator keeps one browser session across the story, as a technician would.
let admin: Page;
test.beforeAll(async ({ browser }) => {
  admin = await (await browser.newContext()).newPage();
});
test.afterAll(async () => {
  await admin.context().close();
});

test("first-run setup creates the administrator, who must enroll an authenticator", async () => {
  const page = admin;
  await page.goto("/organizations");
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { name: "Set up EasyRMM" })).toBeVisible();

  const token = readFileSync(new URL("./.run/data/setup-token", import.meta.url), "utf8").trim();
  await page.getByLabel(/^Setup token/).fill("not-the-token");
  await page.getByLabel(/^First organization/).fill("Northwind Traders");
  await page.getByLabel(/^Your name/).fill(ADMIN.name);
  await page.getByLabel(/^Email/).fill(ADMIN.email);
  await page.getByLabel(/^Password/).fill(ADMIN.password);
  await page.getByLabel(/^Confirm password/).fill(ADMIN.password);
  await page.getByRole("button", { name: "Create administrator" }).click();
  await expect(page.getByText(/setup token is not correct/i)).toBeVisible();

  await page.getByLabel(/^Setup token/).fill(token);
  await page.getByRole("button", { name: "Create administrator" }).click();

  // Sign-in greets the new administrator with the address already filled in.
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByText("Setup is complete. Sign in with the account you just created.")).toBeVisible();
  await expect(page.getByLabel(/^Email/)).toHaveValue(ADMIN.email);
  await expect(page.getByLabel(/^Password/)).toBeFocused();
  await page.getByLabel(/^Password/).fill(ADMIN.password);
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page).toHaveURL(/\/login\/mfa-setup$/);
  await enrollAuthenticator(page, ADMIN.email);
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  const account = page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: /Alex Rivera/ });
  await expect(account).toContainText("Super administrator");
});

test("builds the customer tree: organization, site and device group", async () => {
  const page = admin;
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Organizations" }).click();
  await expect(page.getByRole("link", { name: "Northwind Traders" })).toBeVisible();

  await page.getByRole("button", { name: "New organization" }).click();
  const create = page.getByRole("dialog", { name: "New organization" });
  await create.getByLabel(/^Name/).fill("Northwind Traders");
  await create.getByRole("button", { name: "Create organization" }).click();
  await expect(create.getByText(/already/i)).toBeVisible();
  await create.getByLabel(/^Name/).fill("Contoso Dental Group");
  await create.getByLabel(/^Notes/).fill("Three clinics. Imaging PCs are vendor-managed.");
  await create.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByRole("heading", { name: "Contoso Dental Group" })).toBeVisible();

  await page.getByRole("button", { name: "Add site" }).click();
  const site = page.getByRole("dialog", { name: "New site" });
  await site.getByLabel(/^Name/).fill("Downtown clinic");
  await site.getByLabel(/^Time zone/).fill("America/New_York");
  await site.getByRole("button", { name: /Create site|Add site/ }).click();
  await expect(page.getByRole("heading", { name: "Downtown clinic" })).toBeVisible();

  await page.getByRole("button", { name: "Add device group" }).click();
  const groupDialog = page.getByRole("dialog", { name: "New device group" });
  await groupDialog.getByLabel(/^Name/).fill("Reception");
  await groupDialog.getByRole("button", { name: "Create device group" }).click();
  await expect(page.getByRole("cell", { name: "Reception", exact: true })).toBeVisible();

  // The breadcrumb leads back up the tree, where the counts reflect the new records.
  await page.getByRole("navigation", { name: "Breadcrumb" }).getByRole("link", { name: "Contoso Dental Group" }).click();
  await expect(page.getByRole("row", { name: /Downtown clinic/ })).toContainText("1");

  await page.goto("/organizations");
  await page.getByRole("link", { name: "Northwind Traders" }).click();
  northwindId = page.url().split("/").pop() ?? "";
  expect(northwindId).toMatch(/^[0-9a-f-]{36}$/);
});

test("invites a technician to one organization; the link is shown once", async () => {
  const page = admin;
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Settings" }).click();
  await expect(page).toHaveURL(/\/settings$/);

  await page.getByRole("button", { name: "Invite user" }).click();
  const invite = page.getByRole("dialog", { name: "Invite user" });
  await invite.getByLabel(/^Email/).fill(TECH.email);
  await invite.getByLabel(/^Name/).fill(TECH.name);
  await invite.getByLabel("Role").selectOption({ label: "Technician" });
  await invite.getByLabel("Organization").selectOption({ label: "Contoso Dental Group" });
  await invite.getByRole("button", { name: "Send invitation" }).click();

  // This server has no SMTP, so the console hands over the link instead of emailing it.
  const notice = page.getByRole("dialog", { name: "Send this invitation link" });
  await expect(notice.getByText("Copy this link now. It is shown only once.")).toBeVisible();
  inviteLink = (await notice.locator("pre").innerText()).trim();
  expect(inviteLink).toMatch(/^https:\/\/rmm\.localhost\/welcome#token=[\w-]+$/);
  await page.keyboard.press("Escape");
  await expect(notice).toBeVisible();
  await notice.getByRole("button", { name: "Done" }).click();

  await expect(page.getByRole("row", { name: new RegExp(TECH.name) })).toContainText("Invited");
});

test("the technician accepts, enrolls, and sees only their organization", async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();
  const fragment = new URL(inviteLink).hash;
  await page.goto(`/welcome${fragment}`);
  await expect(page.getByRole("heading", { name: "Welcome to EasyRMM" })).toBeVisible();
  // The token leaves the address bar as soon as it is read.
  await expect(page).toHaveURL(/\/welcome$/);

  await page.getByLabel(/^New password/).fill(TECH.password);
  await page.getByLabel(/^Confirm new password/).fill(TECH.password);
  await page.getByRole("button", { name: "Set password" }).click();
  await expect(page.getByText("Your password is set. Sign in with it now.")).toBeVisible();

  await signIn(page, TECH);
  await expect(page).toHaveURL(/\/login\/mfa-setup$/);
  await enrollAuthenticator(page, TECH.email);
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  await page.goto("/organizations");
  await expect(page.getByRole("link", { name: "Contoso Dental Group" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Northwind Traders" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "New organization" })).toHaveCount(0);
  // A technician's account line shows who they are; only the platform-wide role is named.
  await expect(page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: /Riley Chen/ })).toContainText(TECH.email);

  // Another customer's records do not exist as far as this technician can tell.
  await page.goto(`/organizations/${northwindId}`);
  await expect(page.getByText("Not found")).toBeVisible();

  // The invitation link worked once; it cannot be used again.
  await page.goto(`/welcome${fragment}`);
  await page.getByLabel(/^New password/).fill("another long passphrase");
  await page.getByLabel(/^Confirm new password/).fill("another long passphrase");
  await page.getByRole("button", { name: "Set password" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await context.close();
});

test("devices and remote access report honestly when MeshCentral is not running", async () => {
  // start-server.sh enables remote access but runs no MeshCentral.
  const page = admin;
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Devices" }).click();
  await expect(page.getByRole("heading", { name: "Devices" })).toBeVisible();
  await expect(page.getByText("No devices yet")).toBeVisible();
  await expect(page.getByText("Remote access is unavailable")).toBeVisible();

  await page.getByRole("link", { name: "View details" }).click();
  await expect(page).toHaveURL(/\/settings\?tab=remote$/);
  await expect(page.getByText("EasyRMM cannot reach MeshCentral")).toBeVisible();
  await expect(page.getByText("https://mesh.rmm.localhost")).toBeVisible();

  // A session link for a device that does not exist goes nowhere, and says so.
  await page.goto("/devices/00000000-0000-4000-8000-000000000000/remote/desktop");
  await expect(page.getByText("Device not found")).toBeVisible();
  await page.getByRole("link", { name: "Back to the device" }).click();
  await expect(page.getByText("Not found")).toBeVisible();
});

test("a deep link survives sign-in and the second factor", async () => {
  const page = admin;
  await page.getByRole("navigation", { name: "Main" }).getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login/);
  // Signing out ended the session on the server, not just in this tab.
  expect(await page.evaluate(async () => (await fetch("/api/v1/auth/session")).status)).toBe(401);

  await page.goto("/settings?tab=audit");
  await expect(page).toHaveURL(/\/login\?returnTo=/);
  await signIn(page, ADMIN);
  await page.getByLabel(/^Verification code/).fill(await nextCode(page, ADMIN.email));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page).toHaveURL(/\/settings\?tab=audit$/);
});

test("the audit log records everything and its hash chain verifies", async () => {
  const page = admin;
  for (const label of ["Created organization", "Created site", "Created device group", "Invited user"]) {
    await expect(page.getByRole("cell", { name: new RegExp(label) }).first()).toBeVisible();
  }
  await page.getByLabel("Area").selectOption({ label: "Users" });
  await expect(page.getByRole("cell", { name: /Created organization/ })).toHaveCount(0);

  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(page.getByText(/^Intact: \d+ entries checked, none altered or removed\.$/)).toBeVisible();
});
