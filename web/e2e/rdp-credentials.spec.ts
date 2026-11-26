// ADR-0079: a saved RDP credential in the remote desktop, in the browser. The console is the real one, signed in to
// the server console.spec.ts leaves behind, and the second factor the dialog asks for is checked by that server. No
// MeshCentral runs here, so the device, the credential store and the session launch are answered by the test: what is
// checked is what the console sends and shows (a credential's id, never a password) and the step-up it asks for.

import { expect, test, type Page, type Route } from "@playwright/test";
import { nextCode } from "./authenticator";

const ADMIN = {
  email: "alex@example.com",
  password: "harbor lantern quietly 42",
};
const PASSWORD = "Rdp-e2e-only 4417";
const DEVICE = "00000000-0000-4000-8000-0000000000d1";
const CREDENTIAL = crypto.randomUUID();

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

test("saves a credential after a step-up, then opens the session with its id and never a password", async () => {
  const page = admin;
  const now = new Date().toISOString();
  const device = {
    id: DEVICE, organizationId: "o1", organizationName: "Northwind Traders", siteId: "s1", siteName: "Head office", deviceGroupId: null,
    name: "FRONT-DESK", hostname: "front-desk", osDescription: "Windows 11 Pro", platform: "windows", online: true, agent: null, remoteAgent: true,
    remoteOnline: true, lastSeenAt: now, createdAt: now, updatedAt: now, canDesktop: true, canTerminal: true, canFiles: true, canRunScripts: false,
    canUpdateAgent: false, canReconnectRemote: false, canRepairPatching: false, canRepairEasyRmm: false, remote: null, canManageSoftware: false,
    canCheckHardening: false, canHarden: false, canRemove: false, removal: null, hardening: null, diskHealth: null,
  };
  let saved: unknown[] = [];
  let puts = 0;
  const putBodies: string[] = [];
  const launches: string[] = [];
  const answers: string[] = [];

  await page.route(`**/api/v1/devices/${DEVICE}`, (route) => json(route, device));
  await page.route(`**/api/v1/devices/${DEVICE}/rdp-credentials`, async (route) => {
    const request = route.request();
    if (request.method() === "GET") {
      const body = { credentials: saved };
      answers.push(JSON.stringify(body));
      return json(route, body);
    }
    putBodies.push(request.postData() ?? "");
    // The first save arrives without a second factor: the server asks for one, as it does for a session that has
    // not stepped up, and the console asks and sends the save again.
    if (puts++ === 0) return json(route, { error: { code: "step_up_required", message: "Confirm it is you with your authenticator app or security key to continue." } }, 401);
    saved = [{ id: CREDENTIAL, deviceId: DEVICE, scope: "user", label: "Server admin", domain: "CORP", username: "svc-admin", createdAt: now, lastUsedAt: null }];
    return json(route, saved[0]);
  });
  await page.route(`**/api/v1/devices/${DEVICE}/remote-sessions`, async (route) => {
    launches.push(route.request().postData() ?? "");
    return json(route, { grantId: "g1", url: "https://mesh.example.test/.easyrmm/launch?t=tok", expiresAt: "2030-01-01T00:00:00Z", kind: "rdp", deviceId: DEVICE }, 201);
  });
  await page.route("https://mesh.example.test/**", (route) => route.fulfill({ contentType: "text/html", body: "<!doctype html><title>session</title><p>session</p>" }));

  // Nothing saved yet: the session opens as it always did, and the page offers to save one.
  await page.goto(`/devices/${DEVICE}/remote/rdp`);
  await expect(page.locator("iframe")).toHaveAttribute("src", "https://mesh.example.test/.easyrmm/launch?t=tok");
  expect(launches).toEqual([JSON.stringify({ kind: "rdp" })]);
  await page.getByRole("button", { name: "Saved credential" }).click();
  const dialog = page.getByRole("dialog", { name: "Saved RDP credential" });
  await dialog.getByLabel("Domain").fill("CORP");
  await dialog.getByLabel(/User name/).fill("svc-admin");
  await dialog.getByLabel(/^Password/).fill(PASSWORD);
  await dialog.getByRole("button", { name: "Save and connect" }).click();

  // The step-up dialog asks; the second factor is checked by the real server; the save is sent again by itself.
  const stepUp = page.getByRole("dialog", { name: "Confirm it is you" });
  await stepUp.getByLabel(/Code from your authenticator app/).fill(await nextCode(page, ADMIN.email));
  await stepUp.getByRole("button", { name: "Confirm" }).click();
  await expect(page.locator("iframe")).toHaveAttribute("src", new RegExp(`rdpcred=${CREDENTIAL}`));
  expect(puts).toBe(2);
  expect(launches.at(-1)).toBe(JSON.stringify({ kind: "rdp", savedCredential: true }));

  // The password went to the server in the save and nowhere else: not into the session's address or launch request,
  // and not onto the page.
  expect(putBodies.every((b) => b.includes(PASSWORD))).toBe(true);
  expect([...launches, ...answers].some((s) => s.includes(PASSWORD))).toBe(false);
  expect(await page.locator("iframe").getAttribute("src")).not.toContain(PASSWORD);
  await expect(page.locator("body")).not.toContainText(PASSWORD);

  // Next time the page offers the saved credential, by label and account, and connects with the id again.
  await page.goto(`/devices/${DEVICE}/remote/rdp`);
  const chooser = page.getByRole("form", { name: "How to sign in" });
  await expect(chooser.getByText("CORP\\svc-admin")).toBeVisible();
  await expect(chooser).not.toContainText(PASSWORD);
  await chooser.getByRole("button", { name: "Connect" }).click();
  await expect(page.locator("iframe")).toHaveAttribute("src", new RegExp(`rdpcred=${CREDENTIAL}`));
  expect(launches.at(-1)).toBe(JSON.stringify({ kind: "rdp", savedCredential: true }));
});
