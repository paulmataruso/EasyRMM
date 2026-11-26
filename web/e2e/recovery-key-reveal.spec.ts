// ADR-0081, slice 2: revealing a disk recovery key, in the browser. The console is the real one, signed in to the server
// console.spec.ts leaves behind, and the second factor the step-up dialog asks for is checked by that server. No agent
// or keystore runs here, so the device, its escrow state and the read are answered by the test: what is checked is
// what the console sends (a reason, a ticket, never a key), the step-up it asks for, and that the key is shown once
// and is gone from the page after Done and after leaving the page.

import { expect, test, type Page, type Route } from "@playwright/test";
import { nextCode } from "./authenticator";

const ADMIN = {
  email: "alex@example.com",
  password: "harbor lantern quietly 42",
};
const KEY = "123456-234567-345678-456789-567890-678901-789012-890123";
const DEVICE = "00000000-0000-4000-8000-0000000000e1";
const VOLUME = "vol-1";
const PROTECTOR = "{AAAAAAAA-0000-0000-0000-000000000001}";

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

test("reveals a key after a step-up and a reason, shows it once, and leaves none on the page", async () => {
  const page = admin;
  const now = new Date().toISOString();
  const device = {
    id: DEVICE,
    organizationId: "o1",
    organizationName: "Northwind Traders",
    siteId: "s1",
    siteName: "Head office",
    deviceGroupId: null,
    name: "LAPTOP-7",
    hostname: "laptop-7",
    osDescription: "Windows 11 Pro",
    platform: "windows",
    online: true,
    agent: {
      version: "1.4.0",
      arch: "amd64",
      sha256: "",
      online: true,
      lastSeenAt: now,
      enrolledAt: now,
      update: null,
      accepts: null,
      powerShell7: null,
    },
    remoteAgent: true,
    remoteOnline: true,
    lastSeenAt: now,
    createdAt: now,
    updatedAt: now,
    canDesktop: true,
    canTerminal: true,
    canFiles: true,
    canRunScripts: false,
    canUpdateAgent: false,
    canReconnectRemote: false,
    canRepairPatching: false,
    canRepairEasyRmm: false,
    remote: null,
    canManageSoftware: false,
    canCheckHardening: false,
    canHarden: false,
    canRemove: false,
    removal: null,
    hardening: null,
    diskHealth: null,
  };
  const inventory = {
    inventory: {
      system: {
        manufacturer: "Dell Inc.",
        model: "Latitude",
        serial: "7XK2LM3",
        biosVendor: "Dell Inc.",
        biosVersion: "1.13.2",
        biosDate: "2024-03-14",
        virtualization: "",
      },
      cpu: { model: "Intel Core", sockets: 1, cores: 4, threads: 8 },
      memoryBytes: 16 * 1024 ** 3,
      os: {
        name: "Windows 11 Pro",
        id: "windows",
        version: "24H2",
        kernel: "10.0.26100",
        timezone: "UTC",
      },
      disks: [],
      interfaces: [],
      gateways: [],
      dnsServers: [],
      packageManager: "",
      packageCount: 0,
      receivedAt: now,
    },
    metrics: {
      at: now,
      cpuPercent: 5,
      memoryTotal: 16 * 1024 ** 3,
      memoryUsed: 4 * 1024 ** 3,
      swapTotal: 0,
      swapUsed: 0,
      load1: 0,
      load5: 0,
      load15: 0,
      uptimeSeconds: 3600,
      processes: 100,
      filesystems: [],
    },
  };
  const escrow = {
    applicable: true,
    canRead: true,
    twoPerson: false,
    keystore: {
      state: "unsealed",
      mode: "tpm",
      recoveryVerified: true,
      fileMode: false,
    },
    volumes: [
      {
        id: VOLUME,
        mount: "C:",
        status: "encrypted",
        state: "verified",
        protectors: [{ id: PROTECTOR, state: "verified", verifiedAt: now }],
        reportedAt: now,
      },
    ],
  };
  const reads: string[] = [];
  const answers: string[] = [];
  await page.route(`**/api/v1/devices/${DEVICE}`, (route) =>
    json(route, device),
  );
  await page.route(`**/api/v1/devices/${DEVICE}/inventory`, (route) =>
    json(route, inventory),
  );
  await page.route(`**/api/v1/devices/${DEVICE}/disks`, (route) =>
    json(route, { items: [] }),
  );
  await page.route(`**/api/v1/devices/${DEVICE}/escrow`, (route) =>
    json(route, escrow),
  );
  await page.route(`**/api/v1/devices/${DEVICE}/escrow/read`, async (route) => {
    reads.push(route.request().postData() ?? "");
    // The first read arrives without a second factor: the server asks for one and the console asks and sends it again.
    if (reads.length === 1)
      return json(
        route,
        {
          error: {
            code: "step_up_required",
            message:
              "Confirm it is you with your authenticator app or security key to continue.",
          },
        },
        401,
      );
    const body = { key: KEY };
    answers.push(JSON.stringify(body));
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: { "Cache-Control": "no-store" },
      body: JSON.stringify(body),
    });
  });

  await page.goto(`/devices/${DEVICE}?tab=hardware`);
  await page
    .getByRole("button", { name: "Reveal the recovery key of C:" })
    .click();
  const dialog = page.getByRole("dialog", { name: "Reveal the recovery key" });
  // No reason, no reading.
  await expect(
    dialog.getByRole("button", { name: "Reveal", exact: true }),
  ).toBeDisabled();
  await dialog
    .getByLabel(/Why do you need the key/)
    .fill("Laptop will not boot, owner on site");
  await dialog.getByLabel(/Ticket reference/).fill("T-7");
  await dialog.getByRole("button", { name: "Reveal", exact: true }).click();

  const stepUp = page.getByRole("dialog", { name: "Confirm it is you" });
  await stepUp
    .getByLabel(/Code from your authenticator app/)
    .fill(await nextCode(page, ADMIN.email));
  await stepUp.getByRole("button", { name: "Confirm" }).click();

  await expect(page.getByRole("status", { name: "Recovery key" })).toHaveText(
    KEY,
  );
  expect(reads).toHaveLength(2);
  for (const body of reads) {
    expect(JSON.parse(body)).toEqual({
      volume: VOLUME,
      protector: PROTECTOR,
      reason: "Laptop will not boot, owner on site",
      ticket: "T-7",
    });
    expect(body).not.toContain("123456");
  }
  // Nothing to copy with, and the key is in no storage and not in the address.
  await expect(page.getByRole("button", { name: /copy/i })).toHaveCount(0);
  const stored = await page.evaluate(
    () =>
      JSON.stringify({ ...localStorage }) +
      JSON.stringify({ ...sessionStorage }),
  );
  expect(stored).not.toContain("123456");
  expect(page.url()).not.toContain("123456");

  // Done clears it from the page.
  await page.getByRole("dialog").getByRole("button", { name: "Done" }).click();
  await expect(page.locator("body")).not.toContainText(KEY);

  // Reveal again, then leave the page: it is not there when the person comes back.
  await page
    .getByRole("button", { name: "Reveal the recovery key of C:" })
    .click();
  await page
    .getByRole("dialog")
    .getByLabel(/Why do you need the key/)
    .fill("Second look at the same key, owner asked");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Reveal", exact: true })
    .click();
  await expect(page.getByRole("status", { name: "Recovery key" })).toHaveText(
    KEY,
  );
  await page.goto("/");
  await page.goBack();
  await expect(page.locator("body")).not.toContainText(KEY);
});
