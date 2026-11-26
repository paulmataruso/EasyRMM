// ADR-0081, slice 4: turning BitLocker on, in the browser. The console is the real one, signed in to the server
// console.spec.ts leaves behind, and the step-up the dialog asks for is checked by that server. No agent or keystore runs
// here, so the device, its escrow state and the action's run are answered by the test: what is checked is that the
// button stays off until the computer's name is typed (case aside), that the action is sent with the typed
// confirmation and the parameters, that the second factor is asked for and the request sent again, and that a refusal is
// shown in words.

import { expect, test, type Page, type Route } from "@playwright/test";
import { nextCode } from "./authenticator";

const ADMIN = {
  email: "alex@example.com",
  password: "harbor lantern quietly 42",
};
const DEVICE = "00000000-0000-4000-8000-0000000000e2";

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

const RUN_ID = "00000000-0000-4000-8000-0000000000f2";

/** The device page with one unencrypted volume, and the enable action answered by `result`. */
async function setUp(page: Page, result: unknown) {
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
    canRead: false,
    twoPerson: false,
    canEnable: true,
    keystore: {
      state: "unsealed",
      mode: "tpm",
      recoveryVerified: true,
      fileMode: false,
    },
    volumes: [
      {
        id: "vol-1",
        kind: "bitlocker",
        mount: "C:",
        status: "decrypted",
        state: "not_encrypted",
        protectors: [],
        reportedAt: now,
      },
    ],
  };
  const posts: { body: string }[] = [];
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
  await page.route(
    `**/api/v1/devices/${DEVICE}/winmod/bitlocker.enable`,
    (route) => {
      posts.push({ body: route.request().postData() ?? "" });
      // The first request has no second factor: the server asks for one, the console asks and sends it again.
      if (posts.length === 1)
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
      return json(route, {
        jobId: "j",
        runId: RUN_ID,
        action: "bitlocker.enable",
        status: "queued",
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      });
    },
  );
  await page.route(`**/api/v1/winmod/runs/${RUN_ID}`, (route) =>
    json(route, result),
  );
  await page.goto(`/devices/${DEVICE}?tab=hardware`);
  return posts;
}

async function typeNameAndGo(page: Page) {
  await page.getByRole("button", { name: "Turn on BitLocker for C:" }).click();
  const dialog = page.getByRole("dialog", { name: "Turn on BitLocker" });
  const go = dialog.getByRole("button", { name: "Turn on BitLocker" });
  const name = dialog.getByLabel(/Type the computer’s name to confirm/);
  // Nothing typed, a part of the name and another computer's name: it stays off.
  await expect(go).toBeDisabled();
  await name.fill("LAPTOP");
  await expect(go).toBeDisabled();
  await name.fill("LAPTOP-9");
  await expect(go).toBeDisabled();
  // The name, whatever its case.
  await name.fill("laptop-7");
  await expect(go).toBeEnabled();
  await go.click();
  const stepUp = page.getByRole("dialog", { name: "Confirm it is you" });
  await stepUp
    .getByLabel(/Code from your authenticator app/)
    .fill(await nextCode(page, ADMIN.email));
  await stepUp.getByRole("button", { name: "Confirm" }).click();
  return dialog;
}

test("turns BitLocker on only after the computer's name is typed and a step-up, and sends the typed confirmation", async () => {
  const page = admin;
  const posts = await setUp(page, {
    runId: RUN_ID,
    deviceId: DEVICE,
    action: "bitlocker.enable",
    version: 1,
    status: "succeeded",
    finishedAt: new Date().toISOString(),
    ok: true,
    data: {
      volume: "C:",
      escrow: "verified",
      encryption: "started",
      mode: "used_space",
    },
  });
  await typeNameAndGo(page);
  await expect(page.getByText("Encryption started")).toBeVisible();
  expect(posts).toHaveLength(2);
  for (const p of posts) {
    expect(JSON.parse(p.body)).toEqual({
      params: { computer: "laptop-7", volume: "C:", encryption: "used_space" },
      confirm: "bitlocker.enable:laptop-7",
    });
  }
});

test("says in words what the agent refused, and that nothing was changed", async () => {
  const page = admin;
  await setUp(page, {
    runId: RUN_ID,
    deviceId: DEVICE,
    action: "bitlocker.enable",
    version: 1,
    status: "succeeded",
    finishedAt: new Date().toISOString(),
    ok: false,
    failure: { code: "escrow_unverified", message: "x" },
  });
  const dialog = await typeNameAndGo(page);
  await expect(
    dialog.getByText(
      /could not be escrowed and verified, so encryption was not started/,
    ),
  ).toBeVisible();
  await expect(page.getByText("Encryption started")).toHaveCount(0);
});
