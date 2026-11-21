// The technician console, end to end, against a real server and database: first-run setup,
// mandatory two-factor enrollment, tenancy, invitations, scoped access, device enrollment, a
// hardening check through the device's agent, and the audit trail.
// The suite is one ordered story because each step builds on the server state of the last.

import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";
import { Agent, deviceKey } from "./agent";
import { enrollAuthenticator, nextCode } from "./authenticator";

const ADMIN = { name: "Alex Rivera", email: "alex@example.com", password: "harbor lantern quietly 42" };
const TECH = { name: "Riley Chen", email: "riley@example.com", password: "copper meadow steadily 77" };

async function signIn(page: Page, who: { email: string; password: string }) {
  await page.getByLabel(/^Email/).fill(who.email);
  await page.getByLabel(/^Password/).fill(who.password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

test.describe.configure({ mode: "serial" });

let inviteLink = "";
let northwindId = "";
// The device the suite enrolls, as its agent.
let agent: Agent;

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

test("a page whose file is gone after an upgrade reloads the console once, then says so", async () => {
  const page = admin;
  // As after an upgrade: the server no longer has the file this console was built with.
  const alertsPage = /\/assets\/AlertsPage-[^/]+\.js$/;
  await page.route(alertsPage, (route) => route.fulfill({ status: 404, body: "" }));
  let loads = 0;
  const counted = () => loads++;
  page.on("load", counted);

  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Alerts" }).click();
  // The first failure loads the console again; a second one within a minute is shown instead.
  await expect(page.getByText("This page could not be loaded")).toBeVisible();
  expect(loads).toBe(1);
  page.off("load", counted);

  await page.unroute(alertsPage);
  await page.getByRole("button", { name: "Reload" }).click();
  await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible();

  // The next step starts from the main menu.
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
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
  // Inside a section the sidebar shows the section's tree; Back returns to the main menu.
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("tree", { name: "Organizations: organizations, sites" })).toBeVisible();
  await expect(nav.getByRole("treeitem", { name: /^Contoso Dental Group/ })).toBeVisible();
  await nav.getByRole("button", { name: "Back to the main menu" }).click();
  await nav.getByRole("link", { name: "Settings" }).click();
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
  const nav = page.getByRole("navigation", { name: "Main" });
  await nav.getByRole("button", { name: "Back to the main menu" }).click();
  await nav.getByRole("link", { name: "Devices" }).click();
  await expect(page.getByRole("heading", { name: "Devices", level: 1 })).toBeVisible();
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

test("a deployment token enrolls a device, which then reports in", async () => {
  const page = admin;
  await page.goto("/devices");
  await page.getByRole("link", { name: "Add devices" }).first().click();
  await expect(page.getByRole("heading", { name: "Add devices" })).toBeVisible();
  // The agents this server hands out (make build-agents), with the checksums the installers verify.
  await expect(page.getByText("Windows x86-64")).toBeVisible();
  await expect(page.getByText("Linux x86-64")).toBeVisible();
  const sums = await (await page.request.get("/api/agent/v1/download/SHA256SUMS")).text();
  expect(sums).toMatch(/^[0-9a-f]{64} {2}easyrmm-agent-linux-amd64$/m);
  expect(sums).toMatch(/^[0-9a-f]{64} {2}easyrmm-agent-windows-amd64\.exe$/m);
  const ps1 = await page.request.get("/api/agent/v1/install.ps1");
  expect(await ps1.text()).toContain("$Server = 'https://rmm.localhost'");

  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Device group/).selectOption({ label: "Reception" });
  await page.getByLabel(/^Token name/).fill("Downtown rollout");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  // Windows first: the PowerShell command.
  const windows = await page.locator("pre", { hasText: "install.ps1" }).innerText();
  expect(windows).toContain("DownloadString('https://rmm.localhost/api/agent/v1/install.ps1'))) -Token 'ert_");
  await page.getByRole("radio", { name: "Linux" }).click();
  const command = await page.locator("pre", { hasText: "install.sh" }).innerText();
  // The token travels in the environment, not on a command line other users can read.
  expect(command).toContain("curl -fsSL https://rmm.localhost/api/agent/v1/install.sh | sudo --preserve-env=EASYRMM_TOKEN sh; unset EASYRMM_TOKEN");
  const token = /EASYRMM_TOKEN='(ert_[A-Za-z0-9_-]+)'/.exec(command)?.[1] ?? "";
  expect(token).toHaveLength(47);

  // A device enrolls the way the agent does: its own key, its facts, the token.
  const facts = { hostname: "dt-reception-01", os: "Debian GNU/Linux 13 (trixie)", platform: "linux", arch: "amd64", agentVersion: "0.6.0-e2e" };
  const key = deviceKey();
  const enroll = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: key.publicKey, facts } });
  expect(enroll.status(), await enroll.text()).toBe(201);
  agent = new Agent(page.request, ((await enroll.json()) as { deviceId: string }).deviceId, key.privateKey);
  // The token allowed one device.
  const again = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: deviceKey().publicKey, facts: { ...facts, hostname: "dt-reception-02" } } });
  expect(again.status()).toBe(401);

  await page.getByRole("button", { name: "Create another token" }).click();
  await page.getByLabel("Which deployment tokens").selectOption("all");
  const row = page.getByRole("row", { name: /Downtown rollout/ });
  await expect(row).toContainText("1 of 1");
  await expect(row).toContainText("Used up");

  // The devices tree lists the new device under its site once it loads the
  // list again (it refreshes every 30 seconds); "All devices" goes back to the list.
  await page.reload();
  const nav = page.getByRole("navigation", { name: "Main" });
  await expect(nav.getByRole("treeitem", { name: "dt-reception-01, online" })).toBeVisible();
  await nav.getByRole("button", { name: /^All devices/ }).click();
  const device = page.getByRole("row", { name: /dt-reception-01/ });
  await expect(device).toContainText("Online");
  await expect(device).toContainText("Debian GNU/Linux 13 (trixie)");
  await device.getByRole("link", { name: "dt-reception-01" }).click();
  await expect(page.getByRole("heading", { name: "dt-reception-01" })).toBeVisible();
  await expect(page.getByText("0.6.0-e2e")).toBeVisible();
  await expect(page.getByText("Reception", { exact: true })).toBeVisible();
  // MeshCentral is not running here, so remote access has not been set up on the device.
  await expect(page.getByText("Not set up yet")).toBeVisible();
});

/** The result line EasyRMM's hardening script ends with, as the script writes it on a Debian 13 server. */
function hardeningResult(): string {
  const modules = [
    { module: "ssh", state: "partly", reason: "Some of the settings this module checks are in place.", missing: ["PermitRootLogin prohibit-password (now yes)"], changes: ["PermitRootLogin prohibit-password"] },
    {
      module: "firewall",
      state: "not_in_place",
      reason: "None of the settings this module checks is in place.",
      missing: ["nftables table inet easyrmm loaded"],
      changes: ["Install nftables"],
      ports: { tcp: ["22", "443"], docker: ["tcp/8080"] },
    },
    { module: "fail2ban", state: "not_in_place", missing: ["fail2ban installed and running"] },
    { module: "kernel", state: "in_place", reason: "Everything this module checks is in place." },
    { module: "audit", state: "not_in_place", missing: ["auditd installed and running"] },
    { module: "permissions", state: "in_place" },
    { module: "services", state: "in_place" },
    { module: "kernel-modules", state: "partly", missing: ["sctp kept from loading"] },
    { module: "sudo", state: "in_place" },
    { module: "time", state: "in_place" },
    { module: "shared-memory", state: "not_in_place" },
    { module: "usb-storage", state: "not_in_place" },
    { module: "mac", state: "not_applicable", reason: "Neither SELinux nor AppArmor is installed." },
    { module: "integrity", state: "not_in_place" },
  ];
  const platform = { id: "debian", versionId: "13", family: "debian", container: "none", support: "full" };
  return `EASYRMM-HARDENING-RESULT-V1 ${JSON.stringify({ version: 1, mode: "check", platform, modules })}\n`;
}

test("a hardening check runs through the device's agent; its findings show on the device and across the fleet", async () => {
  const page = admin;
  // The device page from the step before.
  await page.getByRole("tab", { name: "Hardening" }).click();
  await expect(page.getByText("Not checked yet")).toBeVisible();
  await page.getByRole("button", { name: "Run check…" }).click();
  const dialog = page.getByRole("dialog", { name: "Check hardening" });
  // The recommended modules are chosen; the optional ones, chosen one by one here, carry their risk.
  await expect(dialog.getByText("10 of 14 modules")).toBeVisible();
  await expect(dialog.getByText("When applied: USB disks and backup drives stop working.")).toBeVisible();
  for (const name of ["Shared memory", "USB storage", "SELinux or AppArmor", "File integrity"]) {
    await dialog.getByRole("checkbox", { name: new RegExp(`^${name}`) }).check();
  }
  await expect(dialog.getByText("14 of 14 modules")).toBeVisible();
  await dialog.getByRole("button", { name: "Run check" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByText("Checking hardening", { exact: true })).toBeVisible();

  // The device's agent picks the check up: EasyRMM's own script, with every module the console sent as an argument.
  const [job] = await agent.poll();
  expect(job?.shell).toBe("sh");
  expect(job?.args).toEqual(["check", "ssh,firewall,fail2ban,kernel,audit,permissions,services,kernel-modules,sudo,time,shared-memory,usb-storage,mac,integrity"]);
  expect(job?.script).toContain("EASYRMM-HARDENING-RESULT-V1");
  expect(await agent.start(job!.runId)).toBe(true);
  await expect(page.getByRole("heading", { name: "Checks" }).locator("xpath=ancestor::section").getByText("Running")).toBeVisible();
  await agent.succeeded(job!.runId, `EasyRMM hardening check: debian 13 (debian family; container: none; support: full).\n${hardeningResult()}`);

  // Once the run ends, the tab reads what the server kept.
  await expect(page.getByText("5 of 13 in place")).toBeVisible();
  const ssh = page.getByRole("listitem").filter({ has: page.getByRole("heading", { name: "SSH", level: 3 }) });
  await expect(ssh).toContainText("Partly in place");
  await expect(ssh).toContainText("PermitRootLogin prohibit-password (now yes)");
  const firewall = page.getByRole("listitem").filter({ has: page.getByRole("heading", { name: "Firewall", level: 3 }) });
  await expect(firewall).toContainText("22, 443");
  await expect(firewall).toContainText("tcp/8080");
  const last = page.getByRole("heading", { name: "Last check" }).locator("xpath=ancestor::section");
  await expect(last).toContainText("Debian 13");
  await expect(last).toContainText("Tested");
  await last.getByRole("link", { name: "Check hardening (every module)" }).click();
  await expect(page.getByRole("heading", { name: "Check hardening (every module)" })).toBeVisible();
  await page.goBack();

  // Across the fleet: the Devices list's column, and its filter on the server.
  await page.goto("/devices");
  const row = page.getByRole("row", { name: /dt-reception-01/ });
  await expect(row).toContainText("5 of 13 in place");
  await page.getByLabel("Hardening").selectOption({ label: "Needs attention" });
  await expect(page).toHaveURL(/\/devices\?hardening=attention$/);
  await expect(row).toBeVisible();
  await page.getByLabel("Hardening").selectOption({ label: "In place" });
  await expect(page.getByText("No devices match these filters")).toBeVisible();
  await page.getByLabel("Hardening").selectOption({ label: "Not checked" });
  await expect(page.getByText("No devices match these filters")).toBeVisible();
  await page.getByLabel("Hardening").selectOption({ label: "Any hardening" });
  await expect(row).toBeVisible();
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
  for (const label of ["Created organization", "Created site", "Created device group", "Invited user", "Created deployment token", "Enrolled device", "Hardening job"]) {
    await expect(page.getByRole("cell", { name: new RegExp(label) }).first()).toBeVisible();
  }
  await page.getByLabel("Area").selectOption({ label: "Users" });
  await expect(page.getByRole("cell", { name: /Created organization/ })).toHaveCount(0);

  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(page.getByText(/^Intact: \d+ entries checked, none altered or removed\.$/)).toBeVisible();
});
