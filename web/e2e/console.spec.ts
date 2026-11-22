// The technician console, end to end, against a real server and database: first-run setup,
// mandatory two-factor enrollment, tenancy, invitations, scoped access, device enrollment, a
// hardening check through the device's agent, who sees a script's output and arguments, a failing
// disk's health and alert, Update all now for a site with a restart after the install (against the
// patching engine's stand-in), and the audit trail.
// The suite is one ordered story because each step builds on the server state of the last.

import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { inflateRawSync } from "node:zlib";
import { expect, test, type Locator, type Page } from "@playwright/test";
import { Agent, deviceKey } from "./agent";
import { enrollAuthenticator, nextCode } from "./authenticator";

const ADMIN = { name: "Alex Rivera", email: "alex@example.com", password: "harbor lantern quietly 42" };
const TECH = { name: "Riley Chen", email: "riley@example.com", password: "copper meadow steadily 77" };
const READER = { name: "Sam Ortiz", email: "sam@example.com", password: "willow harbor gently 58" };

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
  // The page's own heading: the menu's Alerts section has one too, once its tree loads.
  await expect(page.getByRole("heading", { name: "Alerts", level: 1 })).toBeVisible();

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

test("the customer record: contact information, hours, an address, places and contacts", async () => {
  const page = admin;
  const card = (title: RegExp) => page.locator("section", { has: page.getByRole("heading", { name: title }) });
  await page.goto("/organizations");
  await page.getByRole("main").getByRole("link", { name: "Contoso Dental Group" }).click();

  // The organization's contact information and hours, Monday to Friday.
  await card(/Contact information/).getByRole("button", { name: "Edit" }).click();
  const details = page.getByRole("dialog", { name: "Edit contact information" });
  await details.getByLabel("Main phone").fill("+1 555 0100");
  await details.getByLabel("Main email").fill("front-desk@example.com");
  await details.getByLabel("Website").fill("example.com");
  await details.getByRole("button", { name: "Add a period on Monday" }).click();
  await details.getByRole("button", { name: "Copy Monday to Tuesday–Friday" }).click();
  await details.getByRole("button", { name: "Save" }).click();
  await expect(details).toBeHidden();
  await expect(card(/Contact information/).getByRole("link", { name: "https://example.com" })).toBeVisible();
  await expect(card(/Contact information/).getByText("Mon–Fri")).toBeVisible();
  await expect(card(/Contact information/).getByText(/^(Open|Closed) now$/)).toBeVisible();

  // A primary contact for the organization, and one for the clinic.
  await page.getByRole("tab", { name: "Contacts" }).click();
  for (const [where, name] of [
    ["The organization", "Pat Example"],
    ["Downtown clinic", "Kim Example"],
  ] as const) {
    await page.getByRole("button", { name: "Add contact" }).click();
    const form = page.getByRole("dialog", { name: "New contact" });
    await form.getByLabel("Contact of").selectOption({ label: where });
    await form.getByLabel(/^Name/).fill(name);
    await form.getByLabel("Mobile phone").fill("555 0199");
    await form.getByLabel("Priority").selectOption("primary");
    await form.getByRole("button", { name: "Add contact" }).click();
    await expect(form).toBeHidden();
  }
  await expect(page.getByRole("row", { name: /Pat Example/ })).toContainText("Organization");
  await expect(page.getByRole("row", { name: /Kim Example/ })).toContainText("Downtown clinic");
  // A second primary at the organization makes the first secondary.
  await page.getByRole("button", { name: "Add contact" }).click();
  const second = page.getByRole("dialog", { name: "New contact" });
  await second.getByLabel(/^Name/).fill("Lee Example");
  await second.getByLabel("Priority").selectOption("primary");
  await second.getByLabel("Emergency contact").check();
  await second.getByRole("button", { name: "Add contact" }).click();
  await expect(page.getByRole("row", { name: /Lee Example/ })).toContainText("Emergency");
  await expect(page.getByRole("row", { name: /Pat Example/ })).toContainText("Secondary");

  // The overview names the primary and emergency contacts: Pat, now secondary, is on the Contacts tab only.
  await page.getByRole("tab", { name: "Overview" }).click();
  await expect(card(/Primary and emergency contacts/).getByRole("listitem")).toHaveText([/Lee Example.*Primary.*Emergency/, /Kim Example.*Downtown clinic/]);

  // The clinic's address, its places, and the organization's hours in its own time zone.
  await page.getByRole("main").getByRole("link", { name: "Downtown clinic" }).click();
  await card(/Address and hours/).getByRole("button", { name: "Edit" }).click();
  const address = page.getByRole("dialog", { name: "Edit address and hours" });
  await address.getByLabel("Address line 1").fill("1 Example Road");
  await address.getByLabel("City or town").fill("Springfield");
  await address.getByLabel("Country").selectOption("US");
  await address.getByRole("button", { name: "Save" }).click();
  await expect(address).toBeHidden();
  await expect(card(/Address and hours/).getByText("1 Example Road")).toBeVisible();
  await expect(card(/Address and hours/).getByText("The organization's hours, in the site's time zone.")).toBeVisible();
  await expect(card(/^Contacts$/).getByText("Kim Example")).toBeVisible();

  await card(/^Places$/).getByRole("button", { name: "Add place" }).click();
  const building = page.getByRole("dialog", { name: "New place" });
  await building.getByLabel(/^Name/).fill("Main building");
  await building.getByRole("button", { name: "Add place" }).click();
  await page.getByRole("button", { name: "Add a place inside Main building" }).click();
  const room = page.getByRole("dialog", { name: "New place" });
  await room.getByLabel(/^Name/).fill("Comms room");
  await room.getByRole("button", { name: "Add place" }).click();
  const places = page.getByRole("list", { name: "Places at Downtown clinic" });
  await expect(places.getByRole("listitem")).toHaveText([/Main building/, /Comms room/]);

  // Back on the organization, the clinic shows its address and whether it is open.
  await page.getByRole("navigation", { name: "Breadcrumb" }).getByRole("link", { name: "Contoso Dental Group" }).click();
  const clinic = page.getByRole("row", { name: /Downtown clinic/ });
  await expect(clinic).toContainText("1 Example Road, Springfield, ");
  await expect(clinic.getByText(/^(Open|Closed) now$/)).toBeVisible();

  // A site holding documentation is deleted only once what goes with it is confirmed.
  await page.getByRole("button", { name: "Add site" }).click();
  const popUp = page.getByRole("dialog", { name: "New site" });
  await popUp.getByLabel(/^Name/).fill("Pop-up clinic");
  await popUp.getByLabel(/^Time zone/).fill("America/New_York");
  await popUp.getByRole("button", { name: "Create site" }).click();
  await expect(page.getByRole("heading", { name: "Pop-up clinic" })).toBeVisible();
  await card(/^Places$/).getByRole("button", { name: "Add place" }).click();
  const tent = page.getByRole("dialog", { name: "New place" });
  await tent.getByLabel("Kind").selectOption("other");
  await tent.getByLabel(/^Name/).fill("Tent");
  await tent.getByRole("button", { name: "Add place" }).click();
  await expect(tent).toBeHidden();
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  const confirm = page.getByRole("dialog", { name: "Delete site" });
  await confirm.getByLabel(/Type .* to confirm/).fill("Pop-up clinic");
  await confirm.getByRole("button", { name: "Delete site" }).click();
  await expect(confirm.getByText(/holds 1 place/)).toBeVisible();
  await confirm.getByRole("button", { name: "Delete site and its documentation" }).click();
  await expect(page.getByRole("heading", { name: "Contoso Dental Group" })).toBeVisible();
  await expect(page.getByRole("main").getByRole("link", { name: "Pop-up clinic" })).toHaveCount(0);

  // The contacts export as a report.
  await page.goto("/reports?report=contacts");
  await expect(page.getByRole("cell", { name: "Lee Example" })).toBeVisible();

  // The next step starts inside the Organizations section, as the earlier ones leave it.
  await page.goto("/organizations");
  await expect(page.getByRole("navigation", { name: "Main" }).getByRole("button", { name: "Back to the main menu" })).toBeVisible();
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

  // The device's agent picks the check up: EasyRMM's own script, with every module the console sent as an argument,
  // and the job's time limit, which the script works to.
  const [job] = await agent.poll();
  expect(job?.shell).toBe("sh");
  expect(job?.args).toEqual([
    "check",
    "ssh,firewall,fail2ban,kernel,audit,permissions,services,kernel-modules,sudo,time,shared-memory,usb-storage,mac,integrity",
    "time-limit=1800",
  ]);
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

/** A secret a script is given and prints back: only those who may see job output and arguments ever receive it. */
const MARKER = `e2e-secret-${Date.now().toString(36)}`;

/** Clicks a download link and returns the file the browser saved. */
async function download(page: Page, link: Locator): Promise<{ name: string; body: Buffer }> {
  const [file] = await Promise.all([page.waitForEvent("download"), link.click()]);
  return { name: file.suggestedFilename(), body: await readFile(await file.path()) };
}

/** The files of a ZIP archive, by name: enough of the format for the server's archives (stored or deflated, no ZIP64). */
function unzip(zip: Buffer): Record<string, string> {
  const end = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const count = zip.readUInt16LE(end + 10);
  let at = zip.readUInt32LE(end + 16);
  const files: Record<string, string> = {};
  for (let i = 0; i < count; i++) {
    const method = zip.readUInt16LE(at + 10);
    const size = zip.readUInt32LE(at + 20);
    const [nameLen, extraLen, commentLen] = [zip.readUInt16LE(at + 28), zip.readUInt16LE(at + 30), zip.readUInt16LE(at + 32)];
    const local = zip.readUInt32LE(at + 42);
    const data = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
    const raw = zip.subarray(data, data + size);
    files[zip.subarray(at + 46, at + 46 + nameLen).toString("utf8")] = (method === 8 ? inflateRawSync(raw) : raw).toString("utf8");
    at += 46 + nameLen + extraLen + commentLen;
  }
  return files;
}

/** Accepts an invitation, sets the password, signs in and enrolls an authenticator. */
async function acceptInvitation(page: Page, link: string, who: { email: string; password: string }) {
  await page.goto(`/welcome${new URL(link).hash}`);
  await page.getByLabel(/^New password/).fill(who.password);
  await page.getByLabel(/^Confirm new password/).fill(who.password);
  await page.getByRole("button", { name: "Set password" }).click();
  await expect(page.getByText("Your password is set. Sign in with it now.")).toBeVisible();
  await signIn(page, who);
  await enrollAuthenticator(page, who.email);
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
}

test("a script's output and arguments reach only those who may see them, and every read is recorded", async ({ browser }) => {
  // Two more people sign in, each with a second factor.
  test.slow();
  const page = admin;
  // A Read-Only user of the device's organization: they see jobs and runs, not what they printed or were given.
  await page.goto("/settings");
  await page.getByRole("button", { name: "Invite user" }).click();
  const invite = page.getByRole("dialog", { name: "Invite user" });
  await invite.getByLabel(/^Email/).fill(READER.email);
  await invite.getByLabel(/^Name/).fill(READER.name);
  await invite.getByLabel("Role").selectOption({ label: "Read-Only" });
  await invite.getByLabel("Organization").selectOption({ label: "Contoso Dental Group" });
  await invite.getByRole("button", { name: "Send invitation" }).click();
  const notice = page.getByRole("dialog", { name: "Send this invitation link" });
  const readerLink = (await notice.locator("pre").innerText()).trim();
  await notice.getByRole("button", { name: "Done" }).click();

  // A script that prints the argument it is given.
  await page.goto("/scripts/new");
  await page.getByLabel(/^Name/).fill("Print the token");
  await page.getByLabel("Shell").selectOption({ label: "Bash" });
  await page.getByLabel(/^Body/).fill('echo "token=$1"\n');
  await page.getByRole("button", { name: "Add script" }).click();
  await expect(page.getByRole("heading", { name: "Print the token" })).toBeVisible();

  // The technician signs in again and runs it on the device, with the secret as its argument.
  const techContext = await browser.newContext();
  const tech = await techContext.newPage();
  await tech.goto(`/devices/${agent.deviceId}`);
  await signIn(tech, TECH);
  await tech.getByLabel(/^Verification code/).fill(await nextCode(tech, TECH.email));
  await tech.getByRole("button", { name: "Verify" }).click();
  await expect(tech.getByRole("heading", { name: "dt-reception-01" })).toBeVisible();
  await tech.getByRole("button", { name: "Run script" }).click();
  const run = tech.getByRole("dialog", { name: "Run a script" });
  await run.getByLabel(/^Script/).selectOption({ label: "Print the token" });
  await run.getByLabel("Arguments").fill(MARKER);
  await run.getByRole("button", { name: "Run", exact: true }).click();
  await expect(tech).toHaveURL(/\/jobs\/[0-9a-f-]{36}$/);
  const jobPath = new URL(tech.url()).pathname;

  // The device's agent receives the argument (read for it by a database function only the agent's poll may use) and
  // prints it back.
  const [job] = await agent.poll();
  expect(job?.args).toEqual([MARKER]);
  expect(await agent.start(job!.runId)).toBe(true);
  await agent.succeeded(job!.runId, `token=${MARKER}\n`);
  const runPath = `${jobPath}/runs/${job!.runId}`;

  // The Read-Only user opens the job and the run: both say hidden, and nothing their browser receives holds the secret.
  const readerContext = await browser.newContext();
  const reader = await readerContext.newPage();
  const answers: Promise<string>[] = [];
  reader.on("response", (r) => {
    if (new URL(r.url()).pathname.startsWith("/api/")) answers.push(r.text().catch(() => ""));
  });
  await acceptInvitation(reader, readerLink, READER);
  await reader.goto(jobPath);
  await expect(reader.getByRole("heading", { name: "Print the token" })).toBeVisible();
  await expect(reader.getByText("1 argument. Hidden: needs permission to see job arguments")).toBeVisible();
  // The results hold no output, so they are offered; the output archive is not.
  await expect(reader.getByRole("link", { name: "Download results (CSV)" })).toBeVisible();
  await expect(reader.getByRole("link", { name: "Download output (ZIP)" })).toHaveCount(0);
  await reader.getByRole("table").getByRole("link", { name: "dt-reception-01" }).click();
  await expect(reader).toHaveURL(new RegExp(`${runPath}$`));
  await expect(reader.getByText("Hidden: needs permission to see job output")).toBeVisible();
  await expect(reader.getByText("Succeeded").first()).toBeVisible();
  await expect(reader.getByRole("link", { name: /^Download/ })).toHaveCount(0);
  // Asking the API directly is refused, and the refusal is recorded. (The body is read, so the browser finishes the
  // response and the listener above gets it.)
  const status = (path: string) => reader.evaluate(async (p) => { const r = await fetch(p); await r.text(); return r.status; }, path);
  expect(await status(`/api/v1/job-runs/${job!.runId}/output`)).toBe(403);
  expect(await status(`/api/v1/jobs/${job!.jobId}/arguments`)).toBe(403);
  expect(await status(`/api/v1/job-runs/${job!.runId}/output?download=json`)).toBe(403);
  expect(await status(`/api/v1/jobs/${job!.jobId}/output.zip`)).toBe(403);
  expect(await status(`/api/v1/jobs/${job!.jobId}/runs.csv`)).toBe(200);
  reader.removeAllListeners("response");
  const received = await Promise.all(answers);
  expect(received.length).toBeGreaterThan(5);
  expect(received.filter((body) => body.includes(MARKER))).toEqual([]);
  await readerContext.close();

  // The technician holds job.view_sensitive at the site: the job's page shows the argument, the run's page the output.
  await expect(tech.getByText(MARKER)).toBeVisible();
  // The job's output as an archive holds what the run printed; its results do not (ADR-0064).
  const archive = await download(tech, tech.getByRole("link", { name: "Download output (ZIP)" }));
  expect(archive.name).toBe(`Print_the_token_${job!.jobId}_output.zip`);
  const files = unzip(archive.body);
  expect(files[`dt-reception-01_${job!.runId}/stdout.txt`]).toBe(`token=${MARKER}\n`);
  expect(files["runs.csv"]).toContain(`Succeeded,0,,`);
  const results = await download(tech, tech.getByRole("link", { name: "Download results (CSV)" }));
  expect(results.name).toBe(`Print_the_token_${job!.jobId}_results.csv`);
  expect(results.body.toString("utf8")).toContain(job!.runId);
  expect(results.body.toString("utf8")).not.toContain(MARKER);
  await tech.getByRole("table").getByRole("link", { name: "dt-reception-01" }).click();
  await expect(tech.getByText(`token=${MARKER}`)).toBeVisible();
  await expect(tech.getByText("Opening or downloading a run’s output is recorded in the audit log, each time.")).toBeVisible();
  // The run as a file, with both streams.
  const runFile = await download(tech, tech.getByRole("link", { name: "Download run" }));
  expect(runFile.name).toBe(`dt-reception-01_${job!.runId}.json`);
  expect(JSON.parse(runFile.body.toString("utf8"))).toMatchObject({ runId: job!.runId, status: "succeeded", stdout: `token=${MARKER}\n`, stderr: "" });
  // Once the secret is used, the technician removes it.
  await tech.getByRole("button", { name: "Remove output" }).click();
  const remove = tech.getByRole("dialog", { name: "Remove this run's output?" });
  await expect(remove).toContainText("Backups made before keep it.");
  await remove.getByRole("button", { name: "Remove output" }).click();
  await expect(tech.getByText(/by retention or by someone who could read it/)).toBeVisible();
  await expect(tech.getByText(`token=${MARKER}`)).toHaveCount(0);
  await techContext.close();

  // The site's administrators see who read what, and who was refused.
  await page.goto("/settings?tab=audit");
  await page.getByLabel("Area").selectOption({ label: "Job output" });
  const viewed = page.getByRole("row", { name: /Viewed job output/ });
  await expect(viewed.filter({ hasText: TECH.email })).toHaveCount(1);
  await expect(viewed.filter({ hasText: READER.email })).toContainText("Denied");
  await expect(viewed.first()).toContainText("Print the token on dt-reception-01");
  // Each download is a read of its own: the archive's and the run's.
  await expect(page.getByRole("row", { name: /Downloaded job output/ }).filter({ hasText: TECH.email })).toHaveCount(2);
  await expect(page.getByRole("row", { name: /Removed job output/ }).filter({ hasText: TECH.email })).toHaveCount(1);
  await page.getByLabel("Area").selectOption({ label: "Jobs" });
  const args = page.getByRole("row", { name: /Viewed job arguments/ });
  await expect(args.filter({ hasText: TECH.email })).toHaveCount(1);
  await expect(args.filter({ hasText: READER.email })).toContainText("Denied");
  const exported = page.getByRole("row", { name: /Downloaded job results/ });
  await expect(exported.filter({ hasText: TECH.email })).toHaveCount(1);
  await expect(exported.filter({ hasText: READER.email })).toHaveCount(1);
  await expect(page.getByText(MARKER)).toHaveCount(0);
});

/** An NVMe drive's reading as the agent reports it (agentproto.DiskHealth): critical warning bit 3, media read-only. */
function failingDisk(readAt: string) {
  const read = (value: number) => ({ state: "read", value });
  const notKept = { state: "unsupported", reason: "not_kept" };
  return {
    name: "nvme0n1",
    model: "Samsung SSD 990 PRO 2TB",
    serial: "S7DNNJ0X000001",
    state: "read",
    protocol: "nvme",
    route: "nvme",
    readAt,
    criticalWarning: read(8),
    smartStatus: notKept,
    thresholds: notKept,
    temperature: read(40),
    temperatureLimit: read(70),
    wear: read(3),
    availableSpare: read(100),
    availableSpareThreshold: read(10),
    mediaErrors: read(0),
    reallocatedSectors: notKept,
    pendingSectors: notKept,
    uncorrectableSectors: notKept,
    driveErrors: read(0),
    powerOnHours: read(1200),
    dataWritten: read(5_000_000),
    unsafeShutdowns: read(4),
    powerMode: notKept,
  };
}

test("a failing disk shows on the device and across the fleet, opens an alert, and a Read-Only user sees it", async ({ browser }) => {
  // The server evaluates alert policies once a minute.
  test.slow();
  const page = admin;
  // The agent's inventory with the drive's firmware (ADR-0065), then the drive's reading.
  await agent.inventory({
    system: { manufacturer: "Dell Inc.", model: "OptiPlex 7010", serial: "", biosVendor: "", biosVersion: "", biosDate: "", virtualization: "" },
    cpu: { model: "Intel(R) Core(TM) i5-13500", sockets: 1, cores: 14, threads: 20 },
    memoryBytes: 16 * 1024 ** 3,
    os: { name: "Debian GNU/Linux 13 (trixie)", id: "debian", version: "13", kernel: "6.12.38+deb13-amd64", timezone: "America/New_York" },
    disks: [
      {
        name: "nvme0n1",
        model: "Samsung SSD 990 PRO 2TB",
        serial: "S7DNNJ0X000001",
        sizeBytes: 2_000_398_934_016,
        kind: "nvme",
        removable: false,
        firmware: { state: "read", value: "4B2QJXD7" },
      },
    ],
    interfaces: [],
    gateways: [],
    dnsServers: [],
    packageManager: "dpkg",
    packages: [],
  });
  await agent.hardware({ disks: [failingDisk(new Date().toISOString())] });

  // The device's Disks card: firmware, and health with what made it fail.
  await page.goto(`/devices/${agent.deviceId}?tab=hardware`);
  const disks = page.getByRole("heading", { name: "Disks" }).locator("xpath=ancestor::section[1]");
  const disk = disks.getByRole("row", { name: /nvme0n1/ });
  await expect(disk).toContainText("4B2QJXD7");
  await expect(disk).toContainText("Failing, last read");
  await expect(disk).toContainText("NVMe critical warning: media read-only");
  await disk.getByRole("button", { name: "nvme0n1" }).click();
  const panel = page.getByRole("dialog", { name: "nvme0n1" });
  await expect(panel.getByRole("table", { name: "Facts" }).getByRole("row", { name: /Critical warning/ })).toContainText("Failing: NVMe critical warning");
  await expect(panel.getByRole("table", { name: "Facts" }).getByRole("row", { name: /Pending sectors/ })).toContainText("Unsupported: the drive does not keep this");
  await expect(panel.getByRole("table", { name: "Last 30 days" })).toContainText("Failing");
  await panel.getByRole("button", { name: "Close" }).click();

  // Across the fleet: the Devices list's column, and its filter on the server.
  await page.goto("/devices");
  const row = page.getByRole("row", { name: /dt-reception-01/ });
  await expect(row).toContainText("Failing");
  await page.getByLabel("Disk health").selectOption({ label: "Failing" });
  await expect(page).toHaveURL(/\/devices\?diskHealth=failing$/);
  await expect(row).toBeVisible();
  await page.getByLabel("Disk health").selectOption({ label: "Healthy" });
  await expect(page.getByText("No devices match these filters")).toBeVisible();
  await page.getByLabel("Disk health").selectOption({ label: "Not reported" });
  await expect(page.getByText("No devices match these filters")).toBeVisible();
  await page.getByLabel("Disk health").selectOption({ label: "Any disk health" });
  await expect(row).toBeVisible();

  // The shared Disk failing policy, on from the start, opens one alert for the disk at the next evaluation; the page
  // asks every 30 seconds.
  await page.goto("/alerts");
  const alert = page.getByRole("row", { name: /Disk failing/ });
  await expect(alert).toBeVisible({ timeout: 100_000 });
  await expect(alert).toContainText("nvme0n1 · Samsung SSD 990 PRO 2TB");
  await expect(alert).toContainText("NVMe critical warning: media read-only");
  await expect(alert).toContainText("A disk's own verdict is failing");
  await expect(alert).toContainText("dt-reception-01");
  // The alert is critical, so the device's name pulses in red, with the critical icon and words for screen readers;
  // in the menu's alerts tree too. The pulse is a slow colour change, and holds still under reduced motion.
  const name = alert.getByRole("link", { name: "dt-reception-01, active critical alert" });
  await expect(name).toHaveClass(/\balert-active-pulse\b/);
  await expect(name).toHaveCSS("animation-name", "alert-active-pulse");
  await expect(name).toHaveCSS("animation-duration", "1.8s");
  const tree = page.getByRole("tree", { name: "Alerts: organizations, sites and devices" });
  await expect(tree.getByRole("treeitem", { name: /^dt-reception-01, .*1 critical$/ }).getByText("dt-reception-01")).toHaveClass(/\balert-active-pulse\b/);
  await page.emulateMedia({ reducedMotion: "reduce" });
  await expect(name).toHaveCSS("animation-name", "none");
  await page.emulateMedia({ reducedMotion: null });
  // Anyone can stop it, and this browser remembers; the red then holds still.
  await page.getByRole("button", { name: "Stop flashing" }).click();
  await expect(name).toHaveCSS("animation-name", "none");
  await page.reload();
  await expect(name).toHaveCSS("animation-name", "none");
  await page.getByRole("button", { name: "Flash active alerts" }).click();
  await expect(name).toHaveCSS("animation-name", "alert-active-pulse");

  // The alert's name opens its card, at an address of its own: the disk and its facts, what to do, and the policy's
  // alerts on this disk, read from the server. Back closes it; the address opens it again; Escape closes it in place.
  await alert.getByRole("link", { name: "Disk failing on dt-reception-01, details" }).click();
  const alertCard = page.getByRole("dialog", { name: "Disk failing" });
  await expect(page).toHaveURL(/\/alerts\?alert=[0-9a-f-]{36}$/);
  await expect(alertCard.getByRole("region", { name: "Summary" })).toContainText("nvme0n1 · Samsung SSD 990 PRO 2TB");
  await expect(alertCard.getByRole("region", { name: "Why it opened" })).toContainText("A disk's own verdict is failing");
  await expect(alertCard.getByRole("table", { name: "Facts" }).getByRole("row", { name: /Critical warning/ })).toContainText("Failing: NVMe critical warning");
  await expect(alertCard.getByRole("region", { name: "History" })).toContainText("The only alert this policy has raised on this disk");
  await expect(alertCard.getByRole("region", { name: "What to do next" }).getByRole("link", { name: "Hardware: Disks" })).toHaveAttribute(
    "href",
    `/devices/${agent.deviceId}?tab=hardware`,
  );
  const cardAddress = page.url();
  await page.goBack();
  await expect(alertCard).toBeHidden();
  await expect(page).toHaveURL(/\/alerts$/);
  await page.goto(cardAddress);
  await expect(alertCard.getByRole("region", { name: "Times" })).toContainText("Not acknowledged");
  await page.keyboard.press("Escape");
  await expect(alertCard).toBeHidden();
  await expect(page).toHaveURL(/\/alerts$/);

  // On the device's page, the alert's row pulses and the Alerts card counts it.
  await page.goto(`/devices/${agent.deviceId}`);
  const card = page.getByRole("heading", { name: /^Alerts \d+ active$/ }).locator("xpath=ancestor::section[1]");
  await expect(card.getByRole("listitem").filter({ hasText: "Disk failing" })).toHaveClass(/\balert-active-pulse\b/);

  // A Read-Only user of the organization sees the disk's health, its facts and its alert.
  const readerContext = await browser.newContext();
  const reader = await readerContext.newPage();
  await reader.goto(`/devices/${agent.deviceId}?tab=hardware`);
  await signIn(reader, READER);
  await reader.getByLabel(/^Verification code/).fill(await nextCode(reader, READER.email));
  await reader.getByRole("button", { name: "Verify" }).click();
  const readerDisk = reader.getByRole("heading", { name: "Disks" }).locator("xpath=ancestor::section[1]").getByRole("row", { name: /nvme0n1/ });
  await expect(readerDisk).toContainText("Failing, last read");
  await readerDisk.getByRole("button", { name: "nvme0n1" }).click();
  const readerPanel = reader.getByRole("dialog", { name: "nvme0n1" });
  await expect(readerPanel.getByRole("table", { name: "Facts" })).toContainText("Media read-only");
  await expect(readerPanel.getByRole("region", { name: "Open alerts" })).toContainText("Disk failing");
  await expect(readerPanel.getByRole("region", { name: "Open alerts" }).getByRole("listitem")).toHaveClass(/\balert-active-pulse\b/);
  await readerContext.close();
});

test("a PowerShell 7 script runs only once the agent says it can, and its run names the version used", async ({ browser }) => {
  // The agent's poll is held open for up to 25 seconds while there is no work, as a real agent's is.
  test.slow();
  const page = admin;
  // A Windows device enrolls with a token of its own.
  await page.goto("/devices");
  await page.getByRole("link", { name: "Add devices" }).first().click();
  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Device group/).selectOption({ label: "Reception" });
  await page.getByLabel(/^Token name/).fill("Front desk");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  const token = /-Token '(ert_[A-Za-z0-9_-]+)'/.exec(await page.locator("pre", { hasText: "install.ps1" }).innerText())?.[1] ?? "";
  expect(token).toHaveLength(47);
  const key = deviceKey();
  const facts = { hostname: "dt-frontdesk-01", os: "Microsoft Windows 11 Pro", platform: "windows", arch: "amd64", agentVersion: "0.6.0-e2e" };
  const enroll = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: key.publicKey, facts } });
  expect(enroll.status(), await enroll.text()).toBe(201);
  const pc = new Agent(page.request, ((await enroll.json()) as { deviceId: string }).deviceId, key.privateKey);
  // Its inventory lists Windows PowerShell and the PowerShell 7 its scripts run in.
  const pwsh = { edition: "Core", version: "7.6.10", arch: "x64", path: "C:\\Program Files\\PowerShell\\7\\pwsh.exe" } as const;
  await pc.inventory({
    system: { manufacturer: "Dell Inc.", model: "OptiPlex 7020", serial: "", biosVendor: "", biosVersion: "", biosDate: "", virtualization: "" },
    cpu: { model: "Intel(R) Core(TM) i5-14500", sockets: 1, cores: 14, threads: 20 },
    memoryBytes: 16 * 1024 ** 3,
    os: { name: "Windows 11 Pro", id: "windows", version: "10.0.26100", kernel: "26100.7171", timezone: "UTC" },
    disks: [],
    interfaces: [],
    gateways: [],
    dnsServers: [],
    packageManager: "windows",
    packages: [],
    powerShell: [
      { edition: "Desktop", version: "5.1.26100.7019", arch: "x64", path: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", usable: true },
      { ...pwsh, usable: true },
    ],
  });

  // The administrator adds a PowerShell 7 script; it fails where PowerShell 7 is missing unless the author says otherwise.
  await page.goto("/scripts/new");
  await page.getByLabel(/^Name/).fill("PowerShell version");
  await page.getByLabel("Shell").selectOption({ label: "PowerShell 7" });
  await expect(page.getByLabel("Where PowerShell 7 is missing")).toHaveValue("fail");
  await page.getByLabel(/^Body/).fill("$PSVersionTable.PSVersion.ToString()\n");
  await page.getByRole("button", { name: "Add script" }).click();
  await expect(page.getByRole("heading", { name: "PowerShell version" })).toBeVisible();

  // The technician tries it before the device's agent has said what it runs: refused, with the reason.
  const techContext = await browser.newContext();
  const tech = await techContext.newPage();
  await tech.goto(`/devices/${pc.deviceId}`);
  await signIn(tech, TECH);
  await tech.getByLabel(/^Verification code/).fill(await nextCode(tech, TECH.email));
  await tech.getByRole("button", { name: "Verify" }).click();
  await expect(tech.getByRole("heading", { name: "dt-frontdesk-01" })).toBeVisible();
  await tech.getByRole("button", { name: "Run script" }).click();
  const run = tech.getByRole("dialog", { name: "Run a script" });
  await run.getByLabel(/^Script/).selectOption({ label: "PowerShell version" });
  await run.getByRole("button", { name: "Run", exact: true }).click();
  await expect(run.getByText("dt-frontdesk-01's agent has not yet said whether it can run PowerShell 7 scripts", { exact: false })).toBeVisible();

  // The agent's poll says it takes PowerShell 7 jobs, and waits for work.
  const polled = pc.poll(["job.pwsh"]);
  await expect
    .poll(async () => ((await (await page.request.get(`/api/v1/devices/${pc.deviceId}`)).json()) as { agent: { accepts: string[] | null } }).agent.accepts)
    .toEqual(["job.pwsh"]);
  await run.getByRole("button", { name: "Run", exact: true }).click();
  await expect(tech).toHaveURL(/\/jobs\/[0-9a-f-]{36}$/);
  let jobs = await polled;
  while (jobs.length === 0) jobs = await pc.poll(["job.pwsh"]);
  const [job] = jobs;
  expect(job?.shell).toBe("pwsh");
  expect(job?.pwshFallback ?? false).toBe(false);
  expect(await pc.start(job!.runId)).toBe(true);
  await pc.succeeded(job!.runId, "7.6.10\n", pwsh);

  // The job and the run name the program the agent started.
  await expect(tech.getByText("Without PowerShell 7")).toBeVisible();
  await expect(tech.getByText("Fails the run")).toBeVisible();
  await tech.getByRole("table").getByRole("link", { name: "dt-frontdesk-01" }).click();
  await expect(tech.getByText("PowerShell 7.6.10, 64-bit")).toBeVisible();
  await expect(tech.getByText(pwsh.path)).toBeVisible();
  // The device lists what it found.
  await tech.goto(`/devices/${pc.deviceId}?tab=hardware`);
  await expect(tech.getByText("Runs PowerShell 7 scripts")).toBeVisible();
  await techContext.close();
});

// The patching engine's stand-in (eptest-engine, started by scripts/e2e/start-server.sh): the tests add its endpoints
// and finish its jobs, as an EasyPatch agent's reports would.
const ENGINE = `http://127.0.0.1:${Number(process.env.EASYRMM_E2E_PORT ?? 18180) + 13}/__eptest`;

interface EngineJob {
  ID: string;
  Endpoint: string;
  Type: string;
  Status: string;
}

test("Update all now for a site installs every available update, and restarts the device once the install has finished", async ({ request }) => {
  // EasyRMM links devices to the engine's endpoints, and asks for restarts after installs, once a minute.
  test.setTimeout(300_000);
  const page = admin;

  // The engine has the device's endpoint once EasyRMM has created its organization there: two updates to install, one
  // excluded on the device, and a feature upgrade.
  let endpoint = { endpointId: "", keyFingerprint: "" };
  await expect
    .poll(
      async () => {
        const r = await request.post(`${ENGINE}/endpoints`, {
          data: {
            organization: "Contoso Dental Group",
            hostname: "dt-reception-01",
            updates: [
              { title: "openssl 3.5.7-1~deb13u3", category: "Security", state: "Missing" },
              { title: "tzdata 2026c-0+deb13u1", category: "Other", state: "Failed" },
              { title: "libxml2 2.12.7+dfsg-2", category: "Security", state: "Missing", excluded: true },
              { title: "Debian 14 upgrade", category: "Feature", state: "Missing" },
            ],
          },
        });
        if (r.ok()) endpoint = (await r.json()) as typeof endpoint;
        return r.status();
      },
      { timeout: 90_000, intervals: [2_000] },
    )
    .toBe(201);
  // The device's EasyPatch agent, as its EasyRMM agent reports it.
  await agent.inventory({
    system: { manufacturer: "Dell Inc.", model: "OptiPlex 7010", serial: "", biosVendor: "", biosVersion: "", biosDate: "", virtualization: "" },
    cpu: { model: "Intel(R) Core(TM) i5-13500", sockets: 1, cores: 14, threads: 20 },
    memoryBytes: 16 * 1024 ** 3,
    os: { name: "Debian GNU/Linux 13 (trixie)", id: "debian", version: "13", kernel: "6.12.38+deb13-amd64", timezone: "America/New_York" },
    disks: [],
    interfaces: [],
    gateways: [],
    dnsServers: [],
    packageManager: "dpkg",
    packages: [],
    easyPatch: { version: "1.10.0", status: "Active", serverUrl: "https://patch.example.com", ...endpoint },
  });

  // The overview, for the clinic: once the device is linked, it is the one device there to patch.
  await page.goto("/patching");
  await page.getByLabel("Organization").selectOption({ label: "Contoso Dental Group" });
  await page.getByLabel("Site").selectOption({ label: "Downtown clinic" });
  const bar = page.getByRole("region", { name: "Every device in Downtown clinic (Contoso Dental Group)" });
  await expect(async () => {
    await page.reload();
    await expect(bar).toContainText("you may patch: 1 device", { timeout: 5_000 });
  }).toPass({ timeout: 120_000, intervals: [5_000] });
  await expect(bar.getByRole("button", { name: "Patch all…" })).toBeVisible();
  await expect(bar.getByRole("button", { name: "Schedule restart all…" })).toBeVisible();

  // Update all now: now, every available update, restart if the updates need it, Windows first. The clinic's one
  // device runs Linux, so it is ticked in.
  await bar.getByRole("button", { name: "Update all now…" }).click();
  const dialog = page.getByRole("dialog", { name: "Update all of Downtown clinic (Contoso Dental Group) now" });
  const linux = dialog.getByRole("checkbox", { name: /^Linux \(1\)/ });
  await expect(linux).not.toBeChecked();
  await linux.check();
  await expect(dialog.getByRole("radio", { name: "Restart if the updates need it" })).toBeChecked();
  const what = dialog.getByRole("region", { name: "What would be installed" });
  await expect(what).toContainText("2 updates");
  await expect(what).toContainText(/excluded/i);
  await expect(what).toContainText(/feature upgrade/i);
  await dialog.getByRole("button", { name: "Install now" }).click();

  const result = page.getByRole("dialog", { name: "Install started in Downtown clinic (Contoso Dental Group)" });
  await expect(result).toContainText("1 job created, one per device.");
  await expect(result).toContainText("1 device is set to restart after the install.");
  await result.getByRole("button", { name: "Close" }).last().click();

  // The engine was asked for the two updates, as chosen updates, and no restart yet.
  const jobs = async () => ((await (await request.get(`${ENGINE}/jobs`)).json()) as EngineJob[]).filter((j) => j.Endpoint === endpoint.endpointId);
  const install = (await jobs()).find((j) => j.Type === "InstallUpdates");
  expect(install).toBeTruthy();
  expect((await jobs()).filter((j) => j.Type === "Restart")).toHaveLength(0);

  // The install finishes, and its updates need a restart: EasyRMM asks the engine for one restart.
  await request.post(`${ENGINE}/jobs/${install!.ID}`, { data: { status: "Completed", rebootRequired: true } });
  await expect.poll(async () => (await jobs()).filter((j) => j.Type === "Restart").length, { timeout: 100_000, intervals: [5_000] }).toBe(1);

  // The install's job shows the choice and what became of it, linked to the restart.
  await page.goto(`/patching?tab=jobs&job=${install!.ID}`);
  const job = page.getByRole("dialog").getByRole("region", { name: "Restart after the install" });
  await expect(job).toContainText("Restart asked for");
  await expect(job).toContainText("Restart asked for once the install finished.");
  // The job in full: how it started, from EasyRMM's audit log; the device; its updates, with the engine's details.
  const detail = page.getByRole("dialog");
  await expect(detail.getByRole("region", { name: "How it started" })).toContainText("A request for every device in Contoso Dental Group / Downtown clinic");
  await expect(detail.getByRole("region", { name: "Device" })).toContainText("dt-reception-01");
  await expect(detail.getByRole("region", { name: "Updates" })).toContainText("On the device now");
  await expect(detail.getByRole("region", { name: "Timeline" })).toContainText("Finished");
  await page.getByRole("dialog").getByRole("button", { name: "Close" }).last().click();
  await expect(page.getByRole("dialog")).toBeHidden();
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
  for (const label of ["Created organization", "Created site", "Changed contact information", "Added contact", "Added place", "Created device group", "Invited user", "Created deployment token", "Enrolled device", "Hardening job"]) {
    await expect(page.getByRole("cell", { name: new RegExp(label) }).first()).toBeVisible();
  }
  await page.getByLabel("Area").selectOption({ label: "Users" });
  await expect(page.getByRole("cell", { name: /Created organization/ })).toHaveCount(0);

  await page.getByRole("button", { name: "Verify integrity" }).click();
  await expect(page.getByText(/^Intact: \d+ entries checked, none altered or removed\.$/)).toBeVisible();
});
