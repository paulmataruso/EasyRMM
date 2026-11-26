// ADR-0078 slice C2, in the browser, against the server console.spec.ts leaves behind: the organization's Compliance tab
// with a Windows computer of its own and an agent that answers the jobs. The scan makes the fix queue; a safe fix is
// agreed to, applied and verified by the re-scan, then undone; a fix that can cut access needs the computer's name typed,
// is refused without a step-up (no job, no agreement), and is applied after one. The agent's results are what the Windows
// script reports (written here, as no Windows runs in this suite): what is checked is the console and the server.

import { expect, test, type Page } from "@playwright/test";
import { Agent, deviceKey, type JobPayload } from "./agent";
import { nextCode } from "./authenticator";

const ADMIN = {
  email: "alex@example.com",
  password: "harbor lantern quietly 42",
};

const PLATFORM = {
  id: "windows",
  versionId: "10.0.26100.4349",
  family: "windows",
  container: "none",
  support: "full",
  windows: {
    build: 26100,
    ubr: 4349,
    displayVersion: "24H2",
    edition: "ServerStandard",
    installationType: "Server Core",
    role: "member_server",
    joined: "domain",
    mdm: false,
    architecture: "amd64",
    languageMode: "FullLanguage",
    owners: { groupPolicyRecord: "read", groupPolicyPreferences: false, mdm: false, mdmWinsOverGp: false, defenderForEndpoint: false, configMgr: false, dsc: false, azureMachineConfiguration: false, osConfig: [], tamperProtected: true },
    checkOnlyReasons: [],
    notes: [],
    hardening: { folder: "absent", copySha256: "", warnings: [], setAside: [] },
  },
};

const line = (mode: string, modules: unknown[]) => `EASYRMM-HARDENING-RESULT-V1 ${JSON.stringify({ version: 1, mode, platform: PLATFORM, modules })}\n`;
const NOT = (id: string, value: string, want: string) => ({ id, state: "not_in_place", value, want });
const IN = (id: string, value: string) => ({ id, state: "in_place", value, want: value });

/** What a check of the modules reports: AutoPlay, the minimum password length and Remote Desktop's NLA do not meet; the rest is not described. */
function check(modules: string[], autorun: "not_in_place" | "in_place") {
  return line(
    "check",
    modules.map((m) => {
      if (m === "autoplay") return { module: m, state: autorun, settings: [autorun === "in_place" ? IN("autoplay-autorun", "1") : NOT("autoplay-autorun", "0", "1")] };
      if (m === "accounts") return { module: m, state: "not_in_place", settings: [NOT("accounts-min-length", "8", "14")] };
      if (m === "rdp") return { module: m, state: "not_in_place", settings: [NOT("rdp-nla", "0", "1")] };
      return { module: m, state: "in_place" };
    }),
  );
}

let admin: Page;
let agent: Agent;
let name = "";
let orgId = "";
test.describe.configure({ mode: "serial" });
test.beforeAll(async ({ browser }) => {
  // A session of its own: a second factor given in another session does not count here.
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

/** Jobs the agent has been given and not yet taken by a test. */
const held: JobPayload[] = [];

/**
 * The next job the server has for the agent that starts with `mode` (apply, undo, check), polled until it comes (the poll is held
 * open while there are none). The server's own guard confirmations are answered on the way: the agent confirms that the change stands.
 */
async function take(mode: string, within = 30_000): Promise<JobPayload> {
  const until = Date.now() + within;
  for (;;) {
    const at = held.findIndex((j) => j.args[0] === mode);
    if (at >= 0) return held.splice(at, 1)[0]!;
    expect(Date.now(), `no ${mode} job came`).toBeLessThan(until);
    for (const j of await agent.poll()) {
      if (j.args[0] === "confirm") await answer(j, "The guard was ended: the change stands.\n");
      else held.push(j);
    }
  }
}

/** Runs a job on the agent and reports what the script would. */
async function answer(job: JobPayload, stdout: string) {
  expect(await agent.start(job.runId)).toBe(true);
  await agent.succeeded(job.runId, stdout);
}

const hardeningJobs = async (page: Page) => ((await (await page.request.get("/api/v1/jobs?kind=hardening")).json()) as { items: unknown[] }).items.length;
const queue = (page: Page) => page.getByRole("table", { name: "Fix queue" });
const itemRow = (page: Page, title: string | RegExp) => queue(page).getByRole("row", { name: title });

test("a Windows computer enrolls, and the organization's Compliance tab turns the module on", async () => {
  const page = admin;
  await page.goto("/devices/add");
  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Device group/).selectOption({ label: "Reception" });
  await page.getByLabel(/^Token name/).fill("Fix queue");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByRole("radio", { name: "Linux" }).click();
  const command = await page.locator("pre", { hasText: "install.sh" }).innerText();
  const token = /EASYRMM_TOKEN='(ert_[A-Za-z0-9_-]+)'/.exec(command)?.[1] ?? "";
  expect(token).toHaveLength(47);
  const facts = { hostname: "dt-win-fixqueue", os: "Windows Server 2025 Standard", platform: "windows", arch: "amd64", agentVersion: "0.6.0-e2e" };
  const key = deviceKey();
  const enroll = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: key.publicKey, facts } });
  expect(enroll.status(), await enroll.text()).toBe(201);
  agent = new Agent(page.request, ((await enroll.json()) as { deviceId: string }).deviceId, key.privateKey);
  const dev = (await (await page.request.get(`/api/v1/devices/${agent.deviceId}`)).json()) as { name: string; organizationId: string };
  name = dev.name;
  orgId = dev.organizationId;

  // Off: the tab holds the switch and nothing else, and the computer's own page has no Compliance tab.
  await page.goto(`/devices/${agent.deviceId}`);
  await expect(page.getByRole("tab", { name: "Hardening" })).toBeVisible();
  await expect(page.getByRole("tab", { name: "Compliance" })).toHaveCount(0);
  await page.goto(`/organizations/${orgId}?tab=compliance`);
  await expect(page.getByRole("tab", { name: "Compliance" })).toHaveAttribute("aria-selected", "true");
  await expect(queue(page)).toHaveCount(0);
  await page.getByRole("button", { name: "Turn on compliance checks" }).click();
  await expect(page.getByRole("button", { name: "Scan now" })).toBeVisible();
});

test("a scan asks the computer and makes the fix queue, one item for each control that does not meet", async () => {
  const page = admin;
  // The organization may hold other Windows computers (earlier specs enrolled some): this scan is of this computer alone, from its own tab.
  await page.goto(`/devices/${agent.deviceId}?tab=compliance`);
  await page.getByLabel("Profile").selectOption({ label: "Windows server security baseline" });
  await page.getByRole("button", { name: "Scan now" }).click();
  const job = await take("check");
  await answer(job, check(job.args[1]!.split(","), "not_in_place"));
  await expect(page.getByText("Scan finished.")).toBeVisible({ timeout: 30_000 });

  await expect(itemRow(page, /No AutoRun commands/)).toBeVisible({ timeout: 20_000 });
  await expect(itemRow(page, /No AutoRun commands/).getByText("Safe")).toBeVisible();
  await expect(itemRow(page, /Passwords of at least 14 characters/).getByText("Can break a workflow")).toBeVisible();
  await expect(itemRow(page, /Network Level Authentication required/).getByText("Can cut access")).toBeVisible();
  // The computer's controls and its requirements read the same results, in the console's words.
  await expect(page.getByRole("table", { name: "Controls" }).getByRole("row", { name: /No AutoRun commands/ })).toContainText("Does not meet");
  await expect(page.getByRole("heading", { name: "Requirements for this computer" })).toBeVisible();
  await expect(page.getByText(/requirements can be checked by a scan/)).toBeVisible();
  expect((await page.locator("body").innerText()).toLowerCase()).not.toMatch(/compliant|certified/);
  // Nothing is chosen, and there is no "fix all".
  for (const box of await queue(page).getByRole("checkbox").all()) await expect(box).not.toBeChecked();
  await expect(page.getByRole("button", { name: /fix all|apply all/i })).toHaveCount(0);
});

test("a safe fix is agreed to and applied; the re-scan verifies it; undo puts it back", async () => {
  const page = admin;
  await itemRow(page, /No AutoRun commands/).getByRole("button", { name: /^Apply/ }).click();
  const dialog = page.getByRole("dialog", { name: "Apply fix" });
  await expect(dialog.getByRole("list", { name: "Computers" }).getByText(name)).toBeVisible();
  await expect(dialog.getByLabel(/^Type .* to confirm/)).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Apply" })).toBeDisabled();
  await dialog.getByRole("checkbox", { name: /I have read the warning/ }).check();
  await dialog.getByRole("button", { name: "Apply" }).click();
  await expect(dialog).toBeHidden();

  // One change to one setting, named by id, with the computer's own timer.
  const apply = await take("apply");
  expect(apply.args.slice(0, 3)).toEqual(["apply", "--settings", "autoplay-autorun"]);
  expect(apply.args).toContain("guard-minutes=10");
  await answer(
    apply,
    line("apply", [
      {
        module: "autoplay",
        state: "in_place",
        outcome: "applied",
        recorded: true,
        done: ["autoplay-autorun"],
        settings: [{ id: "autoplay-autorun", state: "in_place", value: "1", outcome: "applied", before: "0", changedAt: new Date().toISOString() }],
      },
    ]),
  );
  // The fix does not decide the result: a re-scan of that one control does.
  await expect(itemRow(page, /No AutoRun commands/).getByText("Applied, checking")).toBeVisible({ timeout: 20_000 });
  const scan = await take("check");
  expect(scan.args[1]).toBe("autoplay");
  await answer(scan, check(["autoplay"], "in_place"));
  await expect(itemRow(page, /No AutoRun commands/).getByText("Applied and verified")).toBeVisible({ timeout: 30_000 });

  await itemRow(page, /No AutoRun commands/).getByRole("button", { name: /^Undo/ }).click();
  const undo = page.getByRole("dialog", { name: "Undo fix" });
  await undo.getByRole("checkbox", { name: /I have read the warning/ }).check();
  await undo.getByRole("button", { name: "Undo" }).click();
  const undoJob = await take("undo");
  expect(undoJob.args.slice(0, 3)).toEqual(["undo", "--settings", "autoplay-autorun"]);
  await answer(
    undoJob,
    line("undo", [
      { module: "autoplay", state: "not_in_place", outcome: "undone", done: ["autoplay-autorun"], settings: [{ id: "autoplay-autorun", state: "not_in_place", value: "0", outcome: "restored", before: "1" }] },
    ]),
  );
  // The undo is checked again too, and the control that does not meet is back in the queue as a new item.
  await answer(await take("check"), check(["autoplay"], "not_in_place"));
  await expect(itemRow(page, /No AutoRun commands/).getByText("Waiting")).toBeVisible({ timeout: 30_000 });
  await page.getByRole("radio", { name: "History" }).click();
  await expect(page.getByRole("table", { name: "Fix history" }).getByText("Undone").first()).toBeVisible({ timeout: 30_000 });

  const audit = (await (await page.request.get(`/api/v1/audit?deviceId=${agent.deviceId}`)).json()) as { items: { action: string }[] };
  expect(audit.items.map((e) => e.action)).toEqual(
    expect.arrayContaining(["compliance.fix.agreed", "compliance.fix.dispatched", "compliance.fix.applied", "compliance.fix.read_back", "compliance.fix.undone"]),
  );
});

test("a fix that can cut access needs the computer's name, and is refused without a step-up: no job, no agreement", async () => {
  const page = admin;
  await page.getByRole("radio", { name: "Queue" }).click();
  const before = await hardeningJobs(page);
  await itemRow(page, /Network Level Authentication required/).getByRole("button", { name: /^Apply/ }).click();
  const dialog = page.getByRole("dialog", { name: "Apply fix" });
  await expect(dialog.getByText(/undoes the change by itself after 10 minutes/)).toBeVisible();
  await dialog.getByRole("checkbox", { name: /I have read the warning/ }).check();
  const apply = dialog.getByRole("button", { name: "Apply" });
  await expect(apply).toBeDisabled();

  // A wrong name is refused by the server.
  await dialog.getByLabel(/^Type .* to confirm/).fill("NOT-THIS-ONE");
  await apply.click();
  await expect(dialog.getByText("The name typed is not the computer's name.")).toBeVisible();

  // The right name: the server asks for a second factor; leaving that leaves the request refused.
  await dialog.getByLabel(/^Type .* to confirm/).fill(name);
  await apply.click();
  const stepUp = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(stepUp).toBeVisible();
  await stepUp.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog.getByText(/Confirm it is you with your authenticator app/)).toBeVisible();
  expect(await hardeningJobs(page)).toBe(before);
  const refused = (await (await page.request.get(`/api/v1/organizations/${orgId}/compliance/fixes?state=active`)).json()) as { items: { controlId: string; state: string }[] };
  expect(refused.items.find((i) => i.controlId === "win.rdp.nla")?.state).toBe("open");

  // With the second factor it goes through, as one job on one setting.
  await apply.click();
  await stepUp.getByLabel(/Code from your authenticator app/).fill(await nextCode(page, ADMIN.email));
  await stepUp.getByRole("button", { name: "Confirm" }).click();
  await expect(dialog).toBeHidden({ timeout: 20_000 });
  const job = await take("apply");
  expect(job.args.slice(0, 3)).toEqual(["apply", "--settings", "rdp-nla"]);
  expect(await hardeningJobs(page)).toBe(before + 1);
  await expect(itemRow(page, /Network Level Authentication required/).getByText("Applying")).toBeVisible({ timeout: 20_000 });
  const detail = (await (await page.request.get(`/api/v1/organizations/${orgId}/compliance/fixes?state=active`)).json()) as { items: { id: string; controlId: string }[] };
  const id = detail.items.find((i) => i.controlId === "win.rdp.nla")!.id;
  const item = (await (await page.request.get(`/api/v1/organizations/${orgId}/compliance/fixes/${id}`)).json()) as { agreements: { act: string; typedText: string | null; stepUp: boolean; warningSha256: string }[] };
  expect(item.agreements).toHaveLength(1);
  expect(item.agreements[0]).toMatchObject({ act: "apply", stepUp: true });
  expect(item.agreements[0]!.typedText?.toLowerCase()).toBe(name.toLowerCase());
  expect(item.agreements[0]!.warningSha256).toHaveLength(64);
});

test("the organization's tab counts the results, and the site's card and the devices filter find the computer", async () => {
  const page = admin;
  await page.goto(`/organizations/${orgId}?tab=compliance`);
  await expect(page.getByText("Controls that do not meet")).toBeVisible();
  const all = queue(page);
  await expect(all.getByRole("row", { name: /Passwords of at least 14 characters/ }).getByRole("link", { name })).toHaveAttribute("href", `/devices/${agent.deviceId}?tab=compliance`);
  // The site's Overview has its result card, and the devices list its filter.
  const dev = (await (await page.request.get(`/api/v1/devices/${agent.deviceId}`)).json()) as { siteId: string };
  await page.goto(`/sites/${dev.siteId}`);
  const card = page.getByRole("heading", { name: "Compliance" }).locator("xpath=ancestor::section[1]");
  await expect(card.getByText("Do not meet")).toBeVisible();
  await expect(card.getByRole("link", { name: "Details" })).toHaveAttribute("href", `/organizations/${orgId}?tab=compliance`);
  await page.goto("/devices?compliance=failing");
  await expect(page.getByRole("link", { name })).toBeVisible();
});
