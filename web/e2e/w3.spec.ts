// ADR-0054 slice W3, in the browser, against the server console.spec.ts leaves behind: the hardening console of a
// Windows computer, with an agent of its own that answers the jobs the console starts. Check, tier 3 refused without a
// step-up, apply with its guard, Keep, undo, and the fleet views of the organization, site and group. The agent's
// results are what the Windows script reports (written here, as no Windows runs in this suite): what is checked is the
// console and the server that records them.

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
const AUTOPLAY_NOT = { id: "autoplay-autorun", state: "not_in_place", value: "0", want: "1" };

let admin: Page;
let agent: Agent;
let name = "";
let siteId = "";
let orgId = "";
let groupId = "";
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

/** The jobs the server has for the agent, polled until `want` have come (the poll is held open while there are none). */
async function jobsFor(want: number, within = 30_000): Promise<JobPayload[]> {
  const got: JobPayload[] = [];
  const until = Date.now() + within;
  while (got.length < want && Date.now() < until) got.push(...(await agent.poll()));
  expect(got.length).toBeGreaterThanOrEqual(want);
  return got;
}

/** Runs a job on the agent and reports what the script would. */
async function answer(job: JobPayload, stdout: string) {
  expect(await agent.start(job.runId)).toBe(true);
  await agent.succeeded(job.runId, stdout);
}

test("a Windows computer enrolls in a group, and its Hardening tab waits for a first check", async () => {
  const page = admin;
  await page.goto("/devices/add");
  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Device group/).selectOption({ label: "Reception" });
  await page.getByLabel(/^Token name/).fill("Hardening console");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByRole("radio", { name: "Linux" }).click();
  const command = await page.locator("pre", { hasText: "install.sh" }).innerText();
  const token = /EASYRMM_TOKEN='(ert_[A-Za-z0-9_-]+)'/.exec(command)?.[1] ?? "";
  expect(token).toHaveLength(47);
  const facts = { hostname: "dt-win-hardening", os: "Windows Server 2025 Standard", platform: "windows", arch: "amd64", agentVersion: "0.6.0-e2e" };
  const key = deviceKey();
  const enroll = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: key.publicKey, facts } });
  expect(enroll.status(), await enroll.text()).toBe(201);
  agent = new Agent(page.request, ((await enroll.json()) as { deviceId: string }).deviceId, key.privateKey);
  const dev = (await (await page.request.get(`/api/v1/devices/${agent.deviceId}`)).json()) as { name: string; organizationId: string; siteId: string; deviceGroupId: string; canHarden: boolean };
  name = dev.name;
  orgId = dev.organizationId;
  siteId = dev.siteId;
  groupId = dev.deviceGroupId;
  expect(dev.canHarden).toBe(true);

  await page.goto(`/devices/${agent.deviceId}?tab=hardening`);
  await expect(page.getByRole("tab", { name: "Hardening" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByText("Not checked yet")).toBeVisible();
});

test("a check shows its modules, and the setting that is not in place", async () => {
  const page = admin;
  await page.getByRole("button", { name: "Run check…" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Check hardening" });
  await dialog.getByRole("button", { name: "Run check" }).click();
  const [job] = await jobsFor(1);
  const modules = job!.args[1]!.split(",");
  expect(job!.args[0]).toBe("check");
  await answer(
    job!,
    line(
      "check",
      modules.map((m) =>
        m === "autoplay"
          ? { module: m, state: "not_in_place", settings: [AUTOPLAY_NOT] }
          : m === "firewall"
            ? { module: m, state: "not_in_place" }
            : { module: m, state: "in_place" },
      ),
    ),
  );
  const autoplay = page.getByRole("heading", { name: "AutoPlay", level: 3 }).locator("xpath=ancestor::li");
  await expect(autoplay.getByText("Not in place").first()).toBeVisible({ timeout: 20_000 });
  await autoplay.getByRole("button", { name: /AutoPlay, show its settings/ }).click();
  const row = autoplay.getByRole("row", { name: /autoplay-autorun/ });
  await expect(row.getByText("Safe")).toBeVisible();
  await expect(row.getByText("Not in place")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Windows Firewall", level: 3 }).locator("xpath=ancestor::li").getByText("Can cut access")).toBeVisible();
});

test("a change that can cut access is refused without a step-up, and no job is made", async () => {
  const page = admin;
  const jobs = async () => ((await (await page.request.get("/api/v1/jobs?kind=hardening")).json()) as { items: unknown[] }).items.length;
  const before = await jobs();
  await page.getByRole("checkbox", { name: "Choose Windows Firewall", exact: true }).check();
  await page.getByRole("button", { name: "Apply…" }).click();
  const dialog = page.getByRole("dialog", { name: "Apply hardening" });
  await expect(dialog.getByText("This can cut access to the computer")).toBeVisible();
  await dialog.getByRole("checkbox", { name: /I have read what this change does/ }).check();
  await expect(dialog.getByRole("button", { name: "Apply" })).toBeDisabled();
  await dialog.getByLabel(/^Type .* to confirm/).fill(name);
  await dialog.getByRole("button", { name: "Apply" }).click();

  // The server asks for a second factor; the person leaves the dialog, so the request stays refused.
  const stepUp = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(stepUp).toBeVisible();
  await stepUp.getByRole("button", { name: "Cancel" }).click();
  await expect(dialog.getByText(/Confirm it is you with your authenticator app/)).toBeVisible();
  expect(await jobs()).toBe(before);
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await page.getByRole("checkbox", { name: "Choose Windows Firewall", exact: true }).uncheck();
});

test("apply asks for the agreement, arms the guard, and Keep ends the wait", async () => {
  const page = admin;
  await page.getByRole("checkbox", { name: "Choose AutoPlay", exact: true }).check();
  await page.getByRole("button", { name: "Apply…" }).click();
  const dialog = page.getByRole("dialog", { name: "Apply hardening" });
  await expect(dialog.getByText("Safe")).toBeVisible();
  await expect(dialog.getByLabel(/^Type .* to confirm/)).toHaveCount(0);
  await expect(dialog.getByRole("button", { name: "Apply" })).toBeDisabled();
  await dialog.getByRole("checkbox", { name: /I have read what this change does/ }).check();
  await dialog.getByRole("button", { name: "Apply" }).click();
  await expect(dialog).toBeHidden();

  const [apply] = await jobsFor(1);
  expect(apply!.args.slice(0, 2)).toEqual(["apply", "autoplay"]);
  expect(apply!.args).toContain("guard-minutes=10");
  await answer(
    apply!,
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
  await expect(page.getByText(/The computer undoes the change in \d:\d\d/)).toBeVisible({ timeout: 20_000 });
  const guards = (await (await page.request.get(`/api/v1/devices/${agent.deviceId}/hardening/guards`)).json()) as { items: { state: string; settings: string[] }[] };
  expect(guards.items[0]).toMatchObject({ state: "armed", settings: ["autoplay-autorun"] });

  await page.getByRole("button", { name: "Keep the change" }).click();
  await expect(page.getByText("Asked the agent to confirm now.")).toBeVisible();
  // The server's own confirmation, and the new one Keep queued: the agent answers both, and the guard is kept.
  const confirms = await jobsFor(1);
  for (const c of confirms) {
    expect(c.args).toEqual(["confirm"]);
    await answer(c, "The guard was ended: the change stands.\n");
  }
  const history = page.getByRole("list", { name: "Hardening history" });
  await expect(history.getByText("Kept")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(/The computer undoes the change in/)).toHaveCount(0);
});

test("undo puts the module back, and the history keeps both", async () => {
  const page = admin;
  await page.getByRole("checkbox", { name: "Choose AutoPlay", exact: true }).check();
  await page.getByRole("button", { name: "Undo…" }).click();
  const dialog = page.getByRole("dialog", { name: "Undo hardening" });
  await dialog.getByRole("checkbox", { name: /I have read what this change does/ }).check();
  await dialog.getByRole("button", { name: "Undo" }).click();
  await expect(dialog).toBeHidden();
  const [undo] = await jobsFor(1);
  expect(undo!.args[0]).toBe("undo");
  await answer(
    undo!,
    line("undo", [
      {
        module: "autoplay",
        state: "not_in_place",
        outcome: "undone",
        done: ["autoplay-autorun"],
        settings: [{ id: "autoplay-autorun", state: "not_in_place", value: "0", outcome: "restored", before: "1" }],
      },
    ]),
  );
  const autoplay = page.getByRole("heading", { name: "AutoPlay", level: 3 }).locator("xpath=ancestor::li");
  await expect(autoplay.getByText(/Last change: Undone/)).toBeVisible({ timeout: 20_000 });
  const audit = (await (await page.request.get(`/api/v1/audit?deviceId=${agent.deviceId}`)).json()) as { items: { action: string }[] };
  expect(audit.items.map((e) => e.action)).toEqual(expect.arrayContaining(["device.hardening", "device.hardening.guard_keep"]));
});

test("the fleet views at the organization, site and group list the computer, with what its check found", async () => {
  const page = admin;
  for (const path of [`/organizations/${orgId}?tab=hardening`, `/sites/${siteId}?tab=hardening`, `/groups/${groupId}?tab=hardening`]) {
    await page.goto(path);
    await expect(page.getByRole("tab", { name: "Hardening" })).toHaveAttribute("aria-selected", "true");
    const list = page.getByRole("table", { name: "Windows computers" });
    await expect(list.getByRole("link", { name })).toHaveAttribute("href", `/devices/${agent.deviceId}?tab=hardening`);
    await expect(page.getByRole("table", { name: "Modules across the computers" }).getByRole("row", { name: /AutoPlay/ })).toBeVisible();
  }
  await page.getByRole("radio", { name: "Not checked" }).click();
  await expect(page.getByRole("table", { name: "Windows computers" }).getByRole("link", { name })).toHaveCount(0);
});
