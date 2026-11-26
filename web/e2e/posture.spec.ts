// ADR-0082 slice P1, in the browser, against the server console.spec.ts leaves behind: a Windows computer with an
// agent of its own; its security posture goes from "cannot tell" (no check has reported) to "does not meet" when a
// hardening check finds the firewall not in place, and the Devices column and filter, the device's reasons and the
// Security report with its CSV all say so in the compliance engine's words. The agent's result is what the Windows
// script reports (written here, as no Windows runs in this suite).

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

let admin: Page;
let agent: Agent;
let name = "";
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

async function jobsFor(want: number, within = 30_000): Promise<JobPayload[]> {
  const got: JobPayload[] = [];
  const until = Date.now() + within;
  while (got.length < want && Date.now() < until) got.push(...(await agent.poll()));
  expect(got.length).toBeGreaterThanOrEqual(want);
  return got;
}

const wordsNeverUsed = async (page: Page) => expect((await page.locator("body").innerText()).toLowerCase()).not.toMatch(/compliant|certified/);

test("a computer no check has reported on cannot be told, and the Devices list says so", async () => {
  const page = admin;
  await page.goto("/devices/add");
  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Device group/).selectOption({ label: "Reception" });
  await page.getByLabel(/^Token name/).fill("Security posture");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByRole("radio", { name: "Linux" }).click();
  const command = await page.locator("pre", { hasText: "install.sh" }).innerText();
  const token = /EASYRMM_TOKEN='(ert_[A-Za-z0-9_-]+)'/.exec(command)?.[1] ?? "";
  expect(token).toHaveLength(47);
  const facts = { hostname: "dt-win-posture", os: "Windows Server 2025 Standard", platform: "windows", arch: "amd64", agentVersion: "0.6.0-e2e" };
  const key = deviceKey();
  const enroll = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: key.publicKey, facts } });
  expect(enroll.status(), await enroll.text()).toBe(201);
  agent = new Agent(page.request, ((await enroll.json()) as { deviceId: string }).deviceId, key.privateKey);
  name = ((await (await page.request.get(`/api/v1/devices/${agent.deviceId}`)).json()) as { name: string }).name;

  await page.goto(`/devices?q=${encodeURIComponent(name)}`);
  const row = page.getByRole("row", { name: new RegExp(name) });
  await expect(page.getByRole("columnheader", { name: "Security" })).toBeVisible();
  await expect(row.getByText(/cannot tell/i)).toBeVisible();
  await page.goto(`/devices?q=${encodeURIComponent(name)}&posture=cannot_tell`);
  await expect(page.getByRole("row", { name: new RegExp(name) })).toBeVisible();
  await page.goto(`/devices?q=${encodeURIComponent(name)}&posture=meets`);
  await expect(page.getByText("No devices match these filters")).toBeVisible();
});

test("a check moves it to does not meet, with the reasons on its Hardening tab", async () => {
  const page = admin;
  await page.goto(`/devices/${agent.deviceId}?tab=hardening`);
  await page.getByRole("button", { name: "Run check…" }).first().click();
  const dialog = page.getByRole("dialog", { name: "Check hardening" });
  await dialog.getByRole("button", { name: "Run check" }).click();
  const [job] = await jobsFor(1);
  const modules = job!.args[1]!.split(",");
  expect(await agent.start(job!.runId)).toBe(true);
  await agent.succeeded(
    job!.runId,
    line(
      "check",
      modules.map((m) => (m === "firewall" ? { module: m, state: "not_in_place" } : { module: m, state: "in_place" })),
    ),
  );
  await expect(page.getByText("Does not meet its security policy").first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("listitem").filter({ hasText: "Firewall" }).filter({ hasText: "Does not meet" })).toBeVisible();
  await wordsNeverUsed(page);
});

test("the Devices column and filter, and the Security report with its CSV, read the same posture", async () => {
  const page = admin;
  await page.goto(`/devices?q=${encodeURIComponent(name)}&posture=does_not_meet`);
  const row = page.getByRole("row", { name: new RegExp(name) });
  await expect(row).toBeVisible();
  await expect(row.getByText(/^\d+%$/)).toBeVisible();
  await page.goto(`/devices?q=${encodeURIComponent(name)}&posture=cannot_tell`);
  await expect(page.getByText("No devices match these filters")).toBeVisible();

  await page.goto(`/reports?report=security&q=${encodeURIComponent(name)}`);
  const table = page.getByRole("table", { name: "Security" });
  await expect(table.getByRole("row", { name: new RegExp(name) })).toContainText("Does not meet its security policy");
  await expect(table.getByRole("row", { name: new RegExp(name) })).toContainText("Firewall: does not meet");
  await wordsNeverUsed(page);
  const csv = await page.request.get(`/api/v1/reports/security/csv?q=${encodeURIComponent(name)}`);
  expect(csv.status()).toBe(200);
  const text = await csv.text();
  expect(text).toContain("Security policy");
  expect(text).toContain("Does not meet its security policy");
  expect(text.toLowerCase()).not.toContain("compliant");
});
