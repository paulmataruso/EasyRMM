// ADR-0083 slice 1, in the browser, against the server console.spec.ts leaves behind: a domain controller with the Group
// Policy role, an agent of its own that answers the module's jobs with the typed results its scripts print (written here, as
// no Windows runs in this suite), the GPO list read by itself, a rename with its reason and step-up whose automatic
// backup the server keeps, the two-person rule on a link at the domain root, and the read-only settings. What is
// checked is the console and the server; the scripts run on a real controller in the owner's smoke test.

import { createHash } from "node:crypto";
import { gzipSync } from "node:zlib";
import { expect, test, type Page } from "@playwright/test";
import { Agent, deviceKey, type JobPayload } from "./agent";
import { nextCode } from "./authenticator";

const ADMIN = { email: "alex@example.com", password: "harbor lantern quietly 42" };
const ACCEPTS = ["job.pwsh", "job.params"];
const GPO = "8f2c1b3a-5d4e-4a7b-9c1d-2e3f4a5b6c7d";
const DOMAIN_DN = "DC=corp,DC=test";
const ver = (n: number) => ({ directory: n, sysvol: n });
const baseline = {
  id: GPO, name: "Workstation baseline", status: "AllSettingsEnabled", description: "", owner: "CORP\\Domain Admins", created: null, modified: "2026-03-02T14:01:09Z",
  computer: ver(3), user: ver(0), wmiFilter: "", default: false, linkCount: 1, links: [],
};

let admin: Page;
let agent: Agent;
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
  stopped = true;
  await admin.context().close();
});

/** Which action a script is, by what it reports or reads: the tab starts several reads together, so jobs come in any order. */
const kindOf = (script: string) =>
  script.includes("gpoCount") ? "status"
  : script.includes("walked") ? "gpo_list"
  : script.includes("inheritanceBlocked") && script.includes("targets") ? "link_tree"
  : script.includes("reportLinks") || (script.includes("Get-GPPermission") && script.includes("Get-GPOReport") && !script.includes("xmlGzip")) ? "gpo_get"
  : script.includes("xmlGzip") ? "gpo_report"
  : script.includes("GetQueryList") ? "wmi_filters"
  : script.includes("Rename-GPO") ? "gpo_rename"
  : script.includes("New-GPLink") ? "link_add"
  : "other";

const defaultReportXml = `<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings"><Name>Workstation baseline</Name><Computer><Enabled>true</Enabled></Computer><User><Enabled>true</Enabled></User></GPO>`;
const defaultReportGz = gzipSync(Buffer.from(defaultReportXml)).toString("base64");
const results: Record<string, unknown> = {
  status: { domain: "corp.test", domainDn: DOMAIN_DN, controller: "dc1.corp.test", gpoCount: 2, empty: 1, unlinked: 1, targets: 3 },
  gpo_list: { total: 1, offset: 0, next: null, walked: true, items: [baseline] },
  link_tree: { domain: "corp.test", total: 1, offset: 0, next: null, targets: [{ dn: DOMAIN_DN, name: "corp.test", kind: "domain", sensitive: true, inheritanceBlocked: false, links: [] }] },
  gpo_get: { ...baseline, reportLinks: [{ name: "Workstations", path: "corp.test/Computers/Workstations", enabled: true, enforced: false, sensitive: false }], trustees: [
    { name: "Authenticated Users", sid: "S-1-5-11", type: "well_known", permission: "GpoApply", inherited: false, denied: false, apply: true }] },
  wmi_filters: { filters: [] },
  gpo_report: { id: GPO, name: "Workstation baseline", xmlGzip: defaultReportGz },
};

/** The agent answers every module job that arrives, in the background, from `results` unless a test set `override` for its kind
 * (a change that must carry the data its script would print). The reads a change refreshes are answered too: the dialog of
 * a change stays busy until the page has read again. */
const override: Record<string, (job: JobPayload) => unknown> = {};
const seen: { kind: string; job: JobPayload }[] = [];
let stopped = false;
async function answerLoop() {
  while (!stopped) {
    let jobs: JobPayload[] = [];
    try {
      jobs = await agent.poll(ACCEPTS);
    } catch {
      return;
    }
    for (const job of jobs.filter((j) => j.script.includes("EASYRMM-WINMOD-RESULT-V1"))) {
      const kind = kindOf(job.script);
      const data = override[kind] ? override[kind]!(job) : (results[kind] ?? { summary: "done" });
      expect(await agent.start(job.runId)).toBe(true);
      await agent.succeeded(job.runId, "EASYRMM-WINMOD-RESULT-V1 " + JSON.stringify({ ok: true, version: 1, data, error: null }) + "\n");
      seen.push({ kind, job });
    }
  }
}
/** The first job of a kind the agent has answered (waits for it). */
async function answered(kind: string): Promise<JobPayload> {
  await expect.poll(() => seen.some((x) => x.kind === kind), { timeout: 30_000 }).toBe(true);
  return seen.find((x) => x.kind === kind)!.job;
}

async function stepUp(page: Page) {
  const dialog = page.getByRole("dialog", { name: "Confirm it is you" });
  if (await dialog.waitFor({ state: "visible", timeout: 5_000 }).then(() => true, () => false)) {
    await dialog.getByLabel(/Code from your authenticator app/).fill(await nextCode(page, ADMIN.email));
    await dialog.getByRole("button", { name: "Confirm" }).click();
  }
}

test("a domain controller with the Group Policy role shows its GPOs by itself, with no read button", async () => {
  const page = admin;
  await page.goto("/devices/add");
  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Token name/).fill("Group Policy console");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByRole("radio", { name: "Linux" }).click();
  const command = await page.locator("pre", { hasText: "install.sh" }).innerText();
  const token = /EASYRMM_TOKEN='(ert_[A-Za-z0-9_-]+)'/.exec(command)?.[1] ?? "";
  const facts = { hostname: "dt-dc-gpo", os: "Windows Server 2025", platform: "windows", arch: "amd64", agentVersion: "0.6.0-e2e" };
  const key = deviceKey();
  const enroll = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: key.publicKey, facts } });
  expect(enroll.status(), await enroll.text()).toBe(201);
  agent = new Agent(page.request, ((await enroll.json()) as { deviceId: string }).deviceId, key.privateKey);
  await agent.heartbeatWith({ facts: { ...facts, roles: [{ name: "gpmc", state: "present" }] } });
  void answerLoop();

  await page.goto(`/devices/${agent.deviceId}?tab=roles`);
  await expect(page.getByRole("tab", { name: "Roles" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Read now/ })).toHaveCount(0);
  await expect(page.getByRole("row", { name: /Workstation baseline/ })).toBeVisible();
  await expect(page.getByText("Not linked anywhere")).toBeVisible();
});

test("a rename needs a reason and a step-up, runs on the controller, and its automatic backup is kept on the server", async () => {
  const page = admin;
  await page.getByRole("row", { name: /Workstation baseline/ }).getByRole("button", { name: "Details" }).click();
  const detail = page.getByRole("dialog", { name: "Workstation baseline" });
  // The dialog reads the GPO by itself; its actions show once the controller has answered.
  await detail.getByRole("button", { name: "Rename" }).click();
  const dialog = page.getByRole("dialog", { name: /Rename Workstation baseline/ });
  await dialog.getByLabel(/New name/).fill("Workstation baseline 2");
  await expect(dialog.getByRole("button", { name: "Rename" })).toBeDisabled();
  await dialog.getByLabel(/Why/).fill("Align the name with the policy");
  await dialog.getByRole("button", { name: "Rename" }).click();
  await stepUp(page);

  const zip = Buffer.from("PK-e2e-backup-of-the-gpo".repeat(20));
  const backupId = "33333333-3333-3333-3333-333333333333";
  override.gpo_rename = () => ({
    summary: "Renamed the GPO Workstation baseline to Workstation baseline 2.", before: { name: "Workstation baseline" }, after: { name: "Workstation baseline 2" },
    gpoId: GPO, gpoName: "Workstation baseline 2",
    backup: { backupId, domain: "corp.test", gpoId: GPO, gpoName: "Workstation baseline", size: zip.length, sha256: createHash("sha256").update(zip).digest("hex"), computer: ver(3), user: ver(0), zip: zip.toString("base64") },
    versionBefore: { computer: ver(3), user: ver(0) }, versionAfter: { computer: ver(3), user: ver(0) },
  });
  const job = await answered("gpo_rename");
  expect(job.params).toMatchObject({ id: GPO, newName: "Workstation baseline 2", reason: "Align the name with the policy", expectComputerVersion: 3, expectUserVersion: 0 });
  // The dialog closes on success; the Backups list shows the backup the server kept, and its bytes are the controller's.
  await expect(page.getByRole("dialog", { name: /Rename/ })).toHaveCount(0, { timeout: 20_000 });
  await page.keyboard.press("Escape");
  await page.getByRole("radio", { name: "Backups" }).click();
  const row = page.getByRole("row", { name: /Workstation baseline/ });
  await expect(row.getByText("Align the name with the policy")).toBeVisible();
  const list = (await (await page.request.get(`/api/v1/devices/${agent.deviceId}/gpo/backups`)).json()) as { id: string; sha256: string }[];
  expect(list).toHaveLength(1);
  const dl = await page.request.get(`/api/v1/devices/${agent.deviceId}/gpo/backups/${list[0]!.id}/download`);
  expect(Buffer.from(await dl.body()).equals(zip)).toBe(true);
  // The audit log has the change, its reason, the backup and the diff.
  const audit = await (await page.request.get("/api/v1/audit?action=winmod.group_policy.gpo_rename.change")).text();
  expect(audit).toContain("Align the name with the policy");
  expect(audit).toContain("Workstation baseline 2");
});

test("a link at the domain root is held for a second person, and the person who asked cannot approve it", async () => {
  const page = admin;
  await page.getByRole("radio", { name: "GPOs" }).click();
  await page.getByRole("row", { name: /Workstation baseline/ }).getByRole("button", { name: "Details" }).click();
  await page.getByRole("dialog", { name: "Workstation baseline" }).getByRole("button", { name: "Link…" }).click();
  const dialog = page.getByRole("dialog", { name: /Link Workstation baseline/ });
  await dialog.getByLabel(/Link to/).fill(DOMAIN_DN);
  await dialog.getByLabel(/Why/).fill("Baseline for every computer");
  await dialog.getByRole("button", { name: "Link", exact: true }).click();
  await stepUp(page);
  await expect(dialog.getByText("A second person must approve this")).toBeVisible();
  await dialog.getByRole("button", { name: "Ask for approval" }).click();
  await expect(page.getByText(/A second administrator who may edit Group Policy must approve/)).toBeVisible();
  await page.getByRole("button", { name: "Close" }).last().click();
  // No job was made for it; the request is in the Approvals list, and the one who asked is told to wait.
  const requests = (await (await page.request.get(`/api/v1/organizations/${(await (await page.request.get(`/api/v1/devices/${agent.deviceId}`)).json() as { organizationId: string }).organizationId}/gpo/requests`)).json()) as { status: string; sensitivity: string; canDecide: boolean }[];
  expect(requests).toHaveLength(1);
  expect(requests[0]).toMatchObject({ status: "pending", sensitivity: "sensitive_link", canDecide: false });
  await page.keyboard.press("Escape");
  await page.getByRole("radio", { name: "Approvals" }).click();
  await expect(page.getByText("Waiting for another administrator")).toBeVisible();
  await expect(page.getByRole("button", { name: "Review" })).toHaveCount(0);
});

test("every setting of a GPO is shown read-only from its report", async () => {
  const page = admin;
  await page.getByRole("radio", { name: "GPOs" }).click();
  override.gpo_report = () => {
    // What decodeReport reads: the report's XML, gzipped, in base64.
    const xml = `<GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><Name>Workstation baseline 2</Name><Computer><VersionDirectory>3</VersionDirectory><VersionSysvol>3</VersionSysvol><Enabled>true</Enabled><ExtensionData><Extension xmlns:q1="http://www.microsoft.com/GroupPolicy/Settings/Registry" xsi:type="q1:RegistrySettings"><q1:Policy><q1:Name>Turn off Windows Defender Antivirus</q1:Name><q1:State>Disabled</q1:State></q1:Policy></Extension><Name>Registry</Name></ExtensionData></Computer><User><Enabled>true</Enabled></User></GPO>`;
    const gz = gzipSync(Buffer.from(xml)).toString("base64");
    return { id: GPO, name: "Workstation baseline 2", xmlGzip: gz };
  };
  await page.getByRole("row", { name: /Workstation baseline/ }).getByRole("button", { name: "Settings" }).click();
  await expect(page.getByText("Turn off Windows Defender Antivirus")).toBeVisible();
  await expect(page.getByText("Read-only", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /^(Edit|Save)/ })).toHaveCount(0);
});
