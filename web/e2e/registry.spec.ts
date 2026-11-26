// ADR-0067 slice 1, in the browser, against the server console.spec.ts leaves behind: a Windows computer's Registry
// tab. A technician-level user (the administrator) opens it, reads a key, searches and exports it; a Read-Only user sees
// no tab; the audit log shows a record for each. The device's agent is the suite's stand-in (agent.ts): it takes the
// signed jobs the console starts and answers with the lines the real builtin writes (the builtin itself runs on the
// Windows runners and on a real computer, not here), so what is checked is the console, the server's checks of the
// result against its input, the permissions and the records.

import { expect, test, type Page } from "@playwright/test";
import { Agent, deviceKey, inputOf, REGISTRY_ACCEPTS, type JobPayload } from "./agent";
import { nextCode } from "./authenticator";

const ADMIN = { email: "alex@example.com", password: "harbor lantern quietly 42" };
const READER = { name: "Sam Ortiz", email: "sam@example.com", password: "willow harbor gently 58" };

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
  await admin.context().close();
});

/** The next job for the agent, polled until it comes (the poll is held open while there is none). */
async function nextJob(within = 30_000): Promise<JobPayload> {
  const until = Date.now() + within;
  while (Date.now() < until) {
    const [job] = await agent.poll(REGISTRY_ACCEPTS);
    if (job) return job;
  }
  throw new Error("no job came for the agent");
}

const begin = (op: string, path: string[]) => ({ t: "begin", v: 1, op, hive: "HKLM", view: "64", path, rules: 1, agentVersion: "0.6.0-e2e", arch: "x64" });
const end = (extra: Record<string, unknown> = {}) => ({ t: "end", complete: true, elapsedMs: 9, ...extra });

test("a Windows computer enrolls with an agent that has the registry editor, and its Registry tab opens", async () => {
  const page = admin;
  await page.goto("/devices/add");
  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Device group/).selectOption({ label: "Reception" });
  await page.getByLabel(/^Token name/).fill("Registry console");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByRole("radio", { name: "Linux" }).click();
  const command = await page.locator("pre", { hasText: "install.sh" }).innerText();
  const token = /EASYRMM_TOKEN='(ert_[A-Za-z0-9_-]+)'/.exec(command)?.[1] ?? "";
  expect(token).toHaveLength(47);
  const facts = { hostname: "dt-win-registry", os: "Windows Server 2025 Standard", platform: "windows", arch: "amd64", agentVersion: "0.6.0-e2e" };
  const key = deviceKey();
  const enroll = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: key.publicKey, facts } });
  expect(enroll.status(), await enroll.text()).toBe(201);
  agent = new Agent(page.request, ((await enroll.json()) as { deviceId: string }).deviceId, key.privateKey);
  // The agent says what it takes, as its poll does.
  await agent.poll(REGISTRY_ACCEPTS);

  await page.goto(`/devices/${agent.deviceId}`);
  await page.getByRole("tab", { name: "Registry" }).click();
  await expect(page.getByRole("tab", { name: "Registry" })).toHaveAttribute("aria-selected", "true");
  const header = page.getByRole("group", { name: "Registry header" });
  await expect(header).toContainText("64-bit view");
  await expect(page.getByRole("tree", { name: "Registry keys" })).toContainText("HKEY_LOCAL_MACHINE");
});

test("a key is read: its values by type, masked data masked, a refused key marked, and when it was read", async () => {
  const page = admin;
  await page.getByRole("tree", { name: "Registry keys" }).getByText("HKEY_LOCAL_MACHINE").click();
  const job = await nextJob();
  expect(job.executor).toBe("builtin");
  expect(job.builtin).toBe("registry");
  expect(job.lane).toBe("quick");
  expect(job.script).toBe("");
  expect(inputOf(job)).toMatchObject({ v: 1, op: "list", hive: "HKLM", view: "64", path: [] });
  expect(await agent.start(job.runId)).toBe(true);
  await agent.resulted(job.runId, [
    begin("list", []),
    { t: "key", kernel: "\\REGISTRY\\MACHINE", subkeys: 3, values: 3, readAt: new Date().toISOString() },
    { t: "subkey", name: "SAM", subkeys: -1, values: -1, state: "refused", rule: "the local accounts database" },
    { t: "subkey", name: "SOFTWARE", subkeys: 9, values: 0 },
    { t: "value", name: "", type: 1, size: 14, text: "e2e default" },
    { t: "value", name: "Build", type: 4, size: 4, number: 26100 },
    // An agent whose rules missed this name: the server masks it before it keeps the result.
    { t: "value", name: "DbPassword", type: 1, size: 28, text: "e2e-secret-data-marker" },
    end(),
  ]);
  const table = page.getByRole("table");
  await expect(table.getByText("e2e default")).toBeVisible({ timeout: 20_000 });
  await expect(table.getByText("0x000065f4 (26100)")).toBeVisible();
  const secret = table.getByRole("row", { name: /DbPassword/ });
  await expect(secret.getByText("Masked")).toBeVisible();
  await expect(page.getByText("e2e-secret-data-marker")).toHaveCount(0);
  const subkeys = page.getByRole("list", { name: "Subkeys" });
  await expect(subkeys.getByRole("button", { name: /SAM.*Refused by EasyRMM/ })).toBeDisabled();
  await expect(page.getByText(/Read at \d\d:\d\d:\d\d/)).toBeVisible();
});

test("a key under HKLM opens, and a refused path typed in the address bar is refused by the server", async () => {
  const page = admin;
  await page.getByLabel("Address").fill("HKLM\\SECURITY\\SAM");
  await page.getByRole("button", { name: "Go" }).click();
  await expect(page.getByText(/Refused by EasyRMM: LSA secrets and cached logons/)).toBeVisible();
  // No job was made for it: the agent has nothing waiting.
  expect(await agent.poll(REGISTRY_ACCEPTS)).toHaveLength(0);
  await page.getByLabel("Address").fill("Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Vendor");
  await page.getByRole("button", { name: "Go" }).click();
  const job = await nextJob();
  expect(inputOf(job)).toMatchObject({ op: "list", hive: "HKLM", path: ["SOFTWARE", "Vendor"] });
  expect(await agent.start(job.runId)).toBe(true);
  await agent.resulted(job.runId, [
    begin("list", ["SOFTWARE", "Vendor"]),
    { t: "key", kernel: "\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor", subkeys: 0, values: 1, readAt: new Date().toISOString() },
    { t: "value", name: "Name", type: 1, size: 12, text: "vendor-name" },
    end(),
  ]);
  await expect(page.getByRole("table").getByText("vendor-name")).toBeVisible({ timeout: 20_000 });
  await expect(page.getByText(/Physical key/)).toContainText("\\REGISTRY\\MACHINE\\SOFTWARE\\Vendor");
});

test("a search lists its matches and the bound that stopped it, without its term in the audit log", async () => {
  const page = admin;
  await page.getByLabel("Search term").fill("e2e-term-marker");
  await page.getByRole("button", { name: /Search below this key/ }).click();
  const job = await nextJob();
  expect(inputOf(job)).toMatchObject({ op: "search", term: "e2e-term-marker", path: ["SOFTWARE", "Vendor"] });
  expect(await agent.start(job.runId)).toBe(true);
  await agent.resulted(job.runId, [
    begin("search", ["SOFTWARE", "Vendor"]),
    { t: "match", kind: "key", path: ["SOFTWARE", "Vendor", "e2e-term-marker key"] },
    { t: "match", kind: "valueName", path: ["SOFTWARE", "Vendor"], name: "e2e-term-marker-value" },
    end({ complete: false, stoppedBy: "time", firstUnvisited: ["SOFTWARE", "Vendor", "Zeta"], visited: 77, matches: 2 }),
  ]);
  const matches = page.getByRole("list", { name: "Search matches" });
  await expect(matches.getByRole("listitem")).toHaveCount(2, { timeout: 20_000 });
  await expect(page.getByText(/Stopped at the time limit/)).toBeVisible();
  await expect(page.getByText("SOFTWARE\\Vendor\\Zeta")).toBeVisible();
});

test("an export downloads as a .reg file in UTF-16 with what was left out named", async () => {
  const page = admin;
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: /Export \.reg/ }).click();
  const job = await nextJob();
  expect(inputOf(job)).toMatchObject({ op: "export", path: ["SOFTWARE", "Vendor"] });
  expect(await agent.start(job.runId)).toBe(true);
  await agent.resulted(job.runId, [
    begin("export", ["SOFTWARE", "Vendor"]),
    {
      t: "xkey",
      path: ["SOFTWARE", "Vendor"],
      values: [
        { t: "value", name: "Name", type: 1, size: 12, text: "vendor-name" },
        { t: "value", name: "Count", type: 4, size: 4, number: 255 },
        { t: "value", name: "ApiToken", type: 1, size: 20, masked: true },
      ],
    },
    { t: "xkey", path: ["SOFTWARE", "Vendor", "Hidden"], state: "refused", rule: "the EasyRMM agent's own keys" },
    end(),
  ]);
  const file = await (await download).createReadStream();
  const chunks: Buffer[] = [];
  for await (const c of file) chunks.push(c as Buffer);
  const bytes = Buffer.concat(chunks);
  expect(bytes.subarray(0, 2)).toEqual(Buffer.from([0xff, 0xfe]));
  const text = bytes.subarray(2).toString("utf16le");
  expect(text).toContain("Windows Registry Editor Version 5.00\r\n");
  expect(text).toContain("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Vendor]\r\n");
  expect(text).toContain('"Name"="vendor-name"');
  expect(text).toContain('"Count"=dword:000000ff');
  expect(text).toContain("; value left out, masked: ApiToken");
  expect(text).toContain("; key refused by EasyRMM and not exported");
});

test("a Read-Only user sees no Registry tab, and the server refuses them a read", async ({ browser }) => {
  const context = await browser.newContext();
  const reader = await context.newPage();
  await reader.goto(`/devices/${agent.deviceId}`);
  await reader.getByLabel(/^Email/).fill(READER.email);
  await reader.getByLabel(/^Password/).fill(READER.password);
  await reader.getByRole("button", { name: "Sign in" }).click();
  await reader.getByLabel(/^Verification code/).fill(await nextCode(reader, READER.email));
  await reader.getByRole("button", { name: "Verify" }).click();
  await expect(reader.getByRole("tab", { name: "Overview" })).toBeVisible();
  await expect(reader.getByRole("tab", { name: "Registry" })).toHaveCount(0);
  const refused = await reader.request.post(`/api/v1/devices/${agent.deviceId}/registry/query`, { data: { op: "list", hive: "HKLM", path: [] } });
  expect(refused.status()).toBe(422);
  expect(await refused.text()).toContain("You cannot read the registry");
  await context.close();
});

test("the audit log records each read, the export and the refusal, and holds neither the term nor any data", async () => {
  const page = admin;
  const audit = async (action: string) =>
    ((await (await page.request.get(`/api/v1/audit?action=${action}&limit=100`)).json()) as { items: { details?: Record<string, unknown> }[] }).items;
  const reads = await audit("registry.read");
  expect(reads.length).toBeGreaterThanOrEqual(4);
  const searches = reads.filter((r) => r.details?.operation === "search");
  expect(searches).toHaveLength(1);
  expect(searches[0]!.details).toMatchObject({ termLength: 15, hive: "HKLM", path: "SOFTWARE\\Vendor" });
  expect((await audit("registry.export")).length).toBe(1);
  expect((await audit("registry.refused")).length).toBe(1);
  const everything = JSON.stringify(await (await page.request.get("/api/v1/audit?limit=500")).json());
  expect(everything).not.toContain("e2e-term-marker");
  expect(everything).not.toContain("e2e-secret-data-marker");
  expect(everything).not.toContain("vendor-name");
});
