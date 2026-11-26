// ADR-0068 slice 1, in the browser, against the server console.spec.ts leaves behind: a Windows computer's Event logs tab.
// A technician-level user (the administrator) opens it, searches, reads an event and asks for the next page; a Read-Only
// user sees no tab; the audit log shows a record for each first page and none holds an event. The device's agent is the
// suite's stand-in (agent.ts): it takes the signed jobs the console starts and answers with the lines the real builtin
// writes (the builtin itself runs on the Windows runners and on a real computer, not here), so what is checked is the
// console, the server's checks of the result against its input, the permissions and the records.

import { expect, test, type Page } from "@playwright/test";
import { Agent, deviceKey, EVENTLOG_ACCEPTS, inputOf, type JobPayload } from "./agent";
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
    const [job] = await agent.poll(EVENTLOG_ACCEPTS);
    if (job) return job;
  }
  throw new Error("no job came for the agent");
}

const begin = (op: string) => ({ t: "begin", v: 1, op, rules: 1, agentVersion: "0.6.0-e2e", arch: "x64", clock: new Date().toISOString() });
const endLine = (extra: Record<string, unknown> = {}) => ({ t: "end", complete: true, returned: 0, read: 0, stoppedBy: "end", ...extra });

const xml = (record: number, id: number, level: number, data: string) =>
  `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Service Control Manager"/><EventID>${id}</EventID><Version>0</Version><Level>${level}</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000</Keywords><TimeCreated SystemTime="2026-11-26T10:0${record % 10}:00.000Z"/><EventRecordID>${record}</EventRecordID><Execution ProcessID="1" ThreadID="2"/><Channel>System</Channel><Computer>dt-win-eventlog</Computer><Security UserID="S-1-5-18"/></System>${data}</Event>`;

/** The builtin's line for an XML. */
const event = (record: number, id: number, level: number, data: { name: string; value: string }[], message: string) => ({
  t: "event",
  log: "System",
  channel: "System",
  record,
  provider: "Service Control Manager",
  id,
  version: 0,
  level,
  task: 0,
  opcode: 0,
  keywords: "0x8080000000000000",
  time: `2026-11-26T10:0${record % 10}:00.000Z`,
  computer: "dt-win-eventlog",
  userSid: "S-1-5-18",
  user: "NT AUTHORITY\\SYSTEM",
  pid: 1,
  tid: 2,
  data,
  message,
  xml: xml(record, id, level, `<EventData>${data.map((d) => `<Data Name="${d.name}">${d.value}</Data>`).join("")}</EventData>`),
});

test("a Windows computer enrolls with an agent that has the event viewer, and its Event logs tab opens", async () => {
  const page = admin;
  await page.goto("/devices/add");
  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Device group/).selectOption({ label: "Reception" });
  await page.getByLabel(/^Token name/).fill("Event log console");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByRole("radio", { name: "Linux" }).click();
  const command = await page.locator("pre", { hasText: "install.sh" }).innerText();
  const token = /EASYRMM_TOKEN='(ert_[A-Za-z0-9_-]+)'/.exec(command)?.[1] ?? "";
  expect(token).toHaveLength(47);
  const facts = { hostname: "dt-win-eventlog", os: "Windows Server 2025 Standard", platform: "windows", arch: "amd64", agentVersion: "0.6.0-e2e" };
  const key = deviceKey();
  const enroll = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: key.publicKey, facts } });
  expect(enroll.status(), await enroll.text()).toBe(201);
  agent = new Agent(page.request, ((await enroll.json()) as { deviceId: string }).deviceId, key.privateKey);
  await agent.poll(EVENTLOG_ACCEPTS);

  await page.goto(`/devices/${agent.deviceId}`);
  await page.getByRole("tab", { name: "Event logs" }).click();
  await expect(page.getByRole("tab", { name: "Event logs" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByRole("group", { name: "Event log header" })).toContainText("On the computer");
  // The tab lists the logs: the agent answers the channel list it was asked for.
  const job = await nextJob();
  expect(job.builtin).toBe("eventlog");
  expect(job.executor).toBe("builtin");
  expect(job.lane).toBe("quick");
  expect(inputOf(job)).toMatchObject({ v: 1, op: "channels", sensitive: false });
  expect(await agent.start(job.runId)).toBe(true);
  await agent.resulted(job.runId, [
    begin("channels"),
    { t: "crash", value: 1, set: true },
    { t: "channel", name: "Application", type: "admin", enabled: true, count: 10, size: 2048 },
    { t: "channel", name: "Security", type: "admin", enabled: true, count: 99 },
    { t: "channel", name: "System", type: "admin", enabled: true, count: 30, size: 4096 },
    { t: "channel", name: "Microsoft-Windows-PowerShell/Operational", type: "operational", enabled: true },
    endLine({ returned: 4 }),
  ]);
  const logs = page.getByRole("group", { name: "Logs to search" });
  await expect(logs.getByRole("checkbox", { name: "System" })).toBeChecked({ timeout: 20_000 });
  // The administrator of the suite holds log.view_sensitive; the Security log is theirs to choose.
  await expect(logs.getByRole("checkbox", { name: "Security" })).toBeEnabled();
});

test("the tab opens into the admin overview by itself: the key events, then the last day's problems, with no click", async () => {
  const page = admin;
  // Nobody pressed anything since the tab opened; the page asks for the key events, then the problems, one after the other.
  const keyJob = await nextJob();
  expect(inputOf(keyJob)).toMatchObject({ op: "query", channels: ["System", "Application", "Security"], time: { last: "24h" }, sensitive: true });
  const keyIds = ((inputOf(keyJob) as unknown as { ids: { from: number }[] }).ids ?? []).map((i) => i.from);
  expect(keyIds).toEqual(expect.arrayContaining([6008, 41, 1074, 7031, 7034, 4625, 4740]));
  expect(await agent.start(keyJob.runId)).toBe(true);
  await agent.resulted(keyJob.runId, [
    begin("query"),
    { t: "pos", channel: "System", state: "ok" },
    { t: "pos", channel: "Application", state: "ok" },
    { t: "pos", channel: "Security", state: "ok" },
    event(21, 7034, 2, [{ name: "param1", value: "Print Spooler" }], "The Print Spooler service terminated unexpectedly."),
    event(20, 7034, 2, [{ name: "param1", value: "Print Spooler" }], "The Print Spooler service terminated unexpectedly."),
    endLine({ returned: 2, read: 40 }),
  ]);
  const problemsJob = await nextJob();
  expect(inputOf(problemsJob)).toMatchObject({ op: "query", channels: ["System", "Application"], levels: [1, 2, 3], time: { last: "24h" } });
  expect(await agent.start(problemsJob.runId)).toBe(true);
  await agent.resulted(problemsJob.runId, [
    begin("query"),
    { t: "pos", channel: "System", state: "ok" },
    { t: "pos", channel: "Application", state: "ok" },
    event(21, 7034, 2, [{ name: "param1", value: "Print Spooler" }], "The Print Spooler service terminated unexpectedly."),
    endLine({ returned: 1, read: 40 }),
  ]);
  await expect(page.getByRole("table", { name: "Service crashes and failures" })).toContainText("×2 since", { timeout: 20_000 });
  await expect(page.getByRole("table", { name: "Problems" }).getByRole("row")).toHaveCount(2);
  for (const name of [/^Search$/, /Read now/, /^Run$/, /Refresh/]) await expect(page.getByRole("button", { name })).toHaveCount(0);
});

/** The next job whose input satisfies the test; a job a newer search replaced is skipped. */
async function jobWhere(pick: (input: Record<string, unknown>) => boolean): Promise<JobPayload> {
  for (let i = 0; i < 10; i++) {
    const job = await nextJob();
    if (pick(inputOf(job) as unknown as Record<string, unknown>)) return job;
  }
  throw new Error("no job with that input came");
}

test("a search is a job: its input is the typed filters, its events are listed newest first, a hidden command line drops its event from a text search", async () => {
  const page = admin;
  await page.getByRole("radio", { name: "All events" }).click();
  await page.getByRole("checkbox", { name: "Application" }).uncheck();
  await page.getByRole("checkbox", { name: "Error" }).check();
  await page.getByLabel("Event IDs").fill("7034, 7031");
  await page.getByLabel("Text").fill("e2e-text-marker");
  // The search runs by itself a moment after the last change.
  const job = await jobWhere((i) => i.text === "e2e-text-marker");
  expect(inputOf(job)).toMatchObject({ op: "query", channels: ["System"], levels: [2], ids: [{ from: 7034 }, { from: 7031 }], text: "e2e-text-marker", sensitive: false });
  expect(await agent.start(job.runId)).toBe(true);
  await agent.resulted(job.runId, [
    begin("query"),
    { t: "pos", channel: "System", state: "ok" },
    event(12, 7034, 2, [{ name: "param1", value: "Print Spooler" }], "The Print Spooler service terminated unexpectedly. e2e-text-marker"),
    // An agent whose rules missed this name: the server hides it before it keeps the result.
    event(11, 7045, 3, [{ name: "ImagePath", value: "c:\\e2e-secret-command-marker.exe --token" }], "A service was installed. c:\\e2e-secret-command-marker.exe"),
    endLine({ returned: 2, read: 2, stoppedBy: "page", cursor: { channels: [{ channel: "System", record: 11 }] } }),
  ]);
  const table = page.getByRole("table", { name: "Events" });
  // The server hid the command line, and on a text query it drops the event it had to hide, since its presence alone would say
  // that the text matched what was hidden: one event and the count of what was dropped.
  await expect(table.getByRole("row")).toHaveCount(2, { timeout: 20_000 });
  await expect(page.getByText(/1 events were dropped from this text search/)).toBeVisible();
  await expect(page.getByText("e2e-secret-command-marker")).toHaveCount(0);
  await table.getByRole("row").nth(1).click();
  await expect(page.getByText("The Print Spooler service terminated unexpectedly. e2e-text-marker")).toBeVisible();
  await page.getByRole("radio", { name: "Details" }).click();
  await expect(page.getByRole("table", { name: "Event data" })).toContainText("Print Spooler");
});

test("the next page names the run, and the server builds the rest", async () => {
  const page = admin;
  await page.getByRole("button", { name: "More" }).click();
  const job = await nextJob();
  const input = inputOf(job);
  expect(input).toMatchObject({ op: "query", channels: ["System"], levels: [2], text: "e2e-text-marker" });
  expect((input as unknown as { cursor: unknown }).cursor).toMatchObject({ channels: [{ channel: "System", record: 11 }] });
  expect(await agent.start(job.runId)).toBe(true);
  await agent.resulted(job.runId, [
    begin("query"),
    { t: "pos", channel: "System", state: "ok" },
    event(10, 7034, 2, [{ name: "param1", value: "Spooler again" }], "e2e-text-marker again"),
    endLine({ returned: 1, read: 5, cursor: { channels: [{ channel: "System", record: 10, done: true }] } }),
  ]);
  await expect(page.getByRole("table", { name: "Events" }).getByRole("row")).toHaveCount(3, { timeout: 20_000 });
  await expect(page.getByRole("button", { name: "More" })).toHaveCount(0);
});

test("a result that breaks a rule is not kept, and the page says so", async () => {
  const page = admin;
  await page.getByRole("checkbox", { name: "Warning" }).check();
  const job = await jobWhere((i) => Array.isArray(i.levels) && i.levels.includes(3));
  expect(await agent.start(job.runId)).toBe(true);
  // A Security event in a result for a query that did not ask for sensitive data.
  const sec = event(5, 4624, 4, [], "An account was logged on.");
  sec.channel = "Security";
  sec.xml = sec.xml.replace("<Channel>System</Channel>", "<Channel>Security</Channel>");
  await agent.resulted(job.runId, [begin("query"), { t: "pos", channel: "System", state: "ok" }, sec, endLine({ returned: 1 })]);
  await expect(page.getByText(/did not finish reading|stopped before|not kept|did not match/i).first()).toBeVisible({ timeout: 20_000 });
  const refused = (await (await page.request.get("/api/v1/audit?action=eventlog.refused_on_device&limit=100")).json()) as { items: { details?: Record<string, unknown> }[] };
  expect(refused.items.length).toBe(1);
});

test("a Read-Only user sees no Event logs tab, and the server refuses them a read", async ({ browser }) => {
  const context = await browser.newContext();
  const reader = await context.newPage();
  await reader.goto(`/devices/${agent.deviceId}`);
  await reader.getByLabel(/^Email/).fill(READER.email);
  await reader.getByLabel(/^Password/).fill(READER.password);
  await reader.getByRole("button", { name: "Sign in" }).click();
  await reader.getByLabel(/^Verification code/).fill(await nextCode(reader, READER.email));
  await reader.getByRole("button", { name: "Verify" }).click();
  await expect(reader.getByRole("tab", { name: "Overview" })).toBeVisible();
  await expect(reader.getByRole("tab", { name: "Event logs" })).toHaveCount(0);
  const { csrfToken } = (await (await reader.request.get("/api/v1/auth/session")).json()) as { csrfToken: string };
  const refused = await reader.request.post(`/api/v1/devices/${agent.deviceId}/eventlog`, {
    headers: { "X-CSRF-Token": csrfToken },
    data: { op: "channels" },
  });
  expect(refused.status()).toBe(422);
  expect(await refused.text()).toContain("You cannot read event logs");
  await context.close();
});

test("the audit log records each first page and holds neither the text nor any event", async () => {
  const page = admin;
  const audit = async (action: string) =>
    ((await (await page.request.get(`/api/v1/audit?action=${action}&limit=100`)).json()) as { items: { details?: Record<string, unknown> }[] }).items;
  const queries = await audit("eventlog.query");
  // The channel list, the overview's two queries, the search and the one that failed its check; the next page is covered by the first.
  const searches = queries.filter((r) => r.details?.operation === "query");
  expect(searches.length).toBeGreaterThanOrEqual(4);
  expect(searches.some((r) => r.details?.sensitive === false && Array.isArray(r.details?.channels) && r.details.channels.length === 1)).toBe(true);
  expect(queries.filter((r) => r.details?.operation === "channels")).toHaveLength(1);
  expect(searches.some((r) => r.details?.textLength === 15)).toBe(true);
  const everything = JSON.stringify(await (await page.request.get("/api/v1/audit?limit=500")).json());
  expect(everything).not.toContain("e2e-text-marker");
  expect(everything).not.toContain("e2e-secret-command-marker");
  expect(everything).not.toContain("Print Spooler");
});
