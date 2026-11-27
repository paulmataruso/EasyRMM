// ADR-0058 slice 1, in the browser, against the server console.spec.ts leaves behind: an operator sets a site's
// heartbeat interval through the API, the agent (a stand-in that signs its requests as the real one does, agent.ts) is
// answered with it, the device's settings say where it comes from, and an Offline policy's page lists the device as
// waiting longer. The real agent following the interval, rc.4's included, is the bundle's check, not this suite's.

import { expect, test, type Page } from "@playwright/test";
import { Agent, deviceKey } from "./agent";
import { nextCode } from "./authenticator";

const ADMIN = { email: "alex@example.com", password: "harbor lantern quietly 42" };
const FACTS = { hostname: "dt-lin-interval", os: "Ubuntu 24.04 LTS", platform: "linux", arch: "amd64", agentVersion: "0.6.0-e2e" };
const KEY = "agent.heartbeat_seconds";

let admin: Page;
let agent: Agent;
let name = "";
let siteId = "";
let csrf = "";
let policyId = "";
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
  csrf = ((await (await admin.request.get("/api/v1/auth/session")).json()) as { csrfToken: string }).csrfToken;
});
test.afterAll(async () => {
  // Leave the shared server as found: the site's interval and the policy are gone.
  if (siteId) await admin.request.delete(`/api/v1/sites/${siteId}/agent-settings/${KEY}`, { headers: { "X-CSRF-Token": csrf } });
  if (policyId) await admin.request.delete(`/api/v1/alert-policies/${policyId}`, { headers: { "X-CSRF-Token": csrf } });
  await admin.context().close();
});

test("an agent is answered with 60 seconds until an interval is set", async () => {
  const page = admin;
  await page.goto("/devices/add");
  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Device group/).selectOption({ label: "Reception" });
  await page.getByLabel(/^Token name/).fill("Heartbeat interval");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByRole("radio", { name: "Linux" }).click();
  const command = await page.locator("pre", { hasText: "install.sh" }).innerText();
  const token = /EASYRMM_TOKEN='(ert_[A-Za-z0-9_-]+)'/.exec(command)?.[1] ?? "";
  const key = deviceKey();
  const enroll = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: key.publicKey, facts: FACTS } });
  expect(enroll.status(), await enroll.text()).toBe(201);
  agent = new Agent(page.request, ((await enroll.json()) as { deviceId: string }).deviceId, key.privateKey);
  const device = (await (await page.request.get(`/api/v1/devices/${agent.deviceId}`)).json()) as { name: string; siteId: string };
  name = device.name;
  siteId = device.siteId;
  expect((await agent.heartbeatWith({ facts: FACTS })).heartbeatSeconds).toBe(60);
});

test("a site's interval reaches the agent, and the device says where it comes from", async () => {
  const page = admin;
  const set = await page.request.put(`/api/v1/sites/${siteId}/agent-settings/${KEY}`, { data: { value: 300, enforced: false }, headers: { "X-CSRF-Token": csrf } });
  expect(set.status(), await set.text()).toBe(200);
  expect((await agent.heartbeatWith({ facts: FACTS })).heartbeatSeconds).toBe(300);

  const settings = (await (await page.request.get(`/api/v1/devices/${agent.deviceId}/agent-settings`)).json()) as {
    device: { heartbeatSeconds: number };
    items: { key: string; effective: { value: number }; inherited: { from: { scope: string; name: string } } }[];
  };
  expect(settings.device.heartbeatSeconds).toBe(300);
  expect(settings.items[0]).toMatchObject({ key: KEY, effective: { value: 300 }, inherited: { from: { scope: "site", name: "Downtown clinic" } } });

  // Below the platform's minimum is refused, with the reason; and a value outside the key's range too.
  const refused = await page.request.put(`/api/v1/sites/${siteId}/agent-settings/${KEY}`, { data: { value: 10 }, headers: { "X-CSRF-Token": csrf } });
  expect(refused.status()).toBe(400);
  expect(((await refused.json()) as { error: { code: string } }).error.code).toBe("setting_invalid");
});

test("an Offline policy's page lists the device that waits longer, loading by itself", async () => {
  const page = admin;
  const made = await page.request.post("/api/v1/alert-policies", {
    data: { name: "Interval offline", kind: "offline", threshold: null, minutes: 10, severity: "warning", enabled: true },
    headers: { "X-CSRF-Token": csrf },
  });
  expect(made.status(), await made.text()).toBe(201);
  policyId = ((await made.json()) as { id: string }).id;

  await page.goto("/settings?tab=alert-policies");
  await page.getByRole("button", { name: "Edit Interval offline" }).click();
  const dialog = page.getByRole("dialog", { name: "Edit Interval offline" });
  const section = dialog.getByRole("region", { name: "Devices that wait longer" });
  await expect(section).toContainText(/waits? longer than 10 minutes/);
  await expect(section.getByRole("link", { name })).toBeVisible();
  await expect(section).toContainText("checks in every 5 minutes, waits 15 minutes");
  await expect(dialog.getByRole("button", { name: /refresh|read now/i })).toHaveCount(0);
});
