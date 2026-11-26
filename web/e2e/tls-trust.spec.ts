// ADR-0055, slice 5b1: what a device's agent trusts, and Reinstall through a remote session, in the browser. The console and the
// server are the real ones, with a stand-in agent that signs its requests as the real one does (agent.ts). This server runs
// in offload mode, where a proxy owns the certificates and EasyRMM serves none, so it never has a chain to ask about: the
// suite checks that, and the page's answer for a device that was cut off is supplied by the test (the chains and the
// agent's verification are covered by the Go tests and the agent's own tests). What is checked for real is what the console
// does with that answer: the card, the fix, and the one-use deployment token the reinstall command is made with.

import { expect, test, type Page } from "@playwright/test";
import { Agent, deviceKey } from "./agent";
import { nextCode } from "./authenticator";

const ADMIN = { email: "alex@example.com", password: "harbor lantern quietly 42" };

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

const FACTS = { hostname: "dt-lin-trust", os: "Ubuntu 24.04 LTS", platform: "linux", arch: "amd64", agentVersion: "0.6.0-e2e" };

test("an agent that announces the capability to a server with no certificate of its own is asked nothing", async () => {
  const page = admin;
  await page.goto("/devices/add");
  await page.getByLabel(/^Site/).selectOption({ label: "Downtown clinic" });
  await page.getByLabel(/^Device group/).selectOption({ label: "Reception" });
  await page.getByLabel(/^Token name/).fill("Agent trust");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByRole("radio", { name: "Linux" }).click();
  const command = await page.locator("pre", { hasText: "install.sh" }).innerText();
  const token = /EASYRMM_TOKEN='(ert_[A-Za-z0-9_-]+)'/.exec(command)?.[1] ?? "";
  const key = deviceKey();
  const enroll = await page.request.post("/api/agent/v1/enroll", { data: { token, publicKey: key.publicKey, facts: FACTS } });
  expect(enroll.status(), await enroll.text()).toBe(201);
  agent = new Agent(page.request, ((await enroll.json()) as { deviceId: string }).deviceId, key.privateKey);
  name = ((await (await page.request.get(`/api/v1/devices/${agent.deviceId}`)).json()) as { name: string }).name;

  const answer = await agent.heartbeatWith({ facts: FACTS, caps: ["tls.trust.v1"] });
  expect(answer.trust).toBeUndefined();
  // The console's answer for the device: nothing asked, so no card.
  const view = await (await page.request.get(`/api/v1/devices/${agent.deviceId}/tls-trust`)).json();
  expect(view).toMatchObject({ capable: true, checks: [], unprotected: false });
  await page.goto(`/devices/${agent.deviceId}`);
  await expect(page.getByRole("heading", { name })).toBeVisible();
  await expect(page.getByText("Certificate trust")).toHaveCount(0);
});

test("a device that cannot verify the certificate is offered a reinstall, and its token is one use", async () => {
  const page = admin;
  const view = {
    capable: true,
    origin: "rmm.example.com",
    trusts: "system",
    widened: false,
    checks: [{ scope: "agent", host: "rmm.example.com", purpose: "served", state: "failed", error: "x509: certificate signed by unknown authority", requestedAt: new Date().toISOString(), checkedAt: new Date().toISOString() }],
    unprotected: false,
    reinstall: { reason: "The agent reported that it cannot verify the server's certificate, and it is not connected now.", fix: "Update the computer's root certificates, or reinstall with --ca-file." },
    canTerminal: false,
    platform: "linux",
    siteId: "",
  };
  // The real site of the real device, so that the real server creates the token.
  const device = (await (await page.request.get(`/api/v1/devices/${agent.deviceId}`)).json()) as { siteId: string };
  view.siteId = device.siteId;
  await page.route(`**/api/v1/devices/${agent.deviceId}/tls-trust`, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(view) }));
  await page.goto(`/devices/${agent.deviceId}`);
  await expect(page.getByText("Certificate trust")).toBeVisible();
  await expect(page.getByText("Cannot verify: x509: certificate signed by unknown authority")).toBeVisible();
  const section = page.getByRole("region", { name: "Reinstall through a remote session" });
  await expect(section).toContainText("Update the computer's root certificates, or reinstall with --ca-file.");
  await section.getByRole("button", { name: "Create install command" }).click();
  await expect(section.locator("pre", { hasText: "EASYRMM_TOKEN" })).toBeVisible();
  const tokens = (await (await page.request.get("/api/v1/enrollment-tokens")).json()) as { items: { name: string; maxUses: number | null; status: string }[] };
  const made = tokens.items.find((t) => t.name === `Reinstall ${name}`);
  expect(made).toMatchObject({ maxUses: 1, status: "active" });
});
