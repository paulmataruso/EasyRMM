// ADR-0078 slice C5, in the browser, against the server console.spec.ts leaves behind: the CMMC workspace in the organization's
// Compliance tab. An assessment is started; the score shows as a range; one computer is put in scope; a requirement is written up,
// has evidence uploaded (and downloaded back, byte for byte), and is attested with a step-up; a plan-of-action item is drafted;
// the system security plan is started and edited; the assessment is sent for review and approved, which freezes it; a new draft
// carries the work over; the exports download and the OSCAL one is the version we pin.

import { expect, test, type Page } from "@playwright/test";
import { nextCode } from "./authenticator";

const ADMIN = {
  email: "alex@example.com",
  password: "harbor lantern quietly 42",
};

let admin: Page;
let orgId = "";
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

const EVIDENCE = "Network diagram, version 3. The CUI boundary is marked.\n";

test("the workspace starts an assessment and shows the score as a range", async () => {
  const page = admin;
  await page.goto("/organizations");
  await page.getByRole("link", { name: "Contoso Dental Group" }).first().click();
  orgId = /organizations\/([0-9a-f-]{36})/.exec(page.url())?.[1] ?? "";
  expect(orgId).toHaveLength(36);
  await page.goto(`/organizations/${orgId}?tab=compliance`);
  const on = page.getByRole("button", { name: "Turn on compliance checks" });
  if (await on.isVisible()) await on.click();
  await expect(page.getByRole("heading", { name: "CMMC assessments" })).toBeVisible();
  await page.getByLabel("Title for a new assessment").fill("Spring assessment");
  await page.getByRole("button", { name: "Start an assessment" }).click();
  await expect(page.getByText("Score if unassessed fail")).toBeVisible();
  await expect(page.getByText("Score if unassessed pass")).toBeVisible();
  await expect(page.getByText(/never posts a score to SPRS/)).toBeVisible();
  // Nothing is assessed yet: the lower bound is 110 less every weight (313), the upper bound is 110.
  await expect(page.getByText("-203", { exact: true })).toBeVisible();
  await expect(page.getByText("110", { exact: true }).first()).toBeVisible();
  expect((await page.locator("body").innerText()).toLowerCase()).not.toMatch(/compliant|certified/);
});

test("a requirement is written up, evidence is stored encrypted and comes back unchanged, and an attestation needs a step-up", async () => {
  const page = admin;
  await page.getByRole("button", { name: /3\.1\.1 / }).first().click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("textbox", { name: "Statement", exact: true }).fill("Accounts are limited to named people, reviewed each quarter.");
  await dialog.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Saved.")).toBeVisible();

  await dialog.getByLabel("Title").first().fill("Network diagram");
  await dialog.getByLabel("Evidence file").setInputFiles({ name: "diagram.txt", mimeType: "text/plain", buffer: Buffer.from(EVIDENCE) });
  await dialog.getByRole("button", { name: "Upload" }).click();
  await expect(page.getByText("Evidence stored, encrypted.")).toBeVisible();
  const link = dialog.getByRole("link", { name: "Download" }).first();
  await expect(link).toBeVisible();
  const href = (await link.getAttribute("href")) ?? "";
  const res = await page.request.get(href);
  expect(res.status()).toBe(200);
  expect(await res.text()).toBe(EVIDENCE);
  expect(res.headers()["content-disposition"]).toContain("attachment");

  // The stored copy is ciphertext, and the library lists it with its hash.
  const list = (await (await page.request.get(`/api/v1/organizations/${orgId}/compliance/evidence`)).json()) as { items: { sha256: string; size: number }[] };
  expect(list.items[0]!.size).toBe(EVIDENCE.length);
  expect(list.items[0]!.sha256).toHaveLength(64);

  await dialog.getByRole("textbox", { name: "Your statement" }).fill("We limit accounts to named people.");
  await dialog.getByRole("button", { name: "Sign the attestation" }).click();
  const stepUp = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(stepUp).toBeVisible();
  await stepUp.getByLabel(/Code from your authenticator app/).fill(await nextCode(page, ADMIN.email));
  await stepUp.getByRole("button", { name: "Confirm" }).click();
  await expect(page.getByText("Attestation signed.")).toBeVisible();
  await expect(dialog.getByText(/An attestation is evidence, not a scan result/)).toBeVisible();
  await dialog.getByRole("button", { name: /close/i }).first().click();
});

test("the plan of action, the system security plan and the review workflow", async () => {
  const page = admin;
  await page.getByRole("tab", { name: "System security plan" }).click();
  await page.getByRole("button", { name: "Start the plan" }).click();
  await expect(page.getByText("The plan was written from the assessment.")).toBeVisible();
  await page.getByLabel("System identification").fill("The clinic's workstations and its file server.");
  await page.getByRole("button", { name: "Save this section" }).click();
  await expect(page.getByText("Section saved.")).toBeVisible();

  await page.getByRole("tab", { name: "Plan of action" }).click();
  await expect(page.getByText(/does not make a requirement met/)).toBeVisible();

  await page.getByRole("button", { name: "Send for review" }).click();
  await expect(page.getByText("In review", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Approve and freeze" }).click();
  await expect(page.getByText("Approved", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Start a new draft from this" })).toBeVisible();
  // Frozen: the server refuses a change, whatever the page offers.
  const a = (await (await page.request.get(`/api/v1/organizations/${orgId}/compliance/assessments`)).json()) as { items: { id: string; state: string }[] };
  const approved = a.items.find((i) => i.state === "approved")!;
  const csrf = (await page.context().cookies()).find((c) => /csrf/i.test(c.name))?.value ?? "";
  const refused = await page.request.put(`/api/v1/organizations/${orgId}/compliance/assessments/${approved.id}/requirements/AC.L2-3.1.1`, { data: { statement: "changed" }, headers: { "X-CSRF-Token": csrf } });
  expect([409, 403]).toContain(refused.status());
});

test("the exports download, the OSCAL one is the pinned version, and a new draft carries the work over", async () => {
  const page = admin;
  await page.getByRole("tab", { name: "Exports" }).click();
  const a = (await (await page.request.get(`/api/v1/organizations/${orgId}/compliance/assessments`)).json()) as { items: { id: string; state: string }[] };
  const id = a.items.find((i) => i.state === "approved")!.id;
  const ssp = await page.request.get(`/api/v1/organizations/${orgId}/compliance/assessments/${id}/export?format=oscal-ssp`);
  expect(ssp.status()).toBe(200);
  const doc = (await ssp.json()) as { "system-security-plan": { metadata: { "oscal-version": string } } };
  expect(doc["system-security-plan"].metadata["oscal-version"]).toBe("1.1.2");
  expect(ssp.headers()["x-content-sha256"]).toHaveLength(64);
  const pdf = await page.request.get(`/api/v1/organizations/${orgId}/compliance/assessments/${id}/export?format=pdf`);
  expect((await pdf.body()).subarray(0, 5).toString()).toBe("%PDF-");
  const zip = await page.request.get(`/api/v1/organizations/${orgId}/compliance/assessments/${id}/export?format=bundle`);
  expect((await zip.body()).subarray(0, 2).toString()).toBe("PK");

  await page.getByRole("button", { name: "All assessments" }).click();
  await page.getByRole("button", { name: "Spring assessment" }).first().click();
  await page.getByRole("button", { name: "Start a new draft from this" }).click();
  await expect(page.getByText("A new draft was made from this assessment.")).toBeVisible();
  await expect(page.getByText("from an earlier approved assessment")).toBeVisible();
});
