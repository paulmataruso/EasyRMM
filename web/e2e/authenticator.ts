// A person's authenticator app in the browser stories (e2e/, e2e-bundle/): it reads the secret
// under the QR code at enrollment, then gives codes the server accepts.

import { expect, type Page } from "@playwright/test";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { totp } from "./totp";

/** Authenticator state per person: the secret and the last time step the server accepted. */
const authenticators = new Map<string, { secret: string; step: number }>();

// Playwright starts a fresh worker (and so a fresh copy of this module) after a failed test. The state
// is mirrored to a file so one failing spec cannot take the sign-in of every later spec with it.
const stateFile = join(dirname(fileURLToPath(import.meta.url)), ".run", "authenticators.json");

function save() {
  try {
    mkdirSync(dirname(stateFile), { recursive: true });
    writeFileSync(stateFile, JSON.stringify(Object.fromEntries(authenticators)));
  } catch {
    // best effort: the in-memory copy still serves this worker
  }
}

function lookup(email: string) {
  try {
    const saved = JSON.parse(readFileSync(stateFile, "utf8")) as Record<string, { secret: string; step: number }>;
    for (const [k, v] of Object.entries(saved)) if (!authenticators.has(k) || v.step > authenticators.get(k)!.step) authenticators.set(k, v);
  } catch {
    // no file yet
  }
  return authenticators.get(email);
}

const currentStep = () => Math.floor(Date.now() / 30_000);

/** Remembers an authenticator set up elsewhere (another identity provider's enrollment, or a test's own key). */
export function addAuthenticator(email: string, secret: string) {
  authenticators.set(email, { secret, step: currentStep() - 1 });
  save();
}

/** A code the server will accept: never a step it has already seen (replay protection). */
export async function nextCode(page: Page, email: string): Promise<string> {
  const a = lookup(email);
  if (!a) throw new Error(`no authenticator for ${email}`);
  let step = Math.max(currentStep(), a.step + 1);
  // The server accepts at most one step ahead of now; wait for the clock otherwise.
  while (step > currentStep() + 1) {
    await page.waitForTimeout(1_000);
    step = Math.max(currentStep(), a.step + 1);
  }
  a.step = step;
  save();
  return totp(a.secret, step - currentStep());
}

/** Scans the "QR code" by reading the secret key printed under it, and confirms a code. */
export async function enrollAuthenticator(page: Page, email: string) {
  const secret = (await page.getByText("Secret key", { exact: true }).locator("xpath=following-sibling::p[1]").innerText()).replace(/\s+/g, "");
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  await expect(page.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  authenticators.set(email, { secret, step: currentStep() - 1 });
  save();
  await page.getByLabel(/^Verification code/).fill(await nextCode(page, email));
  await page.getByRole("button", { name: "Turn on two-factor authentication" }).click();

  // Recovery codes are shown once; leaving needs an explicit acknowledgement.
  await expect(page.getByText("I have saved these recovery codes")).toBeVisible();
  const codes = await page.locator("ul li.select-all").allInnerTexts();
  expect(codes).toHaveLength(10);
  const done = page.getByRole("button", { name: "Continue" });
  await expect(done).toBeDisabled();
  await page.getByLabel("I have saved these recovery codes").check();
  await done.click();
}
