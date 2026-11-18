// Signing in once across EasyRMM and EasyPatch (integration plan P4; ADR-0036), in a real browser against real
// servers: both consoles over TLS on different registrable domains, so EasyRMM's SameSite=Strict cookie never
// crosses between them. scripts/e2e/sign-in-across.sh starts everything and runs this (make e2e-sign-in).
//
// The story: an EasyRMM super administrator connects EasyPatch and sets up sign-in; EasyPatch's own super
// administrator adds EasyRMM as a provider; then the EasyRMM administrator switches to EasyPatch and back without
// signing in again, and EasyPatch renews its one-hour session through EasyRMM by itself.

import { readFileSync } from "node:fs";
import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { totp } from "../e2e/totp";

const env = (name: string): string => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set: run scripts/e2e/sign-in-across.sh`);
  return value;
};
const file = (name: string): string => readFileSync(env(name), "utf8").trim();

const RMM = env("EASYRMM_SIGNIN_RMM_URL");
const EASYPATCH = env("EASYRMM_SIGNIN_EASYPATCH_URL");
const ADMIN = { name: "Alex Rivera", email: "alex@example.com", password: "harbor lantern quietly 42" };
const PATCH_ADMIN = { email: "patch-admin@example.com" };

/** Authenticator state per person: the secret and the last time step the server accepted. */
const authenticators = new Map<string, { secret: string; step: number }>();
const currentStep = () => Math.floor(Date.now() / 30_000);

/** A code the server will accept: never a step it has already seen (replay protection). */
async function nextCode(page: Page, who: string): Promise<string> {
  const a = authenticators.get(who);
  if (!a) throw new Error(`no authenticator for ${who}`);
  let step = Math.max(currentStep(), a.step + 1);
  while (step > currentStep() + 1) {
    await page.waitForTimeout(1_000);
    step = Math.max(currentStep(), a.step + 1);
  }
  a.step = step;
  return totp(a.secret, step - currentStep());
}

/** Reads the authenticator secret printed under the QR code (both consoles print it after "Secret key"). */
async function readSecret(page: Page, who: string) {
  const secret = (await page.getByText("Secret key", { exact: true }).locator("xpath=following-sibling::p[1]").innerText()).replace(/\s+/g, "");
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  authenticators.set(who, { secret, step: currentStep() - 1 });
}

async function saveRecoveryCodes(page: Page) {
  await page.getByLabel("I have saved these recovery codes").check();
  await page.getByRole("button", { name: "Continue" }).click();
}

/**
 * Records, per console, whether a sign-in form was ever on screen: a password field appearing in either console
 * while the person moves between them would be a sign-in page they had to pass.
 */
async function watchForSignInForms(context: BrowserContext) {
  await context.addInitScript(() => {
    const mark = () => {
      if (document.querySelector('input[type="password"][autocomplete="current-password"]')) {
        try {
          localStorage.setItem("e2e.sawSignInForm", location.pathname);
        } catch {
          /* ignore */
        }
      }
    };
    new MutationObserver(mark).observe(document, { childList: true, subtree: true });
  });
}

/** Runs `fn` in a document of `origin` that is not the console (its logo), so the console's own sign-in logic does not run. */
async function inOrigin<T>(origin: string, fn: () => T): Promise<T> {
  const probe = await context.newPage();
  try {
    await probe.goto(`${origin}/logo.svg`);
    return await probe.evaluate(fn);
  } finally {
    await probe.close();
  }
}

const sawSignInForm = (origin: string) => inOrigin(origin, () => localStorage.getItem("e2e.sawSignInForm"));

async function forgetSignInForms() {
  for (const origin of [RMM, EASYPATCH]) await inOrigin(origin, () => localStorage.removeItem("e2e.sawSignInForm"));
}

const startsWith = (url: string) => new RegExp(`^${url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/`);

test.describe.configure({ mode: "serial" });

let context: BrowserContext;
let rmm: Page;
let client = { issuer: "", clientId: "", secret: "" };

test.beforeAll(async ({ browser }) => {
  context = await browser.newContext();
  rmm = await context.newPage();
});
test.afterAll(async () => {
  await context.close();
});

test("EasyRMM: first-run setup, then EasyPatch connected over TLS", async () => {
  await rmm.goto("/");
  await expect(rmm).toHaveURL(/\/setup$/);
  await rmm.getByLabel(/^Setup token/).fill(file("EASYRMM_SIGNIN_SETUP_TOKEN"));
  await rmm.getByLabel(/^First organization/).fill("Northwind Traders");
  await rmm.getByLabel(/^Your name/).fill(ADMIN.name);
  await rmm.getByLabel(/^Email/).fill(ADMIN.email);
  await rmm.getByLabel(/^Password/).fill(ADMIN.password);
  await rmm.getByLabel(/^Confirm password/).fill(ADMIN.password);
  await rmm.getByRole("button", { name: "Create administrator" }).click();
  await expect(rmm).toHaveURL(/\/login$/);
  await rmm.getByLabel(/^Password/).fill(ADMIN.password);
  await rmm.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(rmm).toHaveURL(/\/login\/mfa-setup$/);
  // Over HTTPS on a host name, EasyRMM offers a passkey too; this administrator uses an authenticator app.
  await rmm.getByRole("button", { name: /^Authenticator app/ }).click();
  await readSecret(rmm, ADMIN.email);
  await rmm.getByLabel(/^Verification code/).fill(await nextCode(rmm, ADMIN.email));
  await rmm.getByRole("button", { name: "Turn on two-factor authentication" }).click();
  await saveRecoveryCodes(rmm);
  await expect(rmm.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  await rmm.goto("/settings?tab=easypatch");
  await rmm.getByLabel(/^Address/).fill(EASYPATCH);
  await rmm.getByLabel(/^API token/).fill(file("EASYRMM_SIGNIN_EASYPATCH_TOKEN"));
  await rmm.getByLabel(/^CA certificate/).fill(file("EASYRMM_SIGNIN_CA"));
  await rmm.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(rmm.getByText(/^Connected to EasyPatch /).first()).toBeVisible();
});

test("EasyRMM: sign-in for EasyPatch is set up, and its secret shown once", async () => {
  await rmm.getByRole("button", { name: "Set up sign-in" }).click();
  const dialog = rmm.getByRole("dialog", { name: "Enter these in EasyPatch" });
  await expect(dialog).toBeVisible();
  const value = (term: string) => dialog.locator("dt", { hasText: term }).locator("xpath=following-sibling::dd[1]").locator("code").innerText();
  client = { issuer: await value("Issuer"), clientId: await value("Client ID"), secret: await dialog.locator("pre").innerText() };
  expect(client.issuer).toBe(RMM);
  expect(client.clientId).toMatch(/^easypatch-/);
  expect(client.secret.length).toBeGreaterThan(30);
  await dialog.getByRole("button", { name: "Done" }).click();
});

test("EasyPatch: its super administrator adds EasyRMM as a provider", async () => {
  const ep = await context.newPage();
  await ep.goto(`${EASYPATCH}/login`);
  await ep.getByLabel("Email address").fill(PATCH_ADMIN.email);
  await ep.getByLabel("Password").fill(file("EASYRMM_SIGNIN_EASYPATCH_ADMIN_PASSWORD"));
  await ep.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(ep.getByRole("heading", { name: "Set up two-factor authentication" })).toBeVisible();
  await readSecret(ep, PATCH_ADMIN.email);
  await ep.getByLabel("Verification code").fill(await nextCode(ep, PATCH_ADMIN.email));
  await ep.getByRole("button", { name: "Enable two-factor authentication" }).click();
  await saveRecoveryCodes(ep);
  // EasyPatch offers a passkey once it has loaded the signed-in user, which can be after the page has loaded: checking once
  // can miss it, and the offer then covers the next click until the test times out. Decline it whenever it shows.
  await ep.addLocatorHandler(ep.getByRole("dialog", { name: "Sign in faster with a passkey" }), async (offer) => {
    await offer.getByRole("button", { name: "Not now" }).click();
  });
  await ep.goto(`${EASYPATCH}/settings?tab=sso`);

  await ep.getByRole("button", { name: "Add provider" }).click();
  const dialog = ep.getByRole("dialog");
  await dialog.getByLabel(/^Name on the sign-in button/).fill("EasyRMM");
  await dialog.getByLabel(/^Client ID/).fill(client.clientId);
  await dialog.getByLabel(/^Issuer/).fill(client.issuer);
  await dialog.getByLabel(/^Client secret/).fill(client.secret);
  await dialog.getByLabel("This provider is EasyRMM").check();
  // What does not apply to EasyRMM is not offered.
  await expect(dialog.getByLabel("Trust the provider's email claim")).toHaveCount(0);
  await dialog.getByRole("button", { name: "Add provider" }).click();
  await expect(dialog).toBeHidden();
  await expect(ep.getByRole("row", { name: /EasyRMM/ }).first()).toBeVisible();

  await ep.getByRole("button", { name: "Sign out" }).click();
  await expect(ep.getByRole("link", { name: "Sign in with EasyRMM" })).toBeVisible();
  await ep.close();
});

test("EasyRMM → EasyPatch: one click, no sign-in page, a new account managed by EasyRMM", async () => {
  await watchForSignInForms(context);
  await forgetSignInForms();
  await rmm.goto("/");
  await rmm.getByRole("navigation", { name: "Products" }).getByRole("link", { name: "Open EasyPatch" }).click();

  await expect(rmm).toHaveURL(startsWith(EASYPATCH));
  const products = rmm.getByRole("navigation", { name: "Products" });
  await expect(products.getByRole("link", { name: "Open EasyRMM" })).toBeVisible();
  await expect(rmm.getByRole("navigation", { name: "Main" })).toContainText(/super ?admin/i);
  expect(new URL(rmm.url()).searchParams.get("from")).toBeNull();
  expect(await sawSignInForm(EASYPATCH)).toBeNull();
  expect(await sawSignInForm(RMM)).toBeNull();

  await rmm.goto(`${EASYPATCH}/account`);
  await expect(rmm.getByText(/You sign in through EasyRMM at rmm\.easyrmm\.localhost/)).toBeVisible();
});

test("EasyPatch → EasyRMM: the switch opens EasyRMM's page for what is on screen, still signed in", async () => {
  await forgetSignInForms();
  await rmm.goto(`${EASYPATCH}/endpoints`);
  await rmm.getByRole("navigation", { name: "Products" }).getByRole("link", { name: "Open EasyRMM" }).click();
  await expect(rmm).toHaveURL(`${RMM}/patching`);
  await expect(rmm.getByRole("heading", { name: "Patching" })).toBeVisible();
  expect(await sawSignInForm(RMM)).toBeNull();
});

test("EasyPatch renews an ended session through EasyRMM by itself", async () => {
  await forgetSignInForms();
  await rmm.goto(`${EASYPATCH}/jobs?status=failed`);
  await expect(rmm.getByRole("navigation", { name: "Products" })).toBeVisible();
  // The session ends (it lasts at most an hour): its cookie is gone.
  await context.clearCookies({ name: "__Host-easypatch-session" });
  await rmm.reload();
  await expect(rmm).toHaveURL(`${EASYPATCH}/jobs?status=failed`);
  await expect(rmm.getByRole("navigation", { name: "Products" })).toBeVisible();
  expect(await sawSignInForm(EASYPATCH)).toBeNull();
});

test("signing out of EasyPatch stops the renewal: the sign-in page asks", async () => {
  await rmm.goto(`${EASYPATCH}/`);
  await forgetSignInForms();
  await rmm.getByRole("button", { name: "Sign out" }).click();
  await expect(rmm.getByRole("link", { name: "Sign in with EasyRMM" })).toBeVisible();
  await rmm.reload();
  await expect(rmm.getByRole("link", { name: "Sign in with EasyRMM" })).toBeVisible();
  await expect(rmm).toHaveURL(new RegExp(`${startsWith(EASYPATCH).source}login`));
  // The watcher behind "no sign-in page" above does see one when it is there.
  expect(await sawSignInForm(EASYPATCH)).toBe("/login");
});
