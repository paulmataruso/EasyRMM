// The Authentik test (ADR-0044), run by scripts/e2e/authentik.sh against a
// deployment set up with setup.sh --with-authentik and the patching engine:
//
//   1. the fresh install has no first-run page, only sign-in with Authentik;
//   2. the administrator opens setup.sh's invitation, makes the account with an authenticator app,
//      and lands on the dashboard as super administrator;
//   3. makes an organization, and patching works: the engine answers, and takes an alert rule
//      for the organization;
//   4. the invitation no longer works, and setup.sh --new-invitation issues another that does;
//   5. a second Authentik user without an EasyRMM account is refused;
//   6. signing in again asks for the second factor;
//   7. with Authentik stopped, easyrmm-server recover prints a link that signs in, once;
//   8. EASYRMM_PUBLIC_URL and EASYRMM_AUTHENTIK_CLIENT_SECRET changed in .env and docker compose
//      up -d: authentik-setup applies the blueprint again, Authentik sends people to the new URL
//      and takes the new secret, and signing in there works;
//   9. docker compose up -d with .env unchanged: authentik-setup applies nothing.
//
// Commands in the deployment (docker compose, setup.sh, the change to .env) go through
// EASYRMM_AUTHENTIK_CTL, which the script writes. Links, passwords and keys are made for the run
// and never printed.

import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { expect, test, type Browser, type Locator, type Page, type Response } from "@playwright/test";
import { addAuthenticator, nextCode } from "../e2e/authenticator";

const invitation = process.env.EASYRMM_AUTHENTIK_INVITATION ?? "";
const signInHost = process.env.EASYRMM_AUTHENTIK_SIGNIN_HOST ?? "";
const adminEmail = process.env.EASYRMM_AUTHENTIK_ADMIN_EMAIL ?? "";
const ctlPath = process.env.EASYRMM_AUTHENTIK_CTL ?? "";
// EASYRMM_PUBLIC_URL as installed, and where test 8 moves it to.
const installed = process.env.EASYRMM_AUTHENTIK_URL ?? "";
const moved = process.env.EASYRMM_AUTHENTIK_MOVED_URL ?? "";
// When authentik-setup last applied EasyRMM's blueprint, as test 8 left it.
let appliedInTest8 = "";
const ADMIN = { name: "Morgan Patel", password: "orchard signal calmly 58" };
// Someone at Authentik, in the administrator's domain, whom nobody invited to EasyRMM.
const OTHER = { name: "Riley Chen", email: "riley@easyrmm.test", password: randomBytes(18).toString("base64url") };
const ORG = "Fabrikam Logistics";
const RULE = "Fabrikam agents offline";
const ENROLLMENT_LINK = /https:\/\/\S+\/if\/flow\/easyrmm-enrollment\/\?itoken=[0-9a-f-]+/;

test.describe.configure({ mode: "serial" });

let admin: Page;
let organizationId = "";

test.beforeAll(async ({ browser }) => {
  expect(invitation, "EASYRMM_AUTHENTIK_INVITATION").toMatch(ENROLLMENT_LINK);
  expect(signInHost, "EASYRMM_AUTHENTIK_SIGNIN_HOST").not.toBe("");
  expect(adminEmail, "EASYRMM_AUTHENTIK_ADMIN_EMAIL").not.toBe("");
  expect(ctlPath, "EASYRMM_AUTHENTIK_CTL").not.toBe("");
  expect(installed, "EASYRMM_AUTHENTIK_URL").toMatch(/^https:\/\/[a-z0-9.-]+$/);
  expect(moved, "EASYRMM_AUTHENTIK_MOVED_URL").toMatch(/^https:\/\/[a-z0-9.-]+$/);
  admin = await (await browser.newContext()).newPage();
});
test.afterAll(async () => {
  await admin.context().close();
});

/** Runs docker compose or setup.sh in the deployment and returns the output. */
function ctl(...args: string[]): string {
  return execFileSync(ctlPath, args, { encoding: "utf8", timeout: 600_000, stdio: ["ignore", "pipe", "pipe"] });
}

/** A page in a browser of its own: no EasyRMM session, no Authentik session. */
async function stranger(browser: Browser): Promise<Page> {
  return (await browser.newContext()).newPage();
}

/** Calls EasyRMM's API from a signed-in page, as the console does. */
async function api<T>(page: Page, method: "GET" | "POST", path: string, data?: unknown): Promise<T> {
  const r = await page.evaluate(
    async ({ method, path, data }) => {
      const headers: Record<string, string> = { Accept: "application/json" };
      if (method !== "GET") {
        const session = await fetch("/api/v1/auth/session", { credentials: "same-origin" });
        headers["X-CSRF-Token"] = ((await session.json()) as { csrfToken: string }).csrfToken;
        headers["Content-Type"] = "application/json";
      }
      const res = await fetch(path, { method, headers, credentials: "same-origin", body: data === undefined ? undefined : JSON.stringify(data) });
      return { ok: res.ok, status: res.status, text: await res.text() };
    },
    { method, path, data },
  );
  expect(r.ok, `${method} ${path}: ${r.status} ${r.text}`).toBe(true);
  return JSON.parse(r.text) as T;
}

type Session = { state: string; isSuperAdmin: boolean; user: { email: string } };

/** The page is in EasyRMM, signed in as the administrator, with the second factor done. */
async function signedInAsAdministrator(page: Page) {
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  const session = await api<Session>(page, "GET", "/api/v1/auth/session");
  expect(session).toMatchObject({ state: "active", isSuperAdmin: true, user: { email: adminEmail } });
}

type Stage = "prompt" | "choose" | "totp" | "identify" | "password" | "code" | "failed";

/** Authentik's stages: the element each is found by, and the form it is in. */
const STAGES: { stage: Stage; form: string; find: (form: Locator) => Locator }[] = [
  { stage: "prompt", form: "ak-stage-prompt", find: (f) => f.locator("input[name='name']") },
  { stage: "choose", form: "ak-stage-authenticator-validate", find: (f) => f.getByRole("button", { name: /TOTP/ }) },
  { stage: "totp", form: "ak-stage-authenticator-totp", find: (f) => f.locator("input[name='code']") },
  { stage: "identify", form: "ak-stage-identification", find: (f) => f.locator("input[name='uidField']") },
  { stage: "password", form: "ak-stage-password", find: (f) => f.locator("input[name='password']") },
  { stage: "code", form: "ak-stage-authenticator-validate", find: (f) => f.locator("input[name='code']") },
  // A request of Authentik's page failed. Chromium drops requests when the host's network interfaces
  // change, as containers come and go on a shared machine; reloading goes on with the same flow.
  { stage: "failed", form: "body", find: (f) => f.getByText("The request failed", { exact: false }) },
];

/**
 * Goes through Authentik's flow on the page a stage at a time, as a person would, until the browser
 * is back at EasyRMM. Returns the stages it went through.
 */
async function throughAuthentik(page: Page, person: { name?: string; email: string; password: string }): Promise<Stage[]> {
  const seen: Stage[] = [];
  // The authenticator app's secret, which Authentik shows under the QR code.
  let secret = "";
  const onResponse = async (r: Response) => {
    if (!r.url().includes("/api/v3/flows/executor/") || r.status() !== 200) return;
    const body = (await r.json().catch(() => ({}))) as { config_url?: string };
    if (body.config_url) secret = new URL(body.config_url).searchParams.get("secret") ?? "";
  };
  page.on("response", onResponse);
  try {
    let atAuthentik = false;
    for (let step = 0; step < 20; step++) {
      let found: (typeof STAGES)[number] | undefined;
      let back = false;
      const deadline = Date.now() + 90_000;
      while (!found && !back && Date.now() < deadline) {
        const url = new URL(page.url());
        atAuthentik ||= url.host === signInHost;
        back = atAuthentik && url.host !== signInHost && !url.pathname.startsWith("/api/");
        for (const s of STAGES) {
          if (!back && !found && (await s.find(page.locator(s.form).first()).isVisible().catch(() => false))) found = s;
        }
        if (!found && !back) await page.waitForTimeout(500);
      }
      if (back) return seen;
      if (!found) throw new Error(`no stage of Authentik's on ${page.url()} after: ${seen.join(", ")}`);
      seen.push(found.stage);
      const form = page.locator(found.form).first();
      const field = found.find(form);
      const next = form.getByRole("button", { name: found.stage === "identify" ? "Log in" : "Continue" });
      switch (found.stage) {
        case "failed":
          await page.reload();
          continue;
        case "prompt":
          // The email is the invitation's, not the person's to choose.
          await expect(form.locator("input[name='email']")).toHaveValue(person.email);
          await field.fill(person.name ?? "");
          await form.locator("input[name='password']").fill(person.password);
          await form.locator("input[name='password_repeat']").fill(person.password);
          await next.click();
          break;
        case "choose":
          await field.click();
          break;
        case "totp":
          await expect.poll(() => secret, { message: "the authenticator's secret" }).toMatch(/^[A-Z2-7]{16,}$/);
          addAuthenticator(person.email, secret);
          await field.fill(await nextCode(page, person.email));
          await next.click();
          break;
        case "identify":
          await field.fill(person.email);
          await next.click();
          break;
        case "password":
          await field.fill(person.password);
          await next.click();
          break;
        case "code":
          await field.fill(await nextCode(page, person.email));
          await next.click();
          break;
      }
      // On to the next stage, or the same one again with an error.
      await field.waitFor({ state: "detached", timeout: 90_000 }).catch(() => undefined);
    }
    throw new Error(`Authentik's flow did not end: ${seen.join(", ")}`);
  } finally {
    page.off("response", onResponse);
  }
}

type Held = { redirectUris: string[]; enrollmentRedirect: string; launchUrl: string; clientSecretMatchesEnv: boolean; lastApplied: string };

/**
 * What Authentik holds of .env for EasyRMM, read with Authentik's own models: where it sends people,
 * whether the client secret is the worker's (from .env; the secret itself is not printed), and when
 * EasyRMM's blueprint was last applied.
 */
function heldByAuthentik(): Held {
  const python = [
    "import hmac, json, os",
    "from authentik.blueprints.models import BlueprintInstance",
    "from authentik.core.models import Application",
    "from authentik.providers.oauth2.models import OAuth2Provider",
    "from authentik.stages.redirect.models import RedirectStage",
    "provider = OAuth2Provider.objects.get(name='EasyRMM')",
    "held = {",
    "    'redirectUris': [u.url for u in provider.redirect_uris],",
    "    'enrollmentRedirect': RedirectStage.objects.get(name='easyrmm-enrollment-redirect').target_static,",
    "    'launchUrl': Application.objects.get(slug='easyrmm').meta_launch_url,",
    "    'clientSecretMatchesEnv': hmac.compare_digest(provider.client_secret.encode(), os.environ['EASYRMM_AUTHENTIK_CLIENT_SECRET'].encode()),",
    "    'lastApplied': BlueprintInstance.objects.get(name='EasyRMM - Sign-in').last_applied.isoformat(),",
    "}",
    'print("easyrmm-e2e: " + json.dumps(held))',
  ].join("\n");
  const out = ctl("compose", "exec", "-T", "authentik-worker", "/bin/sh", "/easyrmm/bin/start.sh", "shell", "-c", python);
  const line = out.split("\n").find((l) => l.startsWith("easyrmm-e2e: "));
  expect(line, "Authentik's objects were read").toBeDefined();
  return JSON.parse((line ?? "").slice("easyrmm-e2e: ".length)) as Held;
}

/** authentik-setup's state and exit code, such as "exited 0". */
function setupState(): string {
  return ctl("compose", "ps", "-a", "--format", "{{.State}} {{.ExitCode}}", "authentik-setup").trim();
}

/** Runs docker compose up -d, waits until authentik-setup has run, and returns what it printed. */
async function upAndSetup(): Promise<string> {
  const since = new Date(Date.now() - 1_000).toISOString();
  ctl("compose", "up", "-d", "--no-build", "--quiet-pull");
  // authentik-setup runs again, with .env as it is, once Authentik's worker is healthy.
  await expect.poll(setupState, { message: "authentik-setup finishes", timeout: 600_000, intervals: [5_000] }).toMatch(/^exited /);
  const printed = ctl("compose", "logs", "--no-log-prefix", "--since", since, "authentik-setup")
    .split("\n")
    .filter((line) => line.startsWith("authentik-setup: "))
    .join("\n");
  expect(setupState(), printed).toBe("exited 0");
  return printed;
}

function base32(bytes: Buffer): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = [...bytes].map((b) => b.toString(2).padStart(8, "0")).join("");
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += alphabet.charAt(parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2));
  return out;
}

test("1. the fresh install has no first-run page, only sign-in with Authentik", async () => {
  const page = admin;
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("link", { name: "Sign in with Authentik" })).toBeVisible();
  const buttons = await api<{ providers: { name: string }[] }>(page, "GET", "/api/v1/auth/sso");
  expect(buttons.providers.map((p) => p.name)).toEqual(["Authentik"]);
});

test("2. the invitation makes the administrator's account, with a second factor, and lands on the dashboard", async () => {
  const page = admin;
  await page.goto(invitation);
  const stages = await throughAuthentik(page, { name: ADMIN.name, email: adminEmail, password: ADMIN.password });
  // A name and a password, then a second factor is required: the authenticator app.
  expect(stages.filter((s) => s !== "failed")).toEqual(["prompt", "choose", "totp"]);

  // Then on to EasyRMM, which signs the administrator in through Authentik without asking again.
  await signedInAsAdministrator(page);
  expect(new URL(page.url()).host).toBe(new URL(test.info().project.use.baseURL ?? "").host);
});

test("3. an organization is made, and patching works for it", async () => {
  const page = admin;
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Organizations" }).click();
  await page.getByRole("button", { name: "New organization" }).click();
  const dialog = page.getByRole("dialog", { name: "New organization" });
  await dialog.getByLabel(/^Name/).fill(ORG);
  await dialog.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByRole("heading", { name: ORG })).toBeVisible();
  organizationId = new URL(page.url()).pathname.split("/").pop() ?? "";
  expect(organizationId).toMatch(/^[0-9a-f-]{36}$/);

  // The engine in this deployment answers: the fleet is read from it, and is empty.
  const status = await api<{ configured: boolean }>(page, "GET", "/api/v1/patching");
  expect(status).toMatchObject({ configured: true });
  const fleet = await api<{ devices: unknown[]; errors?: string[] }>(page, "GET", `/api/v1/patching/devices?organizationId=${organizationId}`);
  expect(fleet.devices).toEqual([]);
  expect(fleet.errors ?? []).toEqual([]);
  await page.goto("/patching");
  await expect(page.getByRole("main").getByText("No devices to patch yet")).toBeVisible();

  // And keeps what it is given: an alert rule for the organization.
  await page.goto("/settings?tab=patching&view=rules");
  await page.getByRole("main").getByRole("button", { name: "Add rule" }).click();
  const rule = page.getByRole("dialog", { name: "Add alert rule" });
  await rule.getByRole("textbox", { name: /Name/ }).fill(RULE);
  await rule.getByRole("combobox", { name: "Organization" }).selectOption({ label: ORG });
  await rule.getByRole("button", { name: "Add rule" }).click();
  await expect(page.getByText(`${RULE} added.`)).toBeVisible();
  const rules = await api<{ items: { name: string; organizationId: string | null }[] }>(page, "GET", "/api/v1/patching/alert-rules");
  expect(rules.items).toContainEqual(expect.objectContaining({ name: RULE, organizationId }));
});

test("4. the invitation no longer works; setup.sh --new-invitation issues another", async ({ browser }) => {
  const page = await stranger(browser);
  await page.goto(invitation);
  await expect(page.getByText("Invalid invite/invite not found")).toBeVisible();
  await expect(page.locator("ak-stage-prompt")).toHaveCount(0);

  const issued = ctl("setup", "--new-invitation");
  const another = ENROLLMENT_LINK.exec(issued)?.[0] ?? "";
  expect(another, "setup.sh --new-invitation prints a link").not.toBe("");
  expect(another).not.toBe(invitation);
  // It works after the next docker compose up -d, which runs authentik-setup again.
  ctl("compose", "up", "-d", "--no-build", "--quiet-pull");
  const email = page.locator("ak-stage-prompt input[name='email']");
  await expect
    .poll(
      async () => {
        // Refused until authentik-setup has made it: then the sign-up opens, for the administrator.
        await page.goto(another);
        await email
          .or(page.getByText("Invalid invite/invite not found"))
          .first()
          .waitFor({ timeout: 60_000 })
          .catch(() => undefined);
        return email.inputValue({ timeout: 1_000 }).catch(() => "");
      },
      { message: "the new invitation opens the sign-up for the administrator", timeout: 300_000, intervals: [5_000] },
    )
    .toBe(adminEmail);
  await page.context().close();
});

test("5. an Authentik user without an EasyRMM account is refused", async ({ browser }) => {
  const key = randomBytes(20);
  addAuthenticator(OTHER.email, base32(key));
  const python = [
    "from authentik.core.models import User",
    "from authentik.stages.authenticator_totp.models import TOTPDevice",
    `u, _ = User.objects.update_or_create(username=${JSON.stringify(OTHER.email)}, defaults={"email": ${JSON.stringify(OTHER.email)}, "name": ${JSON.stringify(OTHER.name)}})`,
    `u.set_password(${JSON.stringify(OTHER.password)})`,
    "u.save()",
    "TOTPDevice.objects.filter(user=u).delete()",
    `TOTPDevice.objects.create(user=u, name="Authenticator", key=${JSON.stringify(key.toString("hex"))}, confirmed=True)`,
    'print("easyrmm-e2e: user ready")',
  ].join("\n");
  expect(ctl("compose", "exec", "-T", "authentik-worker", "/bin/sh", "/easyrmm/bin/start.sh", "shell", "-c", python)).toContain("easyrmm-e2e: user ready");

  const page = await stranger(browser);
  await page.goto("/login");
  await page.getByRole("link", { name: "Sign in with Authentik" }).click();
  expect(await throughAuthentik(page, OTHER)).toContain("code");
  await expect(page).toHaveURL(/\/login\?sso_error=no_account$/);
  await expect(page.getByText("There is no EasyRMM account for the email address your identity provider gave.")).toBeVisible();
  await page.context().close();

  // Nobody was added.
  const users = await api<{ items: { email: string }[] }>(admin, "GET", "/api/v1/users");
  expect(users.items.map((u) => u.email)).toEqual([adminEmail]);
});

test("6. signing in again asks for the second factor", async ({ browser }) => {
  const page = await stranger(browser);
  await page.goto("/login");
  await page.getByRole("link", { name: "Sign in with Authentik" }).click();
  // No Authentik session in this browser: email, password, and the second factor again.
  const stages = await throughAuthentik(page, { email: adminEmail, password: ADMIN.password });
  expect(stages.filter((s) => s !== "failed")).toEqual(["identify", "password", "code"]);
  await signedInAsAdministrator(page);
  await page.context().close();
});

test("7. with Authentik stopped, easyrmm-server recover signs in, once", async ({ browser }) => {
  ctl("compose", "stop", "authentik-server", "authentik-worker");
  const page = await stranger(browser);
  const down = await page.goto(`https://${signInHost}/`);
  expect(down?.status()).toBe(502);
  await expect(page.getByText("Sign-in is not answering. Try again in a minute.")).toBeVisible();

  const printed = ctl("compose", "exec", "-T", "server", "easyrmm-server", "recover");
  const link = /https:\/\/\S+\/recover#token=\S+/.exec(printed)?.[0] ?? "";
  expect(link, "the recover command prints a link").not.toBe("");
  await page.goto(link);
  await expect(page.getByRole("heading", { name: "Recovery sign-in" })).toBeVisible();
  await page.getByRole("button", { name: "Sign in" }).click();
  await signedInAsAdministrator(page);
  await page.context().close();

  const again = await stranger(browser);
  await again.goto(link);
  await again.getByRole("button", { name: "Sign in" }).click();
  await expect(again.getByText("This link has expired or was already used.", { exact: false })).toBeVisible();
  await again.context().close();
});

test("8. after EASYRMM_PUBLIC_URL changes in .env, docker compose up -d moves Authentik to it, and signing in works there", async ({ browser }) => {
  test.setTimeout(900_000);
  // What docs/deployment/docker.md says to do (Authentik is still stopped from test 7). The client
  // secret, the blueprint's other value from .env, changes too: EasyRMM and Authentik take it from
  // there, so signing in below works only if Authentik took the new one.
  const started = Date.now();
  ctl("public-url");
  ctl("client-secret");
  const printed = await upAndSetup();
  const { lastApplied, ...held } = heldByAuthentik();
  expect(held).toEqual({
    redirectUris: [`${moved}/api/v1/auth/sso/callback`],
    // sso.DeploymentProviderID's sign-in.
    enrollmentRedirect: `${moved}/api/v1/auth/sso/b2927669-72ce-48a1-a83d-8215013be7ab/start`,
    launchUrl: moved,
    clientSecretMatchesEnv: true,
  });
  // authentik-setup saw both changes, and applied the blueprint for them.
  expect(printed).toContain("the provider's client secret is not EASYRMM_AUTHENTIK_CLIENT_SECRET");
  expect(printed).toContain(`the application's launch URL is '${installed}', not '${moved}'`);
  expect(printed).toContain(`applied: EasyRMM's provider, enrollment flow and application are at ${moved}`);
  expect(Date.parse(lastApplied)).toBeGreaterThan(started);
  appliedInTest8 = lastApplied;

  // EasyRMM started again with the new URL too: sign in there through Authentik.
  const page = await stranger(browser);
  const button = page.getByRole("link", { name: "Sign in with Authentik" });
  await expect
    .poll(
      async () => {
        await page.goto(`${moved}/login`).catch(() => undefined);
        return button
          .waitFor({ timeout: 10_000 })
          .then(() => true)
          .catch(() => false);
      },
      { message: "EasyRMM's sign-in page at the new URL", timeout: 180_000, intervals: [3_000] },
    )
    .toBe(true);
  await button.click();
  const stages = await throughAuthentik(page, { email: adminEmail, password: ADMIN.password });
  expect(stages.filter((s) => s !== "failed")).toEqual(["identify", "password", "code"]);
  await signedInAsAdministrator(page);
  expect(new URL(page.url()).origin).toBe(moved);
  await page.context().close();
});

test("9. docker compose up -d with .env unchanged applies nothing", async () => {
  test.setTimeout(900_000);
  expect(appliedInTest8, "test 8 applied the blueprint").not.toBe("");
  const printed = await upAndSetup();
  expect(printed).toContain("authentik-setup: Authentik matches .env; nothing applied");
  expect(printed).not.toContain("applying the blueprint");
  expect(heldByAuthentik().lastApplied).toBe(appliedInTest8);
});
