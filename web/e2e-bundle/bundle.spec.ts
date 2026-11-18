// The bundle test (one-product plan, B8): EasyRMM with its patching engine, as
// deploy/docker-compose.yml runs it, addressed by IP, and a real Linux machine. The first account
// is made on the first-run page; the machine runs the install command the console shows; EasyRMM
// installs the EasyPatch agent, which enrolls through EasyRMM's address and links; a scan finds
// the update a local package repository offers, and installing it changes the package on the
// machine. scripts/e2e/bundle.sh starts everything and runs this.

import { execFileSync } from "node:child_process";
import { expect, test, type Page } from "@playwright/test";
import { enrollAuthenticator } from "../e2e/authenticator";

const host = process.env.EASYRMM_BUNDLE_HOST ?? "";
const hostname = process.env.EASYRMM_BUNDLE_HOSTNAME ?? "";
const setupToken = process.env.EASYRMM_BUNDLE_SETUP_TOKEN ?? "";
const ADMIN = { name: "Morgan Patel", email: "morgan@example.com", password: "orchard signal calmly 58" };
const ORG = "Fabrikam Logistics";
const SITE = "Main warehouse";
const PACKAGE = "easyrmm-e2e-demo";

test.describe.configure({ mode: "serial" });

let admin: Page;
let deviceId = "";

test.beforeAll(async ({ browser }) => {
  expect(host, "EASYRMM_BUNDLE_HOST").not.toBe("");
  expect(hostname, "EASYRMM_BUNDLE_HOSTNAME").not.toBe("");
  expect(setupToken, "EASYRMM_BUNDLE_SETUP_TOKEN").not.toBe("");
  admin = await (await browser.newContext()).newPage();
});
test.afterAll(async () => {
  await admin.context().close();
});

/** Runs a shell script as root on the Linux machine and returns its output. */
function onHost(script: string): string {
  return execFileSync("docker", ["exec", host, "sh", "-c", script], { encoding: "utf8", timeout: 300_000 });
}

/**
 * Calls EasyRMM's API from the administrator's page, as the console does: the browser's own fetch,
 * with the session's cookie and CSRF token, over the connection Chromium trusts by the server's key.
 */
async function api<T>(method: "GET" | "POST", path: string, data?: unknown): Promise<T> {
  const r = await admin.evaluate(
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

type PatchDevice = { link: string; reason?: string; install?: { state: string; error?: string; note?: string } };
type Update = { updateGuid: string; title: string; state: string };
type Job = { type: string; status: string; failedCount: number; errorMessage: string };

test("the first account is made on the first-run page, with a second factor", async () => {
  const page = admin;
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await page.getByLabel(/^Setup token/).fill(setupToken);
  await page.getByLabel(/^First organization/).fill(ORG);
  await page.getByLabel(/^Your name/).fill(ADMIN.name);
  await page.getByLabel(/^Email/).fill(ADMIN.email);
  await page.getByLabel(/^Password/).fill(ADMIN.password);
  await page.getByLabel(/^Confirm password/).fill(ADMIN.password);
  await page.getByRole("button", { name: "Create administrator" }).click();

  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel(/^Password/).fill(ADMIN.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/login\/mfa-setup$/);
  await enrollAuthenticator(page, ADMIN.email);
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();

  // The organization gets a site, where the machine will go.
  await page.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Organizations" }).click();
  await page.getByRole("link", { name: ORG }).click();
  await page.getByRole("button", { name: "Add site" }).click();
  const site = page.getByRole("dialog", { name: "New site" });
  await site.getByLabel(/^Name/).fill(SITE);
  await site.getByRole("button", { name: "Create site" }).click();
  await expect(page.getByRole("heading", { name: SITE })).toBeVisible();
});

test("the machine runs the console's install command and reports in", async () => {
  const page = admin;
  await page.goto("/devices");
  await page.getByRole("link", { name: "Add devices" }).first().click();
  await expect(page.getByRole("heading", { name: "Add devices" })).toBeVisible();
  await page.getByLabel(/^Site/).selectOption({ label: SITE });
  await page.getByLabel(/^Token name/).fill("Bundle test");
  await page.getByLabel("Device limit").fill("1");
  await page.getByRole("button", { name: "Create token" }).click();
  await page.getByRole("radio", { name: "Linux" }).click();
  const command = await page.locator("pre", { hasText: "install.sh" }).innerText();
  // An address with EasyRMM's own authority: every download is checked against its key.
  expect(command).toContain("--pinnedpubkey 'sha256//");

  // As an administrator pastes it into a root shell on the machine.
  const out = onHost(command);
  expect(out).toContain("Enrolled with https://");
  expect(out).toContain("The agent is running as easyrmm-agent.service.");

  await expect
    .poll(
      async () => {
        const list = await api<{ items: { id: string; hostname: string }[] }>("GET", `/api/v1/devices?q=${encodeURIComponent(hostname)}`);
        deviceId = list.items.find((d) => d.hostname === hostname)?.id ?? "";
        return deviceId;
      },
      { message: "the machine appears in EasyRMM", timeout: 120_000, intervals: [2_000] },
    )
    .not.toBe("");
  await page.goto(`/devices/${deviceId}`);
  await expect(page.getByRole("heading", { name: hostname })).toBeVisible();
});

test("EasyRMM installs the EasyPatch agent, which enrolls through EasyRMM's address and links", async () => {
  // A device that has just enrolled is refused until its first inventory arrives, which says
  // whether it has an EasyPatch agent already; a refusal changes nothing, so ask again.
  let refusal = "";
  await expect
    .poll(
      async () => {
        const r = await api<{ succeeded: number; results: { message?: string }[] }>("POST", "/api/v1/patching/agent-install", { deviceIds: [deviceId] });
        refusal = r.results[0]?.message ?? "";
        return r.succeeded;
      },
      { message: "EasyRMM accepts the install", timeout: 300_000, intervals: [10_000] },
    )
    .toBe(1)
    .catch((e: Error) => {
      throw new Error(`${e.message}\nLast refusal: ${refusal}`);
    });

  let last: PatchDevice | undefined;
  await expect
    .poll(
      async () => {
        last = await api<PatchDevice>("GET", `/api/v1/patching/devices/${deviceId}`);
        if (last.install?.state === "failed") throw new Error(`the install failed: ${JSON.stringify(last.install)}`);
        return last.link;
      },
      { message: "the EasyPatch agent links", timeout: 420_000, intervals: [5_000] },
    )
    .toBe("linked")
    .catch((e: Error) => {
      throw new Error(`${e.message}\nLast state: ${JSON.stringify(last)}`);
    });

  // The agent trusts EasyRMM's authority for EasyRMM's address only (ADR-0042): it was given it at
  // enrollment, and the machine's own certificate store was left alone.
  expect(onHost("systemctl is-active easypatch-agent").trim()).toBe("active");
  expect(onHost("grep -c '^ServerCaCertificate=' /etc/easypatch/agent.conf").trim()).toBe("1");
  expect(onHost("ls /usr/local/share/ca-certificates | wc -l").trim()).toBe("0");
});

test("a scan finds the repository's update, and installing it updates the machine", async () => {
  expect(onHost(`dpkg-query -W -f='\${Version}' ${PACKAGE}`)).toBe("1.0.0");
  await api("POST", "/api/v1/patching/scan", { deviceIds: [deviceId] });

  let update: Update | undefined;
  await expect
    .poll(
      async () => {
        const list = await api<{ items: Update[] }>("GET", `/api/v1/patching/devices/${deviceId}/updates`);
        update = list.items.find((u) => u.title.includes(PACKAGE));
        return update?.state ?? "";
      },
      { message: `the scan reports ${PACKAGE} 1.1.0`, timeout: 300_000, intervals: [5_000] },
    )
    .toBe("Missing");

  const install = await api<{ succeeded: number; failed: number }>("POST", "/api/v1/patching/install", {
    deviceIds: [deviceId],
    updateIds: [update!.updateGuid],
  });
  expect(install).toMatchObject({ succeeded: 1, failed: 0 });

  await expect
    .poll(() => onHost(`dpkg-query -W -f='\${Version}' ${PACKAGE}`), { message: `${PACKAGE} is updated on the machine`, timeout: 300_000, intervals: [5_000] })
    .toBe("1.1.0");
  // EasyPatch's job states end in Completed, Failed, Cancelled or Expired; a completed job can still
  // report failed updates (the console's rule, patchText.tsx).
  await expect
    .poll(
      async () => {
        const jobs = await api<{ items: Job[] }>("GET", `/api/v1/patching/devices/${deviceId}/jobs`);
        const job = jobs.items.find((j) => j.type === "InstallUpdates");
        if (job && (["Failed", "Cancelled", "Expired"].includes(job.status) || job.failedCount > 0)) {
          throw new Error(`the install job did not succeed: ${JSON.stringify(job)}`);
        }
        return job?.status ?? "";
      },
      { message: "EasyPatch records the install as completed", timeout: 180_000, intervals: [5_000] },
    )
    .toBe("Completed");
});
