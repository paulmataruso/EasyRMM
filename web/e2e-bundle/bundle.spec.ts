// The bundle test (one-product plan, B8): EasyRMM with its patching engine, as
// deploy/docker-compose.yml runs it, addressed by IP, and a real Linux machine. The first account
// is made on the first-run page; the machine runs the install command the console shows; EasyRMM
// installs the EasyPatch agent, which enrolls through EasyRMM's address and links; a scan finds
// the update a local package repository offers. On the device's Patches tab (C1) the update is
// excluded and included again and the policy shows; Patching lists the update across devices, and
// its page holds it and releases the hold (C2); installing it from the Patches tab, after the
// preview, changes the package on the machine. A value set on the organization (C4) reaches the site
// and the device, as do a tag's policy and the device's own. scripts/e2e/bundle.sh starts everything
// and runs this.

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
type Preview = { items: { updateGuid: string }[]; skipped: { updateGuid: string; reason: string }[] };
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

let update: Update | undefined;

/** The update's state in EasyPatch, as EasyRMM's API reports it. */
async function updateState(): Promise<string> {
  const list = await api<{ items: Update[] }>("GET", `/api/v1/patching/devices/${deviceId}/updates`);
  update = list.items.find((u) => u.title.includes(PACKAGE));
  return update?.state ?? "";
}

test("a scan finds the repository's update", async () => {
  expect(onHost(`dpkg-query -W -f='\${Version}' ${PACKAGE}`)).toBe("1.0.0");
  await api("POST", "/api/v1/patching/scan", { deviceIds: [deviceId] });
  await expect.poll(updateState, { message: `the scan reports ${PACKAGE} 1.1.0`, timeout: 300_000, intervals: [5_000] }).toBe("Missing");
});

test("the Patches tab excludes the update, includes it again and shows the policy", async () => {
  const page = admin;
  const title = update!.title;
  await page.goto(`/devices/${deviceId}?tab=patches`);
  const main = page.getByRole("main");
  await main.getByRole("button", { name: `Exclude ${title}…` }).click();
  const exclude = page.getByRole("dialog", { name: /^Exclude this update on / });
  await exclude.getByLabel("Reason (optional)").fill("Bundle test");
  await exclude.getByRole("button", { name: "Exclude update" }).click();
  await expect(exclude).toBeHidden();
  await expect.poll(updateState, { message: "EasyPatch records the exclusion" }).toBe("Excluded");
  // An install would leave it out, and say why.
  const preview = await api<Preview>("GET", `/api/v1/patching/devices/${deviceId}/install-preview?updateId=${update!.updateGuid}`);
  expect(preview.items).toEqual([]);
  expect(preview.skipped).toEqual([expect.objectContaining({ updateGuid: update!.updateGuid, reason: "Excluded" })]);

  await main.getByRole("button", { name: `Include ${title}` }).click();
  await expect(page.getByText(/^Included again on /)).toBeVisible();
  await expect.poll(updateState, { message: "EasyPatch includes it again" }).toBe("Missing");

  await main.getByRole("radio", { name: "Policy" }).click();
  await expect(main.getByRole("heading", { name: "Installing" })).toBeVisible();
  await expect(main.getByText("Automatic installs")).toBeVisible();
  // The engine in EasyRMM's deployment has no console of its own, so nothing links to one.
  await expect(main.getByRole("link", { name: /EasyPatch/ })).toHaveCount(0);
});

test("Patching lists the update across devices; its page holds it and releases the hold", async () => {
  const page = admin;
  const title = update!.title;
  await page.goto("/patching");
  const main = page.getByRole("main");
  await expect(main.getByRole("tab", { name: "Overview", selected: true })).toBeVisible();
  await expect(main.getByRole("heading", { name: "Needs attention" })).toBeVisible();

  await main.getByRole("tab", { name: "Updates" }).click();
  await main.getByRole("link", { name: title }).click();
  await expect(main.getByRole("heading", { name: title, level: 1 })).toBeVisible();
  await expect(main.locator(`a[href="/devices/${deviceId}?tab=patches"]`)).toBeVisible();

  await main.getByRole("button", { name: "Hold…" }).click();
  const hold = page.getByRole("dialog", { name: "Hold this update?" });
  await hold.getByLabel("Hold it in").selectOption({ label: ORG });
  await hold.getByLabel(/Why/).fill("Bundle test");
  await hold.getByRole("button", { name: "Hold update" }).click();
  await expect(hold).toBeHidden();
  await expect(main.getByText(`On hold in ${ORG}`)).toBeVisible();
  const held = await api<{ summary: { onHold: boolean }; holds: { reason: string }[] }>("GET", `/api/v1/patching/updates/${update!.updateGuid}`);
  expect(held.summary.onHold).toBe(true);
  expect(held.holds).toEqual([expect.objectContaining({ reason: "Bundle test" })]);

  await main.getByRole("button", { name: "Release hold" }).click();
  const release = page.getByRole("dialog", { name: `Release the hold in ${ORG}?` });
  await release.getByRole("button", { name: "Release hold" }).click();
  await expect(release).toBeHidden();
  await expect(main.getByText(`On hold in ${ORG}`)).toBeHidden();
});

test("installing the update from the Patches tab, after its preview, updates the machine", async () => {
  const page = admin;
  const title = update!.title;
  await page.goto(`/devices/${deviceId}?tab=patches`);
  const main = page.getByRole("main");
  await main.getByLabel(`Select ${title}`).check();
  await main.getByRole("button", { name: "Install selected…" }).click();
  const dialog = page.getByRole("dialog", { name: /^Install 1 update on / });
  await expect(dialog.getByText("The agent scans again before installing.", { exact: false })).toBeVisible();
  await expect(dialog.getByRole("listitem").filter({ hasText: title })).toBeVisible();
  await dialog.getByRole("button", { name: "Install now" }).click();
  await expect(dialog).toBeHidden();

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

test("Patching's Jobs tab finds the install by type and status; a restart is planned on the machine but not sent", async () => {
  const page = admin;
  await page.goto("/patching?tab=jobs");
  const main = page.getByRole("main");
  await main.getByRole("radio", { name: "All recent" }).click();
  await main.getByLabel("Type").selectOption({ label: "Install updates" });
  await main.getByLabel("Status").selectOption({ label: "Completed" });
  await main.getByLabel("Requested").selectOption({ label: "Last 24 hours" });
  await main.getByRole("button", { name: "Install updates" }).first().click();
  const job = page.getByRole("dialog", { name: /^Install updates on / });
  await expect(job.getByText("Sent to the device")).toBeVisible();
  await expect(job.getByText("1 of 1 update installed")).toBeVisible();
  await job.getByRole("button", { name: "Close" }).last().click();
  await main.getByLabel("Type").selectOption({ label: "Restart" });
  await expect(main.getByText("No jobs match")).toBeVisible();

  // The engine is asked whether the machine can restart and whether it is a server; nothing is sent.
  await page.goto(`/devices/${deviceId}?tab=patches`);
  await page.getByRole("main").getByRole("button", { name: "Restart…" }).click();
  const restart = page.getByRole("dialog", { name: /^Restart / });
  const pending = restart.getByRole("checkbox", { name: "Only if a restart is pending" });
  if (await pending.isChecked()) await pending.uncheck();
  await expect(restart.getByRole("heading", { name: "Restarts" })).toBeVisible();
  await expect(restart.getByText("Servers restart only when you tick them")).toBeHidden();
  await restart.getByRole("radio", { name: "Ask users, with a deadline" }).click();
  await expect(restart.getByRole("button", { name: "Restart 1 device" })).toBeEnabled();
  await restart.getByRole("button", { name: "Cancel" }).click();
  const jobs = await api<{ items: Job[] }>("GET", `/api/v1/patching/devices/${deviceId}/jobs`);
  expect(jobs.items.filter((j) => j.type === "Restart")).toEqual([]);
});

test("an organization's policy, a tag's and the device's own reach the device, each from its level", async () => {
  const page = admin;
  const main = page.getByRole("main");
  const orgs = await api<{ items: { id: string; name: string }[] }>("GET", "/api/v1/organizations");
  const org = orgs.items.find((o) => o.name === ORG)!;
  const device = await api<{ siteId: string }>("GET", `/api/v1/devices/${deviceId}`);
  const override = async (label: string) =>
    main.getByRole("radiogroup", { name: `${label}: where its value comes from` }).getByRole("radio", { name: "Override" }).click();
  const save = async () => {
    await main.getByRole("button", { name: "Save policy" }).click();
    await expect(page.getByText("Policy saved.").last()).toBeVisible();
  };

  // The organization scans every 12 hours; its site inherits that from it.
  await page.goto(`/organizations/${org.id}?tab=patch-policy`);
  await override("Scans");
  await main.getByRole("spinbutton", { name: "Scans" }).fill("720");
  await save();
  await page.goto(`/sites/${device.siteId}?tab=patch-policy`);
  await expect(main.getByRole("radiogroup", { name: "Scans: where its value comes from" }).locator("..")).toContainText(
    "Every 12 hours · from the organization",
  );

  // A tag whose policy installs optional updates.
  await page.goto("/settings?tab=patching&view=tags");
  await main.getByRole("button", { name: "Add tag" }).click();
  const add = page.getByRole("dialog", { name: "Add tag" });
  await add.getByLabel("Name").fill("Bundle ring");
  await add.getByLabel("Priority").fill("10");
  await add.getByRole("button", { name: "Add tag" }).click();
  await expect(add).toBeHidden();
  await main.getByRole("button", { name: "Add a policy" }).click();
  await expect(main.getByRole("form", { name: "Bundle ring patch policy" })).toBeVisible();
  await override("Optional updates");
  await main.getByRole("radio", { name: "Install", exact: true }).click();
  await save();

  // The device gets the tag, and a value of its own.
  await page.goto(`/devices/${deviceId}?tab=patches&patches=policy`);
  await main.getByRole("button", { name: "Change tags" }).click();
  const tags = page.getByRole("dialog", { name: "This device's tags" });
  await tags.getByRole("checkbox", { name: /Bundle ring/ }).check();
  await tags.getByRole("button", { name: "Save tags" }).click();
  await expect(tags).toBeHidden();
  await expect(main.getByTitle("Bundle ring")).toBeVisible();
  await main.getByRole("button", { name: "Set values for this device" }).click();
  await override("Scan out of date after");
  await main.getByRole("spinbutton", { name: "Scan out of date after" }).fill("72");
  await save();
  await main.getByRole("button", { name: "Back to the policy in effect" }).click();

  // EasyPatch's effective policy for the device, with the layer each value comes from.
  await expect(async () => {
    await page.reload();
    const installing = main.getByRole("heading", { name: "Installing" }).locator("xpath=ancestor::section[1]");
    await expect(installing.getByText("Tag: Bundle ring")).toBeVisible({ timeout: 5_000 });
    await expect(installing.getByText("Installed", { exact: true })).toBeVisible();
    const schedule = main.getByRole("heading", { name: "Agent schedule" }).locator("xpath=ancestor::section[1]");
    await expect(schedule.getByText("Every 12 hours")).toBeVisible();
    await expect(schedule.getByText("Organization")).toBeVisible();
    await expect(schedule.getByText("72 hours")).toBeVisible();
    await expect(schedule.getByText("This device")).toBeVisible();
  }).toPass({ timeout: 60_000, intervals: [3_000] });
});
