import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PatchActionResult, PatchAvailablePlan, PatchFleet, PatchJobDetail, PatchJobView, PatchScope, RestartPlan } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, type FakeHandler, type FakeReply } from "../../test/fakeApi";
import { org, patchJobDevice, site } from "../../test/fixtures";
import { renderApp, renderWithProviders } from "../../test/render";
import { InstallDialog, RestartDialog } from "./PatchDialogs";
import { PatchJobDialog } from "./PatchJobDialog";

// Patch all (ADR-0030): an install or restart of every device of an organization or site, from the Patching overview
// and the organization and site pages; a restart asked for with an install; and how a job shows that restart.

const T = "2026-11-22T10:00:00Z";
const main = () => within(screen.getByRole("main"));
/** The sidebar tree that chooses the organization and site. */
const tree = () => within(screen.getByRole("tree", { name: "Patching: organizations, sites, groups and devices" }));

const TECH = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "patch.view", "patch.manage"],
});
const VIEWER = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "patch.view"],
});

const EMPTY: PatchFleet = { devices: [], unmatched: [], truncated: false, errors: [] };

/** One Windows server at the head office whose updates failed. */
const FAILING: PatchFleet = {
  ...EMPTY,
  devices: [
    {
      deviceId: "d2",
      name: "DB-01",
      organizationId: "o1",
      organizationName: "Northwind Traders",
      siteId: "s1",
      siteName: "Head office",
      platform: "windows",
      link: "linked",
      canManage: true,
      endpoint: {
        id: "e2",
        hostname: "db-01",
        organizationId: "ep-o1",
        organizationName: "Northwind Traders",
        siteName: "Head office",
        status: "Active",
        operatingSystem: "Windows Server 2025 Standard",
        platform: "Windows",
        agentVersion: "1.10.0",
        agentOutdated: false,
        isOnline: true,
        lastCheckInAt: T,
        lastScanAt: T,
        complianceStatus: "FailedUpdates",
        missingRequiredCount: 0,
        missingTotalCount: 1,
        missingDeferredCount: 0,
        failedCount: 1,
        rebootPending: false,
        knownExploitedMissingCount: 0,
        currentActivity: "",
      },
    },
  ],
};

const ORG_SCOPE: PatchScope = {
  organizationId: "o1",
  organizationName: "Northwind Traders",
  siteId: null,
  siteName: "",
  devices: 12,
  byPlatform: [
    { platform: "windows", count: 9 },
    { platform: "linux", count: 3 },
  ],
  skipped: [
    { reason: "not_permitted", count: 2 },
    { reason: "stopped", count: 1 },
    { reason: "no_agent", count: 3 },
    { reason: "not_linked", count: 1 },
  ],
  canManage: true,
};

const SITE_SCOPE: PatchScope = {
  ...ORG_SCOPE,
  siteId: "s1",
  siteName: "Head office",
  devices: 5,
  byPlatform: [
    { platform: "windows", count: 4 },
    { platform: "linux", count: 1 },
  ],
  skipped: [],
};

const SITES = [site("s1", "o1", "Head office"), site("s2", "o2", "Clinic", { organizationName: "Contoso Dental" })];

const PLAN: PatchAvailablePlan = {
  devices: 10,
  updates: 42,
  upToDate: 2,
  categories: [
    { category: "Security", count: 20 },
    { category: "ServicingStack", count: 2 },
    { category: "Drivers", count: 20 },
  ],
  features: 3,
  excluded: {
    count: 4,
    devices: [
      { deviceId: "d1", deviceName: "WEB-01", count: 3 },
      { deviceId: "d2", deviceName: "DB-01", count: 1 },
    ],
  },
  held: 2,
  notApproved: 1,
  deferred: 5,
  errors: [{ deviceId: "d3", deviceName: "APP-01", message: "The agent has not scanned yet." }],
};

/** Who restarts after an install: one workstation, two servers, and one whose agent cannot restart. */
const AFTER: RestartPlan = {
  devices: [
    { deviceId: "d1", deviceName: "WEB-01", restart: true, server: false, online: true },
    { deviceId: "d4", deviceName: "DC-01", restart: true, server: true, online: true },
    { deviceId: "d5", deviceName: "FS-01", restart: true, server: true, online: false },
    { deviceId: "d6", deviceName: "KIOSK-1", restart: false, reason: "Its EasyPatch agent cannot restart the computer; update the agent first.", server: false, online: true },
  ],
};

/** The scope of the organization, or of its site when one is asked for. */
function scopeRoute(o: PatchScope = ORG_SCOPE, s: PatchScope = SITE_SCOPE): FakeHandler {
  return (r) => ok(r.query.get("siteId") ? s : o);
}

/** The sites, of one organization when asked. */
const sitesRoute: FakeHandler = (r) => {
  const o = r.query.get("organizationId");
  return ok({ items: SITES.filter((s) => !o || s.organizationId === o) });
};

function overviewRoutes(session = TECH, extra: Record<string, FakeHandler | FakeReply> = {}) {
  return {
    ...baseRoutes(session),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders"), org("o2", "Contoso Dental")] }),
    "GET /sites": sitesRoute,
    "GET /patching": ok({ configured: true }),
    "GET /patching/devices": ok(EMPTY),
    "GET /patching/jobs": ok({ items: [] }),
    "GET /patching/alerts/summary": ok({ open: 0, acknowledged: 0, critical: 0, warning: 0, info: 0, capped: false }),
    "GET /patching/scope": scopeRoute(),
    ...extra,
  };
}

function result(extra: Partial<PatchActionResult> = {}): PatchActionResult {
  return { succeeded: 0, failed: 0, results: [], ...extra };
}

describe("Patch all on the patching overview", () => {
  it("offers nothing without an organization, nor where the person may not patch", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(overviewRoutes(TECH, { "GET /patching/scope": scopeRoute({ ...ORG_SCOPE, canManage: false }) }));
    renderApp("/patching");
    await screen.findByRole("main");
    expect(await main().findByText("No devices to patch yet")).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Patch all…" })).not.toBeInTheDocument();
    expect(server.callsTo("GET /patching/scope")).toHaveLength(0);

    // An organization the technician only views there: still nothing.
    await user.click(await tree().findByRole("treeitem", { name: "Northwind Traders" }));
    await waitFor(() => expect(server.callsTo("GET /patching/scope")).toHaveLength(1));
    expect(server.call("GET /patching/scope").query.get("organizationId")).toBe("o1");
    expect(server.call("GET /patching/scope").query.get("siteId")).toBeNull();
    expect(main().queryByRole("button", { name: "Patch all…" })).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Schedule restart all…" })).not.toBeInTheDocument();
  });

  it("does not ask for people who may patch nowhere", async () => {
    const server = installFakeApi(overviewRoutes(VIEWER));
    renderApp("/patching?organizationId=o1");
    await screen.findByRole("main");
    expect(await main().findByText("No devices to patch yet")).toBeInTheDocument();
    expect(server.callsTo("GET /patching/scope")).toHaveLength(0);
    expect(main().queryByRole("button", { name: "Patch all…" })).not.toBeInTheDocument();
  });

  it("says why it is not offered when the organization is not in the patching engine", async () => {
    installFakeApi(
      overviewRoutes(TECH, {
        "GET /patching/scope": { status: 409, body: { error: { code: "easypatch_not_linked", message: "The organization is not in the patching engine yet." } } },
      }),
    );
    renderApp("/patching?organizationId=o1");
    await screen.findByRole("main");
    expect(await main().findByText(/Patch all is not available here: The organization is not in the patching engine yet\./)).toBeInTheDocument();
  });

  it("offers Patch all and Schedule restart all for an organization, Update all now for a site, and filters by site", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(overviewRoutes(TECH, { "GET /patching/devices": ok(FAILING) }));
    renderApp("/patching?organizationId=o1");
    await screen.findByRole("main");
    const bar = await main().findByRole("region", { name: "Every device in Northwind Traders" });
    expect(bar).toHaveTextContent("These act on every device in Northwind Traders you may patch: 12 devices; 7 more are left out.");
    expect(within(bar).getByRole("button", { name: "Patch all…" })).toBeInTheDocument();
    expect(within(bar).getByRole("button", { name: "Schedule restart all…" })).toBeInTheDocument();
    expect(within(bar).queryByRole("button", { name: "Update all now…" })).not.toBeInTheDocument();

    // A site narrows the devices and the buttons, and adds Update all now.
    await user.click(await tree().findByRole("treeitem", { name: "Head office" }));
    const siteBar = await main().findByRole("region", { name: "Every device in Head office (Northwind Traders)" });
    expect(siteBar).toHaveTextContent("These act on every device in Head office (Northwind Traders) you may patch: 5 devices.");
    expect(within(siteBar).getByRole("button", { name: "Update all now…" })).toBeInTheDocument();
    await waitFor(() => expect(server.callsTo("GET /patching/devices").at(-1)!.query.get("siteId")).toBe("s1"));
    expect(server.callsTo("GET /patching/scope").at(-1)!.query.get("siteId")).toBe("s1");
    // Links keep the organization and the site.
    expect(await main().findByRole("link", { name: "Show devices" })).toHaveAttribute(
      "href",
      "/patching?tab=devices&compliance=FailedUpdates&organizationId=o1&siteId=s1",
    );

    // Another organization clears the site.
    await user.click(await tree().findByRole("treeitem", { name: "Contoso Dental" }));
    await waitFor(() => expect(server.callsTo("GET /patching/devices").at(-1)!.query.get("organizationId")).toBe("o2"));
    expect(server.callsTo("GET /patching/devices").at(-1)!.query.get("siteId")).toBeNull();
    expect(tree().getByRole("treeitem", { name: "Contoso Dental" })).toHaveAttribute("aria-selected", "true");
  });

  it("chooses the organization of a site chosen across organizations", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(overviewRoutes());
    renderApp("/patching");
    await screen.findByRole("main");
    await screen.findByRole("tree", { name: "Patching: organizations, sites, groups and devices" });
    await user.click(await tree().findByRole("treeitem", { name: "Clinic" }));
    await waitFor(() => expect(server.callsTo("GET /patching/devices").at(-1)!.query.get("siteId")).toBe("s2"));
    expect(server.callsTo("GET /patching/devices").at(-1)!.query.get("organizationId")).toBe("o2");
    expect(tree().getByRole("treeitem", { name: "Clinic" })).toHaveAttribute("aria-selected", "true");
  });

  it("installs what each policy allows on every device of the platforms ticked, and sums up the batches", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      overviewRoutes(TECH, {
        "POST /patching/install": ok(
          result({
            succeeded: 1000,
            failed: 700,
            results: [{ deviceId: "d9", deviceName: "PC-9", ok: false, message: "Not sent: the patching engine did not take this batch (engine busy)." }],
            scope: ORG_SCOPE,
            batches: [
              { devices: 1000, sent: 1000 },
              { devices: 500, sent: 0, error: "engine busy" },
              { devices: 200, sent: 0, error: "The connection was lost.", unknown: true },
            ],
          }),
        ),
      }),
    );
    renderApp("/patching?organizationId=o1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Patch all…" }));
    const dialog = await screen.findByRole("dialog", { name: "Patch all of Northwind Traders" });
    const devices = within(dialog).getByRole("region", { name: "Devices" });
    expect(devices).toHaveTextContent("12 devices in Northwind Traders install.");
    // Who is left out, and why.
    expect(within(devices).getByText("2 devices you may not patch")).toBeInTheDocument();
    expect(within(devices).getByText("1 device with patching stopped")).toBeInTheDocument();
    expect(within(devices).getByText("3 devices with no EasyPatch agent")).toBeInTheDocument();
    expect(within(devices).getByText("1 device whose EasyPatch agent is not linked yet")).toBeInTheDocument();
    // Every platform is ticked for Patch all; what each policy allows, now, and no restart.
    expect(within(dialog).getByRole("checkbox", { name: "Windows (9)" })).toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: "Linux (3)" })).toBeChecked();
    expect(within(dialog).getByRole("radio", { name: "Updates each device's policy allows" })).toBeChecked();
    expect(within(dialog).getByRole("radio", { name: "Now" })).toBeChecked();
    expect(within(dialog).getByRole("radio", { name: "Don't restart" })).toBeChecked();
    expect(within(dialog).getByText(/Updates that need a restart finish at the next one/)).toBeInTheDocument();
    expect(server.callsTo("POST /patching/install/plan")).toHaveLength(0);
    expect(server.callsTo("POST /patching/restart/plan")).toHaveLength(0);

    await user.click(within(dialog).getByRole("checkbox", { name: "Linux (3)" }));
    expect(devices).toHaveTextContent("9 devices in Northwind Traders install, of the 12 you may patch there.");
    await user.click(within(dialog).getByRole("button", { name: "Install now" }));
    await waitFor(() => expect(server.callsTo("POST /patching/install")).toHaveLength(1));
    expect(server.call("POST /patching/install").body).toEqual({ all: true, organizationId: "o1", platforms: ["windows"], updates: "policy" });

    // The jobs, the batch the engine did not take, and who was left out; never "all".
    const outcome = await screen.findByRole("dialog", { name: "Install started in Northwind Traders" });
    expect(outcome).toHaveTextContent("1,000 jobs created, one per device; 700 devices did not start.");
    expect(within(outcome).getByText("2 batches not sent, or not known to have been")).toBeInTheDocument();
    expect(outcome).toHaveTextContent("Batch 2 of 3: 500 devices not sent. engine busy");
    // A batch the engine did not answer for is not known, as its devices say, not "not sent".
    expect(outcome).toHaveTextContent("Batch 3 of 3: not known whether its 200 devices were sent; see Jobs before sending again. The connection was lost.");
    expect(within(outcome).getByText("3 devices with no EasyPatch agent")).toBeInTheDocument();
    expect(within(outcome).getByRole("link", { name: "PC-9" })).toHaveAttribute("href", "/devices/d9?tab=patches");
    expect(outcome.textContent).not.toMatch(/\ball\b/i);
  });

  it("installs every available update after showing what that takes in and leaves out", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      overviewRoutes(TECH, {
        "POST /patching/install/plan": ok(PLAN),
        "POST /patching/install": ok(
          result({
            succeeded: 2,
            upToDate: 1,
            results: [
              { deviceId: "d1", deviceName: "WEB-01", ok: true, jobId: "j3", jobIds: ["j1", "j2", "j3"], message: "Installs its 1,203 updates in 3 jobs of at most 500, one after another." },
              { deviceId: "d2", deviceName: "DB-01", ok: true, jobId: "j4" },
              { deviceId: "d3", deviceName: "APP-01", ok: true, upToDate: true, message: "Already up to date: it has no available update." },
            ],
            scope: ORG_SCOPE,
          }),
        ),
      }),
    );
    renderApp("/patching?organizationId=o1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Patch all…" }));
    const dialog = await screen.findByRole("dialog", { name: "Patch all of Northwind Traders" });
    await user.click(within(dialog).getByRole("radio", { name: "All available updates" }));
    expect(within(dialog).getByText(/Security, critical, cumulative, definitions, servicing stack, \.NET, drivers, other updates/)).toBeInTheDocument();
    expect(within(dialog).getByRole("checkbox", { name: "Include feature upgrades (new Windows versions)" })).not.toBeChecked();

    const preview = await within(dialog).findByRole("region", { name: "What would be installed" });
    expect(server.call("POST /patching/install/plan").body).toEqual({ all: true, organizationId: "o1", features: false, skipDelayed: false });
    // Updates in the rollout delay are included unless unticked.
    expect(within(dialog).getByRole("checkbox", { name: "Include updates still in the rollout delay (5)" })).toBeChecked();
    expect(within(dialog).getByText(/holds new updates back for a few days after release/)).toBeInTheDocument();
    expect(preview).toHaveTextContent("42 updates on 10 devices; 2 devices already up to date");
    expect(preview).toHaveTextContent("Security: 20");
    expect(preview).toHaveTextContent("Servicing stack: 2");
    expect(within(preview).getByText("3 feature upgrades, unless you tick them above")).toBeInTheDocument();
    expect(within(preview).getByText("4 updates excluded on their devices")).toBeInTheDocument();
    expect(within(preview).getByRole("link", { name: "WEB-01" })).toHaveAttribute("href", "/devices/d1?tab=patches&patches=available");
    expect(within(preview).getByRole("link", { name: "DB-01" })).toHaveAttribute("href", "/devices/d2?tab=patches&patches=available");
    expect(within(preview).getByText("2 updates on hold")).toBeInTheDocument();
    expect(within(preview).getByText("1 application update the patch policy does not approve")).toBeInTheDocument();
    expect(preview).toHaveTextContent("5 updates are still in the rollout delay; installing now installs them anyway.");
    expect(preview).toHaveTextContent("APP-01: The agent has not scanned yet.");

    // Feature upgrades are asked for again with the tick.
    await user.click(within(dialog).getByRole("checkbox", { name: "Include feature upgrades (new Windows versions)" }));
    await waitFor(() => expect(server.callsTo("POST /patching/install/plan")).toHaveLength(2));
    expect(server.call("POST /patching/install/plan", 1).body).toEqual({ all: true, organizationId: "o1", features: true, skipDelayed: false });
    await within(dialog).findByRole("region", { name: "What would be installed" });
    // And without the updates in the rollout delay, which are then left out.
    await user.click(within(dialog).getByRole("checkbox", { name: "Include updates still in the rollout delay (5)" }));
    await waitFor(() => expect(server.callsTo("POST /patching/install/plan")).toHaveLength(3));
    expect(server.call("POST /patching/install/plan", 2).body).toEqual({ all: true, organizationId: "o1", features: true, skipDelayed: true });
    const again = await within(dialog).findByRole("region", { name: "What would be installed" });
    expect(within(again).getByText("5 updates still in the rollout delay, as chosen above")).toBeInTheDocument();
    expect(again).not.toHaveTextContent("installs them anyway");
    await user.click(within(dialog).getByRole("button", { name: "Install now" }));
    await waitFor(() => expect(server.callsTo("POST /patching/install")).toHaveLength(1));
    expect(server.call("POST /patching/install").body).toEqual({ all: true, organizationId: "o1", updates: "available", features: true, skipDelayed: true });
    // A device with more updates than one install takes gets several jobs; one with none is up to date, not a job.
    const outcome = await screen.findByRole("dialog", { name: "Install started in Northwind Traders" });
    expect(outcome).toHaveTextContent("4 jobs created for 2 devices; 1 device already up to date.");
  });

  it("asks for a site or fewer platforms before installing every available update on more than 1,000 devices", async () => {
    const user = userEvent.setup();
    const big: PatchScope = { ...ORG_SCOPE, devices: 1500, byPlatform: [{ platform: "windows", count: 1500 }], skipped: [] };
    const server = installFakeApi(overviewRoutes(TECH, { "GET /patching/scope": scopeRoute(big) }));
    renderWithProviders(<InstallDialog open onClose={() => {}} scope={{ organizationId: "o1", label: "Northwind Traders" }} />);
    const dialog = await screen.findByRole("dialog", { name: "Patch all of Northwind Traders" });
    // One platform: no ticks.
    await within(dialog).findByText(/1,500 devices/);
    expect(within(dialog).queryByRole("checkbox", { name: /Windows/ })).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("radio", { name: "All available updates" }));
    expect(within(dialog).getByText("All available updates reaches at most 1,000 devices at once")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Install now" })).toBeDisabled();
    expect(server.callsTo("POST /patching/install/plan")).toHaveLength(0);
  });

  it("updates a site now with every available update on Windows, restarting where needed, servers only when ticked", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      overviewRoutes(TECH, {
        "POST /patching/install/plan": ok({ ...PLAN, scope: SITE_SCOPE }),
        "POST /patching/restart/plan": ok({ ...AFTER, scope: SITE_SCOPE }),
        "POST /patching/install": ok(
          result({ succeeded: 4, results: [], scope: { ...SITE_SCOPE, skipped: [{ reason: "platform", count: 1 }] }, batches: [{ devices: 4, sent: 4 }], restartAfter: 3 }),
        ),
      }),
    );
    renderApp("/patching?organizationId=o1&siteId=s1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Update all now…" }));
    const dialog = await screen.findByRole("dialog", { name: "Update all of Head office (Northwind Traders) now" });

    // The preset: Windows only, every available update, now, restart if the updates need it, with a countdown.
    expect(await within(dialog).findByRole("checkbox", { name: "Windows (4)" })).toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: "Linux (1)" })).not.toBeChecked();
    expect(within(dialog).getByRole("radio", { name: "All available updates" })).toBeChecked();
    expect(within(dialog).getByRole("radio", { name: "Now" })).toBeChecked();
    expect(within(dialog).getByRole("radio", { name: "Restart if the updates need it" })).toBeChecked();
    await within(dialog).findByRole("region", { name: "What would be installed" });
    expect(server.call("POST /patching/install/plan").body).toEqual({
      all: true,
      organizationId: "o1",
      siteId: "s1",
      platforms: ["windows"],
      features: false,
      skipDelayed: false,
    });

    // The restart is checked first, as it would be after the install; servers start unticked.
    expect(await within(dialog).findByText("Servers restart only when you tick them")).toBeInTheDocument();
    expect(server.call("POST /patching/restart/plan").body).toEqual({
      all: true,
      organizationId: "o1",
      siteId: "s1",
      platforms: ["windows"],
      condition: "OnlyIfPending",
      afterInstall: true,
    });
    expect(within(dialog).getByText(/Servers you leave unticked still install their updates; they do not restart\./)).toBeInTheDocument();
    expect(within(dialog).getByRole("checkbox", { name: "Restart DC-01" })).not.toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: /^Restart FS-01/ })).not.toBeChecked();
    expect(within(dialog).getByRole("checkbox", { name: "All 2" })).not.toBeChecked();
    expect(within(dialog).getByText("Also restarts")).toBeInTheDocument();
    expect(within(dialog).getByText(/cannot restart the computer/)).toBeInTheDocument();
    expect(within(dialog).getByRole("radio", { name: "Count down, then restart" })).toBeChecked();
    expect(within(dialog).getByLabelText("If a device is offline, wait for it")).toHaveValue("120");

    // Every preset can be changed: Linux too is checked again, still naming each platform, so a device enrolled
    // since on another cannot slip in.
    await user.click(within(dialog).getByRole("checkbox", { name: "Linux (1)" }));
    await waitFor(() => expect(server.callsTo("POST /patching/restart/plan")).toHaveLength(2));
    expect((server.call("POST /patching/restart/plan", 1).body as { platforms?: string[] }).platforms).toEqual(["windows", "linux"]);
    await user.click(within(dialog).getByRole("checkbox", { name: "Linux (1)" }));
    await waitFor(() => expect(server.callsTo("POST /patching/restart/plan")).toHaveLength(3));

    await user.click(await within(dialog).findByRole("checkbox", { name: "Restart DC-01" }));
    await user.click(within(dialog).getByRole("button", { name: "Install now" }));
    await waitFor(() => expect(server.callsTo("POST /patching/install")).toHaveLength(1));
    expect(server.call("POST /patching/install").body).toEqual({
      all: true,
      organizationId: "o1",
      siteId: "s1",
      platforms: ["windows"],
      updates: "available",
      features: false,
      skipDelayed: false,
      restart: { condition: "OnlyIfPending", mode: "Countdown", countdownMinutes: 5, expiresAfterMinutes: 120 },
      confirmServers: ["d4"],
    });
    const outcome = await screen.findByRole("dialog", { name: "Install started in Head office (Northwind Traders)" });
    expect(outcome).toHaveTextContent("4 jobs created, one per device.");
    expect(outcome).toHaveTextContent("3 devices are set to restart after the install.");
    expect(within(outcome).getByText("1 device on platforms not chosen")).toBeInTheDocument();
  });

  it("schedules a restart of every device for later, leaving out servers not ticked", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      overviewRoutes(TECH, {
        "POST /patching/restart/plan": ok({ ...AFTER, scope: ORG_SCOPE }),
        "POST /patching/restart": ok(
          result({
            succeeded: 1,
            failed: 2,
            results: [
              { deviceId: "d1", deviceName: "WEB-01", ok: true, jobId: "j1" },
              { deviceId: "d4", deviceName: "DC-01", ok: false, message: "A server: left out because it was not ticked." },
              { deviceId: "d5", deviceName: "FS-01", ok: false, message: "A server: left out because it was not ticked." },
            ],
            scope: ORG_SCOPE,
            batches: [{ devices: 3, sent: 1 }],
          }),
        ),
      }),
    );
    renderApp("/patching?organizationId=o1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Schedule restart all…" }));
    const dialog = await screen.findByRole("dialog", { name: "Restart all of Northwind Traders" });
    expect(await within(dialog).findByText("Servers restart only when you tick them")).toBeInTheDocument();
    expect(server.call("POST /patching/restart/plan").body).toEqual({ all: true, organizationId: "o1" });
    expect(within(dialog).getByText(/Servers you leave unticked are left out; the other devices restart\./)).toBeInTheDocument();
    // Only where a restart is pending, at a later time.
    expect(within(dialog).getByRole("checkbox", { name: "Only if a restart is pending" })).toBeChecked();
    expect(within(dialog).getByRole("radio", { name: /^At/ })).toBeChecked();
    const at = within(dialog).getByLabelText("Restart at");
    await user.clear(at);
    await user.type(at, "2030-01-05T23:00");
    await user.click(within(dialog).getByRole("button", { name: "Schedule restart of 1 device" }));
    await waitFor(() => expect(server.callsTo("POST /patching/restart")).toHaveLength(1));
    expect(server.call("POST /patching/restart").body).toEqual({
      all: true,
      organizationId: "o1",
      mode: "Countdown",
      condition: "OnlyIfPending",
      countdownMinutes: 5,
      expiresAfterMinutes: 120,
      scheduledAt: new Date("2030-01-05T23:00").toISOString(),
    });
    const outcome = await screen.findByRole("dialog", { name: "Restart scheduled in Northwind Traders" });
    expect(outcome).toHaveTextContent("1 job created, one per device; 2 devices did not start.");
    expect(within(outcome).getAllByText("A server: left out because it was not ticked.")).toHaveLength(2);
    expect(outcome.textContent).not.toMatch(/\ball\b/i);
  });

  it("asks for at most 100 devices before restarting all of a scope whether or not a restart is pending", async () => {
    const user = userEvent.setup();
    const big: PatchScope = { ...ORG_SCOPE, devices: 150, byPlatform: [{ platform: "windows", count: 150 }], skipped: [] };
    const server = installFakeApi(overviewRoutes(TECH, { "GET /patching/scope": scopeRoute(big), "POST /patching/restart/plan": ok(AFTER) }));
    renderWithProviders(<RestartDialog open onClose={() => {}} scope={{ organizationId: "o1", label: "Northwind Traders" }} />);
    const dialog = await screen.findByRole("dialog", { name: "Restart all of Northwind Traders" });
    await within(dialog).findByText("Also restarts");
    await user.click(within(dialog).getByRole("checkbox", { name: "Only if a restart is pending" }));
    expect(within(dialog).getByText("Choose at most 100 devices")).toBeInTheDocument();
    expect(within(dialog).getByText(/This reaches 150 devices/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Restart 1 device" })).toBeDisabled();
    expect(server.callsTo("POST /patching/restart/plan")).toHaveLength(1);
  });
});

describe("a restart asked for with an install", () => {
  const TWO = [
    { id: "d1", name: "WEB-01" },
    { id: "d4", name: "DC-01" },
  ];

  it("restarts after the install if the updates need it, or whatever they need, servers only when ticked", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECH),
      "POST /patching/restart/plan": (r) =>
        ok({ devices: AFTER.devices.filter((c) => (r.body as { deviceIds: string[] }).deviceIds.includes(c.deviceId)) }),
      "POST /patching/install": ok(result({ succeeded: 2, results: [], restartAfter: 1 })),
    });
    renderWithProviders(<InstallDialog open onClose={() => {}} devices={TWO} />);
    const dialog = await screen.findByRole("dialog", { name: "Install updates on 2 devices" });
    // Not restarting is the default, with what that means.
    expect(within(dialog).getByRole("radio", { name: "Don't restart" })).toBeChecked();
    expect(within(dialog).getByText(/Updates that need a restart finish at the next one/)).toBeInTheDocument();
    expect(within(dialog).queryByRole("radio", { name: "Count down, then restart" })).not.toBeInTheDocument();
    expect(server.callsTo("POST /patching/restart/plan")).toHaveLength(0);

    await user.click(within(dialog).getByRole("radio", { name: "Restart if the updates need it" }));
    expect(await within(dialog).findByText("Servers restart only when you tick them")).toBeInTheDocument();
    expect(server.call("POST /patching/restart/plan").body).toEqual({ deviceIds: ["d1", "d4"], condition: "OnlyIfPending", afterInstall: true });
    expect(within(dialog).getByText(/each device restarts if they need it to finish/)).toBeInTheDocument();
    expect(within(dialog).getByRole("radio", { name: "Count down, then restart" })).toBeChecked();

    await user.click(within(dialog).getByRole("radio", { name: "Restart when done" }));
    await waitFor(() => expect(server.callsTo("POST /patching/restart/plan")).toHaveLength(2));
    expect(server.call("POST /patching/restart/plan", 1).body).toEqual({ deviceIds: ["d1", "d4"], condition: "Always", afterInstall: true });
    expect(within(dialog).getByText(/each device restarts whatever they need\. At most 100 devices at once\./)).toBeInTheDocument();
    expect(await within(dialog).findByRole("checkbox", { name: "Restart DC-01" })).not.toBeChecked();
    expect(within(dialog).getByText(/Servers you leave unticked still install their updates/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("radio", { name: "Restart at once" }));

    await user.click(within(dialog).getByRole("button", { name: "Install now" }));
    await waitFor(() => expect(server.callsTo("POST /patching/install")).toHaveLength(1));
    // The server installs on both, and restarts only the workstation.
    expect(server.call("POST /patching/install").body).toEqual({
      deviceIds: ["d1", "d4"],
      restart: { condition: "Always", mode: "Immediate", expiresAfterMinutes: 120 },
    });
    expect(await screen.findByText("Install started on 2 devices. 1 device is set to restart after the install.")).toBeInTheDocument();
  });

  it("restarts at most 100 devices when done, and up to 1,000 if the updates need it", async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: 101 }, (_, i) => ({ id: `d${i}`, name: `PC-${i}` }));
    const server = installFakeApi({
      ...baseRoutes(TECH),
      "POST /patching/restart/plan": (r) =>
        ok({
          devices: (r.body as { deviceIds: string[] }).deviceIds.map((id) => ({ deviceId: id, deviceName: id, restart: true, server: false, online: true })),
        }),
    });
    renderWithProviders(<InstallDialog open onClose={() => {}} devices={many} />);
    const dialog = await screen.findByRole("dialog", { name: "Install updates on 101 devices" });
    await user.click(within(dialog).getByRole("radio", { name: "Restart when done" }));
    expect(within(dialog).getByText("At most 100 devices can restart after an install")).toBeInTheDocument();
    expect(within(dialog).getByText(/This install reaches 101 devices\. Choose fewer, or restart only if the updates need it\./)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Install now" })).toBeDisabled();
    expect(server.callsTo("POST /patching/restart/plan")).toHaveLength(0);

    await user.click(within(dialog).getByRole("radio", { name: "Restart if the updates need it" }));
    await waitFor(() => expect(server.callsTo("POST /patching/restart/plan")).toHaveLength(1));
    expect(await within(dialog).findByText("Restarts after its install")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Install now" })).toBeEnabled();

    // Back to no restart: nothing to check.
    await user.click(within(dialog).getByRole("radio", { name: "Don't restart" }));
    expect(within(dialog).queryByText("Restarts after its install")).not.toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Install now" })).toBeEnabled();
  });

  it("says why the restart could not be checked, and checks again", async () => {
    const user = userEvent.setup();
    let fails = true;
    installFakeApi({
      ...baseRoutes(TECH),
      "POST /patching/restart/plan": () =>
        fails
          ? { status: 502, body: { error: { code: "easypatch_unavailable", message: "The patching engine did not answer." } } }
          : ok({ devices: [AFTER.devices[0]] }),
    });
    renderWithProviders(<InstallDialog open onClose={() => {}} devices={TWO} />);
    const dialog = await screen.findByRole("dialog", { name: "Install updates on 2 devices" });
    await user.click(within(dialog).getByRole("radio", { name: "Restart if the updates need it" }));
    expect(await within(dialog).findByText("The patching engine did not answer.")).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Install now" })).toBeDisabled();
    fails = false;
    await user.click(within(dialog).getByRole("button", { name: /Try again|Retry/ }));
    expect(await within(dialog).findByText("Restarts after its install")).toBeInTheDocument();
  });
});

describe("Patch all on the organization and site pages", () => {
  function pageRoutes(scope: PatchScope, extra: Record<string, FakeHandler | FakeReply> = {}) {
    return {
      ...baseRoutes(TECH),
      "GET /sites/:id": ok(site("s1", "o1", "Head office")),
      "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
      "GET /organizations/:id/sites": ok({ items: [site("s1", "o1", "Head office")] }),
      "GET /sites/:id/device-groups": ok({ items: [] }),
      "GET /patching": ok({ configured: true }),
      "GET /patching/scope": ok(scope),
      ...extra,
    };
  }

  it("offers Update all now on a site to those who may patch there", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(pageRoutes(SITE_SCOPE, { "POST /patching/install/plan": ok(PLAN), "POST /patching/restart/plan": ok(AFTER) }));
    renderApp("/sites/s1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Update all now…" }));
    expect(server.call("GET /patching/scope").query.get("siteId")).toBe("s1");
    const dialog = await screen.findByRole("dialog", { name: "Update all of Head office (Northwind Traders) now" });
    expect(await within(dialog).findByRole("checkbox", { name: "Linux (1)" })).not.toBeChecked();
    expect(within(dialog).getByRole("radio", { name: "Restart if the updates need it" })).toBeChecked();
  });

  it("keeps the tick of a site's only platform once it is ticked, so it can be unticked", async () => {
    const user = userEvent.setup();
    const linuxOnly: PatchScope = { ...SITE_SCOPE, devices: 2, byPlatform: [{ platform: "linux", count: 2 }] };
    installFakeApi(pageRoutes(linuxOnly, { "POST /patching/install/plan": ok(PLAN), "POST /patching/restart/plan": ok(AFTER) }));
    renderApp("/sites/s1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Update all now…" }));
    const dialog = await screen.findByRole("dialog", { name: "Update all of Head office (Northwind Traders) now" });
    const linux = await within(dialog).findByRole("checkbox", { name: "Linux (2)" });
    expect(linux).not.toBeChecked();
    await user.click(linux);
    expect(within(dialog).getByRole("checkbox", { name: "Linux (2)" })).toBeChecked();
    await user.click(within(dialog).getByRole("checkbox", { name: "Linux (2)" }));
    expect(within(dialog).getByRole("checkbox", { name: "Linux (2)" })).not.toBeChecked();
  });

  it("offers nothing on a site where the person may not patch", async () => {
    const server = installFakeApi(pageRoutes({ ...SITE_SCOPE, canManage: false }));
    renderApp("/sites/s1");
    await screen.findByRole("main");
    await main().findByRole("heading", { name: "Head office" });
    await waitFor(() => expect(server.callsTo("GET /patching/scope")).toHaveLength(1));
    expect(main().queryByRole("button", { name: "Update all now…" })).not.toBeInTheDocument();
  });

  it("offers Patch all on an organization's page", async () => {
    const user = userEvent.setup();
    installFakeApi(pageRoutes(ORG_SCOPE));
    renderApp("/organizations/o1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Patch all…" }));
    const dialog = await screen.findByRole("dialog", { name: "Patch all of Northwind Traders" });
    expect(within(dialog).getByRole("radio", { name: "Updates each device's policy allows" })).toBeChecked();
    expect(within(dialog).getByRole("radio", { name: "Don't restart" })).toBeChecked();
  });
});

describe("a job's restart after its install", () => {
  function job(id: string, type: string): PatchJobView {
    return {
      id,
      endpointId: "e1",
      hostname: "web-01",
      type,
      status: "Succeeded",
      trigger: "Manual",
      requestedBy: "alex@example.com",
      createdAt: T,
      startedAt: T,
      completedAt: T,
      expiresAt: T,
      progressPercent: null,
      phase: "",
      progressMessage: "",
      errorCode: "",
      errorMessage: "",
      rebootRequired: false,
      timedOut: false,
      cancelRequested: false,
      itemCount: 0,
      succeededCount: 0,
      failedCount: 0,
      deviceId: "d1",
      deviceName: "WEB-01",
      canManage: true,
    };
  }

  function detail(summary: PatchJobView, extra: Partial<PatchJobDetail> = {}): PatchJobDetail {
    return {
      summary,
      installMode: "AllEligible",
      notBefore: null,
      deliveredAt: T,
      acknowledgedAt: T,
      lastProgressAt: T,
      deliveryCount: 1,
      retryOfJobId: null,
      cancelRequestedAt: null,
      items: [],
      events: [],
      deviceId: "d1",
      deviceName: "WEB-01",
      canManage: true,
      ...patchJobDevice(),
      ...extra,
    };
  }

  const INSTALL = detail(job("j1", "InstallUpdates"), {
    restartAfter: {
      condition: "OnlyIfPending",
      mode: "PromptWithDeadline",
      countdownMinutes: null,
      deadlineMinutes: 240,
      expiresAfterMinutes: 120,
      state: "done",
      message: "The updates needed a restart; EasyRMM asked for it.",
      restartJobId: "j2",
      midwayJobId: "j3",
      server: true,
      requestedBy: "alex@example.com",
      requestedAt: T,
    },
  });
  const RESTART = detail(job("j2", "Reboot"), { restartFor: "j1" });

  it("shows the restart asked for with an install, what became of it, and opens its jobs", async () => {
    const user = userEvent.setup();
    const onJob = vi.fn();
    installFakeApi({ ...baseRoutes(TECH), "GET /patching/jobs/:id": (r) => ok(r.params.id === "j1" ? INSTALL : RESTART) });
    renderWithProviders(<PatchJobDialog jobId="j1" onClose={() => {}} onJob={onJob} />);
    const dialog = await screen.findByRole("dialog");
    const after = await within(dialog).findByRole("region", { name: "Restart after the install" });
    expect(after).toHaveTextContent("Restart if the updates need it");
    expect(after).toHaveTextContent("Ask users, with a deadline, within 4 hours");
    expect(after).toHaveTextContent("Wait 2 hours");
    expect(after).toHaveTextContent("Ticked by name to restart");
    expect(within(after).getByText("Restart asked for")).toBeInTheDocument();
    expect(within(after).getByText("The updates needed a restart; EasyRMM asked for it.")).toBeInTheDocument();
    expect(after).toHaveTextContent("by alex@example.com");
    await user.click(within(after).getByRole("button", { name: "The restart after the install" }));
    expect(onJob).toHaveBeenLastCalledWith("j2");
    await user.click(within(after).getByRole("button", { name: "The restart the install waited for" }));
    expect(onJob).toHaveBeenLastCalledWith("j3");
  });

  it("shows which install a restart follows", async () => {
    const user = userEvent.setup();
    const onJob = vi.fn();
    installFakeApi({ ...baseRoutes(TECH), "GET /patching/jobs/:id": (r) => ok(r.params.id === "j1" ? INSTALL : RESTART) });
    renderWithProviders(<PatchJobDialog jobId="j2" onClose={() => {}} onJob={onJob} />);
    const dialog = await screen.findByRole("dialog");
    await user.click(await within(dialog).findByRole("button", { name: "The install job" }));
    expect(onJob).toHaveBeenCalledWith("j1");
    expect(within(dialog).queryByRole("region", { name: "Restart after the install" })).not.toBeInTheDocument();
  });

  it("says when a restart was not asked for, or was refused, and that it waits", async () => {
    const states = [
      ["waiting", "Waiting for the install to finish"],
      ["skipped", "Not restarted"],
      ["failed", "Restart refused"],
    ] as const;
    for (const [state, label] of states) {
      const r = { ...INSTALL.restartAfter!, state, condition: "Always" as const, mode: "Countdown" as const, countdownMinutes: 10, deadlineMinutes: null, restartJobId: null, midwayJobId: null, server: false, requestedBy: "" };
      installFakeApi({ ...baseRoutes(TECH), "GET /patching/jobs/:id": ok({ ...INSTALL, restartAfter: r }) });
      const view = renderWithProviders(<PatchJobDialog jobId="j1" onClose={() => {}} onJob={() => {}} />);
      const after = await screen.findByRole("region", { name: "Restart after the install" });
      expect(after).toHaveTextContent("Restart when done");
      expect(after).toHaveTextContent("Count down, then restart, after 10 minutes");
      expect(within(after).getByText(label)).toBeInTheDocument();
      expect(within(after).queryByRole("button")).not.toBeInTheDocument();
      view.unmount();
    }
  });
});
