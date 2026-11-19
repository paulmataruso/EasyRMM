import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  DevicePatching,
  EasyPatchConnection,
  EasyPatchOrganizations,
  PatchEndpoint,
  PatchFleet,
  PatchActionResult,
  PatchInstallPreview,
  PatchJobDetail,
  PatchJobView,
  PatchPolicy,
  PatchStatus,
  PatchUpdate,
  RestartPlan,
} from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, unreportedRoutes, type FakeHandler, type FakeReply } from "../../test/fakeApi";
import { device, org } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { activityText, maintenanceText, requester } from "./patchText";

const T = "2026-11-16T10:00:00Z";
const main = () => within(screen.getByRole("main"));

const TECH = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "patch.view", "patch.manage", "software.view"],
});
const VIEWER = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "patch.view"],
});

/** A connected EasyPatch server, with a console of its own to link to. */
const READY: PatchStatus = {
  configured: true,
  canOperate: true,
  canSchedule: false,
  consoleUrl: "https://patch.example.com",
};

function endpoint(id: string, hostname: string, extra: Partial<PatchEndpoint> = {}): PatchEndpoint {
  return {
    id,
    hostname,
    organizationId: "ep-o1",
    organizationName: "Northwind Patch",
    siteName: "Head office",
    status: "Active",
    operatingSystem: "Debian GNU/Linux 13 (trixie)",
    platform: "Linux",
    agentVersion: "1.9.0",
    agentOutdated: false,
    isOnline: true,
    lastCheckInAt: T,
    lastScanAt: T,
    complianceStatus: "MissingUpdates",
    missingRequiredCount: 1,
    missingTotalCount: 2,
    missingDeferredCount: 0,
    failedCount: 1,
    rebootPending: false,
    knownExploitedMissingCount: 0,
    currentActivity: "Idle",
    ...extra,
  };
}

const FLEET: PatchFleet = {
  devices: [
    {
      deviceId: "d1",
      name: "WEB-01",
      organizationId: "o1",
      organizationName: "Northwind Traders",
      siteId: "s1",
      siteName: "Head office",
      platform: "linux",
      link: "linked",
      canManage: true,
      endpoint: endpoint("e1", "web-01", { currentActivity: "UpdateScan" }),
      checkedAt: T,
    },
    {
      deviceId: "d2",
      name: "DB-01",
      organizationId: "o1",
      organizationName: "Northwind Traders",
      siteId: "s1",
      siteName: "Head office",
      platform: "linux",
      link: "linked",
      canManage: true,
      endpoint: endpoint("e2", "db-01", {
        complianceStatus: "Compliant",
        missingTotalCount: 0,
        missingRequiredCount: 0,
        failedCount: 0,
      }),
    },
    {
      deviceId: "d3",
      name: "APP-01",
      organizationId: "o1",
      organizationName: "Northwind Traders",
      siteId: "s1",
      siteName: "Head office",
      platform: "linux",
      link: "unlinked",
      reason: 'Host names differ: EasyPatch has "app-02", EasyRMM has "app-01".',
      canManage: true,
    },
  ],
  truncated: false,
  errors: [],
};

function job(id: string, extra: Partial<PatchJobView> = {}): PatchJobView {
  return {
    id,
    endpointId: "e1",
    hostname: "web-01",
    type: "InstallUpdates",
    status: "Running",
    trigger: "Manual",
    requestedBy: "token:easyrmm",
    createdAt: T,
    startedAt: T,
    completedAt: null,
    expiresAt: T,
    progressPercent: 40,
    phase: "Installing",
    progressMessage: "Installing openssl.",
    errorCode: "",
    errorMessage: "",
    rebootRequired: false,
    timedOut: false,
    cancelRequested: false,
    itemCount: 2,
    succeededCount: 1,
    failedCount: 0,
    deviceId: "d1",
    deviceName: "WEB-01",
    canManage: true,
    ...extra,
  };
}

function patchingRoutes(extra: Record<string, FakeHandler | FakeReply> = {}) {
  return {
    ...baseRoutes(TECH),
    "GET /patching": ok(READY),
    "GET /patching/devices": ok(FLEET),
    ...extra,
  };
}

describe("patching page", () => {
  it("lists devices with their status and scans the chosen ones", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      patchingRoutes({
        // The patching engine in EasyRMM's deployment: no console of its own.
        "GET /patching": ok({ ...READY, consoleUrl: undefined }),
        "POST /patching/scan": ok({
          succeeded: 1,
          failed: 0,
          results: [{ deviceId: "d1", deviceName: "WEB-01", ok: true, jobId: "j1" }],
        }),
      }),
    );
    renderApp("/patching");
    await screen.findByRole("main");
    expect(await screen.findByRole("heading", { name: "Patching", level: 1 })).toBeInTheDocument();
    expect(await main().findByText("WEB-01")).toBeInTheDocument();
    // Without a console of EasyPatch's own, there is nothing to open.
    expect(main().queryByText("Open EasyPatch")).not.toBeInTheDocument();
    const table = within(main().getByRole("table"));
    // The status shows under the name on narrow screens and in its own column on wider ones.
    expect(table.getAllByText("Updates missing")).toHaveLength(2);
    expect(table.getAllByText("Up to date")).toHaveLength(2);
    expect(main().getByText(/Host names differ/)).toBeInTheDocument();
    expect(table.getByText("Scanning for updates")).toBeInTheDocument();
    expect(main().getByText(/1 up to date · 1 need attention · 1 not patched from EasyRMM/)).toBeInTheDocument();
    // A device that is not linked cannot be chosen.
    expect(main().queryByLabelText("Select APP-01")).not.toBeInTheDocument();

    await user.click(main().getByLabelText("Select WEB-01"));
    expect(main().getByText("1 selected")).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Scan" }));
    await waitFor(() => expect(server.callsTo("POST /patching/scan")).toHaveLength(1));
    expect(server.call("POST /patching/scan").body).toEqual({
      deviceIds: ["d1"],
    });
    expect(await screen.findByText("Scan started on 1 device.")).toBeInTheDocument();
  });

  it("filters by status and installs on every chosen device, listing those that did not start", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      patchingRoutes({
        "POST /patching/install": ok({
          succeeded: 1,
          failed: 1,
          results: [
            { deviceId: "d1", deviceName: "WEB-01", ok: true, jobId: "j1" },
            {
              deviceId: "d2",
              deviceName: "DB-01",
              ok: false,
              message: "db-01 has no eligible updates.",
            },
          ],
        }),
      }),
    );
    renderApp("/patching");
    await screen.findByRole("main");
    await main().findByText("WEB-01");
    await user.selectOptions(main().getByLabelText("Status"), "FailedUpdates");
    await waitFor(() => expect(server.callsTo("GET /patching/devices").at(-1)!.query.get("compliance")).toBe("FailedUpdates"));

    await user.click(main().getByLabelText("Select every device you can act on"));
    await user.click(main().getByRole("button", { name: "Install updates…" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Install updates on 2 devices",
    });
    // Without the scheduled-installs capability, installs start at once.
    expect(within(dialog).queryByLabelText("Install at")).not.toBeInTheDocument();
    expect(within(dialog).getByText(/needs an EasyPatch server with scheduled installs/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Install now" }));
    await waitFor(() => expect(server.callsTo("POST /patching/install")).toHaveLength(1));
    expect(server.call("POST /patching/install").body).toEqual({
      deviceIds: ["d1", "d2"],
    });
    const failed = await screen.findByRole("dialog", {
      name: "1 device did not start",
    });
    expect(within(failed).getByText("db-01 has no eligible updates.")).toBeInTheDocument();
    expect(within(failed).getByRole("link", { name: "DB-01" })).toHaveAttribute("href", "/devices/d2?tab=patches");
  });

  it("installs the EasyPatch agent on devices that have none, and shows how installs went", async () => {
    const user = userEvent.setup();
    const agentless = (id: string, name: string, extra: Partial<PatchFleet["devices"][number]> = {}): PatchFleet["devices"][number] => ({
      deviceId: id,
      name,
      organizationId: "o1",
      organizationName: "Northwind Traders",
      siteId: "s1",
      siteName: "Head office",
      platform: "windows",
      link: "none",
      canManage: true,
      ...extra,
    });
    const server = installFakeApi(
      patchingRoutes({
        "GET /patching/devices": ok({
          ...FLEET,
          devices: [
            FLEET.devices[0],
            agentless("d4", "PC-04"),
            agentless("d5", "PC-05", {
              install: { state: "failed", automatic: false, requestedBy: "alex@example.com", requestedAt: T, attempts: 1, error: "Exit code 1603" },
            }),
            agentless("d6", "PC-06", { install: { state: "waiting", automatic: true, requestedAt: T, attempts: 0, note: "This agent is too old." } }),
          ],
        }),
        "POST /patching/agent-install": ok({
          succeeded: 1,
          failed: 1,
          results: [
            { deviceId: "d4", deviceName: "PC-04", ok: true },
            { deviceId: "d5", deviceName: "PC-05", ok: false, message: "This device already has an EasyPatch agent (Active); EasyRMM leaves it alone." },
          ],
        }),
      }),
    );
    renderApp("/patching");
    await screen.findByRole("main");
    await main().findByText("PC-04");
    const table = within(main().getByRole("table"));
    // Shown under the name on narrow screens and in the status column on wider ones.
    expect(table.getAllByText("EasyPatch agent install failed")).toHaveLength(2);
    expect(table.getAllByText("Exit code 1603")).toHaveLength(2);
    expect(table.getAllByText("This agent is too old.")).toHaveLength(2);

    // Devices of both kinds: each action says how many it acts on.
    await user.click(main().getByLabelText("Select WEB-01"));
    await user.click(main().getByLabelText("Select PC-04"));
    await user.click(main().getByLabelText("Select PC-05"));
    expect(main().getByRole("button", { name: "Scan 1" })).toBeInTheDocument();
    expect(main().getByRole("button", { name: "Install updates on 1…" })).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Install EasyPatch agent on 2…" }));
    const dialog = await screen.findByRole("dialog", { name: "Install the EasyPatch agent on 2 devices" });
    expect(within(dialog).getByText(/need systemd and apt-get or dnf/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Install EasyPatch agent" }));
    await waitFor(() => expect(server.callsTo("POST /patching/agent-install")).toHaveLength(1));
    expect(server.call("POST /patching/agent-install").body).toEqual({ deviceIds: ["d4", "d5"] });
    expect(await screen.findByText("EasyPatch agent install requested on 1 device.")).toBeInTheDocument();
    const failed = await screen.findByRole("dialog", { name: "1 device did not start" });
    expect(within(failed).getByText(/already has an EasyPatch agent/)).toBeInTheDocument();
    await user.click(within(failed).getAllByRole("button", { name: "Close" }).at(-1)!);
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "1 device did not start" })).not.toBeInTheDocument());
    // Only devices without an agent: the action alone, unnumbered.
    await user.click(main().getByLabelText("Select PC-06"));
    expect(main().queryByRole("button", { name: /^Scan/ })).not.toBeInTheDocument();
    expect(main().getByRole("button", { name: "Install EasyPatch agent…" })).toBeInTheDocument();
  });

  it("says when EasyPatch is not set up", async () => {
    installFakeApi({
      ...baseRoutes(
        sessionView({
          permissions: [...sessionView().permissions, "device.view", "patch.view"],
        }),
      ),
      "GET /patching": ok({
        configured: false,
        canOperate: false,
        canSchedule: false,
      }),
    });
    renderApp("/patching");
    await screen.findByRole("main");
    expect(await main().findByText("EasyPatch is not set up")).toBeInTheDocument();
    expect(main().getByRole("link", { name: "Set up EasyPatch" })).toHaveAttribute("href", "/settings?tab=easypatch");
  });

  it("opens EasyPatch's own list of what the tab shows, in the same tab", async () => {
    installFakeApi(patchingRoutes({ "GET /patching": ok({ ...READY, consoleUrl: "https://patch.example.com" }), "GET /patching/jobs": ok({ items: [] }) }));
    renderApp("/patching");
    await screen.findByRole("main");
    // Role queries over the whole fleet table are slow; the link's text is enough to find it.
    const link = (await main().findByText("Open EasyPatch")).closest("a")!;
    expect(link).toHaveAttribute("href", "/go/to-easypatch?list=endpoints");
    expect(link).not.toHaveAttribute("target");
    await userEvent.setup().click(main().getByRole("tab", { name: "Jobs" }));
    expect(main().getByText("Open EasyPatch").closest("a")).toHaveAttribute("href", "/go/to-easypatch?list=jobs");
  });

  it("is read-only for a viewer, and when EasyPatch's token cannot act", async () => {
    installFakeApi({
      ...patchingRoutes(),
      ...baseRoutes(VIEWER),
      "GET /patching": ok({ ...READY, canOperate: false }),
      "GET /patching/devices": ok(FLEET),
    });
    renderApp("/patching");
    await screen.findByRole("main");
    await main().findByText("WEB-01");
    expect(main().getByText("Read-only")).toBeInTheDocument();
    expect(main().queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("shows EasyPatch errors and an empty list", async () => {
    installFakeApi(
      patchingRoutes({
        "GET /patching/devices": ok({
          devices: [],
          truncated: false,
          errors: ["Northwind Traders: EasyPatch: The database is not available."],
        }),
      }),
    );
    renderApp("/patching");
    await screen.findByRole("main");
    expect(await main().findByText(/The database is not available/)).toBeInTheDocument();
    expect(main().getByText("No devices to patch yet")).toBeInTheDocument();
  });

  it("follows jobs as they run, and cancels one", async () => {
    const user = userEvent.setup();
    const detail: PatchJobDetail = {
      summary: job("j1"),
      installMode: "AllEligible",
      notBefore: null,
      deliveredAt: T,
      lastProgressAt: T,
      items: [
        {
          updateGuid: "u1",
          title: "openssl 3.5.7-1~deb13u3",
          kbNumber: "",
          category: "Security",
          status: "Installing",
          skipReason: "",
          resultCode: null,
          errorCode: "",
          errorMessage: "",
          rebootRequired: false,
          downloadPercent: 100,
          installPercent: 60,
          startedAt: T,
          completedAt: null,
        },
      ],
      events: [
        {
          id: 1,
          type: "JobCreated",
          severity: "Info",
          message: "Job queued.",
          createdAt: T,
        },
      ],
      deviceId: "d1",
      deviceName: "WEB-01",
      canManage: true,
    };
    const server = installFakeApi(
      patchingRoutes({
        "GET /patching/jobs": ok({
          items: [
            job("j1"),
            job("j2", {
              type: "UpdateScan",
              status: "Completed",
              itemCount: 0,
              progressPercent: null,
              requestedBy: "tess@example.com",
            }),
          ],
        }),
        "GET /patching/jobs/:id": ok(detail),
        "POST /patching/jobs/:id/cancel": ok({
          ...detail,
          summary: {
            ...detail.summary,
            status: "Cancelled",
            cancelRequested: true,
          },
        }),
      }),
    );
    renderApp("/patching?tab=jobs");
    await screen.findByRole("main");
    expect(await main().findByText("Running · 40%")).toBeInTheDocument();
    expect(server.call("GET /patching/jobs").query.get("active")).toBe("true");
    expect(main().getByText("1 of 2 updates installed")).toBeInTheDocument();
    expect(main().getByText("API token easyrmm")).toBeInTheDocument();
    expect(main().getByText("tess@example.com")).toBeInTheDocument();

    await user.click(main().getByRole("radio", { name: "All recent" }));
    await waitFor(() => expect(server.callsTo("GET /patching/jobs").at(-1)!.query.get("active")).toBeNull());

    await user.click(main().getByRole("button", { name: "Install updates" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Install updates on WEB-01",
    });
    expect(within(dialog).getByText("Installing openssl.")).toBeInTheDocument();
    expect(within(dialog).getByText("Installing · 60%")).toBeInTheDocument();
    expect(within(dialog).getByText("Job queued.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Cancel job" }));
    await waitFor(() => expect(server.callsTo("POST /patching/jobs/:id/cancel")).toHaveLength(1));
    expect(server.call("POST /patching/jobs/:id/cancel").params.id).toBe("j1");
  });

  it("restarts the chosen devices whose restart is pending, leaving out servers not ticked", async () => {
    const user = userEvent.setup();
    const pending = (d: PatchFleet["devices"][number]) => ({ ...d, endpoint: { ...d.endpoint!, rebootPending: true } });
    const plan: RestartPlan = {
      serversKnown: true,
      devices: [
        { deviceId: "d1", deviceName: "WEB-01", restart: true, server: false, online: true },
        { deviceId: "d2", deviceName: "DB-01", restart: true, server: true, online: false },
      ],
    };
    const server = installFakeApi(
      patchingRoutes({
        "GET /patching/devices": ok({ ...FLEET, devices: [pending(FLEET.devices[0]!), pending(FLEET.devices[1]!), FLEET.devices[2]] }),
        "POST /patching/restart/plan": ok(plan),
        "POST /patching/restart": ok({ succeeded: 1, failed: 0, results: [{ deviceId: "d1", deviceName: "WEB-01", ok: true, jobId: "j7" }] }),
      }),
    );
    renderApp("/patching");
    await screen.findByRole("main");
    await main().findByText("WEB-01");
    await user.click(main().getByLabelText("Select WEB-01"));
    await user.click(main().getByLabelText("Select DB-01"));
    await user.click(main().getByRole("button", { name: "Restart…" }));
    const dialog = await screen.findByRole("dialog", { name: "Restart 2 devices" });
    expect(await within(dialog).findByText("Servers restart only when you tick them")).toBeInTheDocument();
    expect(server.call("POST /patching/restart/plan").body).toEqual({ deviceIds: ["d1", "d2"] });
    expect(within(dialog).getByText("Also restarts")).toBeInTheDocument();
    expect(within(dialog).getByText("Offline")).toBeInTheDocument();
    // More options are for one device at a time, in EasyPatch.
    expect(within(dialog).queryByRole("link", { name: /More restart options/ })).not.toBeInTheDocument();

    const at = within(dialog).getByLabelText("Restart at");
    await user.clear(at);
    await user.type(at, "2030-01-05T23:00");
    await user.click(within(dialog).getByRole("button", { name: "Schedule restart of 1 device" }));
    await waitFor(() => expect(server.callsTo("POST /patching/restart")).toHaveLength(1));
    expect(server.call("POST /patching/restart").body).toEqual({
      deviceIds: ["d1"],
      scheduledAt: new Date("2030-01-05T23:00").toISOString(),
    });
    expect(await screen.findByText("Restart scheduled on 1 device.")).toBeInTheDocument();
  });

  it("offers a restart only for devices whose restart is pending, and says why a device will not restart", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      patchingRoutes({
        "GET /patching/devices": ok({ ...FLEET, devices: [{ ...FLEET.devices[0]!, endpoint: { ...FLEET.devices[0]!.endpoint!, rebootPending: true } }, FLEET.devices[1]] }),
        "POST /patching/restart/plan": ok({
          serversKnown: true,
          devices: [{ deviceId: "d1", deviceName: "WEB-01", restart: false, reason: "Its EasyPatch agent cannot restart the computer; update the agent first.", server: false, online: true }],
        }),
      }),
    );
    renderApp("/patching");
    await screen.findByRole("main");
    await main().findByText("WEB-01");
    await user.click(main().getByLabelText("Select DB-01"));
    expect(main().queryByRole("button", { name: /Restart/ })).not.toBeInTheDocument();
    await user.click(main().getByLabelText("Select WEB-01"));
    await user.click(main().getByRole("button", { name: "Restart 1…" }));
    const dialog = await screen.findByRole("dialog", { name: "Restart WEB-01" });
    expect(await within(dialog).findByText("Nothing to restart")).toBeInTheDocument();
    expect(within(dialog).getByText(/cannot restart the computer/)).toBeInTheDocument();
    expect(within(dialog).queryByLabelText("Restart at")).not.toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Restart" })).toBeDisabled();
    expect(within(dialog).getByRole("link", { name: "More restart options in EasyPatch" })).toHaveAttribute("href", "/go/to-easypatch?device=d1");
    expect(server.callsTo("POST /patching/restart")).toHaveLength(0);
  });

  it("retries a job that failed, then follows the new one", async () => {
    const user = userEvent.setup();
    const failedJob = job("j1", { status: "Failed", progressPercent: null, completedAt: T, failedCount: 1, errorMessage: "dpkg was interrupted" });
    const detail = (summary: PatchJobView): PatchJobDetail => ({
      summary,
      installMode: "AllEligible",
      notBefore: null,
      deliveredAt: T,
      lastProgressAt: T,
      items: [],
      events: [],
      deviceId: "d1",
      deviceName: "WEB-01",
      canManage: true,
    });
    const server = installFakeApi(
      patchingRoutes({
        "GET /patching/jobs": ok({ items: [failedJob] }),
        "GET /patching/jobs/:id": (req) => ok(detail(req.params.id === "j3" ? job("j3", { status: "Queued", progressPercent: null }) : failedJob)),
        "POST /patching/jobs/:id/retry": ok(job("j3", { status: "Queued", progressPercent: null })),
      }),
    );
    renderApp("/patching?tab=jobs&active=false&job=j1");
    const dialog = await screen.findByRole("dialog", { name: "Install updates on WEB-01" });
    expect(await within(dialog).findByText("dpkg was interrupted")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "Open in EasyPatch" })).toHaveAttribute("href", "/go/to-easypatch?job=j1");
    expect(within(dialog).queryByRole("button", { name: "Cancel job" })).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(server.callsTo("POST /patching/jobs/:id/retry")).toHaveLength(1));
    expect(server.call("POST /patching/jobs/:id/retry").params.id).toBe("j1");
    expect(await screen.findByText("Retry queued.")).toBeInTheDocument();
    // The new job opens in its place; while it runs, it is cancelled rather than retried.
    await waitFor(() => expect(server.callsTo("GET /patching/jobs/:id").at(-1)!.params.id).toBe("j3"));
    expect(await within(dialog).findByRole("button", { name: "Cancel job" })).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Retry" })).not.toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "Open in EasyPatch" })).toHaveAttribute("href", "/go/to-easypatch?job=j3");
  });

  it("is in the main menu for those who may see patching", async () => {
    installFakeApi(patchingRoutes());
    renderApp("/patching");
    await screen.findByRole("main");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Patching" })).toBeInTheDocument();
  });
});

const POLICY: PatchPolicy = {
  autoInstallEnabled: true,
  maintenanceDays: [6],
  maintenanceStart: "02:00",
  maintenanceDurationMinutes: 180,
  timeZone: "Europe/Paris",
  scanIntervalMinutes: 240,
  allowedCategories: ["Security", "ServicingStack"],
  includeOptional: false,
  installDelayDays: 3,
  securityInstallDelayDays: 0,
  checkInIntervalSeconds: 60,
  inventoryIntervalMinutes: 1440,
  jitterPercent: 10,
  excludedKbs: [],
  acceptEulas: true,
  scanStaleAfterHours: 72,
  maxConcurrentInstallsPerSite: 10,
  trayIconEnabled: true,
  installNotificationsEnabled: true,
  agentAutoUpdateEnabled: true,
  knownExploitedSkipsDelay: true,
  preDownloadHours: 0,
  restartSchedule: null,
  windowsUpdate: null,
  windowsUpdateValues: null,
  applicationUpdates: null,
  sources: { AutoInstallEnabled: "Organization", MaintenanceWindow: "Organization", AllowedCategories: "Global" },
  sourceTags: null,
};

function update(guid: string, title: string, extra: Partial<PatchUpdate> = {}): PatchUpdate {
  return {
    updateGuid: guid,
    title,
    kbNumber: "",
    kbNumbers: [],
    category: "Security",
    msrcSeverity: "",
    releaseDate: T,
    sizeBytes: 1_543_210,
    rebootLikely: false,
    supportUrl: "",
    state: "Missing",
    isRequired: true,
    isExcluded: false,
    firstDetectedAt: T,
    stateChangedAt: T,
    installedAt: null,
    failedAttempts: 0,
    errorCode: "",
    errorMessage: "",
    activeJob: null,
    package: {
      name: "openssl",
      version: "3.5.7-1",
      installedVersion: "3.5.6-1",
      repository: "trixie-security",
      advisories: [],
    },
    deferredUntil: null,
    cveIds: [],
    knownExploited: false,
    kevDueDate: "",
    holdReason: "",
    ...extra,
  };
}

const AGENT = {
  version: "1.4.0",
  arch: "amd64",
  sha256: "",
  online: true,
  lastSeenAt: T,
  enrolledAt: T,
  update: null,
};
const WEB = device("d1", "WEB-01", {
  platform: "linux",
  osDescription: "Debian GNU/Linux 13 (trixie)",
  agent: AGENT,
});

const LINKED: DevicePatching = {
  deviceId: "d1",
  link: "linked",
  checkedAt: T,
  canManage: true,
  canSchedule: true,
  endpoint: {
    summary: endpoint("e1", "web-01", { knownExploitedMissingCount: 1 }),
    serialNumber: "S-1",
    lastScanAttemptAt: T,
    lastScanError: "",
    rebootReasons: [],
    rebootPendingSince: null,
    installedCount: 1,
    pendingRebootUpdateCount: 0,
    complianceEvaluatedAt: T,
    activeJob: null,
    agentCapabilities: ["restart", "self-update", "uninstall"],
    signedInUsers: null,
    trayConnectedSessions: null,
    hasOwnPolicy: false,
    agentUpdate: {
      supported: true,
      automaticUpdates: true,
      availableVersion: "",
      code: "agent_up_to_date",
      message: "The agent already runs the newest package for its platform.",
      packageFormat: "deb",
    },
    restart: null,
    windowsUpdatePolicy: null,
  },
  policy: POLICY,
};

const PREVIEW: PatchInstallPreview = {
  mode: "AllEligible",
  items: [
    { updateGuid: "u1", title: "openssl 3.5.7-1~deb13u3", kbNumber: "", category: "Security", sizeBytes: 1_543_210, rebootBehavior: null, state: "Missing" },
    { updateGuid: "u2", title: "tzdata 2026c-0+deb13u1", kbNumber: "", category: "Other", sizeBytes: 1_543_210, rebootBehavior: null, state: "Failed" },
  ],
  skipped: [],
  totalSizeBytes: 3_086_420,
  rebootLikelyCount: 0,
  warnings: [],
  filter: { categories: ["Security", "ServicingStack"], includeOptional: false },
  lastScanAt: T,
};

function deviceRoutes(patching: DevicePatching, extra: Record<string, FakeHandler | FakeReply> = {}) {
  return {
    ...baseRoutes(TECH),
    ...unreportedRoutes(),
    "GET /devices/:id": ok(WEB),
    "GET /patching": ok(READY),
    "GET /patching/devices/:id": ok(patching),
    "GET /patching/devices/:id/install-preview": ok(PREVIEW),
    "GET /patching/devices/:id/updates": ok({
      items: [
        update("u1", "openssl 3.5.7-1~deb13u3", { knownExploited: true }),
        update("u2", "tzdata 2026c-0+deb13u1", {
          state: "Failed",
          category: "Other",
          errorMessage: "dpkg was interrupted",
          isRequired: false,
        }),
        update("u3", "curl 8.14.1-2", {
          activeJob: {
            jobId: "j9",
            jobStatus: "Running",
            itemStatus: "Downloading",
            downloadPercent: 30,
            installPercent: null,
            jobType: "InstallUpdates",
          },
        }),
      ],
    }),
    ...extra,
  };
}

describe("device patches", () => {
  it("shows the device's patch status and policy, and installs chosen updates later", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      deviceRoutes(LINKED, {
        "POST /patching/install": ok({
          succeeded: 1,
          failed: 0,
          results: [{ deviceId: "d1", deviceName: "WEB-01", ok: true, jobId: "j1" }],
        }),
        "GET /patching/devices/:id/jobs": ok({
          items: [],
          page: 1,
          pageSize: 50,
          totalCount: 0,
        }),
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    expect(await main().findByText("openssl 3.5.7-1~deb13u3")).toBeInTheDocument();
    expect(main().getByText("Exploited in the wild")).toBeInTheDocument();
    expect(main().getByText("dpkg was interrupted")).toBeInTheDocument();
    expect(main().getByText("Downloading · 30%")).toBeInTheDocument();
    expect(main().getByText("Saturday at 02:00 for 3 hours (Europe/Paris)")).toBeInTheDocument();
    expect(main().getByText("Security, Servicing stack")).toBeInTheDocument();
    expect(main().getByText(/1 fixes a vulnerability exploited in the wild/)).toBeInTheDocument();
    // An update already being installed cannot be chosen again.
    expect(main().queryByLabelText("Select curl 8.14.1-2")).not.toBeInTheDocument();
    // With an EasyPatch server of its own, its console is a link away, on the matching page.
    expect(main().getByRole("link", { name: "Open in EasyPatch" })).toHaveAttribute("href", "/go/to-easypatch?device=d1&tab=updates");
    expect(main().getByRole("link", { name: "openssl 3.5.7-1~deb13u3" })).toHaveAttribute("href", "/go/to-easypatch?update=u1");
    // No restart is pending, so none is offered.
    expect(main().queryByRole("button", { name: "Restart…" })).not.toBeInTheDocument();

    await user.click(main().getByLabelText("Select openssl 3.5.7-1~deb13u3"));
    await user.click(main().getByLabelText("Select tzdata 2026c-0+deb13u1"));
    await user.click(main().getByRole("button", { name: "Install selected…" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Install 2 updates on WEB-01",
    });
    // What EasyPatch would install, from the last scan.
    expect(await within(dialog).findByText("2 updates")).toBeInTheDocument();
    expect(within(dialog).getByText(/The agent scans again before installing/)).toBeInTheDocument();
    expect(server.call("GET /patching/devices/:id/install-preview").query.getAll("updateId")).toEqual(["u1", "u2"]);
    const at = within(dialog).getByLabelText("Install at");
    await user.clear(at);
    await user.type(at, "2030-01-05T02:30");
    expect(within(dialog).getByRole("radio", { name: /^At/ })).toBeChecked();
    await user.click(within(dialog).getByRole("button", { name: "Schedule install" }));
    await waitFor(() => expect(server.callsTo("POST /patching/install")).toHaveLength(1));
    expect(server.call("POST /patching/install").body).toEqual({
      deviceIds: ["d1"],
      updateIds: ["u1", "u2"],
      scheduledAt: new Date("2030-01-05T02:30").toISOString(),
    });
    expect(await screen.findByText("Install scheduled on 1 device.")).toBeInTheDocument();
    // The jobs list opens to follow it.
    expect(await main().findByText("No patch jobs yet")).toBeInTheDocument();
  });

  it("restarts a server whose restart is pending once it is ticked", async () => {
    const user = userEvent.setup();
    const pending: DevicePatching = {
      ...LINKED,
      endpoint: { ...LINKED.endpoint!, summary: { ...LINKED.endpoint!.summary, rebootPending: true }, rebootPendingSince: T, rebootReasons: ["Windows Update"] },
    };
    const server = installFakeApi(
      deviceRoutes(pending, {
        "POST /patching/restart/plan": ok({
          serversKnown: false,
          devices: [{ deviceId: "d1", deviceName: "WEB-01", restart: true, server: true, online: true }],
        }),
        "POST /patching/restart": ok({ succeeded: 1, failed: 0, results: [{ deviceId: "d1", deviceName: "WEB-01", ok: true, jobId: "j8" }] }),
        "GET /patching/devices/:id/jobs": ok({ items: [], page: 1, pageSize: 50, totalCount: 0 }),
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    await main().findByText("openssl 3.5.7-1~deb13u3");
    expect(main().getByText("Windows Update")).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Restart…" }));
    const dialog = await screen.findByRole("dialog", { name: "Restart WEB-01" });
    // An EasyPatch server before 1.10.0 cannot tell servers apart, so every device waits for a tick.
    expect(await within(dialog).findByText("Tick each device to restart")).toBeInTheDocument();
    expect(within(dialog).getByText(/older than 1\.10\.0/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Restart" })).toBeDisabled();
    expect(within(dialog).getByRole("link", { name: "More restart options in EasyPatch" })).toHaveAttribute("href", "/go/to-easypatch?device=d1");
    await user.click(within(dialog).getByRole("checkbox", { name: "Restart WEB-01" }));
    await user.click(within(dialog).getByRole("button", { name: "Restart 1 device" }));
    await waitFor(() => expect(server.callsTo("POST /patching/restart")).toHaveLength(1));
    expect(server.call("POST /patching/restart").body).toEqual({ deviceIds: ["d1"], confirmServers: ["d1"] });
    expect(await screen.findByText("Restart requested on 1 device.")).toBeInTheDocument();
    expect(await main().findByText("No patch jobs yet")).toBeInTheDocument();
  });

  it("shows why a restart was refused", async () => {
    const user = userEvent.setup();
    const pending: DevicePatching = { ...LINKED, endpoint: { ...LINKED.endpoint!, summary: { ...LINKED.endpoint!.summary, rebootPending: true } } };
    installFakeApi(
      deviceRoutes(pending, {
        "POST /patching/restart/plan": ok({ serversKnown: true, devices: [{ deviceId: "d1", deviceName: "WEB-01", restart: true, server: false, online: true }] }),
        "POST /patching/restart": fail(422, "validation_failed", "Some fields need attention.", {
          confirmServers: "These are servers; confirm restarting them: WEB-01.",
        }),
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Restart…" }));
    const dialog = await screen.findByRole("dialog", { name: "Restart WEB-01" });
    expect(await within(dialog).findByText("Restarts")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Restart 1 device" }));
    expect(await within(dialog).findByText(/confirm restarting them: WEB-01/)).toBeInTheDocument();
  });

  it("shows why the server refused an install time", async () => {
    const user = userEvent.setup();
    installFakeApi(
      deviceRoutes(LINKED, {
        "POST /patching/install": fail(422, "validation_failed", "Some fields need attention.", { scheduledAt: "Choose a time within 31 days." }),
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Install updates…" }));
    const dialog = await screen.findByRole("dialog", { name: "Install updates on WEB-01" });
    await user.click(within(dialog).getByRole("radio", { name: /^At/ }));
    await user.click(within(dialog).getByRole("button", { name: "Schedule install" }));
    expect(await within(dialog).findByText("Choose a time within 31 days.")).toBeInTheDocument();
  });

  it("keeps the device when switching to EasyPatch, on the matching tab", async () => {
    const user = userEvent.setup();
    installFakeApi(
      deviceRoutes(LINKED, {
        "GET /patching/switch": ok({ show: true, answering: true }),
        "GET /patching/devices/:id/jobs": ok({ items: [], page: 1, pageSize: 50, totalCount: 0 }),
      }),
    );
    renderApp("/devices/d1?tab=patches");
    const products = within(await screen.findByRole("navigation", { name: "Products" }));
    const link = await products.findByRole("link", { name: "Open WEB-01 in EasyPatch" });
    expect(link).toHaveAttribute("href", "/go/to-easypatch?device=d1&tab=updates");
    await screen.findByRole("main");
    await user.click(await main().findByRole("radio", { name: "Jobs" }));
    expect(products.getByRole("link", { name: "Open WEB-01 in EasyPatch" })).toHaveAttribute("href", "/go/to-easypatch?device=d1&tab=jobs");
  });

  it("shows installed updates, history and jobs", async () => {
    const user = userEvent.setup();
    installFakeApi(
      deviceRoutes(LINKED, {
        "GET /patching/devices/:id/installed": ok({
          items: [
            update("u9", "libc6 2.41-12+deb13u1", {
              state: "Installed",
              installedAt: T,
            }),
          ],
        }),
        "GET /patching/devices/:id/history": ok({
          items: [
            {
              id: 7,
              updateGuid: null,
              title: "libc6 2.41-12+deb13u1",
              kbNumber: "",
              operation: "Installation",
              resultCode: 2,
              result: "Succeeded",
              hResult: "",
              errorDescription: "",
              date: T,
            },
          ],
          page: 1,
          pageSize: 50,
          totalCount: 120,
        }),
        "GET /patching/devices/:id/jobs": ok({
          items: [
            job("j1", {
              status: "Failed",
              errorMessage: "apt-get exited with 100",
            }),
          ],
          page: 1,
          pageSize: 50,
          totalCount: 1,
        }),
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    await main().findByText("openssl 3.5.7-1~deb13u3");
    await user.click(main().getByRole("radio", { name: "Installed" }));
    expect(await main().findByText("libc6 2.41-12+deb13u1")).toBeInTheDocument();
    await user.click(main().getByRole("radio", { name: "History" }));
    expect(await main().findByText("Installation")).toBeInTheDocument();
    expect(main().getByText("Page 1 of 3")).toBeInTheDocument();
    await user.click(main().getByRole("radio", { name: "Jobs" }));
    expect(await main().findByText("apt-get exited with 100")).toBeInTheDocument();
  });

  it("tells a device that was never scanned from one with nothing to install", async () => {
    const never = {
      ...LINKED,
      endpoint: {
        ...LINKED.endpoint!,
        summary: {
          ...LINKED.endpoint!.summary,
          lastScanAt: null,
          complianceStatus: "NeverScanned" as const,
        },
      },
    };
    installFakeApi(
      deviceRoutes(never, {
        "GET /patching/devices/:id/updates": ok({ items: [] }),
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    expect(await main().findByText("Not scanned yet")).toBeInTheDocument();
    expect(main().getByText("Known after the first scan")).toBeInTheDocument();
    expect(main().getByRole("radio", { name: "To install" })).toBeInTheDocument();
    expect(main().queryByText("Nothing to install")).not.toBeInTheDocument();
  });

  it("explains why a device is not patched from EasyRMM", async () => {
    installFakeApi(
      deviceRoutes({
        deviceId: "d1",
        link: "unlinked",
        reason: 'Serial numbers differ: EasyPatch has "A", EasyRMM has "B".',
        canManage: true,
        canSchedule: false,
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    expect(await main().findByText("Not patched from EasyRMM")).toBeInTheDocument();
    expect(main().getByText(/Serial numbers differ/)).toBeInTheDocument();
  });

  it("installs the EasyPatch agent on a device that has none, and follows the install", async () => {
    const user = userEvent.setup();
    let install: DevicePatching["install"];
    const server = installFakeApi(
      deviceRoutes(
        { deviceId: "d1", link: "none", canManage: true, canSchedule: false },
        {
          "GET /patching/devices/:id": () => ok({ deviceId: "d1", link: "none", canManage: true, canSchedule: false, install }),
          "POST /patching/agent-install": () => {
            install = { state: "waiting", automatic: false, requestedBy: "alex@example.com", requestedAt: T, attempts: 0 };
            return ok({ succeeded: 1, failed: 0, results: [{ deviceId: "d1", deviceName: "WEB-01", ok: true }] });
          },
        },
      ),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    expect(await main().findByText(/EasyRMM can install it and enroll it/)).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Install EasyPatch agent…" }));
    const dialog = await screen.findByRole("dialog", { name: "Install the EasyPatch agent on WEB-01" });
    await user.click(within(dialog).getByRole("button", { name: "Install EasyPatch agent" }));
    await waitFor(() => expect(server.callsTo("POST /patching/agent-install")).toHaveLength(1));
    expect(server.call("POST /patching/agent-install").body).toEqual({ deviceIds: ["d1"] });
    // While it waits there is nothing to start again.
    expect(await main().findByText("EasyPatch agent install waiting")).toBeInTheDocument();
    expect(main().getByText(/Requested by alex@example.com/)).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Install EasyPatch agent…" })).not.toBeInTheDocument();
  });

  it("stops patching a device, and allows it again", async () => {
    const user = userEvent.setup();
    let stopped: DevicePatching["stopped"];
    let removal: DevicePatching["removal"];
    const server = installFakeApi(
      deviceRoutes(
        { deviceId: "d1", link: "none", canManage: true, canSchedule: false },
        {
          "GET /patching/devices/:id": () => ok({ deviceId: "d1", link: "none", canManage: true, canSchedule: false, stopped, removal }),
          "POST /patching/stop": () => {
            stopped = { at: T, by: "alex@example.com" };
            removal = { reason: "opted_out", state: "uninstalling", requestedAt: T };
            return ok({ succeeded: 1, failed: 0, results: [{ deviceId: "d1", deviceName: "WEB-01", ok: true, message: "Patching stopped." }] });
          },
          "POST /patching/allow": () => {
            stopped = undefined;
            removal = undefined;
            return ok({
              succeeded: 1,
              failed: 0,
              results: [{ deviceId: "d1", deviceName: "WEB-01", ok: true, message: "Patching allowed again. EasyRMM installs the EasyPatch agent shortly." }],
            });
          },
        },
      ),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Stop patching…" }));
    const dialog = await screen.findByRole("dialog", { name: "Stop patching WEB-01?" });
    expect(within(dialog).getByText(/installs no EasyPatch agent on the device again/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Stop patching" }));
    await waitFor(() => expect(server.callsTo("POST /patching/stop")).toHaveLength(1));
    expect(server.call("POST /patching/stop").body).toEqual({ deviceIds: ["d1"] });

    expect(await main().findByText("Patching stopped")).toBeInTheDocument();
    expect(main().getByText(/Stopped by alex@example.com/)).toBeInTheDocument();
    expect(main().getByText(/The EasyPatch agent is uninstalling itself/)).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Install EasyPatch agent…" })).not.toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Allow patching again" }));
    await waitFor(() => expect(server.callsTo("POST /patching/allow")).toHaveLength(1));
    expect(await screen.findByText("Patching allowed again. EasyRMM installs the EasyPatch agent shortly.")).toBeInTheDocument();
    expect(await main().findByRole("button", { name: "Install EasyPatch agent…" })).toBeInTheDocument();
  });

  it("does not offer to stop or allow patching without patch.manage", async () => {
    installFakeApi(deviceRoutes({ deviceId: "d1", link: "none", canManage: false, canSchedule: false, stopped: { at: T } }));
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    expect(await main().findByText(/Stopped by a removed user/)).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Allow patching again" })).not.toBeInTheDocument();
  });

  it("offers to try a failed install again, and explains automatic ones", async () => {
    installFakeApi(
      deviceRoutes({
        deviceId: "d1",
        link: "none",
        canManage: true,
        canSchedule: false,
        install: { state: "failed", automatic: true, requestedAt: T, attempts: 3, error: "This device does not run systemd, which the EasyPatch agent needs." },
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    expect(await main().findByText("EasyPatch agent install failed")).toBeInTheDocument();
    expect(main().getByText(/does not run systemd/)).toBeInTheDocument();
    expect(main().getByText(/Started by the organization's automatic installs/)).toBeInTheDocument();
    expect(main().getByText(/attempt 3/)).toBeInTheDocument();
    expect(main().getByRole("button", { name: "Try the install again…" })).toBeInTheDocument();
  });

  it("does not offer the install without the right to patch", async () => {
    installFakeApi(
      deviceRoutes({
        deviceId: "d1",
        link: "none",
        canManage: false,
        canSchedule: false,
        install: { state: "succeeded", automatic: false, requestedAt: T, attempts: 1 },
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    expect(await main().findByText("EasyPatch agent installed")).toBeInTheDocument();
    expect(main().getByText(/Requested by a removed user/)).toBeInTheDocument();
    expect(main().getByText(/Install the EasyPatch agent and enroll it with your EasyPatch server/)).toBeInTheDocument();
    expect(main().queryByRole("button", { name: /Install EasyPatch agent/ })).not.toBeInTheDocument();
  });

  it("has no Patches tab until EasyPatch is set up", async () => {
    installFakeApi({
      ...deviceRoutes(LINKED),
      "GET /patching": ok({
        configured: false,
        canOperate: false,
        canSchedule: false,
      }),
    });
    renderApp("/devices/d1");
    await screen.findByRole("main");
    expect(await screen.findByRole("tab", { name: "Hardware" })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Patches" })).not.toBeInTheDocument();
  });
});

const UNSET: EasyPatchConnection = {
  configured: false,
  bundled: false,
  url: "",
  caCert: "",
  serverVersion: "",
  publicUrl: "",
  capabilities: [],
  canOperate: false,
};
const SET: EasyPatchConnection = {
  configured: true,
  bundled: false,
  url: "https://patch.example.com",
  caCert: "",
  serverVersion: "1.9.0",
  publicUrl: "https://patch.example.com",
  capabilities: [],
  canOperate: true,
  checkedAt: T,
  updatedAt: T,
  updatedBy: "alex@example.com",
};
const ORGS: EasyPatchOrganizations = {
  easyPatch: [
    {
      id: "ep-o1",
      name: "Northwind Patch",
      isActive: true,
      siteCount: 1,
      endpointCount: 3,
    },
    {
      id: "ep-o2",
      name: "Contoso Patch",
      isActive: true,
      siteCount: 1,
      endpointCount: 1,
    },
  ],
  links: [
    {
      organizationId: "o1",
      organizationName: "Northwind Traders",
      easyPatchId: "ep-o1",
      easyPatchName: "Northwind Patch",
      linkedAt: T,
      autoInstall: false,
      devices: { linked: 2, unlinked: 1, pending: 0 },
    },
  ],
};

describe("EasyPatch settings", () => {
  it("connects to EasyPatch, checking the token first", async () => {
    const user = userEvent.setup();
    let saved = false;
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/easypatch": () => ok(saved ? SET : UNSET),
      "GET /settings/easypatch/organizations": ok(ORGS),
      "GET /settings/easypatch/devices": ok({ items: [] }),
      "GET /audit": ok({ items: [] }),
      "PUT /settings/easypatch": (r) => {
        if ((r.body as { token: string }).token === "ept_wrong")
          return fail(422, "validation_failed", "Some fields need attention.", {
            token: "EasyPatch refused the token: the API token is not valid",
          });
        saved = true;
        return ok(SET);
      },
    });
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await screen.findByRole("heading", { name: "EasyPatch", level: 1 })).toBeInTheDocument();
    expect(await main().findByText("Not set up")).toBeInTheDocument();
    await user.type(main().getByLabelText(/^Address/), "https://patch.example.com");
    await user.type(main().getByLabelText(/^API token/), "ept_wrong");
    await user.click(main().getByRole("button", { name: "Connect" }));
    expect(await main().findByText(/EasyPatch refused the token/)).toBeInTheDocument();
    await user.clear(main().getByLabelText(/^API token/));
    await user.type(main().getByLabelText(/^API token/), "ept_right");
    await user.click(main().getByRole("button", { name: "Connect" }));
    await waitFor(() => expect(server.callsTo("PUT /settings/easypatch")).toHaveLength(2));
    expect(server.call("PUT /settings/easypatch", 1).body).toEqual({
      url: "https://patch.example.com",
      token: "ept_right",
      caCert: "",
    });
    expect(await screen.findByText("Connected to EasyPatch 1.9.0")).toBeInTheDocument();
    expect(await main().findByText("Connected")).toBeInTheDocument();
    expect(main().getByText("Open EasyPatch").closest("a")).toHaveAttribute("href", "/go/to-easypatch");
    expect(main().getByText(/Not supported by this EasyPatch/)).toBeInTheDocument();
    // The stored token is kept unless a new one is pasted.
    expect(main().getByLabelText(/^API token/)).toHaveAttribute("placeholder", "Stored");
  });

  it("links organizations and lists devices that are not linked", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /organizations": ok({
        items: [org("o1", "Northwind Traders"), org("o2", "Contoso")],
      }),
      "GET /settings/easypatch": ok({
        ...SET,
        canOperate: false,
        lastError: "Cannot reach EasyPatch: connection refused",
        lastErrorAt: "2026-11-16T11:00:00Z",
      }),
      "GET /settings/easypatch/organizations": ok(ORGS),
      "GET /settings/easypatch/devices": ok({
        items: [
          {
            deviceId: "d3",
            deviceName: "APP-01",
            organizationName: "Northwind Traders",
            state: "unlinked",
            reason: "Host names differ.",
            checkedAt: T,
          },
        ],
      }),
      "PUT /settings/easypatch/organizations/:id": noContent,
      "PATCH /settings/easypatch/organizations/:id": noContent,
      "DELETE /settings/easypatch/organizations/:id": noContent,
      "POST /settings/easypatch/check": ok(SET),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("Failing")).toBeInTheDocument();
    expect(main().getByText("Read only: views")).toBeInTheDocument();
    expect(await main().findByText("Host names differ.")).toBeInTheDocument();
    expect(main().getByText(/2 devices patched/)).toBeInTheDocument();

    // Automatic installs of the EasyPatch agent, for linked organizations only.
    await user.click(main().getByLabelText("Install the EasyPatch agent automatically in Northwind Traders"));
    await waitFor(() => expect(server.callsTo("PATCH /settings/easypatch/organizations/:id")).toHaveLength(1));
    expect(server.call("PATCH /settings/easypatch/organizations/:id").params.id).toBe("o1");
    expect(server.call("PATCH /settings/easypatch/organizations/:id").body).toEqual({ autoInstall: true });
    expect(await screen.findByText(/EasyRMM installs the EasyPatch agent on devices in Northwind Traders that have none/)).toBeInTheDocument();
    expect(main().queryByLabelText("Install the EasyPatch agent automatically in Contoso")).not.toBeInTheDocument();

    // Contoso can only take the EasyPatch organization nobody has.
    const contoso = main().getByLabelText("Contoso");
    expect(within(contoso).queryByRole("option", { name: "Northwind Patch" })).not.toBeInTheDocument();
    await user.selectOptions(contoso, "ep-o2");
    await waitFor(() => expect(server.callsTo("PUT /settings/easypatch/organizations/:id")).toHaveLength(1));
    expect(server.call("PUT /settings/easypatch/organizations/:id").params.id).toBe("o2");
    expect(server.call("PUT /settings/easypatch/organizations/:id").body).toEqual({ easyPatchId: "ep-o2" });

    await user.selectOptions(main().getByLabelText("Northwind Traders"), "");
    const confirm = await screen.findByRole("dialog", {
      name: "Stop patching Northwind Traders from EasyRMM?",
    });
    await user.click(within(confirm).getByRole("button", { name: "Unlink" }));
    await waitFor(() => expect(server.callsTo("DELETE /settings/easypatch/organizations/:id")).toHaveLength(1));

    await user.click(main().getByRole("button", { name: "Check now" }));
    await waitFor(() => expect(server.callsTo("POST /settings/easypatch/check")).toHaveLength(1));
  });

  it("removes the server after confirming", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/easypatch": ok(SET),
      "GET /settings/easypatch/organizations": ok({ ...ORGS, links: [] }),
      "GET /settings/easypatch/devices": ok({ items: [] }),
      "DELETE /settings/easypatch": noContent,
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Remove" }));
    const confirm = await screen.findByRole("dialog", {
      name: "Remove EasyPatch?",
    });
    await user.click(within(confirm).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(server.callsTo("DELETE /settings/easypatch")).toHaveLength(1));
    expect(await screen.findByText(/EasyPatch removed/)).toBeInTheDocument();
  });
});

describe("job requester", () => {
  it("names the person an API token acted for when EasyPatch records it", () => {
    expect(requester("tess@example.com")).toBe("tess@example.com");
    expect(requester("token:easyrmm")).toBe("API token easyrmm");
    expect(requester("token:EasyRMM for alice@example.com")).toBe("alice@example.com, through API token EasyRMM");
    expect(requester("token:Patch for prod for bob@example.com")).toBe("bob@example.com, through API token Patch for prod");
    expect(requester("token:Patch for prod")).toBe("API token Patch for prod");
  });
});

describe("EasyPatch agent activity", () => {
  it("is shown in words, and not at all when idle", () => {
    expect(activityText("UpdateScan")).toBe("Scanning for updates");
    expect(activityText("Downloading updates for the maintenance window")).toBe("Downloading updates for the maintenance window");
    expect(activityText("Idle")).toBeNull();
    expect(activityText(null)).toBeNull();
  });
});

describe("maintenance text", () => {
  it("says when automatic installs run", () => {
    expect(maintenanceText(POLICY)).toBe("Saturday at 02:00 for 3 hours (Europe/Paris)");
    expect(maintenanceText({ ...POLICY, autoInstallEnabled: false })).toMatch(/^Off/);
    expect(maintenanceText({ ...POLICY, maintenanceStart: null })).toMatch(/any time/);
    expect(
      maintenanceText({
        ...POLICY,
        maintenanceDays: null,
        maintenanceDurationMinutes: 90,
      }),
    ).toBe("Every day at 02:00 for 90 minutes (Europe/Paris)");
  });
});

// The device's Patches tab (one-product plan, C1): exclusions, removals, messages, agent updates and the policy.
const WIN = device("d2", "APP-01", {
  platform: "windows",
  osDescription: "Windows Server 2025 Standard",
  agent: AGENT,
});

const CU = "2026-11 Cumulative Update for Windows Server 2025 (KB5070001)";

const WIN_POLICY: PatchPolicy = {
  ...POLICY,
  excludedKbs: ["KB5005565"],
  restartSchedule: {
    enabled: true,
    days: [0],
    time: "03:00",
    condition: "OnlyIfPending",
    mode: "PromptWithDeadline",
    countdownMinutes: 15,
    deadlineMinutes: 240,
    expiryMinutes: 60,
  },
  windowsUpdate: {
    automaticUpdates: { mode: "NotifyDownload", scheduledInstallDay: 0, scheduledInstallHour: 3 },
    featureUpdates: { deferDays: 180, targetProductVersion: "", targetReleaseVersion: "" },
    qualityUpdates: null,
    restartBehavior: null,
  },
  applicationUpdates: { enabled: true, approvedApps: ["Mozilla.Firefox"] },
  sources: {
    AutoInstallEnabled: "Organization",
    MaintenanceWindow: "Site",
    AllowedCategories: "Global",
    RestartSchedule: "Endpoint",
    ApplicationUpdates: "Tag",
    "WindowsUpdate.AutomaticUpdates": "Organization",
  },
  sourceTags: { ApplicationUpdates: "Workstations" },
};

const WIN_LINKED: DevicePatching = {
  ...LINKED,
  deviceId: "d2",
  endpoint: {
    ...LINKED.endpoint!,
    summary: endpoint("e2", "app-01", {
      platform: "Windows",
      operatingSystem: "Windows Server 2025 Standard",
      rebootPending: true,
    }),
    rebootPendingSince: T,
    agentCapabilities: ["restart", "self-update", "uninstall", "notify-user", "tray", "uninstall-updates"],
    signedInUsers: 2,
    trayConnectedSessions: 1,
    agentUpdate: {
      supported: true,
      automaticUpdates: false,
      availableVersion: "1.10.1",
      code: "",
      message: "",
      packageFormat: "msi",
    },
    restart: {
      updates: [{ updateGuid: "k1", title: CU, kbNumbers: ["5070001"], source: "Installed", installedAt: T }],
      servicingPackages: ["Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.7171.1.3"],
      fileOperations: [],
      fileOperationCount: 3,
      detailsSupported: true,
    },
    windowsUpdatePolicy: {
      groups: [
        {
          group: "AutomaticUpdates",
          state: "Conflict",
          message: "A Group Policy object also sets this.",
          appliedAt: T,
          conflictingValues: ["AUOptions"],
        },
      ],
      mdmUpdatePoliciesPresent: true,
    },
  },
  policy: WIN_POLICY,
};

const PRESETS = {
  items: [
    {
      preset: "SaveYourWork",
      title: "Please save your work",
      body: "Your IT team is about to carry out maintenance on this computer. Please save your work.",
      needsRestartTime: false,
    },
    {
      preset: "RestartScheduled",
      title: "Restart scheduled",
      body: "This computer will restart at {time}. Please save your work before then.",
      needsRestartTime: true,
    },
  ],
};

function winRoutes(patching: DevicePatching = WIN_LINKED, extra: Record<string, FakeHandler | FakeReply> = {}) {
  return deviceRoutes(patching, {
    "GET /devices/:id": ok(WIN),
    "GET /patching/devices/:id/updates": ok({
      items: [
        update("k1", CU, { package: null, kbNumber: "5070001", state: "PendingReboot" }),
        update("k2", "2026-11 .NET Framework update (KB5005565)", { package: null, kbNumber: "5005565", state: "Excluded", isExcluded: true }),
        update("k3", "Microsoft Defender Antivirus platform update", { package: null, kbNumber: "4052623" }),
      ],
    }),
    "GET /patching/devices/:id/installed": ok({
      items: [
        update("k8", "2026-10 Cumulative Update for Windows Server 2025 (KB5066835)", { package: null, kbNumber: "5066835", state: "Installed", installedAt: T }),
      ],
    }),
    "GET /patching/devices/:id/jobs": ok({ items: [], page: 1, pageSize: 50, totalCount: 0 }),
    "GET /patching/messages": ok(PRESETS),
    ...extra,
  });
}

const queued = (jobId: string): PatchActionResult => ({
  succeeded: 1,
  failed: 0,
  results: [{ deviceId: "d2", deviceName: "APP-01", ok: true, jobId }],
});

const refused = (message: string): PatchActionResult => ({
  succeeded: 0,
  failed: 1,
  results: [{ deviceId: "d2", deviceName: "APP-01", ok: false, message }],
});

describe("device patch actions", () => {
  it("excludes an update on the device and includes it again", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      deviceRoutes(LINKED, {
        "GET /patching/devices/:id/updates": ok({
          items: [
            update("u1", "openssl 3.5.7-1~deb13u3"),
            update("u5", "tzdata 2026c-0+deb13u1", { state: "Excluded", isExcluded: true }),
          ],
        }),
        "POST /patching/devices/:id/exclusions": noContent,
        "DELETE /patching/devices/:id/exclusions/:update": noContent,
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Exclude openssl 3.5.7-1~deb13u3…" }));
    const dialog = await screen.findByRole("dialog", { name: "Exclude this update on WEB-01?" });
    // A package version is excluded, not the package.
    expect(within(dialog).getByText(/This version only/)).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Reason (optional)"), "  Breaks the billing app  ");
    await user.click(within(dialog).getByRole("button", { name: "Exclude update" }));
    await waitFor(() => expect(server.callsTo("POST /patching/devices/:id/exclusions")).toHaveLength(1));
    expect(server.call("POST /patching/devices/:id/exclusions").params).toEqual({ id: "d1" });
    expect(server.call("POST /patching/devices/:id/exclusions").body).toEqual({ updateId: "u1", reason: "Breaks the billing app" });
    expect(await screen.findByText("Excluded on WEB-01.")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());

    // An excluded update can be included again; it is neither installed nor excluded twice.
    expect(main().queryByRole("button", { name: "Exclude tzdata 2026c-0+deb13u1…" })).not.toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Include tzdata 2026c-0+deb13u1" }));
    await waitFor(() => expect(server.callsTo("DELETE /patching/devices/:id/exclusions/:update")).toHaveLength(1));
    expect(server.call("DELETE /patching/devices/:id/exclusions/:update").params).toEqual({ id: "d1", update: "u5" });
    expect(await screen.findByText("Included again on WEB-01.")).toBeInTheDocument();
  });

  it("says why an exclusion or an inclusion was refused", async () => {
    const user = userEvent.setup();
    installFakeApi(
      deviceRoutes(LINKED, {
        "GET /patching/devices/:id/updates": ok({
          items: [update("u1", "openssl 3.5.7-1~deb13u3"), update("u5", "tzdata 2026c-0+deb13u1", { state: "Excluded", isExcluded: true })],
        }),
        "POST /patching/devices/:id/exclusions": fail(400, "validation_failed", "Check the highlighted fields.", {
          reason: "Keep the reason under 500 characters.",
        }),
        "DELETE /patching/devices/:id/exclusions/:update": fail(502, "easypatch_unavailable", "EasyPatch: the server did not answer."),
      }),
    );
    renderApp("/devices/d1?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Exclude openssl 3.5.7-1~deb13u3…" }));
    const dialog = await screen.findByRole("dialog", { name: "Exclude this update on WEB-01?" });
    await user.click(within(dialog).getByRole("button", { name: "Exclude update" }));
    expect(await within(dialog).findByText("Keep the reason under 500 characters.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await user.click(main().getByRole("button", { name: "Include tzdata 2026c-0+deb13u1" }));
    expect(await screen.findByText("EasyPatch: the server did not answer.")).toBeInTheDocument();
  });

  it("shows a Windows device's users, pending restart and agent, and leaves policy exclusions to the policy", async () => {
    installFakeApi(winRoutes());
    renderApp("/devices/d2?tab=patches");
    await screen.findByRole("main");
    expect(await main().findByText("Microsoft Defender Antivirus platform update")).toBeInTheDocument();
    // Who is signed in, and whether the EasyPatch icon can reach them.
    expect(main().getByText("2 users signed in")).toBeInTheDocument();
    expect(main().getByText("The EasyPatch icon is running in 1 of 2 sessions")).toBeInTheDocument();
    // What the pending restart is for.
    expect(main().getByText(CU, { selector: "span" })).toBeInTheDocument();
    expect(main().getByText(/installed, takes effect at the restart/)).toBeInTheDocument();
    expect(main().getByText("1 servicing package waiting")).toBeInTheDocument();
    expect(main().getByText("3 files to change at the restart")).toBeInTheDocument();
    // The agent: a newer version, which this policy leaves to a technician.
    expect(main().getByText("1.10.1 available")).toBeInTheDocument();
    expect(main().getByRole("button", { name: "Update agent…" })).toBeInTheDocument();
    // The policy excludes KB5005565 everywhere: this device cannot include it on its own.
    expect(main().getByText("By the policy's excluded KBs")).toBeInTheDocument();
    expect(main().queryByRole("button", { name: /^Include/ })).not.toBeInTheDocument();
    // An installed update waiting for its restart can be removed; a missing one excluded.
    expect(main().getByRole("button", { name: `Remove ${CU}…` })).toBeInTheDocument();
    expect(main().getByRole("button", { name: "Exclude Microsoft Defender Antivirus platform update…" })).toBeInTheDocument();
  });

  it("messages the device's users with a restart time", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(winRoutes(WIN_LINKED, { "POST /patching/notify": ok(queued("j5")) }));
    renderApp("/devices/d2?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Message users…" }));
    const dialog = await screen.findByRole("dialog", { name: "Message the users of APP-01" });
    expect(await within(dialog).findByRole("radio", { name: /^Please save your work/ })).toBeChecked();
    await user.click(within(dialog).getByRole("radio", { name: /Restart scheduled/ }));
    const at = within(dialog).getByLabelText("Restart time the message names");
    await user.clear(at);
    await user.type(at, "2030-01-05T18:00");
    // The message shows the time the users will read.
    const named = new Date("2030-01-05T18:00").toLocaleString([], { weekday: "long", hour: "numeric", minute: "2-digit" });
    expect(within(dialog).getByText(`This computer will restart at ${named}. Please save your work before then.`)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Send message" }));
    await waitFor(() => expect(server.callsTo("POST /patching/notify")).toHaveLength(1));
    expect(server.call("POST /patching/notify").body).toEqual({
      deviceIds: ["d2"],
      preset: "RestartScheduled",
      restartAt: new Date("2030-01-05T18:00").toISOString(),
    });
    expect(await screen.findByText("Message sent to APP-01. It shows at the agent's next check-in.")).toBeInTheDocument();
  });

  it("sends a message without a time, and shows EasyPatch's refusal", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      winRoutes(WIN_LINKED, { "POST /patching/notify": ok(refused("The EasyPatch agent on APP-01 is too old to show messages.")) }),
    );
    renderApp("/devices/d2?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Message users…" }));
    const dialog = await screen.findByRole("dialog", { name: "Message the users of APP-01" });
    await within(dialog).findByRole("radio", { name: /^Please save your work/ });
    expect(within(dialog).queryByLabelText("Restart time the message names")).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Send message" }));
    expect(await within(dialog).findByText("The EasyPatch agent on APP-01 is too old to show messages.")).toBeInTheDocument();
    expect(server.call("POST /patching/notify").body).toEqual({ deviceIds: ["d2"], preset: "SaveYourWork" });
  });

  it("updates the agent, and shows EasyPatch's refusal", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      winRoutes(WIN_LINKED, {
        "POST /patching/agent-update": ok(refused("APP-01's agent has no release key; reinstall it once to update it.")),
      }),
    );
    renderApp("/devices/d2?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Update agent…" }));
    const dialog = await screen.findByRole("dialog", { name: "Update the EasyPatch agent on APP-01?" });
    expect(within(dialog).getByText(/From 1.9.0 to 1.10.1/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Update agent" }));
    expect(await within(dialog).findByText("APP-01's agent has no release key; reinstall it once to update it.")).toBeInTheDocument();
    expect(server.call("POST /patching/agent-update").body).toEqual({ deviceIds: ["d2"] });

    server.on("POST /patching/agent-update", ok(queued("j6")));
    await user.click(within(dialog).getByRole("button", { name: "Update agent" }));
    expect(await screen.findByText("Agent update queued on APP-01.")).toBeInTheDocument();
  });

  it("removes an installed update, with or without excluding it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      winRoutes(WIN_LINKED, {
        "POST /patching/devices/:id/updates/:update/remove": ok(queued("j7")),
      }),
    );
    renderApp("/devices/d2?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("radio", { name: "Installed" }));
    const name = "2026-10 Cumulative Update for Windows Server 2025 (KB5066835)";
    await user.click(await main().findByRole("button", { name: `Remove ${name}…` }));
    const dialog = await screen.findByRole("dialog", { name: "Remove this update from APP-01?" });
    // Excluding it too is the default, so that EasyPatch does not install it again.
    const block = within(dialog).getByRole("checkbox", { name: "Exclude it on APP-01" });
    expect(block).toBeChecked();
    await user.type(within(dialog).getByLabelText("Reason (optional)"), "Breaks printing");
    await user.click(block);
    expect(within(dialog).queryByLabelText("Reason (optional)")).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Remove update" }));
    await waitFor(() => expect(server.callsTo("POST /patching/devices/:id/updates/:update/remove")).toHaveLength(1));
    const call = server.call("POST /patching/devices/:id/updates/:update/remove");
    expect(call.params).toEqual({ id: "d2", update: "k8" });
    expect(call.body).toEqual({ block: false, reason: "" });
    expect(await screen.findByText("Removal queued on APP-01.")).toBeInTheDocument();
    // The jobs list opens to follow it.
    expect(await main().findByText("No patch jobs yet")).toBeInTheDocument();
  });

  it("shows a removal EasyPatch refused in the dialog", async () => {
    const user = userEvent.setup();
    installFakeApi(
      winRoutes(WIN_LINKED, {
        "POST /patching/devices/:id/updates/:update/remove": ok(refused("EasyPatch: KB5070001 is already being removed.")),
      }),
    );
    renderApp("/devices/d2?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: `Remove ${CU}…` }));
    const dialog = await screen.findByRole("dialog", { name: "Remove this update from APP-01?" });
    await user.click(within(dialog).getByRole("button", { name: "Remove update" }));
    expect(await within(dialog).findByText("EasyPatch: KB5070001 is already being removed.")).toBeInTheDocument();
  });

  it("shows the whole effective policy, with the layer that set each value", async () => {
    const user = userEvent.setup();
    installFakeApi(winRoutes());
    renderApp("/devices/d2?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Whole policy" }));
    expect(await main().findByRole("radio", { name: "Policy" })).toBeChecked();
    const installing = within(main().getByRole("heading", { name: "Installing" }).closest("section")!);
    expect(installing.getByText("Saturday at 02:00 for 3 hours (Europe/Paris)")).toBeInTheDocument();
    expect(installing.getByText("KB5005565")).toBeInTheDocument();
    expect(installing.getByText("winget, for Mozilla.Firefox")).toBeInTheDocument();
    expect(installing.getByText("Tag: Workstations")).toBeInTheDocument();
    expect(installing.getByText("Site")).toBeInTheDocument();
    expect(installing.getByText("Default")).toBeInTheDocument();
    expect(
      main().getByText("Sunday at 03:00, only when a restart is pending, ask users, restart after 4 hours at the latest (Europe/Paris)"),
    ).toBeInTheDocument();
    expect(main().getByText("This device")).toBeInTheDocument();
    // Windows Update's own settings, and how the device applied them.
    expect(main().getByText("Notify before downloading and installing")).toBeInTheDocument();
    expect(main().getByText("Defer 180 days")).toBeInTheDocument();
    expect(main().getByText("Conflict")).toBeInTheDocument();
    expect(main().getByText("A Group Policy object also sets this.")).toBeInTheDocument();
    expect(main().getByText(/Update policies from MDM, such as Intune/)).toBeInTheDocument();
    expect(main().getByRole("link", { name: "Change in EasyPatch" })).toHaveAttribute("href", "/go/to-easypatch?device=d2&tab=policy");
  });

  it("previews an install, with what it leaves out and why", async () => {
    const user = userEvent.setup();
    installFakeApi(
      winRoutes(WIN_LINKED, {
        "GET /patching/devices/:id/install-preview": ok({
          ...PREVIEW,
          items: [],
          skipped: [{ updateGuid: "k2", title: "2026-11 .NET Framework update (KB5005565)", kbNumber: "5005565", category: "Updates", reason: "Excluded" }],
          totalSizeBytes: 0,
          warnings: ["The maintenance window is closed; the install waits for it unless it is started by hand."],
        }),
      }),
    );
    renderApp("/devices/d2?tab=patches");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Install updates…" }));
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("Nothing would be installed")).toBeInTheDocument();
    expect(within(dialog).getByText("2026-11 .NET Framework update (KB5005565)")).toBeInTheDocument();
    expect(within(dialog).getByText(/The maintenance window is closed/)).toBeInTheDocument();
    // The agent scans again before installing, so an install can still be started.
    expect(within(dialog).getByRole("button", { name: "Install now" })).toBeEnabled();
  });

  it("hides EasyPatch links where it has no console of its own", async () => {
    const user = userEvent.setup();
    installFakeApi(winRoutes(WIN_LINKED, { "GET /patching": ok({ ...READY, consoleUrl: undefined }) }));
    renderApp("/devices/d2?tab=patches");
    await screen.findByRole("main");
    expect(await main().findByText("Microsoft Defender Antivirus platform update")).toBeInTheDocument();
    expect(main().queryByRole("link", { name: "Microsoft Defender Antivirus platform update" })).not.toBeInTheDocument();
    expect(main().queryByRole("link", { name: "Open in EasyPatch" })).not.toBeInTheDocument();
    await user.click(main().getByRole("radio", { name: "Policy" }));
    expect(await main().findByRole("heading", { name: "Installing" })).toBeInTheDocument();
    expect(main().queryByRole("link", { name: /EasyPatch/ })).not.toBeInTheDocument();
  });

  it("offers a viewer nothing that changes the device", async () => {
    installFakeApi(winRoutes({ ...WIN_LINKED, canManage: false }));
    renderApp("/devices/d2?tab=patches");
    await screen.findByRole("main");
    expect(await main().findByText("Microsoft Defender Antivirus platform update")).toBeInTheDocument();
    expect(main().getByText("2 users signed in")).toBeInTheDocument();
    for (const name of [/^Exclude/, /^Include/, /^Remove/, "Message users…", "Update agent…"]) {
      expect(main().queryByRole("button", { name })).not.toBeInTheDocument();
    }
  });
});
