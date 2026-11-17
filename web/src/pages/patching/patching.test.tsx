import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  DevicePatching,
  EasyPatchConnection,
  EasyPatchOrganizations,
  PatchEndpoint,
  PatchFleet,
  PatchJobDetail,
  PatchJobView,
  PatchPolicy,
  PatchStatus,
  PatchUpdate,
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

const READY: PatchStatus = {
  configured: true,
  canOperate: true,
  canSchedule: false,
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
    // Without EasyPatch's address, there is nothing to open.
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

  it("opens EasyPatch's own console in a new tab", async () => {
    installFakeApi(patchingRoutes({ "GET /patching": ok({ ...READY, consoleUrl: "https://patch.example.com" }) }));
    renderApp("/patching");
    await screen.findByRole("main");
    // Role queries over the whole fleet table are slow; the link's text is enough to find it.
    const link = (await main().findByText("Open EasyPatch")).closest("a")!;
    expect(link).toHaveTextContent("Open EasyPatch (opens in a new tab)");
    expect(link).toHaveAttribute("href", "https://patch.example.com");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
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
};

function update(guid: string, title: string, extra: Partial<PatchUpdate> = {}): PatchUpdate {
  return {
    updateGuid: guid,
    title,
    kbNumber: "",
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
  },
  policy: POLICY,
};

function deviceRoutes(patching: DevicePatching, extra: Record<string, FakeHandler | FakeReply> = {}) {
  return {
    ...baseRoutes(TECH),
    ...unreportedRoutes(),
    "GET /devices/:id": ok(WEB),
    "GET /patching": ok(READY),
    "GET /patching/devices/:id": ok(patching),
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
    expect(main().getByText(/1 fix vulnerabilities exploited in the wild/)).toBeInTheDocument();
    // An update already being installed cannot be chosen again.
    expect(main().queryByLabelText("Select curl 8.14.1-2")).not.toBeInTheDocument();

    await user.click(main().getByLabelText("Select openssl 3.5.7-1~deb13u3"));
    await user.click(main().getByLabelText("Select tzdata 2026c-0+deb13u1"));
    await user.click(main().getByRole("button", { name: "Install selected…" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Install 2 updates on WEB-01",
    });
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
  url: "",
  caCert: "",
  serverVersion: "",
  publicUrl: "",
  capabilities: [],
  canOperate: false,
};
const SET: EasyPatchConnection = {
  configured: true,
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
    expect(main().getByText("Open EasyPatch").closest("a")).toHaveAttribute("href", "https://patch.example.com");
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
