import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PatchEndpoint, PatchFleet, PatchFleetDevice, PatchFleetUpdate, PatchHold, PatchStatus, PatchUpdateDevice, PatchUpdateView } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, type FakeHandler, type FakeReply } from "../../test/fakeApi";
import { renderApp } from "../../test/render";

// Patching's overview, its update list and an update's page.

const T = "2026-11-18T10:00:00Z";
const main = () => within(screen.getByRole("main"));

const TECH = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "patch.view", "patch.manage"],
});
const ORG_ADMIN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "patch.view", "patch.manage", "patch.configure"],
});
const VIEWER = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "patch.view"],
});

const READY: PatchStatus = { configured: true };

function endpoint(id: string, hostname: string, extra: Partial<PatchEndpoint> = {}): PatchEndpoint {
  return {
    id,
    hostname,
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
    complianceStatus: "Compliant",
    missingRequiredCount: 0,
    missingTotalCount: 0,
    missingDeferredCount: 0,
    failedCount: 0,
    rebootPending: false,
    knownExploitedMissingCount: 0,
    currentActivity: "",
    ...extra,
  };
}

function device(id: string, name: string, org: [string, string], e: PatchEndpoint | undefined, link: PatchFleetDevice["link"] = "linked"): PatchFleetDevice {
  return {
    deviceId: id,
    name,
    organizationId: org[0],
    organizationName: org[1],
    siteId: "s1",
    siteName: "Head office",
    platform: "windows",
    link,
    canManage: true,
    endpoint: e,
  };
}

const NORTHWIND: [string, string] = ["o1", "Northwind Traders"];
const CONTOSO: [string, string] = ["o2", "Contoso Dental"];

const FLEET: PatchFleet = {
  devices: [
    device("d1", "WEB-01", NORTHWIND, endpoint("e1", "web-01")),
    device("d2", "DB-01", NORTHWIND, endpoint("e2", "db-01", { complianceStatus: "FailedUpdates", failedCount: 1, missingRequiredCount: 1, missingTotalCount: 1 })),
    device(
      "d3",
      "DC-01",
      CONTOSO,
      endpoint("e3", "dc-01", { complianceStatus: "MissingUpdates", missingRequiredCount: 2, missingTotalCount: 2, knownExploitedMissingCount: 1, isOnline: false }),
    ),
    device("d4", "FS-01", CONTOSO, endpoint("e4", "fs-01", { complianceStatus: "NeverScanned", agentOutdated: true })),
    device("d5", "APP-01", CONTOSO, undefined, "unlinked"),
  ],
  unmatched: [{ ...endpoint("e9", "FRONTDESK-2", { complianceStatus: "MissingUpdates" }), organizationId: "o2", organizationName: "Contoso Dental", canRemove: true }],
  truncated: false,
  errors: [],
};

function update(extra: Partial<PatchFleetUpdate> = {}): PatchFleetUpdate {
  return {
    updateGuid: "u1",
    title: "2026-11 Cumulative Update for Windows Server 2025 (KB5070001)",
    kbNumber: "5070001",
    category: "Security",
    msrcSeverity: "Critical",
    releaseDate: "2026-11-11T00:00:00Z",
    sizeBytes: 734_003_200,
    missingCount: 2,
    failedCount: 1,
    installedCount: 4,
    pendingRebootCount: 1,
    excludedCount: 0,
    package: null,
    cveCount: 2,
    knownExploited: true,
    reofferedCount: 0,
    onHold: false,
    ...extra,
  };
}

function hold(extra: Partial<PatchHold> = {}): PatchHold {
  return {
    id: "h1",
    updateGuid: "u1",
    title: "2026-11 Cumulative Update",
    kbNumber: "5070001",
    organizationId: "o1",
    organizationName: "Northwind Traders",
    source: "Manual",
    reason: "Breaks the line-of-business app",
    failedEndpoints: null,
    attemptedEndpoints: null,
    createdAt: T,
    createdBy: "Alex Rivera",
    releasedAt: null,
    releasedBy: "",
    canRelease: true,
    ...extra,
  };
}

function view(extra: Partial<PatchUpdateView> = {}): PatchUpdateView {
  return {
    summary: update(),
    description: "Fixes vulnerabilities in the kernel and in the print spooler.",
    supportUrl: "https://support.example.com/kb/5070001",
    kbNumbers: ["5070001"],
    products: ["Windows Server 2025"],
    msClassification: "Security Updates",
    rebootLikely: true,
    supersededUpdateGuids: ["u0"],
    vulnerabilities: [
      {
        cveId: "CVE-2026-1001",
        title: "Print spooler elevation of privilege",
        severity: "Critical",
        cvssBase: 9.8,
        msrcExploited: true,
        kev: true,
        kevDateAdded: "2026-11-12",
        kevDueDate: "2026-12-03",
        kevRansomware: true,
        kevName: "Windows Print Spooler",
      },
      {
        cveId: "CVE-2026-1002",
        title: "",
        severity: "Important",
        cvssBase: null,
        msrcExploited: true,
        kev: false,
        kevDateAdded: null,
        kevDueDate: null,
        kevRansomware: false,
        kevName: "",
      },
    ],
    holds: [],
    canManage: true,
    canHold: false,
    holdIn: [],
    canHoldEverywhere: false,
    ...extra,
  };
}

function updateDevice(id: string | null, hostname: string, state: PatchUpdateDevice["state"], extra: Partial<PatchUpdateDevice> = {}): PatchUpdateDevice {
  return {
    endpointId: `e-${hostname}`,
    hostname,
    deviceId: id,
    deviceName: id ? hostname.toUpperCase() : "",
    organizationName: id ? "Northwind Traders" : "Northwind Patch",
    siteName: "Head office",
    platform: "windows",
    isOnline: true,
    state,
    isRequired: true,
    isExcluded: false,
    failedAttempts: 0,
    errorCode: "",
    errorMessage: "",
    stateChangedAt: T,
    canManage: id !== null,
    ...extra,
  };
}

const DEVICES = {
  items: [
    updateDevice("d1", "web-01", "Missing"),
    updateDevice("d2", "db-01", "Failed", { errorCode: "0x80070005", errorMessage: "Access is denied.", failedAttempts: 2 }),
    updateDevice("d3", "dc-01", "Missing", { canManage: false }),
    updateDevice(null, "kiosk-07", "Missing"),
    updateDevice("d5", "app-01", "Installed"),
  ],
  page: 1,
  pageSize: 200,
  totalCount: 5,
};

function routes(session = TECH, extra: Record<string, FakeHandler | FakeReply> = {}) {
  return {
    ...baseRoutes(session),
    "GET /patching": ok(READY),
    "GET /patching/devices": ok(FLEET),
    "GET /patching/jobs": ok({ items: [] }),
    "GET /patching/alerts/summary": ok({ open: 0, acknowledged: 0, critical: 0, warning: 0, info: 0, capped: false }),
    // With an organization chosen, the overview asks whether Patch all is offered (patchAll.test.tsx): not here.
    "GET /patching/scope": fail(409, "easypatch_not_linked", "The organization is not in the patching engine yet."),
    ...extra,
  };
}

describe("patching overview", () => {
  it("is where Patching opens, with what needs attention worst first", async () => {
    installFakeApi(
      routes(TECH, {
        "GET /patching/jobs": ok({ items: [{ id: "j1" }, { id: "j2" }] }),
        "GET /patching/alerts/summary": ok({ open: 3, acknowledged: 1, critical: 1, warning: 3, info: 0, capped: false }),
      }),
    );
    renderApp("/patching");
    await screen.findByRole("main");
    expect(await main().findByRole("tab", { name: "Overview", selected: true })).toBeInTheDocument();

    // Four devices report; one is up to date.
    expect(await main().findByText("25%")).toBeInTheDocument();
    expect(main().getByText(/of 4 devices the patching engine reports on, besides 1 not patched from EasyRMM/)).toBeInTheDocument();
    expect(main().getByRole("img", { name: /Up to date: 1, Updates missing: 1, Updates failed: 1, Not scanned recently: 1/ })).toBeInTheDocument();

    const attention = within(main().getByRole("heading", { name: "Needs attention" }).closest("section")!);
    expect(await attention.findByText("patching alerts are open")).toBeInTheDocument();
    const rows = attention.getAllByRole("listitem").map((li) => li.textContent);
    expect(rows).toEqual([
      expect.stringContaining("3patching alerts are open"),
      expect.stringContaining("1device misses updates for vulnerabilities exploited in the wild"),
      expect.stringContaining("1device has updates that failed to install"),
      expect.stringContaining("1device misses required updates"),
      expect.stringContaining("1device has never scanned"),
      expect.stringContaining("1device runs an out-of-date EasyPatch agent"),
      expect.stringContaining("1device's EasyPatch agent is offline"),
      expect.stringContaining("1device is not patched from EasyRMM"),
      expect.stringContaining("1patching engine endpoint has no EasyRMM device"),
      expect.stringContaining("2patch jobs are queued or running"),
    ]);
    expect(attention.getByRole("link", { name: "Show the updates" })).toHaveAttribute("href", "/patching?tab=updates&exploited=true");
    expect(attention.getAllByRole("link", { name: "Show devices" })[0]).toHaveAttribute("href", "/patching?tab=devices&compliance=FailedUpdates");
    expect(attention.getByRole("link", { name: "Show jobs" })).toHaveAttribute("href", "/patching?tab=jobs");
    expect(attention.getByRole("link", { name: "Show alerts" })).toHaveAttribute("href", "/patching?tab=alerts");

    // Organizations, least up to date first.
    const orgs = within(main().getByRole("heading", { name: "Organizations, least up to date first" }).closest("section")!);
    const names = orgs.getAllByRole("link").map((a) => a.textContent);
    expect(names).toEqual(["Contoso Dental", "Northwind Traders"]);
    expect(orgs.getByRole("meter", { name: "Contoso Dental: devices up to date" })).toHaveAttribute("aria-valuenow", "0");
    expect(orgs.getByRole("meter", { name: "Northwind Traders: devices up to date" })).toHaveAttribute("aria-valuenow", "50");

    // Endpoints with no EasyRMM device, and what to do about them.
    const unmatched = within(main().getByRole("heading", { name: /In the patching engine, with no EasyRMM device \(1\)/ }).closest("section")!);
    expect(unmatched.getByText("FRONTDESK-2")).toBeInTheDocument();
    expect(unmatched.getByRole("link", { name: "Add a device" })).toHaveAttribute("href", "/devices/add");
  });

  it("keeps the organization chosen in its links, and says when nothing needs attention", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(TECH, {
        "GET /patching/devices": (r) =>
          ok({
            ...FLEET,
            unmatched: [],
            devices: r.query.get("organizationId") === "o1" ? [FLEET.devices[0]] : FLEET.devices,
          }),
      }),
    );
    renderApp("/patching?organizationId=o1");
    await screen.findByRole("main");
    expect(await main().findByText("Nothing needs attention")).toBeInTheDocument();
    expect(main().getByText("100%")).toBeInTheDocument();
    // One organization: no table of them.
    expect(main().queryByText("Organizations, least up to date first")).not.toBeInTheDocument();
    expect(server.call("GET /patching/devices").query.get("organizationId")).toBe("o1");
    expect(server.call("GET /patching/jobs").query.get("active")).toBe("true");
    expect(server.call("GET /patching/alerts/summary").query.get("organizationId")).toBe("o1");
    await user.click(main().getByRole("link", { name: "Up to date" }));
    expect(await main().findByRole("tab", { name: "Devices", selected: true })).toBeInTheDocument();
  });

  it("removes an endpoint with no EasyRMM device, and shows the ones being removed", async () => {
    const user = userEvent.setup();
    let fleet: PatchFleet = FLEET;
    const server = installFakeApi(
      routes(TECH, {
        "GET /patching/devices": () => ok(fleet),
        "POST /patching/endpoints/:id/remove": (r) => {
          const removed = { ...fleet.unmatched[0]!, removal: { reason: "deleted" as const, state: "pending" as const, requestedAt: T } };
          fleet = { ...fleet, unmatched: [removed] };
          return ok({ ...removed, id: r.params.id });
        },
      }),
    );
    renderApp("/patching");
    await screen.findByRole("main");
    const unmatched = within((await main().findByRole("heading", { name: /In the patching engine, with no EasyRMM device/ })).closest("section")!);
    await user.click(unmatched.getByRole("button", { name: "Remove" }));
    const dialog = screen.getByRole("dialog", { name: "Remove FRONTDESK-2?" });
    expect(within(dialog).getByText(/its EasyPatch agent uninstalls itself, and the patching engine stops patching it/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Remove endpoint" }));
    expect(await unmatched.findByText("Removing")).toBeInTheDocument();
    expect(unmatched.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(server.call("POST /patching/endpoints/:id/remove").params.id).toBe("e9");
  });

  it("offers no removal to people who may not remove devices", async () => {
    installFakeApi(routes(TECH, { "GET /patching/devices": ok({ ...FLEET, unmatched: [{ ...FLEET.unmatched[0]!, canRemove: false }] }) }));
    renderApp("/patching");
    await screen.findByRole("main");
    const unmatched = within((await main().findByRole("heading", { name: /In the patching engine, with no EasyRMM device/ })).closest("section")!);
    expect(unmatched.getByText("FRONTDESK-2")).toBeInTheDocument();
    expect(unmatched.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(unmatched.queryByRole("columnheader", { name: "Remove" })).not.toBeInTheDocument();
  });

  it("says when there is nothing to patch yet", async () => {
    installFakeApi(routes(TECH, { "GET /patching/devices": ok({ devices: [], unmatched: [], truncated: false, errors: [] }) }));
    renderApp("/patching");
    await screen.findByRole("main");
    expect(await main().findByText("No devices to patch yet")).toBeInTheDocument();
  });

  it("shows what EasyPatch could not read, and a capped job count", async () => {
    installFakeApi(
      routes(TECH, {
        "GET /patching/devices": ok({ ...FLEET, errors: ["Contoso Dental: EasyPatch did not answer."], truncated: true }),
        "GET /patching/jobs": ok({ items: Array.from({ length: 200 }, (_, i) => ({ id: `j${i}` })) }),
        "GET /patching/alerts/summary": ok({ open: 200, acknowledged: 0, critical: 0, warning: 200, info: 0, capped: true }),
      }),
    );
    renderApp("/patching");
    await screen.findByRole("main");
    expect(await main().findByText("Contoso Dental: EasyPatch did not answer.")).toBeInTheDocument();
    await waitFor(() => expect(main().getAllByText("200+")).toHaveLength(2)); // the jobs, and the alerts
    expect(main().getByText(/Counted over the first 5 devices/)).toBeInTheDocument();
  });
});

describe("update list", () => {
  it("lists updates across devices, filters them and opens one", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(TECH, {
        "GET /patching/updates": ok({
          items: [
            update({ onHold: true }),
            update({
              updateGuid: "u2",
              title: "openssl",
              kbNumber: "",
              category: "Security",
              msrcSeverity: "",
              knownExploited: false,
              cveCount: 1,
              sizeBytes: null,
              package: { name: "openssl", version: "3.5.4-1", installedVersion: "3.5.1-1", repository: "trixie-security", advisories: ["DSA-6001-1"] },
            }),
          ],
          page: 1,
          pageSize: 50,
          totalCount: 120,
        }),
      }),
    );
    renderApp("/patching?tab=updates&organizationId=o1");
    await screen.findByRole("main");
    const link = await main().findByRole("link", { name: /Cumulative Update for Windows Server 2025/ });
    expect(link).toHaveAttribute("href", "/patching/updates/u1?organizationId=o1");
    const table = within(main().getByRole("table"));
    expect(table.getByText("Exploited in the wild")).toBeInTheDocument();
    expect(table.getByText("On hold")).toBeInTheDocument();
    expect(table.getByText(/KB5070001 · Security · Critical · 700 MiB · 2 CVEs/)).toBeInTheDocument();
    expect(table.getByText(/openssl · Security · 1 CVE/)).toBeInTheDocument();
    expect(main().getByText("Page 1 of 3")).toBeInTheDocument();

    await user.selectOptions(main().getByLabelText("Category"), "Security");
    await user.selectOptions(main().getByLabelText("Devices where it is"), "Failed");
    await user.selectOptions(main().getByLabelText("Exploitation"), "true");
    await user.selectOptions(main().getByLabelText("Order"), "failed");
    await user.click(main().getByRole("button", { name: "Next" }));
    await waitFor(() => {
      const q = server.callsTo("GET /patching/updates").at(-1)!.query;
      expect(Object.fromEntries(q)).toEqual({ organizationId: "o1", category: "Security", state: "Failed", knownExploited: "true", sort: "failed", page: "2" });
    });
  });

  it("asks people whose role covers single sites to choose one", async () => {
    installFakeApi(
      routes(TECH, {
        "GET /patching/updates": fail(422, "validation_failed", "Invalid.", { siteId: "Your role covers single sites in this organization: choose one of them." }),
      }),
    );
    renderApp("/patching?tab=updates");
    await screen.findByRole("main");
    expect(await main().findByText("Choose a site")).toBeInTheDocument();
    expect(main().getByText("Your role covers single sites in this organization: choose one of them.")).toBeInTheDocument();
  });

  it("asks for an organization when EasyPatch counts one at a time", async () => {
    installFakeApi(
      routes(TECH, {
        "GET /patching/updates": fail(422, "validation_failed", "Invalid.", { organizationId: "Choose an organization: EasyPatch counts its updates one organization at a time." }),
      }),
    );
    renderApp("/patching?tab=updates");
    await screen.findByRole("main");
    expect(await main().findByText("Choose an organization")).toBeInTheDocument();
  });

  it("says when nothing is needed, and when filters match nothing", async () => {
    installFakeApi(routes(TECH, { "GET /patching/updates": ok({ items: [], page: 1, pageSize: 50, totalCount: 0 }) }));
    renderApp("/patching?tab=updates");
    await screen.findByRole("main");
    expect(await main().findByText("No updates needed")).toBeInTheDocument();
    await userEvent.setup().selectOptions(main().getByLabelText("Category"), "Driver");
    expect(await main().findByText("No updates match these filters")).toBeInTheDocument();
  });

  it("keeps the tab's filters to itself", async () => {
    const user = userEvent.setup();
    installFakeApi(routes(TECH, { "GET /patching/updates": ok({ items: [], page: 1, pageSize: 50, totalCount: 0 }) }));
    renderApp("/patching?tab=updates&category=Driver&organizationId=o1");
    await screen.findByRole("main");
    await main().findByText("No updates match these filters");
    await user.click(main().getByRole("tab", { name: "Devices" }));
    await user.click(main().getByRole("tab", { name: "Updates" }));
    expect(await main().findByText("No updates needed")).toBeInTheDocument();
    expect(main().getByLabelText("Category")).toHaveValue("");
  });
});

describe("update page", () => {
  it("shows what the update fixes and where it stands", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(TECH, { "GET /patching/updates/u1": ok(view()), "GET /patching/updates/u1/devices": ok(DEVICES) }));
    renderApp("/patching/updates/u1?organizationId=o1");
    await screen.findByRole("main");
    expect(await main().findByRole("heading", { name: /Cumulative Update for Windows Server 2025/, level: 1 })).toBeInTheDocument();
    expect(main().getByRole("link", { name: "Patching / Updates" })).toHaveAttribute("href", "/patching?tab=updates&organizationId=o1");
    expect(server.call("GET /patching/updates/u1").query.get("organizationId")).toBe("o1");
    expect(main().getByText("Fixes vulnerabilities in the kernel and in the print spooler.")).toBeInTheDocument();
    expect(main().getByText("Likely needed to finish installing")).toBeInTheDocument();
    expect(main().getByText("1 earlier update")).toBeInTheDocument();
    expect(main().getByRole("link", { name: /Vendor's page/ })).toHaveAttribute("href", "https://support.example.com/kb/5070001");

    // Vulnerabilities: NVD and, for Windows updates, Microsoft's guide.
    expect(main().getByRole("link", { name: /CVE-2026-1001/ })).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2026-1001");
    expect(main().getAllByRole("link", { name: "MSRC" })[0]).toHaveAttribute("href", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1001");
    expect(main().getByText(/In CISA's catalog since 2026-11-12, due 2026-12-03/)).toBeInTheDocument();
    expect(main().getByText("Used by ransomware")).toBeInTheDocument();
    expect(main().getByText("Exploited, says Microsoft")).toBeInTheDocument();
    expect(main().getByText("1 is exploited in the wild")).toBeInTheDocument();

    // Devices: linked ones open their Patches tab; an endpoint without a device says so; failures say why.
    expect(main().getByRole("link", { name: "WEB-01" })).toHaveAttribute("href", "/devices/d1?tab=patches");
    expect(main().getByText("kiosk-07")).toBeInTheDocument();
    expect(main().getByText("No EasyRMM device")).toBeInTheDocument();
    expect(main().getByText(/Access is denied\. \(2 attempts\)/)).toBeInTheDocument();
    // Only devices it can be installed on by this person can be chosen.
    expect(main().getByLabelText("Choose WEB-01")).toBeInTheDocument();
    expect(main().getByLabelText("Choose DB-01")).toBeInTheDocument();
    expect(main().queryByLabelText("Choose DC-01")).not.toBeInTheDocument();
    expect(main().queryByLabelText("Choose kiosk-07")).not.toBeInTheDocument();
    expect(main().queryByLabelText("Choose APP-01")).not.toBeInTheDocument();
    // No hold for a technician.
    expect(main().queryByRole("button", { name: "Hold…" })).not.toBeInTheDocument();

    await user.click(main().getByRole("radio", { name: "Failed 1" }));
    await waitFor(() => expect(server.callsTo("GET /patching/updates/u1/devices").at(-1)!.query.get("state")).toBe("Failed"));
  });

  it("installs on the devices chosen", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(TECH, {
        "GET /patching/updates/u1": ok(view()),
        "GET /patching/updates/u1/devices": ok(DEVICES),
        "POST /patching/updates/u1/install": ok({ succeeded: 2, failed: 0, results: [] }),
      }),
    );
    renderApp("/patching/updates/u1");
    await screen.findByRole("main");
    await user.click(await main().findByLabelText("Choose WEB-01"));
    await user.click(main().getByLabelText("Choose DB-01"));
    await user.click(main().getByRole("button", { name: "Install on 2 devices" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Install on 2 devices?")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Install on 2 devices" }));
    await waitFor(() => expect(server.callsTo("POST /patching/updates/u1/install")).toHaveLength(1));
    expect(server.call("POST /patching/updates/u1/install").body).toEqual({ deviceIds: ["d1", "d2"] });
    expect(await screen.findByText("Install started on 2 devices.")).toBeInTheDocument();
    // The choice is cleared once the install starts.
    expect(main().getByRole("button", { name: "Install where missing…" })).toBeInTheDocument();
  });

  it("installs wherever it is missing in the scope, and lists the devices that did not start", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(TECH, {
        "GET /patching/updates/u1": ok(view({ holds: [hold({ canRelease: false })] })),
        "GET /patching/updates/u1/devices": ok(DEVICES),
        "POST /patching/updates/u1/install": ok({
          succeeded: 2,
          failed: 1,
          results: [{ deviceId: "d3", deviceName: "DC-01", ok: false, message: "You may not install or remove updates on this device." }],
        }),
      }),
    );
    renderApp("/patching/updates/u1?organizationId=o1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Install where missing…" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/On the 3 devices in this view where it is missing or failed/)).toBeInTheDocument();
    expect(within(dialog).getByText("It is on hold")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Install" }));
    await waitFor(() => expect(server.callsTo("POST /patching/updates/u1/install")).toHaveLength(1));
    expect(server.call("POST /patching/updates/u1/install").body).toEqual({ all: true, organizationId: "o1" });
    const result = await screen.findByRole("dialog", { name: "1 device did not start" });
    expect(within(result).getByText("You may not install or remove updates on this device.")).toBeInTheDocument();
  });

  it("removes it from the devices it is installed on, excluding it by default", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(TECH, {
        "GET /patching/updates/u1": ok(view()),
        "GET /patching/updates/u1/devices": ok(DEVICES),
        "POST /patching/updates/u1/remove": ok({ succeeded: 5, failed: 0, results: [] }),
      }),
    );
    renderApp("/patching/updates/u1?siteId=s1&organizationId=o1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Remove…" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Remove it from 5 devices?")).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Reason (optional)"), "Breaks printing");
    await user.click(within(dialog).getByRole("button", { name: "Remove update" }));
    await waitFor(() => expect(server.callsTo("POST /patching/updates/u1/remove")).toHaveLength(1));
    expect(server.call("POST /patching/updates/u1/remove").body).toEqual({ all: true, organizationId: "o1", siteId: "s1", block: true, reason: "Breaks printing" });
    expect(await screen.findByText("Removal queued on 5 devices.")).toBeInTheDocument();

    // Without the exclusion, no reason is sent.
    await user.click(main().getByRole("button", { name: "Remove…" }));
    const again = await screen.findByRole("dialog");
    await user.click(within(again).getByLabelText("Exclude it on these devices"));
    expect(within(again).queryByLabelText("Reason (optional)")).not.toBeInTheDocument();
    await user.click(within(again).getByRole("button", { name: "Remove update" }));
    await waitFor(() => expect(server.callsTo("POST /patching/updates/u1/remove")).toHaveLength(2));
    expect(server.callsTo("POST /patching/updates/u1/remove")[1]!.body).toEqual({ all: true, organizationId: "o1", siteId: "s1", block: false, reason: "" });
  });

  it("offers no removal for packages", async () => {
    installFakeApi(
      routes(TECH, {
        "GET /patching/updates/u1": ok(
          view({ summary: update({ package: { name: "openssl", version: "3.5.4-1", installedVersion: "3.5.1-1", repository: "", advisories: null } }) }),
        ),
        "GET /patching/updates/u1/devices": ok(DEVICES),
      }),
    );
    renderApp("/patching/updates/u1");
    await screen.findByRole("main");
    expect(await main().findByRole("button", { name: "Install where missing…" })).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Remove…" })).not.toBeInTheDocument();
    // No Microsoft guide for a package's CVEs.
    expect(main().queryByRole("link", { name: "MSRC" })).not.toBeInTheDocument();
  });

  it("holds it in an organization, with a reason", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(ORG_ADMIN, {
        "GET /patching/updates/u1": ok(
          view({
            canHold: true,
            holdIn: [
              { id: "o2", name: "Contoso Dental" },
              { id: "o1", name: "Northwind Traders" },
            ],
          }),
        ),
        "GET /patching/updates/u1/devices": ok(DEVICES),
        "POST /patching/updates/u1/holds": ok(hold()),
      }),
    );
    renderApp("/patching/updates/u1?organizationId=o1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Hold…" }));
    const dialog = await screen.findByRole("dialog");
    // The page's organization first; no "every organization" without the right to it.
    const where = within(dialog).getByLabelText("Hold it in");
    expect(where).toHaveValue("o1");
    expect(within(dialog).queryByRole("option", { name: "Every organization" })).not.toBeInTheDocument();
    const button = within(dialog).getByRole("button", { name: "Hold update" });
    expect(button).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Why/), "Breaks the line-of-business app");
    await user.click(button);
    await waitFor(() => expect(server.callsTo("POST /patching/updates/u1/holds")).toHaveLength(1));
    expect(server.call("POST /patching/updates/u1/holds").body).toEqual({ organizationId: "o1", reason: "Breaks the line-of-business app" });
    expect(await screen.findByText("On hold in Northwind Traders.")).toBeInTheDocument();
  });

  it("holds it everywhere for a super administrator, and shows EasyPatch's refusal", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(sessionView({ permissions: ["org.view", "site.view", "device.view", "patch.view", "patch.manage", "patch.configure"] }), {
        "GET /patching/updates/u1": ok(view({ canHold: true, canHoldEverywhere: true, holdIn: [{ id: "o1", name: "Northwind Traders" }], holds: [hold()] })),
        "GET /patching/updates/u1/devices": ok(DEVICES),
        "POST /patching/updates/u1/holds": fail(409, "already_held", "This update is already on hold."),
      }),
    );
    renderApp("/patching/updates/u1");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Hold…" }));
    const dialog = await screen.findByRole("dialog");
    // Already held in Northwind: only "every organization" is left.
    expect(within(dialog).getAllByRole("option").map((o) => o.textContent)).toEqual(["Every organization"]);
    await user.type(within(dialog).getByLabelText(/Why/), "Known bad");
    await user.click(within(dialog).getByRole("button", { name: "Hold update" }));
    await waitFor(() => expect(server.callsTo("POST /patching/updates/u1/holds")).toHaveLength(1));
    expect(server.call("POST /patching/updates/u1/holds").body).toEqual({ reason: "Known bad" });
    expect(await within(dialog).findByText("This update is already on hold.")).toBeInTheDocument();
  });

  it("shows holds and releases one", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(ORG_ADMIN, {
        "GET /patching/updates/u1": ok(
          view({
            holds: [
              hold(),
              hold({
                id: "h2",
                organizationId: null,
                organizationName: "",
                source: "Automatic",
                reason: "Failed on 3 of 4",
                failedEndpoints: 3,
                attemptedEndpoints: 4,
                createdBy: "EasyPatch",
                canRelease: false,
              }),
            ],
          }),
        ),
        "GET /patching/updates/u1/devices": ok(DEVICES),
        "POST /patching/updates/u1/holds/h1/release": ok({ ...hold(), releasedAt: T, canRelease: false }),
      }),
    );
    renderApp("/patching/updates/u1");
    await screen.findByRole("main");
    expect(await main().findByText("On hold in Northwind Traders")).toBeInTheDocument();
    expect(main().getByText("Breaks the line-of-business app")).toBeInTheDocument();
    expect(main().getByText(/Held by Alex Rivera/)).toBeInTheDocument();
    expect(main().getByText("On hold in every organization")).toBeInTheDocument();
    expect(main().getByText("The patching engine held it after it failed on 3 of 4 devices it was tried on.")).toBeInTheDocument();
    // Only the hold this person may release offers it.
    expect(main().getAllByRole("button", { name: "Release hold" })).toHaveLength(1);
    await user.click(main().getByRole("button", { name: "Release hold" }));
    const dialog = await screen.findByRole("dialog", { name: "Release the hold in Northwind Traders?" });
    await user.click(within(dialog).getByRole("button", { name: "Release hold" }));
    await waitFor(() => expect(server.callsTo("POST /patching/updates/u1/holds/h1/release")).toHaveLength(1));
    expect(await screen.findByText("Hold released.")).toBeInTheDocument();
  });

  it("offers a viewer nothing that changes anything", async () => {
    installFakeApi(
      routes(VIEWER, {
        "GET /patching/updates/u1": ok(view({ canManage: false, holds: [hold({ canRelease: false })] })),
        "GET /patching/updates/u1/devices": ok({ ...DEVICES, items: DEVICES.items.map((d) => ({ ...d, canManage: false })) }),
      }),
    );
    renderApp("/patching/updates/u1");
    await screen.findByRole("main");
    expect(await main().findByRole("link", { name: "WEB-01" })).toBeInTheDocument();
    expect(main().queryByRole("button", { name: /Install/ })).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Remove…" })).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Hold…" })).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Release hold" })).not.toBeInTheDocument();
    expect(main().queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("says when the update is not found", async () => {
    installFakeApi(
      routes(TECH, {
        "GET /patching/updates/u9": fail(404, "not_found", "Not found."),
        "GET /patching/updates/u9/devices": ok({ items: [], page: 1, pageSize: 200, totalCount: 0 }),
      }),
    );
    renderApp("/patching/updates/u9");
    await screen.findByRole("main");
    expect(await main().findByRole("link", { name: "Patching / Updates" })).toHaveAttribute("href", "/patching?tab=updates");
    expect(await main().findByText("Not found.")).toBeInTheDocument();
  });
});
