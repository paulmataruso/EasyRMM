import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PatchPolicyLayer, PatchPolicyView, PatchStatus, PatchTag, PolicyLevel } from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, type FakeHandler, type FakeReply } from "../../test/fakeApi";
import { org, site } from "../../test/fixtures";
import { renderApp, renderWithProviders } from "../../test/render";
import { checkPolicy, fromText, PolicyPanel } from "./PolicyEditor";

// Policies at every level, and tags (one-product plan, C4).

const T = "2026-11-19T10:00:00Z";
const main = () => within(screen.getByRole("main"));

/** The whole console at a URL, once its layout is up. */
async function open(path: string) {
  renderApp(path);
  await screen.findByRole("main");
}

const READY: PatchStatus = { configured: true, canOperate: true, canSchedule: false };

/** Configures patching in its organizations; not a super administrator. */
const ORG_ADMIN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "patch.view", "patch.manage", "patch.configure"],
});
const SUPER = sessionView({
  permissions: ["org.view", "org.manage", "org.create", "site.view", "site.manage", "settings.manage", "patch.view", "patch.manage", "patch.configure"],
  globalPermissions: ["org.view", "site.view", "patch.view", "patch.manage", "patch.configure"],
});

function layer(values: Partial<PatchPolicyLayer> = {}): PatchPolicyLayer {
  return {
    checkInIntervalSeconds: null,
    scanIntervalMinutes: null,
    inventoryIntervalMinutes: null,
    jitterPercent: null,
    allowedCategories: null,
    includeOptional: null,
    excludedKbs: [],
    acceptEulas: null,
    autoInstallEnabled: null,
    maintenanceDays: null,
    maintenanceStart: null,
    maintenanceDurationMinutes: null,
    preDownloadHours: null,
    installDelayDays: null,
    securityInstallDelayDays: null,
    knownExploitedSkipsDelay: null,
    scanStaleAfterHours: null,
    maxConcurrentInstallsPerSite: null,
    trayIconEnabled: null,
    installNotificationsEnabled: null,
    agentAutoUpdateEnabled: null,
    restartSchedule: null,
    windowsUpdate: null,
    applicationUpdates: null,
    ...values,
  };
}

const BUILT_IN = layer({
  checkInIntervalSeconds: 60,
  scanIntervalMinutes: 360,
  inventoryIntervalMinutes: 1440,
  jitterPercent: 10,
  allowedCategories: ["Security", "Critical", "Cumulative", "Definition", "ServicingStack", "DotNet", "Other"],
  includeOptional: false,
  acceptEulas: true,
  autoInstallEnabled: false,
  maintenanceDays: [],
  maintenanceStart: "02:00",
  maintenanceDurationMinutes: 180,
  preDownloadHours: 0,
  installDelayDays: 0,
  securityInstallDelayDays: 0,
  knownExploitedSkipsDelay: true,
  scanStaleAfterHours: 48,
  maxConcurrentInstallsPerSite: 10,
  trayIconEnabled: true,
  installNotificationsEnabled: true,
  agentAutoUpdateEnabled: true,
  windowsUpdate: { automaticUpdates: null, featureUpdates: null, qualityUpdates: null, restartBehavior: null },
  applicationUpdates: { enabled: false, approvedApps: [] },
});

/** What an organization inherits: the default policy turns automatic installs on for Saturdays and excludes a KB. */
const INHERITED = layer({
  ...BUILT_IN,
  autoInstallEnabled: true,
  maintenanceDays: [6],
  excludedKbs: ["KB5005565"],
  windowsUpdate: {
    automaticUpdates: { managed: true, value: { mode: "NotifyDownload", scheduledInstallDay: 0, scheduledInstallHour: 3 } },
    featureUpdates: null,
    qualityUpdates: null,
    restartBehavior: null,
  },
});

function sources(over: Record<string, string> = {}): Record<string, string> {
  const all: Record<string, string> = {};
  for (const k of Object.keys(BUILT_IN)) all[k] = "EasyPatch's defaults";
  for (const g of ["automaticUpdates", "featureUpdates", "qualityUpdates", "restartBehavior"]) all[`windowsUpdate.${g}`] = "EasyPatch's defaults";
  return { ...all, ...over };
}

function view(level: PolicyLevel, name: string, extra: Partial<PatchPolicyView> = {}): PatchPolicyView {
  return {
    level,
    name,
    own: layer(),
    hasOwn: false,
    inherited: INHERITED,
    inheritedFrom: sources({
      autoInstallEnabled: "Default policy",
      maintenanceDays: "Default policy",
      excludedKbs: "Default policy",
      "windowsUpdate.automaticUpdates": "Default policy",
    }),
    windows: true,
    canEdit: true,
    organizationId: "o1",
    ...extra,
  };
}

/** A level's policy as EasyPatch keeps it: GET answers what PUT stored, DELETE clears it. */
function policyRoutes(level: PolicyLevel, start: PatchPolicyView): Record<string, FakeHandler> {
  let current = start;
  const path = level === "default" ? "/patching/policies/default" : `/patching/policies/${level}/:id`;
  return {
    [`GET ${path}`]: () => ok(current),
    [`PUT ${path}`]: (r) => {
      current = { ...current, own: r.body as PatchPolicyLayer, hasOwn: true, updatedAt: T };
      return ok(current);
    },
    [`DELETE ${path}`]: () => {
      current = { ...current, own: level === "default" ? BUILT_IN : layer(), hasOwn: false, updatedAt: undefined };
      return ok(current);
    },
  };
}

function orgRoutes(session = ORG_ADMIN, extra: Record<string, FakeHandler | FakeReply> = {}) {
  return {
    ...baseRoutes(session),
    "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
    "GET /organizations/:id/sites": ok({ items: [] }),
    "GET /patching": ok(READY),
    "GET /patching/tags/of/organization/:id": ok({ tags: [], canAssign: false }),
    ...policyRoutes("organization", view("organization", "Northwind Traders")),
    ...extra,
  };
}

/** The value column of a row, found by its Inherit/Override choice. */
const column = (label: string) => screen.getByRole("radiogroup", { name: `${label}: where its value comes from` }).parentElement!;

describe("policy editor", () => {
  it("shows what an organization inherits, overrides a value and saves only that", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(orgRoutes());
    await open("/organizations/o1");
    await user.click(await main().findByRole("tab", { name: "Patch policy" }));
    await screen.findByRole("form", { name: "Northwind Traders patch policy" });
    expect(column("Maintenance window")).toHaveTextContent("Saturday at 02:00 for 3 hours · from the default policy");
    expect(column("Scans")).toHaveTextContent("Every 6 hours · EasyPatch's default");
    expect(column("Automatic Updates")).toHaveTextContent("Notify before downloading and installing · from the default policy");
    expect(main().getByText("Also excluded above:")).toHaveTextContent("KB5005565");
    expect(main().getByText("Nothing set here: everything is inherited.")).toBeInTheDocument();
    expect(main().getByRole("button", { name: "Save policy" })).toBeDisabled();

    await user.click(within(column("Scans")).getByRole("radio", { name: "Override" }));
    const scans = within(column("Scans")).getByRole("spinbutton", { name: "Scans" });
    expect(scans).toHaveValue(360);
    await user.clear(scans);
    await user.type(scans, "720");
    expect(main().getByText("Unsaved changes.")).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Save policy" }));
    expect(await screen.findByText("Policy saved.")).toBeInTheDocument();
    const body = server.call("PUT /patching/policies/organization/:id").body as PatchPolicyLayer;
    expect(body).toEqual(layer({ scanIntervalMinutes: 720 }));
    expect(server.call("PUT /patching/policies/organization/:id").path).toBe("/patching/policies/organization/o1");
    expect(await main().findByText(/^Last changed/)).toBeInTheDocument();
    expect(main().getByRole("button", { name: "Save policy" })).toBeDisabled();

    // Back to inheriting it, then discarding that.
    await user.click(within(column("Scans")).getByRole("radio", { name: "Inherit" }));
    expect(main().getByRole("button", { name: "Save policy" })).toBeEnabled();
    await user.click(main().getByRole("button", { name: "Discard changes" }));
    expect(within(column("Scans")).getByRole("spinbutton", { name: "Scans" })).toHaveValue(720);
  });

  it("checks values before saving and shows what the server refuses", async () => {
    const user = userEvent.setup();
    installFakeApi(
      orgRoutes(ORG_ADMIN, {
        "PUT /patching/policies/organization/:id": fail(422, "validation_failed", "Check the highlighted fields.", {
          jitterPercent: "EasyPatch refused this spread.",
        }),
      }),
    );
    await open("/organizations/o1?tab=patch-policy");
    await screen.findByRole("form", { name: "Northwind Traders patch policy" });
    await user.click(within(column("Check-ins")).getByRole("radio", { name: "Override" }));
    const checkIns = within(column("Check-ins")).getByRole("spinbutton", { name: "Check-ins" });
    await user.clear(checkIns);
    await user.type(checkIns, "5");
    expect(within(column("Check-ins")).getByText("Choose a check-in interval (seconds) from 15 to 3600.")).toBeInTheDocument();
    await user.clear(checkIns);
    expect(within(column("Check-ins")).getByText("Enter a whole number.")).toBeInTheDocument();
    expect(main().getByText("Correct the values marked above to save.")).toBeInTheDocument();
    expect(main().getByRole("button", { name: "Save policy" })).toBeDisabled();
    await user.click(within(column("Check-ins")).getByRole("radio", { name: "Inherit" }));

    // Turning automatic installs on needs a window.
    await user.click(within(column("Maintenance window")).getByRole("radio", { name: "Override" }));
    await user.click(within(column("Maintenance window")).getByRole("checkbox", { name: "Saturday" }));
    expect(within(column("Maintenance window")).getByText("Automatic installs happen only in the maintenance window: choose its days.")).toBeInTheDocument();
    expect(within(column("Maintenance window")).getByText("No days: no maintenance window at this level.")).toBeInTheDocument();
    await user.click(within(column("Maintenance window")).getByRole("checkbox", { name: "Sunday" }));
    await user.selectOptions(within(column("Maintenance window")).getByRole("combobox"), "4 hours");

    await user.click(within(column("Spread")).getByRole("radio", { name: "Override" }));
    await user.click(main().getByRole("button", { name: "Save policy" }));
    expect(await within(column("Spread")).findByText("EasyPatch refused this spread.")).toBeInTheDocument();
  });

  it("sets categories, exclusions, a restart schedule and approved applications", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(orgRoutes());
    await open("/organizations/o1?tab=patch-policy");
    await screen.findByRole("form", { name: "Northwind Traders patch policy" });

    await user.click(within(column("Categories")).getByRole("radio", { name: "Override" }));
    for (const c of ["Definition", "Servicing stack", ".NET", "Other", "Cumulative", "Critical"]) {
      await user.click(within(column("Categories")).getByRole("checkbox", { name: c }));
    }
    await user.click(within(column("Categories")).getByRole("checkbox", { name: "Security" }));
    expect(within(column("Categories")).getByText("Choose at least one category.")).toBeInTheDocument();
    await user.click(within(column("Categories")).getByRole("checkbox", { name: "Security" }));
    await user.click(within(column("Categories")).getByRole("checkbox", { name: "Driver" }));

    const kb = main().getByRole("textbox", { name: "Add to excluded kbs" });
    await user.type(kb, "5034441{Enter}");
    expect(main().getByRole("list", { name: "Excluded KBs" })).toHaveTextContent("KB5034441");
    await user.type(kb, "nope");
    await user.click(within(kb.parentElement!).getByRole("button", { name: "Add" }));
    expect(main().getByText("NOPE is not a KB number such as KB5044284.")).toBeInTheDocument();
    await user.clear(kb);
    await user.type(kb, "KB5034441, KB5046617{Enter}");
    await user.click(main().getByRole("button", { name: "Remove KB5046617" }));

    await user.click(within(column("Restart schedule")).getByRole("radio", { name: "Override" }));
    expect(within(column("Restart schedule")).getByText(/No scheduled restarts/)).toBeInTheDocument();
    await user.click(within(column("Restart schedule")).getByRole("checkbox", { name: "Restart on a schedule" }));
    expect(within(column("Restart schedule")).getByText("Choose at least one day for the restart schedule.")).toBeInTheDocument();
    await user.click(within(column("Restart schedule")).getByRole("checkbox", { name: "Sunday" }));
    await user.click(within(column("Restart schedule")).getByRole("radio", { name: "Always" }));
    await user.selectOptions(within(column("Restart schedule")).getByRole("combobox", { name: /The people signed in/ }), "Countdown");
    await user.selectOptions(within(column("Restart schedule")).getByRole("combobox", { name: "Countdown" }), "15 minutes");
    await user.selectOptions(within(column("Restart schedule")).getByRole("combobox", { name: "The people signed in Signed-in users see the countdown and can only restart sooner." }), "PromptWithDeadline");
    await user.selectOptions(within(column("Restart schedule")).getByRole("combobox", { name: "Deadline" }), "8 hours");
    await user.selectOptions(within(column("Restart schedule")).getByRole("combobox", { name: "An offline computer can wait" }), "4 hours");

    await user.click(within(column("Update approved applications")).getByRole("radio", { name: "Override" }));
    await user.click(main().getByRole("checkbox", { name: "Keep the approved applications up to date" }));
    const app = main().getByRole("textbox", { name: "Add to approved applications" });
    await user.type(app, "firefox{Enter}");
    expect(main().getByText("firefox is not a winget package ID such as Mozilla.Firefox.")).toBeInTheDocument();
    await user.clear(app);
    await user.type(app, "Mozilla.Firefox{Enter}");

    await user.click(main().getByRole("button", { name: "Save policy" }));
    expect(await screen.findByText("Policy saved.")).toBeInTheDocument();
    expect(server.call("PUT /patching/policies/organization/:id").body).toEqual(
      layer({
        allowedCategories: ["Security", "Driver"],
        excludedKbs: ["KB5034441"],
        restartSchedule: {
          enabled: true,
          days: [0],
          time: "03:00",
          condition: "Always",
          mode: "PromptWithDeadline",
          countdownMinutes: 15,
          deadlineMinutes: 480,
          expiryMinutes: 240,
        },
        applicationUpdates: { enabled: true, approvedApps: ["Mozilla.Firefox"] },
      }),
    );
    expect(within(column("Restart schedule")).getByRole("checkbox", { name: "Restart on a schedule" })).toBeChecked();
  });

  it("manages Windows Update groups, leaves them alone, or inherits them", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(orgRoutes());
    await open("/organizations/o1?tab=patch-policy");
    await screen.findByRole("form", { name: "Northwind Traders patch policy" });

    await user.click(within(column("Feature updates")).getByRole("radio", { name: "Manage" }));
    await user.selectOptions(within(column("Feature updates")).getByRole("combobox", { name: "Stay on" }), "Windows 11");
    expect(
      within(column("Feature updates")).getByText("To keep a Windows version, give both the product and the version (for example 24H2)."),
    ).toBeInTheDocument();
    const version = within(column("Feature updates")).getByRole("textbox", { name: "Version" });
    await user.type(version, "2024");
    expect(within(column("Feature updates")).getByText("The version looks like 24H2.")).toBeInTheDocument();
    await user.clear(version);
    await user.type(version, "24h2");
    await user.type(within(column("Feature updates")).getByRole("spinbutton", { name: "Defer feature updates by" }), "400");
    expect(within(column("Feature updates")).getByText("Defer feature updates by 0 to 365 days.")).toBeInTheDocument();
    await user.clear(within(column("Feature updates")).getByRole("spinbutton", { name: "Defer feature updates by" }));

    await user.click(within(column("Quality updates and pausing")).getByRole("radio", { name: "Manage" }));
    await user.type(within(column("Quality updates and pausing")).getByRole("spinbutton", { name: "Defer quality updates by" }), "45");
    expect(within(column("Quality updates and pausing")).getByText("Defer quality updates by 0 to 30 days.")).toBeInTheDocument();
    await user.click(within(column("Quality updates and pausing")).getByRole("radio", { name: "Leave alone" }));
    expect(column("Quality updates and pausing")).toHaveTextContent("Not managed: Windows keeps its own settings for this group");

    await user.click(within(column("Restart behaviour")).getByRole("radio", { name: "Manage" }));
    await user.selectOptions(within(column("Restart behaviour")).getByRole("combobox", { name: "Active hours from" }), "08:00");
    expect(within(column("Restart behaviour")).getByText("Give both the start and the end of active hours.")).toBeInTheDocument();
    await user.selectOptions(within(column("Restart behaviour")).getByRole("combobox", { name: "to" }), "08:00");
    expect(within(column("Restart behaviour")).getByText("Active hours span 1 to 18 hours.")).toBeInTheDocument();
    await user.selectOptions(within(column("Restart behaviour")).getByRole("combobox", { name: "to" }), "18:00");
    await user.click(within(column("Restart behaviour")).getByRole("checkbox", { name: "No automatic restart while someone is signed in" }));

    // Automatic Updates: managed above; this organization schedules installs instead.
    await user.click(within(column("Automatic Updates")).getByRole("radio", { name: "Manage" }));
    await user.selectOptions(within(column("Automatic Updates")).getByRole("combobox", { name: "Windows updates itself" }), "AutoDownloadScheduleInstall");
    await user.selectOptions(within(column("Automatic Updates")).getByRole("combobox", { name: "Install on" }), "Friday");
    await user.selectOptions(within(column("Automatic Updates")).getByRole("combobox", { name: "At" }), "22:00");

    await user.click(main().getByRole("button", { name: "Save policy" }));
    expect(await screen.findByText("Policy saved.")).toBeInTheDocument();
    expect((server.call("PUT /patching/policies/organization/:id").body as PatchPolicyLayer).windowsUpdate).toEqual({
      automaticUpdates: { managed: true, value: { mode: "AutoDownloadScheduleInstall", scheduledInstallDay: 6, scheduledInstallHour: 22 } },
      featureUpdates: { managed: true, value: { deferDays: null, targetProductVersion: "Windows 11", targetReleaseVersion: "24H2" } },
      qualityUpdates: { managed: false, value: null },
      restartBehavior: { managed: true, value: { noAutoRestartWithSignedInUsers: false, activeHoursStart: 8, activeHoursEnd: 18 } },
    });
  });

  it("makes a level inherit everything again, after typing its name", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...orgRoutes(),
      ...policyRoutes("organization", view("organization", "Northwind Traders", { own: layer({ jitterPercent: 20 }), hasOwn: true, updatedAt: T })),
    });
    await open("/organizations/o1?tab=patch-policy");
    await screen.findByRole("form", { name: "Northwind Traders patch policy" });
    expect(within(column("Spread")).getByRole("spinbutton", { name: "Spread" })).toHaveValue(20);
    await user.click(main().getByRole("button", { name: "Inherit everything" }));
    const dialog = await screen.findByRole("dialog", { name: "Inherit everything" });
    const confirm = within(dialog).getByRole("button", { name: "Inherit everything" });
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByRole("textbox"), "Northwind Traders");
    await user.click(confirm);
    expect(await screen.findByText("This policy inherits everything again.")).toBeInTheDocument();
    expect(server.callsTo("DELETE /patching/policies/organization/:id")).toHaveLength(1);
    expect(column("Spread")).toHaveTextContent("10% · EasyPatch's default");
    expect(main().queryByRole("button", { name: "Inherit everything" })).not.toBeInTheDocument();
  });

  it("shows a policy without changing it to someone who may not", async () => {
    installFakeApi(orgRoutes(ORG_ADMIN, policyRoutes("organization", view("organization", "Northwind Traders", { canEdit: false, own: layer({ jitterPercent: 20 }), hasOwn: true }))));
    await open("/organizations/o1?tab=patch-policy");
    await screen.findByRole("form", { name: "Northwind Traders patch policy" });
    expect(main().getByText("You can see this policy. Changing it needs permission to configure patching in this organization.")).toBeInTheDocument();
    expect(main().queryByRole("radiogroup")).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Save policy" })).not.toBeInTheDocument();
    expect(main().getByText("20%")).toBeInTheDocument();
    expect(main().getAllByText("· set here")).toHaveLength(1);
  });

  it("says so when the organization is not patched by EasyPatch", async () => {
    installFakeApi(
      orgRoutes(ORG_ADMIN, {
        "GET /patching/policies/organization/:id": fail(409, "easypatch_not_linked", "This organization is not linked to EasyPatch."),
      }),
    );
    await open("/organizations/o1?tab=patch-policy");
    expect(await main().findByText("Not patched by EasyPatch")).toBeInTheDocument();
  });

  it("hides the tab until EasyPatch is set up", async () => {
    installFakeApi(orgRoutes(ORG_ADMIN, { "GET /patching": ok({ ...READY, configured: false }) }));
    await open("/organizations/o1?tab=patch-policy");
    expect(await main().findByRole("heading", { name: "Sites" })).toBeInTheDocument();
    expect(main().queryByRole("tab", { name: "Patch policy" })).not.toBeInTheDocument();
  });

  it("edits a site's policy, and says when EasyPatch has no site yet", async () => {
    const user = userEvent.setup();
    const routes = {
      ...baseRoutes(ORG_ADMIN),
      "GET /sites/:id": ok(site("s1", "o1", "Head office")),
      "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
      "GET /sites/:id/device-groups": ok({ items: [] }),
      "GET /patching": ok(READY),
      "GET /patching/tags/of/site/:id": ok({ tags: [{ id: "t1", name: "Servers", color: "teal" }], canAssign: false }),
      ...policyRoutes(
        "site",
        view("site", "Head office", {
          timeZone: "Europe/Paris",
          inheritedFrom: sources({ maintenanceDays: "Organization", autoInstallEnabled: "Tag Servers", excludedKbs: "Default policy" }),
        }),
      ),
    };
    const server = installFakeApi(routes);
    await open("/sites/s1");
    await user.click(await main().findByRole("tab", { name: "Patch policy" }));
    await screen.findByRole("form", { name: "Head office patch policy" });
    expect(main().getByText(/Times are in Europe\/Paris/)).toBeInTheDocument();
    expect(main().getByTitle("Servers")).toBeInTheDocument();
    expect(column("Maintenance window")).toHaveTextContent("Saturday at 02:00 for 3 hours (Europe/Paris) · from the organization");
    expect(column("Automatic installs")).toHaveTextContent("On, inside the maintenance window · from the tag Servers");
    expect(within(column("Installs at once, per site")).getByRole("radio", { name: "Inherit" })).toBeChecked();
    await user.click(within(column("Agent updates")).getByRole("radio", { name: "Override" }));
    await user.click(within(column("Agent updates")).getByRole("radio", { name: "Manual" }));
    await user.click(main().getByRole("button", { name: "Save policy" }));
    expect(await screen.findByText("Policy saved.")).toBeInTheDocument();
    expect(server.call("PUT /patching/policies/site/:id").body).toEqual(layer({ agentAutoUpdateEnabled: false }));

    server.on("GET /patching/policies/site/:id", fail(409, "easypatch_site_not_found", "EasyPatch has no site for this site yet."));
    await open("/sites/s2?tab=patch-policy");
    expect(await screen.findByText("No patch policy yet")).toBeInTheDocument();
  });

  it("leaves Windows settings and site limits off a device that is not a Windows computer", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(ORG_ADMIN),
      ...policyRoutes("device", view("device", "DB-01", { windows: false })),
    });
    renderWithProviders(<PolicyPanel level="device" id="d1" />);
    await screen.findByRole("form", { name: "DB-01 patch policy" });
    expect(screen.getByText(/Values set here apply to this device only/)).toBeInTheDocument();
    for (const name of ["Windows Update settings", "Application updates"]) {
      expect(screen.queryByRole("heading", { name })).not.toBeInTheDocument();
    }
    for (const label of ["Download ahead", "Installs at once, per site", "EasyPatch icon"]) {
      expect(screen.queryByRole("radiogroup", { name: `${label}: where its value comes from` })).not.toBeInTheDocument();
    }
    await user.click(within(column("Optional updates")).getByRole("radio", { name: "Override" }));
    await user.click(within(column("Optional updates")).getByRole("radio", { name: "Install" }));
    await user.click(screen.getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(server.callsTo("PUT /patching/policies/device/:id")).toHaveLength(1));
    expect(server.call("PUT /patching/policies/device/:id").body).toEqual(layer({ includeOptional: true }));
  });
});

const TAGS: PatchTag[] = [
  { id: "t1", name: "Pilot ring", color: "amber", description: "Gets updates a week early.", priority: 50, endpointCount: 3, siteCount: 1, organizationCount: 0, hasPolicy: true, createdAt: T },
  { id: "t2", name: "Servers", color: "teal", description: null, priority: 10, endpointCount: 0, siteCount: 0, organizationCount: 2, hasPolicy: false, createdAt: T },
];

describe("Settings → Patching", () => {
  function settingsRoutes(session = SUPER, extra: Record<string, FakeHandler | FakeReply> = {}) {
    return {
      ...baseRoutes(session),
      "GET /patching": ok(READY),
      "GET /patching/tags": ok({ items: TAGS, canManage: session === SUPER }),
      ...policyRoutes("default", view("default", "Default policy", { own: BUILT_IN, inherited: BUILT_IN, inheritedFrom: sources(), hasOwn: true })),
      ...policyRoutes("tag", view("tag", "Pilot ring", { inheritedFrom: sources({ maintenanceDays: "Default policy", autoInstallEnabled: "Default policy" }) })),
      ...extra,
    };
  }

  it("edits the default policy, which has nothing to inherit, and restores EasyPatch's", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(settingsRoutes());
    await open("/settings?tab=patching");
    expect(await screen.findByRole("heading", { name: "Patching", level: 1 })).toBeInTheDocument();
    await screen.findByRole("form", { name: "Default policy patch policy" });
    expect(main().queryByRole("radiogroup", { name: "Scans: where its value comes from" })).not.toBeInTheDocument();
    expect(main().getByText(/Every organization starts from the default policy/)).toBeInTheDocument();
    const scans = main().getByRole("spinbutton", { name: "Scans" });
    expect(scans).toHaveValue(360);
    await user.clear(scans);
    await user.type(scans, "240");
    // Windows Update groups are left alone or managed; there is nothing above to inherit.
    expect(main().queryByRole("radio", { name: "Inherit" })).not.toBeInTheDocument();
    await user.click(main().getByRole("checkbox", { name: "Restart on a schedule" }));
    await user.click(main().getByRole("checkbox", { name: "Restart on a schedule" }));
    await user.click(main().getByRole("button", { name: "Save policy" }));
    expect(await screen.findByText("Policy saved.")).toBeInTheDocument();
    expect(server.call("PUT /patching/policies/default").body).toEqual({ ...BUILT_IN, scanIntervalMinutes: 240 });

    await user.click(main().getByRole("button", { name: "Restore EasyPatch's defaults" }));
    const dialog = await screen.findByRole("dialog", { name: "Restore EasyPatch's defaults" });
    await user.type(within(dialog).getByRole("textbox"), "Default policy");
    await user.click(within(dialog).getByRole("button", { name: "Restore defaults" }));
    expect(await screen.findByText("The default policy is EasyPatch's again.")).toBeInTheDocument();
    expect(main().getByRole("spinbutton", { name: "Scans" })).toHaveValue(360);
  });

  it("adds, changes and deletes tags, and opens a tag's policy", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      settingsRoutes(SUPER, {
        "POST /patching/tags": (r) => {
          const b = r.body as { name: string };
          return b.name === "Servers"
            ? fail(422, "validation_failed", "Check the highlighted fields.", { name: "A tag with this name already exists." })
            : { status: 201, body: { ...TAGS[1], id: "t3", ...(r.body as object) } };
        },
        "PUT /patching/tags/:id": (r) => ok({ ...TAGS[1], ...(r.body as object) }),
        "DELETE /patching/tags/:id": noContent,
      }),
    );
    await open("/settings?tab=patching&view=tags");
    const table = await main().findByRole("table");
    expect(within(table).getByTitle("Pilot ring")).toBeInTheDocument();
    expect(within(table).getByText("Gets updates a week early.")).toBeInTheDocument();
    expect(within(table).getByText("3 devices, 1 site, 0 organizations")).toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Add tag" }));
    let dialog = await screen.findByRole("dialog", { name: "Add tag" });
    await user.type(within(dialog).getByRole("textbox", { name: /Name/ }), "Servers");
    const priority = within(dialog).getByRole("spinbutton", { name: "Priority" });
    await user.clear(priority);
    await user.type(priority, "2000");
    expect(within(dialog).getByText("Choose a priority from 0 to 1000.")).toBeInTheDocument();
    await user.clear(priority);
    await user.type(priority, "20");
    await user.click(within(dialog).getByRole("button", { name: "Add tag" }));
    expect(await within(dialog).findByText("A tag with this name already exists.")).toBeInTheDocument();
    await user.clear(within(dialog).getByRole("textbox", { name: /Name/ }));
    await user.type(within(dialog).getByRole("textbox", { name: /Name/ }), "  Laptops ");
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "Colour" }), "Purple");
    await user.type(within(dialog).getByRole("textbox", { name: "Description" }), "Roaming machines");
    await user.click(within(dialog).getByRole("button", { name: "Add tag" }));
    expect(await screen.findByText("Tag “Laptops” added.")).toBeInTheDocument();
    expect(server.call("POST /patching/tags", 1).body).toEqual({ name: "Laptops", color: "purple", description: "Roaming machines", priority: 20 });

    await user.click(main().getByRole("button", { name: "Edit Servers" }));
    dialog = await screen.findByRole("dialog", { name: "Edit tag" });
    expect(within(dialog).getByRole("textbox", { name: /Name/ })).toHaveValue("Servers");
    await user.clear(within(dialog).getByRole("spinbutton", { name: "Priority" }));
    await user.type(within(dialog).getByRole("spinbutton", { name: "Priority" }), "70");
    await user.click(within(dialog).getByRole("button", { name: "Save tag" }));
    expect(await screen.findByText("Tag “Servers” saved.")).toBeInTheDocument();
    expect(server.call("PUT /patching/tags/:id").path).toBe("/patching/tags/t2");

    await user.click(main().getByRole("button", { name: "Delete Servers" }));
    dialog = await screen.findByRole("dialog", { name: "Delete tag" });
    expect(dialog).toHaveTextContent("takes it off 0 devices, 0 sites and 2 organizations");
    await user.type(within(dialog).getByRole("textbox"), "Servers");
    await user.click(within(dialog).getByRole("button", { name: "Delete tag" }));
    expect(await screen.findByText("Tag “Servers” deleted.")).toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Edit policy" }));
    await screen.findByRole("form", { name: "Pilot ring patch policy" });
    expect(main().getByText("Priority 50")).toBeInTheDocument();
    expect(main().getByText(/when tags disagree, the higher priority wins/)).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "All tags" }));
    expect(await main().findByRole("table")).toBeInTheDocument();
  });

  it("shows tags to an organization's administrator without letting them change them", async () => {
    installFakeApi(settingsRoutes(ORG_ADMIN));
    await open("/settings?tab=patching&view=tags");
    const table = await main().findByRole("table");
    expect(within(table).getByText("Has a policy")).toBeInTheDocument();
    expect(within(table).getByText("None")).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Add tag" })).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: /^Delete/ })).not.toBeInTheDocument();
  });

  it("points to Settings → EasyPatch until EasyPatch is set up", async () => {
    installFakeApi(settingsRoutes(SUPER, { "GET /patching": ok({ ...READY, configured: false }) }));
    await open("/settings?tab=patching");
    expect(await main().findByText("EasyPatch is not set up")).toBeInTheDocument();
    expect(main().getByRole("link", { name: "Set up EasyPatch" })).toHaveAttribute("href", "/settings?tab=easypatch");
  });

  const REASON = "With a connected EasyPatch server, the default policy, tags and tags' policies are changed in EasyPatch's own console.";
  const connected = () =>
    settingsRoutes(SUPER, {
      ...policyRoutes("default", view("default", "Default policy", { own: BUILT_IN, inherited: BUILT_IN, canEdit: false, readOnlyReason: REASON })),
      "GET /patching/tags": ok({ items: TAGS, canManage: false, readOnlyReason: REASON }),
      "GET /patching/policies/tag/:id": fail(409, "easypatch_server_wide", "A tag's policy is seen and changed in EasyPatch's own console."),
    });

  it("with a connected EasyPatch server, leaves the default policy and tags to EasyPatch's console", async () => {
    const user = userEvent.setup();
    installFakeApi(connected());
    await open("/settings?tab=patching");
    expect(await main().findByText(REASON)).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Save policy" })).not.toBeInTheDocument();

    await user.click(main().getByRole("radio", { name: "Tags" }));
    const table = await main().findByRole("table");
    expect(main().getByText(/Tags made there can be given to organizations, sites and devices here/)).toBeInTheDocument();
    expect(within(table).getByText("Has a policy")).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "View policy" })).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Add tag" })).not.toBeInTheDocument();
  });

  it("with a connected EasyPatch server, says a tag's policy is in EasyPatch's console", async () => {
    installFakeApi(connected());
    await open("/settings?tab=patching&view=tags&tag=t1");
    expect(await main().findByText("Managed in EasyPatch")).toBeInTheDocument();
    expect(main().getByText("A tag's policy is seen and changed in EasyPatch's own console.")).toBeInTheDocument();
  });

  it("says who changes the default policy to everyone else", async () => {
    installFakeApi(settingsRoutes(ORG_ADMIN, policyRoutes("default", view("default", "Default policy", { own: BUILT_IN, inherited: BUILT_IN, canEdit: false }))));
    await open("/settings?tab=patching");
    expect(await main().findByText("Only super administrators change the default policy and tags' policies.")).toBeInTheDocument();
    expect(main().getByText("Every 6 hours")).toBeInTheDocument();
  });
});

describe("tags on organizations, sites and devices", () => {
  it("assigns tags to an organization", async () => {
    const user = userEvent.setup();
    let assigned = [{ id: "t2", name: "Servers", color: "teal" }];
    const server = installFakeApi(
      orgRoutes(SUPER, {
        "GET /patching/tags": ok({ items: TAGS, canManage: true }),
        "GET /patching/tags/of/organization/:id": () => ok({ tags: assigned, canAssign: true }),
        "PUT /patching/tags/of/organization/:id": (r) => {
          const ids = (r.body as { tagIds: string[] }).tagIds;
          assigned = TAGS.filter((t) => ids.includes(t.id)).map(({ id, name, color }) => ({ id, name, color }));
          return ok({ tags: assigned, canAssign: true });
        },
      }),
    );
    await open("/organizations/o1?tab=patch-policy");
    await user.click(await main().findByRole("button", { name: "Change tags" }));
    const dialog = await screen.findByRole("dialog", { name: "This organization's tags" });
    expect(within(dialog).getByRole("checkbox", { name: /Servers/ })).toBeChecked();
    await user.click(within(dialog).getByRole("checkbox", { name: /Pilot ring/ }));
    expect(within(dialog).getByText("Has a policy, priority 50")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Save tags" }));
    expect(await screen.findByText("Tags saved.")).toBeInTheDocument();
    expect(server.call("PUT /patching/tags/of/organization/:id").body).toEqual({ tagIds: ["t2", "t1"] });
    expect(await main().findByTitle("Pilot ring")).toBeInTheDocument();
  });

  it("keeps a device's tags from its site, and says when there are none", async () => {
    const user = userEvent.setup();
    const { TagsField } = await import("./Tags");
    installFakeApi({
      ...baseRoutes(SUPER),
      "GET /patching/tags": ok({ items: [], canManage: true }),
      "GET /patching/tags/of/device/:id": ok({ tags: [{ id: "t1", name: "Pilot ring", color: "amber", inheritedFrom: "Site" }], canAssign: true }),
    });
    renderWithProviders(<TagsField level="device" id="d1" />);
    expect(await screen.findByTitle("Pilot ring (from its site)")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Change tags" }));
    const dialog = await screen.findByRole("dialog", { name: "This device's tags" });
    expect(dialog).toHaveTextContent("Tags the device has through its site or organization are changed there.");
    expect(await within(dialog).findByText("No tags yet")).toBeInTheDocument();
  });
});

describe("policy checks", () => {
  it("mirrors the server's", () => {
    const base = layer();
    expect(checkPolicy(layer({ maintenanceDurationMinutes: 5, maintenanceDays: [1], maintenanceStart: "02:00" }), "site", INHERITED, true).maintenanceDays).toBe(
      "Choose a window length from 15 to 1440 minutes.",
    );
    expect(checkPolicy(layer({ maintenanceDays: [1], maintenanceStart: "2am", maintenanceDurationMinutes: 60 }), "site", INHERITED, true).maintenanceDays).toBe(
      "Give a time as in 02:00.",
    );
    // A tag that sets no window is not held to one: its devices keep their own.
    expect(checkPolicy(layer({ autoInstallEnabled: true }), "tag", BUILT_IN, true)).toEqual({});
    expect(checkPolicy(layer({ autoInstallEnabled: true }), "site", BUILT_IN, true).maintenanceDays).toMatch(/choose its days/);
    expect(checkPolicy(base, "site", BUILT_IN, true)).toEqual({});
    const schedule = { enabled: true, days: [0], time: "3am", condition: "Always", mode: "Immediate", countdownMinutes: 5, deadlineMinutes: 240, expiryMinutes: 120 };
    expect(checkPolicy(layer({ restartSchedule: schedule }), "site", BUILT_IN, true).restartSchedule).toBe("Give the restart time as in 03:00.");
    const apps = Array.from({ length: 101 }, (_, i) => `Vendor.App${i}`);
    expect(checkPolicy(layer({ applicationUpdates: { enabled: true, approvedApps: apps } }), "site", BUILT_IN, true).applicationUpdates).toBe(
      "Approve at most 100 applications.",
    );
    // Not a Windows computer: its Windows settings are not checked, as they do not apply.
    expect(checkPolicy(layer({ applicationUpdates: { enabled: true, approvedApps: apps } }), "device", BUILT_IN, false)).toEqual({});
  });

  it("names where a value comes from", () => {
    expect(fromText(undefined)).toBe("");
    expect(fromText("Site")).toBe("from the site");
    expect(fromText("Somewhere")).toBe("from Somewhere");
  });
});
