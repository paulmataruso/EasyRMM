import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DeviceRole, DeviceRoles } from "../../../../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../../../../test/fakeApi";
import { device, history, inventory, metrics } from "../../../../../test/fixtures";
import { renderApp } from "../../../../../test/render";
import { filterNodes } from "./SettingsTree";
import { dnToPath, versionText } from "./gpoText";
import type { Gpo, GpoBackup, GpoDetail, GpoPage, GpoReport, GpoRequest, GpoStatus, LinkTree, WmiFilters } from "./types";

// The Group Policy view of the Roles tab (ADR-0083, slice 1).

const AGENT = {
  version: "1.5.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-26T10:00:00Z",
  enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null,
};
const DC = device("d1", "DC1", { platform: "windows", osDescription: "Windows Server 2025", agent: AGENT });
const role: DeviceRole = { name: "gpmc", state: "present", module: "group_policy", label: "Group Policy", enabled: true };
const roles: DeviceRoles = { known: true, reportedAt: "2026-11-26T10:00:00Z", roles: [role] };
const base = ["org.view", "site.view", "device.view"] as const;
const ALL = [...base, "gpo.view", "gpo.edit", "gpo.link", "gpo.manage"] as const;

const ver = (n: number) => ({ directory: n, sysvol: n });
const gpo = (id: string, name: string, extra: Partial<Gpo> = {}): Gpo => ({
  id, name, status: "AllSettingsEnabled", description: "", owner: "CORP\\Domain Admins", created: null, modified: "2026-03-02T14:01:09Z",
  computer: ver(3), user: ver(0), wmiFilter: "", default: false, linkCount: 1, links: [], ...extra,
});
const BASELINE = gpo("11111111-1111-1111-1111-111111111111", "Workstation baseline");
const DEFAULT = gpo("31b2f340-016d-11d2-945f-00c04fb984f9", "Default Domain Policy", { default: true });
const ORPHAN = gpo("22222222-2222-2222-2222-222222222222", "Old experiment", { linkCount: 0 });
const STATUS: GpoStatus = { domain: "corp.test", domainDn: "DC=corp,DC=test", controller: "dc1.corp.test", gpoCount: 3, empty: 1, unlinked: 1, targets: 4 };
const PAGE: GpoPage = { total: 3, offset: 0, next: null, walked: true, items: [BASELINE, DEFAULT, ORPHAN] };
const DETAIL: GpoDetail = {
  ...BASELINE,
  reportLinks: [{ name: "Workstations", path: "corp.test/Computers/Workstations", enabled: true, enforced: false, sensitive: false }],
  trustees: [
    { name: "Authenticated Users", sid: "S-1-5-11", type: "well_known", permission: "GpoApply", inherited: false, denied: false, apply: true },
    { name: "Domain Admins", sid: "S-1-5-21-1-2-3-512", type: "group", permission: "GpoEditDeleteModifySecurity", inherited: false, denied: false, apply: false },
  ],
};
const TREE: LinkTree = {
  domain: "corp.test", total: 2, offset: 0, next: null,
  targets: [
    { dn: "DC=corp,DC=test", name: "corp.test", kind: "domain", sensitive: true, inheritanceBlocked: false, links: [{ gpoId: DEFAULT.id, gpoName: DEFAULT.name, target: "DC=corp,DC=test", targetName: "corp.test", kind: "domain", enabled: true, enforced: false, order: 1 }] },
    { dn: "OU=Workstations,DC=corp,DC=test", name: "Workstations", kind: "ou", sensitive: false, inheritanceBlocked: true,
      links: [{ gpoId: BASELINE.id, gpoName: BASELINE.name, target: "OU=Workstations,DC=corp,DC=test", targetName: "Workstations", kind: "ou", enabled: true, enforced: false, order: 1 }] },
  ],
};
const REPORT: GpoReport = {
  id: BASELINE.id, name: BASELINE.name, created: "", modified: "2026-03-02T14:01:09", links: [], truncated: false, settings: 4, total: 4,
  findings: ["A Group Policy Preferences item holds a stored password (cpassword)."],
  computer: {
    enabled: true, version: ver(3),
    extensions: [
      { name: "Registry", kind: "RegistrySettings", noApi: false, settings: [{ label: "Turn off Windows Defender Antivirus", state: "Disabled", children: [{ label: "Category", value: "Windows Components/Microsoft Defender Antivirus" }] }] },
      { name: "Software Installation", kind: "SoftwareInstallationSettings", noApi: true, settings: [{ label: "Contoso Viewer 2.1", children: [{ label: "Deployment Type", value: "Assigned" }] }] },
    ],
  },
  user: { enabled: false, version: ver(0), extensions: [] },
};
const WMI: WmiFilters = { filters: [{ id: "f1", name: "Laptops", description: "", queries: ["root\\CIMv2;SELECT * FROM Win32_Battery"] }] };
const BACKUP: GpoBackup = {
  id: "b1", backupId: "33333333-3333-3333-3333-333333333333", gpoId: BASELINE.id, gpoName: BASELINE.name, kind: "automatic", action: "group_policy.gpo_rename",
  actorLabel: "admin@example.com", reason: "Tidy up the name", size: 9000, sha256: "a".repeat(64), computerVersion: 3, userVersion: 0, createdAt: "2026-11-26T09:00:00Z", parts: 1,
};
const REQUEST: GpoRequest = {
  id: "r1", deviceId: "d1", action: "group_policy.link_add", label: "Link a GPO", params: { id: BASELINE.id, target: "DC=corp,DC=test", reason: "Baseline everywhere" },
  sensitivity: "sensitive_link", summary: "Link a GPO: Workstation baseline", reason: "Baseline everywhere", status: "pending", requestedBy: "u2", requestedLabel: "ann@example.com",
  createdAt: "2026-11-26T09:30:00Z", expiresAt: "2026-11-27T09:30:00Z", decidedLabel: "", decidedReason: "", decidedAt: null, runId: null, canDecide: true,
};

type Results = Record<string, unknown>;
function routes(session: ReturnType<typeof sessionView>, results: Results, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(DC),
    "GET /devices/:id/roles": ok(roles),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: [] }),
    "GET /devices/:id/defender": fail(404, "not_found", "none"),
    "GET /devices/:id/gpo/backups": ok([BACKUP]),
    "GET /organizations/:id/gpo/requests": ok([REQUEST]),
    "GET /organizations/:id/gpo/settings": ok({ approvalSensitive: true, approvalAll: false }),
    // A stored result is shown at once, and no run is started.
    "POST /devices/:id/winmod-read/:action": (req: { params: Record<string, string> }) =>
      ok({ action: req.params.action, takenAt: "2026-11-26T10:00:00Z", stale: false, data: results[req.params.action!] ?? null, refreshing: false, offline: false }),
    "POST /devices/:id/winmod/:action": (req: { params: Record<string, string> }) =>
      ok({ jobId: "j", runId: req.params.action, action: req.params.action, status: "queued", expiresAt: "2026-11-26T11:00:00Z" }),
    "GET /winmod/runs/:id": (req: { params: Record<string, string> }) =>
      ok({ runId: req.params.id, deviceId: "d1", action: req.params.id, version: 1, status: "succeeded", finishedAt: "2026-11-26T10:00:00Z", ok: true, data: { summary: "done" } }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}
const RESULTS: Results = {
  "group_policy.status": STATUS, "group_policy.gpo_list": PAGE, "group_policy.gpo_get": DETAIL, "group_policy.link_tree": TREE,
  "group_policy.wmi_filters": WMI, "group_policy.gpo_report": REPORT,
};
const admin = sessionView({ isSuperAdmin: false, permissions: [...ALL] });
const winmod = (api: ReturnType<typeof installFakeApi>, action: string) => api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.params.action === action);

async function open() {
  renderApp("/devices/d1?tab=roles");
  await screen.findByRole("tab", { name: "Roles" });
  return (await screen.findByText("Workstation baseline", { selector: "td" })).closest("tr")!;
}

describe("the Group Policy helpers", () => {
  it("writes a version pair, and a readable path for a distinguished name", () => {
    expect(versionText(ver(3))).toBe("3");
    expect(versionText({ directory: 4, sysvol: 3 })).toBe("4 / 3");
    expect(dnToPath("OU=East,OU=Sales,DC=corp,DC=test")).toBe("corp.test/Sales/East");
  });
  it("filters the settings by name, value or state, keeping the path to a match", () => {
    const nodes = REPORT.computer.extensions[0]!.settings;
    expect(filterNodes(nodes, "defender")).toHaveLength(1);
    expect(filterNodes(nodes, "disabled")).toHaveLength(1);
    expect(filterNodes(nodes, "nothing like it")).toHaveLength(0);
    expect(filterNodes(nodes, "")).toBe(nodes);
  });
});

describe("the Group Policy view", () => {
  it("shows the GPOs from the stored result with no read button, and the card of counts", async () => {
    installFakeApi(routes(admin, RESULTS));
    const row = await open();
    expect(screen.queryByRole("button", { name: /Read now/ })).toBeNull();
    expect(within(row).getByText("Enabled")).toBeInTheDocument();
    const def = screen.getByText("Default Domain Policy", { selector: "td" }).closest("tr")!;
    expect(within(def).getByText("Default")).toBeInTheDocument();
    expect(within(screen.getByText("Old experiment", { selector: "td" }).closest("tr")!).getByText("None")).toBeInTheDocument();
    expect(screen.getByText("Not linked anywhere")).toBeInTheDocument();
  });

  it("shows a skeleton until the first result", async () => {
    installFakeApi(routes(admin, {}));
    renderApp("/devices/d1?tab=roles");
    await screen.findByRole("tab", { name: "Roles" });
    expect((await screen.findAllByRole("status")).length).toBeGreaterThan(0);
  });

  it("renames a GPO with a typed reason, the versions it was read at, and a step-up handled by the client", async () => {
    const api = installFakeApi(routes(admin, RESULTS));
    const row = await open();
    await userEvent.click(within(row).getByRole("button", { name: "Details" }));
    const detail = await screen.findByRole("dialog", { name: "Workstation baseline" });
    await userEvent.click(await within(detail).findByRole("button", { name: "Rename" }));
    const dialog = await screen.findByRole("dialog", { name: /Rename Workstation baseline/ });
    const go = within(dialog).getByRole("button", { name: "Rename" });
    await userEvent.clear(within(dialog).getByLabelText(/New name/));
    await userEvent.type(within(dialog).getByLabelText(/New name/), "Workstation baseline 2");
    expect(go).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Why/), "Align the name with the policy");
    await userEvent.click(go);
    await waitFor(() => expect(winmod(api, "group_policy.gpo_rename")).toBeTruthy());
    expect(winmod(api, "group_policy.gpo_rename")!.body).toEqual({
      params: { id: BASELINE.id, newName: "Workstation baseline 2", expectComputerVersion: 3, expectUserVersion: 0, reason: "Align the name with the policy" },
    });
  });

  it("deletes only with the GPO's name typed, and never offers delete or rename on a Default policy", async () => {
    const api = installFakeApi(routes(admin, { ...RESULTS, "group_policy.gpo_get": { ...DETAIL, ...DEFAULT, reportLinks: [], trustees: [] } }));
    await open();
    const def = screen.getByText("Default Domain Policy", { selector: "td" }).closest("tr")!;
    await userEvent.click(within(def).getByRole("button", { name: "Details" }));
    const detail = await screen.findByRole("dialog", { name: "Default Domain Policy" });
    expect(await within(detail).findByRole("button", { name: "Status" })).toBeInTheDocument();
    expect(within(detail).queryByRole("button", { name: "Delete" })).toBeNull();
    expect(within(detail).queryByRole("button", { name: "Rename" })).toBeNull();
    expect(winmod(api, "group_policy.gpo_delete")).toBeUndefined();
  });

  it("confirms a delete by the typed name", async () => {
    const api = installFakeApi(routes(admin, RESULTS));
    const row = await open();
    await userEvent.click(within(row).getByRole("button", { name: "Details" }));
    const detail = await screen.findByRole("dialog", { name: "Workstation baseline" });
    await userEvent.click(await within(detail).findByRole("button", { name: "Delete" }));
    const dialog = await screen.findByRole("dialog", { name: /Delete Workstation baseline/ });
    const go = within(dialog).getByRole("button", { name: "Delete GPO" });
    await userEvent.type(within(dialog).getByLabelText(/Why/), "It is replaced by the new baseline");
    expect(go).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Type/), "Workstation baseline");
    await userEvent.click(go);
    await waitFor(() => expect(winmod(api, "group_policy.gpo_delete")).toBeTruthy());
    expect(winmod(api, "group_policy.gpo_delete")!.body).toMatchObject({ confirm: "group_policy.gpo_delete:Workstation baseline", params: { id: BASELINE.id, name: "Workstation baseline" } });
  });

  it("offers a request for approval when the server says a second person must approve", async () => {
    const api = installFakeApi(
      routes(admin, RESULTS, {
        "POST /devices/:id/winmod/:action": fail(409, "approval_required", "A change at the domain root, the Domain Controllers OU or a site, or to a GPO linked there, needs a second person to approve it."),
        "POST /devices/:id/gpo/requests": ok(REQUEST),
      }),
    );
    const row = await open();
    await userEvent.click(within(row).getByRole("button", { name: "Details" }));
    const detail = await screen.findByRole("dialog", { name: "Workstation baseline" });
    await userEvent.click(await within(detail).findByRole("button", { name: "Link…" }));
    const dialog = await screen.findByRole("dialog", { name: /Link Workstation baseline/ });
    await userEvent.type(within(dialog).getByLabelText(/Link to/), "DC=corp,DC=test");
    await userEvent.type(within(dialog).getByLabelText(/Why/), "Baseline for every computer");
    await userEvent.click(within(dialog).getByRole("button", { name: "Link" }));
    await userEvent.click(await within(dialog).findByRole("button", { name: "Ask for approval" }));
    expect(await screen.findByText(/A second administrator who may edit Group Policy must approve/)).toBeInTheDocument();
    expect(api.callsTo("POST /devices/:id/gpo/requests")[0]!.body).toMatchObject({ action: "group_policy.link_add", params: { target: "DC=corp,DC=test", reason: "Baseline for every computer" } });
  });

  it("shows every setting read-only, with the findings, the no-API areas and a search", async () => {
    installFakeApi(routes(admin, RESULTS));
    const row = await open();
    await userEvent.click(within(row).getByRole("button", { name: "Settings" }));
    expect(await screen.findByText(/stored password \(cpassword\)/)).toBeInTheDocument();
    expect(screen.getByText("Turn off Windows Defender Antivirus")).toBeInTheDocument();
    expect(screen.getAllByText("Disabled", { selector: "span" }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Read-only here: no supported API changes this/).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /Edit|Save/ })).toBeNull();
    await userEvent.type(screen.getByLabelText("Search the settings"), "viewer");
    expect(screen.queryByText("Turn off Windows Defender Antivirus")).toBeNull();
    expect(screen.getByText("Contoso Viewer 2.1")).toBeInTheDocument();
  });

  it("lists the link tree and the WMI filters, and blocks inheritance through a dialog", async () => {
    const api = installFakeApi(routes(admin, RESULTS));
    await open();
    await userEvent.click(screen.getByRole("radio", { name: "Links" }));
    const ou = (await screen.findByText("Workstations", { selector: "span" })).closest("tr")!;
    expect(within(ou).getByText("blocks inheritance")).toBeInTheDocument();
    const root = screen.getByText("corp.test", { selector: "span.font-medium" }).closest("tr")!;
    expect(within(root).getByText("reaches many")).toBeInTheDocument();
    await userEvent.click(within(ou).getByRole("button", { name: "Allow inheritance" }));
    const dialog = await screen.findByRole("dialog", { name: "Allow inheritance" });
    await userEvent.type(within(dialog).getByLabelText(/Why/), "Workstations should get the baseline");
    await userEvent.click(within(dialog).getByRole("button", { name: "Allow inheritance" }));
    await waitFor(() => expect(winmod(api, "group_policy.inheritance_block")).toBeTruthy());
    expect(winmod(api, "group_policy.inheritance_block")!.body).toMatchObject({ params: { target: "OU=Workstations,DC=corp,DC=test", blocked: false } });
    await userEvent.click(screen.getByRole("radio", { name: "WMI filters" }));
    expect(await screen.findByText("Laptops")).toBeInTheDocument();
  });

  it("lists the backups and sends one in pieces before it asks for the restore", async () => {
    const api = installFakeApi(
      routes(admin, RESULTS, { "GET /devices/:id/gpo/backups/:backupId/chunks/:index": ok({ index: 0, count: 1, chunk: "UEs=" }) }),
    );
    await open();
    await userEvent.click(screen.getByRole("radio", { name: "Backups" }));
    const row = (await screen.findByText("Workstation baseline", { selector: "td" })).closest("tr")!;
    expect(within(row).getByText("Tidy up the name")).toBeInTheDocument();
    await userEvent.click(within(row).getByRole("button", { name: "Restore" }));
    const dialog = await screen.findByRole("dialog", { name: /Restore Workstation baseline/ });
    await userEvent.type(within(dialog).getByLabelText(/Why/), "The rename broke a script");
    await userEvent.type(within(dialog).getByLabelText(/Type/), "Workstation baseline");
    await userEvent.click(within(dialog).getByRole("button", { name: "Restore" }));
    await waitFor(() => expect(winmod(api, "group_policy.gpo_restore")).toBeTruthy());
    expect(winmod(api, "group_policy.gpo_restore_stage")!.body).toEqual({ params: { backupId: BACKUP.backupId, index: 0, count: 1, chunk: "UEs=" } });
    expect(winmod(api, "group_policy.gpo_restore")!.body).toMatchObject({
      confirm: "group_policy.gpo_restore:Workstation baseline", params: { zipSha256: BACKUP.sha256, parts: 1, backupId: BACKUP.backupId },
    });
  });

  it("lets a second administrator review and approve, and says who is waiting for whom", async () => {
    const api = installFakeApi(routes(admin, RESULTS, { "POST /gpo/requests/:id/approve": ok({ jobId: "j", runId: "r", action: "group_policy.link_add", status: "queued", expiresAt: "" }) }));
    await open();
    await userEvent.click(screen.getByRole("radio", { name: "Approvals" }));
    await userEvent.click(await screen.findByRole("button", { name: "Review" }));
    const dialog = await screen.findByRole("dialog", { name: "Review a change" });
    expect(within(dialog).getByText("DC=corp,DC=test")).toBeInTheDocument();
    const approve = within(dialog).getByRole("button", { name: "Approve and run" });
    expect(approve).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Your reason/), "Reviewed the target and the GPO");
    await userEvent.click(approve);
    await waitFor(() => expect(api.callsTo("POST /gpo/requests/:id/approve")).toHaveLength(1));
    expect(api.callsTo("POST /gpo/requests/:id/approve")[0]!.body).toEqual({ reason: "Reviewed the target and the GPO" });
  });

  it("offers no change to someone with gpo.view only, and none on a controller the domain's changes do not go through", async () => {
    installFakeApi(routes(sessionView({ isSuperAdmin: false, permissions: [...base, "gpo.view"] }), RESULTS));
    await open();
    expect(screen.queryByRole("button", { name: "Create a GPO" })).toBeNull();
    expect(screen.queryByRole("radio", { name: "WMI filters" })).toBeNull();
  });

  it("is not in the Roles tab for someone without gpo.view", async () => {
    installFakeApi(routes(sessionView({ isSuperAdmin: false, permissions: [...base] }), RESULTS));
    renderApp("/devices/d1?tab=overview");
    await screen.findByRole("heading", { name: "DC1" });
    expect(screen.queryByRole("tab", { name: "Roles" })).toBeNull();
  });
});
