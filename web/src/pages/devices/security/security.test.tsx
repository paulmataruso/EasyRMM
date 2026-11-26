import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { baseRoutes, installFakeApi, ok, sessionView } from "../../../test/fakeApi";
import { device, history, inventory, metrics } from "../../../test/fixtures";
import { renderApp } from "../../../test/render";
import { asrWeakens, weakens } from "./text";

// The Defender module's panels (ADR-0074): locks where something else owns a setting, the weakening actions and their
// confirmation, EasyRMM's own exclusions, Tamper Protection read-only, and the events.

const WINDOWS = device("d1", "FRONT-DESK", {
  platform: "windows",
  osDescription: "Windows 11 Pro 24H2",
  agent: { version: "1.5.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null },
});
const ROLE = { name: "defender", state: "present", module: "defender", label: "Microsoft Defender", enabled: true };
const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "defender.view", "defender.manage"] });
const SITE_ADMIN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "defender.view", "defender.manage", "defender.weaken", "defender.view_sensitive"],
});

const run = (action: string, id: string) => ({ jobId: `j-${id}`, runId: id, action, status: "queued", expiresAt: "2026-11-26T11:00:00Z" });
const result = (action: string, id: string, data: unknown) => ({
  runId: id,
  deviceId: "d1",
  action,
  version: 1,
  status: "succeeded",
  finishedAt: "2026-11-26T10:00:00Z",
  ok: true,
  data,
});

function routes(session: ReturnType<typeof sessionView>, reads: Record<string, unknown>) {
  const table: Record<string, unknown> = {
    ...baseRoutes(session),
    "GET /devices/:id": ok(WINDOWS),
    "GET /devices/:id/roles": ok({ known: true, reportedAt: "2026-11-26T10:00:00Z", roles: [ROLE] }),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: [] }),
    "GET /devices/:id/defender": { status: 404, body: { error: { code: "not_found", message: "none" } } },
    "GET /devices/:id/defender/events": ok({
      items: [
        { id: 2, eventId: 5007, at: "2026-11-26T09:00:00Z", severity: 0, summary: { class: "exclusion" }, ours: false, backfill: false },
        { id: 1, eventId: 1116, at: "2026-11-26T08:00:00Z", severity: 5, threatName: "Virus:DOS/EICAR_Test_File", summary: {}, ours: false, backfill: false },
        { id: 0, eventId: 5001, at: "2026-11-26T07:00:00Z", severity: 0, summary: {}, ours: true, backfill: false },
      ],
      gap: "2026-11-25T12:00:00Z",
    }),
    "POST /devices/:id/winmod-read/:action": (req: { params: Record<string, string> }) =>
      ok({ action: req.params.action, takenAt: null, stale: true, data: null, refreshing: true, offline: false, runId: req.params.action }),
    "POST /devices/:id/winmod/:action": (req: { params: Record<string, string> }) => ok(run(req.params.action ?? "", req.params.action ?? "")),
    "GET /winmod/runs/:id": (req: { params: Record<string, string> }) => {
      const id = req.params.id ?? "";
      const name = id.replace(/^defender\./, "");
      if (name in reads) return ok(result(id, id, reads[name]));
      // A panel the test did not give data for reads by itself too; the computer says it cannot.
      if (name.endsWith("_read") || name === "status") return ok({ ...result(id, id, undefined), ok: false, failure: { code: "unsupported", message: "Not in this test." } });
      return ok(result(id, id, { applied: true, reason: "", before: "a", after: "b" }));
    },
  };
  return table as Parameters<typeof installFakeApi>[0];
}

describe("the direction of a change (a mirror of the server's table)", () => {
  it("knows what lowers protection", () => {
    expect(weakens("DisableRealtimeMonitoring", "true")).toBe(true);
    expect(weakens("DisableRealtimeMonitoring", "false")).toBe(false);
    expect(weakens("MAPSReporting", "0")).toBe(true);
    expect(weakens("MAPSReporting", "2")).toBe(false);
    expect(weakens("PUAProtection", "AuditMode")).toBe(true);
    expect(weakens("HighThreatDefaultAction", "NoAction")).toBe(true);
    expect(weakens("HighThreatDefaultAction", "Quarantine")).toBe(false);
    expect(weakens("ScanAvgCPULoadFactor", "30")).toBe(false);
    expect(weakens("DisableAutoExclusions", "true")).toBe(true);
    expect(weakens("NoSuchField", "true")).toBe(false);
    expect(asrWeakens("AuditMode")).toBe(true);
    expect(asrWeakens("Warn")).toBe(false);
  });
});

const PREFS = {
  tamperProtected: true,
  fields: [
    { name: "DisableRealtimeMonitoring", group: "protection", value: false, supported: true, managedBy: null },
    { name: "DisableBehaviorMonitoring", group: "protection", value: false, supported: true, managedBy: "group_policy" },
    { name: "ScanAvgCPULoadFactor", group: "performance", value: 50, supported: true, managedBy: null },
    { name: "DisableAutoExclusions", group: "servers", value: false, supported: false, managedBy: null },
  ],
};

describe("the Protection panel", () => {
  it("locks a setting Group Policy owns, hides one the computer does not have, and says Tamper Protection is not changed here", async () => {
    installFakeApi(routes(SITE_ADMIN, { "preferences_read": PREFS }));
    renderApp("/devices/d1?tab=security");
    await screen.findByText("Managed by Group Policy");
    expect(screen.queryByLabelText("Disable behavior monitoring value")).toBeNull();
    expect(screen.getByLabelText("Disable realtime monitoring value")).toBeInTheDocument();
    expect(screen.queryByText("Disable auto exclusions")).toBeNull();
    expect(screen.getByText(/never from here/)).toBeInTheDocument();
  });

  it("changes a routine setting at once, with no confirmation", async () => {
    const api = installFakeApi(routes(TECH, { preferences_read: PREFS }));
    renderApp("/devices/d1?tab=security");
    const input = await screen.findByLabelText("Scan avg CPU load factor value");
    await userEvent.clear(input);
    await userEvent.type(input, "30");
    await userEvent.click(within(input.closest("li")!).getByRole("button", { name: "Apply" }));
    await screen.findByText("Scan avg CPU load factor changed.");
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.path.endsWith("preferences_set"))!;
    expect(call.body).toEqual({ params: { field: "ScanAvgCPULoadFactor", value: "30" } });
  });

  it("asks before lowering protection and sends the weakening action with its typed confirmation", async () => {
    const api = installFakeApi(routes(SITE_ADMIN, { preferences_read: PREFS }));
    renderApp("/devices/d1?tab=security");
    const select = await screen.findByLabelText("Disable realtime monitoring value");
    await userEvent.selectOptions(select, "true");
    await userEvent.click(within(select.closest("li")!).getByRole("button", { name: "Apply" }));
    expect(api.callsTo("POST /devices/:id/winmod/:action").filter((c) => c.path.endsWith("preferences_weaken"))).toHaveLength(0);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/second factor/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Lower protection" }));
    await screen.findByText("Disable realtime monitoring changed.");
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.path.endsWith("preferences_weaken"))!;
    expect(call.body).toEqual({ params: { field: "DisableRealtimeMonitoring", value: "true" }, confirm: "defender.preferences_weaken:DisableRealtimeMonitoring" });
  });

  it("gives a Technician no way to lower protection", async () => {
    installFakeApi(routes(TECH, { preferences_read: PREFS }));
    renderApp("/devices/d1?tab=security");
    const select = await screen.findByLabelText("Disable realtime monitoring value");
    await userEvent.selectOptions(select, "true");
    expect(within(select.closest("li")!).getByRole("button", { name: "Apply" })).toBeDisabled();
    expect(screen.getByText("Needs a Site Administrator")).toBeInTheDocument();
  });

  it("says a write that did not apply did not change anything", async () => {
    installFakeApi(
      routes(TECH, { preferences_read: PREFS }),
    );
    const api = installFakeApi({
      ...routes(TECH, { preferences_read: PREFS }),
      "GET /winmod/runs/:id": (req: { params: Record<string, string> }) =>
        (req.params.id ?? "").endsWith("_read") && req.params.id !== "defender.preferences_read"
          ? ok({ ...result("x", req.params.id ?? "", undefined), ok: false, failure: { code: "unsupported", message: "Not in this test." } })
          : ok(result("x", req.params.id ?? "", req.params.id === "defender.preferences_read" ? PREFS : { applied: false, reason: "Tamper Protection blocked it.", before: "50", after: "50" })),
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/devices/d1?tab=security");
    const input = await screen.findByLabelText("Scan avg CPU load factor value");
    await userEvent.clear(input);
    await userEvent.type(input, "30");
    await userEvent.click(within(input.closest("li")!).getByRole("button", { name: "Apply" }));
    await screen.findByText("Tamper Protection blocked it.");
    expect(api.callsTo("POST /devices/:id/winmod/:action").length).toBeGreaterThan(0);
  });
});

const EXCLUSIONS = {
  path: [
    { value: "C:\\Program Files\\EasyRMM\\Agent", ours: true, managedBy: null },
    { value: "D:\\LineOfBusiness", ours: false, managedBy: null },
    { value: "E:\\Policy", ours: false, managedBy: "group_policy" },
  ],
  process: [],
  extension: [],
  asrOnly: [],
  unavailable: [],
  localMergeDisabled: false,
  tamperProtected: false,
};

describe("the Exclusions panel", () => {
  it("shows EasyRMM's own locked first with no way to remove them, and an administrator's removable", async () => {
    const api = installFakeApi(routes(SITE_ADMIN, { exclusions_read: EXCLUSIONS }));
    renderApp("/devices/d1?tab=security");
    const paths = await screen.findByRole("region", { name: "Paths" });
    const items = within(paths).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("EasyRMM");
    expect(within(items[0]!).queryByRole("button", { name: "Remove" })).toBeNull();
    expect(within(items[1]!).getByRole("button", { name: "Remove" })).toBeInTheDocument();
    expect(items[2]).toHaveTextContent("Managed by Group Policy");
    expect(within(items[2]!).queryByRole("button", { name: "Remove" })).toBeNull();

    await userEvent.click(within(items[1]!).getByRole("button", { name: "Remove" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Remove exclusion" }));
    await screen.findByText("Exclusion removed.");
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.path.endsWith("exclusion_remove"))!;
    expect(call.body).toEqual({ params: { kind: "path", value: "D:\\LineOfBusiness" }, confirm: "defender.exclusion_remove:D:\\LineOfBusiness" });
  });

  it("adds an exclusion only with a reason, behind a confirmation that says what stops being scanned", async () => {
    const api = installFakeApi(routes(SITE_ADMIN, { exclusions_read: EXCLUSIONS }));
    renderApp("/devices/d1?tab=security");
    const form = await screen.findByRole("form", { name: "Add an exclusion" });
    await userEvent.type(within(form).getByLabelText("Value"), "D:\\NewApp");
    expect(within(form).getByRole("button", { name: "Add exclusion" })).toBeDisabled();
    await userEvent.type(within(form).getByLabelText("Reason"), "line of business app");
    await userEvent.click(within(form).getByRole("button", { name: "Add exclusion" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/stop scanning/)).toHaveTextContent("D:\\NewApp");
    await userEvent.click(within(dialog).getByRole("button", { name: "Add exclusion" }));
    await screen.findByText("Exclusion added.");
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.path.endsWith("exclusion_add"))!;
    expect(call.body).toEqual({
      params: { kind: "path", value: "D:\\NewApp", reason: "line of business app" },
      confirm: "defender.exclusion_add:D:\\NewApp",
    });
  });

  it("is not offered to someone without view_sensitive, and a Technician cannot add", async () => {
    installFakeApi(routes(TECH, {}));
    renderApp("/devices/d1?tab=security");
    await screen.findByText("Protection settings");
    expect(screen.queryByText("Exclusions")).toBeNull();
    expect(screen.queryByText("Quarantine")).toBeNull();
  });
});

describe("the other panels", () => {
  it("turns an ASR rule on, and treats an unrecognized rule as unrecognized", async () => {
    const api = installFakeApi(
      routes(SITE_ADMIN, {
        asr_read: {
          supported: true,
          rules: [
            { id: "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", name: "Block credential stealing from the Windows local security authority subsystem", known: true, mode: "AuditMode", managedBy: null },
            { id: "00000000-0000-0000-0000-000000000000", name: "", known: false, mode: "Enabled", managedBy: null },
          ],
        },
      }),
    );
    renderApp("/devices/d1?tab=security");
    await screen.findByText("Unrecognized rule");
    const select = await screen.findByLabelText(/Block credential stealing.* mode/);
    await userEvent.selectOptions(select, "Enabled");
    await userEvent.click(within(select.closest("li")!).getByRole("button", { name: "Apply" }));
    await screen.findByText("Rule changed.");
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.path.endsWith("asr_set"))!;
    expect(call.body).toEqual({ params: { id: "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", mode: "Enabled" } });
  });

  it("restores a quarantined item only after a warning and with the typed confirmation", async () => {
    const api = installFakeApi(routes(SITE_ADMIN, { quarantine_read: { items: [{ name: "Virus:DOS/EICAR_Test_File", path: "C:\\x\\eicar.txt" }] }, threats_read: { threats: [] } }));
    renderApp("/devices/d1?tab=security");
    await userEvent.click(await screen.findByRole("button", { name: "Restore" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/where Defender found it/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: "Restore" }));
    await screen.findByText("Restored to its original location.");
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.path.endsWith("quarantine_restore"))!;
    expect(call.body).toEqual({ params: { name: "Virus:DOS/EICAR_Test_File" }, confirm: "defender.quarantine_restore:Virus:DOS/EICAR_Test_File" });
  });

  it("runs a quick scan from the Scans panel", async () => {
    const api = installFakeApi(routes(TECH, { scan_quick: { scanType: "quick", finishedAt: "2026-11-26T10:05:00Z" } }));
    renderApp("/devices/d1?tab=security");
    await userEvent.click(await screen.findByRole("button", { name: "Quick scan" }));
    await screen.findAllByText(/The quick scan finished/);
    expect(api.callsTo("POST /devices/:id/winmod/:action").at(-1)!.path).toBe("/devices/d1/winmod/defender.scan_quick");
  });

  it("shows the events, EasyRMM's own marked, and warns of a gap", async () => {
    installFakeApi(routes(TECH, {}));
    renderApp("/devices/d1?tab=security");
    await screen.findByText(/Malware detected: Virus:DOS\/EICAR_Test_File/);
    expect(screen.getByText("An exclusion changed")).toBeInTheDocument();
    expect(screen.getByText("Made by EasyRMM")).toBeInTheDocument();
    expect(screen.getByText(/Events may have been missed/)).toBeInTheDocument();
  });
});
