import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AlertEntry, AlertPolicy, DiskCheck } from "../../api/types";
import { baseRoutes, installFakeApi, noContent, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { alertEntry, alertPolicy, device, org, site } from "../../test/fixtures";
import { renderApp, renderWithProviders } from "../../test/render";
import { applyAlertFlash, getStoredAlertFlash } from "../../lib/alertFlash";
import { conditionText, formatMinutes, resolutionText, risingHint, valueText } from "./alertText";
import { DeviceAlertsCard } from "./DeviceAlertsCard";

const location = () => screen.getByTestId("location").textContent;

const TECHNICIAN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "alert.view", "alert.manage", "monitoring.view"],
});
const VIEWER = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "alert.view"] });
const ADMIN = sessionView({ permissions: [...sessionView().permissions, "device.view", "alert.view", "alert.manage", "monitoring.view", "monitoring.manage"] });

const DISK = alertEntry("a1", "Disk almost full");
const CPU = alertEntry("a2", "High processor use", { kind: "cpu", threshold: 95, minutes: 15, severity: "warning", lastValue: 97, deviceId: "d2", deviceName: "WEB-02", status: "acknowledged", acknowledgedBy: "sam@example.com", acknowledgedAt: "2026-11-01T10:05:00Z" });

function routes(alerts: AlertEntry[] = [DISK, CPU]) {
  return {
    ...baseRoutes(TECHNICIAN),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders"), org("o2", "Contoso Dental Group")] }),
    "GET /alerts": (r: FakeRequest) => ok({ items: r.query.get("status") === "resolved" ? [] : alerts }),
    "GET /alert-policies": ok({ items: [] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
  };
}

describe("alert text", () => {
  it("describes conditions, values and resolutions", () => {
    expect(formatMinutes(1)).toBe("1 minute");
    expect(formatMinutes(120)).toBe("2 hours");
    expect(formatMinutes(90)).toBe("90 minutes");
    expect(conditionText({ kind: "offline", threshold: null, minutes: 15 })).toBe("No check-in for 15 minutes");
    expect(conditionText({ kind: "cpu", threshold: 95, minutes: 60 })).toBe("Processor at 95% or more for 1 hour");
    expect(conditionText({ kind: "memory", threshold: 80, minutes: 5 })).toBe("Memory at 80% or more for 5 minutes");
    expect(conditionText({ kind: "disk", threshold: 90, minutes: 5 })).toBe("A disk 90% full or more for 5 minutes");
    expect(valueText({ kind: "offline", lastValue: 125 })).toBe("Offline 2 h 5 min");
    expect(valueText({ kind: "disk", lastValue: 94.4 })).toBe("94%");
    expect(resolutionText({ resolution: "manual", resolvedBy: "sam@example.com" })).toBe("Resolved by sam@example.com");
    expect(resolutionText({ resolution: "manual" })).toBe("Resolved by hand");
    expect(resolutionText({ resolution: "policy_off" })).toBe("Policy turned off");
    expect(resolutionText({})).toBe("Resolved");
  });
});

describe("alerts page", () => {
  it("lists active alerts, then acknowledges and resolves them", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes(),
      "POST /alerts/:id/acknowledge": (r) => ok({ ...DISK, id: r.params.id, status: "acknowledged" }),
      "POST /alerts/:id/resolve": (r) => ok({ ...CPU, id: r.params.id, status: "resolved" }),
    });
    renderApp("/alerts");
    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getAllByText("Critical").length).toBeGreaterThan(0);
    expect(within(rows[0]!).getByText("A disk 90% full or more for 5 minutes")).toBeInTheDocument();
    expect(within(rows[0]!).getByRole("link", { name: "DB-01" })).toHaveAttribute("href", "/devices/d1");
    expect(within(rows[0]!).getByText("94%")).toBeInTheDocument();
    expect(within(rows[1]!).getAllByText(/by sam@example.com/).length).toBeGreaterThan(0);
    // An acknowledged alert can only be resolved.
    expect(within(rows[1]!).queryByRole("button", { name: /Acknowledge/ })).not.toBeInTheDocument();
    expect(server.call("GET /alerts").query.get("status")).toBe("active");

    // The buttons are in the row twice: under the alert on phones, in their own column on wider screens.
    await user.click(within(rows[0]!).getAllByRole("button", { name: "Acknowledge Disk almost full on DB-01" })[0]!);
    await waitFor(() => expect(server.callsTo("POST /alerts/:id/acknowledge")).toHaveLength(1));
    expect(server.call("POST /alerts/:id/acknowledge").path).toBe("/alerts/a1/acknowledge");
    expect(await screen.findByText(/Acknowledged Disk almost full on DB-01/)).toBeInTheDocument();
    await user.click(within(rows[1]!).getAllByRole("button", { name: "Resolve High processor use on WEB-02" })[0]!);
    await waitFor(() => expect(server.callsTo("POST /alerts/:id/resolve")).toHaveLength(1));
    expect(await screen.findByText(/a new alert opens within a minute/)).toBeInTheDocument();
  });

  it("shows a failed action as an error", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...routes([DISK]),
      "POST /alerts/:id/resolve": { status: 409, body: { error: { code: "alert_resolved", message: "This alert is already resolved." } } },
    });
    renderApp("/alerts");
    await user.click((await screen.findAllByRole("button", { name: "Resolve Disk almost full on DB-01" }))[0]!);
    expect(await screen.findByText("This alert is already resolved.")).toBeInTheDocument();
  });

  it("keeps its filters in the URL", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...routes([DISK]), "GET /devices/:id": ok(device("d1", "DB-01")) });
    renderApp("/alerts?deviceId=d1");
    expect(await screen.findByRole("button", { name: "Show alerts on every device" })).toBeInTheDocument();
    expect((await screen.findAllByText("DB-01")).length).toBeGreaterThan(0);
    expect(server.call("GET /alerts").query.get("deviceId")).toBe("d1");

    await user.selectOptions(screen.getByLabelText("Severity"), "critical");
    await waitFor(() => expect(location()).toBe("/alerts?deviceId=d1&severity=critical"));
    await user.click(screen.getByRole("button", { name: "Show alerts on every device" }));
    await waitFor(() => expect(location()).toBe("/alerts?severity=critical"));
    // An organization narrows to its sites; choosing one clears a device or site chosen before.
    await user.selectOptions(screen.getByLabelText("Organization"), "o1");
    await waitFor(() => expect(server.callsTo("GET /alerts").at(-1)?.query.get("organizationId")).toBe("o1"));
    expect(location()).toBe("/alerts?severity=critical&organizationId=o1");
    await user.selectOptions(screen.getByLabelText("Site"), "s1");
    await waitFor(() => expect(server.callsTo("GET /alerts").at(-1)?.query.get("siteId")).toBe("s1"));

    server.on("GET /alerts", ok({ items: [] }));
    await user.selectOptions(screen.getByLabelText("Show"), "resolved");
    await waitFor(() => expect(server.callsTo("GET /alerts").at(-1)?.query.get("status")).toBe("resolved"));
    expect(await screen.findByText("No alerts match these filters")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(await screen.findByText("No resolved alerts")).toBeInTheDocument();
    expect(location()).toBe("/alerts?status=resolved");
  });

  it("lists resolved alerts with why they resolved, and pages", async () => {
    const user = userEvent.setup();
    const resolved = alertEntry("a3", "Device offline", { kind: "offline", threshold: null, status: "resolved", resolution: "cleared", resolvedAt: "2026-11-01T11:00:00Z", lastValue: 40 });
    const server = installFakeApi({ ...routes(), "GET /alerts": (r) => ok({ items: [resolved], next: r.query.get("before") ? undefined : "17" }) });
    renderApp("/alerts?status=resolved");
    expect((await screen.findAllByText(/Condition cleared/)).length).toBeGreaterThan(0);
    expect(screen.getByText("Offline 40 min")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Resolve/ })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Older alerts" }));
    await waitFor(() => expect(server.callsTo("GET /alerts").at(-1)?.query.get("before")).toBe("17"));
    await user.click(await screen.findByRole("button", { name: "Newest" }));
    await waitFor(() => expect(location()).toBe("/alerts?status=resolved"));
  });

  it("says when nothing needs attention", async () => {
    const user = userEvent.setup();
    installFakeApi(routes([]));
    renderApp("/alerts");
    expect(await screen.findByText("No active alerts")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Review policies" }));
    expect(await screen.findByRole("tab", { name: "Policies", selected: true })).toBeInTheDocument();
    expect(await screen.findByText("No alert policies")).toBeInTheDocument();
    expect(screen.getByText(/An administrator adds them/)).toBeInTheDocument();
  });

  it("hides policies and actions from people who may only look", async () => {
    installFakeApi({ ...routes([{ ...DISK, canManage: false }]), ...{ "GET /auth/session": ok(VIEWER) } });
    renderApp("/alerts?tab=policies");
    expect(await screen.findByRole("table")).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Policies" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Acknowledge|Resolve/ })).not.toBeInTheDocument();
  });
});

describe("alert policies", () => {
  const policies = [
    alertPolicy("p1", "Device offline", { kind: "offline", threshold: null, severity: "critical", activeAlerts: 2 }),
    alertPolicy("p2", "Acme memory", { level: "organization", organizationId: "o1", organizationName: "Northwind Traders", kind: "memory", threshold: 80, enabled: false, canEdit: false }),
  ];

  function adminRoutes() {
    return {
      ...routes(),
      "GET /auth/session": ok(ADMIN),
      "GET /alert-policies": ok({ items: policies }),
    };
  }

  it("lists policies with their condition, scope and state", async () => {
    installFakeApi(adminRoutes());
    renderApp("/alerts?tab=policies");
    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(within(rows[0]!).getAllByText("No check-in for 15 minutes").length).toBeGreaterThan(0);
    expect(within(rows[0]!).getAllByText("Every device").length).toBeGreaterThan(0);
    expect(within(rows[0]!).getByText("On")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("2")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("Off")).toBeInTheDocument();
    expect(within(rows[1]!).queryByRole("button", { name: /Edit/ })).not.toBeInTheDocument();
    expect(screen.getByText("2 policies, 1 turned on.")).toBeInTheDocument();
  });

  it("adds a policy for one site", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...adminRoutes(), "POST /alert-policies": (r) => ({ status: 201, body: alertPolicy("p9", (r.body as { name: string }).name) }) });
    renderApp("/alerts?tab=policies");
    await user.click(await screen.findByRole("button", { name: "New policy" }));
    const dialog = await screen.findByRole("dialog", { name: "New alert policy" });

    await user.click(within(dialog).getByRole("button", { name: "Add policy" }));
    expect(within(dialog).getByText("Enter a name.")).toBeInTheDocument();
    expect(server.callsTo("POST /alert-policies")).toHaveLength(0);

    await user.type(within(dialog).getByLabelText(/Name/), "Head office disks");
    await user.selectOptions(within(dialog).getByLabelText("Applies to"), "site");
    await user.selectOptions(within(dialog).getByLabelText(/Organization/), "o1");
    await user.selectOptions(await within(dialog).findByLabelText(/Site/), "s1");
    await user.selectOptions(within(dialog).getByLabelText("Watch for"), "disk");
    const threshold = within(dialog).getByLabelText("At or above");
    await user.clear(threshold);
    await user.type(threshold, "85");
    const minutes = within(dialog).getByLabelText("For");
    await user.clear(minutes);
    await user.type(minutes, "10");
    await user.click(within(dialog).getByRole("radio", { name: "Critical" }));
    expect(within(dialog).getByText("Raises a critical alert on a device in Head office when: a disk 85% full or more for 10 minutes.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Add policy" }));
    await waitFor(() => expect(server.callsTo("POST /alert-policies")).toHaveLength(1));
    expect(server.call("POST /alert-policies").body).toEqual({
      organizationId: "o1",
      siteId: "s1",
      name: "Head office disks",
      description: "",
      kind: "disk",
      threshold: 85,
      minutes: 10,
      severity: "critical",
      enabled: true,
    });
    expect(await screen.findByText(/Added Head office disks/)).toBeInTheDocument();
  });

  it("checks the minutes an offline policy needs", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(adminRoutes());
    renderApp("/alerts?tab=policies");
    await user.click(await screen.findByRole("button", { name: "New policy" }));
    const dialog = await screen.findByRole("dialog", { name: "New alert policy" });
    await user.type(within(dialog).getByLabelText(/Name/), "Down");
    await user.selectOptions(within(dialog).getByLabelText("Watch for"), "offline");
    expect(within(dialog).queryByLabelText("At or above")).not.toBeInTheDocument();
    const minutes = within(dialog).getByLabelText("Without a check-in for");
    await user.clear(minutes);
    await user.type(minutes, "2");
    await user.click(within(dialog).getByRole("button", { name: "Add policy" }));
    expect(within(dialog).getByText("Use 3 to 1,440 minutes.")).toBeInTheDocument();
    expect(server.callsTo("POST /alert-policies")).toHaveLength(0);
  });

  it("shows the server's complaint about a field", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...adminRoutes(),
      "POST /alert-policies": { status: 422, body: { error: { code: "validation_failed", message: "Some fields need attention.", fields: { name: "A policy with this name already exists here." } } } },
    });
    renderApp("/alerts?tab=policies");
    await user.click(await screen.findByRole("button", { name: "New policy" }));
    const dialog = await screen.findByRole("dialog", { name: "New alert policy" });
    await user.type(within(dialog).getByLabelText(/Name/), "Device offline");
    await user.click(within(dialog).getByRole("button", { name: "Add policy" }));
    expect(await within(dialog).findByText("A policy with this name already exists here.")).toBeInTheDocument();
  });

  it("edits, turns off and deletes a policy", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...adminRoutes(),
      "PATCH /alert-policies/:id": (r) => ok({ ...policies[0], ...(r.body as object) }),
      "DELETE /alert-policies/:id": noContent,
    });
    renderApp("/alerts?tab=policies");
    await user.click(await screen.findByRole("button", { name: "Edit Device offline" }));
    let dialog = await screen.findByRole("dialog", { name: "Edit Device offline" });
    expect(within(dialog).getByText("Every device")).toBeInTheDocument();
    expect(within(dialog).queryByLabelText("Applies to")).not.toBeInTheDocument();
    const minutes = within(dialog).getByLabelText("Without a check-in for");
    expect(minutes).toHaveValue(15);
    await user.clear(minutes);
    await user.type(minutes, "30");
    await user.click(within(dialog).getByRole("checkbox", { name: "Turned on" }));
    expect(within(dialog).getByText(/^Once turned on, raises a critical alert on any device/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(server.callsTo("PATCH /alert-policies/:id")).toHaveLength(1));
    expect(server.call("PATCH /alert-policies/:id").body).toMatchObject({ kind: "offline", threshold: null, minutes: 30, enabled: false });

    await user.click(await screen.findByRole("button", { name: "Edit Device offline" }));
    dialog = await screen.findByRole("dialog", { name: "Edit Device offline" });
    await user.click(within(dialog).getByRole("button", { name: "Delete policy" }));
    const confirm = await screen.findByRole("dialog", { name: "Delete Device offline?" });
    expect(within(confirm).getByText("Its 2 active alerts resolve now. Resolved alerts keep its name.")).toBeInTheDocument();
    await user.click(within(confirm).getByRole("button", { name: "Delete policy" }));
    await waitFor(() => expect(server.callsTo("DELETE /alert-policies/:id")).toHaveLength(1));
    expect(await screen.findByText("Deleted Device offline.")).toBeInTheDocument();
  });
});

describe("disk health alerts (ADR-0065)", () => {
  const LABEL = "PhysicalDrive1 · Samsung SSD 870 EVO 1TB";
  const FAILING = alertEntry("a5", "Disk failing", {
    kind: "disk_health",
    checkName: "failing",
    threshold: null,
    minutes: 30,
    value: 1,
    lastValue: 1,
    subject: "0123456789abcdef0123456789abcdef",
    subjectLabel: LABEL,
    detail: "SMART status: threshold exceeded",
  });
  const ERRORS = alertEntry("a6", "Disk errors", {
    kind: "disk_health",
    checkName: "errors",
    threshold: 1,
    minutes: 30,
    severity: "warning",
    value: 3,
    lastValue: 3,
    subject: "fedcba9876543210fedcba9876543210",
    subjectLabel: "sda · ST4000VN008",
    detail: "Reallocated sectors 3",
  });
  const GONE = alertEntry("a7", "Disk failing", {
    ...FAILING,
    id: "a7",
    status: "resolved",
    resolution: "subject_gone",
    resolvedAt: "2026-11-15T10:00:00Z",
  });

  it("describes each check, its value and why it resolved", () => {
    const c = (checkName: DiskCheck, threshold: number | null, minutes = 30) => conditionText({ kind: "disk_health", checkName, threshold, minutes });
    expect(c("failing", null)).toBe("A disk's own verdict is failing");
    expect(c("errors", 5)).toBe("A disk with 5 or more reallocated sectors and media errors");
    expect(c("pending", 1)).toBe("A disk with 1 or more pending and uncorrectable sectors");
    expect(c("wear", 90)).toBe("A disk with 90% or more of its rated endurance used");
    expect(c("temperature", null, 60)).toBe("A disk at or over its own temperature limit for 1 hour");
    expect(c("temperature", 55, 30)).toBe("A disk at 55 °C or more for 30 minutes");
    // A check or a kind a newer server knows keeps its name.
    expect(c("smart_trend" as DiskCheck, 1)).toBe("Disk health: smart_trend");
    expect(conditionText({ kind: "disk_health", threshold: null, minutes: 30 })).toBe("Disk health");
    expect(conditionText({ kind: "battery" as never, threshold: null, minutes: 30 })).toBe("battery");

    const v = (checkName: DiskCheck, lastValue: number) => valueText({ kind: "disk_health", checkName, lastValue });
    expect(v("failing", 1)).toBe("Failing");
    expect(v("failing", 0)).toBe("Not failing");
    expect(v("errors", 3)).toBe("3 errors");
    expect(v("errors", 1)).toBe("1 error");
    expect(v("pending", 8)).toBe("8 sectors");
    expect(v("wear", 91.2)).toBe("91% used");
    expect(v("temperature", 61)).toBe("61 °C");
    expect(v("smart_trend" as DiskCheck, 4)).toBe("4");

    expect(resolutionText({ resolution: "subject_gone" })).toBe("The disk is gone: missing from the device's disk readings for 14 days");
    expect(resolutionText({ resolution: "replaced" as never })).toBe("replaced");

    // Counts that only rise: acknowledge rather than resolve.
    expect(risingHint(ERRORS)).toMatch(/^This count only rises: acknowledge this alert rather than resolve it/);
    expect(risingHint({ ...ERRORS, checkName: "wear", status: "acknowledged" })).toMatch(/^Wear only rises/);
    expect(risingHint({ ...ERRORS, checkName: "pending" })).toBeNull();
    expect(risingHint({ ...ERRORS, status: "resolved" })).toBeNull();
    expect(risingHint(FAILING)).toBeNull();
    expect(risingHint(DISK)).toBeNull();
  });

  it("lists disk alerts with their disk, what holds, and why a gone disk's alert resolved", async () => {
    const server = installFakeApi({ ...routes([FAILING, ERRORS]), "GET /alerts": (r: FakeRequest) => ok({ items: r.query.get("status") === "all" ? [GONE] : [FAILING, ERRORS] }) });
    renderApp("/alerts");
    const table = await screen.findByRole("table");
    const [failing, errors] = within(table).getAllByRole("row").slice(1);
    expect(within(failing!).getByText(LABEL)).toBeInTheDocument();
    expect(within(failing!).getByText("SMART status: threshold exceeded")).toBeInTheDocument();
    expect(within(failing!).getByText("A disk's own verdict is failing")).toBeInTheDocument();
    expect(within(failing!).getByText("Failing")).toBeInTheDocument();
    expect(within(failing!).queryByText(/only rises/)).not.toBeInTheDocument();
    expect(within(errors!).getByText("sda · ST4000VN008")).toBeInTheDocument();
    expect(within(errors!).getByText("Reallocated sectors 3")).toBeInTheDocument();
    expect(within(errors!).getByText("3 errors")).toBeInTheDocument();
    expect(within(errors!).getByText(/^This count only rises: acknowledge this alert rather than resolve it/)).toBeInTheDocument();
    expect(within(errors!).getAllByRole("button", { name: "Resolve Disk errors on DB-01" })[0]).toHaveAttribute("title", expect.stringMatching(/only rises/));

    await userEvent.setup().selectOptions(screen.getByLabelText("Show"), "all");
    await waitFor(() => expect(server.callsTo("GET /alerts").at(-1)?.query.get("status")).toBe("all"));
    expect((await screen.findAllByText(/The disk is gone: missing from the device's disk readings for 14 days/)).length).toBeGreaterThan(0);
  });

  it("shows a disk alert's disk on the device's page and the dashboard", async () => {
    installFakeApi(routes([ERRORS]));
    const { unmount } = renderWithProviders(<DeviceAlertsCard deviceId="d1" />);
    expect(await screen.findByText("sda · ST4000VN008")).toBeInTheDocument();
    expect(screen.getByText("Reallocated sectors 3")).toBeInTheDocument();
    expect(screen.getByText("3 errors")).toBeInTheDocument();
    expect(screen.getByText(/^This count only rises/)).toBeInTheDocument();
    unmount();

    installFakeApi({
      ...routes([FAILING]),
      "GET /auth/session": ok(ADMIN),
      "GET /alerts/summary": ok({ active: 1, critical: 1, warning: 0, acknowledged: 0, devices: 1 }),
      "GET /users": ok({ items: [] }),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/");
    const card = (await screen.findByRole("heading", { name: "Needs attention" })).closest("section") as HTMLElement;
    expect(await within(card).findByText(new RegExp(`${LABEL} · `))).toBeInTheDocument();
  });

  describe("policies", () => {
    function adminRoutes(policies = [alertPolicy("p1", "High processor use")] as AlertPolicy[]) {
      return { ...routes(), "GET /auth/session": ok(ADMIN), "GET /alert-policies": ok({ items: policies }) };
    }
    /** Opens a new policy for disk health, on the policies page rendered once per test. */
    async function newPolicy(user: ReturnType<typeof userEvent.setup>) {
      if (!screen.queryByRole("tab", { name: "Policies" })) renderApp("/alerts?tab=policies");
      await screen.findByRole("button", { name: "Edit High processor use" });
      await user.click(screen.getByRole("button", { name: "New policy" }));
      const dialog = await screen.findByRole("dialog", { name: "New alert policy" });
      await user.type(within(dialog).getByLabelText(/Name/), "Disks");
      await user.selectOptions(within(dialog).getByLabelText("Watch for"), "disk_health");
      return dialog;
    }

    it("adds a failing check, which takes no threshold and no minutes", async () => {
      const user = userEvent.setup();
      const server = installFakeApi({ ...adminRoutes(), "POST /alert-policies": (r) => ({ status: 201, body: alertPolicy("p9", (r.body as { name: string }).name) }) });
      const dialog = await newPolicy(user);
      expect(within(dialog).getByLabelText("Check")).toHaveValue("failing");
      expect(within(within(dialog).getByLabelText("Check")).getAllByRole("option").map((o) => o.textContent)).toEqual([
        "Disk failing",
        "Reallocated sectors and media errors",
        "Pending and uncorrectable sectors",
        "Wear",
        "Temperature",
      ]);
      expect(within(dialog).queryByLabelText("At or above")).not.toBeInTheDocument();
      expect(within(dialog).queryByLabelText("For")).not.toBeInTheDocument();
      expect(within(dialog).getByText(/^The drive's own verdict: SMART status threshold exceeded/)).toBeInTheDocument();
      await user.click(within(dialog).getByRole("radio", { name: "Critical" }));
      expect(within(dialog).getByText("Raises a critical alert on any device when: a disk's own verdict is failing.")).toBeInTheDocument();
      await user.click(within(dialog).getByRole("button", { name: "Add policy" }));
      await waitFor(() => expect(server.callsTo("POST /alert-policies")).toHaveLength(1));
      expect(server.call("POST /alert-policies").body).toEqual({
        organizationId: null,
        siteId: null,
        name: "Disks",
        description: "",
        kind: "disk_health",
        checkName: "failing",
        threshold: null,
        minutes: 30,
        severity: "critical",
        enabled: true,
      });
    });

    it("adds the counting checks with the threshold each takes", async () => {
      const user = userEvent.setup();
      const server = installFakeApi({ ...adminRoutes(), "POST /alert-policies": (r) => ({ status: 201, body: alertPolicy("p9", (r.body as { name: string }).name) }) });
      const dialog = await newPolicy(user);
      await user.selectOptions(within(dialog).getByLabelText("Check"), "errors");
      const threshold = within(dialog).getByLabelText("At or above");
      expect(threshold).toHaveValue(1);
      expect(within(dialog).getByText("sectors and errors")).toBeInTheDocument();
      expect(within(dialog).queryByLabelText("For")).not.toBeInTheDocument();
      expect(within(dialog).getByText(/These counts only rise.*acknowledge it rather than resolve it/)).toBeInTheDocument();
      await user.clear(threshold);
      await user.type(threshold, "0");
      await user.click(within(dialog).getByRole("button", { name: "Add policy" }));
      expect(within(dialog).getByText("Use a count from 1 to 100.")).toBeInTheDocument();
      expect(server.callsTo("POST /alert-policies")).toHaveLength(0);
      await user.clear(threshold);
      await user.type(threshold, "5");
      expect(within(dialog).getByText("Raises a warning alert on any device when: a disk with 5 or more reallocated sectors and media errors.")).toBeInTheDocument();
      await user.click(within(dialog).getByRole("button", { name: "Add policy" }));
      await waitFor(() => expect(server.callsTo("POST /alert-policies")).toHaveLength(1));
      expect(server.call("POST /alert-policies").body).toMatchObject({ kind: "disk_health", checkName: "errors", threshold: 5, minutes: 30 });

      server.on("POST /alert-policies", (r) => ({ status: 201, body: alertPolicy("p10", (r.body as { name: string }).name) }));
      const again = await newPolicy(user);
      await user.selectOptions(within(again).getByLabelText("Check"), "pending");
      expect(within(again).getByLabelText("At or above")).toHaveValue(1);
      expect(within(again).getByText("sectors")).toBeInTheDocument();
      await user.selectOptions(within(again).getByLabelText("Check"), "wear");
      const wear = within(again).getByLabelText("At or above");
      expect(wear).toHaveValue(90);
      expect(within(again).getByText("% used")).toBeInTheDocument();
      await user.clear(wear);
      await user.type(wear, "101");
      await user.click(within(again).getByRole("button", { name: "Add policy" }));
      expect(within(again).getByText("Use a percentage from 1 to 100.")).toBeInTheDocument();
      await user.clear(wear);
      await user.type(wear, "80");
      await user.click(within(again).getByRole("button", { name: "Add policy" }));
      await waitFor(() => expect(server.callsTo("POST /alert-policies")).toHaveLength(2));
      expect(server.call("POST /alert-policies", 1).body).toMatchObject({ checkName: "wear", threshold: 80, minutes: 30 });
    });

    it("adds a temperature check by the drive's own limit or a temperature, over at least 30 minutes", async () => {
      const user = userEvent.setup();
      const server = installFakeApi({ ...adminRoutes(), "POST /alert-policies": (r) => ({ status: 201, body: alertPolicy("p9", (r.body as { name: string }).name) }) });
      const dialog = await newPolicy(user);
      await user.selectOptions(within(dialog).getByLabelText("Check"), "temperature");
      expect(within(dialog).getByLabelText("At or above")).toHaveValue("limit");
      expect(within(dialog).queryByLabelText("Temperature")).not.toBeInTheDocument();
      const minutes = within(dialog).getByLabelText("For");
      expect(minutes).toHaveValue(60);
      expect(within(dialog).getByText(/each drive's own temperature limit; a drive that reports no limit is not checked/)).toBeInTheDocument();
      expect(within(dialog).getByText("Raises a warning alert on any device when: a disk at or over its own temperature limit for 1 hour.")).toBeInTheDocument();
      await user.click(within(dialog).getByRole("button", { name: "Add policy" }));
      await waitFor(() => expect(server.callsTo("POST /alert-policies")).toHaveLength(1));
      expect(server.call("POST /alert-policies").body).toMatchObject({ kind: "disk_health", checkName: "temperature", threshold: null, minutes: 60 });

      server.on("POST /alert-policies", (r) => ({ status: 201, body: alertPolicy("p10", (r.body as { name: string }).name) }));
      const again = await newPolicy(user);
      await user.selectOptions(within(again).getByLabelText("Check"), "temperature");
      await user.selectOptions(within(again).getByLabelText("At or above"), "degrees");
      const degrees = within(again).getByLabelText("Temperature");
      expect(degrees).toHaveValue(60);
      await user.clear(degrees);
      await user.type(degrees, "55");
      const span = within(again).getByLabelText("For");
      await user.clear(span);
      await user.type(span, "30");
      await user.click(within(again).getByRole("button", { name: "Add policy" }));
      // 30 minutes, the reading interval, holds one reading, and the check needs two.
      expect(within(again).getByText("Use 60 to 1,440 minutes.")).toBeInTheDocument();
      await user.clear(span);
      await user.type(span, "59");
      await user.click(within(again).getByRole("button", { name: "Add policy" }));
      expect(within(again).getByText("Use 60 to 1,440 minutes.")).toBeInTheDocument();
      expect(span).toHaveAttribute("min", "60");
      await user.clear(span);
      await user.type(span, "75");
      expect(within(again).getByText("Raises a warning alert on any device when: a disk at 55 °C or more for 75 minutes.")).toBeInTheDocument();
      await user.clear(degrees);
      await user.click(within(again).getByRole("button", { name: "Add policy" }));
      expect(within(again).getByText("Use 1 to 100 °C, or the drive's own limit.")).toBeInTheDocument();
      await user.type(degrees, "55");
      await user.click(within(again).getByRole("button", { name: "Add policy" }));
      await waitFor(() => expect(server.callsTo("POST /alert-policies")).toHaveLength(2));
      expect(server.call("POST /alert-policies", 1).body).toMatchObject({ checkName: "temperature", threshold: 55, minutes: 75 });
    });

    it("switches a temperature check to the drive's own limit with driveLimit, which a null threshold cannot say", async () => {
      const user = userEvent.setup();
      const hot = alertPolicy("p3", "Disk too hot", { kind: "disk_health", checkName: "temperature", threshold: 55, minutes: 60 });
      const failing = alertPolicy("p4", "Disk failing", { kind: "disk_health", checkName: "failing", threshold: null, minutes: 30, severity: "critical" });
      const server = installFakeApi({
        ...adminRoutes([hot, failing]),
        "PATCH /alert-policies/:id": (r) => ok({ ...hot, ...(r.body as object) }),
      });
      renderApp("/alerts?tab=policies");
      const table = await screen.findByRole("table");
      expect(within(table).getAllByText("A disk at 55 °C or more for 1 hour").length).toBeGreaterThan(0);
      expect(within(table).getAllByText("A disk's own verdict is failing").length).toBeGreaterThan(0);

      await user.click(screen.getByRole("button", { name: "Edit Disk too hot" }));
      let dialog = await screen.findByRole("dialog", { name: "Edit Disk too hot" });
      expect(within(dialog).getByLabelText("Watch for")).toHaveValue("disk_health");
      expect(within(dialog).getByLabelText("Check")).toHaveValue("temperature");
      expect(within(dialog).getByLabelText("At or above")).toHaveValue("degrees");
      expect(within(dialog).getByLabelText("Temperature")).toHaveValue(55);
      await user.selectOptions(within(dialog).getByLabelText("At or above"), "limit");
      await user.click(within(dialog).getByRole("button", { name: "Save changes" }));
      await waitFor(() => expect(server.callsTo("PATCH /alert-policies/:id")).toHaveLength(1));
      expect(server.call("PATCH /alert-policies/:id").body).toEqual({
        name: "Disk too hot",
        description: "",
        kind: "disk_health",
        checkName: "temperature",
        threshold: null,
        driveLimit: true,
        minutes: 60,
        severity: "warning",
        enabled: true,
      });

      // A failing check sends no driveLimit, and moving a policy to another kind drops its check.
      await user.click(await screen.findByRole("button", { name: "Edit Disk failing" }));
      dialog = await screen.findByRole("dialog", { name: "Edit Disk failing" });
      expect(within(dialog).getByLabelText("Check")).toHaveValue("failing");
      expect(within(dialog).queryByLabelText("At or above")).not.toBeInTheDocument();
      await user.selectOptions(within(dialog).getByLabelText("Watch for"), "memory");
      expect(within(dialog).getByLabelText("At or above")).toHaveValue(95);
      await user.click(within(dialog).getByRole("button", { name: "Save changes" }));
      await waitFor(() => expect(server.callsTo("PATCH /alert-policies/:id")).toHaveLength(2));
      expect(server.call("PATCH /alert-policies/:id", 1).body).toEqual({
        name: "Disk failing",
        description: "",
        kind: "memory",
        threshold: 95,
        minutes: 30,
        severity: "critical",
        enabled: true,
      });
    });
  });
});

describe("alerts elsewhere", () => {
  it("lists a device's active alerts on its page", async () => {
    const server = installFakeApi({ ...routes([DISK]), "POST /alerts/:id/acknowledge": ok({ ...DISK, status: "acknowledged" }) });
    renderWithProviders(<DeviceAlertsCard deviceId="d1" />);
    expect(await screen.findByText("Disk almost full")).toBeInTheDocument();
    expect(screen.getByText("94%")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "History" })).toHaveAttribute("href", "/alerts?deviceId=d1&status=all");
    expect(server.call("GET /alerts").query.get("deviceId")).toBe("d1");
    await userEvent.setup().click(screen.getByRole("button", { name: "Acknowledge Disk almost full on DB-01" }));
    await waitFor(() => expect(server.callsTo("POST /alerts/:id/acknowledge")).toHaveLength(1));
  });

  it("says when a device has no active alerts", async () => {
    installFakeApi(routes([]));
    renderWithProviders(<DeviceAlertsCard deviceId="d1" />);
    expect(await screen.findByText("No active alerts")).toBeInTheDocument();
  });

  it("counts active alerts in the menu and leads the dashboard with them", async () => {
    installFakeApi({
      ...routes([CPU, DISK]),
      "GET /auth/session": ok(ADMIN),
      "GET /alerts/summary": ok({ active: 2, critical: 1, warning: 1, acknowledged: 1, devices: 2 }),
      "GET /sites": ok({ items: [] }),
      "GET /users": ok({ items: [] }),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/");
    const nav = (await screen.findAllByRole("navigation", { name: "Main" }))[0]!;
    expect(await within(nav).findByTitle("2 active, 1 critical")).toHaveTextContent("2");
    expect(await screen.findByText("1 critical on 2 devices")).toBeInTheDocument();
    const card = (await screen.findByRole("heading", { name: "Needs attention" })).closest("section, div")!;
    expect(card).toBeTruthy();
    const items = await screen.findAllByRole("listitem");
    const first = items.find((li) => li.textContent?.includes("on DB-01") || li.textContent?.includes("on WEB-02"));
    expect(first?.textContent).toContain("Disk almost full");
  });
});

describe("active alerts pulse in red", () => {
  const rowOf = (name: string) => screen.getByText(name).closest("li") as HTMLElement;
  afterEach(() => {
    vi.restoreAllMocks();
    applyAlertFlash(true);
  });

  it("pulses each of a device's active alerts and counts them", async () => {
    installFakeApi(routes([DISK, CPU]));
    renderWithProviders(<DeviceAlertsCard deviceId="d1" />);
    expect(await screen.findByText("Disk almost full")).toBeInTheDocument();
    // Open and acknowledged alerts are both active; the severity keeps its own badge beside the pulse.
    expect(rowOf("Disk almost full")).toHaveClass("alert-active-pulse", "alert-active-pulse--row");
    expect(within(rowOf("Disk almost full")).getByText("Critical")).toBeInTheDocument();
    expect(rowOf("High processor use")).toHaveClass("alert-active-pulse");
    expect(within(rowOf("High processor use")).getByText("Warning")).toBeInTheDocument();
    // The title counts the active ones, in words for screen readers, and pulses with them.
    const heading = screen.getByRole("heading", { name: "Alerts 2 active" });
    const count = within(heading).getByTitle("2 active alerts");
    expect(count).toHaveTextContent("2 active");
    expect(count).toHaveClass("alert-active-pulse");
    // Nothing on the card announces the pulse.
    expect(heading.closest("section")?.querySelector("[aria-live]")).toBeNull();
  });

  it("counts past the first page of a device's alerts", async () => {
    installFakeApi({ ...routes(), "GET /alerts": ok({ items: [DISK], next: "17" }) });
    renderWithProviders(<DeviceAlertsCard deviceId="d1" />);
    expect(await screen.findByRole("heading", { name: "Alerts 1+ active" })).toBeInTheDocument();
    expect(screen.getByTitle("More than 1 active alert")).toBeInTheDocument();
  });

  it("shows no count, and no switch, while a device has no active alerts", async () => {
    installFakeApi(routes([]));
    renderWithProviders(<DeviceAlertsCard deviceId="d1" />);
    expect(await screen.findByText("No active alerts")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Alerts" })).toBeInTheDocument();
    expect(document.querySelector(".alert-active-pulse")).toBeNull();
    expect(screen.queryByRole("button", { name: "Stop flashing" })).not.toBeInTheDocument();
  });

  it("stops flashing from a device's Alerts card, in this browser, and starts again", async () => {
    const user = userEvent.setup();
    installFakeApi(routes([DISK]));
    renderWithProviders(<DeviceAlertsCard deviceId="d1" />);
    await user.click(await screen.findByRole("button", { name: "Stop flashing" }));
    // The rows keep their class: the stylesheet holds them in steady red.
    expect(document.documentElement).toHaveAttribute("data-alert-flash", "off");
    expect(window.localStorage.getItem("easyrmm.alertFlash")).toBe("off");
    expect(rowOf("Disk almost full")).toHaveClass("alert-active-pulse");
    await user.click(screen.getByRole("button", { name: "Flash active alerts" }));
    expect(document.documentElement).not.toHaveAttribute("data-alert-flash");
    expect(window.localStorage.getItem("easyrmm.alertFlash")).toBeNull();
    expect(screen.getByRole("button", { name: "Stop flashing" })).toBeInTheDocument();
  });

  it("stops flashing from the Alerts page, and keeps the choice for the next visit", async () => {
    const user = userEvent.setup();
    installFakeApi(routes());
    renderApp("/alerts");
    await user.click(await screen.findByRole("button", { name: "Stop flashing" }));
    expect(document.documentElement).toHaveAttribute("data-alert-flash", "off");
    expect(getStoredAlertFlash()).toBe(false);
    // Another tab's choice applies here too.
    window.localStorage.removeItem("easyrmm.alertFlash");
    window.dispatchEvent(new StorageEvent("storage", { key: "easyrmm.alertFlash" }));
    expect(await screen.findByRole("button", { name: "Stop flashing" })).toBeInTheDocument();
    expect(document.documentElement).not.toHaveAttribute("data-alert-flash");
  });

  it("stops flashing for the page when the browser keeps nothing", async () => {
    const user = userEvent.setup();
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    installFakeApi(routes([DISK]));
    renderWithProviders(<DeviceAlertsCard deviceId="d1" />);
    await user.click(await screen.findByRole("button", { name: "Stop flashing" }));
    expect(document.documentElement).toHaveAttribute("data-alert-flash", "off");
    expect(getStoredAlertFlash()).toBe(true);
  });

  it("pulses a device's name on the alerts page only while it has an active critical alert", async () => {
    const OTHER = alertEntry("a8", "Disk almost full", { deviceId: "d3", deviceName: "FILE-03" });
    const server = installFakeApi({
      ...routes([DISK, CPU, OTHER]),
      // DB-01 has an active critical alert, WEB-02 only a warning, and FILE-03's critical alert resolved since the
      // list loaded.
      "GET /alerts/devices": ok({
        items: [
          { deviceId: "d1", organizationId: "o1", siteId: "s1", active: 1, critical: 1 },
          { deviceId: "d2", organizationId: "o1", siteId: "s1", active: 1, critical: 0 },
        ],
      }),
    });
    renderApp("/alerts?severity=warning");
    const db = await screen.findByRole("link", { name: "DB-01, active critical alert" });
    expect(db).toHaveClass("alert-active-pulse");
    expect(db).toHaveAttribute("title", "DB-01 has an active critical alert");
    expect(db.querySelector("svg")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "WEB-02" })).not.toHaveClass("alert-active-pulse");
    expect(screen.getByRole("link", { name: "FILE-03" })).not.toHaveClass("alert-active-pulse");
    // One request answers for every row, whatever the page's filters.
    expect(server.callsTo("GET /alerts/devices")).toHaveLength(1);
  });

  it("pulses gently, and holds still under reduced motion", () => {
    const css = readFileSync(resolve(process.cwd(), "src/index.css"), "utf8");
    const rule = /\n\.alert-active-pulse \{([^}]*)\}/.exec(css)?.[1] ?? "";
    const seconds = Number(/animation: alert-active-pulse ([\d.]+)s ease-in-out infinite/.exec(rule)?.[1]);
    // One slow cycle of 1.5 to 2 seconds: far under three flashes a second (WCAG 2.3.1).
    expect(seconds).toBeGreaterThanOrEqual(1.5);
    expect(seconds).toBeLessThanOrEqual(2);
    // Only the colour and a soft fill change: nothing moves, blinks out or grows.
    const keyframes = /@keyframes alert-active-pulse \{([\s\S]*?)\n\}/.exec(css)?.[1] ?? "";
    expect([...keyframes.matchAll(/([a-z-]+):/g)].map((m) => m[1])).toEqual(["color", "background-color", "color", "background-color"]);
    const reduced = /@media \(prefers-reduced-motion: reduce\) \{([\s\S]*?)\n\}/.exec(css)?.[1] ?? "";
    expect(reduced).toMatch(/\.alert-active-pulse \{\s*animation: none;\s*color: var\(--alert-pulse-red\);/);
    // Stopped from the console, the same steady red (WCAG 2.2.2).
    expect(css).toMatch(/\n:root\[data-alert-flash='off'\] \.alert-active-pulse \{\s*animation: none;\s*color: var\(--alert-pulse-red\);\s*background-color: var\(--alert-pulse-fill\);/);
  });
});
