import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AlertEntry } from "../../api/types";
import { baseRoutes, installFakeApi, noContent, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { alertEntry, alertPolicy, device, org, site } from "../../test/fixtures";
import { renderApp, renderWithProviders } from "../../test/render";
import { conditionText, formatMinutes, resolutionText, valueText } from "./alertText";
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
