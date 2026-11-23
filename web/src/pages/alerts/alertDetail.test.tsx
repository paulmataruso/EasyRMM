import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AlertEntry, AlertMetrics, AlertPolicy, DiskCheck } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, type FakeHandler, type FakeReply } from "../../test/fakeApi";
import { alertEntry, alertPolicy, device, diskHealth } from "../../test/fixtures";
import { renderApp, renderWithProviders } from "../../test/render";
import { alertGuide } from "./alertGuide";
import { DeviceAlertsCard } from "./DeviceAlertsCard";

const location = () => screen.getByTestId("location").textContent;

const TECHNICIAN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "alert.view", "alert.manage", "monitoring.view"],
});
const VIEWER = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "alert.view"] });

const T = "2026-11-01T10:00:00Z";
const DISK = alertEntry("a1", "Disk almost full");
const CPU = alertEntry("a2", "High processor use", {
  policyId: "p2",
  kind: "cpu",
  threshold: 95,
  minutes: 15,
  severity: "warning",
  value: 96,
  lastValue: 97,
  status: "resolved",
  acknowledgedAt: "2026-11-01T10:05:00Z",
  acknowledgedBy: "sam@example.com",
  resolvedAt: "2026-11-01T12:30:00Z",
  resolution: "cleared",
});
const OFFLINE = alertEntry("a3", "Device offline", { policyId: "p3", kind: "offline", threshold: null, minutes: 15, value: 16, lastValue: 125 });
const DISK_SUBJECT = "00112233445566778899aabbccddeeff";
const FAILING = alertEntry("a4", "Disk failing", {
  policyId: "p4",
  kind: "disk_health",
  checkName: "failing",
  threshold: null,
  minutes: 30,
  subject: DISK_SUBJECT,
  subjectLabel: "nvme0n1 · Samsung PM9A3",
  detail: "NVMe critical warning: media read-only",
  value: 1,
  lastValue: 1,
});

const DISK_POLICY = alertPolicy("p1", "Disk almost full", { kind: "disk", threshold: 90, minutes: 5, severity: "critical", description: "Free space before the database stops." });

function metrics(extra: Partial<AlertMetrics> = {}): AlertMetrics {
  const start = Date.parse(T) - 40 * 60_000;
  return {
    metric: "cpu",
    threshold: 95,
    from: new Date(start).toISOString(),
    to: "2026-11-01T13:00:00Z",
    bucketSeconds: 60,
    trimmed: false,
    samples: Array.from({ length: 30 }, (_, i) => ({ at: new Date(start + i * 60_000).toISOString(), value: 90 + (i % 8) })),
    ...extra,
  };
}

type Routes = Record<string, FakeHandler | FakeReply>;

/** The fake server: alerts by id, and the policy's alerts on the device for each card's history. */
function routes(alerts: AlertEntry[], extra: Routes = {}, session = TECHNICIAN): Routes {
  const byId = new Map(alerts.map((a) => [a.id, a]));
  return {
    // Before the shared routes, so that /alerts/summary and /alerts/devices stay theirs.
    "GET /alerts/:id": (r) => (byId.has(r.params.id!) ? ok(byId.get(r.params.id!)) : fail(404, "not_found", "Not found.")),
    "GET /devices/:id": ok(device("d1", "DB-01", { online: false, lastSeenAt: "2026-11-01T09:44:00Z" })),
    ...baseRoutes(session),
    "GET /alerts": (r) => {
      const policy = r.query.get("policyId");
      return ok({ items: policy ? alerts.filter((a) => a.policyId === policy) : alerts, next: null });
    },
    "GET /alert-policies": ok({ items: [] }),
    "GET /alert-policies/:id": (r) => (r.params.id === "p1" ? ok(DISK_POLICY) : fail(404, "not_found", "Not found.")),
    "GET /alerts/:id/metrics": ok(metrics()),
    ...extra,
  };
}

async function openCard(path: string, name: string) {
  renderApp(path);
  return screen.findByRole("dialog", { name });
}

const section = (dialog: HTMLElement, name: string) => within(dialog).getByRole("heading", { name }).closest("section") as HTMLElement;

describe("an alert's card", () => {
  it("opens from the Alerts page with its own URL, and closing it goes back", async () => {
    const user = userEvent.setup();
    installFakeApi(routes([DISK, CPU]));
    renderApp("/alerts");
    await user.click(await screen.findByRole("link", { name: "Disk almost full on DB-01, details" }));
    const dialog = await screen.findByRole("dialog", { name: "Disk almost full" });
    expect(location()).toBe("/alerts?alert=a1");
    expect(within(dialog).getByText("Disk use on DB-01")).toBeInTheDocument();
    expect(within(dialog).getAllByRole("heading", { level: 3 }).map((h) => h.textContent)).toEqual([
      "Summary",
      "Why it opened",
      "Measurements",
      "Times",
      "What it means",
      "What to do next",
      "History",
    ]);
    // Its actions are in the card too.
    expect(within(dialog).getByRole("button", { name: "Acknowledge Disk almost full on DB-01" })).toBeInTheDocument();

    await user.click(within(dialog).getAllByRole("button", { name: "Close" }).at(-1)!);
    await waitFor(() => expect(location()).toBe("/alerts"));
    expect(screen.queryByRole("dialog", { name: "Disk almost full" })).not.toBeInTheDocument();
    // Focus goes back to the link that opened it.
    expect(screen.getByRole("link", { name: "Disk almost full on DB-01, details" })).toHaveFocus();
  });

  it("opened from a link, closes in place", async () => {
    const user = userEvent.setup();
    installFakeApi(routes([DISK]));
    const dialog = await openCard("/alerts?status=all&alert=a1", "Disk almost full");
    await user.click(within(dialog).getAllByRole("button", { name: "Close" })[0]!);
    await waitFor(() => expect(location()).toBe("/alerts?status=all"));
  });

  it("opened from a link, closes from an alert in its history too", async () => {
    const user = userEvent.setup();
    const before = alertEntry("a0", "Disk almost full", { status: "resolved", openedAt: "2026-10-30T08:00:00Z", resolvedAt: "2026-10-30T08:45:00Z", resolution: "cleared" });
    installFakeApi(routes([DISK, before]));
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    await user.click(await within(section(dialog, "History")).findByRole("link", { name: /^Opened / }));
    await waitFor(() => expect(location()).toBe("/alerts?alert=a0"));
    expect(await within(section(dialog, "Times")).findByText("Open for")).toBeInTheDocument();
    await user.click(within(dialog).getAllByRole("button", { name: "Close" }).at(-1)!);
    await waitFor(() => expect(location()).toBe("/alerts"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("closes on Escape", async () => {
    installFakeApi(routes([DISK]));
    const dialog = await openCard("/alerts?status=all&alert=a1", "Disk almost full");
    // The browser turns Escape on a modal dialog into its cancel event; jsdom has no modal dialogs, so the test sends it.
    fireEvent(dialog, new Event("cancel", { cancelable: true }));
    await waitFor(() => expect(location()).toBe("/alerts?status=all"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("says so when the alert is not found", async () => {
    installFakeApi(routes([]));
    const dialog = await openCard("/alerts?alert=nope", "Alert");
    expect(await within(dialog).findByText("Not found")).toBeInTheDocument();
  });

  it("is not there for someone who cannot see alerts", async () => {
    const server = installFakeApi(routes([DISK], {}, sessionView({ isSuperAdmin: false, permissions: ["org.view"] })));
    renderApp("/?alert=a1");
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(server.callsTo("GET /alerts/:id")).toHaveLength(0);
  });

  it("is linked from the device page's alerts", async () => {
    installFakeApi(routes([DISK]));
    renderWithProviders(<DeviceAlertsCard deviceId="d1" />, "/devices/d1");
    const link = await screen.findByRole("link", { name: "Disk almost full, details" });
    expect(link).toHaveAttribute("href", "/devices/d1?alert=a1");
    // On a pulsing row, hover underlines and keeps the pulse's colours, which hold 4.5:1 in every state; the accent
    // on the row's red tint would not.
    expect(link).toHaveClass("hover:underline");
    expect(link.className).not.toMatch(/hover:text-/);
  });

  it("is linked from the dashboard", async () => {
    installFakeApi(routes([DISK], { "GET /alerts/summary": ok({ active: 1, critical: 1, warning: 0, acknowledged: 0, devices: 1 }) }));
    renderApp("/");
    expect(await screen.findByRole("link", { name: "Disk almost full on DB-01, details" })).toHaveAttribute("href", "/?alert=a1");
  });
});

describe("remote access alerts (ADR-0069)", () => {
  const DOWN = alertEntry("a5", "Remote access down", {
    policyId: "p5",
    kind: "remote_down",
    threshold: null,
    minutes: 15,
    value: 15,
    lastValue: 42,
    detail: "MeshAgent is installed but not running. Not connected for 42 minutes.",
    repairs: [
      {
        target: "meshagent",
        trigger: "automatic",
        state: "failed",
        startedAt: "2026-11-01T10:20:00Z",
        endedAt: "2026-11-01T10:40:00Z",
        error: "MeshAgent did not connect to MeshCentral after the last step.",
        steps: [
          { step: "restart", state: "done" },
          { step: "repair", state: "failed", error: "download failed" },
        ],
      },
    ],
  });
  const SILENT = alertEntry("a6", "EasyRMM agent silent", { policyId: "p6", kind: "agent_silent", threshold: null, minutes: 15, value: 16, lastValue: 90, repairs: [] });

  it("shows the watchdog's reason, the condition and the repairs tried since it opened", async () => {
    installFakeApi(routes([DOWN]));
    const dialog = await openCard("/alerts?alert=a5", "Remote access down");
    expect(within(dialog).getByText("MeshAgent is installed but not running. Not connected for 42 minutes.")).toBeInTheDocument();
    expect(within(dialog).getByText("MeshAgent not connected to MeshCentral for 15 minutes, while the EasyRMM agent checks in")).toBeInTheDocument();
    expect(within(dialog).getByText("Not connected 42 min")).toBeInTheDocument();
    const repairs = section(dialog, "Repairs tried");
    expect(within(repairs).getByText(/Automatic · meshagent · it did not come back/)).toBeInTheDocument();
    expect(within(repairs).getByText("download failed", { selector: "span.block" })).toBeInTheDocument();
    expect(within(repairs).getByText("MeshAgent did not connect to MeshCentral after the last step.")).toBeInTheDocument();
    expect(within(dialog).getByText(/its Reconnect remote access button/)).toBeInTheDocument();
  });

  it("says when no repair was tried, and explains a silent agent", async () => {
    installFakeApi(routes([SILENT]));
    const dialog = await openCard("/alerts?alert=a6", "EasyRMM agent silent");
    expect(within(section(dialog, "Repairs tried")).getByText("None since the alert opened.")).toBeInTheDocument();
    expect(within(dialog).getByText("No EasyRMM check-in for 15 minutes, while MeshAgent is connected")).toBeInTheDocument();
    expect(within(dialog).getByText(/MeshCentral sees MeshAgent connected on this device/)).toBeInTheDocument();
    expect(within(dialog).getByText("Silent 1 h 30 min")).toBeInTheDocument();
  });
});

describe("the Repair failed alert (ADR-0069)", () => {
  const FAILED = alertEntry("a7", "Repair failed", {
    policyId: null,
    kind: "repair_failed",
    threshold: null,
    minutes: 0,
    severity: "warning",
    subject: "easypatch-agent",
    subjectLabel: "EasyPatch agent",
    detail: "Repairing the EasyPatch agent did not bring it back. The last step failed: apt-get could not reinstall the EasyPatch agent (exit code 100)",
    repairs: [
      { target: "easypatch-agent", trigger: "automatic", state: "failed", startedAt: "2026-11-01T10:20:00Z", endedAt: "2026-11-01T11:40:00Z", error: "x", steps: [{ step: "restart", state: "done" }, { step: "repair", state: "failed", error: "apt-get could not reinstall" }] },
      { target: "meshagent", trigger: "manual", state: "succeeded", startedAt: "2026-11-01T10:30:00Z", endedAt: "2026-11-01T10:35:00Z", error: "", steps: [{ step: "restart", state: "done" }] },
    ],
  });

  it("shows the last step's diagnostics and only the repairs of its agent", async () => {
    installFakeApi(routes([FAILED]));
    const dialog = await openCard("/alerts?alert=a7", "Repair failed");
    expect(within(dialog).getAllByText(/The last step failed: apt-get could not reinstall the EasyPatch agent \(exit code 100\)/).length).toBeGreaterThan(0);
    const repairs = section(dialog, "Repairs tried");
    expect(within(repairs).getByText(/Automatic · easypatch-agent · it did not come back/)).toBeInTheDocument();
    expect(within(repairs).queryByText(/meshagent/)).not.toBeInTheDocument();
    expect(within(repairs).getByText(/Reinstall the EasyPatch agent's package of the same version/)).toBeInTheDocument();
    expect(within(dialog).getByText(/EasyRMM tried to repair this device's EasyPatch agent by itself/)).toBeInTheDocument();
    expect(within(dialog).getByText("An automatic repair ended with the agent still broken")).toBeInTheDocument();
  });
});

describe("an alert's card, section by section", () => {
  it("summarizes the alert with its device, site and organization linked", async () => {
    installFakeApi(routes([DISK]));
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    const summary = section(dialog, "Summary");
    expect(within(summary).getByText("Critical")).toBeInTheDocument();
    expect(within(summary).getByText("Open")).toBeInTheDocument();
    expect(within(summary).getByRole("link", { name: "DB-01" })).toHaveAttribute("href", "/devices/d1");
    expect(within(summary).getByRole("link", { name: "Head office" })).toHaveAttribute("href", "/sites/s1");
    expect(within(summary).getByRole("link", { name: "Northwind Traders" })).toHaveAttribute("href", "/organizations/o1");
    expect(await within(summary).findByText("· offline now")).toBeInTheDocument();
    // Only disk health alerts name a disk.
    expect(within(summary).queryByText("Disk")).not.toBeInTheDocument();
  });

  it("says why it opened: the policy, its description, the value then and now", async () => {
    installFakeApi(routes([DISK]));
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    const why = section(dialog, "Why it opened");
    expect(within(why).getByText("A disk 90% full or more for 5 minutes")).toBeInTheDocument();
    // The console has no page for one policy, so its name is plain text.
    expect(await within(why).findByText("Disk almost full", { selector: "span.font-medium" })).toBeInTheDocument();
    expect(within(why).queryByRole("link")).not.toBeInTheDocument();
    expect(within(why).getByText("· Every device")).toBeInTheDocument();
    expect(within(why).getByText("Free space before the database stops.")).toBeInTheDocument();
    expect(within(why).getByText("93%")).toBeInTheDocument();
    expect(within(why).getByText("Latest value").nextElementSibling).toHaveTextContent("94%");
    expect(within(why).queryByText("Policy now")).not.toBeInTheDocument();
  });

  it("says when the policy has changed since, and keeps a very long description whole", async () => {
    const long = `${"Call the on-call engineer before touching the volume. ".repeat(37)}End.`.slice(0, 2000);
    installFakeApi(
      routes([DISK], {
        "GET /alert-policies/:id": ok({ ...DISK_POLICY, threshold: 80, description: long, enabled: false, level: "site", organizationName: "Northwind Traders", siteName: "Head office" } satisfies AlertPolicy),
      }),
    );
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    const why = section(dialog, "Why it opened");
    expect(await within(why).findByText("A disk 80% full or more for 5 minutes")).toBeInTheDocument();
    expect(within(why).getByText("· Northwind Traders / Head office · turned off")).toBeInTheDocument();
    const description = within(why).getByText(long.trim(), { normalizer: (s) => s.trim() });
    expect(description.textContent).toHaveLength(2000);
    // Wrapped, never cut.
    expect(description).toHaveClass("whitespace-pre-wrap");
    expect(description.closest("dd")).toHaveClass("break-words");
  });

  it("shows a deleted policy without asking for it, and no history", async () => {
    const server = installFakeApi(routes([{ ...DISK, policyId: null }]));
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    expect(within(section(dialog, "Why it opened")).getByText("Deleted")).toBeInTheDocument();
    expect(within(section(dialog, "History")).getByText(/Its policy was deleted/)).toBeInTheDocument();
    expect(server.callsTo("GET /alert-policies/:id")).toHaveLength(0);
  });

  it("does not ask for a policy the role cannot see", async () => {
    const server = installFakeApi(routes([DISK], {}, VIEWER));
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    expect(within(section(dialog, "Why it opened")).getByText("Your role cannot see alert policies")).toBeInTheDocument();
    expect(server.callsTo("GET /alert-policies/:id")).toHaveLength(0);
  });

  it("says when a policy is no longer available", async () => {
    installFakeApi(routes([{ ...DISK, policyId: "p9" }]));
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    expect(await within(section(dialog, "Why it opened")).findByText("No longer available")).toBeInTheDocument();
  });

  it("charts a metric alert's measurement with its threshold and when it was open", async () => {
    const server = installFakeApi(routes([CPU]));
    const dialog = await openCard("/alerts?alert=a2", "High processor use");
    const chart = await within(dialog).findByRole("group", { name: /^Processor use around this alert, threshold 95%\./ });
    const legend = within(section(dialog, "Measurements")).getByRole("list", { name: "Legend" });
    // The legend names the line, its latest point, the threshold and the shaded period.
    expect(within(legend).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Processor use95%", "Threshold 95%", "While the alert was open"]);
    expect(chart.querySelector("line[data-reference]")).not.toBeNull();
    const band = chart.querySelector("rect[data-band]");
    expect(Number(band?.getAttribute("width"))).toBeGreaterThan(0);
    expect(server.call("GET /alerts/:id/metrics").path).toBe("/alerts/a2/metrics");
    expect(within(dialog).getByText(/From 15 minutes before the alert opened until it resolved/)).toBeInTheDocument();
  });

  it("says when there are no measurements", async () => {
    installFakeApi(routes([CPU], { "GET /alerts/:id/metrics": ok(metrics({ samples: [], bucketSeconds: 300 })) }));
    const dialog = await openCard("/alerts?alert=a2", "High processor use");
    expect(await within(dialog).findByText("No measurements in this period.")).toBeInTheDocument();
    const measurements = section(dialog, "Measurements");
    expect(within(measurements).getByText(/Each point is the average over 5 min\.$/)).toBeInTheDocument();
    expect(within(measurements).queryByText(/no longer kept/)).not.toBeInTheDocument();
  });

  it("says on the chart when earlier measurements are no longer kept", async () => {
    const from = "2026-11-15T12:00:00Z";
    installFakeApi(routes([CPU], { "GET /alerts/:id/metrics": ok(metrics({ trimmed: true, from, to: "2026-11-22T12:00:00Z", bucketSeconds: 3600 })) }));
    const dialog = await openCard("/alerts?alert=a2", "High processor use");
    const measurements = section(dialog, "Measurements");
    const note = await within(measurements).findByText(/^Earlier measurements are no longer kept, so the chart starts at/);
    expect(within(note).getByText((_, el) => el?.tagName === "TIME")).toHaveAttribute("dateTime", from);
    expect(within(measurements).getByText(/with some time either side, as far as measurements are kept\./)).toBeInTheDocument();
  });

  it("shows an error, not a reason, when the measurements cannot be read", async () => {
    installFakeApi(routes([CPU], { "GET /alerts/:id/metrics": fail(404, "not_found", "Not found.") }));
    const dialog = await openCard("/alerts?alert=a2", "High processor use");
    expect(await within(section(dialog, "Measurements")).findByText("Not found")).toBeInTheDocument();
  });

  it("asks for no measurements for offline and disk health alerts", async () => {
    const server = installFakeApi(
      routes([OFFLINE, FAILING], { "GET /devices/:id/disks/:key": ok({ ...diskHealth(DISK_SUBJECT, "nvme0n1"), history: [], alerts: [] }) }),
    );
    const dialog = await openCard("/alerts?alert=a3", "Device offline");
    expect(within(dialog).queryByRole("heading", { name: "Measurements" })).not.toBeInTheDocument();
    expect(server.callsTo("GET /alerts/:id/metrics")).toHaveLength(0);
    // An offline alert says when the device was last seen.
    const why = section(dialog, "Why it opened");
    expect(await within(why).findByText("Last seen")).toBeInTheDocument();
    expect(within(why).getByText("Offline 16 min")).toBeInTheDocument();
    expect(within(why).getByText("Offline 2 h 5 min")).toBeInTheDocument();
    expect(within(section(dialog, "What to do next")).getByText("sudo easyrmm-agent status")).toBeInTheDocument();
  });

  it("shows a disk health alert's disk and its facts", async () => {
    const server = installFakeApi(
      routes([FAILING], {
        "GET /devices/:id/disks/:key": ok({
          ...diskHealth(DISK_SUBJECT, "nvme0n1", {
            state: "failing",
            reason: "critical_warning",
            detail: "NVMe critical warning: media read-only",
            facts: [
              { name: "criticalWarning", state: "failing", reason: "critical_warning", value: 8 },
              { name: "temperature", state: "healthy", value: 41 },
            ],
          }),
          history: [],
          alerts: [],
        }),
      }),
    );
    const dialog = await openCard("/alerts?alert=a4", "Disk failing");
    const summary = section(dialog, "Summary");
    expect(within(summary).getByText("Disk health · Disk failing")).toBeInTheDocument();
    expect(within(summary).getByText("nvme0n1 · Samsung PM9A3")).toBeInTheDocument();
    expect(within(summary).getByText("NVMe critical warning: media read-only")).toBeInTheDocument();
    const disk = section(dialog, "The disk");
    expect(await within(disk).findByText("Samsung PM9A3")).toBeInTheDocument();
    expect(within(disk).getByRole("link", { name: "The device's disks" })).toHaveAttribute("href", "/devices/d1?tab=hardware");
    const facts = within(dialog).getByRole("table", { name: "Facts" });
    expect(within(facts).getAllByRole("row")).toHaveLength(3);
    expect(server.call("GET /devices/:id/disks/:key").params.key).toBe(DISK_SUBJECT);
    // Its history is this disk's alerts from this policy.
    const q = server.callsTo("GET /alerts").find((c) => c.query.get("policyId"))!.query;
    expect([q.get("deviceId"), q.get("policyId"), q.get("subject"), q.get("status")]).toEqual(["d1", "p4", DISK_SUBJECT, "all"]);
    expect(within(section(dialog, "History")).getByText(/The only alert this policy has raised on this disk/)).toBeInTheDocument();
  });

  it("says when the disk is no longer read", async () => {
    installFakeApi(routes([FAILING], { "GET /devices/:id/disks/:key": fail(404, "not_found", "Not found.") }));
    const dialog = await openCard("/alerts?alert=a4", "Disk failing");
    expect(await within(section(dialog, "The disk")).findByText(/no longer list this disk/)).toBeInTheDocument();
    expect(within(dialog).queryByRole("table", { name: "Facts" })).not.toBeInTheDocument();
  });

  it("gives the times: opened, how long, acknowledged and resolved", async () => {
    installFakeApi(routes([CPU, DISK]));
    const dialog = await openCard("/alerts?alert=a2", "High processor use");
    const times = section(dialog, "Times");
    expect(within(times).getByText("Open for").nextElementSibling).toHaveTextContent("2 h 30 min");
    expect(within(times).getByText("Acknowledged").nextElementSibling).toHaveTextContent(/by sam@example\.com$/);
    expect(within(times).getByText("Resolved").nextElementSibling).toHaveTextContent(/Condition cleared$/);
  });

  it("gives the times of an alert still open", async () => {
    installFakeApi(routes([DISK]));
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    const times = section(dialog, "Times");
    expect(within(times).getByText("Open so far")).toBeInTheDocument();
    expect(within(times).getByText("Not acknowledged")).toBeInTheDocument();
    expect(within(times).getByText("Not yet")).toBeInTheDocument();
  });

  it("lists the policy's other alerts on the device, each opening its own card", async () => {
    const user = userEvent.setup();
    const before = alertEntry("a0", "Disk almost full", { status: "resolved", openedAt: "2026-10-30T08:00:00Z", resolvedAt: "2026-10-30T08:45:00Z", resolution: "manual", resolvedBy: "sam@example.com", lastValue: 91 });
    const older = alertEntry("a00", "Disk almost full", { status: "resolved", openedAt: "2026-10-29T08:00:00Z", resolvedAt: "2026-10-29T09:00:00Z", resolution: "cleared" });
    const server = installFakeApi(routes([DISK, before, older]));
    renderApp("/alerts");
    await user.click((await screen.findAllByRole("link", { name: "Disk almost full on DB-01, details" }))[0]!);
    let dialog = await screen.findByRole("dialog", { name: "Disk almost full" });
    const history = section(dialog, "History");
    expect(await within(history).findByText(/^3 times this policy opened an alert on this device, since/)).toBeInTheDocument();
    const items = within(history).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("(this alert)");
    expect(items[1]).toHaveTextContent("91% · open for 45 min · Resolved by sam@example.com");
    expect(within(history).getByRole("link", { name: "All of the device's alerts" })).toHaveAttribute("href", "/alerts?deviceId=d1&status=all");
    const q = server.callsTo("GET /alerts").find((c) => c.query.get("policyId"))!.query;
    expect([q.get("deviceId"), q.get("policyId"), q.get("subject"), q.get("limit")]).toEqual(["d1", "p1", null, "20"]);

    // An earlier one opens over this one, and its title takes the focus from the link, which is gone; closing goes back
    // to the page, past both.
    await user.click(within(items[1]!).getByRole("link"));
    await waitFor(() => expect(location()).toBe("/alerts?alert=a0"));
    dialog = await screen.findByRole("dialog", { name: "Disk almost full" });
    expect(await within(section(dialog, "Times")).findByText("Open for")).toBeInTheDocument();
    const title = within(dialog).getByRole("heading", { level: 2 });
    expect(title.contains(document.activeElement)).toBe(true);
    expect(document.activeElement).toHaveTextContent("Disk almost full");
    await user.click(within(dialog).getAllByRole("button", { name: "Close" }).at(-1)!);
    await waitFor(() => expect(location()).toBe("/alerts"));
  });

  it("says how many it lists when there are more", async () => {
    installFakeApi(
      routes([DISK], {
        "GET /alerts": (r) => ok({ items: r.query.get("policyId") ? [DISK, { ...DISK, id: "a5" }] : [DISK], next: r.query.get("policyId") ? "9" : null }),
      }),
    );
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    expect(await within(section(dialog, "History")).findByText(/^The latest 2 times this policy opened an alert on this device/)).toBeInTheDocument();
  });

  it("explains what it means and what to do, with the device's tabs", async () => {
    installFakeApi(routes([DISK]));
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    expect(within(section(dialog, "What it means")).getByText("The device's fullest filesystem was 90% full or more in every measurement for 5 minutes.")).toBeInTheDocument();
    const next = section(dialog, "What to do next");
    expect(within(next).getAllByRole("listitem")).toHaveLength(3);
    expect(within(next).getByRole("link", { name: "Overview: Health and Performance" })).toHaveAttribute("href", "/devices/d1");
    expect(within(next).getByRole("link", { name: "Hardware: Disks" })).toHaveAttribute("href", "/devices/d1?tab=hardware");
  });

  it("keeps the raw details folded, as JSON to copy", async () => {
    const user = userEvent.setup();
    installFakeApi(routes([DISK]));
    const dialog = await openCard("/alerts?alert=a1", "Disk almost full");
    const details = within(dialog).getByText("Raw details (JSON)").closest("details")!;
    expect(details).not.toHaveAttribute("open");
    await user.click(within(details).getByText("Raw details (JSON)"));
    expect(details).toHaveAttribute("open");
    expect(JSON.parse(details.querySelector("pre")!.textContent!)).toEqual(DISK);
    // Copy puts the same JSON on the clipboard.
    await user.click(within(details).getByRole("button", { name: "Copy" }));
    expect(await within(details).findByRole("button", { name: "Copied" })).toBeInTheDocument();
    const copied = await navigator.clipboard.readText();
    expect(copied).toBe(JSON.stringify(DISK, null, 2));
  });

  it("wraps a very long disk name and detail", async () => {
    const label = `${"PhysicalDrive12 · ".repeat(16)}End`;
    const detail = `${"Pending sectors 8, uncorrectable sectors 0. ".repeat(11)}End`;
    installFakeApi(routes([{ ...FAILING, subjectLabel: label, detail }], { "GET /devices/:id/disks/:key": fail(404, "not_found", "Not found.") }));
    const dialog = await openCard("/alerts?alert=a4", "Disk failing");
    const summary = section(dialog, "Summary");
    expect(within(summary).getByText(label.trim(), { normalizer: (s) => s.trim() }).closest("dd")).toHaveClass("break-words");
    expect(within(summary).getByText(detail.trim(), { normalizer: (s) => s.trim() }).closest("dd")).toHaveClass("break-words");
  });
});

describe("what an alert means", () => {
  const kinds = { kind: "cpu", checkName: null, threshold: 95, minutes: 15 } as const;
  it("says it for each kind", () => {
    expect(alertGuide(kinds).means).toBe("Processor use was at 95% or more in every measurement for 15 minutes. The agent measures once a minute.");
    expect(alertGuide({ ...kinds, kind: "memory" }).means).toMatch(/^Memory in use was at 95%/);
    expect(alertGuide({ ...kinds, kind: "offline", threshold: null }).means).toMatch(/^Neither the EasyRMM agent nor MeshAgent has checked in from this device for 15 minutes/);
    expect(alertGuide({ ...kinds, kind: "disk", threshold: 90, minutes: 60 }).means).toMatch(/90% full or more in every measurement for 1 hour\.$/);
    expect(alertGuide({ ...kinds, kind: "offline" }).tabs.map((t) => t.tab)).toEqual(["overview"]);
    expect(alertGuide({ ...kinds, kind: "nope" as never }).means).toMatch(/does not know/);
  });

  it("says it for each disk health check", () => {
    const disk = (checkName: DiskCheck | null, threshold: number | null = 1) => alertGuide({ kind: "disk_health", checkName, threshold, minutes: 60 });
    expect(disk("failing").means).toMatch(/^The disk's own verdict is failing/);
    expect(disk("errors", 5).means).toMatch(/^The disk has 5 or more reallocated sectors/);
    expect(disk("errors").next[2]).toMatch(/only rises/);
    expect(disk("pending", 8).means).toMatch(/^The disk has 8 or more pending/);
    expect(disk("wear", 90).means).toMatch(/90% or more of its rated endurance/);
    expect(disk("wear").next[2]).toMatch(/only rises/);
    expect(disk("temperature", null).means).toBe("Every reading of the disk for 1 hour was at or over the drive's own temperature limit.");
    expect(disk("temperature", 60).means).toBe("Every reading of the disk for 1 hour was at 60 °C or more.");
    expect(disk(null).means).toMatch(/does not know/);
    for (const check of ["failing", "errors", "pending", "wear", "temperature", null] as const) expect(disk(check).tabs.map((t) => t.tab)).toEqual(["hardware"]);
  });
});
