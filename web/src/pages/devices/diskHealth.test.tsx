import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DiskHealth, DiskHealthDetail, Inventory } from "../../api/types";
import { formatShortDate, formatShortDateTime } from "../../lib/format";
import { baseRoutes, fail, installFakeApi, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { device, diskHealth, history, inventory, metrics, org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { formatDay } from "./diskHealthText";

const location = () => screen.getByTestId("location").textContent;

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null };
const SERVER = device("d1", "DB-01", { platform: "linux", osDescription: "Debian GNU/Linux 13 (trixie)", agent: AGENT });
const READ_ONLY = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });

const JUDGED = "2026-11-01T10:00:00Z";
const LATER = "2026-11-01T11:30:00Z";
const GONE = "2026-10-28T08:00:00Z";
const when = (at: string) => formatShortDateTime(at);

const NVME_KEY = "0123456789abcdef0123456789abcdef";
const USB_KEY = "fedcba9876543210fedcba9876543210";
const OLD_KEY = "00112233445566778899aabbccddeeff";
const ATA_KEY = "ffeeddccbbaa99887766554433221100";

/** The inventory's NVMe drive, failing, whose three readings since timed out. */
const NVME: DiskHealth = diskHealth(NVME_KEY, "nvme0n1", {
  state: "failing",
  reason: "critical_warning",
  detail: "NVMe critical warning: media read-only",
  judgedLevel: "failing",
  judgedAt: JUDGED,
  since: 3,
  latest: { state: "unknown", reason: "timeout", detail: "", readAt: LATER, receivedAt: LATER },
  facts: [
    { name: "criticalWarning", state: "failing", reason: "critical_warning", value: 8 },
    { name: "temperature", state: "healthy", value: 41 },
    { name: "temperatureLimit", state: "reported", value: 70 },
    { name: "pendingSectors", state: "unsupported", reason: "not_kept", value: null },
    { name: "dataWritten", state: "reported", value: 1000 },
  ],
});

/** The inventory's USB stick, behind a bridge the agent does not read yet. */
const USB: DiskHealth = diskHealth(USB_KEY, "sdb", {
  model: "Ultra Fit",
  serial: "",
  unstable: true,
  state: "unavailable",
  reason: "usb_bridge",
  judgedLevel: null,
  judgedAt: null,
  protocol: "",
  route: "",
  factsAt: null,
  latest: { state: "unavailable", reason: "usb_bridge", detail: "", readAt: LATER, receivedAt: LATER },
});

/** A disk the latest report no longer lists, and the inventory neither. */
const OLD: DiskHealth = diskHealth(OLD_KEY, "sdc", {
  model: "WDC WD40EFRX",
  serial: "WD-WCC4E0000001",
  state: "unknown",
  reason: "missing",
  judgedLevel: "warning",
  judgedAt: GONE,
  missingSince: "2026-10-29T08:00:00Z",
  protocol: "ata",
  route: "sg",
});

/** An ATA disk with its attributes, which the inventory does not list. */
const ATA: DiskHealth = diskHealth(ATA_KEY, "sdd", {
  model: "ST4000VN008",
  serial: "ZDH0000001",
  protocol: "ata",
  route: "sg",
  facts: [
    { name: "smartStatus", state: "healthy", value: 0 },
    { name: "thresholds", state: "reported", value: null },
    { name: "reallocatedSectors", state: "healthy", value: 0 },
  ],
  attributes: [
    { id: 5, flags: 0x33, value: 100, worst: 100, threshold: 10, raw: 0, preFail: true, state: "healthy" },
    { id: 199, flags: 0x3e, value: 200, worst: 200, threshold: 0, raw: 2, preFail: false, state: "healthy" },
    { id: 240, flags: 0, value: 100, worst: 253, raw: 281474976710655, preFail: false, state: "reported" },
  ],
});

const INVENTORY: Inventory = inventory({
  disks: [
    { ...inventory().disks[0]!, firmware: { state: "read", value: "GDC5602Q" } },
    { ...inventory().disks[1]!, firmware: { state: "unavailable", reason: "usb_bridge" } },
    // An older agent's disk: no firmware fact, no health.
    { name: "sde", model: "Flash Reader", serial: "", sizeBytes: 0, kind: "", removable: true },
  ],
});

function detail(d: DiskHealth, extra: Partial<DiskHealthDetail> = {}): DiskHealthDetail {
  return { ...d, history: [], alerts: [], ...extra };
}

function routes(disks: DiskHealth[], extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "alert.view"] })),
    "GET /devices/:id": ok(SERVER),
    "GET /devices/:id/inventory": ok({ inventory: INVENTORY, metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: disks }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

const disksCard = async () => (await screen.findByRole("heading", { name: "Disks" })).closest("section") as HTMLElement;
const row = (card: HTMLElement, name: string) => within(card).getAllByRole("row").find((r) => within(r).queryAllByRole("cell")[0]?.textContent?.startsWith(name)) as HTMLElement;

describe("the Disks card", () => {
  it("shows each disk's firmware and health, the disks only the report lists after them and missing ones last", async () => {
    installFakeApi(routes([OLD, NVME, USB, ATA]));
    renderApp("/devices/d1?tab=hardware");
    const card = await disksCard();
    await within(card).findByRole("button", { name: "nvme0n1" });
    const rows = within(card).getAllByRole("row").slice(1);
    expect(rows.map((r) => within(r).getAllByRole("cell")[0]?.textContent)).toEqual(["nvme0n1", "sdbRemovable", "sdeRemovable", "sdd", "sdcMissing"]);
    expect(within(card).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Disk", "Model", "Type", "Size", "Serial number", "Firmware", "Health"]);

    const nvme = row(card, "nvme0n1");
    expect(nvme).toHaveTextContent("GDC5602Q");
    expect(nvme).toHaveTextContent(`Failing, last read ${when(JUDGED)}`);
    expect(within(nvme).getByText("NVMe critical warning: media read-only")).toBeInTheDocument();
    expect(within(nvme).getByText("The 3 readings since could not tell; the latest: timed out.")).toBeInTheDocument();

    const usb = row(card, "sdb");
    const [, , , , , firmware, health] = within(usb).getAllByRole("cell");
    expect(firmware).toHaveTextContent(/^Unavailable: behind a USB bridge, not read yet$/);
    expect(within(health!).getByText("Unavailable").parentElement).toHaveTextContent(/^Unavailable: behind a USB bridge, not read yet$/);
    expect(within(health!).getByText(`As of ${when(LATER)}`)).toBeInTheDocument();

    // An older agent's disk: no firmware, and no health for it in the report.
    const old = row(card, "sde");
    expect(within(old).getAllByRole("cell")[5]).toHaveTextContent("—");
    expect(within(old).getByText("Not reported")).toHaveAttribute("title", "The agent's disk health report does not list this disk.");

    const missing = row(card, "sdc");
    expect(missing).toHaveTextContent(`Missing since ${formatShortDate("2026-10-29T08:00:00Z")}; last read Warning, ${when(GONE)}`);
    expect(missing).toHaveTextContent("WDC WD40EFRX");
    expect(within(card).getByText(/Select a disk for its facts/)).toBeInTheDocument();
  });

  it("says Not reported, with the agent's version, when the agent has sent no disk health", async () => {
    installFakeApi(routes([]));
    renderApp("/devices/d1?tab=hardware");
    const card = await disksCard();
    expect(await within(card).findByText(/Disk health not reported: this device's agent, version 1.4.0, has sent none/)).toBeInTheDocument();
    expect(within(card).getAllByText("Not reported")).toHaveLength(3);
    expect(within(card).queryByRole("button")).not.toBeInTheDocument();
  });

  it("keeps the inventory when the disk health cannot be read", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes([], { "GET /devices/:id/disks": fail(500, "internal", "Something went wrong.") }));
    renderApp("/devices/d1?tab=hardware");
    const card = await disksCard();
    expect(await within(card).findByText("Something went wrong.")).toBeInTheDocument();
    expect(row(card, "nvme0n1")).toHaveTextContent("Samsung PM9A3");
    server.on("GET /devices/:id/disks", ok({ items: [NVME] }));
    await user.click(within(card).getByRole("button", { name: /Try again|Retry/ }));
    expect(await within(card).findByRole("button", { name: "nvme0n1" })).toBeInTheDocument();
  });

  it("shows the disks a report lists when the inventory lists none", async () => {
    installFakeApi(routes([ATA], { "GET /devices/:id/inventory": ok({ inventory: inventory({ disks: [] }), metrics: null }) }));
    renderApp("/devices/d1?tab=hardware");
    const card = await disksCard();
    expect(await within(card).findByRole("button", { name: "sdd" })).toBeInTheDocument();
    expect(within(card).queryByText("No disks reported")).not.toBeInTheDocument();
  });
});

describe("a disk's panel", () => {
  it("lists every fact with its state, the last 30 days and the disk's open alerts", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes([NVME, USB], {
        "GET /devices/:id/disks/:key": (r: FakeRequest) =>
          ok(
            detail(NVME, {
              history: [
                { day: "2026-11-01T00:00:00Z", state: "failing", temperature: 44, wear: 12, reallocatedSectors: null, mediaErrors: 3, pendingSectors: null, uncorrectableSectors: null, driveErrors: null, powerOnHours: 9000 },
                { day: "2026-10-31T00:00:00Z", state: "healthy", temperature: 40, wear: 12, reallocatedSectors: null, mediaErrors: 0, pendingSectors: null, uncorrectableSectors: null, driveErrors: null, powerOnHours: 8990 },
              ],
              alerts: [{ id: "a9", name: "Disk failing", checkName: "failing", severity: "critical", status: "open", detail: "NVMe critical warning: media read-only", openedAt: JUDGED }],
              key: r.params.key ?? "",
            }),
          ),
      }),
    );
    renderApp("/devices/d1?tab=hardware");
    const card = await disksCard();
    await user.click(await within(card).findByRole("button", { name: "nvme0n1" }));
    const panel = await screen.findByRole("dialog", { name: "nvme0n1" });
    expect(server.call("GET /devices/:id/disks/:key").path).toBe(`/devices/d1/disks/${NVME_KEY}`);
    expect(within(panel).getByText(`, last read ${when(JUDGED)}`, { exact: false })).toBeInTheDocument();
    expect(within(panel).getByText("GDC5602Q")).toBeInTheDocument();
    expect(within(panel).getByText("NVMe, Linux, the NVMe admin command")).toBeInTheDocument();

    const facts = within(panel).getByRole("table", { name: "Facts" });
    const factRows = within(facts).getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell").map((c) => c.textContent));
    expect(factRows).toEqual([
      ["Critical warning (NVMe)", "Media read-only", "Failing: NVMe critical warning"],
      ["Temperature", "41 °C", "Healthy"],
      ["The drive's temperature limit", "70 °C", "Reported"],
      ["Pending sectors", "—", "Unsupported: the drive does not keep this"],
      ["Data written", "512.0 MB", "Reported"],
    ]);
    expect(within(panel).queryByRole("table", { name: "SMART attributes" })).not.toBeInTheDocument();

    const days = await within(panel).findByRole("table", { name: "Last 30 days" });
    expect(within(days).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Day (UTC)", "Worst state", "Highest temperature", "Wear", "Media errors"]);
    expect(within(days).getAllByRole("row")[1]!.textContent).toBe(`${formatDay("2026-11-01T00:00:00Z")}Failing44 °C12%3`);

    const alerts = within(panel).getByRole("heading", { name: "Open alerts" }).closest("section") as HTMLElement;
    expect(within(alerts).getByText("Disk failing", { selector: "span.font-medium" })).toBeInTheDocument();
    expect(within(alerts).getByText("Critical")).toBeInTheDocument();
    expect(within(alerts).getByRole("link", { name: "The device's alerts" })).toHaveAttribute("href", "/alerts?deviceId=d1&status=all");

    await user.click(within(panel).getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "nvme0n1" })).not.toBeInTheDocument());

    // A disk never read has no facts yet, and an identity from its name.
    server.on("GET /devices/:id/disks/:key", ok(detail(USB)));
    await user.click(within(card).getByRole("button", { name: "sdb" }));
    const usb = await screen.findByRole("dialog", { name: "sdb" });
    expect(within(usb).getByText("No facts read yet.")).toBeInTheDocument();
    expect(within(usb).getByText("Not read")).toBeInTheDocument();
    expect(within(usb).getByText("Never read")).toBeInTheDocument();
    expect(within(usb).getByText(/the disk reports no serial number/)).toBeInTheDocument();
    expect(await within(usb).findByText("No readings in the last 30 days.")).toBeInTheDocument();
    expect(within(usb).getByText("No open alerts on this disk.")).toBeInTheDocument();
  });

  it("shows an ATA disk's attributes, and no alerts to someone who may not view them", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...routes([ATA], { "GET /devices/:id/disks/:key": ok(detail(ATA, { alerts: null })) }),
      ...{ "GET /auth/session": ok(READ_ONLY) },
    });
    renderApp("/devices/d1?tab=hardware");
    await user.click(await within(await disksCard()).findByRole("button", { name: "sdd" }));
    const panel = await screen.findByRole("dialog", { name: "sdd" });
    const attrs = within(panel).getByRole("table", { name: "SMART attributes" });
    expect(within(attrs).getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell").map((c) => c.textContent))).toEqual([
      ["5", "Reallocated sectors", "Pre-fail", "100", "100", "10", "0", "Healthy"],
      ["199", "The maker's own", "Old age", "200", "200", "0", "2", "Healthy"],
      ["240", "The maker's own", "Old age", "100", "253", "—", "281474976710655", "Reported"],
    ]);
    const facts = within(panel).getByRole("table", { name: "Facts" });
    expect(within(facts).getByRole("row", { name: /SMART status/ })).toHaveTextContent("Passed");
    expect(within(facts).getByRole("row", { name: /Attribute thresholds/ })).toHaveTextContent("Read");
    expect(await within(panel).findByText("No readings in the last 30 days.")).toBeInTheDocument();
    expect(within(panel).queryByRole("heading", { name: "Open alerts" })).not.toBeInTheDocument();
  });

  it("says when its history cannot be read", async () => {
    const user = userEvent.setup();
    installFakeApi(routes([NVME], { "GET /devices/:id/disks/:key": fail(404, "not_found", "Not found.") }));
    renderApp("/devices/d1?tab=hardware");
    await user.click(await within(await disksCard()).findByRole("button", { name: "nvme0n1" }));
    const panel = await screen.findByRole("dialog", { name: "nvme0n1" });
    // The list's facts show at once; the history says what went wrong.
    expect(within(panel).getByRole("table", { name: "Facts" })).toBeInTheDocument();
    expect(await within(panel).findByText("Not found.")).toBeInTheDocument();
  });
});

describe("disk health across the fleet", () => {
  const LINUX = { platform: "linux" as const, agent: AGENT };
  const DEVICES = [
    device("d1", "DB-01", { ...LINUX, diskHealth: { label: "failing", states: { failing: 1, healthy: 1, unsupported: 1 } } }),
    device("d2", "WEB-01", { ...LINUX, diskHealth: { label: "healthy", states: { healthy: 1, unavailable: 3 } } }),
    device("d3", "NAS-01", { ...LINUX, diskHealth: { label: "unavailable", states: { unavailable: 4 } } }),
    device("d4", "BUILD-01", { ...LINUX }),
    device("d5", "FRONT-DESK", { agent: AGENT, diskHealth: { label: "warning", states: { warning: 1 } } }),
  ];
  const lists = {
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
  };
  const matches: Record<string, string[]> = {
    failing: ["d1"],
    warning: ["d5"],
    unknown: [],
    healthy: ["d2"],
    unavailable: ["d2", "d3"],
    unsupported: ["d1"],
    not_reported: ["d4"],
  };

  it("labels each device, sorts by the label and filters on the server", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(READ_ONLY),
      ...lists,
      "GET /devices": (r) => {
        const f = r.query.get("diskHealth");
        return ok({ items: DEVICES.filter((d) => !f || matches[f]?.includes(d.id)) });
      },
    });
    renderApp("/devices");
    await screen.findByRole("link", { name: "DB-01" });
    const header = screen.getByRole("columnheader", { name: /Disk health/ });
    expect(header).toHaveAttribute("aria-sort", "none");
    // Hardening's column stays last.
    const cell = (name: string) => within(screen.getByRole("row", { name: new RegExp(name) })).getAllByRole("cell").at(-2) as HTMLElement;
    expect(within(cell("DB-01")).getByText("Failing, 1 disk unsupported")).toHaveAttribute("title", "1 disk failing, 1 disk healthy, 1 disk unsupported");
    expect(cell("WEB-01")).toHaveTextContent("Healthy, 3 disks unavailable");
    expect(cell("NAS-01")).toHaveTextContent("Unavailable, 4 disks");
    expect(cell("BUILD-01")).toHaveTextContent("Not reported");
    expect(cell("FRONT-DESK")).toHaveTextContent("Warning");

    const names = () => screen.getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("link")[0]?.textContent);
    expect(names()).toEqual(["DB-01", "WEB-01", "NAS-01", "BUILD-01", "FRONT-DESK"]);
    await user.click(within(header).getByRole("button", { name: /Disk health/ }));
    await waitFor(() => expect(location()).toBe("/devices?sort=diskHealth"));
    expect(names()).toEqual(["DB-01", "FRONT-DESK", "NAS-01", "WEB-01", "BUILD-01"]);
    expect(screen.getByRole("columnheader", { name: /Disk health/ })).toHaveAttribute("aria-sort", "ascending");
    await user.click(screen.getByRole("button", { name: /Disk health/ }));
    await waitFor(() => expect(location()).toBe("/devices?sort=-diskHealth"));
    expect(names()).toEqual(["BUILD-01", "WEB-01", "NAS-01", "FRONT-DESK", "DB-01"]);
    expect(screen.getByRole("columnheader", { name: /Disk health/ })).toHaveAttribute("aria-sort", "descending");
    await user.click(screen.getByRole("button", { name: /Disk health/ }));
    await waitFor(() => expect(location()).toBe("/devices"));

    const filter = screen.getByLabelText("Disk health");
    expect(within(filter).getAllByRole("option").map((o) => o.textContent)).toEqual([
      "Any disk health",
      "Failing",
      "Warning",
      "Unknown",
      "Healthy",
      "Unavailable",
      "Unsupported",
      "Not reported",
    ]);
    await user.selectOptions(filter, "unavailable");
    await waitFor(() => expect(screen.queryByRole("link", { name: "DB-01" })).not.toBeInTheDocument());
    expect(server.callsTo("GET /devices").at(-1)?.query.get("diskHealth")).toBe("unavailable");
    expect(location()).toBe("/devices?diskHealth=unavailable");
    expect(screen.getByRole("link", { name: "WEB-01" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "NAS-01" })).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Disk health"), "unknown");
    expect(await screen.findByText("No devices match these filters")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Disk health"), "not_reported");
    expect(await screen.findByRole("link", { name: "BUILD-01" })).toBeInTheDocument();
    expect(server.callsTo("GET /devices").at(-1)?.query.get("diskHealth")).toBe("not_reported");
  });

  it("has no disk health column when no listed device has the agent", async () => {
    installFakeApi({ ...baseRoutes(READ_ONLY), ...lists, "GET /devices": ok({ items: [device("d9", "KIOSK-01")] }) });
    renderApp("/devices");
    await screen.findByRole("link", { name: "KIOSK-01" });
    expect(screen.queryByRole("columnheader", { name: /Disk health/ })).not.toBeInTheDocument();
    // The filter stays.
    expect(screen.getByLabelText("Disk health")).toBeInTheDocument();
  });
});
