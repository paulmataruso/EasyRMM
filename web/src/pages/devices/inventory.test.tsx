import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Package } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { SHOWN_PACKAGES } from "./DeviceSoftware";

const location = () => screen.getByTestId("location").textContent;

const AGENT = { version: "1.4.0", arch: "amd64", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z" };
const SERVER = device("d1", "DB-01", { platform: "linux", osDescription: "Debian GNU/Linux 13 (trixie)", agent: AGENT });

const TECHNICIAN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "software.view"] });

const PACKAGES: Package[] = [
  { name: "bash", version: "5.2.37-2", arch: "amd64" },
  { name: "openssl", version: "3.5.1-1", arch: "amd64" },
  { name: "postgresql-18", version: "18.1-1.pgdg13+1", arch: "amd64" },
];

function routes(extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(TECHNICIAN),
    "GET /devices/:id": ok(SERVER),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/software": ok({ items: PACKAGES }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

describe("device health", () => {
  it("shows the latest measurements, fullest filesystem first, and flags what is running out", async () => {
    installFakeApi(routes());
    renderApp("/devices/d1");
    const card = (await screen.findByRole("heading", { name: "Health" })).closest("section") as HTMLElement;
    const meters = await within(card).findAllByRole("meter");
    expect(meters.map((m) => m.getAttribute("aria-label"))).toEqual(["Processor", "Memory", "Swap", "/var", "/"]);
    expect(within(card).getByRole("meter", { name: "Processor" })).toHaveAttribute("aria-valuetext", "38%");
    expect(within(card).getByRole("meter", { name: "Memory" })).toHaveAttribute("aria-valuetext", "81%, high");
    expect(within(card).getByRole("meter", { name: "/var" })).toHaveAttribute("aria-valuetext", "93%, critical");
    expect(within(card).getByText(/104 GiB of 128 GiB/)).toBeInTheDocument();
    expect(within(card).getByText(/28 GiB free/)).toBeInTheDocument();
    expect(within(card).getByText("4.25 · 3.50 · 2.75")).toBeInTheDocument();
    expect(within(card).getByText("3 d 4 h")).toBeInTheDocument();
    expect(within(card).getByText("412")).toBeInTheDocument();
  });

  it("charts use over the chosen period with a legend and a data table", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/devices/d1");
    const card = (await screen.findByRole("heading", { name: "Performance" })).closest("section") as HTMLElement;
    const legend = await within(card).findByRole("list", { name: "Legend" });
    expect(within(legend).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["Processor40%", "Memory80%", "Fullest disk93%"]);
    expect(server.call("GET /devices/:id/metrics").query.get("range")).toBe("24h");

    await user.click(within(card).getByRole("button", { name: "Show as a table" }));
    const table = within(card).getByRole("table", { name: /Processor, memory and fullest disk use, last 24 hours/ });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Time", "Processor", "Memory", "Fullest disk"]);

    const period = within(card).getByRole("radiogroup", { name: "Period" });
    await user.click(within(period).getByRole("radio", { name: "7 days" }));
    await waitFor(() => expect(server.callsTo("GET /devices/:id/metrics").at(-1)?.query.get("range")).toBe("7d"));
    expect(within(period).getByRole("radio", { name: "7 days" })).toHaveAttribute("aria-checked", "true");
    // Arrow keys move between periods, as in any radio group.
    await user.keyboard("{ArrowLeft}");
    await waitFor(() => expect(server.callsTo("GET /devices/:id/metrics").at(-1)?.query.get("range")).toBe("24h"));
  });

  it("reads values from the chart with the keyboard", async () => {
    const user = userEvent.setup();
    installFakeApi(routes());
    renderApp("/devices/d1");
    const chart = await screen.findByRole("group", { name: /fullest disk use, last 24 hours/ });
    chart.focus();
    await user.keyboard("{End}");
    const readout = document.getElementById(chart.getAttribute("aria-describedby") ?? "") as HTMLElement;
    expect(readout.textContent).toMatch(/Processor 40%, Memory 80%, Fullest disk 93%$/);
    await user.keyboard("{Home}");
    expect(readout.textContent).toMatch(/Processor 20%/);
    await user.keyboard("{ArrowRight}");
    expect(readout.textContent).toMatch(/Processor 30%/);
    await user.keyboard("{Escape}");
    expect(readout.textContent).toBe("");
  });

  it("says when the agent has not measured anything yet", async () => {
    installFakeApi({ ...routes(), ...unreportedRoutes() });
    renderApp("/devices/d1");
    expect(await screen.findByText("No measurements yet")).toBeInTheDocument();
    expect(await screen.findByText("No measurements in this period.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Show as a table" })).not.toBeInTheDocument();
  });

  it("offers no inventory for a device without the EasyRMM agent", async () => {
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(device("d2", "FRONT-DESK")), "GET /audit": ok({ items: [] }) });
    renderApp("/devices/d2");
    expect(await screen.findByRole("heading", { name: "FRONT-DESK" })).toBeInTheDocument();
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Health" })).not.toBeInTheDocument();
  });
});

describe("device hardware", () => {
  it("lists the system, disks, filesystems and network", async () => {
    const user = userEvent.setup();
    installFakeApi(routes());
    renderApp("/devices/d1");
    await user.click(await screen.findByRole("tab", { name: "Hardware" }));
    expect(location()).toBe("/devices/d1?tab=hardware");
    const system = (await screen.findByRole("heading", { name: "System" })).closest("section") as HTMLElement;
    expect(within(system).getByText("PowerEdge R650")).toBeInTheDocument();
    expect(within(system).getByText("Physical machine")).toBeInTheDocument();
    expect(within(system).getByText("2 sockets, 32 cores, 64 threads")).toBeInTheDocument();
    expect(within(system).getByText("128 GiB")).toBeInTheDocument();
    expect(within(system).getByText("Dell Inc. 1.13.2 (2024-03-14)")).toBeInTheDocument();

    const disks = (screen.getByRole("heading", { name: "Disks" }).closest("section") as HTMLElement).querySelector("tbody") as HTMLElement;
    const [nvme, usb] = within(disks).getAllByRole("row");
    expect(nvme).toHaveTextContent(/nvme0n1.*Samsung PM9A3.*NVMe SSD.*894 GiB/);
    expect(usb).toHaveTextContent(/sdb.*Removable/);

    const fs = screen.getByRole("heading", { name: "Filesystems" }).closest("section") as HTMLElement;
    expect(within(fs).getAllByRole("meter").map((m) => m.getAttribute("aria-label"))).toEqual(["Used on /var", "Used on /"]);

    const net = screen.getByRole("heading", { name: "Network" }).closest("section") as HTMLElement;
    expect(within(net).getByText("2001:db8::20/64")).toBeInTheDocument();
    expect(within(net).getByText("10 Gbit/s")).toBeInTheDocument();
    expect(within(net).getByText("Down")).toBeInTheDocument();
    expect(within(net).getByText("192.0.2.53, 2001:db8::53")).toBeInTheDocument();
  });

  it("opens from the health card when there are more filesystems than it shows", async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: 6 }, (_, i) => ({ mount: `/srv/${i}`, device: `/dev/sd${i}`, type: "ext4", totalBytes: 100, usedBytes: i }));
    installFakeApi(routes({ "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics({ filesystems: many }) }) }));
    renderApp("/devices/d1");
    await user.click(await screen.findByRole("button", { name: "2 more filesystems on the Hardware tab" }));
    expect(location()).toBe("/devices/d1?tab=hardware");
    expect(await screen.findByRole("tab", { name: "Hardware" })).toHaveAttribute("aria-selected", "true");
  });

  it("describes a container that reports no disks", async () => {
    installFakeApi(
      routes({
        "GET /devices/:id/inventory": ok({ inventory: inventory({ system: { ...inventory().system, virtualization: "container" }, disks: [] }), metrics: null }),
      }),
    );
    renderApp("/devices/d1?tab=hardware");
    expect(await screen.findByText("Container")).toBeInTheDocument();
    expect(screen.getByText("No disks reported")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Filesystems" })).not.toBeInTheDocument();
  });

  it("waits for the first inventory", async () => {
    installFakeApi({ ...routes(), ...unreportedRoutes() });
    renderApp("/devices/d1?tab=hardware");
    expect(await screen.findByText("No inventory yet")).toBeInTheDocument();
  });
});

describe("device software", () => {
  it("lists and filters the installed packages", async () => {
    const user = userEvent.setup();
    installFakeApi(routes());
    renderApp("/devices/d1?tab=software");
    const table = await screen.findByRole("table");
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(screen.getByText("3 packages")).toBeInTheDocument();
    expect(screen.getByText(/From dpkg \(Debian, Ubuntu\)/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Search the software on every device" })).toHaveAttribute("href", "/software");

    await user.type(screen.getByLabelText("Filter packages"), "SSL");
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(2);
    expect(screen.getByText("1 of 3 packages")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Filter packages"));
    await user.type(screen.getByLabelText("Filter packages"), "pgdg");
    expect(within(screen.getByRole("table")).getByText("postgresql-18")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Filter packages"), "zzz");
    expect(screen.getByText("No packages match")).toBeInTheDocument();
  });

  it("draws a long list in part and says how to find the rest", async () => {
    const many = Array.from({ length: SHOWN_PACKAGES + 50 }, (_, i) => ({ name: `lib${String(i).padStart(4, "0")}`, version: "1.0", arch: "amd64" }));
    installFakeApi(routes({ "GET /devices/:id/software": ok({ items: many }) }));
    renderApp("/devices/d1?tab=software");
    expect(await screen.findByText(`Showing the first ${SHOWN_PACKAGES} of ${SHOWN_PACKAGES + 50}. Filter by name to find the rest.`)).toBeInTheDocument();
    expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(SHOWN_PACKAGES + 1);
  });

  it("is a tab only for people who can see software", async () => {
    installFakeApi(routes({ ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["device.view"] })) }));
    renderApp("/devices/d1?tab=software");
    expect(await screen.findByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByRole("tab", { name: "Software" })).not.toBeInTheDocument();
  });
});
