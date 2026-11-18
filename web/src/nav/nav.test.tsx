import { describe, expect, it, vi } from "vitest";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DeviceAlertCount } from "../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, unreportedRoutes, type FakeRequest } from "../test/fakeApi";
import { device, org, script, site } from "../test/fixtures";
import { renderApp } from "../test/render";

const ADMIN = sessionView({
  permissions: [
    "org.view",
    "org.create",
    "site.view",
    "device.view",
    "enrollment.manage",
    "alert.view",
    "script.view",
    "script.manage",
    "job.view",
    "user.view",
    "audit.view",
    "settings.manage",
  ],
});

const ORGS = [org("o1", "Northwind Traders"), org("o2", "Contoso Dental Group")];
const SITES = [site("s1", "o1", "Head office"), site("s2", "o1", "Warehouse"), site("s3", "o2", "Main clinic", { organizationName: "Contoso Dental Group" })];
const DB01 = device("d1", "DB-01");
const FRONT = device("d2", "FRONT-DESK", { siteId: "s2", siteName: "Warehouse", online: false, remoteOnline: false });
const RECEPTION = device("d3", "RECEPTION", { organizationId: "o2", organizationName: "Contoso Dental Group", siteId: "s3", siteName: "Main clinic", remoteAgent: false });

function routes(session = ADMIN) {
  return {
    ...baseRoutes(session),
    "GET /organizations": ok({ items: ORGS }),
    "GET /sites": ok({ items: SITES }),
    "GET /devices": ok({ items: [DB01, FRONT, RECEPTION] }),
    // Rows load their device's page ahead of a click.
    "GET /devices/:id": (r: FakeRequest) => ok([DB01, FRONT, RECEPTION].find((d) => d.id === r.params.id)),
    "GET /remote-access/status": ok({ address: "https://mesh.rmm.example.com", connected: true, lastSyncAt: "2026-11-01T09:59:00Z", devices: 3, devicesOnline: 2 }),
    "GET /audit": ok({ items: [] }),
  };
}

const location = () => screen.getByTestId("location").textContent;

describe("section navigation", () => {
  it("replaces the main menu with the devices tree, and Back returns to it", async () => {
    const user = userEvent.setup();
    installFakeApi({ ...routes(), ...unreportedRoutes() });
    renderApp("/devices");

    const tree = await screen.findByRole("tree", { name: "Devices: organizations, sites and devices" });
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).queryByRole("link", { name: "Dashboard" })).not.toBeInTheDocument();
    expect(within(nav).getByRole("button", { name: "All devices, 2 of 3 devices online" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByRole("link", { name: "Add devices" })).toHaveAttribute("href", "/devices/add");
    expect(within(nav).getByText("3 devices, 2 online")).toBeInTheDocument();
    expect(within(tree).getByRole("treeitem", { name: "Northwind Traders, 1 of 2 devices online" })).toHaveAttribute("aria-expanded", "true");
    expect(within(tree).getByRole("treeitem", { name: "FRONT-DESK, offline" })).toHaveAttribute("aria-level", "3");

    // A site narrows the list; a device opens its page.
    await user.click(within(tree).getByRole("treeitem", { name: "Warehouse, 0 of 1 device online" }));
    await waitFor(() => expect(location()).toBe("/devices?organizationId=o1&siteId=s2"));
    expect(within(tree).getByRole("treeitem", { name: "Warehouse, 0 of 1 device online" })).toHaveAttribute("aria-selected", "true");
    await user.click(within(tree).getByRole("treeitem", { name: "DB-01, online" }));
    await waitFor(() => expect(location()).toBe("/devices/d1"));
    expect(within(tree).getByRole("treeitem", { name: "DB-01, online" })).toHaveAttribute("aria-selected", "true");

    // The filter narrows to matches by name or hostname.
    await user.type(within(nav).getByLabelText("Filter the tree"), "front");
    expect(within(nav).getByText("1 match")).toBeInTheDocument();
    expect(within(tree).queryByRole("treeitem", { name: /^DB-01/ })).not.toBeInTheDocument();
    await user.clear(within(nav).getByLabelText("Filter the tree"));

    // Back shows the main menu, with focus on the section it left.
    await user.click(within(nav).getByRole("button", { name: "Back to the main menu" }));
    expect(screen.queryByRole("tree")).not.toBeInTheDocument();
    const devicesLink = within(nav).getByRole("link", { name: "Devices" });
    await waitFor(() => expect(devicesLink).toHaveFocus());
    expect(within(nav).queryByRole("link", { name: "Software" })).not.toBeInTheDocument();

    // Choosing a section from the menu opens its navigation again, with focus on Back.
    await user.click(devicesLink);
    expect(await screen.findByRole("tree", { name: "Devices: organizations, sites and devices" })).toBeInTheDocument();
    await waitFor(() => expect(within(nav).getByRole("button", { name: "Back to the main menu" })).toHaveFocus());
    expect(location()).toBe("/devices");
  });

  it("widens the sidebar for long names, within a limit, and narrows it again for the main menu", async () => {
    const user = userEvent.setup();
    const long = "Northwind Traders International Holdings (EMEA)";
    installFakeApi({ ...routes(), ...unreportedRoutes(), "GET /organizations": ok({ items: [org("o1", long), ORGS[1]!] }) });
    renderApp("/devices");

    const tree = await screen.findByRole("tree");
    const sidebar = screen.getAllByRole("complementary")[0]!;
    // Every name counts, the longest here an organization's; tests measure 8 pixels a character.
    expect(sidebar.style.width).toMatch(/^clamp\(15rem, (\d+)px, min\(24rem, 33\.3vw\)\)$/);
    expect(Number(/(\d+)px/.exec(sidebar.style.width)![1])).toBeGreaterThan(long.length * 8);
    // Past the limit, names are cut short and shown in full on hover.
    expect(within(tree).getByRole("treeitem", { name: new RegExp(`^${long.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`) })).toHaveAttribute("title", long);

    await user.click(screen.getByRole("button", { name: "Back to the main menu" }));
    expect(sidebar.style.width).toBe("");
  });

  it("moves through the tree with the keyboard", async () => {
    const user = userEvent.setup();
    installFakeApi(routes());
    renderApp("/devices");
    const tree = await screen.findByRole("tree");
    const filter = screen.getByLabelText("Filter the tree");
    act(() => filter.focus());
    await user.keyboard("{ArrowDown}");
    // The selected row (All devices is outside the tree) or the first row takes focus.
    const contoso = within(tree).getByRole("treeitem", { name: "Contoso Dental Group, 1 of 1 device online" });
    expect(contoso).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(contoso).toHaveAttribute("aria-expanded", "false");
    await user.keyboard("{ArrowRight}");
    expect(contoso).toHaveAttribute("aria-expanded", "true");
    await user.keyboard("{ArrowDown}");
    expect(within(tree).getByRole("treeitem", { name: "Main clinic, 1 of 1 device online" })).toHaveFocus();
    await user.keyboard("{End}");
    expect(within(tree).getByRole("treeitem", { name: "FRONT-DESK, offline" })).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(within(tree).getByRole("treeitem", { name: "Warehouse, 0 of 1 device online" })).toHaveFocus();
    await user.keyboard("{Home}{Enter}");
    await waitFor(() => expect(location()).toBe("/devices?organizationId=o2"));

    await user.click(screen.getByRole("button", { name: "Collapse all" }));
    expect(within(tree).getAllByRole("treeitem")).toHaveLength(2);
  });

  it("quick connects from a device row without leaving the page", async () => {
    const user = userEvent.setup();
    const open = vi.fn(() => ({ closed: false, focus: vi.fn(), location: { pathname: "" } }));
    vi.stubGlobal("open", open);
    installFakeApi(routes());
    renderApp("/devices");

    const tree = await screen.findByRole("tree");
    // Devices without remote access offer nothing to connect to.
    expect(within(within(tree).getByRole("treeitem", { name: "RECEPTION, online" })).queryByRole("button")).not.toBeInTheDocument();

    const row = within(tree).getByRole("treeitem", { name: "DB-01, online" });
    await user.click(within(row).getByRole("button", { name: "Quick connect to DB-01" }));
    const panel = screen.getByRole("dialog", { name: "DB-01" });
    expect(within(panel).getByText("Ready to connect")).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "Open Terminal in this tab" })).toHaveAttribute("href", "/devices/d1/remote/terminal");
    expect(within(panel).getByRole("button", { name: "Remote desktop" })).toHaveFocus();
    await user.click(within(panel).getByRole("button", { name: "Remote desktop" }));
    expect(open).toHaveBeenCalledWith("/devices/d1/remote/desktop", "easyrmm-session-d1", expect.stringContaining("popup=yes"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(location()).toBe("/devices");

    // From the keyboard: Shift+F10 on a row. An offline device says why it cannot connect.
    const front = within(tree).getByRole("treeitem", { name: "FRONT-DESK, offline" });
    act(() => front.focus());
    await user.keyboard("{Shift>}{F10}{/Shift}");
    const offline = screen.getByRole("dialog", { name: "FRONT-DESK" });
    expect(within(offline).getByText("The device is offline.")).toBeInTheDocument();
    expect(within(offline).getByRole("button", { name: "Remote desktop" })).toBeDisabled();
    expect(within(offline).queryByRole("link", { name: /in this tab/ })).not.toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(front).toHaveFocus();

    // The context menu opens it too, and a click elsewhere closes it.
    fireEvent.contextMenu(row);
    expect(screen.getByRole("dialog", { name: "DB-01" })).toBeInTheDocument();
    await user.click(screen.getByRole("main"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("counts active alerts down the tree and lists only the devices that have them", async () => {
    const user = userEvent.setup();
    const counts: DeviceAlertCount[] = [{ deviceId: "d2", organizationId: "o1", siteId: "s2", active: 2, critical: 1 }];
    const server = installFakeApi({ ...routes(), "GET /alerts/devices": ok({ items: counts }) });
    renderApp("/alerts");

    const tree = await screen.findByRole("tree", { name: "Alerts: organizations, sites and devices" });
    expect(screen.getByRole("button", { name: "All alerts, 2 active alerts, 1 critical" })).toBeInTheDocument();
    expect(within(tree).getByRole("treeitem", { name: "Northwind Traders, 2 active alerts, 1 critical" })).toBeInTheDocument();
    expect(within(tree).getByRole("treeitem", { name: "Head office" })).toBeInTheDocument();
    expect(within(tree).queryByRole("treeitem", { name: /^DB-01/ })).not.toBeInTheDocument();
    expect(screen.getByText("2 active alerts on 1 device")).toBeInTheDocument();

    await user.click(within(tree).getByRole("treeitem", { name: "FRONT-DESK, offline, 2 active alerts, 1 critical" }));
    await waitFor(() => expect(location()).toBe("/alerts?organizationId=o1&siteId=s2&deviceId=d2"));
    await waitFor(() => expect(server.callsTo("GET /alerts").at(-1)?.query.get("deviceId")).toBe("d2"));
    expect(await screen.findByRole("button", { name: "Show alerts on every device" })).toBeInTheDocument();
  });

  it("narrows the script library to the shared library, an organization or a site", async () => {
    const user = userEvent.setup();
    const scripts = [script("sc1", "Disk usage"), script("sc2", "Restart spooler", { level: "site", organizationId: "o1", siteId: "s1" })];
    const server = installFakeApi({ ...routes(), "GET /scripts": ok({ items: scripts }) });
    renderApp("/scripts");

    const tree = await screen.findByRole("tree", { name: "Scripts: organizations, sites" });
    expect(screen.getByRole("button", { name: "All scripts, 2 scripts" })).toHaveAttribute("aria-current", "page");
    expect(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: "New script" })).toHaveAttribute("href", "/scripts/new");
    // The library lists no devices.
    expect(within(tree).queryByRole("treeitem", { name: /^DB-01/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Shared library, 1 script" }));
    await waitFor(() => expect(location()).toBe("/scripts?library=shared"));
    await user.click(within(tree).getByRole("treeitem", { name: "Head office, 1 script" }));
    await waitFor(() => expect(location()).toBe("/scripts?library=o1&siteId=s1"));
    await waitFor(() => expect(server.callsTo("GET /scripts").at(-1)?.query.get("siteId")).toBe("s1"));
    expect(await screen.findByLabelText("Site")).toHaveValue("s1");
  });

  it("narrows jobs to where they ran", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...routes(), "GET /jobs": ok({ items: [] }) });
    renderApp("/jobs");
    const tree = await screen.findByRole("tree", { name: "Jobs: organizations, sites and devices" });
    await user.click(within(tree).getByRole("treeitem", { name: "Warehouse" }));
    await waitFor(() => expect(server.callsTo("GET /jobs").at(-1)?.query.get("siteId")).toBe("s2"));
    expect(server.callsTo("GET /jobs").at(-1)?.query.get("organizationId")).toBe("o1");
    expect(await screen.findByText("No jobs match these filters.")).toBeInTheDocument();
  });

  it("leads organizations and sites to their pages", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...routes(),
      "GET /sites/:id": ok(SITES[1]),
      "GET /organizations/:id": ok(ORGS[0]),
      "GET /sites/:id/device-groups": ok({ items: [] }),
    });
    renderApp("/organizations");
    const tree = await screen.findByRole("tree", { name: "Organizations: organizations, sites" });
    expect(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: "New organization" })).toHaveAttribute("href", "/organizations?new=1");
    expect(within(tree).getByRole("treeitem", { name: "Northwind Traders, 2 devices" })).toBeInTheDocument();
    await user.click(within(tree).getByRole("treeitem", { name: "Warehouse, 1 device" }));
    await waitFor(() => expect(location()).toBe("/sites/s2"));
    expect(await screen.findByRole("heading", { name: "Warehouse", level: 1 })).toBeInTheDocument();
  });

  it("lists settings' parts that the role may see", async () => {
    const user = userEvent.setup();
    installFakeApi({ ...baseRoutes(ADMIN), "GET /audit": ok({ items: [] }), "GET /users": ok({ items: [] }) });
    renderApp("/settings?tab=audit");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(await within(nav).findByRole("link", { name: "Audit log" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByRole("link", { name: "Users" })).toHaveAttribute("href", "/settings");
    expect(within(nav).getByRole("link", { name: "Remote access" })).toHaveAttribute("href", "/settings?tab=remote");
    expect(screen.getByRole("heading", { name: "Audit log", level: 1 })).toBeInTheDocument();
    await user.click(within(nav).getByRole("button", { name: "Back to the main menu" }));
    expect(within(nav).getByRole("link", { name: "Settings" })).toBeInTheDocument();
  });

  it("keeps the main menu for sections the role cannot see", async () => {
    installFakeApi({ ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "audit.view"] })), "GET /audit": ok({ items: [] }) });
    renderApp("/settings");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    // Only the audit log: it is the page, and the only part listed.
    expect(await within(nav).findByRole("link", { name: "Audit log" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
  });
});
