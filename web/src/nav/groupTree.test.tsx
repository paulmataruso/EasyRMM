import { describe, expect, it, onTestFinished } from "vitest";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Device, DeviceTreeData } from "../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, unreportedRoutes, type FakeRequest } from "../test/fakeApi";
import { device, org, site } from "../test/fixtures";
import { renderApp } from "../test/render";

// The device tree on every view (ADR-0069): organizations, sites, groups and devices, with devices loaded as a node opens.

const ADMIN = sessionView({
  permissions: ["org.view", "site.view", "device.view", "alert.view", "script.view", "job.view", "patch.view", "user.view", "audit.view", "settings.manage"],
});
const ORGS = [org("o1", "Northwind Traders")];
const SITES = [site("s1", "o1", "Head office"), site("s2", "o1", "Warehouse")];
const SERVERS = { id: "g1", organizationId: "o1", siteId: "s1", name: "Servers", description: "" };
const DB01 = device("d1", "DB-01", { deviceGroupId: "g1" });
const ACCT = device("d2", "ACCOUNTS");
const PACK = device("d3", "PACK-01", { siteId: "s2", siteName: "Warehouse" });
const ALL: Device[] = [DB01, ACCT, PACK];

/** Counts as the server gives them: a large Servers group keeps the small-fleet rule from opening everything. */
const TREE: DeviceTreeData = {
  groups: [SERVERS],
  counts: [
    { siteId: "s1", groupId: "g1", total: 150, online: 100 },
    { siteId: "s1", groupId: null, total: 1, online: 1 },
    { siteId: "s2", groupId: null, total: 1, online: 1 },
  ],
};

function devicesFor(r: FakeRequest) {
  const q = r.query;
  return ok({
    items: ALL.filter(
      (d) =>
        (!q.get("groupId") || d.deviceGroupId === q.get("groupId")) &&
        (!q.get("siteId") || d.siteId === q.get("siteId")) &&
        (q.get("ungrouped") !== "true" || !d.deviceGroupId) &&
        (!q.get("q") || d.name.toLowerCase().includes(q.get("q")!.toLowerCase())),
    ),
  });
}

function routes() {
  return {
    ...baseRoutes(ADMIN),
    ...unreportedRoutes(),
    "GET /organizations": ok({ items: ORGS }),
    "GET /sites": ok({ items: SITES }),
    "GET /device-tree": ok(TREE),
    "GET /devices": devicesFor,
    "GET /devices/:id": (r: FakeRequest) => ok(ALL.find((d) => d.id === r.params.id)),
    "GET /scripts": ok({ items: [] }),
    "GET /jobs": ok({ items: [] }),
    "GET /patching": ok({ configured: false }),
    "GET /audit": ok({ items: [] }),
    "GET /remote-access/status": ok({ address: "https://mesh.rmm.example.com", connected: true, lastSyncAt: "2026-11-01T09:59:00Z", devices: 3, devicesOnline: 2 }),
    "GET /sites/:id": ok(SITES[0]),
    "GET /organizations/:id": ok(ORGS[0]),
  };
}

/** Opens a row the way the keyboard does. */
function open(row: HTMLElement) {
  act(() => row.focus());
  fireEvent.keyDown(row, { key: "ArrowRight" });
}

const location = () => screen.getByTestId("location").textContent;

describe("the device tree", () => {
  it("shows the same four levels on every view, groups before a site's own devices", async () => {
    const sections: [string, string][] = [
      ["/organizations", "Organizations"],
      ["/devices", "Devices"],
      ["/alerts", "Alerts"],
      ["/scripts", "Scripts"],
      ["/jobs", "Jobs"],
      ["/patching", "Patching"],
    ];
    for (const [path, title] of sections) {
      installFakeApi(routes());
      const { unmount } = renderApp(path);
      const tree = await screen.findByRole("tree", { name: `${title}: organizations, sites, groups and devices` });
      const head = await within(tree).findByRole("treeitem", { name: /^Head office/ });
      expect(head).toHaveAttribute("aria-level", "2");
      open(head);
      expect(await within(tree).findByRole("treeitem", { name: /^Servers/ })).toHaveAttribute("aria-level", "3");
      expect(within(tree).getByRole("treeitem", { name: "ACCOUNTS, online" })).toHaveAttribute("aria-level", "3");
      unmount();
    }
  });

  it("opens a group only when asked, and loads its devices then", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/devices");
    const tree = await screen.findByRole("tree");
    // Organizations open by default in a large fleet; sites and groups wait.
    const head = await within(tree).findByRole("treeitem", { name: "Head office, 101 of 151 devices online" });
    expect(server.callsTo("GET /devices").filter((c) => c.query.get("groupId") || c.query.get("siteId"))).toHaveLength(0);

    open(head);
    const servers = await within(tree).findByRole("treeitem", { name: "Servers, 100 of 150 devices online" });
    expect(servers).toHaveAttribute("aria-level", "3");
    expect(servers).toHaveAttribute("aria-expanded", "false");
    // The site's own device shows after its groups; the group's devices are not asked for yet.
    expect(await within(tree).findByRole("treeitem", { name: "ACCOUNTS, online" })).toHaveAttribute("aria-level", "3");
    expect(server.callsTo("GET /devices").some((c) => c.query.get("groupId"))).toBe(false);
    expect(server.callsTo("GET /devices").some((c) => c.query.get("siteId") === "s1" && c.query.get("ungrouped") === "true")).toBe(true);

    open(servers);
    const db = await within(tree).findByRole("treeitem", { name: "DB-01, online" });
    expect(db).toHaveAttribute("aria-level", "4");
    expect(server.callsTo("GET /devices").some((c) => c.query.get("groupId") === "g1")).toBe(true);
    // The other site, never opened, has not been asked for.
    expect(server.callsTo("GET /devices").some((c) => c.query.get("siteId") === "s2")).toBe(false);
  });

  it("narrows each view to a group, and to a device, by the address", async () => {
    const user = userEvent.setup();
    const cases: [string, string, string][] = [
      ["/devices", "/devices?organizationId=o1&siteId=s1&groupId=g1", "/devices/d1"],
      ["/alerts", "/alerts?organizationId=o1&siteId=s1&groupId=g1", "/alerts?organizationId=o1&siteId=s1&groupId=g1&deviceId=d1"],
      ["/jobs", "/jobs?organizationId=o1&siteId=s1&groupId=g1", "/jobs?organizationId=o1&siteId=s1&groupId=g1&deviceId=d1"],
      ["/scripts", "/scripts?library=o1&groupId=g1", "/scripts?library=o1&deviceId=d1"],
      ["/organizations", "/sites/s1?groupId=g1", "/devices/d1"],
    ];
    for (const [start, groupHref, deviceHref] of cases) {
      installFakeApi(routes());
      const { unmount } = renderApp(start);
      const tree = await screen.findByRole("tree");
      const head = await within(tree).findByRole("treeitem", { name: /^Head office/ });
      open(head);
      const servers = await within(tree).findByRole("treeitem", { name: /^Servers/ });
      await user.click(servers);
      await waitFor(() => expect(location()).toBe(groupHref));
      await waitFor(() => expect(within(tree).getByRole("treeitem", { name: /^Servers/ })).toHaveAttribute("aria-selected", "true"));
      open(servers);
      await user.click(await within(tree).findByRole("treeitem", { name: "DB-01, online" }));
      await waitFor(() => expect(location()).toBe(deviceHref));
      unmount();
    }
  });

  it("narrows patching to a group and shows the engine's site-wide tabs say so", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...routes(), "GET /patching": ok({ configured: true }), "GET /patching/devices": ok({ devices: [], errors: [], unmatched: [], truncated: false }) });
    renderApp("/patching?tab=devices");
    const tree = await screen.findByRole("tree");
    const head = await within(tree).findByRole("treeitem", { name: /^Head office/ });
    open(head);
    await user.click(await within(tree).findByRole("treeitem", { name: /^Servers/ }));
    await waitFor(() => expect(location()).toBe("/patching?tab=devices&organizationId=o1&siteId=s1&groupId=g1"));
    await waitFor(() => expect(server.callsTo("GET /patching/devices").at(-1)?.query.get("groupId")).toBe("g1"));
  });

  it("searches names on the server and shows the way to each match", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/devices");
    await screen.findByRole("tree");
    await user.type(screen.getByLabelText("Filter the tree"), "db-0");
    // The tree is replaced while nothing matches a half-typed name, so it is looked up again.
    const tree = await screen.findByRole("tree");
    await waitFor(() => expect(server.callsTo("GET /devices").some((c) => c.query.get("q") === "db-0")).toBe(true));
    expect(await within(tree).findByRole("treeitem", { name: "DB-01, online" })).toBeInTheDocument();
    expect(within(tree).getByRole("treeitem", { name: /^Servers/ })).toHaveAttribute("aria-expanded", "true");
    expect(within(tree).queryByRole("treeitem", { name: /^PACK-01/ })).not.toBeInTheDocument();
    expect(screen.getByText("1 match")).toBeInTheDocument();
  });

  it("opens the way to a device selected by its page, groups included", async () => {
    installFakeApi(routes());
    renderApp("/devices/d1");
    const tree = await screen.findByRole("tree");
    const row = await within(tree).findByRole("treeitem", { name: "DB-01, online" });
    expect(row).toHaveAttribute("aria-selected", "true");
    expect(within(tree).getByRole("treeitem", { name: /^Servers/ })).toHaveAttribute("aria-expanded", "true");
  });

  it("renders only the rows on screen once the tree is long", async () => {
    // jsdom does not scroll; let scrollTop hold what it is given.
    const top = new WeakMap<Element, number>();
    Object.defineProperty(HTMLElement.prototype, "scrollTop", { configurable: true, get: function (this: Element) { return top.get(this) ?? 0; }, set: function (this: Element, v: number) { top.set(this, v); } });
    onTestFinished(() => void delete (HTMLElement.prototype as { scrollTop?: number }).scrollTop);
    const orgs = Array.from({ length: 400 }, (_, i) => org(`x${i}`, `Org ${String(i).padStart(3, "0")}`));
    installFakeApi({ ...routes(), "GET /organizations": ok({ items: orgs }), "GET /sites": ok({ items: [] }), "GET /device-tree": ok({ groups: [], counts: [] }) });
    renderApp("/organizations");
    const tree = await screen.findByRole("tree");
    const rendered = within(tree).getAllByRole("treeitem");
    expect(rendered.length).toBeLessThan(60);
    expect(rendered[0]).toHaveAttribute("aria-posinset", "1");
    expect(rendered[0]).toHaveAttribute("aria-setsize", "400");
    // The rest is scrolled to, and the end key reaches the last row.
    act(() => rendered[0]!.focus());
    fireEvent.keyDown(rendered[0]!, { key: "End" });
    const last = await within(tree).findByRole("treeitem", { name: /^Org 399/ });
    await waitFor(() => expect(last).toHaveFocus());
    expect(within(tree).getAllByRole("treeitem").length).toBeLessThan(60);
  });
});
