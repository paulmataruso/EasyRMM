import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { baseRoutes, fail, installFakeApi, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { device, org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const location = () => screen.getByTestId("location").textContent;

const DEVICES = [
  device("d1", "FRONT-DESK"),
  device("d2", "back-office", { remoteOnline: false, siteId: "s2", siteName: "Warehouse", hostname: "bo-01.northwind.local" }),
  device("d3", "LAB-07", { organizationId: "o2", organizationName: "Contoso Dental Group", siteId: "s3", siteName: "Clinic" }),
];

const VIEWER = sessionView({ permissions: [...sessionView().permissions, "device.view"] });

function routes(extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(VIEWER),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders"), org("o2", "Contoso Dental Group"), org("o3", "Fabrikam")] }),
    "GET /sites": ok({
      items: [site("s1", "o1", "Head office"), site("s2", "o1", "Warehouse"), site("s3", "o2", "Clinic", { organizationName: "Contoso Dental Group" })],
    }),
    "GET /devices": (r: FakeRequest) =>
      ok({
        items: DEVICES.filter(
          (d) => (!r.query.get("organizationId") || d.organizationId === r.query.get("organizationId")) && (!r.query.get("siteId") || d.siteId === r.query.get("siteId")),
        ),
      }),
    "GET /devices/:id": (r: FakeRequest) => ok(DEVICES.find((d) => d.id === r.params.id)),
    "GET /audit": ok({ items: [] }),
    "GET /remote-access/status": ok({ address: "", connected: true, lastSyncAt: null, devices: 0, devicesOnline: 0 }),
    ...extra,
  };
}

const tree = () => screen.getByRole("tree", { name: "Organizations, sites and devices" });
const item = (name: RegExp | string) => within(tree()).getByRole("treeitem", { name });

describe("device tree", () => {
  it("docks beside the devices list, lists every organization, site and device, and filters the list", async () => {
    const user = userEvent.setup();
    installFakeApi(routes());
    renderApp("/devices");
    const toggle = await screen.findByRole("button", { name: "Tree" });
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    expect(screen.queryByRole("complementary", { name: "Device tree" })).not.toBeInTheDocument();

    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-pressed", "true");
    const dock = screen.getByRole("complementary", { name: "Device tree" });
    await within(dock).findByRole("tree");
    expect(within(dock).getByText("3 organizations, 3 devices, 2 online")).toBeInTheDocument();
    // A small fleet opens fully: organizations (including one without sites), sites and devices.
    expect(within(tree()).getAllByRole("treeitem").map((e) => e.getAttribute("aria-level") + " " + e.textContent?.split(",")[0])).toEqual([
      "1 Contoso Dental Group1/1",
      "2 Clinic1/1",
      "3 LAB-07",
      "1 Fabrikam0",
      "1 Northwind Traders1/2",
      "2 Head office1/1",
      "3 FRONT-DESK",
      "2 Warehouse0/1",
      "3 back-office",
    ]);
    expect(item(/^Northwind Traders/)).toHaveAccessibleName("Northwind Traders, 1 of 2 devices online");
    expect(item(/^back-office/)).toHaveAccessibleName("back-office, offline");
    expect(within(dock).getByRole("button", { name: /All devices/ })).toHaveAttribute("aria-current", "page");

    // A site narrows the list, keeping its other filters; the tree marks where the list is.
    await user.click(item(/^Warehouse/));
    expect(location()).toBe("/devices?organizationId=o1&siteId=s2");
    await waitFor(() => expect(screen.queryByRole("link", { name: "FRONT-DESK" })).not.toBeInTheDocument());
    expect(item(/^Warehouse/)).toHaveAttribute("aria-selected", "true");
    await user.click(item(/^Contoso/));
    expect(location()).toBe("/devices?organizationId=o2");
    await user.click(within(dock).getByRole("button", { name: /All devices/ }));
    expect(location()).toBe("/devices");

    // The choice is remembered in this browser.
    expect(window.localStorage.getItem("easyrmm.deviceTree")).toBe("open");
    await user.click(within(dock).getByRole("button", { name: "Close the device tree" }));
    expect(screen.queryByRole("complementary", { name: "Device tree" })).not.toBeInTheDocument();
    expect(window.localStorage.getItem("easyrmm.deviceTree")).toBeNull();
    expect(toggle).toHaveFocus();
  });

  it("stays open while moving to a device and marks it", async () => {
    const user = userEvent.setup();
    window.localStorage.setItem("easyrmm.deviceTree", "open");
    installFakeApi(routes());
    renderApp("/devices");
    await user.click(await within(await screen.findByRole("complementary", { name: "Device tree" })).findByRole("treeitem", { name: /^back-office/ }));
    expect(location()).toBe("/devices/d2");
    expect(await screen.findByRole("heading", { name: "back-office" })).toBeInTheDocument();
    expect(item(/^back-office/)).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("button", { name: "Tree" })).toHaveAttribute("aria-pressed", "true");
    // Not on other pages.
    await user.click(screen.getByRole("link", { name: "Organizations" }));
    expect(screen.queryByRole("complementary", { name: "Device tree" })).not.toBeInTheDocument();
  });

  it("moves through the tree with the keyboard", async () => {
    const user = userEvent.setup();
    window.localStorage.setItem("easyrmm.deviceTree", "open");
    installFakeApi(routes());
    renderApp("/devices/d1");
    await screen.findByRole("tree");
    // The page's device is the tree's entry point.
    const front = item(/^FRONT-DESK/);
    expect(front).toHaveAttribute("tabindex", "0");
    front.focus();
    await user.keyboard("{ArrowLeft}");
    expect(item(/^Head office/)).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(item(/^Head office/)).toHaveAttribute("aria-expanded", "false");
    expect(within(tree()).queryByRole("treeitem", { name: /^FRONT-DESK/ })).not.toBeInTheDocument();
    await user.keyboard("{ArrowRight}");
    expect(item(/^Head office/)).toHaveAttribute("aria-expanded", "true");
    await user.keyboard("{ArrowRight}");
    expect(item(/^FRONT-DESK/)).toHaveFocus();
    await user.keyboard("{ArrowDown}");
    expect(item(/^Warehouse/)).toHaveFocus();
    await user.keyboard("{Home}");
    expect(item(/^Contoso/)).toHaveFocus();
    await user.keyboard("{End}");
    expect(item(/^back-office/)).toHaveFocus();
    await user.keyboard("{ArrowUp}{Enter}");
    expect(location()).toBe("/devices?organizationId=o1&siteId=s2");

    // Collapse all leaves the organizations.
    await user.click(screen.getByRole("button", { name: "Collapse all" }));
    expect(within(tree()).getAllByRole("treeitem")).toHaveLength(3);
    expect(screen.getByRole("button", { name: "Collapse all" })).toBeDisabled();
  });

  it("filters by name or hostname", async () => {
    const user = userEvent.setup();
    window.localStorage.setItem("easyrmm.deviceTree", "open");
    installFakeApi(routes());
    renderApp("/devices");
    await screen.findByRole("tree");
    const filter = screen.getByRole("searchbox", { name: "Filter the tree" });
    await user.type(filter, "bo-01");
    expect(screen.getByText("1 match")).toBeInTheDocument();
    expect(within(tree()).getAllByRole("treeitem").map((e) => e.textContent?.split(",")[0])).toEqual(["Northwind Traders1/2", "Warehouse0/1", "back-office"]);
    expect(screen.queryByRole("button", { name: /All devices/ })).not.toBeInTheDocument();
    // Down from the filter enters the tree.
    await user.keyboard("{ArrowDown}");
    expect(item(/^Northwind/)).toHaveFocus();

    await user.clear(filter);
    await user.type(filter, "zzz");
    expect(screen.getByText("Nothing matches “zzz”.")).toBeInTheDocument();
  });

  it("opens over the page on narrow screens and closes after a choice", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("matchMedia", (query: string) => ({ matches: false, media: query, addEventListener: () => {}, removeEventListener: () => {} }));
    installFakeApi(routes());
    renderApp("/devices");
    await user.click(await screen.findByRole("button", { name: "Tree" }));
    const dock = screen.getByRole("complementary", { name: "Device tree" });
    await within(dock).findByRole("tree");
    expect(within(dock).getByRole("searchbox")).toHaveFocus();
    // Not remembered: on a phone it is a way to get somewhere, not a layout.
    expect(window.localStorage.getItem("easyrmm.deviceTree")).toBeNull();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("complementary", { name: "Device tree" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Tree" }));
    await user.click(await screen.findByRole("treeitem", { name: /^LAB-07/ }));
    expect(location()).toBe("/devices/d3");
    await waitFor(() => expect(screen.queryByRole("complementary", { name: "Device tree" })).not.toBeInTheDocument());
  });

  it("says when the tree cannot load", async () => {
    window.localStorage.setItem("easyrmm.deviceTree", "open");
    installFakeApi(routes({ "GET /sites": fail(500, "internal", "Something went wrong.") }));
    renderApp("/devices");
    const dock = await screen.findByRole("complementary", { name: "Device tree" });
    expect(await within(dock).findByText("Could not load this data")).toBeInTheDocument();
    expect(within(dock).getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("is not offered to people who cannot view devices", async () => {
    window.localStorage.setItem("easyrmm.deviceTree", "open");
    installFakeApi({ ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view"] })), "GET /organizations": ok({ items: [] }) });
    renderApp("/organizations");
    await screen.findByRole("heading", { name: "Organizations" });
    expect(screen.queryByRole("complementary", { name: "Device tree" })).not.toBeInTheDocument();
  });
});
