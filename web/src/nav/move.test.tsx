import { describe, expect, it } from "vitest";
import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Device, DeviceTreeData, SessionView } from "../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, unreportedRoutes, type FakeHandler, type FakeReply, type FakeRequest } from "../test/fakeApi";
import { device, group, org, site } from "../test/fixtures";
import { renderApp } from "../test/render";
import { consequences, moveKind, widest, type MoveTarget } from "./move";

// Moving devices (ADR-0069): dragging onto the tree, Move to…, and the group menu.

const PERMS = ["org.view", "site.view", "site.manage", "device.view", "device.edit", "alert.view", "script.view", "job.view"] as const;
const ORGS = [org("o1", "Northwind Traders"), org("o2", "Contoso Dental Group")];
const SITES = [site("s1", "o1", "Head office"), site("s2", "o1", "Warehouse"), site("s3", "o2", "Main clinic", { organizationName: "Contoso Dental Group" })];
const SERVERS = { id: "g1", organizationId: "o1", siteId: "s1", name: "Servers", description: "Racks" };
const DESKS = { id: "g2", organizationId: "o1", siteId: "s1", name: "Desks", description: "" };
const DB01 = device("d1", "DB-01", { deviceGroupId: "g1" });
const ACCT = device("d2", "ACCOUNTS");
const PACK = device("d3", "PACK-01", { siteId: "s2", siteName: "Warehouse" });
const ALL: Device[] = [DB01, ACCT, PACK];
const TREE: DeviceTreeData = {
  groups: [SERVERS, DESKS],
  counts: [
    { siteId: "s1", groupId: "g1", total: 1, online: 1 },
    { siteId: "s1", groupId: null, total: 1, online: 1 },
    { siteId: "s2", groupId: null, total: 1, online: 1 },
  ],
};

function routes(extra: Record<string, FakeHandler | FakeReply> = {}, perms: readonly string[] = PERMS): Record<string, FakeHandler | FakeReply> {
  return {
    ...baseRoutes(sessionView({ permissions: [...perms] as SessionView["permissions"] })),
    ...unreportedRoutes(),
    "GET /organizations": ok({ items: ORGS }),
    "GET /sites": ok({ items: SITES }),
    "GET /device-tree": ok(TREE),
    "GET /devices": (r: FakeRequest) =>
      ok({
        items: ALL.filter(
          (d) =>
            (!r.query.get("groupId") || d.deviceGroupId === r.query.get("groupId")) &&
            (!r.query.get("siteId") || d.siteId === r.query.get("siteId")) &&
            (r.query.get("ungrouped") !== "true" || !d.deviceGroupId),
        ),
      }),
    "GET /devices/:id": (r: FakeRequest) => ok(ALL.find((d) => d.id === r.params.id)),
    "GET /sites/:id/device-groups": (r: FakeRequest) => ok({ items: [SERVERS, DESKS].filter((g) => g.siteId === r.params.id).map((g) => group(g.id, g.siteId, g.name)) }),
    "GET /remote-access/status": ok({ address: "https://mesh.rmm.example.com", connected: true, lastSyncAt: "2026-11-01T09:59:00Z", devices: 3, devicesOnline: 2 }),
    "GET /audit": ok({ items: [] }),
    "POST /devices/move": ok({ moved: 1, unchanged: 0, otherOrganization: 0, canceledRuns: 0 }),
    ...extra,
  };
}

/** What jsdom lacks: the data a drag carries. */
function transfer() {
  const data = new Map<string, string>();
  return {
    types: ["application/x-easyrmm-devices", "text/plain"],
    effectAllowed: "",
    dropEffect: "",
    setData: (k: string, v: string) => void data.set(k, v),
    getData: (k: string) => data.get(k) ?? "",
  };
}

function drag(from: HTMLElement, to: HTMLElement) {
  const dataTransfer = transfer();
  fireEvent.dragStart(from, { dataTransfer });
  fireEvent.dragOver(to, { dataTransfer });
  fireEvent.drop(to, { dataTransfer });
  fireEvent.dragEnd(from, { dataTransfer });
}

const opens = (row: HTMLElement) => {
  act(() => row.focus());
  fireEvent.keyDown(row, { key: "ArrowRight" });
};

async function treeAt(path: string) {
  renderApp(path);
  const tree = await screen.findByRole("tree");
  return tree;
}

describe("what a move changes", () => {
  const target = (o: string, s: string, g: string | null): MoveTarget => ({ organizationId: o, organizationName: "Org", siteId: s, siteName: "Site", groupId: g, groupName: g ? "Group" : "" });
  it("says how far a move reaches, and what follows beyond a site", () => {
    expect(moveKind(DB01, target("o1", "s1", "g1"))).toBe("none");
    expect(moveKind(DB01, target("o1", "s1", null))).toBe("group");
    expect(moveKind(DB01, target("o1", "s2", null))).toBe("site");
    expect(moveKind(DB01, target("o2", "s3", null))).toBe("organization");
    expect(widest([DB01, ACCT], target("o1", "s1", "g1"))).toBe("group");
    expect(widest([DB01, PACK], target("o1", "s1", "g1"))).toBe("site");
    expect(widest([], target("o1", "s1", null))).toBe("none");
    expect(consequences([DB01], target("o1", "s1", null))).toEqual([]);
    expect(consequences([PACK], target("o1", "s1", null))).toHaveLength(2);
    const across = consequences([PACK], target("o2", "s3", null)).join(" ");
    expect(across).toMatch(/Queued jobs of the old organization are canceled/);
    expect(across).toMatch(/stay with the old organization/);
  });
});

describe("moving devices from the tree", () => {
  it("moves a dragged device into a group of its site at once", async () => {
    const server = installFakeApi(routes());
    const tree = await treeAt("/devices");
    const row = await within(tree).findByRole("treeitem", { name: "ACCOUNTS, online" });
    expect(row).toHaveAttribute("draggable", "true");
    drag(row, await within(tree).findByRole("treeitem", { name: /^Desks/ }));
    await waitFor(() => expect(server.callsTo("POST /devices/move")).toHaveLength(1));
    expect(server.call("POST /devices/move").body).toEqual({ deviceIds: ["d2"], siteId: "s1", groupId: "g2" });
    expect(await screen.findByText("ACCOUNTS moved to Head office / Desks.")).toBeInTheDocument();
  });

  it("asks before moving to another site, naming what follows, and drops on an organization into the picker", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    const tree = await treeAt("/devices");
    const row = await within(tree).findByRole("treeitem", { name: "ACCOUNTS, online" });
    drag(row, await within(tree).findByRole("treeitem", { name: /^Warehouse/ }));
    const confirm = await screen.findByRole("dialog", { name: "Move ACCOUNTS to Warehouse?" });
    expect(within(confirm).getByText(/Remote access follows its site/)).toBeInTheDocument();
    expect(server.callsTo("POST /devices/move")).toHaveLength(0);
    await user.click(within(confirm).getByRole("button", { name: "Move" }));
    await waitFor(() => expect(server.call("POST /devices/move").body).toEqual({ deviceIds: ["d2"], siteId: "s2", groupId: null }));

    drag(await within(tree).findByRole("treeitem", { name: "PACK-01, online" }), await within(tree).findByRole("treeitem", { name: /^Contoso Dental Group/ }));
    const picker = await screen.findByRole("dialog", { name: "Move PACK-01 to…" });
    expect(within(picker).getByRole("radio", { name: /Main clinic, no group/ })).toBeInTheDocument();
    expect(within(picker).queryByRole("radio", { name: /Warehouse/ })).not.toBeInTheDocument();
  });

  it("does not offer moving without device.edit", async () => {
    installFakeApi(routes({}, ["org.view", "site.view", "device.view"]));
    const tree = await treeAt("/devices");
    const row = await within(tree).findByRole("treeitem", { name: "ACCOUNTS, online" });
    expect(row).not.toHaveAttribute("draggable", "true");
    act(() => row.focus());
    fireEvent.keyDown(row, { key: "F10", shiftKey: true });
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("moves with the keyboard: the row's menu opens the tree as a picker", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    const tree = await treeAt("/devices");
    const row = await within(tree).findByRole("treeitem", { name: "ACCOUNTS, online" });
    act(() => row.focus());
    fireEvent.keyDown(row, { key: "F10", shiftKey: true });
    const menu = await screen.findByRole("menu", { name: "Actions for ACCOUNTS" });
    await user.click(within(menu).getByRole("menuitem", { name: "Move to…" }));
    const dialog = await screen.findByRole("dialog", { name: "Move ACCOUNTS to…" });
    expect(within(dialog).getByRole("button", { name: "Move" })).toBeDisabled();
    await user.click(within(dialog).getByRole("radio", { name: /Head office \/ Desks/ }));
    await user.click(within(dialog).getByRole("button", { name: "Move to Desks" }));
    await waitFor(() => expect(server.call("POST /devices/move").body).toEqual({ deviceIds: ["d2"], siteId: "s1", groupId: "g2" }));
  });

  it("shows what follows in the picker for another organization, and refuses the place a device is in", async () => {
    const user = userEvent.setup();
    installFakeApi(routes());
    renderApp("/devices/d3");
    await screen.findByRole("heading", { name: "PACK-01", level: 1 });
    await user.click(await screen.findByRole("button", { name: "Move to…" }));
    const dialog = await screen.findByRole("dialog", { name: "Move PACK-01 to…" });
    await user.click(await within(dialog).findByRole("radio", { name: /Warehouse, no group/ }));
    expect(within(dialog).getByText(/already there/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: /^Move to/ })).toBeDisabled();
    await user.click(within(dialog).getByRole("radio", { name: /Main clinic, no group/ }));
    expect(within(dialog).getByText(/Queued jobs of the old organization are canceled/)).toBeInTheDocument();
    expect(within(dialog).getByText("Moving to Contoso Dental Group changes who sees this device")).toBeInTheDocument();
  });

  it("shows the server's refusal in the dialog and keeps it open", async () => {
    const user = userEvent.setup();
    installFakeApi(
      routes({ "POST /devices/move": () => ({ status: 409, body: { error: { code: "device_busy", message: "PACK-01 is running a job for its organization. Try again when it finishes." } } }) }),
    );
    renderApp("/devices/d3");
    await user.click(await screen.findByRole("button", { name: "Move to…" }));
    const dialog = await screen.findByRole("dialog", { name: "Move PACK-01 to…" });
    await user.click(await within(dialog).findByRole("radio", { name: /Main clinic, no group/ }));
    await user.click(within(dialog).getByRole("button", { name: /^Move to/ }));
    expect(await within(dialog).findByText(/Try again when it finishes/)).toBeInTheDocument();
  });
});

describe("moving devices from the devices list", () => {
  it("moves the chosen devices together, and drags them together", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/devices");
    const table = await screen.findByRole("table");
    await user.click(await within(table).findByRole("checkbox", { name: "Choose DB-01" }));
    await user.click(within(table).getByRole("checkbox", { name: "Choose ACCOUNTS" }));
    await user.click(screen.getByRole("button", { name: "Move 2 devices to…" }));
    const dialog = await screen.findByRole("dialog", { name: "Move 2 devices to…" });
    await user.click(await within(dialog).findByRole("radio", { name: /Warehouse, no group/ }));
    await user.click(within(dialog).getByRole("button", { name: /^Move to/ }));
    await waitFor(() => expect(server.call("POST /devices/move").body).toEqual({ deviceIds: ["d1", "d2"], siteId: "s2", groupId: null }));

    // Dragging a chosen row takes the others chosen with it.
    const tree = await screen.findByRole("tree");
    await user.click(within(table).getByRole("checkbox", { name: "Choose DB-01" }));
    await user.click(within(table).getByRole("checkbox", { name: "Choose ACCOUNTS" }));
    drag(within(table).getByText("DB-01").closest("tr")!, await within(tree).findByRole("treeitem", { name: /^Desks/ }));
    await waitFor(() => expect(server.callsTo("POST /devices/move")).toHaveLength(2));
    expect(server.call("POST /devices/move", 1).body).toEqual({ deviceIds: ["d1", "d2"], siteId: "s1", groupId: "g2" });
  });

  it("has no choosing without device.edit", async () => {
    installFakeApi(routes({}, ["org.view", "site.view", "device.view"]));
    renderApp("/devices");
    await screen.findByRole("table");
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });
});

describe("the group menu", () => {
  it("creates a group in a site, renames one and deletes one", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes({
        "POST /sites/:id/device-groups": () => ({ status: 201, body: group("g9", "s2", "Docks") }),
        "PUT /device-groups/:id": (r: FakeRequest) => ok(group(r.params.id!, "s1", "Racks")),
        "DELETE /device-groups/:id": { status: 204 },
      }),
    );
    const tree = await treeAt("/devices");
    // A site's menu: New group.
    const warehouse = await within(tree).findByRole("treeitem", { name: /^Warehouse/ });
    act(() => warehouse.focus());
    fireEvent.keyDown(warehouse, { key: "F10", shiftKey: true });
    await user.click(within(await screen.findByRole("menu", { name: "Actions for Warehouse" })).getByRole("menuitem", { name: "New group" }));
    const created = await screen.findByRole("dialog", { name: "New device group" });
    await user.type(within(created).getByLabelText(/Name/), "Docks");
    await user.click(within(created).getByRole("button", { name: "Create device group" }));
    await waitFor(() => expect(server.call("POST /sites/:id/device-groups").body).toEqual({ name: "Docks", description: "" }));

    // A group's menu: Rename and Delete.
    const servers = await within(tree).findByRole("treeitem", { name: /^Servers/ });
    act(() => servers.focus());
    fireEvent.keyDown(servers, { key: "F10", shiftKey: true });
    const menu = await screen.findByRole("menu", { name: "Actions for Servers" });
    expect(within(menu).queryByRole("menuitem", { name: "New group" })).not.toBeInTheDocument();
    await user.click(within(menu).getByRole("menuitem", { name: "Rename" }));
    const renamed = await screen.findByRole("dialog", { name: "Edit device group" });
    expect(within(renamed).getByLabelText(/Name/)).toHaveValue("Servers");
    expect(within(renamed).getByLabelText(/Description/)).toHaveValue("Racks");
    await user.clear(within(renamed).getByLabelText(/Name/));
    await user.type(within(renamed).getByLabelText(/Name/), "Racks");
    await user.click(within(renamed).getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(server.call("PUT /device-groups/:id").body).toEqual({ name: "Racks", description: "Racks" }));

    act(() => servers.focus());
    fireEvent.keyDown(servers, { key: "F10", shiftKey: true });
    await user.click(within(await screen.findByRole("menu")).getByRole("menuitem", { name: "Delete" }));
    const confirm = await screen.findByRole("dialog", { name: "Delete device group" });
    expect(within(confirm).getByText(/stay in the site, in no group/)).toBeInTheDocument();
    await user.click(within(confirm).getByRole("button", { name: "Delete device group" }));
    await waitFor(() => expect(server.callsTo("DELETE /device-groups/:id")).toHaveLength(1));
    expect(server.call("DELETE /device-groups/:id").params.id).toBe("g1");
  });

  it("is offered to those who manage sites only, and closes with Escape", async () => {
    const user = userEvent.setup();
    installFakeApi(routes({}, ["org.view", "site.view", "device.view", "device.edit"]));
    const tree = await treeAt("/devices");
    const head = await within(tree).findByRole("treeitem", { name: /^Head office/ });
    act(() => head.focus());
    fireEvent.keyDown(head, { key: "F10", shiftKey: true });
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();

    const row = await within(tree).findByRole("treeitem", { name: "ACCOUNTS, online" });
    act(() => row.focus());
    fireEvent.keyDown(row, { key: "F10", shiftKey: true });
    expect(await screen.findByRole("menu")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("menu")).not.toBeInTheDocument());
    expect(row).toHaveFocus();
  });
});
