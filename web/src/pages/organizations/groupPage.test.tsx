import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DeviceGroupDetail } from "../../api/types";
import {
  baseRoutes,
  fail,
  installFakeApi,
  noContent,
  ok,
  sessionView,
  unreportedRoutes,
  type FakeReply,
  type FakeRequest,
} from "../../test/fakeApi";
import { device, org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// The group's own page (ADR-0072): Overview, and Settings with group-wide verbose agent logging.

const ADMIN = sessionView({
  permissions: [
    "org.view",
    "site.view",
    "site.manage",
    "device.view",
    "device.edit",
    "alert.view",
    "script.view",
    "job.view",
    "patch.view",
    "user.view",
    "audit.view",
  ],
});
const GROUP: DeviceGroupDetail = {
  id: "g1",
  organizationId: "o1",
  organizationName: "Northwind Traders",
  siteId: "s1",
  siteName: "Head office",
  name: "Servers",
  description: "Rack machines",
  deviceCount: 1,
  verboseUntil: null,
  canManage: true,
  canEditDevices: true,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
};

function routes(group: () => FakeReply, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(ADMIN),
    ...unreportedRoutes(),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /device-tree": ok({
      groups: [
        {
          id: "g1",
          organizationId: "o1",
          siteId: "s1",
          name: "Servers",
          description: "",
        },
      ],
      counts: [],
    }),
    "GET /device-groups/:id": group,
    "GET /devices": ok({
      items: [device("d1", "DB-01", { deviceGroupId: "g1", online: true })],
    }),
    "GET /sites/:id": ok(site("s1", "o1", "Head office")),
    "GET /sites/:id/device-groups": ok({ items: [GROUP] }),
    "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
    "GET /patching": ok({ configured: false }),
    "GET /audit": ok({ items: [] }),
    ...extra,
  };
}

describe("the group page", () => {
  it("shows the group, its devices and the Organizations tree, with Overview and Settings", async () => {
    installFakeApi(routes(() => ok(GROUP)));
    renderApp("/groups/g1");
    expect(await screen.findByRole("heading", { name: "Servers", level: 1 })).toBeInTheDocument();
    expect(screen.getByText("Rack machines")).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "DB-01" })).toHaveAttribute("href", "/devices/d1");
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "Settings" })).toBeInTheDocument();
    // The Organizations section's tree, with this group selected.
    const tree = await screen.findByRole("tree");
    await waitFor(() => expect(within(tree).getByRole("treeitem", { name: /^Servers/ })).toHaveAttribute("aria-selected", "true"));
    expect(screen.getAllByRole("link", { name: "Head office" }).some((a) => a.getAttribute("href") === "/sites/s1")).toBe(true);
  });

  it("hides Settings without device.edit, and shows no rename or delete without site.manage", async () => {
    installFakeApi(routes(() => ok({ ...GROUP, canEditDevices: false, canManage: false })));
    renderApp("/groups/g1?tab=settings");
    expect(await screen.findByRole("heading", { name: "Servers", level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Settings" })).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByRole("button", { name: "Rename" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
  });

  it("says so when the group cannot be seen", async () => {
    installFakeApi(routes(() => fail(404, "not_found", "Not found.")));
    renderApp("/groups/g9");
    expect((await screen.findAllByText(/not found/i)).length).toBeGreaterThan(0);
  });

  it("renames the group and deletes it, returning to its site", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(() => ok(GROUP), {
        "PUT /device-groups/:id": (r: FakeRequest) => ok({ ...GROUP, ...(r.body as object) }),
        "DELETE /device-groups/:id": noContent,
      }),
    );
    renderApp("/groups/g1");
    await user.click(await screen.findByRole("button", { name: "Rename" }));
    const dialog = await screen.findByRole("dialog");
    await user.clear(within(dialog).getByLabelText(/^Name/));
    await user.type(within(dialog).getByLabelText(/^Name/), "Racks");
    await user.click(within(dialog).getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(server.call("PUT /device-groups/:id").body).toEqual({
        name: "Racks",
        description: "Rack machines",
      }),
    );

    await user.click(screen.getByRole("button", { name: "Delete" }));
    await user.click(await screen.findByRole("button", { name: "Delete device group" }));
    await waitFor(() => expect(server.callsTo("DELETE /device-groups/:id")).toHaveLength(1));
    expect(server.call("DELETE /device-groups/:id").params.id).toBe("g1");
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/sites/s1"));
  });

  it("turns group-wide verbose logging on and off in Settings", async () => {
    const user = userEvent.setup();
    let until: string | null = null;
    const server = installFakeApi(
      routes(() => ok({ ...GROUP, verboseUntil: until }), {
        "PUT /device-groups/:id/agent-logs/verbose": () => {
          until = new Date(Date.now() + 4 * 3600_000).toISOString();
          return ok({ until });
        },
        "DELETE /device-groups/:id/agent-logs/verbose": () => {
          until = null;
          return noContent;
        },
      }),
    );
    renderApp("/groups/g1?tab=settings");
    const hours = await screen.findByLabelText("For");
    expect(hours).toHaveValue("2");
    await user.selectOptions(hours, "4");
    await user.click(screen.getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(server.call("PUT /device-groups/:id/agent-logs/verbose").body).toEqual({ hours: 4 }));
    expect(server.call("PUT /device-groups/:id/agent-logs/verbose").params.id).toBe("g1");
    expect(await screen.findByText("Verbose logging is on")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Turn off" }));
    await waitFor(() => expect(server.callsTo("DELETE /device-groups/:id/agent-logs/verbose")).toHaveLength(1));
    await waitFor(() => expect(screen.queryByText("Verbose logging is on")).not.toBeInTheDocument());
  });

  it("opens the group page from the site's group row and from the old ?groupId= link", async () => {
    const user = userEvent.setup();
    installFakeApi(routes(() => ok(GROUP)));
    const { unmount } = renderApp("/sites/s1");
    await user.click(await screen.findByRole("link", { name: "Servers" }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/groups/g1"));
    unmount();
    installFakeApi(routes(() => ok(GROUP)));
    renderApp("/sites/s1?groupId=g1");
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/groups/g1"));
    expect(await screen.findByRole("heading", { name: "Servers", level: 1 })).toBeInTheDocument();
  });
});
