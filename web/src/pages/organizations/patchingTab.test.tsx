import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView } from "../../test/fakeApi";
import { org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// ADR-0072, S8: an organization's and a site's Patching tab, its permission, and the old URLs.

const CONFIGURER = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "patch.view", "patch.configure"],
});
const VIEWER = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "patch.view"] });
const main = () => ({
  findByRole: async (...a: Parameters<typeof screen.findByRole>) => within(await screen.findByRole("main")).findByRole(...a),
  findByText: async (...a: Parameters<typeof screen.findByText>) => within(await screen.findByRole("main")).findByText(...a),
  getByText: (...a: Parameters<typeof screen.getByText>) => within(screen.getByRole("main")).getByText(...a),
  queryByRole: (...a: Parameters<typeof screen.queryByRole>) => within(screen.getByRole("main")).queryByRole(...a),
});

function routes(session = CONFIGURER, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(session),
    "GET /patching": ok({ configured: true }),
    "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
    "GET /organizations/:id/sites": ok({ items: [] }),
    "GET /sites/:id": ok(site("s1", "o1", "Head office")),
    "GET /sites/:id/device-groups": ok({ items: [] }),
    "GET /patching/scope": ok({ organizationId: "o1", organizationName: "Northwind Traders", siteId: null, siteName: "", devices: 0, byPlatform: [], skipped: [], canManage: false }),
    "GET /patching/policies/:level/:id": fail(409, "easypatch_not_linked", "This organization is not in the patching engine yet."),
    "GET /patching/tags/of/:level/:id": ok({ tags: [], canAssign: false }),
    "GET /patching/organizations/:id/agent-install": ok({ organizationId: "o1", organizationName: "Northwind Traders", autoInstall: false, devices: { linked: 2, unlinked: 1, pending: 0 } }),
    "GET /patching/report-schedules": ok([]),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

describe("the Patching tab", () => {
  it("turns the automatic agent install on and off for the organization", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(CONFIGURER, { "PATCH /settings/easypatch/organizations/:id": noContent }));
    renderApp("/organizations/o1?tab=patching");
    const box = await main().findByRole("checkbox", { name: /Install automatically/ });
    expect(box).not.toBeChecked();
    expect(main().getByText(/2 devices patched/)).toBeInTheDocument();
    expect(main().getByText(/1 not linked/)).toBeInTheDocument();
    await user.click(box);
    await waitFor(() => expect(server.callsTo("PATCH /settings/easypatch/organizations/:id")).toHaveLength(1));
    expect(server.call("PATCH /settings/easypatch/organizations/:id").params.id).toBe("o1");
    expect(server.call("PATCH /settings/easypatch/organizations/:id").body).toEqual({ autoInstall: true });
    expect(await screen.findByText(/EasyRMM installs the EasyPatch agent on devices in this organization that have none/)).toBeInTheDocument();
  });

  it("says when the organization is not in the patching engine yet", async () => {
    installFakeApi(routes(CONFIGURER, { "GET /patching/organizations/:id/agent-install": fail(404, "not_found", "Not found.") }));
    renderApp("/organizations/o1?tab=patching");
    expect(await main().findByText(/being created in the patching engine/)).toBeInTheDocument();
  });

  it("is on the site as well, with only its policy", async () => {
    installFakeApi(routes());
    renderApp("/sites/s1?tab=patching");
    expect(await screen.findByRole("tab", { name: "Patching", selected: true })).toBeInTheDocument();
    expect(await main().findByText("Not in the patching engine yet")).toBeInTheDocument();
    expect(main().queryByRole("checkbox", { name: /Install automatically/ })).not.toBeInTheDocument();
  });

  it("needs patch.configure: someone who may only view patching has no tab", async () => {
    installFakeApi(routes(VIEWER));
    renderApp("/organizations/o1?tab=patching");
    expect(await main().findByRole("heading", { name: "Sites" })).toBeInTheDocument();
    expect(main().queryByRole("tab", { name: "Patching" })).not.toBeInTheDocument();
  });

  it("opens from the old Patch policy address", async () => {
    installFakeApi(routes());
    renderApp("/organizations/o1?tab=patch-policy");
    expect(await screen.findByRole("tab", { name: "Patching", selected: true })).toBeInTheDocument();
  });
});
