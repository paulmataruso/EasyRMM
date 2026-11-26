import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Permission } from "../../api/types";
import type { AdDomains } from "../devices/modules/directory/types";
import { baseRoutes, installFakeApi, noContent, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// The Active Directory card of the organization page (ADR-0075 section 8): the chosen controller per domain, its
// health, and the pin.

const ctl = (id: string, name: string, over = {}) => ({ deviceId: id, siteId: "s1", name, controller: name, readOnly: false, online: true, pdc: false, health: "healthy" as const, ...over });
const DOMAINS: AdDomains = {
  enabled: true,
  domains: [
    {
      sid: "S-1-5-21-1-2-3", name: "corp.test", pinned: null, chosen: "d2", why: "pdc", lockedOut: 3, replicationFailures: 0, worst: "warning",
      controllers: [ctl("d1", "DC1"), ctl("d2", "DC2", { pdc: true }), ctl("d3", "RODC", { readOnly: true })],
    },
  ],
};

function routes(permissions: Permission[], data: AdDomains) {
  return {
    ...baseRoutes(sessionView({ isSuperAdmin: false, permissions })),
    ...unreportedRoutes(),
    "GET /patching/scope": ok({ organizationId: "o1", organizationName: "N", siteId: null, siteName: "", devices: 0, byPlatform: [], skipped: [], canManage: false }),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
    "GET /organizations/:id/sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /patching": ok({ configured: false }),
    "GET /audit": ok({ items: [] }),
    "GET /organizations/:id/ad/domains": ok(data),
    "PUT /organizations/:id/ad/domains/:sid/preferred": noContent,
  } as Parameters<typeof installFakeApi>[0];
}

describe("the Active Directory card", () => {
  it("shows each domain's chosen controller and health, and lets an administrator pin another", async () => {
    const api = installFakeApi(routes(["org.view", "site.view", "device.view", "ad.view", "ad.manage"], DOMAINS));
    renderApp("/organizations/o1");
    expect(await screen.findByRole("link", { name: "DC2" })).toHaveAttribute("href", "/devices/d2?tab=roles");
    expect(screen.getByText("holds the PDC emulator role")).toBeInTheDocument();
    expect(screen.getByText("Warning")).toBeInTheDocument();
    const pin = screen.getByLabelText("Preferred controller for corp.test");
    expect(screen.queryByRole("option", { name: "RODC" })).toBeNull(); // a read-only controller is never chosen for writes
    await userEvent.selectOptions(pin, "d1");
    expect(api.call("PUT /organizations/:id/ad/domains/:sid/preferred").body).toEqual({ deviceId: "d1" });
  });

  it("gives someone who may only view no pin, and no pin on a read-only controller", async () => {
    installFakeApi(routes(["org.view", "site.view", "device.view", "ad.view"], DOMAINS));
    renderApp("/organizations/o1");
    await screen.findByRole("link", { name: "DC2" });
    expect(screen.queryByLabelText(/Preferred controller/)).toBeNull();
  });

  it("is not shown without ad.view", async () => {
    const api = installFakeApi(routes(["org.view", "site.view", "device.view"], DOMAINS));
    renderApp("/organizations/o1");
    await screen.findByText("Sites");
    expect(screen.queryByText("Active Directory")).toBeNull();
    expect(api.callsTo("GET /organizations/:id/ad/domains")).toHaveLength(0);
  });
});
