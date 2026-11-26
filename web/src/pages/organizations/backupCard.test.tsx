import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import type { BackupFleet, Permission } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// The Windows Backup card on the organization and site pages (ADR-0077, section 4).

const FLEET: BackupFleet = {
  enabled: true,
  counts: { backedUp: 1, stale: 0, failed: 1, overdue: 0, notConfigured: 0, notInstalled: 0, noData: 0 },
  devices: [
    { deviceId: "d1", siteId: "s1", name: "FILE-SRV", state: "ok", lastSuccess: "2026-11-26T09:00:00Z", lastFailure: null, openAlerts: 0 },
    { deviceId: "d2", siteId: "s1", name: "SQL-SRV", state: "failed", lastSuccess: null, lastFailure: "2026-11-26T08:00:00Z", openAlerts: 1 },
  ],
};

function routes(permissions: Permission[], fleet: BackupFleet) {
  return {
    ...baseRoutes(sessionView({ isSuperAdmin: false, permissions })),
    ...unreportedRoutes(),
    "GET /patching/scope": ok({ organizationId: "o1", organizationName: "N", siteId: null, siteName: "", devices: 0, byPlatform: [], skipped: [], canManage: false }),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
    "GET /sites/:id": ok(site("s1", "o1", "Head office")),
    "GET /organizations/:id/sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /patching": ok({ configured: false }),
    "GET /audit": ok({ items: [] }),
    "GET /organizations/:id/backup": ok(fleet),
    "GET /sites/:id/backup": ok(fleet),
  } as Parameters<typeof installFakeApi>[0];
}

describe("the Backup card", () => {
  it("shows counts and the servers, and links each to its Backup tab", async () => {
    installFakeApi(routes(["org.view", "site.view", "device.view", "backup.view"], FLEET));
    renderApp("/organizations/o1");
    expect(await screen.findByText("FILE-SRV")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "SQL-SRV" })).toHaveAttribute("href", "/devices/d2?tab=backup");
    expect(screen.getByText("Windows Backup")).toBeInTheDocument();
    expect(screen.getAllByText("Failed").length).toBe(2);
  });

  it("is not shown without backup.view, nor when the module is off", async () => {
    const api = installFakeApi(routes(["org.view", "site.view", "device.view"], FLEET));
    renderApp("/organizations/o1");
    await screen.findByText("Sites");
    expect(screen.queryByText("Windows Backup")).toBeNull();
    expect(api.callsTo("GET /organizations/:id/backup")).toHaveLength(0);
  });

  it("says nothing where the module is off", async () => {
    installFakeApi(routes(["org.view", "site.view", "device.view", "backup.view"], { ...FLEET, enabled: false, devices: [] }));
    renderApp("/organizations/o1");
    await screen.findByText("Sites");
    expect(screen.queryByText("Windows Backup")).toBeNull();
  });
});
