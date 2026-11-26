import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import { baseRoutes, installFakeApi, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// The Security card on the Overview and the Security tab of an organization and a site (ADR-0074 section 6): read from
// what is stored, never a job.

const FLEET = {
  items: [
    { deviceId: "d1", name: "DC01", siteId: "s1", siteName: "Head office", runningMode: "Normal", realTimeProtection: true, tamperProtected: true, signatureAgeDays: 0, quickScanAgeDays: 1, readAt: "2026-11-26T10:00:00Z", openAlerts: 0, threats30Days: 0 },
    { deviceId: "d2", name: "PC02", siteId: "s1", siteName: "Head office", runningMode: "Normal", realTimeProtection: false, tamperProtected: false, signatureAgeDays: 5, quickScanAgeDays: null, readAt: "2026-11-26T10:00:00Z", openAlerts: 2, threats30Days: 3 },
  ],
  protected: 1,
  notProtected: 1,
  signaturesOld: 1,
  threats30Days: 3,
  unknown: 0,
};
const VIEWER = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "defender.view", "monitoring.view"] });
const NO_DEFENDER = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });

function routes(session: ReturnType<typeof sessionView>, fleet: unknown = FLEET) {
  return {
    ...baseRoutes(session),
    ...unreportedRoutes(),
    "GET /patching/scope": ok({ organizationId: "o1", organizationName: "Northwind Traders", siteId: null, siteName: "", devices: 0, byPlatform: [], skipped: [], canManage: false }),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
    "GET /sites/:id": ok(site("s1", "o1", "Head office")),
    "GET /organizations/:id/sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /patching": ok({ configured: false }),
    "GET /audit": ok({ items: [] }),
    "GET /organizations/:id/defender/fleet": ok(fleet),
    "GET /sites/:id/defender/fleet": ok(fleet),
  } as Parameters<typeof installFakeApi>[0];
}

describe("the Security card and tab", () => {
  it("counts what is stored on the organization's Overview and links to the tab", async () => {
    const api = installFakeApi(routes(VIEWER));
    renderApp("/organizations/o1");
    const card = within(await screen.findByRole("heading", { name: "Security" }).then((h) => h.closest("section, div")!.parentElement!));
    expect(await card.findByText("Threats in 30 days")).toBeInTheDocument();
    expect(card.getByRole("link", { name: "Details" })).toHaveAttribute("href", "/organizations/o1?tab=security");
    expect(api.callsTo("GET /organizations/:id/defender/fleet")).toHaveLength(1);
    expect(api.callsTo("POST /devices/:id/winmod/:action")).toHaveLength(0);
  });

  it("lists the computers in the tab with their state, signature age and alerts", async () => {
    installFakeApi(routes(VIEWER));
    renderApp("/organizations/o1?tab=security");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByRole("link", { name: "DC01" })).toHaveAttribute("href", "/devices/d1?tab=security");
    expect(main.getByText("Protected")).toBeInTheDocument();
    expect(main.getByText("Real-time protection off")).toBeInTheDocument();
    expect(main.getByText("5 days ago")).toBeInTheDocument();
    expect(main.getByText("Never")).toBeInTheDocument();
    expect(main.getAllByText("Head office", { selector: "td" })).toHaveLength(2);
  });

  it("shows the site's tab without a Site column", async () => {
    installFakeApi(routes(VIEWER));
    renderApp("/sites/s1?tab=security");
    const main = within(await screen.findByRole("main"));
    await main.findByRole("link", { name: "PC02" });
    expect(main.queryByRole("columnheader", { name: "Site" })).toBeNull();
  });

  it("has no card and no tab without defender.view, and no card where no computer has Defender", async () => {
    installFakeApi(routes(NO_DEFENDER));
    renderApp("/organizations/o1");
    await screen.findByRole("tab", { name: "Overview" });
    expect(screen.queryByRole("tab", { name: "Security" })).toBeNull();
    expect(screen.queryByRole("heading", { name: "Security" })).toBeNull();
  });

  it("shows no card when the module is off or nothing reports Defender", async () => {
    installFakeApi(routes(VIEWER, { ...FLEET, items: [], protected: 0, notProtected: 0, signaturesOld: 0, threats30Days: 0 }));
    renderApp("/organizations/o1");
    await screen.findByRole("tab", { name: "Security" });
    expect(screen.queryByRole("heading", { name: "Security" })).toBeNull();
  });
});
