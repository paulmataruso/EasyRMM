import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import { baseRoutes, installFakeApi, ok, sessionView } from "../test/fakeApi";
import { renderApp } from "../test/render";
import { easyPatchHref } from "../pages/patching/patchText";
import { switchTarget } from "./productSwitch";

describe("the EasyPatch page for the page someone is on", () => {
  it.each([
    ["/devices/d1", "", "/go/to-easypatch?device=d1"],
    ["/devices/d1", "?tab=patches", "/go/to-easypatch?device=d1&tab=updates"],
    ["/devices/d1", "?tab=patches&patches=installed", "/go/to-easypatch?device=d1&tab=installed"],
    ["/devices/d1", "?tab=patches&patches=history", "/go/to-easypatch?device=d1&tab=history"],
    ["/devices/d1", "?tab=patches&patches=jobs", "/go/to-easypatch?device=d1&tab=jobs"],
    // Other tabs of the device open its overview.
    ["/devices/d1", "?tab=software&patches=jobs", "/go/to-easypatch?device=d1"],
    ["/devices/d1", "?tab=patches&patches=nonsense", "/go/to-easypatch?device=d1"],
    ["/devices", "", "/go/to-easypatch?list=endpoints"],
    ["/devices/approvals", "", "/go/to-easypatch?list=endpoints"],
    ["/devices/add", "", "/go/to-easypatch?list=endpoints"],
    ["/organizations/o1", "?tab=sites", "/go/to-easypatch?organization=o1"],
    ["/organizations", "", "/go/to-easypatch"],
    ["/sites/s1", "", "/go/to-easypatch?site=s1"],
    ["/patching", "", "/go/to-easypatch?list=endpoints"],
    ["/patching", "?tab=jobs", "/go/to-easypatch?list=jobs"],
    ["/patching", "?tab=jobs&active=false&job=j1", "/go/to-easypatch?job=j1"],
    ["/", "", "/go/to-easypatch"],
    ["/scripts/x", "", "/go/to-easypatch"],
    ["/settings", "?tab=easypatch", "/go/to-easypatch"],
  ])("%s%s", (path, search, href) => {
    expect(easyPatchHref(switchTarget(path, search))).toBe(href);
  });
});

describe("the product switch", () => {
  const products = () => within(screen.getByRole("navigation", { name: "Products" }));

  it("is hidden until EasyPatch is set up for the person", async () => {
    installFakeApi(baseRoutes(sessionView()));
    renderApp("/nowhere");
    await screen.findByRole("main");
    expect(screen.queryByRole("navigation", { name: "Products" })).not.toBeInTheDocument();
  });

  it("says which product this is and opens EasyPatch in the same tab", async () => {
    installFakeApi({ ...baseRoutes(sessionView()), "GET /patching/switch": ok({ show: true, answering: true }) });
    renderApp("/nowhere");
    await screen.findByRole("navigation", { name: "Products" });
    expect(products().getByRole("link", { name: "EasyRMM" })).toHaveAttribute("aria-current", "true");
    const link = products().getByRole("link", { name: "Open EasyPatch" });
    expect(link).toHaveAttribute("href", "/go/to-easypatch");
    expect(link).toHaveTextContent("EasyPatch");
    expect(link).not.toHaveAttribute("target");
    expect(link).not.toHaveAttribute("aria-current");
  });

  it("warns when EasyPatch was not answering, and still links to it", async () => {
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /patching/switch": ok({ show: true, answering: false, failingSince: new Date(Date.now() - 5 * 60_000).toISOString() }),
    });
    renderApp("/nowhere");
    await screen.findByRole("navigation", { name: "Products" });
    const link = products().getByRole("link", { name: /^Open EasyPatch\. EasyPatch was not answering 5 minutes ago; it may have recovered\.$/ });
    expect(link).toHaveAttribute("href", "/go/to-easypatch");
    expect(link.getAttribute("title")).toMatch(/not answering/);
  });
});
