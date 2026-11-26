import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { WindowsModuleSetting } from "../../api/types";
import {
  baseRoutes,
  installFakeApi,
  noContent,
  ok,
  sessionView,
  unreportedRoutes,
} from "../../test/fakeApi";
import { org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// The "Windows modules" card on the organization and site pages (ADR-0073, slice 2).

const NO_PATCH_ALL = {
  "GET /patching/scope": ok({
    organizationId: "o1",
    organizationName: "Northwind Traders",
    siteId: null,
    siteName: "",
    devices: 0,
    byPlatform: [],
    skipped: [],
    canManage: false,
  }),
};

const ADMIN = sessionView({
  isSuperAdmin: false,
  permissions: [
    "org.view",
    "org.manage",
    "site.view",
    "site.manage",
    "device.view",
  ],
});
const VIEWER = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view"],
});

const MODULES: WindowsModuleSetting[] = [
  {
    module: "defender",
    label: "Microsoft Defender",
    enabled: true,
    override: null,
  },
  { module: "dns", label: "DNS", enabled: false, override: false },
];

function routes(
  session: ReturnType<typeof sessionView>,
  extra: Record<string, unknown> = {},
) {
  return {
    ...baseRoutes(session),
    ...unreportedRoutes(),
    ...NO_PATCH_ALL,
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
    "GET /sites/:id": ok(site("s1", "o1", "Head office")),
    "GET /organizations/:id/sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /patching": ok({ configured: false }),
    "GET /audit": ok({ items: [] }),
    "GET /organizations/:id/windows-modules": ok(MODULES),
    "GET /sites/:id/windows-modules": ok([
      { ...MODULES[0], override: true },
      { ...MODULES[1], enabled: true, override: null },
    ]),
    ...extra,
  };
}

describe("the Windows modules card", () => {
  it("lists the modules and turns one off for the organization", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(ADMIN, {
        "PUT /organizations/:id/windows-modules/:module": noContent,
      }),
    );
    renderApp("/organizations/o1?tab=windows-modules");
    const main = within(await screen.findByRole("main"));
    const defender = await main.findByRole("checkbox", {
      name: "Microsoft Defender",
    });
    expect(defender).toBeChecked();
    expect(main.getByRole("checkbox", { name: "DNS" })).not.toBeChecked();
    await user.click(defender);
    const call = server.call("PUT /organizations/:id/windows-modules/:module");
    expect(call.path).toBe("/organizations/o1/windows-modules/defender");
    expect(call.body).toEqual({ enabled: false });
  });

  it("lets a viewer read the toggles but not change them", async () => {
    installFakeApi(routes(VIEWER));
    renderApp("/organizations/o1?tab=windows-modules");
    const main = within(await screen.findByRole("main"));
    expect(
      await main.findByRole("checkbox", { name: "Microsoft Defender" }),
    ).toBeDisabled();
  });

  it("shows a site's own settings and returns one to its organization", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(ADMIN, { "DELETE /sites/:id/windows-modules/:module": noContent }),
    );
    renderApp("/sites/s1?tab=windows-modules");
    const main = within(await screen.findByRole("main"));
    await main.findByRole("checkbox", { name: "Microsoft Defender" });
    expect(main.getByText("Follows the organization")).toBeInTheDocument();
    await user.click(
      main.getByRole("button", { name: "Use the organization's setting" }),
    );
    expect(server.call("DELETE /sites/:id/windows-modules/:module").path).toBe(
      "/sites/s1/windows-modules/defender",
    );
  });
});
