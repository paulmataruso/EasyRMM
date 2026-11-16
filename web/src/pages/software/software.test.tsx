import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { SoftwareDevice, SoftwareSummary } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const location = () => screen.getByTestId("location").textContent;

const TECHNICIAN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "software.view"] });

const VERSIONS: SoftwareSummary[] = [
  { name: "openssh-server", version: "1:10.0p1-7", devices: 12 },
  { name: "openssl", version: "3.0.13-0ubuntu3.5", devices: 4 },
  { name: "openssl", version: "3.5.1-1", devices: 1 },
];

const HOLDERS: SoftwareDevice[] = [
  { deviceId: "d1", deviceName: "DB-01", organizationId: "o1", organizationName: "Northwind Traders", siteId: "s1", siteName: "Head office", version: "3.5.1-1", arch: "amd64" },
];

function routes() {
  return {
    ...baseRoutes(TECHNICIAN),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders"), org("o2", "Contoso Dental Group")] }),
    "GET /software": (r: FakeRequest) => {
      const q = (r.query.get("q") ?? "").toLowerCase();
      return ok({ items: VERSIONS.filter((v) => v.name.includes(q)), truncated: false });
    },
    "GET /software/devices": ok({ items: HOLDERS }),
  };
}

describe("software", () => {
  it("searches every device's packages and keeps the search in the URL", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/software");
    const table = await screen.findByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.textContent)).toEqual(["openssh-server1:10.0p1-712 devices", "openssl3.0.13-0ubuntu3.54 devices", "openssl3.5.1-11 device"]);
    expect(screen.getByText("3 package versions")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Package"), "openssl");
    await waitFor(() => expect(location()).toBe("/software?q=openssl"));
    await waitFor(() => expect(within(screen.getByRole("table")).getAllByRole("row")).toHaveLength(3));
    expect(server.callsTo("GET /software").at(-1)?.query.get("q")).toBe("openssl");

    await user.selectOptions(screen.getByLabelText("Organization"), "o2");
    await waitFor(() => expect(server.callsTo("GET /software").at(-1)?.query.get("organizationId")).toBe("o2"));
  });

  it("lists the devices with one version, within the chosen organization", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/software?organizationId=o1");
    const toggle = await screen.findByRole("button", { name: "1 device" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const link = await screen.findByRole("link", { name: "DB-01" });
    expect(link).toHaveAttribute("href", "/devices/d1?tab=software");
    expect(screen.getByText(/Northwind Traders \/ Head office · amd64/)).toBeInTheDocument();
    const call = server.call("GET /software/devices");
    expect([call.query.get("name"), call.query.get("version"), call.query.get("organizationId")]).toEqual(["openssl", "3.5.1-1", "o1"]);
    await user.click(toggle);
    expect(screen.queryByRole("link", { name: "DB-01" })).not.toBeInTheDocument();
  });

  it("says when a search was cut short or found nothing", async () => {
    const server = installFakeApi({ ...routes(), "GET /software": ok({ items: VERSIONS, truncated: true }) });
    const { unmount } = renderApp("/software");
    expect(await screen.findByText("Showing the first 500 package versions. Search by name to narrow the list.")).toBeInTheDocument();
    unmount();

    server.on("GET /software", ok({ items: [], truncated: false }));
    const second = renderApp("/software");
    expect(await screen.findByText("No software reported yet")).toBeInTheDocument();
    second.unmount();

    renderApp("/software?q=nginx");
    expect(await screen.findByText("No packages match")).toBeInTheDocument();
    expect(screen.getByText(/whose name contains “nginx”/)).toBeInTheDocument();
  });

  it("is in the navigation only for people who can see software", async () => {
    installFakeApi({ ...routes(), "GET /dashboard": ok({}) });
    const { unmount } = renderApp("/software");
    const nav = await screen.findByRole("navigation", { name: /main/i });
    expect(within(nav).getByRole("link", { name: "Software" })).toHaveAttribute("href", "/software");
    unmount();

    installFakeApi({ ...routes(), ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["device.view"] })), "GET /software": ok({ items: [], truncated: false }) });
    renderApp("/software");
    const other = await screen.findByRole("navigation", { name: /main/i });
    expect(within(other).queryByRole("link", { name: "Software" })).not.toBeInTheDocument();
  });
});
