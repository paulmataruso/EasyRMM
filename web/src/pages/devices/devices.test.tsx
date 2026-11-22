import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { RemoteAccessStatus } from "../../api/types";
import { baseRoutes, unreportedRoutes, fail, installFakeApi, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { auditEntry, device, org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { remoteAccessState } from "./DeviceDetailPage";

const location = () => screen.getByTestId("location").textContent;

const DEVICES = [
  device("d1", "FRONT-DESK"),
  device("d2", "back-office", { remoteOnline: false, lastSeenAt: "2026-10-30T08:00:00Z", siteId: "s2", siteName: "Warehouse", hostname: "bo-01.northwind.local" }),
  device("d3", "LAB-07", { organizationId: "o2", organizationName: "Contoso Dental Group", platform: "linux", osDescription: "" }),
];

const STATUS: RemoteAccessStatus = { address: "https://mesh.rmm.example.com", connected: true, lastSyncAt: "2026-11-01T09:59:00Z", devices: 3, devicesOnline: 2 };

const TECHNICIAN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "device.remote_desktop", "device.terminal", "device.files"],
});

const lists = {
  "GET /organizations": ok({ items: [org("o1", "Northwind Traders"), org("o2", "Contoso Dental Group")] }),
  "GET /sites": (r: FakeRequest) =>
    ok({
      items: [site("s1", "o1", "Head office"), site("s2", "o1", "Warehouse"), site("s3", "o2", "Clinic", { organizationName: "Contoso Dental Group" })].filter(
        (s) => !r.query.get("organizationId") || s.organizationId === r.query.get("organizationId"),
      ),
    }),
};

/** Answers /devices the way the server filters. */
function deviceList(r: FakeRequest) {
  const q = (r.query.get("q") ?? "").toLowerCase();
  const status = r.query.get("status");
  return ok({
    items: DEVICES.filter(
      (d) =>
        (!q || d.name.toLowerCase().includes(q) || d.hostname.includes(q)) &&
        (!status || d.online === (status === "online")) &&
        (!r.query.get("organizationId") || d.organizationId === r.query.get("organizationId")) &&
        (!r.query.get("siteId") || d.siteId === r.query.get("siteId")),
    ),
  });
}

/** Answers a session launch the way the server does. */
const launch = (r: FakeRequest) => {
  const kind = (r.body as { kind: string }).kind;
  return { status: 201, body: { grantId: `g-${kind}`, url: `https://mesh.rmm.example.com/.easyrmm/launch?t=${kind}-token`, expiresAt: "2030-01-01T00:00:00Z", kind, deviceId: r.params.id } };
};

describe("devices", () => {
  it("lists devices and filters them on the server, keeping filters in the URL", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      ...lists,
      "GET /devices": deviceList,
      "GET /devices/:id": (r) => ok(DEVICES.find((d) => d.id === r.params.id)),
      "GET /remote-access/status": ok(STATUS),
    });
    renderApp("/devices");
    expect(await screen.findByRole("link", { name: "FRONT-DESK" })).toBeInTheDocument();
    expect(screen.getByText("3 devices, 2 online")).toBeInTheDocument();
    const offline = screen.getByRole("row", { name: /back-office/ });
    expect(within(offline).getByText("Offline")).toBeInTheDocument();
    expect(within(offline).getByText("bo-01.northwind.local")).toBeInTheDocument();
    // A hostname that only repeats the name is not shown twice.
    expect(within(screen.getByRole("row", { name: /FRONT-DESK/ })).queryByText("front-desk")).not.toBeInTheDocument();
    // An empty OS description falls back to the platform.
    expect(within(screen.getByRole("row", { name: /LAB-07/ })).getByText("Linux")).toBeInTheDocument();
    // Connected: no warning.
    expect(screen.queryByText("Remote access is unavailable")).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Status"), "online");
    await waitFor(() => expect(screen.queryByRole("link", { name: "back-office" })).not.toBeInTheDocument());
    expect(location()).toBe("/devices?status=online");
    expect(server.callsTo("GET /devices").at(-1)?.query.get("status")).toBe("online");

    await user.selectOptions(screen.getByLabelText("Organization"), "o2");
    await waitFor(() => expect(screen.queryByRole("link", { name: "FRONT-DESK" })).not.toBeInTheDocument());
    expect(screen.getByRole("link", { name: "LAB-07" })).toBeInTheDocument();
    // The site list narrows to the chosen organization.
    await waitFor(() => expect(within(screen.getByLabelText("Site")).getAllByRole("option").map((o) => o.textContent)).toEqual(["All sites", "Clinic"]));

    await user.type(screen.getByLabelText("Search"), "zzz");
    expect(await screen.findByText("No devices match these filters")).toBeInTheDocument();
    expect(location()).toBe("/devices?status=online&organizationId=o2&q=zzz");
  });

  it("opens a device with j and Enter", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      ...lists,
      "GET /devices": deviceList,
      "GET /devices/:id": (r) => ok(DEVICES.find((d) => d.id === r.params.id)),
    });
    renderApp("/devices");
    await screen.findByRole("link", { name: "FRONT-DESK" });
    await user.keyboard("jj");
    expect(screen.getByRole("link", { name: "back-office" })).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(await screen.findByRole("heading", { name: "back-office" })).toBeInTheDocument();
    expect(location()).toBe("/devices/d2");
  });

  it("says plainly how devices arrive when there are none", async () => {
    installFakeApi({ ...baseRoutes(TECHNICIAN), ...lists, "GET /devices": ok({ items: [] }) });
    const { unmount } = renderApp("/devices");
    expect(await screen.findByText("No devices yet")).toBeInTheDocument();
    expect(screen.getByText(/Ask an administrator who manages enrollment/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Add devices" })).not.toBeInTheDocument();
    unmount();

    // Someone who manages enrollment is sent to the deployment page.
    const admin = sessionView({ permissions: [...sessionView().permissions, "enrollment.manage"] });
    installFakeApi({ ...baseRoutes(admin), ...lists, "GET /devices": ok({ items: [] }), "GET /remote-access/status": ok(STATUS) });
    const second = renderApp("/devices");
    expect(await screen.findByText(/Install the EasyRMM agent on a computer with a deployment token/)).toBeInTheDocument();
    const links = screen.getAllByRole("link", { name: "Add devices" });
    expect(links).toHaveLength(2);
    for (const link of links) expect(link).toHaveAttribute("href", "/devices/add");
    second.unmount();

    // With a site filter, the site carries over.
    installFakeApi({ ...baseRoutes(admin), ...lists, "GET /devices": ok({ items: [] }), "GET /remote-access/status": ok(STATUS) });
    renderApp("/devices?siteId=s2");
    expect(await screen.findByText("No devices match these filters")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Add devices" })).toHaveAttribute("href", "/devices/add?siteId=s2");
  });

  it("warns administrators when MeshCentral cannot be reached", async () => {
    installFakeApi({
      ...baseRoutes(sessionView()),
      ...lists,
      "GET /devices": ok({ items: [] }),
      "GET /remote-access/status": ok({ ...STATUS, connected: false }),
    });
    renderApp("/devices");
    expect(await screen.findByText("Remote access is unavailable")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "View details" })).toHaveAttribute("href", "/settings?tab=remote");
  });

  it("lists enrolled devices on a server with remote access turned off", async () => {
    const enrolled = device("d9", "BUILD-01", {
      platform: "linux",
      remoteAgent: false,
      remoteOnline: false,
      online: true,
      canDesktop: false,
      canTerminal: false,
      canFiles: false,
      agent: { version: "1.4.0", arch: "arm64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null },
    });
    // No /remote-access/status route: an administrator's page must not ask for it when the feature is off.
    installFakeApi({
      ...baseRoutes(sessionView({ features: { remoteAccess: false } })),
      ...unreportedRoutes(),
      ...lists,
      "GET /devices": ok({ items: [enrolled] }),
      "GET /devices/:id": ok(enrolled),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/devices");
    const row = await screen.findByRole("row", { name: /BUILD-01/ });
    expect(within(row).getByText("Online")).toBeInTheDocument();
    expect(within(row).getByText("Now")).toBeInTheDocument();
    expect(screen.getByText("1 device, 1 online")).toBeInTheDocument();

    await userEvent.setup().click(within(row).getByRole("link", { name: "BUILD-01" }));
    expect(await screen.findByRole("heading", { name: "BUILD-01" })).toBeInTheDocument();
    expect(screen.getByText("Turned off on this server")).toBeInTheDocument();
    expect(screen.getByText("1.4.0")).toBeInTheDocument();
    expect(screen.getByText("(arm64)")).toBeInTheDocument();
    expect(screen.getByText("Enrolled")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remote desktop" })).not.toBeInTheDocument();
  });

  it("is in the navigation only for people who can view devices", async () => {
    installFakeApi(baseRoutes(TECHNICIAN));
    const { unmount } = renderApp("/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Devices" })).toHaveAttribute("href", "/devices");
    // A technician without settings.manage, user.view or audit.view has no settings.
    expect(within(nav).queryByRole("link", { name: "Settings" })).not.toBeInTheDocument();
    unmount();

    installFakeApi({ ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view"] })), "GET /organizations": ok({ items: [] }) });
    renderApp("/organizations");
    const nav2 = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav2).queryByRole("link", { name: "Devices" })).not.toBeInTheDocument();
  });
});

describe("device detail", () => {
  it("offers the sessions the role allows and lists recent ones", async () => {
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /devices/:id": ok(device("d1", "FRONT-DESK", { canFiles: false, deviceGroupName: "Reception" })),
      "GET /audit": ok({
        items: [
          auditEntry(9, "device.remote_session", { actorLabel: "sam@example.com", details: { kind: "terminal", device: "FRONT-DESK" } }),
          auditEntry(8, "device.remote_session", { actorLabel: "rob@example.com", outcome: "denied", details: { kind: "desktop", device: "FRONT-DESK" } }),
        ],
      }),
    });
    renderApp("/devices/d1");
    expect(await screen.findByRole("heading", { name: "FRONT-DESK" })).toBeInTheDocument();
    for (const name of ["Remote desktop", "Terminal"]) expect(screen.getByRole("button", { name })).toHaveAttribute("aria-haspopup", "menu");
    expect(screen.queryByRole("button", { name: "Files" })).not.toBeInTheDocument();
    expect(screen.getByText("Reception")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Northwind Traders / Head office" })).toHaveAttribute("href", "/sites/s1");

    expect(await screen.findByText("sam@example.com")).toBeInTheDocument();
    expect(screen.getByText(/· denied/)).toBeInTheDocument();
    const q = server.call("GET /audit").query;
    expect([q.get("deviceId"), q.get("action")]).toEqual(["d1", "device.remote_session"]);
  });

  it("opens a session in this tab or in a window of its own", async () => {
    const user = userEvent.setup();
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(DEVICES[0]), "POST /devices/:id/remote-sessions": launch });
    const popup = { closed: false, focus: vi.fn(), location: { pathname: "/devices/d1/remote/terminal", assign: vi.fn() } };
    const open = vi.fn<typeof window.open>(() => popup as unknown as Window);
    vi.stubGlobal("open", open);
    renderApp("/devices/d1");

    const terminal = await screen.findByRole("button", { name: "Terminal" });
    await user.click(terminal);
    const menu = screen.getByRole("menu", { name: "Open Terminal" });
    expect(terminal).toHaveAttribute("aria-expanded", "true");
    expect(within(menu).getByRole("menuitem", { name: "In this tab" })).toHaveFocus();
    expect(within(menu).getByRole("menuitem", { name: "In this tab" })).toHaveAttribute("href", "/devices/d1/remote/terminal");
    await user.keyboard("{ArrowDown}");
    expect(within(menu).getByRole("menuitem", { name: "In a new window" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
    expect(terminal).toHaveFocus();

    // A window of its own, named after the device; asking again brings it forward rather than opening another.
    await user.click(terminal);
    await user.click(screen.getByRole("menuitem", { name: "In a new window" }));
    expect(open).toHaveBeenCalledTimes(1);
    expect(open.mock.calls[0]?.slice(0, 2)).toEqual(["/devices/d1/remote/terminal", "easyrmm-session-d1"]);
    expect(open.mock.calls[0]?.[2]).toMatch(/^popup=yes,width=\d+,height=\d+/);
    expect(location()).toBe("/devices/d1");
    await user.click(screen.getByRole("button", { name: "Remote desktop" }));
    await user.click(screen.getByRole("menuitem", { name: "In a new window" }));
    expect(open).toHaveBeenCalledTimes(1);
    expect(popup.location.assign).toHaveBeenCalledWith("/devices/d1/remote/desktop");
    expect(popup.focus).toHaveBeenCalled();

    // In this tab.
    await user.click(terminal);
    await user.click(screen.getByRole("menuitem", { name: "In this tab" }));
    expect(location()).toBe("/devices/d1/remote/terminal");
  });

  it("offers RDP on Windows devices to those who may open a remote desktop", async () => {
    const user = userEvent.setup();
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(device("d1", "FRONT-DESK")), "POST /devices/:id/remote-sessions": launch });
    const { unmount } = renderApp("/devices/d1");
    const rdp = await screen.findByRole("button", { name: "RDP" });
    expect(screen.getAllByRole("button", { name: /^(Remote desktop|RDP|Terminal|Files)$/ }).map((b) => b.textContent)).toEqual(["Remote desktop", "RDP", "Terminal", "Files"]);
    await user.click(rdp);
    expect(within(screen.getByRole("menu", { name: "Open RDP" })).getByRole("menuitem", { name: "In this tab" })).toHaveAttribute("href", "/devices/d1/remote/rdp");
    unmount();

    for (const d of [device("d2", "LAB-07", { platform: "linux" }), device("d3", "KIOSK", { canDesktop: false })]) {
      installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(d) });
      const view = renderApp(`/devices/${d.id}`);
      expect(await screen.findByRole("heading", { name: d.name })).toBeInTheDocument();
      expect(screen.queryByRole("button", { name: "RDP" })).not.toBeInTheDocument();
      view.unmount();
    }
  });

  it("says so when the browser blocks the session window", async () => {
    const user = userEvent.setup();
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(device("d9", "KIOSK")) });
    vi.stubGlobal("open", vi.fn(() => null));
    renderApp("/devices/d9");
    await user.click(await screen.findByRole("button", { name: "Files" }));
    await user.click(screen.getByRole("menuitem", { name: "In a new window" }));
    expect(await screen.findByText(/Your browser blocked the new window/)).toBeInTheDocument();
    // A click outside closes an open menu.
    await user.click(screen.getByRole("button", { name: "Files" }));
    expect(screen.getByRole("menu")).toBeInTheDocument();
    await user.click(screen.getByRole("heading", { name: "KIOSK" }));
    expect(screen.queryByRole("menu")).not.toBeInTheDocument();
  });

  it("explains why sessions cannot start on an offline device", async () => {
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /devices/:id": ok(device("d2", "back-office", { remoteOnline: false })),
    });
    renderApp("/devices/d2");
    expect(await screen.findByText("The device is offline.")).toBeInTheDocument();
    for (const name of ["Remote desktop", "Terminal", "Files"]) expect(screen.getByRole("button", { name })).toBeDisabled();
    expect(screen.getByText("Not connected")).toBeInTheDocument();
    expect(screen.getByText("Not installed")).toBeInTheDocument();
    // No audit.view: no session history.
    expect(screen.queryByText("Remote sessions")).not.toBeInTheDocument();
  });

  it("tells a checking-in device apart from one whose MeshAgent is down", async () => {
    const agent = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      ...unreportedRoutes(),
      "GET /devices/:id": ok(device("d4", "SRV-01", { platform: "linux", online: true, remoteOnline: false, agent })),
    });
    const { unmount } = renderApp("/devices/d4");
    expect(await screen.findByText("Remote access is not connected.")).toBeInTheDocument();
    expect(screen.getByText(/The device is checking in, but its MeshAgent is not connected/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Terminal" })).toBeDisabled();
    unmount();

    // Enrolled, but MeshAgent has not linked yet: no session buttons, and a pointer to what to check.
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      ...unreportedRoutes(),
      "GET /devices/:id": ok(device("d5", "SRV-02", { platform: "linux", online: true, remoteAgent: false, remoteOnline: false, canDesktop: false, canTerminal: false, canFiles: false, agent })),
    });
    renderApp("/devices/d5");
    expect(await screen.findByText("Not set up yet")).toBeInTheDocument();
    expect(screen.getByText(/“sudo easyrmm-agent status”/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Terminal" })).not.toBeInTheDocument();
    expect(screen.getByText("Online")).toBeInTheDocument();
    // On Windows the agent is not on the PATH: the hint names where it is.
    const windows = { remoteAgent: false, remoteOnline: false, agent, platform: "windows" as const };
    expect(remoteAccessState(windows, true).hint).toContain(String.raw`“& "$env:ProgramFiles\EasyRMM\Agent\easyrmm-agent.exe" status” in PowerShell as administrator`);
  });

  it("shows read-only people the device without session buttons", async () => {
    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["device.view"] })),
      "GET /devices/:id": ok(device("d1", "FRONT-DESK", { canDesktop: false, canTerminal: false, canFiles: false, remoteOnline: false })),
    });
    renderApp("/devices/d1");
    expect(await screen.findByRole("heading", { name: "FRONT-DESK" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remote desktop" })).not.toBeInTheDocument();
    // The offline notice is about sessions, so people who cannot start one do not get it.
    expect(screen.queryByText("The device is offline.")).not.toBeInTheDocument();
  });

  it("says when a device does not exist or is out of reach", async () => {
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": fail(404, "not_found", "Not found.") });
    renderApp("/devices/nope");
    expect(await screen.findByText("Not found")).toBeInTheDocument();
  });
});

describe("remote sessions", () => {
  it("embeds the session, switches between kinds and reconnects with a fresh link each time", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(DEVICES[0]), "POST /devices/:id/remote-sessions": launch });
    renderApp("/devices/d1/remote/desktop");
    const frame = await screen.findByTitle("Remote desktop on FRONT-DESK");
    expect(frame).toHaveAttribute("src", "https://mesh.rmm.example.com/.easyrmm/launch?t=desktop-token");
    expect(frame).toHaveAttribute("sandbox", "allow-scripts allow-same-origin allow-forms allow-downloads allow-popups allow-modals");
    expect(frame).toHaveAttribute("referrerpolicy", "no-referrer");
    expect(server.callsTo("POST /devices/:id/remote-sessions")).toHaveLength(1);
    // The full-window page has no console navigation.
    expect(screen.queryByRole("navigation", { name: "Main" })).not.toBeInTheDocument();

    await user.click(screen.getByRole("link", { name: "Terminal" }));
    expect(await screen.findByTitle("Terminal on FRONT-DESK")).toHaveAttribute("src", expect.stringContaining("terminal-token"));
    expect(location()).toBe("/devices/d1/remote/terminal");
    expect(screen.getByRole("link", { name: "Terminal" })).toHaveAttribute("aria-current", "page");

    await user.click(screen.getByRole("button", { name: /Reconnect|Start this session again/ }));
    await waitFor(() => expect(server.callsTo("POST /devices/:id/remote-sessions")).toHaveLength(3));
    expect(server.calls.filter((c) => c.method === "POST").map((c) => (c.body as { kind: string }).kind)).toEqual(["desktop", "terminal", "terminal"]);

    await user.click(screen.getByRole("link", { name: /End/ }));
    expect(location()).toBe("/devices/d1");
  });

  it("opens an RDP session", async () => {
    const server = installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(DEVICES[0]), "POST /devices/:id/remote-sessions": launch });
    renderApp("/devices/d1/remote/rdp");
    expect(await screen.findByTitle("RDP on FRONT-DESK")).toHaveAttribute("src", expect.stringContaining("rdp-token"));
    expect(server.calls.filter((c) => c.method === "POST").map((c) => (c.body as { kind: string }).kind)).toEqual(["rdp"]);
    expect(screen.getByRole("link", { name: "RDP" })).toHaveAttribute("aria-current", "page");
  });

  it("ends a session in its own window by closing the window", async () => {
    const user = userEvent.setup();
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(DEVICES[0]), "POST /devices/:id/remote-sessions": launch });
    const close = vi.fn();
    vi.stubGlobal("close", close);
    window.name = "easyrmm-session-d1";
    try {
      renderApp("/devices/d1/remote/terminal");
      await screen.findByTitle("Terminal on FRONT-DESK");
      // No way back into the console from here: the console is in the window that opened this one.
      expect(screen.queryByRole("link", { name: "Device details" })).not.toBeInTheDocument();
      expect(screen.queryByRole("link", { name: /End/ })).not.toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: /End/ }));
      expect(close).toHaveBeenCalled();
      expect(location()).toBe("/devices/d1/remote/terminal");
    } finally {
      window.name = "";
    }
  });

  it("offers to close a session window whose session could not start", async () => {
    const user = userEvent.setup();
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(DEVICES[0]), "POST /devices/:id/remote-sessions": fail(409, "device_offline", "The device is offline.") });
    const close = vi.fn();
    vi.stubGlobal("close", close);
    window.name = "easyrmm-session-d1";
    try {
      renderApp("/devices/d1/remote/desktop");
      expect(await screen.findByText("The device is offline")).toBeInTheDocument();
      expect(screen.queryByRole("link", { name: "Back to the device" })).not.toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: "Close window" }));
      expect(close).toHaveBeenCalled();
    } finally {
      window.name = "";
    }
  });

  it("helps when the browser does not yet trust the server's own certificate for the session", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /devices/:id": ok(DEVICES[0]),
      "POST /devices/:id/remote-sessions": (r) => {
        const kind = (r.body as { kind: string }).kind;
        return { status: 201, body: { grantId: `g-${kind}`, url: `https://203.0.113.10:4443/.easyrmm/launch?t=${kind}-token`, expiresAt: "2030-01-01T00:00:00Z", kind, deviceId: r.params.id, internalCa: true } };
      },
    });
    renderApp("/devices/d1/remote/terminal");
    expect(await screen.findByTitle("Terminal on FRONT-DESK")).toHaveAttribute("src", expect.stringContaining("203.0.113.10:4443"));
    expect(screen.queryByRole("region", { name: /may not trust/ })).not.toBeInTheDocument();

    const toggle = screen.getByRole("button", { name: /Not loading\?|Help if the session does not load/ });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const help = screen.getByRole("region", { name: "Your browser may not trust this address yet" });
    expect(within(help).getByText("https://203.0.113.10:4443")).toBeInTheDocument();
    const open = within(help).getByRole("link", { name: "Open 203.0.113.10:4443 in a new tab" });
    expect(open).toHaveAttribute("href", "https://203.0.113.10:4443");
    expect(open).toHaveAttribute("target", "_blank");
    expect(open).toHaveAttribute("rel", "noopener noreferrer");
    expect(within(help).getByRole("link", { name: /certificate authority/ })).toHaveAttribute("href", "/devices/add");

    // Reconnecting closes the help and asks for a fresh link.
    await user.click(within(help).getByRole("button", { name: "Reconnect" }));
    await waitFor(() => expect(server.callsTo("POST /devices/:id/remote-sessions")).toHaveLength(2));
    expect(screen.queryByRole("region", { name: /may not trust/ })).not.toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: /Not loading\?|Help if the session does not load/ }));
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("region", { name: /may not trust/ })).not.toBeInTheDocument();
  });

  it("offers no certificate help for a session on a trusted name", async () => {
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(DEVICES[0]), "POST /devices/:id/remote-sessions": launch });
    renderApp("/devices/d1/remote/terminal");
    await screen.findByTitle("Terminal on FRONT-DESK");
    expect(screen.queryByRole("button", { name: /Not loading\?|Help if the session does not load/ })).not.toBeInTheDocument();
  });

  it("explains a session that could not start and tries again", async () => {
    const user = userEvent.setup();
    let attempts = 0;
    installFakeApi({
      ...baseRoutes(TECHNICIAN),
      "GET /devices/:id": ok(DEVICES[0]),
      "POST /devices/:id/remote-sessions": (r) =>
        ++attempts === 1 ? fail(503, "remote_unavailable", "Remote access is unavailable right now. Try again in a minute.") : launch(r),
    });
    renderApp("/devices/d1/remote/files");
    expect(await screen.findByText("Remote access is unavailable")).toBeInTheDocument();
    expect(screen.getByText("Remote access is unavailable right now. Try again in a minute.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByTitle("Files on FRONT-DESK")).toBeInTheDocument();
  });

  it.each([
    [fail(409, "device_offline", "The device is offline."), "The device is offline", true],
    [fail(409, "remote_agent_missing", "This device has no remote-access agent."), "No remote-access agent", false],
    [fail(403, "forbidden", "You do not have permission."), "Not available to your role", false],
    [fail(404, "not_found", "Not found."), "Device not found", false],
    [fail(500, "internal", "Something went wrong."), "The session could not start", true],
  ])("shows %#: %s", async (reply, title, retry) => {
    installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(DEVICES[0]), "POST /devices/:id/remote-sessions": reply });
    renderApp("/devices/d1/remote/desktop");
    expect(await screen.findByText(title)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Try again" }) !== null).toBe(retry);
    expect(screen.getByRole("link", { name: "Back to the device" })).toBeInTheDocument();
  });

  it("refuses an unknown session type without asking the server", async () => {
    const server = installFakeApi({ ...baseRoutes(TECHNICIAN), "GET /devices/:id": ok(DEVICES[0]) });
    renderApp("/devices/d1/remote/teleport");
    expect(await screen.findByText("Unknown session type")).toBeInTheDocument();
    expect(server.callsTo("POST /devices/:id/remote-sessions")).toHaveLength(0);
  });
});

describe("remote access settings", () => {
  it("shows the connection and what to check when it is down", async () => {
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /users": ok({ items: [] }),
      "GET /remote-access/status": ok({ ...STATUS, connected: false, lastError: "meshcentral: unavailable: dial tcp 127.0.0.1:14430: connection refused", lastErrorAt: "2026-11-01T10:00:00Z" }),
    });
    renderApp("/settings?tab=remote");
    expect(await screen.findByText("EasyRMM cannot reach MeshCentral")).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByText("https://mesh.rmm.example.com")).toBeInTheDocument();
    expect(screen.getByText(/connection refused/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "3 known, 2 online" })).toHaveAttribute("href", "/devices");
  });

  it("shows a healthy connection", async () => {
    installFakeApi({ ...baseRoutes(sessionView()), "GET /users": ok({ items: [] }), "GET /remote-access/status": ok({ ...STATUS, lastSyncAt: undefined }) });
    renderApp("/settings?tab=remote");
    expect(await screen.findByText("Connected")).toBeInTheDocument();
    expect(screen.getByText("Not yet")).toBeInTheDocument();
    expect(screen.queryByText("EasyRMM cannot reach MeshCentral")).not.toBeInTheDocument();
  });

  it("says when remote access is turned off", async () => {
    installFakeApi({ ...baseRoutes(sessionView()), "GET /users": ok({ items: [] }), "GET /remote-access/status": fail(404, "not_found", "Not found.") });
    renderApp("/settings?tab=remote");
    expect(await screen.findByText("Remote access is turned off")).toBeInTheDocument();
  });

  it("is a tab only for people who manage settings", async () => {
    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "user.view"] })),
      "GET /users": ok({ items: [] }),
      "GET /roles": ok({ items: [] }),
      "GET /organizations": ok({ items: [] }),
    });
    renderApp("/settings?tab=remote");
    expect(await screen.findByRole("tab", { name: "Users" })).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByRole("tab", { name: "Remote access" })).not.toBeInTheDocument();
  });

  it("is reachable for an administrator who manages only settings", async () => {
    installFakeApi({ ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["settings.manage"] })), "GET /remote-access/status": ok(STATUS) });
    renderApp("/settings");
    expect(await screen.findByRole("tab", { name: "Remote access" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("Connected")).toBeInTheDocument();
  });
});
