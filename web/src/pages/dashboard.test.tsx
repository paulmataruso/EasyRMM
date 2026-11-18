import { describe, expect, it, vi } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { RecentConnection } from "../api/types";
import { baseRoutes, installFakeApi, ok, sessionView } from "../test/fakeApi";
import { device, org, site } from "../test/fixtures";
import { renderApp } from "../test/render";

const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "alert.view"] });

const RECENT: RecentConnection[] = [
  { device: device("d1", "DB-01"), kind: "desktop", at: new Date(Date.now() - 5 * 60_000).toISOString() },
  { device: device("d2", "FRONT-DESK", { online: false, remoteOnline: false }), kind: "terminal", at: new Date(Date.now() - 3 * 3600_000).toISOString() },
  { device: device("d3", "KIOSK", { canDesktop: false, canTerminal: false, canFiles: false }), kind: "files", at: new Date(Date.now() - 86_400_000).toISOString() },
];

function routes(session = TECH, recent = RECENT) {
  return {
    ...baseRoutes(session),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /devices/recent-connections": ok({ items: recent }),
  };
}

describe("dashboard", () => {
  it("lists recent connections, each ready to connect again", async () => {
    const user = userEvent.setup();
    const open = vi.fn(() => ({ closed: false, focus: vi.fn(), location: { pathname: "" } }));
    vi.stubGlobal("open", open);
    installFakeApi(routes());
    renderApp("/");

    const card = (await screen.findByRole("heading", { name: "Recent connections" })).closest("section, div")!.parentElement!;
    const rows = await within(card).findAllByRole("listitem");
    expect(rows).toHaveLength(3);
    expect(within(rows[0]!).getByRole("link", { name: "DB-01" })).toHaveAttribute("href", "/devices/d1");
    expect(rows[0]).toHaveTextContent(/Remote desktop, 5 minutes ago · Northwind Traders \/ Head office/);
    expect(rows[1]).toHaveTextContent(/Terminal, 3 hours ago/);
    expect(rows[1]).toHaveTextContent("offline");
    // Rights since taken away leave the device listed but not connectable.
    expect(within(rows[2]!).getByRole("button", { name: "Connect to KIOSK" })).toBeDisabled();

    await user.click(within(rows[0]!).getByRole("button", { name: "Connect to DB-01" }));
    const panel = screen.getByRole("dialog", { name: "DB-01" });
    await user.click(within(panel).getByRole("button", { name: "Files" }));
    expect(open).toHaveBeenCalledWith("/devices/d1/remote/files", "easyrmm-session-d1", expect.any(String));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    // The setup checklist and organizations list are gone.
    expect(screen.queryByRole("heading", { name: /Get started/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Organizations", level: 2 })).not.toBeInTheDocument();
  });

  it("says what the card is for before the first connection", async () => {
    installFakeApi(routes(TECH, []));
    renderApp("/");
    expect(await screen.findByText("No connections yet")).toBeInTheDocument();
    expect(screen.getByText(/Devices you open a remote session on are listed here/)).toBeInTheDocument();
  });

  it("has no recent connections without remote access", async () => {
    installFakeApi(routes(sessionView({ ...TECH, features: { remoteAccess: false } })));
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "Dashboard" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Recent connections" })).not.toBeInTheDocument();
  });
});
