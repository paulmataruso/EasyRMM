import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { SlowDevice } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { alertPolicy } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { slowText } from "./SlowDevices";

const ADMIN = sessionView({ permissions: [...sessionView().permissions, "device.view", "alert.view", "monitoring.view", "monitoring.manage"] });

const slow = (n: number, seconds: number, wait: number): SlowDevice => ({
  deviceId: `d${n}`,
  name: `PC-${n}`,
  siteId: "s1",
  siteName: "Head office",
  heartbeatSeconds: seconds,
  waitMinutes: wait,
});

const OFFLINE = alertPolicy("p1", "Device offline", { kind: "offline", threshold: null, minutes: 10, severity: "critical" });

function routes(items: SlowDevice[], total = items.length, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(ADMIN),
    "GET /alerts": ok({ items: [] }),
    "GET /alert-policies": ok({ items: [OFFLINE] }),
    "GET /alert-policies/:id/slow-devices": ok({ items, total }),
    ...extra,
  };
}

describe("devices that wait longer (ADR-0058)", () => {
  it("lists the devices whose interval makes the policy wait, with how long", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes([slow(1, 300, 15), slow(2, 30, 10)]));
    renderApp("/settings?tab=alert-policies");
    await user.click(await screen.findByRole("button", { name: "Edit Device offline" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit Device offline" });
    const section = await within(dialog).findByRole("region", { name: "Devices that wait longer" });
    expect(within(section).getByText(/2 devices wait longer than 10 minutes/)).toBeInTheDocument();
    expect(within(section).getByRole("link", { name: "PC-1" })).toHaveAttribute("href", "/devices/d1");
    expect(within(section).getByText(/checks in every 5 minutes, waits 15 minutes/)).toBeInTheDocument();
    expect(within(section).getByText(/checks in every 1 minute \(30 seconds\), waits 10 minutes/)).toBeInTheDocument();
    expect(server.callsTo("GET /alert-policies/:id/slow-devices")).toHaveLength(1);
    // Nothing on the page asks to be refreshed: it loaded by itself.
    expect(screen.queryByRole("button", { name: /refresh|read now/i })).not.toBeInTheDocument();
  });

  it("shows placeholders while it loads, and says how many more there are", async () => {
    const user = userEvent.setup();
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    installFakeApi(
      routes([1, 2, 3, 4, 5, 6, 7].map((n) => slow(n, 300, 15)), 9, {
        "GET /alert-policies/:id/slow-devices": async () => {
          await gate;
          return ok({ items: [1, 2, 3, 4, 5, 6, 7].map((n) => slow(n, 300, 15)), total: 9 });
        },
      }),
    );
    renderApp("/settings?tab=alert-policies");
    await user.click(await screen.findByRole("button", { name: "Edit Device offline" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit Device offline" });
    expect(await within(dialog).findByLabelText("Checking the devices' heartbeat intervals")).toBeInTheDocument();
    release();
    const section = await within(dialog).findByRole("region", { name: "Devices that wait longer" });
    expect(within(section).getAllByRole("listitem")).toHaveLength(5);
    expect(within(section).getByText("and 4 more.")).toBeInTheDocument();
    expect(within(dialog).queryByLabelText("Checking the devices' heartbeat intervals")).not.toBeInTheDocument();
  });

  it("shows nothing when no device waits longer, or the kind does not follow the interval", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes([], 0, { "GET /alert-policies": ok({ items: [OFFLINE, alertPolicy("p2", "Not connected", { kind: "remote_down", threshold: null, level: "shared" })] }) }),
    );
    renderApp("/settings?tab=alert-policies");
    await user.click(await screen.findByRole("button", { name: "Edit Device offline" }));
    let dialog = await screen.findByRole("dialog", { name: "Edit Device offline" });
    await waitFor(() => expect(server.callsTo("GET /alert-policies/:id/slow-devices")).toHaveLength(1));
    expect(within(dialog).queryByRole("region", { name: "Devices that wait longer" })).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await user.click(await screen.findByRole("button", { name: "Edit Not connected" }));
    dialog = await screen.findByRole("dialog", { name: "Edit Not connected" });
    expect(within(dialog).queryByRole("region", { name: "Devices that wait longer" })).not.toBeInTheDocument();
    expect(server.callsTo("GET /alert-policies/:id/slow-devices")).toHaveLength(1);
  });

  it("says so when a saved policy waits longer on some devices", async () => {
    const user = userEvent.setup();
    installFakeApi(
      routes([slow(1, 300, 15)], 1, { "PATCH /alert-policies/:id": ok({ ...OFFLINE, minutes: 10 }) }),
    );
    renderApp("/settings?tab=alert-policies");
    await user.click(await screen.findByRole("button", { name: "Edit Device offline" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit Device offline" });
    await user.click(within(dialog).getByRole("button", { name: "Save changes" }));
    expect(await screen.findByText(/Saved Device offline/)).toBeInTheDocument();
    expect(await screen.findByText(/1 device waits longer than 10 minutes/)).toBeInTheDocument();
  });

  it("words the sentence for one device and for many", () => {
    expect(slowText(1, 60)).toBe("1 device waits longer than 1 hour: a longer heartbeat interval makes this policy wait for it.");
    expect(slowText(3, 5)).toBe("3 devices wait longer than 5 minutes: a longer heartbeat interval makes this policy wait for it.");
  });
});
