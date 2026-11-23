import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Device, Repair, RemoteStatus } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { device } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { unavailableReason } from "./remote";
import { shownRepair } from "./remoteRepair";

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const TECHNICIAN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "device.edit", "device.remote_desktop", "device.terminal", "device.files"] });

const status = (extra: Partial<RemoteStatus>): RemoteStatus => ({ reason: "not_connected", message: "MeshAgent is running but is not connected to MeshCentral.", since: null, reportedAt: null, ...extra });

const repair = (extra: Partial<Repair> = {}): Repair => ({
  id: "r1",
  target: "meshagent",
  carriedBy: "easyrmm-agent",
  trigger: "manual",
  state: "running",
  steps: [
    { id: "r1.0", step: "restart", state: "sent" },
    { id: "r1.1", step: "repair", state: "pending" },
  ],
  startedAt: new Date().toISOString(),
  endedAt: null,
  error: "",
  ...extra,
});

function page(d: Device, repairs: () => Repair[]) {
  return {
    ...baseRoutes(TECHNICIAN),
    ...unreportedRoutes(),
    "GET /devices/:id": () => ok(d),
    "GET /devices/:id/repairs": () => ok({ items: repairs() }),
  };
}

describe("why remote access is not connected", () => {
  it("says what the watchdog found, before the generic words", () => {
    const base = { remoteAgent: true, remoteOnline: false, online: true };
    expect(unavailableReason({ ...base, remote: null })).toBe("Remote access is not connected.");
    expect(unavailableReason({ ...base, remote: status({ reason: "unknown", message: "no idea" }) })).toBe("Remote access is not connected.");
    expect(unavailableReason({ ...base, remote: status({ reason: "not_running", message: "MeshAgent is installed but not running." }) })).toBe(
      "MeshAgent is installed but not running.",
    );
    // Not linked yet: the reason beats "not set up".
    expect(unavailableReason({ ...base, remoteAgent: false, remote: status({ reason: "not_installed", message: "MeshAgent is not installed on the device." }) })).toBe(
      "MeshAgent is not installed on the device.",
    );
    expect(unavailableReason({ ...base, remoteAgent: false, remote: null })).toBe("Remote access is not set up on this device.");
    expect(unavailableReason({ ...base, online: false, remote: status({ reason: "device_offline", message: "x" }) })).toBe("The device is offline.");
    expect(unavailableReason({ remoteAgent: true, remoteOnline: true, online: true, remote: status({ reason: "connected", message: "x" }) })).toBeNull();
  });

  it("shows the reason, since when and the last error on the device page", async () => {
    const d = device("d1", "SRV-01", {
      platform: "linux",
      online: true,
      remoteOnline: false,
      agent: AGENT,
      remote: status({ reason: "other_server", message: "MeshAgent's settings name another MeshCentral server.", host: "old.example.test:443", error: "start failed" }),
    });
    installFakeApi(page(d, () => []));
    renderApp("/devices/d1");
    expect(await screen.findByText("MeshAgent's settings name another MeshCentral server.")).toBeInTheDocument();
    expect(screen.getByText("Its settings name old.example.test:443.")).toBeInTheDocument();
    expect(screen.getByText("Last error on the device: start failed")).toBeInTheDocument();
  });
});

describe("reconnecting remote access", () => {
  it("asks for the repair and follows its steps to the end", async () => {
    const user = userEvent.setup();
    const d = device("d1", "SRV-01", { platform: "linux", online: true, remoteOnline: false, agent: AGENT, canReconnectRemote: true, remote: status({}) });
    const state: { list: Repair[] } = { list: [] };
    const server = installFakeApi({
      ...page(d, () => state.list),
      "POST /devices/:id/repairs": () => {
        state.list = [repair()];
        return ok(state.list[0]);
      },
    });
    renderApp("/devices/d1");
    await user.click(await screen.findByRole("button", { name: "Reconnect remote access" }));
    expect(await screen.findByText("Reconnecting remote access")).toBeInTheDocument();
    expect(server.callsTo("POST /devices/:id/repairs")[0]?.body).toEqual({ target: "meshagent" });
    expect(screen.getByText(/Restart MeshAgent/)).toBeInTheDocument();
    expect(screen.getByText(/Sent to the EasyRMM agent/)).toBeInTheDocument();
    expect(screen.getByText(/Waiting for the EasyRMM agent to check in/)).toBeInTheDocument();
    // One at a time.
    expect(screen.getByRole("button", { name: "Reconnect remote access" })).toBeDisabled();
  });

  it("shows how a repair that failed ended, and what failed", async () => {
    const d = device("d1", "SRV-01", { platform: "linux", online: true, remoteOnline: false, agent: AGENT, canReconnectRemote: true, remote: status({}) });
    const done = repair({
      state: "failed",
      endedAt: new Date().toISOString(),
      error: "The last step failed: download failed",
      steps: [
        { id: "r1.0", step: "restart", state: "failed", error: "the unit does not exist" },
        { id: "r1.1", step: "repair", state: "failed", error: "download failed" },
      ],
    });
    installFakeApi(page(d, () => [done]));
    renderApp("/devices/d1");
    const card = (await screen.findByText("Remote access did not come back")).closest("div")!.parentElement!;
    expect(within(card).getByText("the unit does not exist")).toBeInTheDocument();
    expect(within(card).getAllByText("download failed")).toHaveLength(1);
    expect(within(card).getByText("The last step failed: download failed")).toBeInTheDocument();
  });

  it("is not offered without device.edit, or while the device is not checking in", async () => {
    const readOnly = device("d1", "SRV-01", { platform: "linux", online: true, remoteOnline: false, agent: AGENT, canReconnectRemote: false });
    installFakeApi(page(readOnly, () => []));
    const { unmount } = renderApp("/devices/d1");
    await screen.findByText("Remote access is not connected.");
    expect(screen.queryByRole("button", { name: "Reconnect remote access" })).not.toBeInTheDocument();
    unmount();

    const asleep = device("d2", "SRV-02", { platform: "linux", online: false, remoteOnline: false, agent: AGENT, canReconnectRemote: true });
    installFakeApi(page(asleep, () => []));
    renderApp("/devices/d2");
    const button = await screen.findByRole("button", { name: "Reconnect remote access" });
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute("title", "The device is not checking in, so nothing can be repaired from here.");
  });

  it("can be asked again after the server refuses", async () => {
    const user = userEvent.setup();
    const d = device("d1", "SRV-01", { platform: "linux", online: true, remoteOnline: false, agent: AGENT, canReconnectRemote: true });
    installFakeApi({
      ...page(d, () => []),
      "POST /devices/:id/repairs": fail(409, "device_leaving", "The device is being removed; nothing is repaired on it."),
    });
    renderApp("/devices/d1");
    await user.click(await screen.findByRole("button", { name: "Reconnect remote access" }));
    // The mutation's failure is not swallowed: the button is usable again.
    expect(await screen.findByRole("button", { name: "Reconnect remote access" })).toBeEnabled();
  });
});

describe("which repair is shown", () => {
  const now = Date.now();
  it("shows the latest while it runs, and for an hour after it ended", () => {
    expect(shownRepair(undefined, now)).toBeNull();
    expect(shownRepair([], now)).toBeNull();
    expect(shownRepair([repair()], now)?.id).toBe("r1");
    const ended = (ago: number) => repair({ state: "succeeded", endedAt: new Date(now - ago).toISOString() });
    expect(shownRepair([ended(59 * 60_000)], now)).not.toBeNull();
    expect(shownRepair([ended(61 * 60_000)], now)).toBeNull();
  });
});
