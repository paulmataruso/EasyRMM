import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Device, DeviceRemoval } from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { device } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const location = () => screen.getByTestId("location").textContent;

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null };

const ADMIN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });

const removal = (extra: Partial<DeviceRemoval> = {}): DeviceRemoval => ({
  requestedAt: "2026-11-01T10:00:00Z",
  sentAt: null,
  reportedAt: null,
  error: "",
  ...extra,
});

/** Routes for one device page, answering /devices/:id with the device as it stands. */
function page(state: { d: Device }) {
  return {
    ...baseRoutes(ADMIN),
    ...unreportedRoutes(),
    "GET /devices/:id": () => ok(state.d),
    "GET /devices": () => ok({ items: [] }),
  };
}

describe("removing a device", () => {
  it("asks the agent to uninstall itself and shows where that stands", async () => {
    const user = userEvent.setup();
    const state = { d: device("d1", "SRV-01", { platform: "linux", agent: AGENT, canRemove: true }) };
    const server = installFakeApi({
      ...page(state),
      "POST /devices/:id/removal": () => {
        state.d = { ...state.d, removal: removal() };
        return ok({ status: "asked", device: state.d });
      },
      "DELETE /devices/:id/removal": () => {
        state.d = { ...state.d, removal: null };
        return ok(state.d);
      },
    });
    renderApp("/devices/d1");
    await user.click(await screen.findByRole("button", { name: "Remove" }));
    const dialog = screen.getByRole("dialog", { name: "Remove SRV-01?" });
    expect(within(dialog).getByText(/its EasyRMM agent uninstalls itself, with MeshAgent and the EasyPatch agent/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Remove device" }));

    expect(await screen.findByText("Waiting for the agent to check in")).toBeInTheDocument();
    expect(server.calls.filter((c) => c.method === "POST")).toHaveLength(1);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(screen.getByText("Removing")).toBeInTheDocument();
    expect(location()).toBe("/devices/d1");

    // Kept after all.
    await user.click(screen.getByRole("button", { name: "Keep the device" }));
    expect(await screen.findByRole("button", { name: "Remove" })).toBeInTheDocument();
    expect(screen.queryByText("Waiting for the agent to check in")).not.toBeInTheDocument();
    expect(server.callsTo("DELETE /devices/:id/removal")).toHaveLength(1);
  });

  it("removes a device without an agent at once", async () => {
    const user = userEvent.setup();
    const state = { d: device("d2", "FOUND-PC", { agent: null, canRemove: true }) };
    installFakeApi({ ...page(state), "POST /devices/:id/removal": ok({ status: "removed" }) });
    renderApp("/devices/d2");
    await user.click(await screen.findByRole("button", { name: "Remove" }));
    const dialog = screen.getByRole("dialog", { name: "Remove FOUND-PC?" });
    expect(within(dialog).getByText(/has no EasyRMM agent, so it is removed now/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Remove now" }));
    await waitFor(() => expect(location()).toBe("/devices"));
    expect(await screen.findByText("Removed FOUND-PC.")).toBeInTheDocument();
  });

  it("shows why the agent could not uninstall itself, and removes the device anyway", async () => {
    const user = userEvent.setup();
    const state = {
      d: device("d1", "SRV-01", {
        platform: "linux",
        agent: AGENT,
        canRemove: true,
        removal: removal({ sentAt: "2026-11-01T10:01:00Z", reportedAt: "2026-11-01T10:02:00Z", error: "Removing the agent's service failed: access denied" }),
      }),
    };
    const server = installFakeApi({
      ...page(state),
      "POST /devices/:id/removal": () => {
        state.d = { ...state.d, removal: removal({ requestedAt: "2026-11-01T11:00:00Z" }) };
        return ok({ status: "asked", device: state.d });
      },
      "DELETE /devices/:id": noContent,
    });
    renderApp("/devices/d1");
    expect(await screen.findByText("The agent could not uninstall itself")).toBeInTheDocument();
    expect(screen.getByText("Removing the agent's service failed: access denied")).toBeInTheDocument();
    expect(screen.getByText("Removal failed")).toBeInTheDocument();

    // Asked again: waiting once more.
    await user.click(screen.getByRole("button", { name: "Ask again" }));
    expect(await screen.findByText("Waiting for the agent to check in")).toBeInTheDocument();
    expect(server.callsTo("POST /devices/:id/removal")).toHaveLength(1);

    // Removed without waiting.
    await user.click(screen.getByRole("button", { name: "Remove now" }));
    const dialog = screen.getByRole("dialog", { name: "Remove SRV-01 without its agent?" });
    expect(within(dialog).getByText(/If its agent checks in within 90 days, it is told to uninstall itself then/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Remove anyway" }));
    await waitFor(() => expect(location()).toBe("/devices"));
    expect(server.callsTo("DELETE /devices/:id")).toHaveLength(1);
  });

  it("says the agent is uninstalling once it has the instruction, and shows a refusal", async () => {
    const user = userEvent.setup();
    const state = { d: device("d1", "SRV-01", { platform: "linux", agent: AGENT, canRemove: true, removal: removal({ sentAt: "2026-11-01T10:01:00Z" }) }) };
    installFakeApi({ ...page(state), "DELETE /devices/:id/removal": fail(409, "not_removing", "The device is not being removed.") });
    renderApp("/devices/d1");
    expect(await screen.findByText("The agent is uninstalling itself")).toBeInTheDocument();
    expect(screen.getByText(/EasyRMM removes the device once the agent confirms/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Keep the device" }));
    expect(await screen.findByText("The device is not being removed.")).toBeInTheDocument();
  });

  it("offers nothing to people who may not remove devices", async () => {
    const state = { d: device("d1", "SRV-01", { platform: "linux", agent: AGENT, canRemove: false, removal: removal() }) };
    installFakeApi(page(state));
    renderApp("/devices/d1");
    expect(await screen.findByText("Waiting for the agent to check in")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove now" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Keep the device" })).not.toBeInTheDocument();
  });
});
