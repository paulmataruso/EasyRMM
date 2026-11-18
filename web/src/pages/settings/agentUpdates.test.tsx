import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AgentUpdate, AgentUpdateSettings, DeviceAgent } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const SETTINGS: AgentUpdateSettings = {
  mode: "automatic",
  maxConcurrent: 20,
  stored: false,
  updatedAt: null,
  version: "v1.5.0",
  builds: [
    { os: "linux", arch: "amd64", file: "easyrmm-agent-linux-amd64", size: 1, sha256: "aa", version: "v1.5.0" },
    { os: "windows", arch: "amd64", file: "easyrmm-agent-windows-amd64.exe", size: 1, sha256: "bb", version: "v1.5.0" },
  ],
  fleet: { current: 40, updating: 3, queued: 2, available: 5, failed: 1, unsupported: 4 },
};

const main = () => within(screen.getByRole("main"));

describe("agent update settings", () => {
  it("shows the build and the fleet, and saves the rollout", async () => {
    const user = userEvent.setup();
    const saved: AgentUpdateSettings = { ...SETTINGS, mode: "manual", maxConcurrent: 5, stored: true, updatedAt: new Date().toISOString(), updatedBy: "alex@example.com" };
    let current = SETTINGS;
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/agent-updates": () => ok(current),
      "PUT /settings/agent-updates": () => {
        current = saved;
        return ok(saved);
      },
      "POST /settings/agent-updates/request-all": ok({ requested: 6 }),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/settings?tab=agent-updates");

    expect(await screen.findByRole("heading", { name: "Agent updates", level: 1 })).toBeInTheDocument();
    expect(await main().findByText("v1.5.0")).toBeInTheDocument();
    // Windows first.
    expect(main().getByText("Windows x86-64").compareDocumentPosition(main().getByText("Linux x86-64")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    for (const [label, n] of [["Up to date", "40"], ["Updating", "3"], ["Waiting to update", "2"], ["Update available", "5"], ["Update failed", "1"], ["Cannot update itself", "4"]]) {
      const term = main().getByText(label!);
      expect(term.closest("div")).toHaveTextContent(n!);
    }
    expect(main().getByText(/predate self-update/)).toBeInTheDocument();
    expect(main().getByText("The default setting applies.")).toBeInTheDocument();
    expect(main().getByLabelText(/Automatically/)).toBeChecked();

    // Asking every outdated agent: available and failed ones.
    await user.click(main().getByRole("button", { name: "Update 6 outdated agents" }));
    await waitFor(() => expect(server.callsTo("POST /settings/agent-updates/request-all")).toHaveLength(1));
    expect(await screen.findByText("Asked 6 agents to update.")).toBeInTheDocument();

    await user.click(main().getByLabelText(/When asked/));
    const max = main().getByLabelText(/^Devices at once/);
    await user.clear(max);
    await user.type(max, "5x");
    await user.click(main().getByRole("button", { name: "Save" }));
    await waitFor(() => expect(server.callsTo("PUT /settings/agent-updates")).toHaveLength(1));
    expect(server.callsTo("PUT /settings/agent-updates")[0]!.body).toEqual({ mode: "manual", maxConcurrent: 5 });
    expect(await main().findByText(/by alex@example.com/)).toBeInTheDocument();
  });

  it("says when the server has no builds, and shows validation errors", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/agent-updates": ok({ ...SETTINGS, version: "", builds: [], fleet: { none: 3 } }),
      "PUT /settings/agent-updates": fail(422, "validation_failed", "Check the highlighted fields.", { maxConcurrent: "Allow between 1 and 1000 devices at once." }),
    });
    renderApp("/settings?tab=agent-updates");
    expect(await screen.findByText("No agent builds")).toBeInTheDocument();
    expect(main().getByText("Version unknown")).toBeInTheDocument();
    expect(main().getByText("No build for the platform").closest("div")).toHaveTextContent("3");
    expect(main().queryByRole("button", { name: /outdated/ })).not.toBeInTheDocument();
    await user.clear(main().getByLabelText(/^Devices at once/));
    await user.click(main().getByRole("button", { name: "Save" }));
    expect(await main().findByText("Allow between 1 and 1000 devices at once.")).toBeInTheDocument();
  });

  it("is not offered without settings.manage", async () => {
    installFakeApi({ ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "user.view"] })), "GET /users": ok({ items: [] }) });
    renderApp("/settings?tab=agent-updates");
    expect(await screen.findByRole("heading", { name: "Users", level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Agent updates" })).not.toBeInTheDocument();
  });
});

const agent = (update: AgentUpdate | null): DeviceAgent => ({
  version: "v1.4.0",
  arch: "amd64",
  sha256: update?.status === "unsupported" ? "" : "cc",
  online: true,
  lastSeenAt: "2026-11-01T10:00:00Z",
  enrolledAt: "2026-10-01T09:00:00Z",
  update,
});

function deviceRoutes(update: AgentUpdate | null, canUpdateAgent = true, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(sessionView()),
    "GET /devices/:id": ok(device("d1", "DB-01", { platform: "linux", agent: agent(update), canUpdateAgent })),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /audit": ok({ items: [] }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

const details = async () => within((await screen.findByRole("heading", { name: "Details" })).closest("section") as HTMLElement);

describe("a device's agent update", () => {
  it("offers an available update and asks for it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      deviceRoutes({ status: "available", version: "v1.5.0", attempts: 0, error: "", requested: false }, true, {
        "POST /devices/:id/agent-update": ok(device("d1", "DB-01", { agent: agent({ status: "queued", version: "v1.5.0", attempts: 0, error: "", requested: true }) })),
      }),
    );
    renderApp("/devices/d1");
    const d = await details();
    expect(await d.findByText("Update available")).toBeInTheDocument();
    expect(d.getByText("The server ships v1.5.0.")).toBeInTheDocument();
    await user.click(d.getByRole("button", { name: "Update agent" }));
    await waitFor(() => expect(server.callsTo("POST /devices/:id/agent-update")).toHaveLength(1));
    expect(await screen.findByText("DB-01 updates its agent within a few minutes.")).toBeInTheDocument();
  });

  it("shows a failed update and lets it be tried again", async () => {
    installFakeApi(deviceRoutes({ status: "failed", version: "v1.5.0", attempts: 3, error: "the new build does not run: exec format error", requested: false }));
    renderApp("/devices/d1");
    const d = await details();
    expect(await d.findByText("Update failed")).toBeInTheDocument();
    expect(d.getByText(/Failed 3 times\. the new build does not run/)).toBeInTheDocument();
    expect(d.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("explains an agent that cannot update itself, and offers nothing without device.edit", async () => {
    installFakeApi(deviceRoutes({ status: "unsupported", version: "v1.5.0", attempts: 0, error: "", requested: false }, false));
    renderApp("/devices/d1");
    const d = await details();
    expect(await d.findByText("Cannot update itself")).toBeInTheDocument();
    expect(d.getByText(/Run the install command on the device once more/)).toBeInTheDocument();
    expect(d.queryByRole("button", { name: /Update agent|Try again/ })).not.toBeInTheDocument();
  });

  it("says nothing when the agent is current or the server has no build", async () => {
    installFakeApi(deviceRoutes({ status: "current", version: "v1.5.0", attempts: 0, error: "", requested: false }));
    const { unmount } = renderApp("/devices/d1");
    const d = await details();
    expect(await d.findByText("v1.4.0")).toBeInTheDocument();
    expect(d.queryByText(/Up to date|Update available/)).not.toBeInTheDocument();
    unmount();
  });
});
