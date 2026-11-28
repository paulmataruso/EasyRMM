import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import type { Device } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { device } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// The installer, the server's build and Uninstalled (ADR-0056 slice 2, ADR-0053).

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };

const ADMIN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });

function page(d: Device) {
  return {
    ...baseRoutes(ADMIN),
    ...unreportedRoutes(),
    "GET /devices/:id": () => ok(d),
    "GET /devices": () => ok({ items: [d] }),
  };
}

describe("the device page's agent line", () => {
  it("names the package that installed the agent and says the device has run the server's build", async () => {
    const d = device("d1", "SRV-01", { platform: "linux", agent: { ...AGENT, installer: "deb", ranServerBuildAt: "2026-11-02T10:00:00Z" } });
    installFakeApi(page(d));
    renderApp("/devices/d1");
    expect(await screen.findByText("Installed by: DEB package")).toBeInTheDocument();
    expect(screen.getByTestId("server-build")).toHaveTextContent("Has run the server's build");
  });

  it("calls a device that has not run the server's build new, and one installed by the command so", async () => {
    const d = device("d1", "SRV-01", { platform: "linux", agent: { ...AGENT, installer: "", ranServerBuildAt: null } });
    installFakeApi(page(d));
    renderApp("/devices/d1");
    expect(await screen.findByText("Installed by: Install command")).toBeInTheDocument();
    expect(screen.getByTestId("server-build")).toHaveTextContent("New: has not run the server's build yet");
  });

  it("shows an agent that was uninstalled without a request", async () => {
    const d = device("d1", "SRV-01", {
      platform: "linux",
      agent: { ...AGENT, installer: "rpm", ranServerBuildAt: "2026-11-02T10:00:00Z", uninstalledAt: "2026-11-05T10:00:00Z", uninstalledInstaller: "rpm" },
    });
    installFakeApi(page(d));
    renderApp("/devices");
    expect(await screen.findByText("Uninstalled")).toBeInTheDocument();
  });

  it("shows nothing of them for a server that does not send the fields", async () => {
    const d = device("d1", "SRV-01", { platform: "linux", agent: AGENT });
    installFakeApi(page(d));
    renderApp("/devices/d1");
    expect(await screen.findByText(/1\.4\.0/)).toBeInTheDocument();
    expect(screen.queryByText(/Installed by/)).toBeNull();
    expect(screen.queryByTestId("server-build")).toBeNull();
  });
});
