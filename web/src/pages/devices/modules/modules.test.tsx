import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  DefenderStatus,
  DeviceRole,
  DeviceRoles,
  WinmodResult,
} from "../../../api/types";
import {
  baseRoutes,
  fail,
  installFakeApi,
  ok,
  sessionView,
} from "../../../test/fakeApi";
import { device, history, inventory, metrics } from "../../../test/fixtures";
import { renderApp } from "../../../test/render";
import { moduleTabState, DEVICE_MODULE_TABS } from "./moduleTabs";

// The module frame on the device page (ADR-0073, slice 8): the tab rule, the "module off" page and defender.status.

const AGENT = {
  version: "1.5.0",
  arch: "amd64",
  sha256: "",
  online: true,
  lastSeenAt: "2026-11-01T10:00:00Z",
  enrolledAt: "2026-10-01T09:00:00Z",
  update: null,
  accepts: null,
  powerShell7: null,
};
const WINDOWS = device("d1", "FRONT-DESK", {
  platform: "windows",
  osDescription: "Windows 11 Pro 24H2",
  agent: AGENT,
});
const VIEWER = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "defender.view"],
});
const ADMIN = sessionView({
  isSuperAdmin: false,
  permissions: [
    "org.view",
    "org.manage",
    "site.view",
    "site.manage",
    "device.view",
    "defender.view",
  ],
});

const DEFENDER_ROLE: DeviceRole = {
  name: "defender",
  state: "present",
  module: "defender",
  label: "Microsoft Defender",
  enabled: true,
};
const roles = (r: DeviceRole[], known = true): DeviceRoles => ({
  known,
  reportedAt: "2026-11-26T10:00:00Z",
  roles: r,
});

const STATUS: DefenderStatus = {
  antivirusEnabled: true,
  antispywareEnabled: true,
  realTimeProtectionEnabled: false,
  behaviorMonitorEnabled: null,
  ioavProtectionEnabled: true,
  onAccessProtectionEnabled: true,
  nisEnabled: true,
  tamperProtected: true,
  runningMode: "Normal",
  computerState: 0,
  engineVersion: "1.1.24090.11",
  productVersion: "4.18.24090.11",
  serviceVersion: "4.18.24090.11",
  signatureVersion: "1.421.100.0",
  signatureUpdatedAt: "2026-11-25T08:00:00Z",
  signatureAgeDays: 1,
  quickScanAgeDays: 2,
  fullScanAgeDays: null,
};

function routes(
  session: ReturnType<typeof sessionView>,
  r: DeviceRoles,
  result?: Partial<WinmodResult>,
) {
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(WINDOWS),
    "GET /devices/:id/roles": ok(r),
    "GET /devices/:id/inventory": ok({
      inventory: inventory(),
      metrics: metrics(),
    }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: [] }),
    "GET /devices/:id/defender": fail(404, "not_found", "none"),
    "POST /devices/:id/winmod/defender.status": ok({
      jobId: "j1",
      runId: "r1",
      action: "defender.status",
      status: "queued",
      expiresAt: "2026-11-26T11:00:00Z",
    }),
    "GET /winmod/runs/:id": ok({
      runId: "r1",
      deviceId: "d1",
      action: "defender.status",
      version: 1,
      status: "succeeded",
      finishedAt: "2026-11-26T10:00:00Z",
      ok: true,
      data: STATUS,
      ...result,
    }),
  } as Parameters<typeof installFakeApi>[0];
}

const tab = DEVICE_MODULE_TABS[0]!;
const can = (p: string) => p === "defender.view";

describe("moduleTabState", () => {
  it("shows the tab only when the role is found, the module is on and the viewer may see it", () => {
    expect(moduleTabState(tab, roles([DEFENDER_ROLE]), can)).toBe("shown");
    expect(
      moduleTabState(tab, roles([{ ...DEFENDER_ROLE, enabled: false }]), can),
    ).toBe("off");
    expect(moduleTabState(tab, roles([]), can)).toBe("absent");
    expect(moduleTabState(tab, roles([DEFENDER_ROLE], false), can)).toBe(
      "absent",
    );
    expect(moduleTabState(tab, undefined, can)).toBe("absent");
    expect(moduleTabState(tab, roles([DEFENDER_ROLE]), () => false)).toBe(
      "absent",
    );
  });
});

describe("the Security tab", () => {
  it("is in the strip and reads Defender's state on request", async () => {
    const api = installFakeApi(routes(VIEWER, roles([DEFENDER_ROLE])));
    renderApp("/devices/d1?tab=security");
    await screen.findByRole("tab", { name: "Security" });
    await screen.findByText("Not read yet");
    expect(api.callsTo("POST /devices/:id/winmod/defender.status")).toHaveLength(0);
    await userEvent.click(screen.getByRole("button", { name: "Read now" }));
    await screen.findByText("Real-time protection");
    expect(screen.getByText("Not reported")).toBeInTheDocument();
    expect(screen.getByText("1.421.100.0")).toBeInTheDocument();
    expect(screen.getByText(/\(1 day ago\)/)).toBeInTheDocument();
    expect(screen.getByText("Never")).toBeInTheDocument();
    expect(api.callsTo("POST /devices/:id/winmod/defender.status")).toHaveLength(1);
  });

  it("says why when Defender is not installed", async () => {
    installFakeApi(
      routes(VIEWER, roles([DEFENDER_ROLE]), {
        ok: false,
        data: undefined,
        failure: { code: "module_missing", message: "x" },
      }),
    );
    renderApp("/devices/d1?tab=security");
    await userEvent.click(await screen.findByRole("button", { name: "Read now" }));
    await screen.findByText(/Microsoft Defender is not installed/);
  });

  it("is hidden when the module is off, and its URL says so with a link for an administrator", async () => {
    installFakeApi(
      routes(ADMIN, roles([{ ...DEFENDER_ROLE, enabled: false }])),
    );
    renderApp("/devices/d1?tab=security");
    await screen.findByText("Microsoft Defender is off for this site");
    expect(screen.queryByRole("tab", { name: "Security" })).toBeNull();
    expect(
      screen.getByRole("link", { name: /Windows modules settings/ }),
    ).toHaveAttribute("href", "/sites/s1?tab=windows-modules");
  });

  it("gives a viewer without the permission to change it no link", async () => {
    installFakeApi(
      routes(VIEWER, roles([{ ...DEFENDER_ROLE, enabled: false }])),
    );
    renderApp("/devices/d1?tab=security");
    await screen.findByText("Microsoft Defender is off for this site");
    expect(screen.queryByRole("link", { name: /Windows modules/ })).toBeNull();
  });

  it("is absent, and the URL falls back to Overview, when the role was not found", async () => {
    installFakeApi(routes(VIEWER, roles([])));
    renderApp("/devices/d1?tab=security");
    await screen.findByRole("tab", { name: "Overview" });
    expect(screen.queryByRole("tab", { name: "Security" })).toBeNull();
    expect(screen.queryByText(/is off for this site/)).toBeNull();
  });
});
