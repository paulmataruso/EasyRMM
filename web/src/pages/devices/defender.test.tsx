import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import type { DeviceDefender } from "../../api/types";
import {
  baseRoutes,
  fail,
  installFakeApi,
  ok,
  sessionView,
} from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";

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
const TECHNICIAN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view"],
});
const WINDOWS = device("d1", "FRONT-DESK", {
  platform: "windows",
  osDescription: "Windows 11 Pro 24H2",
  agent: AGENT,
});
const LINUX = device("d1", "web-01", {
  platform: "linux",
  osDescription: "Ubuntu 24.04",
  agent: AGENT,
});
const HASH = "a".repeat(64);
const MD5 = "b".repeat(32);

function routes(
  defender: DeviceDefender | ReturnType<typeof fail>,
  dev = WINDOWS,
) {
  return {
    ...baseRoutes(TECHNICIAN),
    "GET /devices/:id": ok(dev),
    "GET /devices/:id/inventory": ok({
      inventory: inventory(),
      metrics: metrics(),
    }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: [] }),
    "GET /devices/:id/defender":
      "body" in defender && "status" in defender ? defender : ok(defender),
  } as Parameters<typeof installFakeApi>[0];
}

const REPORT: DeviceDefender = {
  defender: {
    state: "present_not_effective",
    reason: "local exclusions are ignored (DisableLocalAdminMerge)",
    kinds: [
      { kind: "path", state: "effective" },
      {
        kind: "process",
        state: "refused",
        reason: "Access is denied (Tamper Protection is on)",
      },
      {
        kind: "asr",
        state: "not_needed",
        reason: "No Attack Surface Reduction rule is set.",
      },
      { kind: "cfa", state: "effective" },
    ],
    folders: [
      { path: "C:\\ProgramData\\EasyRMM\\Agent", listed: true, ours: true },
      {
        path: "C:\\Program Files\\EasyRMM\\MeshAgent",
        listed: false,
        ours: false,
        reason: "can be changed by BUILTIN\\Users",
      },
    ],
  },
  defenderAt: "2026-11-26T10:00:00Z",
  installed: {
    source: "reported by the device",
    observedAt: "2026-11-26T10:00:00Z",
    agentVersion: "v1.5.0",
    meshAgentVersion: "Compiled Nov 3",
    files: [
      {
        program: "easyrmm-agent",
        name: "easyrmm-agent.exe",
        size: 5,
        md5: MD5,
        sha256: HASH,
        status: "mismatch",
        expected: {
          source: "server",
          version: "v1.5.0",
          md5: MD5,
          sha256: "c".repeat(64),
          computedAt: "2026-11-26T09:00:00Z",
          stale: false,
        },
      },
      {
        program: "meshagent",
        name: "meshagent.exe",
        size: 5,
        md5: MD5,
        sha256: HASH,
        status: "not_current",
        expected: {
          source: "meshcentral",
          version: "",
          md5: MD5,
          sha256: "d".repeat(64),
          computedAt: "2026-11-26T09:00:00Z",
          stale: true,
        },
      },
      {
        program: "easypatch-agent",
        name: "EasyPatch.Agent.exe",
        size: 5,
        md5: MD5,
        sha256: HASH,
        status: "no_expected",
      },
    ],
    missing: [],
    patchNote:
      "The files inside the EasyPatch agent's installer are not listed yet, so these have no expected value.",
  },
};

describe("a Windows device's Defender card", () => {
  it("shows the status and why, each kind and each folder, and what the hashes say", async () => {
    installFakeApi(routes(REPORT));
    renderApp("/devices/d1");
    const card = (
      await screen.findByRole("heading", {
        name: "Microsoft Defender exclusions",
      })
    ).closest("section") as HTMLElement;
    expect(within(card).getByText("Listed, not in effect")).toBeInTheDocument();
    expect(
      within(card).getByText(/DisableLocalAdminMerge/),
    ).toBeInTheDocument();
    expect(within(card).getByLabelText("Folders: Working")).toBeInTheDocument();
    expect(
      within(card).getByLabelText("Programs: Defender refused"),
    ).toBeInTheDocument();
    expect(
      within(card).getByText(/Tamper Protection is on/),
    ).toBeInTheDocument();
    expect(
      within(card).getByLabelText("Attack Surface Reduction: Not needed"),
    ).toBeInTheDocument();
    expect(
      within(card).getByLabelText("C:\\ProgramData\\EasyRMM\\Agent: excluded"),
    ).toBeInTheDocument();
    expect(
      within(card).getByLabelText(
        "C:\\Program Files\\EasyRMM\\MeshAgent: not excluded",
      ),
    ).toBeInTheDocument();
    expect(
      within(card).getByText("can be changed by BUILTIN\\Users"),
    ).toBeInTheDocument();

    const files = (
      await screen.findByRole("heading", { name: "Installed files" })
    ).closest("section") as HTMLElement;
    expect(
      within(files).getByText("Reported by the device"),
    ).toBeInTheDocument();
    expect(
      within(files).getByText("Differs from the list"),
    ).toBeInTheDocument();
    expect(
      within(files).getByText("Not the current build"),
    ).toBeInTheDocument();
    expect(within(files).getByText("No expected value")).toBeInTheDocument();
    expect(within(files).getByText("Stale")).toBeInTheDocument();
    expect(within(files).getByText(/not listed yet/)).toBeInTheDocument();
    expect(
      within(files).getByText(/EasyRMM agent v1.5.0, MeshAgent Compiled Nov 3/),
    ).toBeInTheDocument();
  });

  it("says Not applicable, with the reason, where Defender is not the active antivirus", async () => {
    installFakeApi(
      routes({
        defender: {
          state: "not_applicable",
          reason:
            "Microsoft Defender is not the active antivirus (running mode Passive); another product is, or it is passive.",
          kinds: [],
          folders: [],
        },
        defenderAt: "2026-11-26T10:00:00Z",
        installed: null,
      }),
    );
    renderApp("/devices/d1");
    expect(await screen.findByText("Not applicable")).toBeInTheDocument();
    expect(screen.getByText(/running mode Passive/)).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Installed files" }),
    ).not.toBeInTheDocument();
  });

  it("shows nothing for a device that has reported nothing", async () => {
    const server = installFakeApi(
      routes({ defender: null, defenderAt: null, installed: null }),
    );
    renderApp("/devices/d1");
    expect(
      await screen.findByRole("heading", { name: "Health" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Microsoft Defender exclusions" }),
    ).not.toBeInTheDocument();
    expect(server.callsTo("GET /devices/:id/defender").length).toBeGreaterThan(
      0,
    );
  });

  it("does not ask a Linux device", async () => {
    const server = installFakeApi(
      routes({ defender: null, defenderAt: null, installed: null }, LINUX),
    );
    renderApp("/devices/d1");
    expect(
      await screen.findByRole("heading", { name: "Health" }),
    ).toBeInTheDocument();
    expect(server.callsTo("GET /devices/:id/defender")).toHaveLength(0);
  });

  it("shows the EasyPatch agent's own report in a second card", async () => {
    installFakeApi(
      routes({
        ...REPORT,
        defender: {
          ...REPORT.defender!,
          easypatch: {
            state: "not_locked",
            reason:
              "C:\\Program Files\\EasyPatch Agent may be changed by S-1-5-32-545.",
            kinds: [],
            folders: [
              { path: "C:\\ProgramData\\EasyPatch", listed: true, ours: true },
            ],
          },
        },
      }),
    );
    renderApp("/devices/d1");
    const card = (
      await screen.findByRole("heading", {
        name: "Microsoft Defender exclusions: EasyPatch agent",
      })
    ).closest("section") as HTMLElement;
    expect(
      within(card).getByText("A folder is not locked down"),
    ).toBeInTheDocument();
    expect(
      within(card).getByLabelText("C:\\ProgramData\\EasyPatch: excluded"),
    ).toBeInTheDocument();
  });
});
