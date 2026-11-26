import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import type { DeviceEscrow } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { keystoreNotice } from "./DeviceRecoveryKeys";

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const WINDOWS_PC = device("d1", "FRONT-DESK", { platform: "windows", osDescription: "Windows 11 Pro 24H2", agent: AGENT });
const windowsOs = { ...inventory().os, name: "Windows 11 Pro", id: "windows" };

const READY = { state: "unsealed", mode: "tpm", recoveryVerified: true, fileMode: false } as const;

function routes(escrow: DeviceEscrow) {
  return {
    ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] })),
    "GET /devices/:id": ok(WINDOWS_PC),
    "GET /devices/:id/inventory": ok({ inventory: inventory({ os: windowsOs }), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: [] }),
    "GET /devices/:id/escrow": ok(escrow),
  } as Parameters<typeof installFakeApi>[0];
}

const volume = (over: Partial<DeviceEscrow["volumes"][number]> = {}): DeviceEscrow["volumes"][number] => ({
  id: "\\\\?\\Volume{1}\\",
  kind: "bitlocker",
  mount: "C:",
  status: "encrypted",
  state: "verified",
  protectors: [{ id: "{AAAA-1}", state: "verified", verifiedAt: "2026-11-01T10:00:00Z" }],
  reportedAt: "2026-11-01T10:00:00Z",
  ...over,
});

describe("disk recovery keys (ADR-0081)", () => {
  it("shows each volume's escrow state and never a key", async () => {
    const escrow: DeviceEscrow = {
      applicable: true, canRead: false, twoPerson: false,
      keystore: READY,
      volumes: [
        volume(),
        volume({ id: "v2", mount: "D:", state: "conflict", protectors: [{ id: "{BBBB-2}", state: "conflict" }] }),
        volume({ id: "v3", mount: "E:", state: "missing", protectors: [] }),
      ],
    };
    installFakeApi(routes(escrow));
    renderApp("/devices/d1?tab=hardware");
    const card = (await screen.findByRole("heading", { name: "Disk recovery keys" })).closest("section") as HTMLElement;
    const [first, second, third, ...more] = within(card).getAllByRole("row").slice(1) as [HTMLElement, HTMLElement, HTMLElement];
    expect(more).toHaveLength(0);
    // The volume's state and its protector's, each a badge.
    expect(within(first).getAllByText("Verified")).toHaveLength(2);
    expect(within(second).getAllByText("Conflict")).toHaveLength(2);
    expect(within(third).getByText("Missing")).toBeInTheDocument();
    expect(within(third).getByText("No recovery password protector")).toBeInTheDocument();
    expect(card.textContent).not.toMatch(/\d{6}-\d{6}/);
    // A ready keystore says nothing about itself.
    expect(within(card).queryByRole("alert")).not.toBeInTheDocument();
  });

  it("shows a LUKS volume's key slots, and why one cannot be escrowed", async () => {
    const luks = (over: Partial<DeviceEscrow["volumes"][number]>) =>
      volume({ kind: "luks", status: "luks2", mount: "/", protectors: [], ...over });
    installFakeApi(
      routes({
        applicable: true, canRead: false, twoPerson: false, keystore: READY,
        volumes: [
          luks({ id: "u1", state: "verified", protectors: [{ id: "0a0a-1", state: "verified", verifiedAt: "2026-11-01T10:00:00Z" }] }),
          luks({ id: "u2", mount: "/data", state: "cannot_escrow", reason: "Only a passphrase unlocks this volume." }),
          luks({ id: "u3", mount: "/srv", state: "managed_elsewhere", reason: "Clevis manages how this volume unlocks." }),
          luks({ id: "u4", mount: "/var", state: "missing" }),
        ],
      }),
    );
    renderApp("/devices/d1?tab=hardware");
    const card = (await screen.findByRole("heading", { name: "Disk recovery keys" })).closest("section") as HTMLElement;
    const rows = within(card).getAllByRole("row").slice(1) as HTMLElement[];
    expect(rows).toHaveLength(4);
    expect(within(rows[0]!).getByText("LUKS (luks2)")).toBeInTheDocument();
    expect(within(rows[0]!).getAllByText("Verified")).toHaveLength(2);
    expect(within(rows[1]!).getByText("Cannot escrow")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("Only a passphrase unlocks this volume.")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("Managed elsewhere")).toBeInTheDocument();
    expect(within(rows[3]!).getByText("Missing")).toBeInTheDocument();
    expect(within(rows[3]!).getByText("No key slot of EasyRMM's yet")).toBeInTheDocument();
    expect(within(card).getByText(/On Linux the agent adds a key slot of its own/)).toBeInTheDocument();
  });

  it("says why escrow is not running, and warns about the file stand-in", async () => {
    installFakeApi(routes({ applicable: true, canRead: false, twoPerson: false, keystore: { state: "uninitialised", recoveryVerified: false, fileMode: false }, volumes: [] }));
    renderApp("/devices/d1?tab=hardware");
    expect(await screen.findByText(/The keystore is not initialised, so recovery-key escrow is off/)).toBeInTheDocument();
    expect(screen.getByText("No encrypted volumes reported")).toBeInTheDocument();
  });

  it("warns that the stand-in mode keeps its key in a file", async () => {
    installFakeApi(routes({ applicable: true, canRead: false, twoPerson: false, keystore: { ...READY, mode: "file", fileMode: true }, volumes: [volume()] }));
    renderApp("/devices/d1?tab=hardware");
    expect(await screen.findByText("Keystore protection: file (stand-in)")).toBeInTheDocument();
  });

  it("is not shown where the device cannot escrow", async () => {
    installFakeApi(routes({ applicable: false, canRead: false, twoPerson: false, keystore: READY, volumes: [] }));
    renderApp("/devices/d1?tab=hardware");
    await screen.findByRole("heading", { name: "Disks" });
    expect(screen.queryByRole("heading", { name: "Disk recovery keys" })).not.toBeInTheDocument();
  });

  it("explains each keystore state", () => {
    expect(keystoreNotice(READY)).toBeNull();
    expect(keystoreNotice({ state: "sealed", recoveryVerified: true, fileMode: false, detail: "TPM policy changed" })).toMatch(/sealed \(TPM policy changed\)/);
    expect(keystoreNotice({ state: "unavailable", recoveryVerified: false, fileMode: false })).toMatch(/cannot be reached/);
    expect(keystoreNotice({ ...READY, recoveryVerified: false })).toMatch(/recovery has not been verified/);
  });
});
