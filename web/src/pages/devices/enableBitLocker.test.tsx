import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DeviceEscrow } from "../../api/types";
import {
  baseRoutes,
  fail,
  installFakeApi,
  ok,
  sessionView,
} from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// Turning BitLocker on (ADR-0081, slice 4): the computer's name typed out, then the action, then its result.

const AGENT = {
  version: "1.4.0",
  arch: "amd64",
  sha256: "",
  online: true,
  lastSeenAt: "2026-11-01T10:00:00Z",
  enrolledAt: "2026-10-01T09:00:00Z",
  update: null,
  accepts: null,
  powerShell7: null,
};
const WINDOWS_PC = device("d1", "FRONT-DESK", {
  platform: "windows",
  osDescription: "Windows 11 Pro 24H2",
  agent: AGENT,
});
const windowsOs = { ...inventory().os, name: "Windows 11 Pro", id: "windows" };

const escrow = (over: Partial<DeviceEscrow> = {}): DeviceEscrow => ({
  applicable: true,
  canRead: false,
  twoPerson: false,
  canEnable: true,
  keystore: {
    state: "unsealed",
    mode: "tpm",
    recoveryVerified: true,
    fileMode: false,
  },
  volumes: [
    {
      id: "vol-1",
      kind: "bitlocker",
      mount: "C:",
      status: "decrypted",
      state: "not_encrypted",
      protectors: [],
      reportedAt: "2026-11-01T10:00:00Z",
    },
    {
      id: "vol-2",
      kind: "bitlocker",
      mount: "D:",
      status: "encrypted",
      state: "verified",
      protectors: [
        {
          id: "{AAAA-1}",
          state: "verified",
          verifiedAt: "2026-11-01T10:00:00Z",
          rotationDue: true,
          rotationDueAt: "2026-11-01T10:30:00Z",
        },
      ],
      reportedAt: "2026-11-01T10:00:00Z",
    },
  ],
  ...over,
});

function routes(e: DeviceEscrow, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(
      sessionView({
        isSuperAdmin: false,
        permissions: [
          "org.view",
          "site.view",
          "device.view",
          "device.bitlocker.manage",
        ] as never,
      }),
    ),
    "GET /devices/:id": ok(WINDOWS_PC),
    "GET /devices/:id/inventory": ok({
      inventory: inventory({ os: windowsOs }),
      metrics: metrics(),
    }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: [] }),
    "GET /devices/:id/escrow": ok(e),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

const RUN = {
  jobId: "j1",
  runId: "r1",
  action: "bitlocker.enable",
  status: "queued",
  expiresAt: "2026-11-01T11:00:00Z",
};

async function openDialog() {
  const user = userEvent.setup();
  renderApp("/devices/d1?tab=hardware");
  await user.click(
    await screen.findByRole("button", { name: "Turn on BitLocker for C:" }),
  );
  const dialog = await screen.findByRole("dialog", {
    name: "Turn on BitLocker",
  });
  return { user, dialog };
}

describe("turning BitLocker on from the console", () => {
  it("is offered only for an unencrypted volume, and only to someone who may", async () => {
    installFakeApi(routes(escrow({ canEnable: false })));
    renderApp("/devices/d1?tab=hardware");
    const card = (
      await screen.findByRole("heading", { name: "Disk recovery keys" })
    ).closest("section") as HTMLElement;
    expect(within(card).getByText("Not encrypted")).toBeInTheDocument();
    expect(
      within(card).queryByRole("button", { name: /Turn on BitLocker/ }),
    ).not.toBeInTheDocument();
  });

  it("shows a key that was read as one that will be replaced", async () => {
    installFakeApi(routes(escrow()));
    renderApp("/devices/d1?tab=hardware");
    expect(await screen.findByText("Will be replaced")).toBeInTheDocument();
  });

  it("keeps the button off until the computer's name is typed, then sends the typed confirmation", async () => {
    const server = installFakeApi(
      routes(escrow(), {
        "POST /devices/:id/winmod/:action": ok(RUN),
        "GET /winmod/runs/:id": ok({
          runId: "r1",
          deviceId: "d1",
          action: "bitlocker.enable",
          version: 1,
          status: "succeeded",
          finishedAt: "2026-11-01T10:05:00Z",
          ok: true,
          data: {
            volume: "C:",
            escrow: "verified",
            encryption: "started",
            mode: "used_space",
          },
        }),
      }),
    );
    const { user, dialog } = await openDialog();
    const go = within(dialog).getByRole("button", {
      name: "Turn on BitLocker",
    });
    expect(go).toBeDisabled();
    const name = within(dialog).getByLabelText(
      /Type the computer’s name to confirm/,
    );
    await user.type(name, "front");
    expect(go).toBeDisabled();
    await user.clear(name);
    await user.type(name, "front-desk");
    expect(go).toBeEnabled();
    await user.click(go);
    expect(await screen.findByText("Encryption started")).toBeInTheDocument();
    const call = server.call("POST /devices/:id/winmod/:action");
    expect(call.path).toBe("/devices/d1/winmod/bitlocker.enable");
    expect(call.body).toEqual({
      params: {
        computer: "front-desk",
        volume: "C:",
        encryption: "used_space",
      },
      confirm: "bitlocker.enable:front-desk",
    });
  });

  it("sends the whole-volume mode when it is chosen", async () => {
    const server = installFakeApi(
      routes(escrow(), {
        "POST /devices/:id/winmod/:action": ok(RUN),
        "GET /winmod/runs/:id": ok({
          runId: "r1",
          deviceId: "d1",
          action: "bitlocker.enable",
          version: 1,
          status: "succeeded",
          finishedAt: "x",
          ok: true,
          data: {},
        }),
      }),
    );
    const { user, dialog } = await openDialog();
    await user.selectOptions(
      within(dialog).getByLabelText("What to encrypt"),
      "full",
    );
    await user.type(
      within(dialog).getByLabelText(/Type the computer’s name to confirm/),
      "FRONT-DESK",
    );
    await user.click(
      within(dialog).getByRole("button", { name: "Turn on BitLocker" }),
    );
    await screen.findByText("Encryption started");
    expect(
      (
        server.call("POST /devices/:id/winmod/:action").body as {
          params: { encryption: string };
        }
      ).params.encryption,
    ).toBe("full");
  });

  it("says in words what the agent refused, and that nothing was changed", async () => {
    installFakeApi(
      routes(escrow(), {
        "POST /devices/:id/winmod/:action": ok(RUN),
        "GET /winmod/runs/:id": ok({
          runId: "r1",
          deviceId: "d1",
          action: "bitlocker.enable",
          version: 1,
          status: "succeeded",
          finishedAt: "x",
          ok: false,
          failure: { code: "domain_controller", message: "x" },
        }),
      }),
    );
    const { user, dialog } = await openDialog();
    await user.type(
      within(dialog).getByLabelText(/Type the computer’s name to confirm/),
      "FRONT-DESK",
    );
    await user.click(
      within(dialog).getByRole("button", { name: "Turn on BitLocker" }),
    );
    expect(
      await within(dialog).findByText(
        /domain controller; EasyRMM does not turn BitLocker on there. Nothing was changed/,
      ),
    ).toBeInTheDocument();
    expect(
      within(dialog).queryByText("Encryption started"),
    ).not.toBeInTheDocument();
  });

  it("shows the server's refusal, such as a keystore that cannot verify, and lets the person try again", async () => {
    installFakeApi(
      routes(escrow(), {
        "POST /devices/:id/winmod/:action": fail(
          503,
          "keystore_not_ready",
          "The keystore is not ready: it is sealed, or its recovery has not been verified.",
        ),
      }),
    );
    const { user, dialog } = await openDialog();
    await user.type(
      within(dialog).getByLabelText(/Type the computer’s name to confirm/),
      "FRONT-DESK",
    );
    await user.click(
      within(dialog).getByRole("button", { name: "Turn on BitLocker" }),
    );
    await waitFor(() =>
      expect(
        within(dialog).getByText(/The keystore is not ready/),
      ).toBeInTheDocument(),
    );
    expect(
      within(dialog).getByRole("button", { name: "Turn on BitLocker" }),
    ).toBeEnabled();
  });
});
