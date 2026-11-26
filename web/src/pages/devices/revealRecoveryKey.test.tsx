import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DeviceEscrow, RecoveryKeyRequest } from "../../api/types";
import {
  baseRoutes,
  fail,
  installFakeApi,
  ok,
  sessionView,
  type FakeRequest,
} from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { REVEAL_SECONDS } from "./RevealRecoveryKey";

const KEY = "123456-234567-345678-456789-567890-678901-789012-890123";
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
const READY = {
  state: "unsealed",
  mode: "tpm",
  recoveryVerified: true,
  fileMode: false,
} as const;

const escrow = (over: Partial<DeviceEscrow> = {}): DeviceEscrow => ({
  applicable: true,
  canRead: true,
  twoPerson: false,
  keystore: READY,
  volumes: [
    {
      id: "vol-1",
      mount: "C:",
      status: "encrypted",
      state: "verified",
      protectors: [
        {
          id: "{AAAA-1}",
          state: "verified",
          verifiedAt: "2026-11-01T10:00:00Z",
        },
      ],
      reportedAt: "2026-11-01T10:00:00Z",
    },
  ],
  ...over,
});

function routes(
  e: DeviceEscrow,
  extra: Record<string, unknown> = {},
  perms: string[] = [
    "org.view",
    "site.view",
    "device.view",
    "device.recovery_key.read",
  ],
) {
  return {
    ...baseRoutes(
      sessionView({ isSuperAdmin: false, permissions: perms as never }),
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

async function openDialog() {
  const user = userEvent.setup();
  renderApp("/devices/d1?tab=hardware");
  await user.click(
    await screen.findByRole("button", {
      name: "Reveal the recovery key of C:",
    }),
  );
  return {
    user,
    dialog: await screen.findByRole("dialog", {
      name: "Reveal the recovery key",
    }),
  };
}

describe("revealing a recovery key (ADR-0081)", () => {
  it("offers nothing to a person without the read permission", async () => {
    installFakeApi(routes(escrow({ canRead: false })));
    renderApp("/devices/d1?tab=hardware");
    await screen.findByRole("heading", { name: "Disk recovery keys" });
    expect(
      screen.queryByRole("button", { name: /Reveal/ }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/Reading a key needs the Recovery Key Reader add-on/),
    ).toBeInTheDocument();
  });

  it("needs a reason of ten characters, sends it, and shows the key once with no copy button", async () => {
    const server = installFakeApi(
      routes(escrow(), { "POST /devices/:id/escrow/read": ok({ key: KEY }) }),
    );
    const { user, dialog } = await openDialog();
    const submit = within(dialog).getByRole("button", { name: "Reveal" });
    expect(submit).toBeDisabled();
    await user.type(
      within(dialog).getByLabelText(/Why do you need the key/),
      "boot loop, owner waiting",
    );
    await user.type(within(dialog).getByLabelText(/Ticket reference/), "T-7");
    await user.click(submit);
    const shown = await screen.findByRole("status", { name: "Recovery key" });
    expect(shown).toHaveTextContent(KEY);
    expect(
      screen.queryByRole("button", { name: /copy/i }),
    ).not.toBeInTheDocument();
    expect(
      server
        .callsTo("POST /devices/:id/escrow/read")
        .map((c: FakeRequest) => c.body),
    ).toEqual([
      {
        volume: "vol-1",
        protector: "{AAAA-1}",
        reason: "boot loop, owner waiting",
        ticket: "T-7",
      },
    ]);
    // Never in storage or the address.
    expect(JSON.stringify({ ...localStorage })).not.toContain("123456");
    expect(JSON.stringify({ ...sessionStorage })).not.toContain("123456");
    expect(window.location.href).not.toContain("123456");
    // Closing drops it from the page.
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Done" }),
    );
    await waitFor(() => expect(document.body.textContent).not.toContain(KEY));
  });

  it("drops the key when the page is left", async () => {
    installFakeApi(
      routes(escrow(), { "POST /devices/:id/escrow/read": ok({ key: KEY }) }),
    );
    const { user, dialog } = await openDialog();
    await user.type(
      within(dialog).getByLabelText(/Why do you need the key/),
      "boot loop, owner waiting",
    );
    await user.click(within(dialog).getByRole("button", { name: "Reveal" }));
    await screen.findByRole("status", { name: "Recovery key" });
    // pagehide
    act(() => {
      window.dispatchEvent(new Event("pagehide"));
    });
    await waitFor(() => expect(document.body.textContent).not.toContain(KEY));
  });

  it("counts down and removes the key when the time is up", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      installFakeApi(
        routes(escrow(), { "POST /devices/:id/escrow/read": ok({ key: KEY }) }),
      );
      const { user, dialog } = await openDialog();
      await user.type(
        within(dialog).getByLabelText(/Why do you need the key/),
        "boot loop, owner waiting",
      );
      await user.click(within(dialog).getByRole("button", { name: "Reveal" }));
      await screen.findByRole("status", { name: "Recovery key" });
      await act(async () => {
        await vi.advanceTimersByTimeAsync((REVEAL_SECONDS + 1) * 1000);
      });
      expect(document.body.textContent).not.toContain(KEY);
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows why a read was refused, and keeps no key", async () => {
    installFakeApi(
      routes(escrow(), {
        "POST /devices/:id/escrow/read": fail(
          429,
          "read_limit",
          "Too many recovery keys were read in the last hour. Try again later.",
        ),
      }),
    );
    const { user, dialog } = await openDialog();
    await user.type(
      within(dialog).getByLabelText(/Why do you need the key/),
      "boot loop, owner waiting",
    );
    await user.click(within(dialog).getByRole("button", { name: "Reveal" }));
    expect(
      await within(dialog).findByText(/Too many recovery keys were read/),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("status", { name: "Recovery key" }),
    ).not.toBeInTheDocument();
  });

  it("asks for step-up through the console's own dialog and sends the request again", async () => {
    let calls = 0;
    installFakeApi(
      routes(escrow(), {
        "POST /devices/:id/escrow/read": () =>
          ++calls === 1
            ? fail(401, "step_up_required", "Confirm it is you.")
            : ok({ key: KEY }),
        "GET /auth/step-up": ok({ methods: ["totp"] }),
      }),
    );
    const { user, dialog } = await openDialog();
    await user.type(
      within(dialog).getByLabelText(/Why do you need the key/),
      "boot loop, owner waiting",
    );
    await user.click(within(dialog).getByRole("button", { name: "Reveal" }));
    const stepUp = await screen.findByRole("dialog", {
      name: "Confirm it is you",
    });
    await user.click(within(stepUp).getByRole("button", { name: "Cancel" }));
    // Declined: the request is not repeated and no key is shown.
    expect(calls).toBe(1);
    expect(
      screen.queryByRole("status", { name: "Recovery key" }),
    ).not.toBeInTheDocument();
  });

  it("waits for a second person where the organization asks for two, then reveals with the approval", async () => {
    const REQ: RecoveryKeyRequest = {
      id: "r1",
      deviceId: "d1",
      device: "FRONT-DESK",
      volume: "vol-1",
      protector: "{AAAA-1}",
      requester: "me@example.com",
      reason: "boot loop, owner waiting",
      state: "pending",
      createdAt: "2026-11-01T10:00:00Z",
      expiresAt: "2026-11-01T10:30:00Z",
      mine: true,
      canDecide: false,
    };
    let approved = false;
    const server = installFakeApi(
      routes(escrow({ twoPerson: true }), {
        "POST /devices/:id/escrow/read": (r: FakeRequest) =>
          (r.body as { requestId?: string }).requestId
            ? ok({ key: KEY })
            : { status: 202, body: { pending: REQ } },
        "GET /keystore/requests": () =>
          ok({
            requests: [
              {
                ...REQ,
                state: approved ? "approved" : "pending",
                approver: approved ? "b@example.com" : undefined,
              },
            ],
          }),
      }),
    );
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const { user, dialog } = await openDialog();
      await user.type(
        within(dialog).getByLabelText(/Why do you need the key/),
        "boot loop, owner waiting",
      );
      await user.click(within(dialog).getByRole("button", { name: "Reveal" }));
      expect(
        await screen.findByText("Waiting for a second person"),
      ).toBeInTheDocument();
      expect(document.body.textContent).not.toContain(KEY);
      approved = true;
      await act(async () => {
        await vi.advanceTimersByTimeAsync(6000);
      });
      await user.click(
        await screen.findByRole("button", { name: "Reveal the key" }),
      );
      expect(
        await screen.findByRole("status", { name: "Recovery key" }),
      ).toHaveTextContent(KEY);
      const posts = server
        .callsTo("POST /devices/:id/escrow/read")
        .map((c: FakeRequest) => c.body);
      expect(posts[1]).toEqual({
        volume: "vol-1",
        protector: "{AAAA-1}",
        requestId: "r1",
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("lets an approver decide a request for this device, and not their own", async () => {
    const mk = (over: Partial<RecoveryKeyRequest>): RecoveryKeyRequest => ({
      id: "r1",
      deviceId: "d1",
      device: "FRONT-DESK",
      volume: "vol-1",
      protector: "{AAAA-1}",
      requester: "tech@example.com",
      reason: "boot loop, owner waiting",
      state: "pending",
      createdAt: "2026-11-01T10:00:00Z",
      expiresAt: "2026-11-01T10:30:00Z",
      mine: false,
      canDecide: true,
      ...over,
    });
    const server = installFakeApi(
      routes(
        escrow({ canRead: false }),
        {
          "GET /keystore/requests": ok({
            requests: [
              mk({}),
              mk({
                id: "r2",
                mine: true,
                canDecide: false,
                requester: "me@example.com",
              }),
            ],
          }),
          "POST /keystore/requests/:id/approve": ok(mk({ state: "approved" })),
        },
        ["org.view", "site.view", "device.view", "device.recovery_key.approve"],
      ),
    );
    const user = userEvent.setup();
    renderApp("/devices/d1?tab=hardware");
    const waiting = (
      await screen.findByRole("heading", { name: "Waiting for your decision" })
    ).parentElement as HTMLElement;
    expect(within(waiting).getAllByRole("listitem")).toHaveLength(1);
    expect(
      within(waiting).getByText(/boot loop, owner waiting/),
    ).toBeInTheDocument();
    await user.click(within(waiting).getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(
        server.callsTo("POST /keystore/requests/:id/approve"),
      ).toHaveLength(1),
    );
  });
});

beforeEach(() => {
  vi.useRealTimers();
});
afterEach(() => {
  vi.useRealTimers();
});
