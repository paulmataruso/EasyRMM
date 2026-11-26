import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  KeystoreAlert,
  KeystoreNotice,
  KeystoreOrgSettings,
  KeystoreStatus,
} from "../../api/types";
import {
  baseRoutes,
  fail,
  installFakeApi,
  noContent,
  ok,
  sessionView,
  unreportedRoutes,
} from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// The keystore's console pages (ADR-0081): Settings > Keystore and an organization's Recovery keys tab.

const ALERT: KeystoreAlert = {
  id: "a1",
  kind: "keystore_file_mode",
  subject: "keystore",
  severity: "warning",
  detail: "The keystore's key is protected by a file on its own host.",
  openedAt: "2026-11-26T10:00:00Z",
};
const ORG_ALERT: KeystoreAlert = {
  id: "a2",
  organizationId: "o1",
  kind: "escrow_conflict",
  severity: "warning",
  detail: "A different recovery key arrived.",
  openedAt: "2026-11-26T11:00:00Z",
};
const OTHER_ALERT: KeystoreAlert = { ...ORG_ALERT, id: "a3", organizationId: "o2", detail: "Another organization's." };
const STATUS: KeystoreStatus = {
  state: "unsealed",
  mode: "tpm",
  primary: 1,
  recoveryVerified: true,
  kekUsage: [{ version: 1, keys: 3 }],
  versions: [
    { version: 1, mode: "tpm", state: "active", open: true, createdAt: "2026-10-01T09:00:00Z", recoveryVerifiedAt: "2026-10-01T09:05:00Z" },
    { version: 2, mode: "tpm", state: "pending", open: true, createdAt: "2026-11-20T09:00:00Z" },
  ],
};
const NOTICES: KeystoreNotice[] = [
  { id: "n1", device: "pc1", deviceId: "d1", organizationId: "o1", by: "tech@example.test", approver: "boss@example.test", reason: "Disk would not boot after a BIOS update", at: "2026-11-25T10:00:00Z" },
  { id: "n2", device: "other-pc", deviceId: "d2", organizationId: "o2", by: "x@example.test", reason: "Belongs to another organization", at: "2026-11-25T11:00:00Z" },
];

const SUPER = sessionView();
const ORG_ADMIN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "org.manage", "user.manage", "user.view", "site.view", "device.view"],
});

function routes(session: ReturnType<typeof sessionView>, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(session),
    ...unreportedRoutes(),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
    "GET /organizations/:id/sites": ok({ items: [] }),
    "GET /sites": ok({ items: [] }),
    "GET /patching": ok({ configured: false }),
    "GET /patching/scope": ok({ organizationId: "o1", organizationName: "Northwind Traders", siteId: null, siteName: "", devices: 0, byPlatform: [], skipped: [], canManage: false }),
    "GET /audit": ok({ items: [] }),
    "GET /keystore": ok(STATUS),
    "GET /keystore/alerts": ok({ alerts: [ALERT, ORG_ALERT, OTHER_ALERT] }),
    "GET /keystore/notices": ok({ notices: NOTICES }),
    "GET /organizations/:id/keystore-settings": ok({ twoPerson: false, luksEscrow: false, approvers: 1 } satisfies KeystoreOrgSettings),
    ...extra,
  };
}

describe("Settings > Keystore", () => {
  it("shows the keystore, its key versions and every open alert", async () => {
    installFakeApi(routes(SUPER));
    renderApp("/settings?tab=keystore");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText("unsealed")).toBeInTheDocument();
    expect(main.getByText("protected by tpm")).toBeInTheDocument();
    expect(main.getByText("v1")).toBeInTheDocument();
    expect(main.getByText("not verified")).toBeInTheDocument();
    // How many organization keys each version still wraps (slice 4's re-wrap shows here).
    expect(main.getByText("Keys it wraps")).toBeInTheDocument();
    expect(main.getByText("3")).toBeInTheDocument();
    expect(main.getByText("The keystore's key is in a file")).toBeInTheDocument();
    expect(main.getAllByRole("button", { name: /^Resolve:/ })).toHaveLength(3);
  });

  it("resolves an alert and asks the list again", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(SUPER, { "POST /keystore/alerts/:id/resolve": noContent }));
    renderApp("/settings?tab=keystore");
    const main = within(await screen.findByRole("main"));
    await user.click(await main.findByRole("button", { name: "Resolve: The keystore's key is in a file" }));
    expect(server.call("POST /keystore/alerts/:id/resolve").path).toBe("/keystore/alerts/a1/resolve");
  });

  it("is not offered to someone without the platform right", async () => {
    installFakeApi(routes(ORG_ADMIN, { "GET /users": ok({ items: [], total: 0 }) }));
    renderApp("/settings?tab=keystore");
    // The first part this person may see is shown instead.
    await screen.findByRole("main");
    expect(screen.queryByText("Keystore alerts")).not.toBeInTheDocument();
  });
});

describe("an organization's Recovery keys tab", () => {
  it("shows the escrow key and rotates it after a confirmation", async () => {
    const user = userEvent.setup();
    const key = { version: 1, kekVersion: 2, createdAt: "2026-11-01T10:00:00Z", retired: 0, toMove: 0 };
    const server = installFakeApi(
      routes(ORG_ADMIN, {
        "GET /organizations/:id/keystore-settings": ok({ twoPerson: false, luksEscrow: false, approvers: 1, key } satisfies KeystoreOrgSettings),
        "POST /organizations/:id/keystore/rotate-key": ok({ twoPerson: false, luksEscrow: false, approvers: 1, key: { ...key, version: 2, retired: 1, toMove: 4 } }),
      }),
    );
    renderApp("/organizations/o1?tab=recovery-keys");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText("keystore key v2")).toBeInTheDocument();
    await user.click(main.getByRole("button", { name: "Rotate the escrow key" }));
    const dialog = await screen.findByRole("dialog", { name: "Rotate the escrow key?" });
    expect(server.callsTo("POST /organizations/:id/keystore/rotate-key")).toHaveLength(0);
    await user.click(within(dialog).getByRole("button", { name: "Rotate" }));
    await waitFor(() => expect(server.call("POST /organizations/:id/keystore/rotate-key").path).toBe("/organizations/o1/keystore/rotate-key"));
  });

  it("says the key is made at the first escrow when there is none yet", async () => {
    installFakeApi(routes(ORG_ADMIN));
    renderApp("/organizations/o1?tab=recovery-keys");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText(/The key is made when the first device here escrows a key/)).toBeInTheDocument();
    expect(main.queryByRole("button", { name: "Rotate the escrow key" })).not.toBeInTheDocument();
  });

  it("shows only this organization's reads and alerts", async () => {
    installFakeApi(routes(ORG_ADMIN));
    renderApp("/organizations/o1?tab=recovery-keys");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText("Disk would not boot after a BIOS update")).toBeInTheDocument();
    expect(main.getByText("boss@example.test")).toBeInTheDocument();
    expect(main.queryByText("Belongs to another organization")).not.toBeInTheDocument();
    expect(main.getByText("A recovery key conflicts with the verified one")).toBeInTheDocument();
    expect(main.queryByText("Another organization's.")).not.toBeInTheDocument();
    expect(main.queryByText("The keystore's key is in a file")).not.toBeInTheDocument();
  });

  it("has the two-person switch off and recommends it, then turns it on", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(ORG_ADMIN, {
        "GET /organizations/:id/keystore-settings": ok({ twoPerson: false, luksEscrow: false, approvers: 2 }),
        "PUT /organizations/:id/keystore-settings": ok({ twoPerson: true, luksEscrow: false, approvers: 2 }),
      }),
    );
    renderApp("/organizations/o1?tab=recovery-keys");
    const main = within(await screen.findByRole("main"));
    const sw = await main.findByRole("checkbox", { name: /Ask a second person to approve each read/ });
    expect(sw).not.toBeChecked();
    expect(main.getByText(/We recommend turning it on/)).toBeInTheDocument();
    await user.click(sw);
    const call = server.call("PUT /organizations/:id/keystore-settings");
    expect(call.path).toBe("/organizations/o1/keystore-settings");
    expect(call.body).toEqual({ twoPerson: true });
  });

  it("has the LUKS escrow switch off, says what it does, and turns it on", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(ORG_ADMIN, {
        "PUT /organizations/:id/keystore-settings": ok({ twoPerson: false, luksEscrow: true, approvers: 1 }),
      }),
    );
    renderApp("/organizations/o1?tab=recovery-keys");
    const main = within(await screen.findByRole("main"));
    const sw = await main.findByRole("checkbox", { name: /Escrow the keys of encrypted Linux volumes/ });
    expect(sw).not.toBeChecked();
    expect(main.getByText(/add a key slot to each encrypted Linux volume it can unlock by itself/)).toBeInTheDocument();
    await user.click(sw);
    expect(server.call("PUT /organizations/:id/keystore-settings").body).toEqual({ luksEscrow: true });
  });

  it("explains a refusal to turn it on without two approvers", async () => {
    const user = userEvent.setup();
    installFakeApi(
      routes(ORG_ADMIN, {
        "PUT /organizations/:id/keystore-settings": fail(409, "need_approvers", "Give the Recovery Key Approver add-on to at least two people in this organization first."),
      }),
    );
    renderApp("/organizations/o1?tab=recovery-keys");
    const main = within(await screen.findByRole("main"));
    await user.click(await main.findByRole("checkbox", { name: /Ask a second person/ }));
    expect(await main.findByText(/at least two people in this organization/)).toBeInTheDocument();
  });

  it("is hidden from someone who cannot manage the organization", async () => {
    installFakeApi(routes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] })));
    renderApp("/organizations/o1?tab=recovery-keys");
    await screen.findByRole("main");
    expect(screen.queryByRole("tab", { name: "Recovery keys" })).not.toBeInTheDocument();
    expect(screen.queryByText("Ask a second person to approve each read")).not.toBeInTheDocument();
  });
});
