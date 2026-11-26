import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { NotificationChannel, PlatformNotice } from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// Notification channels in the console (ADR-0053, slice 3): an organization's Notifications tab and Settings >
// Notifications for super administrators.

const MAIL: NotificationChannel = {
  id: "c1",
  organizationId: "o1",
  platform: false,
  shared: false,
  kind: "email",
  name: "Service desk",
  enabled: true,
  state: "sending",
  recipients: ["desk@example.test", "lead@example.test"],
  pending: 0,
  lastSuccessAt: "2026-11-26T10:00:00Z",
};
const HOOK: NotificationChannel = {
  id: "c2",
  organizationId: "o1",
  platform: false,
  shared: false,
  kind: "webhook",
  name: "PSA hook",
  enabled: true,
  state: "waiting_for_approval",
  host: "10.0.0.7",
  port: 8443,
  pending: 2,
  approval: { state: "requested", host: "10.0.0.7", port: 8443, proposed: ["10.0.0.7"], prefixes: [], requestedAt: "2026-11-26T10:00:00Z" },
};
const SHARED: NotificationChannel = { id: "c3", organizationId: null, platform: true, shared: true, kind: "webhook", name: "MSP-wide hook", enabled: true, pending: 0 };
const NOTICE: PlatformNotice = {
  id: "n1",
  organizationId: "o1",
  kind: "channel_failing",
  subject: "c1",
  title: 'Notification channel "Service desk" is failing',
  detail: "The mail server refused the message.",
  openedAt: "2026-11-26T10:00:00Z",
};

const SUPER = sessionView();
const ORG_ADMIN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "org.manage", "user.view", "site.view", "device.view", "notification.manage"] });

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
    "GET /notifications/channels": ok({ channels: [MAIL, HOOK, SHARED] }),
    "GET /notices": ok({ notices: [NOTICE] }),
    "GET /notifications/deliveries": ok({ deliveries: [], retentionDays: 30 }),
    ...extra,
  };
}

describe("an organization's Notifications tab", () => {
  it("lists its own channels and the shared platform ones with a name and kind only", async () => {
    installFakeApi(routes(ORG_ADMIN));
    renderApp("/organizations/o1?tab=notifications");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText("Service desk")).toBeInTheDocument();
    expect(main.getByText("2 recipients")).toBeInTheDocument();
    expect(main.getByText("Waiting for approval")).toBeInTheDocument();
    const shared = main.getByText("MSP-wide hook").closest("tr")!;
    expect(within(shared).getByText(/shared by the platform/)).toBeInTheDocument();
    // A shared channel has no actions for the organization.
    expect(within(shared).queryByRole("button")).not.toBeInTheDocument();
    // A super administrator's Approve is not offered to the organization.
    expect(main.queryByRole("button", { name: /^Approve/ })).not.toBeInTheDocument();
    expect(main.getByText('Notification channel "Service desk" is failing')).toBeInTheDocument();
  });

  it("creates an email channel", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(ORG_ADMIN, { "POST /notifications/channels": ok({ ...MAIL, id: "c9" }) }));
    renderApp("/organizations/o1?tab=notifications");
    const main = within(await screen.findByRole("main"));
    await user.click(await main.findByRole("button", { name: /Add channel/ }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.type(dialog.getByLabelText(/^Name/), "On call");
    await user.type(dialog.getByLabelText(/^Recipients/), "a@example.test, b@example.test");
    await user.click(dialog.getByRole("button", { name: "Add channel" }));
    expect(server.call("POST /notifications/channels").body).toEqual({
      organizationId: "o1",
      kind: "email",
      name: "On call",
      recipients: ["a@example.test", "b@example.test"],
    });
  });

  it("creates a webhook with its certificate authority, and explains a refused address", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(ORG_ADMIN, { "POST /notifications/channels": fail(422, "validation_failed", "Some fields need attention.", { url: "The web address must start with https://." }) }));
    renderApp("/organizations/o1?tab=notifications");
    const main = within(await screen.findByRole("main"));
    await user.click(await main.findByRole("button", { name: /Add channel/ }));
    const dialog = within(await screen.findByRole("dialog"));
    await user.selectOptions(dialog.getByLabelText("Kind"), "webhook");
    await user.type(dialog.getByLabelText(/^Name/), "PSA");
    await user.type(dialog.getByLabelText(/^Web address/), "http://psa.example.test/hook");
    await user.type(dialog.getByLabelText(/^Certificate authority/), "pem");
    await user.click(dialog.getByRole("button", { name: "Add channel" }));
    expect(server.call("POST /notifications/channels").body).toEqual({ organizationId: "o1", kind: "webhook", name: "PSA", url: "http://psa.example.test/hook", trustedAuthority: "pem" });
    expect(await dialog.findByText("The web address must start with https://.")).toBeInTheDocument();
  });

  it("tests a channel and shows the receiver's answer in EasyRMM's words", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(ORG_ADMIN, {
        "POST /notifications/channels/:id/test": ok({ deliveryId: "d1", status: "failed", message: "The receiver at hooks.example.test answered 410." }),
      }),
    );
    renderApp("/organizations/o1?tab=notifications");
    const main = within(await screen.findByRole("main"));
    await user.click(await main.findByRole("button", { name: "Test Service desk" }));
    expect(server.call("POST /notifications/channels/:id/test").path).toBe("/notifications/channels/c1/test");
    expect(await main.findByText("The receiver at hooks.example.test answered 410.")).toBeInTheDocument();
    expect(main.getByText("Test failed")).toBeInTheDocument();
  });

  it("shows a webhook's address and secret on request, and can replace the secret", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(ORG_ADMIN, {
        "POST /notifications/channels/:id/reveal": ok({ url: "https://psa.example.test/hook?t=1", secret: "s3cret-value" }),
        "POST /notifications/channels/:id/rotate-secret": noContent,
      }),
    );
    renderApp("/organizations/o1?tab=notifications");
    const main = within(await screen.findByRole("main"));
    await user.click(await main.findByRole("button", { name: "Show secret of PSA hook" }));
    const dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByText("s3cret-value")).toBeInTheDocument();
    expect(dialog.getByText("https://psa.example.test/hook?t=1")).toBeInTheDocument();
    await user.click(dialog.getByRole("button", { name: "Replace secret" }));
    expect(server.call("POST /notifications/channels/:id/rotate-secret").path).toBe("/notifications/channels/c2/rotate-secret");
  });

  it("deletes a channel after asking, and says what it does to the waiting messages", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(ORG_ADMIN, { "DELETE /notifications/channels/:id": noContent }));
    renderApp("/organizations/o1?tab=notifications");
    const main = within(await screen.findByRole("main"));
    await user.click(await main.findByRole("button", { name: "Delete Service desk" }));
    const dialog = within(await screen.findByRole("dialog"));
    expect(dialog.getByText(/waiting messages are dropped/)).toBeInTheDocument();
    await user.click(dialog.getByRole("button", { name: "Delete channel" }));
    expect(server.call("DELETE /notifications/channels/:id").path).toBe("/notifications/channels/c1");
  });

  it("acknowledges a notice", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(ORG_ADMIN, { "POST /notices/:id/acknowledge": noContent }));
    renderApp("/organizations/o1?tab=notifications");
    const main = within(await screen.findByRole("main"));
    await user.click(await main.findByRole("button", { name: "Acknowledge" }));
    expect(server.call("POST /notices/:id/acknowledge").path).toBe("/notices/n1/acknowledge");
  });

  it("is hidden from someone without notification.manage", async () => {
    installFakeApi(routes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] })));
    renderApp("/organizations/o1?tab=notifications");
    await screen.findByRole("main");
    expect(screen.queryByRole("tab", { name: "Notifications" })).not.toBeInTheDocument();
    expect(screen.queryByText("Service desk")).not.toBeInTheDocument();
  });
});

describe("Settings > Notifications for super administrators", () => {
  it("lists every owner's channels, approves a private destination and shares a platform channel", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(SUPER, {
        "GET /settings/mail-server": ok({
          inForce: "none",
          limits: { perMinute: 30, perDay: 9000, account: { adminPerHour: 60, organizationPerDay: 500, accountBurst: 3, accountEveryMinutes: 20, resetsPerHour: 30, organizationResetsPerHour: 10 } },
          usage: { lastMinute: 0, lastDay: 0, accountLastDay: 0, adminDayLimit: 8100, otherDayLimit: 7200 },
        }),
        "GET /notifications/channels": ok({ channels: [HOOK, { ...SHARED, shared: false, sharedWith: [] }] }),
        "POST /notifications/channels/:id/approval/approve": ok({}),
        "PUT /notifications/channels/:id/shares/:orgId": noContent,
      }),
    );
    renderApp("/settings?tab=notifications");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText("PSA hook")).toBeInTheDocument();
    await user.click(main.getByRole("button", { name: "Approve PSA hook" }));
    let dialog = within(await screen.findByRole("dialog"));
    const field = dialog.getByLabelText("Addresses or networks");
    expect(field).toHaveValue("10.0.0.7");
    await user.clear(field);
    await user.type(field, "10.0.0.0/24");
    await user.click(dialog.getByRole("button", { name: "Approve" }));
    expect(server.call("POST /notifications/channels/:id/approval/approve").body).toEqual({ prefixes: ["10.0.0.0/24"] });
    await user.click(await main.findByRole("button", { name: "Share MSP-wide hook" }));
    dialog = within(await screen.findByRole("dialog"));
    await user.click(await dialog.findByRole("checkbox", { name: "Northwind Traders" }));
    expect(server.call("PUT /notifications/channels/:id/shares/:orgId").path).toBe("/notifications/channels/c3/shares/o1");
  });
});
