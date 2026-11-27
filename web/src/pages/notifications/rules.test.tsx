import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { FleetSilence, MaintenanceWindow, NotificationChannel, NotificationRule, QuarantinedRow } from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";

// Device alert rules in the console (ADR-0053, slice 4): an organization's Notifications tab and Settings.

const CHANNEL: NotificationChannel = { id: "c1", organizationId: "o1", platform: false, shared: false, kind: "email", name: "Service desk", enabled: true, state: "sending", recipients: ["desk@example.test"], pending: 0 };
const SHARED: NotificationChannel = { id: "c3", organizationId: null, platform: true, shared: true, kind: "webhook", name: "MSP hook", enabled: true, pending: 0 };

const RULE: NotificationRule = {
  id: "r1",
  organizationId: "o1",
  platform: false,
  source: "alerts",
  name: "Servers offline",
  enabled: true,
  organizations: { mode: "any", ids: [] },
  sites: { mode: "list", ids: ["s1"] },
  groups: { mode: "any", ids: [] },
  deviceKinds: { mode: "list", values: ["server"] },
  severities: { mode: "any", values: [] },
  conditions: { mode: "list", values: ["offline"] },
  checks: { mode: "any", values: [] },
  waitMinutes: 10,
  onResolve: true,
  onAcknowledge: false,
  reminderHours: 4,
  ignoreWindows: false,
  groupOutages: true,
  channelIds: ["c1"],
  matchesNothing: false,
  createdAt: "2026-11-26T10:00:00Z",
  updatedAt: "2026-11-26T10:00:00Z",
};

const WINDOW: MaintenanceWindow = {
  id: "w1",
  organizationId: "o1",
  siteId: "s1",
  siteName: "Main office",
  name: "Nightly patching",
  kind: "weekly",
  days: [6],
  start: "22:00",
  lengthMinutes: 240,
  enabled: true,
  purpose: "notifications",
  active: true,
  createdAt: "2026-11-26T10:00:00Z",
  canEdit: true,
};

const SITE = { id: "s1", organizationId: "o1", organizationName: "Acme", name: "Main office", timezone: "UTC", notes: "", deviceGroupCount: 0, createdAt: "", updatedAt: "", canManage: true, openNow: null };

const ORG_ADMIN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "org.manage", "user.view", "site.view", "device.view", "notification.manage", "monitoring.view", "monitoring.manage"] });

function routes(extra: Record<string, unknown> = {}, session = ORG_ADMIN) {
  return {
    ...baseRoutes(session),
    "GET /patching/scope": ok({ organizationId: "o1", organizationName: "Acme", siteId: null, siteName: "", devices: 0, byPlatform: [], skipped: [], canManage: false }),
    ...unreportedRoutes(),
    "GET /organizations": ok({ items: [org("o1", "Acme")] }),
    "GET /organizations/:id": ok(org("o1", "Acme")),
    "GET /organizations/:id/sites": ok({ items: [] }),
    "GET /patching": ok({ configured: false }),
    "GET /sites": ok({ items: [SITE] }),
    "GET /sites/s1/device-groups": ok({ items: [] }),
    "GET /notices": ok({ notices: [] }),
    "GET /notifications/channels": ok({ channels: [CHANNEL, SHARED] }),
    "GET /notifications/deliveries": ok({ deliveries: [], retentionDays: 30 }),
    "GET /notifications/quotas/o1": ok({ channels: 20, rules: 50, testsPerHour: 20, messagesPerHour: 600 }),
    "GET /notifications/rules": ok({ rules: [RULE] }),
    "GET /maintenance-windows": ok({ windows: [WINDOW] }),
    "GET /audit": ok({ items: [] }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

async function openTab() {
  renderApp("/organizations/o1?tab=notifications");
  await screen.findByRole("heading", { name: "Rules" });
}

describe("an organization's rules and windows", () => {
  it("lists a rule with what it is about and when, and a window holding now", async () => {
    installFakeApi(routes());
    await openTab();
    const row = (await screen.findByText("Servers offline")).closest("tr")!;
    expect(within(row).getByText(/sites: 1; kinds: server; conditions: offline/)).toBeInTheDocument();
    expect(within(row).getByText(/After 10 min, reminders every 4 h/)).toBeInTheDocument();
    expect(await screen.findByText("Nightly patching")).toBeInTheDocument();
    expect(screen.getByText("Holding now")).toBeInTheDocument();
    expect(screen.getByText("Sat at 22:00 for 4 h")).toBeInTheDocument();
  });

  it("shows a rule whose list was emptied as matching nothing", async () => {
    installFakeApi(routes({ "GET /notifications/rules": ok({ rules: [{ ...RULE, sites: { mode: "list", ids: [] }, matchesNothing: true }] }) }));
    await openTab();
    expect(await screen.findByText("Matches nothing")).toBeInTheDocument();
    expect(screen.getByText(/sites: none left/)).toBeInTheDocument();
  });

  it("creates a rule with its filters, timing and channels", async () => {
    const api = installFakeApi(routes({ "GET /notifications/rules": ok({ rules: [] }), "POST /notifications/rules": { status: 201, body: RULE } }));
    const user = userEvent.setup();
    await openTab();
    await user.click(await screen.findByRole("button", { name: "Add rule" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(/^Name/), "Servers offline");
    const kinds = within(dialog).getByRole("radiogroup", { name: "Kind of device: any or a list" });
    await user.click(within(kinds).getByRole("radio", { name: "List" }));
    await user.click(within(dialog).getByRole("checkbox", { name: "Servers" }));
    const conditions = within(dialog).getByRole("radiogroup", { name: "Condition: any or a list" });
    await user.click(within(conditions).getByRole("radio", { name: "List" }));
    await user.click(within(dialog).getByRole("checkbox", { name: "Offline" }));
    await user.clear(within(dialog).getByLabelText(/Wait before telling/));
    await user.type(within(dialog).getByLabelText(/Wait before telling/), "10");
    await user.click(await within(dialog).findByRole("checkbox", { name: /Service desk/ }));
    await user.click(within(dialog).getByRole("checkbox", { name: /MSP hook/ }));
    await user.click(within(dialog).getByRole("button", { name: "Add rule" }));
    await waitFor(() => expect(api.callsTo("POST /notifications/rules")).toHaveLength(1));
    expect(api.call("POST /notifications/rules").body).toMatchObject({
      organizationId: "o1",
      name: "Servers offline",
      source: "alerts",
      deviceKinds: { mode: "list", values: ["server"] },
      conditions: { mode: "list", values: ["offline"] },
      waitMinutes: 10,
      onResolve: true,
      channelIds: ["c1", "c3"],
    });
  });

  it("says why a rule was refused", async () => {
    installFakeApi(routes({ "GET /notifications/rules": ok({ rules: [] }), "POST /notifications/rules": fail(422, "invalid", "Another rule of this owner has that name.", { name: "Another rule of this owner has that name." }) }));
    const user = userEvent.setup();
    await openTab();
    await user.click(await screen.findByRole("button", { name: "Add rule" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(/^Name/), "Dup");
    await user.click(await within(dialog).findByRole("checkbox", { name: /Service desk/ }));
    await user.click(within(dialog).getByRole("button", { name: "Add rule" }));
    expect((await within(dialog).findAllByText("Another rule of this owner has that name.")).length).toBeGreaterThan(0);
  });

  it("turns a rule off, deletes it and deletes a window", async () => {
    const api = installFakeApi(routes({ "PUT /notifications/rules/r1": ok({ ...RULE, enabled: false }), "DELETE /notifications/rules/r1": noContent, "DELETE /maintenance-windows/w1": noContent }));
    const user = userEvent.setup();
    await openTab();
    await user.click(await screen.findByRole("button", { name: "Turn off" }));
    await waitFor(() => expect(api.call("PUT /notifications/rules/r1").body).toMatchObject({ enabled: false }));
    await user.click(screen.getAllByRole("button", { name: "Delete" })[0]!);
    await user.click(await within(await screen.findByRole("dialog")).findByRole("button", { name: "Delete rule" }));
    await waitFor(() => expect(api.callsTo("DELETE /notifications/rules/r1")).toHaveLength(1));
    await user.click(screen.getAllByRole("button", { name: "Delete" }).at(-1)!);
    await user.click(await within(await screen.findByRole("dialog")).findByRole("button", { name: "Delete window" }));
    await waitFor(() => expect(api.callsTo("DELETE /maintenance-windows/w1")).toHaveLength(1));
  });

  it("adds a weekly window to a site", async () => {
    const api = installFakeApi(routes({ "POST /sites/s1/maintenance-windows": { status: 201, body: WINDOW } }));
    const user = userEvent.setup();
    await openTab();
    await user.click(await screen.findByRole("button", { name: "Add window" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(/^Name/), "Nightly patching");
    await user.click(within(dialog).getByRole("checkbox", { name: "Mon" }));
    await user.click(within(dialog).getByRole("button", { name: "Add window" }));
    await waitFor(() => expect(api.callsTo("POST /sites/s1/maintenance-windows")).toHaveLength(1));
    expect(api.call("POST /sites/s1/maintenance-windows").body).toMatchObject({ name: "Nightly patching", kind: "weekly", days: [6, 1], start: "22:00", lengthMinutes: 240, enabled: true });
  });

  it("adds a one-off window", async () => {
    const api = installFakeApi(routes({ "POST /sites/s1/maintenance-windows": { status: 201, body: { ...WINDOW, kind: "once" } } }));
    const user = userEvent.setup();
    await openTab();
    await user.click(await screen.findByRole("button", { name: "Add window" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText(/^Name/), "Move");
    await user.selectOptions(within(dialog).getByLabelText("Repeats"), "once");
    await user.type(within(dialog).getByLabelText(/^Starts/), "2026-12-01T09:00");
    await user.click(within(dialog).getByRole("button", { name: "Add window" }));
    await waitFor(() => expect(api.callsTo("POST /sites/s1/maintenance-windows")).toHaveLength(1));
    expect(api.call("POST /sites/s1/maintenance-windows").body).toMatchObject({ kind: "once", days: [], startsAt: "2026-12-01T09:00" });
  });
});

describe("Settings: the fleet-wide hold and quarantined changes", () => {
  const SILENCE: FleetSilence = { id: "f1", startedAt: new Date(Date.now() - 600_000).toISOString(), counted: 41 };
  const ROW: QuarantinedRow = { id: 7, subjectType: "alert", subjectId: "a1", event: "opened", error: "reading the journal row", failedRuns: 3, createdAt: "2026-11-26T10:00:00Z", held: 2 };

  function settings(extra: Record<string, unknown> = {}) {
    return routes({
      "GET /settings/mail-server": ok({ inForce: "none", limits: { perMinute: 30, perDay: 9000, account: { adminPerHour: 60, organizationPerDay: 500, accountBurst: 3, accountEveryMinutes: 20, resetsPerHour: 30, organizationResetsPerHour: 10 } }, usage: { lastMinute: 0, lastDay: 0, accountLastDay: 0, adminDayLimit: 8100, otherDayLimit: 7200 } }),
      "GET /notifications/rules": ok({ rules: [{ ...RULE, organizationId: null, platform: true, organizations: { mode: "list", ids: ["o1"] } }] }),
      "GET /notifications/silence": ok({ silence: SILENCE }),
      "GET /notifications/quarantined": ok({ rows: [ROW] }),
      ...extra,
    }, sessionView());
  }

  it("shows the hold and ends it", async () => {
    const api = installFakeApi({ ...settings(), "POST /notifications/silence/end": noContent });
    const user = userEvent.setup();
    renderApp("/settings?tab=notifications");
    expect(await screen.findByText("Most devices stopped checking in at once")).toBeInTheDocument();
    expect(screen.getByText(/41 devices that had been checking in/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "End now" }));
    await waitFor(() => expect(api.callsTo("POST /notifications/silence/end")).toHaveLength(1));
  });

  it("says no hold is in force", async () => {
    installFakeApi(settings({ "GET /notifications/silence": ok({ silence: null }), "GET /notifications/quarantined": ok({ rows: [] }) }));
    renderApp("/settings?tab=notifications");
    expect(await screen.findByText(/No hold is in force/)).toBeInTheDocument();
    expect(await screen.findByText("Nothing is set aside")).toBeInTheDocument();
  });

  it("retries and discards a quarantined change", async () => {
    const api = installFakeApi({ ...settings(), "POST /notifications/quarantined/7/retry": noContent, "POST /notifications/quarantined/7/discard": noContent });
    const user = userEvent.setup();
    renderApp("/settings?tab=notifications");
    const row = (await screen.findByText("reading the journal row")).closest("tr")!;
    expect(within(row).getByText("2")).toBeInTheDocument();
    await user.click(within(row).getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(api.callsTo("POST /notifications/quarantined/7/retry")).toHaveLength(1));
    await user.click(within(row).getByRole("button", { name: "Discard" }));
    await waitFor(() => expect(api.callsTo("POST /notifications/quarantined/7/discard")).toHaveLength(1));
  });

  it("lists the platform's rules and windows, windows read-only", async () => {
    installFakeApi(settings());
    renderApp("/settings?tab=notifications");
    await screen.findByText("Servers offline");
    expect(await screen.findByText("Nightly patching")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add window" })).not.toBeInTheDocument();
    expect(screen.getByText(/organizations: 1; sites: 1/)).toBeInTheDocument();
  });
});
