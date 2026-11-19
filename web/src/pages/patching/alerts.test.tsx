import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  AuditEntry,
  PatchAlert,
  PatchAlertRule,
  PatchAlertRuleList,
  PatchAlertRuleType,
  PatchChannel,
  PatchDelivery,
  PatchNotifications,
  PatchStatus,
  PatchTag,
} from "../../api/types";
import { auditTarget } from "../../components/StatusBadges";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, type FakeHandler, type FakeReply, type FakeRequest } from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { deliveryError } from "./Notifications";
import { acknowledgedBy, thresholdText } from "./patchAlertText";

// EasyPatch's alerts under Patching → Alerts, and its alert rules and notification channels under Settings → Patching
// (one-product plan, C7).

const main = () => within(screen.getByRole("main"));

async function open(path: string) {
  renderApp(path);
  await screen.findByRole("main");
}

const READY: PatchStatus = { configured: true, canOperate: true, canSchedule: false, bundled: true };

const SUPER = sessionView({
  permissions: ["org.view", "site.view", "device.view", "settings.manage", "audit.view", "patch.view", "patch.manage", "patch.configure"],
  globalPermissions: ["org.view", "site.view", "device.view", "audit.view", "patch.view", "patch.manage", "patch.configure"],
});
const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "patch.view", "patch.manage"] });
const VIEWER = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "patch.view"] });
/** Configures patching in its organizations; not a super administrator. */
const ORG_ADMIN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "patch.view", "patch.manage", "patch.configure"] });

const HOUR = 3600_000;
const ago = (hours: number) => new Date(Date.now() - hours * HOUR).toISOString();

function alert(id: string, extra: Partial<PatchAlert> = {}): PatchAlert {
  return {
    id,
    ruleId: "r1",
    ruleName: "Device offline",
    ruleType: "EndpointOffline",
    severity: "Warning",
    status: "Open",
    title: `Alert ${id}`,
    details: null,
    organizationId: "o1",
    organizationName: "Acme",
    hostname: null,
    openedAt: ago(5),
    lastSeenAt: ago(5),
    resolvedAt: null,
    acknowledgedAt: null,
    acknowledgedBy: null,
    canAcknowledge: true,
    ...extra,
  };
}

const ALERTS: PatchAlert[] = [
  alert("a1", {
    severity: "Critical",
    ruleType: "KnownExploitedMissing",
    ruleName: "Exploited, Acme servers",
    title: "WEB-01 misses an update for an exploited vulnerability",
    details: "KB5044284 fixes CVE-2026-1234.",
    deviceId: "d1",
    deviceName: "WEB-01",
    hostname: "WEB-01",
    lastSeenAt: ago(1),
  }),
  alert("a2", { title: "DB-01 has been offline for 26 hours", deviceId: "d2", deviceName: "DB-01", hostname: "DB-01" }),
  alert("a3", {
    ruleType: "UpdateHeld",
    ruleName: "Update on hold",
    title: "2 updates Acme needs are on hold",
    canAcknowledge: false,
  }),
  alert("a4", {
    severity: "Info",
    ruleType: "RestartPending",
    ruleName: "Restart pending",
    title: "KIOSK-7 has waited 9 days for a restart",
    hostname: "KIOSK-7",
    status: "Acknowledged",
    acknowledgedBy: "easyrmm:otto@example.com",
    acknowledgedAt: ago(2),
    canAcknowledge: false,
  }),
];

function patchingRoutes(session = TECH, extra: Record<string, FakeHandler | FakeReply> = {}) {
  return {
    ...baseRoutes(session),
    "GET /patching": ok(READY),
    "GET /organizations": ok({ items: [org("o1", "Acme"), org("o2", "Globex")] }),
    "GET /patching/alerts": ok({ items: ALERTS, capped: false }),
    ...extra,
  };
}

describe("Patching → Alerts", () => {
  it("lists the alerts worst first, filters them and acknowledges them one at a time or together", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      patchingRoutes(TECH, {
        // The second time, someone else has acknowledged one of the two first.
        "POST /patching/alerts/acknowledge": ok({ acknowledged: 1 }),
      }),
    );
    await open("/patching?tab=alerts");
    expect(await main().findByRole("tab", { name: "Alerts", selected: true })).toBeInTheDocument();
    const table = await main().findByRole("table", { name: "Patching alerts" });
    const row = (title: string) => within(table).getByText(title).closest("tr") as HTMLElement;

    const exploited = row("WEB-01 misses an update for an exploited vulnerability");
    expect(within(exploited).getByText("Critical")).toBeInTheDocument();
    expect(within(exploited).getByText("KB5044284 fixes CVE-2026-1234.")).toBeInTheDocument();
    expect(within(exploited).getByText("Exploited vulnerability unpatched · Exploited, Acme servers")).toBeInTheDocument();
    expect(within(exploited).getAllByRole("link", { name: "WEB-01" })[0]).toHaveAttribute("href", "/devices/d1?tab=patches");
    expect(within(exploited).getByText(/^seen /)).toBeInTheDocument();
    // An organization's alert, and an endpoint EasyRMM has no device for.
    expect(within(row("2 updates Acme needs are on hold")).getAllByText("The whole organization")).toHaveLength(2); // the column, and under the alert on a phone
    expect(within(row("2 updates Acme needs are on hold")).queryByRole("button", { name: /Acknowledge/ })).not.toBeInTheDocument();
    const kiosk = row("KIOSK-7 has waited 9 days for a restart");
    expect(within(kiosk).getAllByText("Acme, no EasyRMM device")).toHaveLength(2);
    expect(within(kiosk).getByText("Acknowledged")).toBeInTheDocument();
    expect(within(kiosk).getByText(/by otto@example\.com/)).toBeInTheDocument();
    // The rule's name is left out when it is the type's own.
    expect(within(row("DB-01 has been offline for 26 hours")).getByText("Device offline")).toBeInTheDocument();

    // Filters go to the server.
    await user.selectOptions(main().getByRole("combobox", { name: "Show" }), "Resolved");
    await user.selectOptions(main().getByRole("combobox", { name: "Severity" }), "Critical");
    await user.selectOptions(main().getByRole("combobox", { name: "Type" }), "Restart pending");
    await user.selectOptions(main().getByRole("combobox", { name: "Organization" }), "Globex");
    await user.type(main().getByRole("searchbox", { name: "Search" }), "kiosk");
    await waitFor(() => expect(server.callsTo("GET /patching/alerts").at(-1)!.query.get("search")).toBe("kiosk"));
    const q = server.callsTo("GET /patching/alerts").at(-1)!.query;
    expect(Object.fromEntries(q)).toEqual({ status: "resolved", severity: "Critical", ruleType: "RestartPending", organizationId: "o2", search: "kiosk" });
    await user.selectOptions(main().getByRole("combobox", { name: "Show" }), "Needs attention");
    await user.selectOptions(main().getByRole("combobox", { name: "Severity" }), "Any severity");
    await user.selectOptions(main().getByRole("combobox", { name: "Type" }), "Any type");
    await user.clear(main().getByRole("searchbox", { name: "Search" }));
    await waitFor(() => expect(server.callsTo("GET /patching/alerts").at(-1)!.query.get("search")).toBeNull());

    // One at a time.
    await user.click(within(row("DB-01 has been offline for 26 hours")).getByRole("button", { name: "Acknowledge DB-01 has been offline for 26 hours" }));
    expect(await screen.findByText("1 alert acknowledged.")).toBeInTheDocument();
    expect(server.call("POST /patching/alerts/acknowledge").body).toEqual({ alertIds: ["a2"] });

    // Together: select-all takes only those the caller may acknowledge.
    expect(main().getByText("Select alerts to acknowledge them together.")).toBeInTheDocument();
    const all = main().getByRole("checkbox", { name: "Select every alert you can acknowledge" });
    await user.click(all);
    expect(main().getByText("2 alerts selected")).toBeInTheDocument();
    await user.click(main().getByRole("checkbox", { name: "Select WEB-01 misses an update for an exploited vulnerability" }));
    expect(all).toHaveProperty("indeterminate", true);
    await user.click(main().getByRole("checkbox", { name: "Select WEB-01 misses an update for an exploited vulnerability" }));
    await user.click(main().getByRole("button", { name: "Acknowledge" }));
    // Someone acknowledged one first: said, not hidden.
    expect(await screen.findByText("1 alert acknowledged; the rest were acknowledged or resolved already.")).toBeInTheDocument();
    expect(server.call("POST /patching/alerts/acknowledge", 1).body).toEqual({ alertIds: ["a1", "a2"] });
    expect(main().getByText("Select alerts to acknowledge them together.")).toBeInTheDocument();
  });

  it("says why an acknowledgement failed", async () => {
    const user = userEvent.setup();
    installFakeApi(patchingRoutes(TECH, { "POST /patching/alerts/acknowledge": fail(503, "easypatch_unavailable", "EasyPatch did not answer.") }));
    await open("/patching?tab=alerts");
    await user.click(await main().findByRole("checkbox", { name: "Select DB-01 has been offline for 26 hours" }));
    await user.click(main().getByRole("button", { name: "Acknowledge" }));
    expect(await main().findByText("EasyPatch did not answer.")).toBeInTheDocument();
  });

  it("shows one device's alerts, and lets the caller go back to every device", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(patchingRoutes(TECH, { "GET /patching/alerts": (r) => ok({ items: r.query.get("deviceId") ? [ALERTS[0]] : ALERTS, capped: false }) }));
    await open("/patching?tab=alerts&deviceId=d1");
    expect(await main().findByText("Alerts of WEB-01")).toBeInTheDocument();
    expect(server.call("GET /patching/alerts").query.get("deviceId")).toBe("d1");
    await user.click(main().getByRole("button", { name: "Show every device" }));
    await waitFor(() => expect(main().queryByText(/Alerts of/)).not.toBeInTheDocument());
    expect(server.callsTo("GET /patching/alerts").at(-1)!.query.get("deviceId")).toBeNull();
  });

  it("lets those who only view patching see alerts without acknowledging them", async () => {
    installFakeApi(patchingRoutes(VIEWER, { "GET /patching/alerts": ok({ items: ALERTS.map((a) => ({ ...a, canAcknowledge: false })), capped: true }) }));
    await open("/patching?tab=alerts");
    await main().findByRole("table", { name: "Patching alerts" });
    expect(main().queryByRole("checkbox")).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: /^Acknowledge/ })).not.toBeInTheDocument();
    expect(main().getByText(/These are the first 4 that match, the most severe first/)).toBeInTheDocument();
  });

  it("says when nothing needs attention, and when nothing matches the filters", async () => {
    const user = userEvent.setup();
    installFakeApi(patchingRoutes(TECH, { "GET /patching/alerts": ok({ items: [], capped: false }) }));
    await open("/patching?tab=alerts");
    expect(await main().findByText("Nothing needs attention")).toBeInTheDocument();
    await user.selectOptions(main().getByRole("combobox", { name: "Severity" }), "Info");
    expect(await main().findByText("No alerts match")).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Clear filters" }));
    expect(await main().findByText("Nothing needs attention")).toBeInTheDocument();
  });
});

// Settings → Patching → Alert rules and Notifications.

const TYPES: PatchAlertRuleType[] = [
  { type: "EndpointOffline", thresholdUnit: "hours", thresholdMin: 1, thresholdMax: 720, thresholdDefault: 24, supportsTag: true },
  { type: "InstallFailed", thresholdUnit: null, thresholdMin: null, thresholdMax: null, thresholdDefault: null, supportsTag: true },
  { type: "SecurityUpdateMissing", thresholdUnit: "days", thresholdMin: 0, thresholdMax: 365, thresholdDefault: 14, supportsTag: true },
  { type: "ScanStale", thresholdUnit: null, thresholdMin: null, thresholdMax: null, thresholdDefault: null, supportsTag: true },
  { type: "RestartPending", thresholdUnit: "days", thresholdMin: 1, thresholdMax: 90, thresholdDefault: 7, supportsTag: true },
  { type: "EnrollmentPending", thresholdUnit: null, thresholdMin: null, thresholdMax: null, thresholdDefault: null, supportsTag: false },
  { type: "OsUnsupported", thresholdUnit: "days", thresholdMin: 0, thresholdMax: 365, thresholdDefault: 30, supportsTag: true },
  { type: "KnownExploitedMissing", thresholdUnit: null, thresholdMin: null, thresholdMax: null, thresholdDefault: null, supportsTag: true },
  { type: "UpdateHeld", thresholdUnit: null, thresholdMin: null, thresholdMax: null, thresholdDefault: null, supportsTag: false },
];

function rule(id: string, extra: Partial<PatchAlertRule> = {}): PatchAlertRule {
  return {
    id,
    name: `Rule ${id}`,
    type: "EndpointOffline",
    enabled: true,
    severity: "Warning",
    threshold: 24,
    thresholdUnit: "hours",
    organizationId: null,
    tagId: null,
    channelIds: [],
    notifyOnResolve: false,
    renotifyHours: 0,
    unresolvedAlerts: 0,
    updatedAt: ago(10),
    ...extra,
  };
}

const RULES: PatchAlertRule[] = [
  rule("r1", { name: "Device offline", unresolvedAlerts: 2, channelIds: ["c1", "gone"], renotifyHours: 24, notifyOnResolve: true }),
  rule("r2", {
    name: "Exploited, Acme servers",
    type: "KnownExploitedMissing",
    severity: "Critical",
    threshold: null,
    thresholdUnit: null,
    organizationId: "o1",
    organizationName: "Acme",
    tagId: "t2",
    tagName: "Servers",
  }),
  rule("r3", { name: "Old platform", type: "OsUnsupported", threshold: 0, thresholdUnit: "days", enabled: false, unlinkedOrganization: true }),
];

const TAGS: PatchTag[] = [
  { id: "t1", name: "Pilot ring", color: "amber", description: null, priority: 50, endpointCount: 3, siteCount: 1, organizationCount: 0, hasPolicy: true, createdAt: ago(100) },
  { id: "t2", name: "Servers", color: "teal", description: null, priority: 10, endpointCount: 0, siteCount: 0, organizationCount: 2, hasPolicy: false, createdAt: ago(100) },
];

function channel(id: string, extra: Partial<PatchChannel> = {}): PatchChannel {
  return {
    id,
    name: `Channel ${id}`,
    type: "Email",
    enabled: true,
    emailRecipients: ["ops@example.com"],
    webhookFormat: null,
    webhookHost: null,
    hasSigningSecret: false,
    createdAt: ago(100),
    updatedAt: ago(100),
    lastDelivery: null,
    ...extra,
  };
}

const CHANNELS: PatchChannel[] = [
  channel("c1", {
    name: "Service desk",
    emailRecipients: ["desk@example.com", "oncall@example.com"],
    lastDelivery: { status: "Failed", createdAt: ago(1), lastError: "The mail server refused the sender." },
  }),
  channel("c2", { name: "Ops chat", type: "Webhook", emailRecipients: [], webhookFormat: "Slack", webhookHost: "hooks.slack.com", lastDelivery: { status: "Sent", createdAt: ago(3), lastError: null } }),
  channel("c3", { name: "PSA", type: "Webhook", emailRecipients: [], webhookFormat: "Generic", webhookHost: "psa.example.com", hasSigningSecret: true, enabled: false }),
];

const RULE_LIST: PatchAlertRuleList = {
  items: RULES,
  types: TYPES,
  channels: CHANNELS.map(({ id, name, type, enabled }) => ({ id, name, type, enabled })),
};

const MAIL = { host: "smtp.example.com", port: 587, security: "StartTls", fromAddress: "rmm@example.com", fromName: "EasyRMM" };

function delivery(id: string, extra: Partial<PatchDelivery> = {}): PatchDelivery {
  return {
    id,
    channelId: "c1",
    channelName: "Service desk",
    kind: "AlertsOpened",
    subject: "[Warning] DB-01 has been offline for 26 hours",
    status: "Sent",
    attempts: 1,
    lastError: null,
    createdAt: ago(2),
    nextAttemptAt: ago(2),
    sentAt: ago(2),
    ...extra,
  };
}

function settingsRoutes(session = SUPER, extra: Record<string, FakeHandler | FakeReply> = {}) {
  return {
    ...baseRoutes(session),
    "GET /patching": ok(READY),
    "GET /organizations": ok({ items: [org("o1", "Acme"), org("o2", "Globex")] }),
    "GET /patching/alert-rules": ok(RULE_LIST),
    "GET /patching/tags": ok({ items: TAGS, canManage: true }),
    "GET /patching/notifications": ok({ channels: CHANNELS, mail: MAIL, allowPrivateNetworkWebhooks: false } satisfies PatchNotifications),
    "GET /patching/notifications/deliveries": (r: FakeRequest) =>
      ok({
        items: r.query.get("page") === "2" ? [delivery("m51", { kind: "Test", subject: "Test from EasyPatch" })] : [delivery("m1"), delivery("m2", { status: "Failed", attempts: 3, lastError: "Connection refused." })],
        page: Number(r.query.get("page") ?? 1),
        pageSize: 50,
        totalCount: 51,
      }),
    ...extra,
  };
}

describe("Settings → Patching → Alert rules", () => {
  it("lists the rules, with what they look for, cover and send to", async () => {
    installFakeApi(settingsRoutes());
    await open("/settings?tab=patching&view=rules");
    const table = await main().findByRole("table", { name: "Alert rules" });
    const row = (name: string) => within(table).getByRole("button", { name: `Edit ${name}` }).closest("tr") as HTMLElement;
    const offline = row("Device offline");
    expect(within(offline).getByText("Offline for 24 hours or more")).toBeInTheDocument();
    expect(within(offline).getAllByText("Every organization")).toHaveLength(2); // the column, and under the name on a narrow screen
    expect(within(offline).getByText("Service desk, A deleted channel")).toBeInTheDocument();
    expect(within(offline).getByText("again every 24 hours, and when resolved")).toBeInTheDocument();
    expect(within(offline).getByRole("link", { name: "2" })).toHaveAttribute("href", "/patching?tab=alerts&ruleType=EndpointOffline");
    const exploited = row("Exploited, Acme servers");
    expect(within(exploited).getByText("Critical")).toBeInTheDocument();
    expect(within(exploited).getAllByText("Acme, devices tagged Servers")).toHaveLength(2);
    expect(within(exploited).getByText("Whenever it happens")).toBeInTheDocument();
    expect(within(exploited).getByText("Patching → Alerts only")).toBeInTheDocument();
    const old = row("Old platform");
    expect(within(old).getByText("Off")).toBeInTheDocument();
    expect(within(old).getByText("Once support has ended")).toBeInTheDocument();
    expect(within(old).getAllByText("An EasyPatch organization EasyRMM does not link")).toHaveLength(2);
  });

  it("adds a rule, checking it as EasyPatch does", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      settingsRoutes(SUPER, {
        "POST /patching/alert-rules": (r) => {
          const b = r.body as PatchAlertRule;
          return b.name === "Taken"
            ? fail(422, "validation_failed", "Check the highlighted fields.", { name: "A rule of this name exists." })
            : { status: 201, body: rule("r9", b) };
        },
      }),
    );
    await open("/settings?tab=patching&view=rules");
    await user.click(await main().findByRole("button", { name: "Add rule" }));
    const dialog = await screen.findByRole("dialog", { name: "Add alert rule" });
    const d = within(dialog);
    expect(d.getByText("The device's EasyPatch agent has not checked in for a while.")).toBeInTheDocument();
    expect(d.getByRole("spinbutton", { name: /After how many hours/ })).toHaveValue(24);

    // Nothing to save until it is right.
    const threshold = d.getByRole("spinbutton", { name: /After how many hours/ });
    await user.clear(threshold);
    await user.type(threshold, "800");
    await user.click(d.getByRole("button", { name: "Add rule" }));
    expect(d.getByText("Name the rule.")).toBeInTheDocument();
    expect(d.getByText("Choose from 1 to 720 hours.")).toBeInTheDocument();
    expect(server.callsTo("POST /patching/alert-rules")).toHaveLength(0);

    // Another type takes its own threshold, and an organization's own alert takes no tag.
    await user.selectOptions(d.getByRole("combobox", { name: /Raises an alert when/ }), "Update on hold");
    expect(d.queryByRole("spinbutton", { name: /After how many/ })).not.toBeInTheDocument();
    expect(d.getByRole("combobox", { name: /Devices/ })).toBeDisabled();
    expect(d.getByText("This rule looks at organizations, not devices.")).toBeInTheDocument();
    await user.selectOptions(d.getByRole("combobox", { name: /Raises an alert when/ }), "Operating system unsupported");
    expect(d.getByRole("spinbutton", { name: /Days before support ends/ })).toHaveValue(30);
    await user.selectOptions(d.getByRole("combobox", { name: /Devices/ }), "Tagged Pilot ring");
    await user.selectOptions(d.getByRole("combobox", { name: "Severity" }), "Critical");
    await user.selectOptions(d.getByRole("combobox", { name: "Organization" }), "Globex");
    await user.click(d.getByRole("checkbox", { name: /Ops chat/ }));
    await user.click(d.getByRole("checkbox", { name: /PSA/ }));
    await user.click(d.getByRole("checkbox", { name: /PSA/ }));
    const again = d.getByRole("spinbutton", { name: /Send again every/ });
    await user.clear(again);
    await user.type(again, "1000");
    await user.type(d.getByRole("textbox", { name: /Name/ }), "Taken");
    await user.click(d.getByRole("button", { name: "Add rule" }));
    expect(d.getByText("Choose from 0 to 720 hours.")).toBeInTheDocument();
    await user.clear(again);
    await user.type(again, "12");
    await user.click(d.getByRole("checkbox", { name: "Also send when the alert resolves" }));
    await user.click(d.getByRole("button", { name: "Add rule" }));
    expect(await d.findByText("A rule of this name exists.")).toBeInTheDocument();
    const name = d.getByRole("textbox", { name: /Name/ });
    await user.clear(name);
    await user.type(name, "  Unsupported OS, pilot  ");
    await user.click(d.getByRole("button", { name: "Add rule" }));
    expect(await screen.findByText("Unsupported OS, pilot added.")).toBeInTheDocument();
    expect(server.call("POST /patching/alert-rules", 1).body).toEqual({
      name: "Unsupported OS, pilot",
      type: "OsUnsupported",
      enabled: true,
      severity: "Critical",
      threshold: 30,
      organizationId: "o2",
      tagId: "t1",
      channelIds: ["c2"],
      notifyOnResolve: true,
      renotifyHours: 12,
    });
  });

  it("edits a rule, and says when it covers an organization EasyRMM does not link", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      settingsRoutes(SUPER, {
        "PUT /patching/alert-rules/:id": (r) =>
          (r.body as PatchAlertRule).organizationId === null
            ? fail(422, "validation_failed", "Check the highlighted fields.", { organizationId: "Choose the organization this rule covers." })
            : ok(rule(r.params.id ?? "", r.body as PatchAlertRule)),
      }),
    );
    await open("/settings?tab=patching&view=rules");
    await user.click(await main().findByRole("button", { name: "Edit Old platform" }));
    let dialog = within(await screen.findByRole("dialog", { name: "Edit alert rule" }));
    expect(dialog.getByText(/covers an EasyPatch organization EasyRMM does not link/)).toBeInTheDocument();
    expect(dialog.getByRole("spinbutton", { name: /Days before support ends/ })).toHaveValue(0);
    expect(dialog.getByRole("checkbox", { name: "Check this rule" })).not.toBeChecked();
    await user.click(dialog.getByRole("button", { name: "Save rule" }));
    expect(await dialog.findByText("Choose the organization this rule covers.")).toBeInTheDocument();
    await user.selectOptions(dialog.getByRole("combobox", { name: "Organization" }), "Acme");
    await user.click(dialog.getByRole("checkbox", { name: "Check this rule" }));
    await user.click(dialog.getByRole("button", { name: "Save rule" }));
    expect(await screen.findByText("Old platform saved.")).toBeInTheDocument();
    expect(server.call("PUT /patching/alert-rules/:id", 1).path).toBe("/patching/alert-rules/r3");
    expect(server.call("PUT /patching/alert-rules/:id", 1).body).toMatchObject({ organizationId: "o1", enabled: true, threshold: 0 });

    // A rule's tag and channels come back as they were.
    await user.click(main().getByRole("button", { name: "Edit Exploited, Acme servers" }));
    dialog = within(await screen.findByRole("dialog", { name: "Edit alert rule" }));
    expect(dialog.getByRole("combobox", { name: /Devices/ })).toHaveValue("t2");
    expect(dialog.getByRole("combobox", { name: "Organization" })).toHaveValue("o1");
    await user.click(dialog.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("deletes a rule", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(settingsRoutes(SUPER, { "DELETE /patching/alert-rules/:id": noContent }));
    await open("/settings?tab=patching&view=rules");
    await user.click(await main().findByRole("button", { name: "Delete Device offline" }));
    const dialog = await screen.findByRole("dialog", { name: "Delete rule" });
    expect(dialog).toHaveTextContent("EasyPatch stops checking Device offline and resolves its 2 open alerts.");
    await user.click(within(dialog).getByRole("button", { name: "Delete rule" }));
    expect(await screen.findByText("Device offline deleted.")).toBeInTheDocument();
    expect(server.call("DELETE /patching/alert-rules/:id").path).toBe("/patching/alert-rules/r1");
  });

  it("says when there are no rules", async () => {
    installFakeApi(settingsRoutes(SUPER, { "GET /patching/alert-rules": ok({ ...RULE_LIST, items: [] }) }));
    await open("/settings?tab=patching&view=rules");
    expect(await main().findByText("No alert rules")).toBeInTheDocument();
  });

  it("with a connected EasyPatch server, says its console keeps them", async () => {
    const reason = "With a connected EasyPatch server, its alert rules and notification channels are kept in EasyPatch's own console.";
    installFakeApi(
      settingsRoutes(SUPER, {
        "GET /patching/alert-rules": fail(409, "easypatch_server_wide", reason),
        "GET /patching/notifications": fail(409, "easypatch_server_wide", reason),
      }),
    );
    await open("/settings?tab=patching&view=rules");
    expect(await main().findByText(reason)).toBeInTheDocument();
    expect(main().getByText("Set in EasyPatch")).toBeInTheDocument();
    expect(main().queryByRole("button", { name: /retry/i })).not.toBeInTheDocument();
  });

  it("is only for super administrators", async () => {
    installFakeApi(
      settingsRoutes(ORG_ADMIN, {
        "GET /patching/policies/default": ok({}),
        "GET /patching/policies": ok({ items: [] }),
      }),
    );
    await open("/settings?tab=patching&view=rules");
    const show = await main().findByRole("combobox", { name: "Show" });
    expect(within(show).queryByRole("option", { name: "Alert rules" })).not.toBeInTheDocument();
    expect(within(show).queryByRole("option", { name: "Notifications" })).not.toBeInTheDocument();
  });
});

describe("Settings → Patching → Notifications", () => {
  it("lists the channels and the mail server, and allows webhooks to private networks", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      settingsRoutes(SUPER, {
        "PUT /patching/notifications": (r) => ok({ channels: CHANNELS, mail: MAIL, allowPrivateNetworkWebhooks: (r.body as { allowPrivateNetworkWebhooks: boolean }).allowPrivateNetworkWebhooks }),
      }),
    );
    await open("/settings?tab=patching&view=notifications");
    const table = await main().findByRole("table", { name: "Notification channels" });
    const row = (name: string) => within(table).getByText(name).closest("tr") as HTMLElement;
    expect(within(row("Service desk")).getByText("desk@example.com, oncall@example.com")).toBeInTheDocument();
    // Each last message shows in its column, and under the channel on a phone.
    expect(within(row("Service desk")).getAllByText("The mail server refused the sender.")).toHaveLength(2);
    expect(within(row("Ops chat")).getByText("Slack to hooks.slack.com")).toBeInTheDocument();
    expect(within(row("Ops chat")).getAllByText("Sent")).toHaveLength(2);
    expect(within(row("PSA")).getByText("Off")).toBeInTheDocument();
    expect(within(row("PSA")).getAllByText("Nothing sent yet")).toHaveLength(2);
    // Only a generic webhook has a signing key.
    expect(within(row("PSA")).getByRole("button", { name: "New signing key for PSA" })).toBeInTheDocument();
    expect(within(row("Ops chat")).queryByRole("button", { name: /signing key/ })).not.toBeInTheDocument();

    expect(main().getByText("smtp.example.com:587")).toBeInTheDocument();
    expect(main().getByText(/\(STARTTLS\), from EasyRMM <rmm@example\.com>/)).toBeInTheDocument();
    const allow = main().getByRole("checkbox", { name: "Allow webhooks to private network addresses" });
    expect(allow).not.toBeChecked();
    await user.click(allow);
    expect(await screen.findByText("Webhooks to private networks allowed.")).toBeInTheDocument();
    expect(server.call("PUT /patching/notifications").body).toEqual({ allowPrivateNetworkWebhooks: true });
  });

  it("warns that email cannot send without a mail server", async () => {
    installFakeApi(settingsRoutes(SUPER, { "GET /patching/notifications": ok({ channels: CHANNELS, mail: { ...MAIL, host: "", port: 0 }, allowPrivateNetworkWebhooks: true }) }));
    await open("/settings?tab=patching&view=notifications");
    const table = await main().findByRole("table", { name: "Notification channels" });
    // The warning, and the one email channel's badge.
    expect(main().getAllByText("No mail server")).toHaveLength(2);
    expect(within(table).getAllByText("No mail server")).toHaveLength(1);
    expect(main().getByRole("checkbox", { name: "Allow webhooks to private network addresses" })).toBeChecked();
  });

  it("adds an email channel, and a webhook whose signing key it shows once", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      settingsRoutes(SUPER, {
        "POST /patching/notifications/channels": (r) => {
          const b = r.body as PatchChannel & { webhookUrl: string | null };
          const saved = channel("c9", { ...b, webhookHost: b.webhookUrl ? new URL(b.webhookUrl).host : null, hasSigningSecret: b.webhookFormat === "Generic" });
          return { status: 201, body: { channel: saved, signingSecret: b.webhookFormat === "Generic" ? "whsec_0123456789abcdef" : null } };
        },
      }),
    );
    await open("/settings?tab=patching&view=notifications");
    await user.click(await main().findByRole("button", { name: "Add channel" }));
    let dialog = within(await screen.findByRole("dialog", { name: "Add channel" }));
    await user.click(dialog.getByRole("button", { name: "Add channel" }));
    expect(dialog.getByText("Name the channel.")).toBeInTheDocument();
    expect(dialog.getByText("Enter at least one email address.")).toBeInTheDocument();
    await user.type(dialog.getByRole("textbox", { name: /Name/ }), "Night shift");
    await user.type(dialog.getByRole("textbox", { name: /Recipients/ }), "a@example.com, b@example.com\nc@example.com");
    await user.click(dialog.getByRole("button", { name: "Add channel" }));
    expect(await screen.findByText("Night shift added.")).toBeInTheDocument();
    expect(server.call("POST /patching/notifications/channels").body).toEqual({
      name: "Night shift",
      type: "Email",
      enabled: true,
      emailRecipients: ["a@example.com", "b@example.com", "c@example.com"],
      webhookFormat: null,
      webhookUrl: null,
    });

    await user.click(main().getByRole("button", { name: "Add channel" }));
    dialog = within(await screen.findByRole("dialog", { name: "Add channel" }));
    await user.type(dialog.getByRole("textbox", { name: /Name/ }), "Ticketing");
    await user.selectOptions(dialog.getByRole("combobox", { name: /Sends by/ }), "Webhook");
    await user.selectOptions(dialog.getByRole("combobox", { name: "Format" }), "Generic JSON, signed");
    await user.type(dialog.getByRole("textbox", { name: /Address/ }), "http://psa.example.com/hook");
    await user.click(dialog.getByRole("button", { name: "Add channel" }));
    expect(dialog.getByText("Enter the webhook's https:// address.")).toBeInTheDocument();
    await user.clear(dialog.getByRole("textbox", { name: /Address/ }));
    await user.type(dialog.getByRole("textbox", { name: /Address/ }), "https://psa.example.com/hook?key=s3cret");
    await user.click(dialog.getByRole("button", { name: "Add channel" }));
    const secret = await screen.findByRole("dialog", { name: "Signing key for Ticketing" });
    expect(within(secret).getByText("whsec_0123456789abcdef")).toBeInTheDocument();
    expect(secret).toHaveTextContent("it is not shown again");
    expect(server.call("POST /patching/notifications/channels", 1).body).toEqual({
      name: "Ticketing",
      type: "Webhook",
      enabled: true,
      emailRecipients: [],
      webhookFormat: "Generic",
      webhookUrl: "https://psa.example.com/hook?key=s3cret",
    });
    await user.click(within(secret).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("edits a webhook without showing its address, keeping it unless a new one is entered", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      settingsRoutes(SUPER, {
        "PUT /patching/notifications/channels/:id": (r) =>
          (r.body as { name: string }).name === "Bad"
            ? fail(422, "validation_failed", "Check the highlighted fields.", { webhookUrl: "EasyPatch could not reach this address." })
            : ok({ channel: channel(r.params.id ?? "", r.body as PatchChannel), signingSecret: null }),
      }),
    );
    await open("/settings?tab=patching&view=notifications");
    await user.click(await main().findByRole("button", { name: "Edit Ops chat" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Edit channel" }));
    expect(dialog.getByRole("textbox", { name: /Address/ })).toHaveValue("");
    expect(dialog.getByText(/Leave empty to keep the address at hooks\.slack\.com/)).toBeInTheDocument();
    expect(dialog.getByRole("combobox", { name: /Sends by/ })).toBeDisabled();
    const name = dialog.getByRole("textbox", { name: /Name/ });
    await user.clear(name);
    await user.type(name, "Bad");
    await user.click(dialog.getByRole("button", { name: "Save channel" }));
    expect(await dialog.findByText("EasyPatch could not reach this address.")).toBeInTheDocument();
    await user.clear(name);
    await user.type(name, "Ops channel");
    await user.click(dialog.getByRole("checkbox", { name: "Send messages to this channel" }));
    await user.click(dialog.getByRole("button", { name: "Save channel" }));
    expect(await screen.findByText("Ops channel saved.")).toBeInTheDocument();
    expect(server.call("PUT /patching/notifications/channels/:id", 1).path).toBe("/patching/notifications/channels/c2");
    expect(server.call("PUT /patching/notifications/channels/:id", 1).body).toEqual({
      name: "Ops channel",
      type: "Webhook",
      enabled: false,
      emailRecipients: [],
      webhookFormat: "Slack",
      webhookUrl: null,
    });
  });

  it("sends a test, makes a new signing key and deletes a channel", async () => {
    const user = userEvent.setup();
    let tests = 0;
    const server = installFakeApi(
      settingsRoutes(SUPER, {
        "POST /patching/notifications/channels/:id/test": () =>
          ++tests === 1 ? { status: 202, body: delivery("m9", { kind: "Test", status: "Pending" }) } : fail(409, "easypatch_test_too_soon", "Wait a minute between tests of a channel."),
        "POST /patching/notifications/channels/:id/rotate-secret": (r) => ok({ channel: CHANNELS[2], signingSecret: `new-${r.params.id}` }),
        "DELETE /patching/notifications/channels/:id": noContent,
      }),
    );
    await open("/settings?tab=patching&view=notifications");
    await user.click(await main().findByRole("button", { name: "Send a test to Service desk" }));
    expect(await screen.findByText("Test sent to Service desk. How it went shows under Messages in a moment.")).toBeInTheDocument();
    expect(server.call("POST /patching/notifications/channels/:id/test").path).toBe("/patching/notifications/channels/c1/test");
    await user.click(main().getByRole("button", { name: "Send a test to Service desk" }));
    expect(await screen.findByText("Wait a minute between tests of a channel.")).toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "New signing key for PSA" }));
    let dialog = await screen.findByRole("dialog", { name: "New signing key" });
    expect(dialog).toHaveTextContent("The current key stops working at once");
    await user.click(within(dialog).getByRole("button", { name: "Make a new key" }));
    const secret = await screen.findByRole("dialog", { name: "Signing key for PSA" });
    expect(within(secret).getByText("new-c3")).toBeInTheDocument();
    await user.click(within(secret).getByRole("button", { name: "Done" }));

    await user.click(main().getByRole("button", { name: "Delete Ops chat" }));
    dialog = await screen.findByRole("dialog", { name: "Delete channel" });
    expect(dialog).toHaveTextContent("Rules stop sending to Ops chat, and its messages are deleted with it.");
    await user.click(within(dialog).getByRole("button", { name: "Delete channel" }));
    expect(await screen.findByText("Ops chat deleted.")).toBeInTheDocument();
    expect(server.call("DELETE /patching/notifications/channels/:id").path).toBe("/patching/notifications/channels/c2");
  });

  it("lists the messages sent, filters them and pages through them", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(settingsRoutes());
    await open("/settings?tab=patching&view=notifications");
    const table = await main().findByRole("table", { name: "Messages to notification channels" });
    const failed = within(table).getByText("Connection refused.").closest("tr") as HTMLElement;
    expect(within(failed).getByText("Failed")).toBeInTheDocument();
    expect(within(failed).getByText("3 attempts")).toBeInTheDocument();
    expect(main().getByText("51 messages, newest first; page 1 of 2")).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Older" }));
    expect(await within(main().getByRole("table", { name: "Messages to notification channels" })).findByText("Test from EasyPatch")).toBeInTheDocument();
    expect(server.callsTo("GET /patching/notifications/deliveries").at(-1)!.query.get("page")).toBe("2");
    await user.selectOptions(main().getByRole("combobox", { name: "Channel" }), "Ops chat");
    await user.selectOptions(main().getByRole("combobox", { name: "Result" }), "Failed");
    await waitFor(() => expect(Object.fromEntries(server.callsTo("GET /patching/notifications/deliveries").at(-1)!.query)).toEqual({ channelId: "c2", status: "Failed" }));
  });

  it("says when there are no channels or messages", async () => {
    installFakeApi(
      settingsRoutes(SUPER, {
        "GET /patching/notifications": ok({ channels: [], mail: MAIL, allowPrivateNetworkWebhooks: false }),
        "GET /patching/notifications/deliveries": ok({ items: [], page: 1, pageSize: 50, totalCount: 0 }),
      }),
    );
    await open("/settings?tab=patching&view=notifications");
    expect(await main().findByText("No channels")).toBeInTheDocument();
    expect(await main().findByText("No messages yet")).toBeInTheDocument();
  });
});

describe("alert wording", () => {
  it("says each threshold in words", () => {
    expect(thresholdText("EndpointOffline", 1)).toBe("Offline for 1 hour or more");
    expect(thresholdText("SecurityUpdateMissing", 0)).toBe("As soon as it is required");
    expect(thresholdText("SecurityUpdateMissing", 14)).toBe("Missing 14 days after it became required");
    expect(thresholdText("RestartPending", 7)).toBe("Waiting 7 days or more");
    expect(thresholdText("OsUnsupported", 30)).toBe("Support ends within 30 days, or has ended");
    expect(thresholdText("InstallFailed", null)).toBeNull();
    expect(thresholdText("ScanStale", 3)).toBeNull();
    expect(acknowledgedBy("easyrmm:otto@example.com")).toBe("otto@example.com");
    expect(acknowledgedBy("jo")).toBe("jo");
    expect(deliveryError("SMTP is not configured (Settings → Notifications).")).toBe("EasyRMM has no mail server: set EASYRMM_SMTP_HOST and restart EasyRMM.");
    expect(deliveryError("Connection refused.")).toBe("Connection refused.");
  });

  it("names what an acknowledgement in EasyRMM's audit log acted on", () => {
    const entry = (details: Record<string, unknown>): AuditEntry =>
      ({ id: "e1", action: "patch.alert_acknowledge", actorType: "user", targetType: "device", details }) as unknown as AuditEntry;
    expect(auditTarget(entry({ alerts: 1, device: "WEB-01", titles: ["x"] }))).toBe("1 alert on WEB-01");
    expect(auditTarget(entry({ alerts: 3, titles: [] }))).toBe("3 alerts of the organization");
    expect(auditTarget({ ...entry({}), action: "patch.notifications_update", targetType: "easypatch_notifications" } as AuditEntry)).toBe("Patching notifications");
  });
});
