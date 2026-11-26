import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { FixItem, FixWarning } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { device, org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { bulkProblem, FIX_STATES, REQUIREMENT_STATUS, RESULT_WORDS, TIERS } from "./complianceText";

// The compliance screens (ADR-0078, slice C2): the organization's tab, the fix queue and its agreements, the site's card,
// the computer's tab and the wording rules.

const WARN = (tier: "T1" | "T2" | "T3"): FixWarning => ({
  id: `warn.${tier.toLowerCase()}.v1`,
  version: 1,
  tier,
  title: tier === "T3" ? "A change that can lock people out" : tier === "T2" ? "A change that can break a workflow" : "A reversible change",
  paragraphs: [`Text for ${tier}.`],
  undoNote: "Undo puts back the old value.",
  typedRequired: tier === "T3",
  stepUpRequired: tier === "T3",
  sha256: "0".repeat(64),
});

function item(id: string, tier: "T1" | "T2" | "T3", over: Partial<FixItem> = {}): FixItem {
  return {
    id,
    organizationId: "o1",
    deviceId: "d1",
    siteId: "s1",
    deviceName: "HQ-WIN",
    platform: "windows",
    controlId: `win.${id}`,
    controlVersion: 1,
    title: `Control ${id}`,
    severity: "medium",
    tier,
    state: "open",
    observed: { value: "0" },
    expected: { value: "1" },
    warning: WARN(tier),
    preconditions: tier === "T3" ? ["The computer undoes the change by itself after 10 minutes unless the agent reports back."] : [],
    undoKind: "restore_backup",
    needsRestart: false,
    requirements: [{ framework: "nist-800-171r2", id: "3.1.1" }],
    applyBlocked: "",
    requiresTyped: tier === "T3",
    requiresStepUp: tier === "T3",
    requiresApproval: false,
    canUndo: false,
    outcome: null,
    failReason: "",
    decline: null,
    applyJobId: null,
    undoJobId: null,
    requestedBy: null,
    createdAt: "2026-11-26T09:00:00Z",
    updatedAt: "2026-11-26T09:00:00Z",
    ...over,
  };
}

const ITEMS = [
  item("autorun", "T1"),
  item("autoplay", "T1", { deviceId: "d2", deviceName: "HQ-WIN2" }),
  item("minlen", "T2"),
  item("complexity", "T2"),
  item("nla", "T3", { title: "Remote Desktop needs network level authentication" }),
  item("sshroot", "T2", { platform: "linux", deviceName: "HQ-LNX", applyBlocked: "The fix for this control changes a whole group of settings at once." }),
];

const ADMIN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "compliance.view", "compliance.scan", "compliance.fix", "compliance.fix_high", "compliance.fix_approve", "compliance.edit", "device.harden"],
});
const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "compliance.view", "compliance.scan", "compliance.fix"] });
const READ_ONLY = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });

const SUMMARY = { enabled: true, devices: 2, meets: 10, doesNotMeet: 4, cannotTell: 1, stale: 2, failingDevices: 2, lastScan: "2026-11-26T08:00:00Z", disclaimer: "Assessment aid. It reports what EasyRMM could check." };
const FRAMEWORK = {
  framework: "nist-800-171r2",
  version: "r2",
  title: "NIST SP 800-171 Rev. 2",
  scanId: "sc1",
  coverage: { total: 110, checked: 20, partly: 10, organisational: 80, noCheckYet: 0 },
  counts: { checked_meets: 3, checked_not_meets: 1, not_assessed: 106 },
  requirements: [
    { reqId: "3.1.1", status: "checked_not_meets", label: "checked: does not meet", failing: [{ deviceId: "d1", controlId: "win.autorun" }], meeting: 0, cannotTell: 0 },
    { reqId: "3.1.2", status: "checked_meets", label: "checked: all in-scope computers meet", meeting: 2, cannotTell: 0 },
    { reqId: "3.2.1", status: "not_assessed", label: "not assessed", reason: "People show this.", meeting: 0, cannotTell: 0 },
  ],
  inScope: 2,
  disclaimer: "Assessment aid. It reports what EasyRMM could check.",
  titles: { "3.1.1": "Limit system access to authorized users", "3.1.2": "Limit the kinds of transactions users may do" },
};

function routes(session = ADMIN, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(session),
    ...unreportedRoutes(),
    "GET /patching/scope": ok({ organizationId: "o1", organizationName: "Northwind Traders", siteId: null, siteName: "", devices: 0, byPlatform: [], skipped: [], canManage: false }),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
    "GET /sites/:id": ok(site("s1", "o1", "Head office")),
    "GET /organizations/:id/sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /patching": ok({ configured: false }),
    "GET /audit": ok({ items: [] }),
    "GET /organizations/:id/compliance/settings": ok({ enabled: true, freshnessDays: 30, scanSchedule: null, scanProfile: null }),
    "GET /organizations/:id/compliance/summary": ok(SUMMARY),
    "GET /sites/:id/compliance/summary": ok(SUMMARY),
    "GET /organizations/:id/compliance/assessments": ok({ items: [] }),
    "GET /organizations/:id/compliance/fixes": ok({ items: ITEMS }),
    "GET /organizations/:id/compliance/fix-settings": ok({ requireApproval: [] }),
    "GET /organizations/:id/compliance/packs": ok({
      items: [
        { key: "nist-800-171r2", version: "r2", kind: "framework", title: "NIST SP 800-171 Rev. 2", reviewState: "none", enabled: true, framework: "nist-800-171r2" },
        { key: "cis-xref", version: "1", kind: "framework", title: "Cross-reference", reviewState: "needed", enabled: false, framework: "cis-xref" },
      ],
    }),
    "GET /organizations/:id/compliance/frameworks/:key": ok(FRAMEWORK),
    "GET /compliance/profiles": ok({ items: [{ key: "win-server-baseline", version: "1", title: "Windows server baseline", platform: { os: "windows" }, frameworkKey: null, controls: 40 }] }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

const row = (name: RegExp) => screen.getByRole("row", { name });

describe("the organization's Compliance tab", () => {
  it("shows the counts, the frameworks' requirements in the console's words, and never says compliant", async () => {
    installFakeApi(routes());
    renderApp("/organizations/o1?tab=compliance");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText("Controls that meet")).toBeInTheDocument();
    expect(main.getByText("Controls that do not meet")).toBeInTheDocument();
    const table = await main.findByRole("table", { name: "NIST SP 800-171 Rev. 2 requirements" });
    expect(within(table).getByText("Limit system access to authorized users")).toBeInTheDocument();
    expect(within(table).getByText("checked: does not meet")).toBeInTheDocument();
    expect(within(table).getByText("checked: all in-scope computers meet")).toBeInTheDocument();
    // The pack waiting on its review is not offered.
    expect(main.queryByRole("option", { name: "Cross-reference" })).toBeNull();
    const text = (document.body.textContent ?? "").toLowerCase();
    for (const banned of ["compliant", "certified", "audit-ready", "cis benchmark"]) expect(text).not.toContain(banned);
  });

  it("is shown to who may view compliance, and not to a viewer without the permission", async () => {
    installFakeApi(routes(READ_ONLY));
    renderApp("/organizations/o1");
    await screen.findByRole("heading", { name: "Northwind Traders" });
    expect(screen.queryByRole("tab", { name: "Compliance" })).toBeNull();
  });

  it("holds only the switch while the module is off", async () => {
    const api = installFakeApi(
      routes(ADMIN, {
        "GET /organizations/:id/compliance/settings": ok({ enabled: false, freshnessDays: 30, scanSchedule: null, scanProfile: null }),
        "PUT /organizations/:id/compliance/settings": ok({ enabled: true, freshnessDays: 30, scanSchedule: null, scanProfile: null }),
      }),
    );
    renderApp("/organizations/o1?tab=compliance");
    await userEvent.click(await screen.findByRole("button", { name: "Turn on compliance checks" }));
    await waitFor(() => expect(api.call("PUT /organizations/:id/compliance/settings").body).toMatchObject({ enabled: true }));
    expect(screen.queryByRole("table", { name: "Fix queue" })).toBeNull();
  });

  it("starts a scan with the chosen profile", async () => {
    const api = installFakeApi(
      routes(ADMIN, { "POST /organizations/:id/compliance/scans": ok({ id: "sc2" }), "GET /organizations/:id/compliance/scans/:scanId": ok({ state: "done", waiting: 0 }) }),
    );
    renderApp("/organizations/o1?tab=compliance");
    await userEvent.click(await screen.findByRole("button", { name: "Scan now" }));
    await waitFor(() => expect(api.call("POST /organizations/:id/compliance/scans").body).toMatchObject({ profile: "win-server-baseline", run: true }));
    // The page reads the scan until it ends, which moves it forward on the server.
    expect(await screen.findByText("Scan finished.")).toBeInTheDocument();
  });
});

describe("the fix queue", () => {
  it("lists each item with its tier and what it would help, and offers no Apply where the fix is not one control's", async () => {
    installFakeApi(routes());
    renderApp("/organizations/o1?tab=compliance");
    const queue = within(await screen.findByRole("table", { name: "Fix queue" }));
    expect(queue.getAllByText("Would help: nist-800-171r2 3.1.1").length).toBeGreaterThan(0);
    expect(queue.getByText("Can cut access")).toBeInTheDocument();
    // No default selection, and no "fix all".
    for (const box of queue.getAllByRole("checkbox")) expect(box).not.toBeChecked();
    expect(screen.queryByRole("button", { name: /fix all|apply all/i })).toBeNull();
    const linux = within(row(/HQ-LNX/));
    expect(linux.queryByRole("button", { name: /^Apply/ })).toBeNull();
    expect(linux.getByText(/changes a whole group of settings at once/)).toBeInTheDocument();
  });

  it("applies a safe item after the agreement: one request with the agreement in it", async () => {
    const api = installFakeApi(routes(ADMIN, { "POST /organizations/:id/compliance/fixes/apply": ok({ items: [item("autorun", "T1", { state: "applying" })] }) }));
    renderApp("/organizations/o1?tab=compliance");
    await userEvent.click(await screen.findByRole("button", { name: "Apply Control autorun on HQ-WIN" }));
    const dialog = await screen.findByRole("dialog", { name: "Apply fix" });
    expect(within(dialog).getByText("A reversible change")).toBeInTheDocument();
    expect(within(dialog).queryByLabelText(/^Type .* to confirm/)).toBeNull();
    const apply = within(dialog).getByRole("button", { name: "Apply" });
    expect(apply).toBeDisabled();
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /I have read the warning/ }));
    await userEvent.click(apply);
    await waitFor(() => expect(api.call("POST /organizations/:id/compliance/fixes/apply").body).toEqual({ itemIds: ["autorun"], agreed: true }));
  });

  it("asks for the computer's name when a change can cut access, refuses a wrong one, and shows the step-up refusal", async () => {
    const api = installFakeApi(
      routes(ADMIN, {
        "POST /organizations/:id/compliance/fixes/apply": fail(401, "step_up_required", "This needs step-up authentication."),
        "GET /auth/step-up": ok({ validUntil: null, methods: ["totp"], provider: "Authentik" }),
      }),
    );
    renderApp("/organizations/o1?tab=compliance");
    await userEvent.click(await screen.findByRole("button", { name: /^Apply Remote Desktop needs network level authentication/ }));
    const dialog = await screen.findByRole("dialog", { name: "Apply fix" });
    expect(within(dialog).getByText("A change that can lock people out")).toBeInTheDocument();
    expect(within(dialog).getByText(/undoes the change by itself after 10 minutes/)).toBeInTheDocument();
    const apply = within(dialog).getByRole("button", { name: "Apply" });
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /I have read the warning/ }));
    expect(apply).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Type HQ-WIN to confirm"), "HQ-WIN");
    await userEvent.click(apply);
    await waitFor(() => expect(api.call("POST /organizations/:id/compliance/fixes/apply").body).toEqual({ itemIds: ["nla"], agreed: true, typed: "HQ-WIN" }));
    // The console's step-up dialog asks; leaving it leaves the request refused, and the dialog says why.
    const stepUp = await screen.findByRole("dialog", { name: "Confirm it is you" });
    await userEvent.click(within(stepUp).getByRole("button", { name: "Cancel" }));
    expect(await within(dialog).findByText(/needs step-up authentication/)).toBeInTheDocument();
    expect(api.callsTo("POST /organizations/:id/compliance/fixes/apply")).toHaveLength(1);
  });

  it("offers a bulk Apply for safe items only, one control of tier 2, and never tier 3", async () => {
    installFakeApi(routes());
    renderApp("/organizations/o1?tab=compliance");
    await screen.findByRole("table", { name: "Fix queue" });
    expect(screen.queryByRole("checkbox", { name: /Remote Desktop needs network level authentication/ })).toBeNull();
    await userEvent.click(screen.getByRole("checkbox", { name: "Choose Control autorun on HQ-WIN" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Choose Control autoplay on HQ-WIN2" }));
    expect(screen.getByRole("button", { name: "Apply 2 chosen…" })).toBeEnabled();
    // A safe item and one that can break a workflow are two agreements, not one.
    await userEvent.click(screen.getByRole("checkbox", { name: "Choose Control minlen on HQ-WIN" }));
    expect(screen.getByText(/Choose items of one tier/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply 3 chosen…" })).toBeDisabled();
  });

  it("hides Apply from who holds no device.harden, and Approve from who may not approve", async () => {
    installFakeApi(routes(TECH, { "GET /organizations/:id/compliance/fixes": ok({ items: [item("autorun", "T1"), item("nla", "T3", { state: "awaiting_approval" })] }) }));
    renderApp("/organizations/o1?tab=compliance");
    await screen.findByRole("table", { name: "Fix queue" });
    expect(screen.queryByRole("button", { name: /^Apply/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /^Approve/ })).toBeNull();
    expect(screen.getByRole("button", { name: "Set aside Control autorun on HQ-WIN" })).toBeInTheDocument();
  });

  it("offers Undo for an applied item, and Approve for one that waits", async () => {
    const api = installFakeApi(
      routes(ADMIN, {
        "GET /organizations/:id/compliance/fixes": ok({
          items: [item("autorun", "T1", { state: "verified", canUndo: true }), item("minlen", "T2", { state: "awaiting_approval", requiresApproval: true })],
        }),
        "POST /organizations/:id/compliance/fixes/:itemId/undo": ok(item("autorun", "T1", { state: "undoing" })),
        "POST /organizations/:id/compliance/fixes/:itemId/approve": ok(item("minlen", "T2", { state: "applying" })),
      }),
    );
    renderApp("/organizations/o1?tab=compliance");
    await userEvent.click(await screen.findByRole("button", { name: "Undo Control autorun on HQ-WIN" }));
    let dialog = await screen.findByRole("dialog", { name: "Undo fix" });
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /I have read the warning/ }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(api.call("POST /organizations/:id/compliance/fixes/:itemId/undo").body).toEqual({ agreed: true }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Undo fix" })).toBeNull());

    await userEvent.click(screen.getByRole("button", { name: "Approve Control minlen on HQ-WIN" }));
    dialog = await screen.findByRole("dialog", { name: "Approve fix" });
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /I have read the warning/ }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(api.call("POST /organizations/:id/compliance/fixes/:itemId/approve").body).toEqual({ agreed: true }));
  });

  it("sets an item aside with a reason, and a deferral with a date", async () => {
    const api = installFakeApi(routes(ADMIN, { "POST /organizations/:id/compliance/fixes/:itemId/decline": ok(item("autorun", "T1", { state: "declined" })) }));
    renderApp("/organizations/o1?tab=compliance");
    await userEvent.click(await screen.findByRole("button", { name: "Set aside Control autorun on HQ-WIN" }));
    const dialog = await screen.findByRole("dialog", { name: "Set this item aside" });
    expect(within(dialog).getByRole("button", { name: "Set aside" })).toBeDisabled();
    await userEvent.selectOptions(within(dialog).getByLabelText("Why"), "deferred");
    await userEvent.type(within(dialog).getByLabelText("Reason"), "After the audit");
    await userEvent.click(within(dialog).getByRole("button", { name: "Set aside" }));
    await waitFor(() => expect(api.call("POST /organizations/:id/compliance/fixes/:itemId/decline").body).toMatchObject({ kind: "deferred", reason: "After the audit" }));
    expect((api.call("POST /organizations/:id/compliance/fixes/:itemId/decline").body as { expiresAt: string }).expiresAt).toMatch(/^\d{4}-\d\d-\d\dT/);
  });

  it("keeps the history apart from the queue", async () => {
    const api = installFakeApi(routes());
    renderApp("/organizations/o1?tab=compliance");
    await screen.findByRole("table", { name: "Fix queue" });
    await userEvent.click(screen.getByRole("radio", { name: "History" }));
    await waitFor(() => expect(api.calls.some((c) => c.path.endsWith("/compliance/fixes") && c.query?.get("state") === "history")).toBe(true));
  });
});

describe("the site's card and the computer's tab", () => {
  it("counts the site's stored results on its Overview, and links to the organization's tab", async () => {
    const api = installFakeApi(routes());
    renderApp("/sites/s1");
    const heading = await screen.findByRole("heading", { name: "Compliance" });
    const card = within(heading.closest("section, div")!.parentElement!);
    expect(await card.findByText("Do not meet")).toBeInTheDocument();
    expect(card.getByRole("link", { name: "Details" })).toHaveAttribute("href", "/organizations/o1?tab=compliance");
    expect(api.callsTo("GET /sites/:id/compliance/summary")).toHaveLength(1);
    expect(api.calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("does not show the card where the module is off", async () => {
    installFakeApi(routes(ADMIN, { "GET /organizations/:id/compliance/settings": ok({ enabled: false, freshnessDays: 30, scanSchedule: null, scanProfile: null }) }));
    renderApp("/sites/s1");
    await screen.findByRole("heading", { name: "Device groups" });
    expect(screen.queryByRole("heading", { name: "Compliance" })).toBeNull();
  });

  it("shows a computer's controls by what a scan found, its items, and its requirements", async () => {
    const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
    installFakeApi(
      routes(ADMIN, {
        "GET /devices/:id": ok(device("d1", "HQ-WIN", { platform: "windows", agent: AGENT })),
        "GET /devices/:id/compliance": ok({
          items: [
            { controlId: "win.autorun", controlVersion: 1, title: "No AutoRun commands", state: "not_in_place", word: "does not meet", checkedAt: "2026-11-26T08:00:00Z", scanId: "sc1" },
            { controlId: "win.uac", controlVersion: 1, title: "UAC is on", state: "in_place", word: "meets", checkedAt: "2026-11-26T08:00:00Z", scanId: "sc1" },
            { controlId: "win.old", controlVersion: 1, title: "An old result", state: "stale", word: "cannot tell", checkedAt: "2026-09-01T08:00:00Z", scanId: "sc0" },
          ],
        }),
        "GET /devices/:id/compliance/frameworks/:key": ok(FRAMEWORK),
        "GET /devices/:id/roles": ok({ roles: [] }),
      }),
    );
    renderApp("/devices/d1?tab=compliance");
    expect(await screen.findByRole("tab", { name: "Compliance" })).toHaveAttribute("aria-selected", "true");
    const controls = within(await screen.findByRole("table", { name: "Controls" }));
    expect(controls.getAllByRole("row")[1]).toHaveTextContent("No AutoRun commands");
    expect(controls.getByText("Does not meet")).toBeInTheDocument();
    expect(controls.getByText("Cannot tell")).toBeInTheDocument();
    expect(controls.getByText("out of date")).toBeInTheDocument();
    expect(await screen.findByRole("table", { name: "NIST SP 800-171 Rev. 2 requirements" })).toBeInTheDocument();
    expect(await screen.findByRole("table", { name: "Fix queue" })).toBeInTheDocument();
  });
});

describe("the wording", () => {
  it("uses meets, does not meet and cannot tell, and no claim of compliance", () => {
    const all = [
      ...Object.values(RESULT_WORDS).map((w) => w.label),
      ...Object.values(REQUIREMENT_STATUS).map((w) => w.label),
      ...Object.values(FIX_STATES).flatMap((s) => [s.label, s.title]),
      ...Object.values(TIERS).flatMap((t) => [t.label, t.title]),
    ].join(" ");
    expect(all).not.toMatch(/complian|certif|audit-ready|CIS/i);
    expect(Object.keys(RESULT_WORDS)).toEqual(["meets", "does not meet", "cannot tell"]);
  });

  it("holds bulk agreements to the tiers' rules", () => {
    const a = { tier: "T1" as const, controlId: "a" };
    expect(bulkProblem([a])).toBeNull();
    expect(bulkProblem([a, { ...a, controlId: "b" }])).toBeNull();
    expect(bulkProblem([{ tier: "T2", controlId: "a" }, { tier: "T2", controlId: "a" }])).toBeNull();
    expect(bulkProblem([{ tier: "T2", controlId: "a" }, { tier: "T2", controlId: "b" }])).not.toBeNull();
    expect(bulkProblem([{ tier: "T3", controlId: "a" }, { tier: "T3", controlId: "a" }])).not.toBeNull();
    expect(bulkProblem([a, { tier: "T2", controlId: "a" }])).not.toBeNull();
  });
});
