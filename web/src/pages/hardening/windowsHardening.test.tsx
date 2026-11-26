import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DeviceHardening, HardeningFleet, HardeningGuard, WindowsCatalogModule } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { device, jobRun } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { changeTier } from "./WindowsChangeDialog";
import { countdown } from "./windowsText";

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const SERVER = device("d1", "HQ-WIN", { platform: "windows", osDescription: "Windows Server 2025", agent: AGENT, canRunScripts: true });

const ADMIN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "script.run", "job.view", "device.harden"] });
const TECHNICIAN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "script.run", "job.view"] });
const READ_ONLY = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });

const T = "2026-11-01T10:00:00Z";

const CATALOG: WindowsCatalogModule[] = [
  {
    id: "accounts",
    tier: 2,
    switches: ["lockoutExposed"],
    settings: [
      { id: "accounts-min-length", what: "Minimum password length", tier: 2, cite: "meets" },
      { id: "accounts-lockout-threshold", what: "Lock an account after failed sign-ins", tier: 3, cite: "differs" },
      { id: "accounts-lockout-duration", what: "How long a locked account stays locked", tier: 3, cite: "differs" },
    ],
  },
  { id: "autoplay", tier: 1, switches: [], settings: [{ id: "autoplay-autorun", what: "No AutoRun commands", tier: 1, cite: "meets" }] },
  { id: "laps", tier: 0, switches: [], settings: [{ id: "laps-managed", what: "Windows LAPS manages the password", tier: 0, cite: "not_set" }] },
];

const FOUND: DeviceHardening = {
  platform: {
    id: "windows",
    versionId: "10.0.26100",
    family: "windows",
    container: "none",
    support: "full",
    windows: {
      build: 26100,
      displayVersion: "24H2",
      edition: "ServerStandard",
      installationType: "Server Core",
      role: "member_server",
      joined: "domain",
      mdm: false,
      owners: { groupPolicyRecord: "read", mdm: false, defenderForEndpoint: false, configMgr: false, dsc: false, azureMachineConfiguration: false, tamperProtected: true },
      checkOnlyReasons: [],
    },
  },
  jobId: "j2",
  checkedAt: T,
  controlSources: [{ name: "DISA STIG: Microsoft Windows Server 2025", version: "V1R3", date: "2026-02", url: "https://example.test" }],
  modules: [
    {
      module: "accounts",
      state: "partly",
      jobId: "j2",
      checkedAt: T,
      restart: true,
      settings: [
        { id: "accounts-min-length", state: "in_place", value: "14", want: "14" },
        { id: "accounts-lockout-threshold", state: "managed_elsewhere", value: "5", want: "10", reasons: ["group_policy"] },
        { id: "accounts-lockout-duration", state: "not_in_place", value: "0", want: "15" },
      ],
      managed: [{ id: "accounts-lockout-threshold", owner: "group_policy", policy: "LockoutBadCount", value: "5", state: "managed_elsewhere" }],
      related: { sp80053R5: [{ id: "AC-7", title: "Unsuccessful Logon Attempts" }], sp800171R2: ["3.1.8"], sp800171R3: ["03.01.08"], iso27001: ["A.8.5"] },
    },
    {
      module: "autoplay",
      state: "not_in_place",
      jobId: "j2",
      checkedAt: T,
      settings: [{ id: "autoplay-autorun", state: "not_in_place", value: "0", want: "1" }],
    },
    { module: "laps", state: "not_in_place", jobId: "j2", checkedAt: T, reason: "Windows LAPS does not manage the local administrator's password." },
  ],
};

const ARMED: HardeningGuard = {
  applyJobId: "j3",
  settings: ["autoplay-autorun"],
  armedAt: new Date(Date.now() - 60_000).toISOString(),
  rollbackAt: new Date(Date.now() + 540_000).toISOString(),
  state: "armed",
  decidedAt: null,
  keepRequestedAt: null,
};
const OLD: HardeningGuard = { ...ARMED, applyJobId: "j1", settings: ["wdigest-logon-credential", "accounts-min-length"], state: "timed_out", decidedAt: "2026-10-31T10:12:00Z", armedAt: "2026-10-31T10:00:00Z", rollbackAt: "2026-10-31T10:10:00Z" };

function routes(session = ADMIN, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(session),
    ...unreportedRoutes(),
    "GET /devices/:id": ok(SERVER),
    "GET /devices/:id/hardening": ok(FOUND),
    "GET /devices/:id/hardening/guards": ok({ items: [] }),
    "GET /hardening/windows/catalog": ok({ items: CATALOG }),
    "GET /job-runs": ok({ items: [jobRun("r1", "d1", "HQ-WIN", "succeeded", { jobId: "j2", scriptName: "Check Windows hardening (every module)" })] }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

const moduleItem = (name: string) => screen.getByRole("heading", { name, level: 3 }).closest("li") as HTMLElement;

describe("a Windows computer's hardening", () => {
  it("shows each module with its tier and state, and each setting with its value, owner and related controls", async () => {
    installFakeApi(routes());
    renderApp("/devices/d1?tab=hardening");
    expect(await screen.findByRole("tab", { name: "Hardening" })).toHaveAttribute("aria-selected", "true");
    const accounts = await waitFor(() => moduleItem("Accounts"));
    expect(within(accounts).getByText("Can break a workflow")).toBeInTheDocument();
    expect(within(accounts).getByText("Partly in place")).toBeInTheDocument();
    expect(within(accounts).getByText("Restart needed")).toBeInTheDocument();
    expect(within(moduleItem("Windows LAPS")).getByText("Report only")).toBeInTheDocument();

    // Per setting, once the module is opened.
    await userEvent.click(within(accounts).getByRole("button", { name: /Accounts, show its settings/ }));
    const table = within(accounts).getByRole("table");
    expect(within(table).getByText("Minimum password length")).toBeInTheDocument();
    const lockout = within(table).getByText("accounts-lockout-threshold").closest("tr") as HTMLElement;
    expect(within(lockout).getByText("Managed elsewhere")).toBeInTheDocument();
    expect(within(lockout).getByText("Can cut access")).toBeInTheDocument();
    expect(within(lockout).getByText("Differs on purpose")).toBeInTheDocument();
    expect(within(accounts).getByText(/by group_policy: LockoutBadCount = 5/)).toBeInTheDocument();
    const related = within(accounts).getByRole("region", { name: "Related controls" });
    expect(within(related).getByText(/AC-7 Unsuccessful Logon Attempts/)).toBeInTheDocument();
    expect(within(related).getByText(/not a statement that the computer complies/)).toBeInTheDocument();
    expect(within(related).getByText("A.8.5")).toBeInTheDocument();

    // The computer as the check read it, with the other owners.
    const last = screen.getByRole("heading", { name: "Last check" }).closest("section") as HTMLElement;
    expect(within(last).getByText("Member server")).toBeInTheDocument();
    expect(within(last).getByText("Group Policy")).toBeInTheDocument();
    expect(screen.getByText(/DISA STIG: Microsoft Windows Server 2025 V1R3/)).toBeInTheDocument();
  });

  it("offers apply and undo to who holds device.harden here, and not to a technician or a viewer", async () => {
    installFakeApi(routes(TECHNICIAN));
    const { unmount } = renderApp("/devices/d1?tab=hardening");
    await screen.findByRole("button", { name: "Run check…" });
    expect(screen.queryByRole("checkbox", { name: /Choose/ })).not.toBeInTheDocument();
    unmount();

    installFakeApi(routes(READ_ONLY));
    renderApp("/devices/d1?tab=hardening");
    await waitFor(() => moduleItem("Accounts"));
    expect(screen.queryByRole("button", { name: "Run check…" })).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: /Choose/ })).not.toBeInTheDocument();
  });

  it("checks permission where the computer is: device.harden granted for another organization does not count", async () => {
    const elsewhere = sessionView({
      ...ADMIN,
      scopedPermissions: { "device.harden": { organizations: ["o9"], sites: [] }, "script.run": { organizations: ["o1"], sites: [] } },
    });
    installFakeApi(routes(elsewhere));
    renderApp("/devices/d1?tab=hardening");
    await screen.findByRole("button", { name: "Run check…" });
    expect(screen.queryByRole("checkbox", { name: /Choose/ })).not.toBeInTheDocument();
  });

  it("applies a module after the agreement: one request, the platform and the agreement in it", async () => {
    const server = installFakeApi(routes(ADMIN, { "POST /jobs/hardening": ok({ id: "j9" }) }));
    renderApp("/devices/d1?tab=hardening");
    await userEvent.click(await screen.findByRole("checkbox", { name: "Choose AutoPlay" }));
    await userEvent.click(screen.getByRole("button", { name: "Apply…" }));
    const dialog = await screen.findByRole("dialog", { name: "Apply hardening" });
    expect(within(dialog).getByText("Safe")).toBeInTheDocument();
    expect(within(dialog).getByText(/undoes this by itself unless the agent confirms/)).toBeInTheDocument();
    const apply = within(dialog).getByRole("button", { name: "Apply" });
    expect(apply).toBeDisabled();
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /I have read what this change does/ }));
    await userEvent.click(apply);
    await waitFor(() => expect(server.call("POST /jobs/hardening").body).toMatchObject({
      deviceIds: ["d1"], platform: "windows", mode: "apply", modules: ["autoplay"], confirm: { agreed: true },
    }));
    expect((server.call("POST /jobs/hardening").body as { confirm: object }).confirm).not.toHaveProperty("typed");
  });

  it("applies single settings, which cannot be mixed with whole modules", async () => {
    const server = installFakeApi(routes(ADMIN, { "POST /jobs/hardening": ok({ id: "j9" }) }));
    renderApp("/devices/d1?tab=hardening");
    const autoplay = await waitFor(() => moduleItem("AutoPlay"));
    await userEvent.click(within(autoplay).getByRole("button", { name: /AutoPlay, show its settings/ }));
    await userEvent.click(within(autoplay).getByRole("checkbox", { name: "Choose autoplay-autorun" }));
    // The module boxes are off while a setting is chosen.
    expect(screen.getByRole("checkbox", { name: "Choose Accounts" })).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Undo…" }));
    const dialog = await screen.findByRole("dialog", { name: "Undo hardening" });
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /I have read what this change does/ }));
    await userEvent.click(within(dialog).getByRole("button", { name: "Undo" }));
    await waitFor(() => expect(server.call("POST /jobs/hardening").body).toMatchObject({ mode: "undo", settings: ["autoplay-autorun"], modules: [] }));
  });

  it("asks for the computer's name when a change can cut access, and shows the server's step-up refusal", async () => {
    const server = installFakeApi(
      routes(ADMIN, {
        "POST /jobs/hardening": fail(401, "step_up_required", "This change can cut access to the computer and needs step-up authentication."),
        "GET /auth/step-up": ok({ validUntil: null, methods: ["totp"], provider: "Authentik" }),
      }),
    );
    renderApp("/devices/d1?tab=hardening");
    const accounts = await waitFor(() => moduleItem("Accounts"));
    await userEvent.click(within(accounts).getByRole("button", { name: /Accounts, show its settings/ }));
    await userEvent.click(within(accounts).getByRole("checkbox", { name: "Choose accounts-lockout-duration" }));
    await userEvent.click(screen.getByRole("button", { name: "Apply…" }));
    const dialog = await screen.findByRole("dialog", { name: "Apply hardening" });
    expect(within(dialog).getByText("This can cut access to the computer")).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("checkbox", { name: /I have read what this change does/ }));
    const apply = within(dialog).getByRole("button", { name: "Apply" });
    expect(apply).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Type HQ-WIN to confirm"), "HQ-WIN");
    await userEvent.click(apply);
    await waitFor(() => expect(server.call("POST /jobs/hardening").body).toMatchObject({ settings: ["accounts-lockout-duration"], confirm: { agreed: true, typed: "HQ-WIN" } }));
    // The console's step-up dialog asks; leaving it leaves the request refused, and the dialog says why.
    const stepUp = await screen.findByRole("dialog", { name: "Confirm it is you" });
    await userEvent.click(within(stepUp).getByRole("button", { name: "Cancel" }));
    expect(await within(dialog).findByText(/needs step-up authentication/)).toBeInTheDocument();
    expect(server.callsTo("POST /jobs/hardening")).toHaveLength(1);
  });

  it("shows the guard's countdown with a Keep button, and what happened to earlier guards", async () => {
    const keepAsked: string[] = [];
    installFakeApi(
      routes(ADMIN, {
        "GET /devices/:id/hardening/guards": ok({ items: [ARMED, OLD] }),
        "POST /devices/:id/hardening/guard/keep": () => {
          keepAsked.push("d1");
          return ok({ ...ARMED, keepRequestedAt: T });
        },
      }),
    );
    renderApp("/devices/d1?tab=hardening");
    expect(await screen.findByText(/The computer undoes the change in [89]:\d\d/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Keep the change" }));
    await waitFor(() => expect(keepAsked).toEqual(["d1"]));
    const history = screen.getByRole("list", { name: "Hardening history" });
    expect(within(history).getByText("Undone by the computer")).toBeInTheDocument();
    expect(within(history).getByText("Waiting")).toBeInTheDocument();
    expect(within(history).getByText("wdigest-logon-credential, accounts-min-length")).toBeInTheDocument();
  });

  it("hides Keep from someone who cannot apply", async () => {
    installFakeApi(routes(TECHNICIAN, { "GET /devices/:id/hardening/guards": ok({ items: [ARMED] }) }));
    renderApp("/devices/d1?tab=hardening");
    expect(await screen.findByText(/The computer undoes the change in/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Keep the change" })).not.toBeInTheDocument();
  });
});

describe("the fleet views", () => {
  const FLEET: HardeningFleet = {
    truncated: false,
    modules: [
      { module: "autoplay", states: { in_place: 1, not_in_place: 1 } },
      { module: "smb", states: { partly: 1 } },
    ],
    devices: [
      { id: "d1", name: "HQ-WIN-1", siteName: "Head office", groupName: "Servers", checkedAt: T, states: { in_place: 1, partly: 1 }, guard: "armed" },
      { id: "d2", name: "HQ-WIN-2", siteName: "Head office", groupName: "", checkedAt: T, states: { in_place: 2 }, guard: "" },
      { id: "d3", name: "HQ-WIN-3", siteName: "Head office", groupName: "", checkedAt: null, states: {}, guard: "" },
    ],
  };

  it("sums up an organization's Windows computers, filters them and links to their pages", async () => {
    const server = installFakeApi({
      ...baseRoutes(ADMIN),
      "GET /organizations/o1": ok({ id: "o1", name: "Northwind Traders", timezone: "UTC", canManage: false, canDelete: false, siteCount: 1, deviceCount: 3, createdAt: T, updatedAt: T }),
      "GET /organizations/o1/sites": ok({ items: [] }),
      "GET /hardening/windows/fleet": ok(FLEET),
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/organizations/o1?tab=hardening");
    const modules = await screen.findByRole("table", { name: "Modules across the computers" });
    expect(within(modules).getByText("SMB 1")).toBeInTheDocument();
    expect(server.call("GET /hardening/windows/fleet").query.get("organizationId")).toBe("o1");
    const list = screen.getByRole("table", { name: "Windows computers" });
    expect(within(list).getByRole("link", { name: "HQ-WIN-1" })).toHaveAttribute("href", "/devices/d1?tab=hardening");
    expect(within(list).getByText("Waiting")).toBeInTheDocument();
    expect(within(list).getByText("Not checked")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("radio", { name: "Needs attention" }));
    expect(within(list).getAllByRole("row")).toHaveLength(2);
    await userEvent.click(screen.getByRole("radio", { name: "Not checked" }));
    expect(within(list).getByRole("link", { name: "HQ-WIN-3" })).toBeInTheDocument();
    expect(within(list).queryByRole("link", { name: "HQ-WIN-1" })).not.toBeInTheDocument();
  });
});

describe("the helpers", () => {
  it("judges a change's tier as the server does: by modules or by settings", () => {
    expect(changeTier(CATALOG, { mode: "apply", modules: ["autoplay"] })).toBe(1);
    expect(changeTier(CATALOG, { mode: "apply", modules: ["accounts"] })).toBe(3);
    expect(changeTier(CATALOG, { mode: "apply", settings: ["accounts-min-length"], modules: [] })).toBe(2);
    expect(changeTier(CATALOG, { mode: "check", modules: ["laps"] })).toBe(0);
  });

  it("counts down to the timer, never below zero", () => {
    const at = "2026-11-01T10:10:00Z";
    expect(countdown(at, Date.parse("2026-11-01T10:02:18Z"))).toBe("7:42");
    expect(countdown(at, Date.parse("2026-11-01T10:11:00Z"))).toBe("0:00");
  });
});
