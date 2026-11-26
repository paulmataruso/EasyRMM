import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DeviceRole, DeviceRoles } from "../../../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, type FakeReply } from "../../../../test/fakeApi";
import { device, history, inventory, metrics } from "../../../../test/fixtures";
import { renderApp } from "../../../../test/render";
import { DEVICE_MODULE_TABS, moduleTabState } from "../moduleTabs";
import type { DirectoryHealth, DirectoryStatus, GroupPage, MemberPage, UserPage } from "./types";

// The Directory tab (ADR-0075, A8): detection, reads, the help-desk actions and the one-time password.

const AGENT = {
  version: "1.5.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z",
  enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null,
};
const DC = device("d1", "DC1", { platform: "windows", osDescription: "Windows Server 2025", agent: AGENT });
const ROLE: DeviceRole = { name: "ad_ds", state: "present", module: "active_directory", label: "Active Directory", enabled: true };
const roles = (r: DeviceRole[]): DeviceRoles => ({ known: true, reportedAt: "2026-11-26T10:00:00Z", roles: r });

const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "ad.view", "ad.helpdesk"] });
const VIEWER = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "ad.view"] });

const STATUS: DirectoryStatus = {
  domain: "corp.test", domainSid: "S-1-5-21-1-2-3", forest: "corp.test", forestRootSid: "S-1-5-21-1-2-3", domainMode: "Windows2016Domain",
  forestMode: "Windows2016Forest", controller: "dc1.corp.test", readOnly: false, globalCatalog: true, pdcEmulator: "dc1.corp.test",
  recycleBinEnabled: false,
  passwordPolicy: { minLength: 7, complexity: true, historyCount: 24, maxAgeDays: 42, lockoutThreshold: 5, lockoutDurationMinutes: 30, lockoutObservationMinutes: 30 },
};
const HEALTH: DirectoryHealth = {
  controller: "dc1.corp.test", domain: "corp.test",
  checks: [
    { name: "replication", state: "critical", detail: "The directory reports replication failures." },
    { name: "services", state: "ok", detail: "The directory services are running." },
  ],
  replication: { failureCount: 2, oldestFailureAt: "2026-11-26T05:00:00Z", partners: [] },
};
const row = (over: Partial<UserPage["items"][number]>): UserPage["items"][number] => ({
  id: "S-1-5-21-1-2-3-1104", sam: "ann", name: "Ann Ordinary", upn: "ann@corp.test", enabled: true, lockedOut: false, passwordExpired: false,
  protection: "none", reason: "", ...over,
});
const USERS: UserPage = {
  items: [
    row({}),
    row({ id: "S-1-5-21-1-2-3-1105", sam: "bob", name: "Bob Locked", lockedOut: true }),
    row({ id: "S-1-5-21-1-2-3-1107", sam: "admin2", name: "Admin Two", protection: "protected", reason: "it is, or is inside, a privileged group" }),
  ],
  next: null, scanned: 3, domainSid: "S-1-5-21-1-2-3",
};
const GROUPS: GroupPage = {
  items: [{ id: "S-1-5-21-1-2-3-1300", sam: "Sales", name: "Sales", scope: "global", category: "security", description: "Sales staff", protection: "none", reason: "" }],
  next: null, scanned: 1, domainSid: "S-1-5-21-1-2-3",
};
const MEMBERS: MemberPage = { items: [{ id: "S-1-5-21-1-2-3-1104", sam: "ann", name: "Ann Ordinary", kind: "user", key: "ann" }], next: null, total: 1 };
const GENERATED = "Gx7#kQ9-mP2$rT5&vW8z";

/** A controller: each action answers with its own data; a refusal can be set per action. */
function controller(refuse: Record<string, { code: string; message: string }> = {}, session = TECH) {
  const data: Record<string, unknown> = {
    status: STATUS, health_read: HEALTH, user_list: USERS, group_list: GROUPS, group_members: MEMBERS,
    user_reset_password: { mustChange: true, unlocked: false }, user_disable: { done: true }, user_unlock: { done: true },
  };
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(DC),
    "GET /devices/:id/roles": ok(roles([ROLE])),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: [] }),
    "POST /devices/:id/winmod/:action": (req): FakeReply => {
      const action = req.params.action!.replace("active_directory.", "");
      const generated = action === "user_reset_password" && !(req.body as { params: { password?: string } }).params.password;
      return ok({ jobId: "j", runId: `r-${action}`, action, status: "queued", expiresAt: "2026-11-26T11:00:00Z", ...(generated ? { generated: { password: GENERATED } } : {}) });
    },
    "GET /winmod/runs/:id": (req): FakeReply => {
      const action = req.params.id!.replace("r-", "");
      const base = { runId: req.params.id, deviceId: "d1", action, version: 1, status: "succeeded", finishedAt: "2026-11-26T10:00:00Z" };
      return refuse[action] ? ok({ ...base, ok: false, failure: refuse[action] }) : ok({ ...base, ok: true, data: data[action] });
    },
  } as Parameters<typeof installFakeApi>[0];
}

async function readAll() {
  await userEvent.click(await screen.findByRole("button", { name: "Read now" }));
  await screen.findByText("Directory health");
  await userEvent.click(screen.getByRole("button", { name: "List users" }));
  await screen.findByText("Ann Ordinary");
}

describe("the Directory tab", () => {
  it("is offered only where a domain controller was found and the viewer may read it", () => {
    const tab = DEVICE_MODULE_TABS.find((t) => t.id === "directory")!;
    const can = (p: string) => p === "ad.view";
    expect(moduleTabState(tab, roles([ROLE]), can)).toBe("shown");
    expect(moduleTabState(tab, roles([]), can)).toBe("absent");
    expect(moduleTabState(tab, roles([ROLE]), () => false)).toBe("absent");
    expect(moduleTabState(tab, roles([{ ...ROLE, enabled: false }]), can)).toBe("off");
  });

  it("reads the domain and its health only when asked, then lists users with their protection", async () => {
    const api = installFakeApi(controller());
    renderApp("/devices/d1?tab=directory");
    await screen.findByText("Not read yet");
    expect(api.callsTo("POST /devices/:id/winmod/:action")).toHaveLength(0);
    await readAll();
    expect(screen.getAllByText("dc1.corp.test").length).toBeGreaterThan(0);
    expect(screen.getByText(/Off: a deleted object is gone for good/)).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText(/Changes are made through this controller/)).toBeInTheDocument();
    // A protected account is marked and has no buttons; a locked one can be unlocked.
    const admin = screen.getByText("Admin Two").closest("tr")!;
    expect(within(admin).getByText("Protected")).toBeInTheDocument();
    expect(within(admin).queryByRole("button")).toBeNull();
    const bob = screen.getByText("Bob Locked").closest("tr")!;
    expect(within(bob).getByRole("button", { name: "Unlock" })).toBeInTheDocument();
  });

  it("offers no action to someone without the help-desk permission", async () => {
    installFakeApi(controller({}, VIEWER));
    renderApp("/devices/d1?tab=directory");
    await readAll();
    expect(screen.queryByRole("button", { name: "Unlock" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Disable" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Reset password" })).toBeNull();
  });

  it("asks for the account's name before disabling, and sends the typed confirmation", async () => {
    const api = installFakeApi(controller());
    renderApp("/devices/d1?tab=directory");
    await readAll();
    const ann = screen.getByText("Ann Ordinary").closest("tr")!;
    await userEvent.click(within(ann).getByRole("button", { name: "Disable" }));
    const dialog = await screen.findByRole("dialog");
    const go = within(dialog).getByRole("button", { name: "Disable" });
    expect(go).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Type ann to confirm/), "ann");
    await userEvent.click(go);
    await screen.findByText(/Done\./);
    const sent = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.params.action === "active_directory.user_disable")!;
    expect(sent.body).toEqual({ params: { id: "S-1-5-21-1-2-3-1104" }, confirm: "active_directory.user_disable:S-1-5-21-1-2-3-1104" });
  });

  it("shows a generated password once, and sends none", async () => {
    const api = installFakeApi(controller());
    renderApp("/devices/d1?tab=directory");
    await readAll();
    const ann = screen.getByText("Ann Ordinary").closest("tr")!;
    await userEvent.click(within(ann).getByRole("button", { name: "Reset password" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/Type ann to confirm/), "ann");
    await userEvent.click(within(dialog).getByRole("button", { name: "Reset password" }));
    await within(dialog).findByText(GENERATED);
    const sent = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.params.action === "active_directory.user_reset_password")!;
    expect(JSON.stringify(sent.body)).not.toContain(GENERATED);
    expect((sent.body as { params: Record<string, unknown> }).params).toMatchObject({ id: "S-1-5-21-1-2-3-1104", mustChange: true, unlock: false });
    expect((sent.body as { params: Record<string, unknown> }).params).not.toHaveProperty("password");
    expect(within(dialog).getByText(/Other controllers may take a few moments/)).toBeInTheDocument();
    // Closed, it is gone: opening the dialog again shows no password.
    await userEvent.click(within(dialog).getAllByRole("button", { name: "Close" }).at(-1)!);
    expect(screen.queryByText(GENERATED)).toBeNull();
    await userEvent.click(within(screen.getByText("Ann Ordinary").closest("tr")!).getByRole("button", { name: "Reset password" }));
    expect(screen.queryByText(GENERATED)).toBeNull();
  });

  it("says what a refusal by the controller was, in its own words", async () => {
    installFakeApi(controller({ user_reset_password: { code: "partial", message: "The password was changed, but the must-change flag or the unlock was not." } }));
    renderApp("/devices/d1?tab=directory");
    await readAll();
    await userEvent.click(within(screen.getByText("Ann Ordinary").closest("tr")!).getByRole("button", { name: "Reset password" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/Type ann to confirm/), "ann");
    await userEvent.click(within(dialog).getByRole("button", { name: "Reset password" }));
    await within(dialog).findByText(/The password was changed, but the must-change flag/);
    expect(screen.queryByText(GENERATED)).toBeNull();
  });

  it("explains a controller without the PowerShell module", async () => {
    installFakeApi(controller({ status: { code: "module_missing", message: "x" } }));
    renderApp("/devices/d1?tab=directory");
    await userEvent.click(await screen.findByRole("button", { name: "Read now" }));
    await screen.findByText(/RSAT-AD-PowerShell/);
  });

  it("lists a group's members", async () => {
    installFakeApi(controller());
    renderApp("/devices/d1?tab=directory");
    await readAll();
    await userEvent.click(screen.getByRole("button", { name: "List groups" }));
    await userEvent.click(await screen.findByRole("button", { name: "Members" }));
    await screen.findByText(/1 direct member/);
    expect(screen.getAllByText("Ann Ordinary").length).toBeGreaterThan(0);
  });
});
