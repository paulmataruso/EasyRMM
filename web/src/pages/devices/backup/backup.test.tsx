import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { BackupStatus, DeviceRole, DeviceRoles, Permission } from "../../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../../test/fakeApi";
import { device, history, inventory, metrics } from "../../../test/fixtures";
import { renderApp } from "../../../test/render";

// The Backup tab (ADR-0077): a server's state and actions with their tiers, a desktop's honest card, and the share
// password as a secret that is sent once and never shown again.

const AGENT = {
  version: "1.5.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z",
  enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null,
};
const SERVER = device("d1", "FILE-SRV", { platform: "windows", osDescription: "Windows Server 2025", agent: AGENT });
const BASE: Permission[] = ["org.view", "site.view", "device.view", "backup.view", "backup.manage"];
const TECH = sessionView({ isSuperAdmin: false, permissions: BASE });
const ADMIN = sessionView({ isSuperAdmin: false, permissions: [...BASE, "backup.destroy", "backup.view_sensitive"] });

const ROLE: DeviceRole = { name: "windows_backup", state: "present", module: "windows_backup", label: "Windows Backup", enabled: true };
const roles = (r: DeviceRole[]): DeviceRoles => ({ known: true, reportedAt: "2026-11-26T10:00:00Z", roles: r });

const STATUS: BackupStatus = {
  installed: true, configured: true, running: false, nextRun: "2026-11-27T21:00:00Z", lastSuccess: "2026-11-26T21:00:00Z",
  lastFailure: null, lastResultHR: 0, lastSuccessAgeDays: 0, versionCount: 4, oldestVersion: "2026-11-20T21:00:00Z",
  newestVersion: "2026-11-26T21:00:00Z", schedule: ["21:00"], systemState: true, bareMetal: false, volumeCount: 1,
  fileSpecCount: 2, vssFull: false, targets: [{ kind: "network", freeBytes: 500e9, totalBytes: 1000e9, online: true }], job: null,
};

type Reply = { ok: boolean; data?: unknown; failure?: { code: string; message: string } };

/** Routes for every action: the result of each is looked up in `results` by action name. */
function routes(session: ReturnType<typeof sessionView>, r: DeviceRoles, results: Record<string, Reply>) {
  const last = { action: "" };
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(SERVER),
    "GET /devices/:id/roles": ok(r),
    "POST /devices/:id/roles/rescan": { status: 202 },
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: [] }),
    "GET /devices/:id/defender": fail(404, "not_found", "none"),
    "POST /devices/:id/winmod/:action": (req: { params: Record<string, string> }) => {
      last.action = req.params.action!.replace("windows_backup.", "");
      return ok({ jobId: "j", runId: `r-${last.action}`, action: req.params.action, status: "queued", expiresAt: "2026-11-26T11:00:00Z" });
    },
    "GET /winmod/runs/:id": (req: { params: Record<string, string> }) => {
      const action = req.params.id!.replace("r-", "");
      const res = results[action] ?? { ok: true, data: {} };
      return ok({ runId: req.params.id, deviceId: "d1", action, version: 1, status: "succeeded", finishedAt: "2026-11-26T10:00:00Z", ...res });
    },
  } as Parameters<typeof installFakeApi>[0];
}

describe("the Backup tab", () => {
  it("shows a server's state and starts a backup without a confirmation", async () => {
    const api = installFakeApi(routes(TECH, roles([ROLE]), { status: { ok: true, data: STATUS }, run_now: { ok: true, data: { done: true } } }));
    renderApp("/devices/d1?tab=backup");
    await screen.findByText("Healthy");
    expect(screen.getAllByText("Network share").length).toBeGreaterThan(1);
    expect(screen.getByText(/free of/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Run now/ }));
    await waitFor(() => expect(api.callsTo("POST /devices/:id/winmod/:action").some((c) => c.path.endsWith("windows_backup.run_now"))).toBe(true));
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.path.endsWith("windows_backup.run_now"))!;
    expect((call.body as { confirm?: string }).confirm).toBeUndefined();
  });

  it("keeps tier 3 actions off for someone without backup.destroy", async () => {
    installFakeApi(routes(TECH, roles([ROLE]), { status: { ok: true, data: STATUS } }));
    renderApp("/devices/d1?tab=backup");
    await screen.findByText("Healthy");
    expect(screen.getByRole("button", { name: "Remove policy" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Whole disk" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove old versions" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Show paths and folders" })).toBeNull();
  });

  it("removes the policy only after the computer's name is typed, with the confirmation the server expects", async () => {
    const api = installFakeApi(routes(ADMIN, roles([ROLE]), { status: { ok: true, data: STATUS }, policy_remove: { ok: true, data: { done: true } } }));
    renderApp("/devices/d1?tab=backup");
    await screen.findByText("Healthy");
    await userEvent.click(screen.getByRole("button", { name: "Remove policy" }));
    const dialog = await screen.findByRole("dialog", { name: /Remove the backup policy/ });
    const submit = within(dialog).getByRole("button", { name: "Remove policy" });
    expect(submit).toBeDisabled();
    await userEvent.type(within(dialog).getByRole("textbox"), "FILE-SRV");
    await userEvent.click(submit);
    await waitFor(() => expect(api.callsTo("POST /devices/:id/winmod/:action").some((c) => c.path.endsWith("windows_backup.policy_remove"))).toBe(true));
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.path.endsWith("windows_backup.policy_remove"))!;
    expect(call.body).toMatchObject({ confirm: "windows_backup.policy_remove:FILE-SRV", params: { device: "FILE-SRV" } });
  });

  it("sends the share password once, as a password field, and clears it", async () => {
    const api = installFakeApi(routes(TECH, roles([ROLE]), { status: { ok: true, data: STATUS }, target_network_set: { ok: true, data: { done: true, credentialSet: true } } }));
    renderApp("/devices/d1?tab=backup");
    await screen.findByText("Healthy");
    await userEvent.click(screen.getByRole("button", { name: "Network share" }));
    const dialog = await screen.findByRole("dialog", { name: /Back up to a network share/ });
    expect(within(dialog).getByText(/overwrites the last one/)).toBeInTheDocument();
    const password = within(dialog).getByLabelText(/Password/);
    expect(password).toHaveAttribute("type", "password");
    await userEvent.type(within(dialog).getByLabelText(/Account/), "EXAMPLE\\svc");
    await userEvent.type(password, "s3cret-value");
    await userEvent.click(within(dialog).getByRole("button", { name: "Set target" }));
    await waitFor(() => expect(api.callsTo("POST /devices/:id/winmod/:action").some((c) => c.path.endsWith("windows_backup.target_network_set"))).toBe(true));
    const call = api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.path.endsWith("windows_backup.target_network_set"))!;
    expect(call.body).toMatchObject({ confirm: "windows_backup.target_network_set:FILE-SRV", params: { user: "EXAMPLE\\svc", password: "s3cret-value" } });
    expect(document.body.textContent).not.toContain("s3cret-value");
  });

  it("offers to install the feature on a server that lacks it, and reads nothing", async () => {
    const api = installFakeApi(routes(ADMIN, roles([{ ...ROLE, state: "not_installed" }]), {}));
    renderApp("/devices/d1?tab=backup");
    await screen.findByText("Windows Server Backup is not installed");
    expect(screen.getByRole("button", { name: "Install Windows Server Backup" })).toBeEnabled();
    expect(api.callsTo("POST /devices/:id/winmod/:action")).toHaveLength(0);
  });

  it("says plainly that a desktop is not managed, and that the Windows 11 Backup app has no management interface", async () => {
    installFakeApi(routes(TECH, roles([ROLE]), { status: { ok: false, failure: { code: "not_offered", message: "x" } } }));
    renderApp("/devices/d1?tab=backup");
    await screen.findByText("What Windows allows on a desktop");
    expect(screen.getByText(/Backup app.*no management interface/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Run now/ })).toBeNull();
  });

  it("explains a refusal in words", async () => {
    installFakeApi(routes(TECH, roles([ROLE]), { status: { ok: true, data: STATUS }, run_now: { ok: false, failure: { code: "busy", message: "x" } } }));
    renderApp("/devices/d1?tab=backup");
    await screen.findByText("Healthy");
    await userEvent.click(screen.getByRole("button", { name: /Run now/ }));
    await screen.findByText(/running another operation/);
  });
});
