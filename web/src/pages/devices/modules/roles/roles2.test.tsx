import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DeviceRole, DeviceRoles } from "../../../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../../../test/fakeApi";
import { device, history, inventory, metrics } from "../../../../test/fixtures";
import { renderApp } from "../../../../test/render";
import type { CaFindings, CaRequests, CaStatus, CaTemplates } from "./ca/types";
import type { Hardening, PrintJobDocs, PrintJobList, PrintStatus, PrinterList } from "./print/types";
import type { OpenFileList, SessionList, ShareAccess, ShareList, SharesStatus } from "./shares/types";

// The certificate authority, file-sharing and print views of the Roles tab (ADR-0076).

const AGENT = {
  version: "1.5.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z",
  enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null,
};
const SERVER = device("d1", "FS1", { platform: "windows", osDescription: "Windows Server 2025", agent: AGENT });
const role = (module: string, label: string): DeviceRole => ({ name: module, state: "present", module, label, enabled: true });
const roles = (r: DeviceRole[]): DeviceRoles => ({ known: true, reportedAt: "2026-11-26T10:00:00Z", roles: r });
const base = ["org.view", "site.view", "device.view"] as const;

type Results = Record<string, unknown>;
function routes(session: ReturnType<typeof sessionView>, r: DeviceRoles, results: Results) {
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(SERVER),
    "GET /devices/:id/roles": ok(r),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/disks": ok({ items: [] }),
    "GET /devices/:id/defender": fail(404, "not_found", "none"),
    "POST /devices/:id/winmod-read/:action": (req: { params: Record<string, string> }) =>
      ok({ action: req.params.action, takenAt: null, stale: true, data: null, refreshing: true, offline: false, runId: req.params.action }),
    "POST /devices/:id/winmod/:action": (req: { params: Record<string, string> }) =>
      ok({ jobId: "j", runId: req.params.action, action: req.params.action, status: "queued", expiresAt: "2026-11-26T11:00:00Z" }),
    "GET /winmod/runs/:id": (req: { params: Record<string, string> }) =>
      ok({ runId: req.params.id, deviceId: "d1", action: req.params.id, version: 1, status: "succeeded", finishedAt: "2026-11-26T10:00:00Z", ok: true, data: results[req.params.id!] ?? { done: true } }),
  } as Parameters<typeof installFakeApi>[0];
}

async function readNow() {
  await screen.findByRole("tab", { name: "Roles" });
}
const winmod = (api: ReturnType<typeof installFakeApi>, action: string) => api.callsTo("POST /devices/:id/winmod/:action").find((c) => c.params.action === action);

const SHARES_STATUS: SharesStatus = { serviceState: "running", shareCount: 4, userShareCount: 1, sessionCount: 1, openFileCount: 1, smb1Enabled: false, signingRequired: true, encryptionRequired: null };
const share = (name: string, protectedShare: boolean) => ({
  name, path: `D:\\${name}`, description: "", special: protectedShare, protected: protectedShare, scoped: false, continuouslyAvailable: false,
  encrypted: false, caching: "Manual", folderEnumeration: "AccessBased", concurrentUserLimit: 0,
});
const SHARES: ShareList = { truncated: false, shares: [share("Data", false), share("SYSVOL", true), share("C$", true)] };
const ACCESS: ShareAccess = { name: "Data", entries: [{ account: "CORP\\Staff", right: "Change", type: "Allow" }] };
const SESSIONS: SessionList = { total: 1, sessions: [{ id: "123", user: "CORP\\alice", client: "PC1", openFiles: 1, secondsActive: 60, secondsIdle: 5 }] };
const FILES: OpenFileList = { total: 1, files: [{ id: "9", sessionId: "123", path: "D:\\Data\\plan.xlsx", user: "CORP\\alice", client: "PC1", locks: 0 }] };

describe("the file shares view", () => {
  const results: Results = {
    "file_shares.status": SHARES_STATUS, "file_shares.share_list": SHARES, "file_shares.share_perms_get": ACCESS,
    "file_shares.session_list": SESSIONS, "file_shares.openfile_list": FILES,
  };
  const admin = sessionView({ isSuperAdmin: false, permissions: [...base, "shares.view", "shares.manage"] });

  it("shows the protected shares without a way to change them, and removes a share with the computer's name", async () => {
    const api = installFakeApi(routes(admin, roles([role("file_shares", "File shares")]), results));
    renderApp("/devices/d1?tab=roles");
    await readNow();
    const data = (await screen.findByText("Data", { selector: "td" })).closest("tr")!;
    for (const name of ["SYSVOL", "C$"]) {
      const row = screen.getByText(name, { selector: "td" }).closest("tr")!;
      expect(within(row).getByText("Protected")).toBeInTheDocument();
      expect(within(row).queryByRole("button", { name: "Remove" })).toBeNull();
    }
    await userEvent.click(within(data).getByRole("button", { name: "Remove" }));
    const dialog = await screen.findByRole("dialog");
    const go = within(dialog).getByRole("button", { name: "Remove share" });
    expect(go).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Type/), "FS1");
    await userEvent.click(go);
    await screen.findByText("Shares", { selector: "h2" });
    expect(winmod(api, "file_shares.share_remove")!.body).toEqual({ params: { device: "FS1", name: "Data" }, confirm: "file_shares.share_remove:FS1" });
  });

  it("reads the permissions of a share and lists sessions and open files", async () => {
    installFakeApi(routes(admin, roles([role("file_shares", "File shares")]), results));
    renderApp("/devices/d1?tab=roles");
    await readNow();
    await userEvent.click(within((await screen.findByText("Data", { selector: "td" })).closest("tr")!).getByRole("button", { name: "Permissions" }));
    expect(await screen.findByText("CORP\\Staff")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("radio", { name: "Sessions and open files" }));
    expect(await screen.findByText("D:\\Data\\plan.xlsx")).toBeInTheDocument();
  });

  it("offers no change to someone without shares.manage", async () => {
    installFakeApi(routes(sessionView({ isSuperAdmin: false, permissions: [...base, "shares.view"] }), roles([role("file_shares", "File shares")]), results));
    renderApp("/devices/d1?tab=roles");
    await readNow();
    await screen.findByText("Data", { selector: "td" });
    expect(screen.queryByRole("button", { name: "Remove" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Share a folder" })).toBeNull();
  });
});

const PRINT_STATUS: PrintStatus = { serviceState: "running", printerCount: 1, sharedCount: 0, jobCount: 1, domainController: false };
const PRINTERS: PrinterList = {
  truncated: false,
  printers: [{ name: "Front desk", driver: "d", port: "p", shared: false, shareName: "", published: false, status: "Normal", paused: false, offline: false, isDefault: true, jobCount: 1, jobsInError: 0, oldestJobAgeMinutes: 3 }],
};
const HARD: Hardening = { restrictDriverInstall: 0, noWarningNoElevation: null, updatePromptSettings: null, weakened: true, spoolerRunning: true, domainController: false };
const JOBS: PrintJobList = { printer: "Front desk", total: 1, jobs: [{ id: 7, status: "", sizeBytes: 1000, pages: 1, submitted: null, ageMinutes: 3 }] };
const DOCS: PrintJobDocs = { jobs: [{ id: 7, document: "payroll.pdf", owner: "CORP\\bob", client: "PC2" }] };

describe("the print view", () => {
  const results: Results = { "print.status": PRINT_STATUS, "print.printer_list": PRINTERS, "print.hardening_status": HARD, "print.job_list": JOBS, "print.job_list_sensitive": DOCS };
  const tech = sessionView({ isSuperAdmin: false, permissions: [...base, "print.view", "print.manage"] });
  const admin = sessionView({ isSuperAdmin: false, permissions: [...base, "print.view", "print.manage", "print.view_sensitive", "print.destroy"] });

  it("gives a Technician pause and cancel but no tier 3 action and no document names", async () => {
    const api = installFakeApi(routes(tech, roles([role("print", "Print")]), results));
    renderApp("/devices/d1?tab=roles");
    await readNow();
    const row = (await screen.findByText("Front desk", { selector: "td" })).closest("tr")!;
    expect(screen.getByText("Point and Print is weakened")).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: "Remove" })).toBeNull();
    expect(within(row).queryByRole("button", { name: "Clear queue" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Restart the Print Spooler" })).toBeNull();
    await userEvent.click(within(row).getByRole("button", { name: "Jobs" }));
    await screen.findByText("Jobs of Front desk");
    expect(screen.queryByText(/payroll\.pdf/)).toBeNull();
    expect(winmod(api, "print.job_list_sensitive")).toBeUndefined();
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await screen.findByText("Jobs of Front desk");
    expect(winmod(api, "print.job_cancel")!.body).toEqual({ params: { printer: "Front desk", ids: "7" } });
  });

  it("shows document names to print.view_sensitive and clears a queue with a typed name", async () => {
    const api = installFakeApi(routes(admin, roles([role("print", "Print")]), results));
    renderApp("/devices/d1?tab=roles");
    await readNow();
    const row = (await screen.findByText("Front desk", { selector: "td" })).closest("tr")!;
    await userEvent.click(within(row).getByRole("button", { name: "Jobs" }));
    expect(await screen.findByText(/payroll\.pdf/)).toBeInTheDocument();
    await userEvent.click(within(row).getByRole("button", { name: "Clear queue" }));
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByLabelText(/Type/), "FS1");
    await userEvent.click(within(dialog).getByRole("button", { name: "Cancel all jobs" }));
    await screen.findByText("Printers", { selector: "h2" });
    expect(winmod(api, "print.queue_clear")!.body).toEqual({ params: { device: "FS1", printer: "Front desk" }, confirm: "print.queue_clear:FS1" });
  });
});

const CA_STATUS: CaStatus = {
  caName: "Corp CA", caType: "enterprise_root", enterprise: true, serviceState: "running",
  certificate: { subject: "CN=Corp CA", thumbprint: "AB", notAfter: "2031-01-01T00:00:00Z", daysLeft: 1500, signatureAlgorithm: "sha256RSA", keyLength: 4096 },
  crl: { baseThisUpdate: null, baseNextUpdate: "2026-12-01T00:00:00Z", hoursToBaseExpiry: 100, deltaNextUpdate: null },
  counts: { pending: 1, issued: 3, revoked: 0, failed: 0 },
};
const PENDING: CaRequests = {
  total: 1, next: null,
  requests: [{ id: 12, requester: "CORP\\carol", template: "WebServer", submitted: null, serial: "", notAfter: null, commonName: "intranet.example.test", revokedWhen: null, revokedReason: null, disposition: "pending" }],
};
const TEMPLATES: CaTemplates = { standalone: false, templates: [] };
const FINDINGS: CaFindings = { caName: "Corp CA", findings: [{ id: "ESC6:Corp CA", class: "ESC6", subject: "Corp CA", evidence: "The CA accepts a subject alternative name from the request." }], notes: [] };

describe("the certificate authority view", () => {
  const results: Results = {
    "certificate_authority.status": CA_STATUS, "certificate_authority.requests_pending": PENDING,
    "certificate_authority.requests_list": { requests: [], total: 0, next: null }, "certificate_authority.template_list": TEMPLATES,
    "certificate_authority.template_available": TEMPLATES, "certificate_authority.ca_findings": FINDINGS,
  };
  const admin = sessionView({ isSuperAdmin: false, permissions: [...base, "ca.view", "ca.manage"] });

  it("approves a pending request only with the computer's name typed", async () => {
    const api = installFakeApi(routes(admin, roles([role("certificate_authority", "Certificate authority")]), results));
    renderApp("/devices/d1?tab=roles");
    await readNow();
    await userEvent.click(await screen.findByRole("button", { name: "Approve" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/Every computer that trusts this CA/)).toBeInTheDocument();
    const go = within(dialog).getByRole("button", { name: "Approve and issue" });
    expect(go).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Type/), "FS1");
    await userEvent.click(go);
    await waitFor(() => expect(winmod(api, "certificate_authority.request_approve")).toBeDefined());
    expect(winmod(api, "certificate_authority.request_approve")!.body).toEqual({ params: { device: "FS1", id: 12 }, confirm: "certificate_authority.request_approve:FS1" });
  });

  it("shows the findings and says it offers no fix", async () => {
    installFakeApi(routes(admin, roles([role("certificate_authority", "Certificate authority")]), results));
    renderApp("/devices/d1?tab=roles");
    await readNow();
    await userEvent.click(await screen.findByRole("radio", { name: "Findings" }));
    expect(await screen.findByText("ESC6: Corp CA")).toBeInTheDocument();
    expect(screen.getByText(/does not offer a fix/)).toBeInTheDocument();
  });
});

describe("modules read by themselves", () => {
  const results: Results = {
    "file_shares.status": SHARES_STATUS, "file_shares.share_list": SHARES, "file_shares.share_perms_get": ACCESS,
    "file_shares.session_list": SESSIONS, "file_shares.openfile_list": FILES,
  };
  const admin = sessionView({ isSuperAdmin: false, permissions: [...base, "shares.view", "shares.manage"] });

  it("shows the page's skeleton until the first result, with no button to read", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    installFakeApi({
      ...routes(admin, roles([role("file_shares", "File shares")]), results),
      "GET /winmod/runs/:id": async (req: { params: Record<string, string> }) => {
        await gate;
        return ok({ runId: req.params.id, deviceId: "d1", action: req.params.id, version: 1, status: "succeeded", finishedAt: "2026-11-26T10:00:00Z", ok: true, data: results[req.params.id!] });
      },
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/devices/d1?tab=roles");
    expect(await screen.findByRole("status", { name: "Loading File shares" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /read now|refresh/i })).toBeNull();
    expect(screen.queryByText("Data", { selector: "td" })).toBeNull();
    release();
    expect(await screen.findByText("Data", { selector: "td" })).toBeInTheDocument();
    expect(screen.queryByRole("status", { name: "Loading File shares" })).toBeNull();
  });

  it("shows the stored result at once with its age, and puts the new one in place when it arrives", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    const stored = { ...SHARES_STATUS, shareCount: 7 };
    installFakeApi({
      ...routes(admin, roles([role("file_shares", "File shares")]), results),
      "POST /devices/:id/winmod-read/:action": (req: { params: Record<string, string> }) =>
        ok({
          action: req.params.action, takenAt: "2026-11-26T09:58:00Z", stale: true, refreshing: true, offline: false, runId: req.params.action,
          data: req.params.action === "file_shares.status" ? stored : results[req.params.action!],
        }),
      "GET /winmod/runs/:id": async (req: { params: Record<string, string> }) => {
        await gate;
        return ok({ runId: req.params.id, deviceId: "d1", action: req.params.id, version: 1, status: "succeeded", finishedAt: "2026-11-26T10:00:00Z", ok: true, data: results[req.params.id!] });
      },
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/devices/d1?tab=roles");
    expect(await screen.findByText(/\(7 with the administrative ones\)/)).toBeInTheDocument();
    expect(screen.getByText(/As of/)).toBeInTheDocument();
    expect(await screen.findByText("Updating")).toBeInTheDocument();
    release();
    expect(await screen.findByText(/\(4 with the administrative ones\)/)).toBeInTheDocument();
    expect(screen.queryByText(/\(7 with the administrative ones\)/)).toBeNull();
  });

  it("opens a share's permissions when Permissions is clicked, and changes them from the dialog", async () => {
    const api = installFakeApi(routes(admin, roles([role("file_shares", "File shares")]), results));
    renderApp("/devices/d1?tab=roles");
    const row = (await screen.findByText("Data", { selector: "td" })).closest("tr")!;
    const button = within(row).getByRole("button", { name: "Permissions" });
    expect(button).toBeEnabled();
    await userEvent.click(button);
    const dialog = await screen.findByRole("dialog", { name: "Permissions of Data" });
    expect(await within(dialog).findByText("CORP\\Staff")).toBeInTheDocument();
    expect(api.callsTo("POST /devices/:id/winmod-read/:action").some((c) => c.params.action === "file_shares.share_perms_get" && JSON.stringify(c.body) === JSON.stringify({ params: { name: "Data" } }))).toBe(true);
    // Edit: Grant access opens the grant form for this share; closing it returns to the permissions.
    await userEvent.click(within(dialog).getByRole("button", { name: "Grant access" }));
    const grant = await screen.findByRole("dialog", { name: "Grant share access" });
    await userEvent.type(within(grant).getByLabelText(/User or group/), "CORP\\Ops");
    await userEvent.type(within(grant).getByLabelText(/Type/), "FS1");
    await userEvent.click(within(grant).getByRole("button", { name: "Grant" }));
    await screen.findByRole("dialog", { name: "Permissions of Data" });
    expect(winmod(api, "file_shares.share_grant")!.body).toEqual({
      params: { device: "FS1", name: "Data", account: "CORP\\Ops", right: "Read" }, confirm: "file_shares.share_grant:FS1",
    });
  });

  it("shows a protected share's permissions and offers no change to them", async () => {
    installFakeApi(routes(admin, roles([role("file_shares", "File shares")]), results));
    renderApp("/devices/d1?tab=roles");
    const row = (await screen.findByText("SYSVOL", { selector: "td" })).closest("tr")!;
    await userEvent.click(within(row).getByRole("button", { name: "Permissions" }));
    const dialog = await screen.findByRole("dialog", { name: "Permissions of SYSVOL" });
    expect(within(dialog).queryByRole("button", { name: "Grant access" })).toBeNull();
    expect(within(dialog).queryByRole("button", { name: "Revoke" })).toBeNull();
  });
});
