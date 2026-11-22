import { describe, expect, it, vi } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PatchJobDetail, PatchJobFacts, PatchJobItem, PatchJobUpdateFacts, PatchJobView } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { renderWithProviders } from "../../test/render";
import { CVES_SHOWN, EVENTS_SHOWN, PatchJobDialog, UPDATES_SHOWN } from "./PatchJobDialog";

// A patch job in full (ADR-0030, amended 2026-11-22): its summary, how it started, the device, each update with what
// the patching engine knows of it, and its timeline; long lists show their first entries and a button for the rest.

const T0 = "2026-11-22T10:00:00Z";
const T1 = "2026-11-22T10:02:00Z";
const T2 = "2026-11-22T10:14:30Z";

const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "patch.view", "patch.manage"] });

function job(extra: Partial<PatchJobView> = {}): PatchJobView {
  return {
    id: "j1",
    endpointId: "e1",
    hostname: "web-01",
    type: "InstallUpdates",
    status: "Completed",
    trigger: "Manual",
    requestedBy: "tess@example.com",
    createdAt: T0,
    startedAt: T1,
    completedAt: T2,
    expiresAt: "2026-11-29T10:00:00Z",
    progressPercent: null,
    phase: "",
    progressMessage: "",
    errorCode: "",
    errorMessage: "",
    rebootRequired: false,
    timedOut: false,
    cancelRequested: false,
    itemCount: 0,
    succeededCount: 0,
    failedCount: 0,
    deviceId: "d1",
    deviceName: "WEB-01",
    canManage: true,
    ...extra,
  };
}

function item(n: number, extra: Partial<PatchJobItem> = {}): PatchJobItem {
  return {
    updateGuid: `u${n}`,
    title: `Update ${n}`,
    kbNumber: "",
    category: "Security",
    status: "Succeeded",
    skipReason: "",
    resultCode: 2,
    errorCode: "",
    errorMessage: "",
    rebootRequired: false,
    downloadPercent: 100,
    installPercent: 100,
    startedAt: T1,
    completedAt: T2,
    ...extra,
  };
}

function facts(extra: Partial<PatchJobUpdateFacts> = {}): PatchJobUpdateFacts {
  return {
    kbNumbers: [],
    msrcSeverity: "",
    sizeBytes: null,
    releaseDate: null,
    cveIds: [],
    knownExploited: false,
    kevDueDate: "",
    supportUrl: "",
    state: "Installed",
    package: null,
    ...extra,
  };
}

/** A job as the dialog shows it: its detail, and what the engine knows of its updates, read apart. */
type Shown = PatchJobDetail & PatchJobFacts;

function detail(extra: Partial<Shown> = {}): Shown {
  return {
    summary: job(),
    installMode: "Selected",
    notBefore: null,
    deliveredAt: "2026-11-22T10:00:30Z",
    acknowledgedAt: "2026-11-22T10:01:00Z",
    lastProgressAt: T2,
    deliveryCount: 1,
    retryOfJobId: null,
    cancelRequestedAt: null,
    items: [],
    events: [],
    deviceId: "d1",
    deviceName: "WEB-01",
    canManage: true,
    restartAfter: null,
    restartFor: null,
    device: {
      organizationName: "Northwind Traders",
      siteName: "Head office",
      platform: "windows",
      os: "Microsoft Windows Server 2022 Standard",
      agentVersion: "0.6.0",
      endpoint: {
        hostname: "web-01",
        operatingSystem: "Windows Server 2022 Standard",
        osBuild: "20348.2849",
        osSupportStatus: "Supported",
        agentVersion: "1.10.0",
        agentOutdated: false,
        online: true,
        lastCheckInAt: T2,
        rebootPending: false,
      },
    },
    origin: null,
    updateFacts: {},
    updateFactsError: null,
    ...extra,
  };
}

let shown: { unmount: () => void } | null = null;

/** Opens a job in the dialog, closing the one open before. */
async function open(d: Shown, onJob: (id: string) => void = () => {}) {
  shown?.unmount();
  const { updateFacts, updateFactsError, ...rest } = d;
  installFakeApi({ ...baseRoutes(TECH), "GET /patching/jobs/:id": ok(rest), "GET /patching/jobs/:id/facts": ok({ updateFacts, updateFactsError }) });
  shown = renderWithProviders(<PatchJobDialog jobId={d.summary.id} onClose={() => {}} onJob={onJob} />);
  const dialog = await screen.findByRole("dialog", { name: /on WEB-01$/ });
  await within(dialog).findByRole("region", { name: "Summary" });
  return dialog;
}

const region = (dialog: HTMLElement, name: string) => within(dialog).getByRole("region", { name });

describe("a patch job in full", () => {
  it("sums the job up: its result, how long it took, the updates by status and size, and the restart it needs", async () => {
    const d = detail({
      summary: job({ itemCount: 3, succeededCount: 2, failedCount: 1, rebootRequired: true, status: "Failed" }),
      items: [item(1, { rebootRequired: true }), item(2), item(3, { status: "Failed", resultCode: 4, errorCode: "0x80070643" })],
      updateFacts: { u1: facts({ sizeBytes: 3 * 1024 ** 2 }), u2: facts({ sizeBytes: 1024 ** 2 }) },
    });
    const dialog = await open(d);
    const summary = region(dialog, "Summary");
    expect(summary).toHaveTextContent("2 of 3 updates installed, 1 failed");
    expect(summary).toHaveTextContent("Took12 min");
    expect(summary).toHaveTextContent("RestartNeeded to finish");
    const totals = within(region(dialog, "Updates")).getByRole("list", { name: "Totals" });
    expect(totals).toHaveTextContent("3 in all");
    expect(totals).toHaveTextContent("Succeeded: 2");
    expect(totals).toHaveTextContent("Failed: 1");
    expect(totals).toHaveTextContent("Size: 4.0 MiB (1 size unknown)");
    expect(totals).toHaveTextContent("1 update need a restart");
  });

  it("explains the engine's error: a known code in hex with what it means and what to try, an unknown one as unknown", async () => {
    const dialog = await open(
      detail({ summary: job({ status: "Failed", errorCode: "-2145107924", errorMessage: "Installation failed: 0x8024402C" }) }),
    );
    const alert = within(dialog).getByRole("alert");
    expect(alert).toHaveTextContent("The patching engine reported an error");
    expect(alert).toHaveTextContent("Installation failed: 0x8024402C");
    expect(alert).toHaveTextContent("0x8024402C The name of the update server or proxy could not be resolved.");
    expect(alert).toHaveTextContent("Check the device's DNS and proxy settings.");

    const unknown = await open(detail({ summary: job({ status: "Failed", errorCode: "0x80249999", errorMessage: "" }) }));
    expect(within(unknown).getByRole("alert")).toHaveTextContent("0x80249999 Unknown code (a Windows Update error EasyRMM has no explanation for).");
  });

  it("says how the job started: by whom, as part of which Patch all, with which updates", async () => {
    const d = detail({
      origin: {
        action: "patch.install",
        by: "tess@example.com",
        system: false,
        at: T0,
        patchAll: "Downtown clinic (Contoso Dental Group)",
        requestId: "5d1e0c9a-0000-4000-8000-000000000001",
        updates: "all available",
        featureUpgrades: false,
        scheduledAt: null,
      },
    });
    const origin = region(await open(d), "How it started");
    expect(origin).toHaveTextContent("tess@example.com");
    expect(origin).toHaveTextContent("A request for every device in Downtown clinic (Contoso Dental Group)");
    expect(origin).toHaveTextContent("Request 5d1e0c9a-0000-4000-8000-000000000001");
    expect(origin).toHaveTextContent("Every available update, without feature upgrades");
  });

  it("says when EasyRMM started a job itself, or a policy or the engine did, and links the job it runs again", async () => {
    const user = userEvent.setup();
    const onJob = vi.fn();
    const restart = detail({
      summary: job({ type: "Restart" }),
      restartFor: "j0",
      origin: {
        action: "patch.restart",
        by: "patching",
        system: true,
        at: T0,
        patchAll: null,
        requestId: null,
        updates: null,
        featureUpgrades: null,
        scheduledAt: null,
      },
    });
    let origin = region(await open(restart, onJob), "How it started");
    expect(origin).toHaveTextContent("Started byEasyRMM");
    await user.click(within(origin).getByRole("button", { name: "The install job" }));
    expect(onJob).toHaveBeenCalledWith("j0");

    origin = region(await open(detail({ summary: job({ trigger: "Scheduled", requestedBy: "policy" }) })), "How it started");
    expect(origin).toHaveTextContent("On a schedule");
    expect(origin).toHaveTextContent("The device's patch policy started it in its maintenance window.");

    origin = region(await open(detail({ retryOfJobId: "j0" }), onJob), "How it started");
    expect(origin).toHaveTextContent("By hand, by tess@example.com");
    expect(origin).toHaveTextContent("EasyRMM has no record of starting it");
    await user.click(within(origin).getByRole("button", { name: "The earlier job" }));
    expect(onJob).toHaveBeenLastCalledWith("j0");
  });

  it("shows the device as EasyRMM and the engine know it, and says when the engine could not be read", async () => {
    const d = detail();
    d.device.endpoint = { ...d.device.endpoint!, osSupportStatus: "ExtendedSecurityUpdates", agentOutdated: true, rebootPending: true, online: false };
    const device = region(await open(d), "Device");
    expect(within(device).getByRole("link", { name: "WEB-01" })).toHaveAttribute("href", "/devices/d1?tab=patches");
    expect(device).toHaveTextContent("Northwind Traders / Head office");
    expect(device).toHaveTextContent("Windows Server 2022 Standard (build 20348.2849)");
    expect(device).toHaveTextContent("Extended security updates only");
    expect(device).toHaveTextContent("EasyRMM agent0.6.0");
    expect(device).toHaveTextContent("EasyPatch agent1.10.0Outdated");
    expect(device).toHaveTextContent("Offline");
    expect(device).toHaveTextContent("A restart is pending on the device.");

    const unread = detail({ device: { ...d.device, agentVersion: null, endpoint: null } });
    const without = region(await open(unread), "Device");
    expect(without).toHaveTextContent("Microsoft Windows Server 2022 Standard");
    expect(without).toHaveTextContent("EasyRMM agentNone");
    expect(without).toHaveTextContent("The patching engine could not be read");
    expect(without).not.toHaveTextContent("EasyPatch agent");
  });

  it("shows each update: its KB or package, severity, size, CVEs and whether it is exploited, and why it failed", async () => {
    const user = userEvent.setup();
    const cves = Array.from({ length: CVES_SHOWN + 3 }, (_, i) => `CVE-2026-10${i}`);
    const d = detail({
      items: [
        item(1, { title: "2026-11 Cumulative Update for Windows Server 2022", kbNumber: "5070001", rebootRequired: true }),
        item(2, { title: "openssl 3.5.7-1~deb13u3", category: "Security", status: "Failed", errorCode: "apt_exit_100", errorMessage: "dpkg was interrupted" }),
        item(3, { title: "Defender platform", status: "Failed", errorCode: "0x80249999", errorMessage: "" }),
        item(4, { title: "Driver", status: "Skipped", skipReason: "RequiresUserInput", resultCode: null }),
      ],
      updateFacts: {
        u1: facts({ kbNumbers: ["5070001"], msrcSeverity: "Critical", sizeBytes: 512 * 1024 ** 2, cveIds: cves, knownExploited: true, kevDueDate: "2026-12-01", supportUrl: "https://support.example.com/kb/5070001" }),
        u2: facts({ state: "Failed", package: { name: "openssl", version: "3.5.7-1~deb13u3", installedVersion: "3.5.6-1", repository: "trixie-security", advisories: ["DSA-6001-1"] } }),
      },
    });
    const updates = region(await open(d), "Updates");
    const [first, second, third, fourth] = within(updates)
      .getAllByRole("listitem")
      .filter((li) => li.closest("ul")?.getAttribute("aria-label") !== "Totals") as [HTMLElement, HTMLElement, HTMLElement, HTMLElement];
    const rows = [first, second, third, fourth] as const;
    expect(rows[0]).toHaveTextContent("KB5070001 · Security · Critical · 512 MiB");
    expect(rows[0]).toHaveTextContent(`Known exploited, fix by`);
    expect(within(rows[0]).getAllByText(/^CVE-2026-10/)).toHaveLength(CVES_SHOWN);
    await user.click(within(rows[0]).getByRole("button", { name: "3 more CVEs" }));
    expect(within(rows[0]).getAllByText(/^CVE-2026-10/)).toHaveLength(CVES_SHOWN + 3);
    expect(rows[0]).toHaveTextContent("Needs a restart to finish");
    expect(within(rows[0]).getByRole("link", { name: "About this update" })).toHaveAttribute("href", "https://support.example.com/kb/5070001");
    expect(rows[0]).toHaveTextContent("On the device now: Installed");
    expect(rows[1]).toHaveTextContent("On the device now: Failed");
    expect(rows[2]).not.toHaveTextContent("On the device now");
    expect(rows[1]).toHaveTextContent("openssl 3.5.7-1~deb13u3, from 3.5.6-1");
    expect(rows[1]).toHaveTextContent("Advisories: DSA-6001-1");
    expect(rows[1]).toHaveTextContent("dpkg was interrupted");
    expect(rows[1]).toHaveTextContent("Code apt_exit_100");
    expect(rows[2]).toHaveTextContent("0x80249999 Unknown code");
    expect(rows[2]).toHaveTextContent("The patching engine no longer lists this update for the device.");
    expect(rows[3]).toHaveTextContent("Skipped: Needs someone at the computer to install");
  });

  it("says when the engine's details of the updates could not be read, rather than that it has none", async () => {
    const d = detail({ items: [item(1)], updateFactsError: "The patching engine is not answering." });
    const updates = region(await open(d), "Updates");
    expect(updates).toHaveTextContent("The patching engine's details of these updates could not be read");
    expect(updates).toHaveTextContent("The patching engine is not answering.");
    expect(updates).not.toHaveTextContent("no longer lists");
  });

  it("shows the first updates of a long job, and all of them when asked", async () => {
    const user = userEvent.setup();
    const many = Array.from({ length: UPDATES_SHOWN + 35 }, (_, i) => item(i + 1));
    const updates = region(await open(detail({ items: many })), "Updates");
    expect(within(updates).getByText(`Update ${UPDATES_SHOWN}`)).toBeInTheDocument();
    expect(within(updates).queryByText(`Update ${UPDATES_SHOWN + 1}`)).not.toBeInTheDocument();
    await user.click(within(updates).getByRole("button", { name: `Show all ${many.length} updates` }));
    expect(within(updates).getByText(`Update ${many.length}`)).toBeInTheDocument();
    expect(within(updates).queryByRole("button", { name: /Show all/ })).not.toBeInTheDocument();
  });

  it("puts what happened in order, the engine's events among it, and shows the first entries of a long timeline", async () => {
    const user = userEvent.setup();
    const d = detail({
      events: [
        { id: 2, type: "JobFinished", severity: "Error", message: "Install updates failed: 1 update failed.", createdAt: "2026-11-22T10:14:31Z" },
        { id: 1, type: "JobStarted", severity: "Info", message: "Install updates started.", createdAt: "2026-11-22T10:02:01Z" },
        { id: 0, type: "JobQueued", severity: "Info", message: "Install updates queued by tess@example.com.", createdAt: T0 },
      ],
      summary: job({ status: "Failed" }),
    });
    const timeline = region(await open(d), "Timeline");
    // Each entry: when, then what; the engine's queued and started events, which say again what the job's own times
    // say, are left out.
    const entries = within(timeline)
      .getAllByRole("listitem")
      .map((li) => li.querySelector("span")?.textContent);
    expect(within(timeline).getAllByRole("listitem")[0]!.querySelector("time")).toHaveAttribute("dateTime", T0);
    expect(entries).toEqual([
      "Requested by tess@example.com",
      "Sent to the device",
      "The device accepted it",
      "Started",
      "Failed",
      "Install updates failed: 1 update failed.",
    ]);
    expect(within(timeline).getByText("Install updates failed: 1 update failed.")).toHaveClass("text-danger");

    const events = Array.from({ length: EVENTS_SHOWN + 10 }, (_, i) => ({
      id: i,
      type: "Progress",
      severity: "Info",
      message: `Step ${i + 1}`,
      createdAt: new Date(Date.parse(T1) + i * 1000).toISOString(),
    }));
    const long = region(await open(detail({ events })), "Timeline");
    expect(within(long).getAllByRole("listitem")).toHaveLength(EVENTS_SHOWN);
    await user.click(within(long).getByRole("button", { name: /^Show all \d+ entries$/ }));
    expect(within(long).getByText(`Step ${EVENTS_SHOWN + 10}`)).toBeInTheDocument();
  });

  it("shows nothing to fill in for a job just queued: no updates, no device view from the engine, one entry", async () => {
    const d = detail({
      summary: job({ status: "Queued", startedAt: null, completedAt: null, type: "UpdateScan" }),
      deliveredAt: null,
      acknowledgedAt: null,
      lastProgressAt: null,
      deliveryCount: 0,
    });
    const dialog = await open(d);
    expect(within(dialog).queryByRole("region", { name: "Updates" })).not.toBeInTheDocument();
    expect(region(dialog, "Summary")).not.toHaveTextContent("Took");
    expect(region(dialog, "Summary")).toHaveTextContent("Gives up at");
    expect(within(region(dialog, "Timeline")).getAllByRole("listitem")).toHaveLength(1);
  });
});
