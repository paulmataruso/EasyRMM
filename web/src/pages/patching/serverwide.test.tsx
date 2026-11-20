import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PatchAgentPackage, PatchAuditEntry, PatchLifecycleEntry, PatchLifecycleInput, PatchServerSettings, PatchSettingsView, PatchStatus } from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, type FakeHandler, type FakeReply } from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { engineActionLabel } from "./EngineAudit";

// EasyPatch's server-wide settings under Settings → Patching.

const main = () => within(screen.getByRole("main"));

async function open(path: string) {
  renderApp(path);
  await screen.findByRole("main");
}

const READY: PatchStatus = { configured: true, canSchedule: false };

const SUPER = sessionView({
  permissions: ["org.view", "site.view", "device.view", "settings.manage", "audit.view", "report.view", "patch.view", "patch.manage", "patch.configure"],
  globalPermissions: ["org.view", "site.view", "device.view", "audit.view", "report.view", "patch.view", "patch.manage", "patch.configure"],
});
/** Configures patching in its organizations, and audits them; not a super administrator. */
const ORG_ADMIN = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "audit.view", "patch.view", "patch.manage", "patch.configure"],
});

const SETTINGS: PatchServerSettings = {
  globalMaxConcurrentInstalls: 50,
  jobDefaultExpiryHours: 168,
  runningJobTimeoutHours: 12,
  waitingForRebootExpiryDays: 30,
  deliveryLeaseMinutes: 10,
  maxDeliveryAttempts: 5,
  offlineThresholdMinutes: 10,
  credentialLifetimeDays: 365,
  credentialRotateBeforeDays: 30,
  retentionEventsDays: 90,
  retentionAuditDays: 365,
  retentionJobsDays: 180,
  retentionScansDays: 90,
  retentionHistoryDays: 730,
  retentionReportsMonths: 24,
  vulnerabilityFeedsEnabled: true,
  reportBrandName: null,
  rolloutGuardEnabled: true,
  rolloutGuardMinFailedEndpoints: 3,
  rolloutGuardFailurePercent: 20,
  rolloutGuardWindowDays: 7,
};

const HOUR = 3600_000;
const ago = (hours: number) => new Date(Date.now() - hours * HOUR).toISOString();

function settingsView(extra: Partial<PatchSettingsView> = {}): PatchSettingsView {
  return {
    settings: SETTINGS,
    feeds: [
      { name: "kev", lastAttemptAt: ago(2), lastSuccessAt: ago(2), version: "2026.11.18", itemCount: 1484 },
      { name: "msrc", lastAttemptAt: ago(1), lastSuccessAt: null, lastError: "The feed answered 503.", itemCount: 0 },
    ],
    version: "1.10.0",
    canEdit: true,
    ...extra,
  };
}

/** A date this many days from today, as 2006-01-02. */
function inDays(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

const LIFECYCLE: PatchLifecycleEntry[] = [
  { id: "l1", product: "Windows 10", editionGroup: "HomePro", buildNumber: 19045, versionLabel: "22H2", endOfServicing: inDays(-400), esuEndDate: inDays(700), notes: "Commercial ESU." },
  { id: "l2", product: "Windows 11", editionGroup: "HomePro", buildNumber: 26100, versionLabel: "24H2", endOfServicing: inDays(60), esuEndDate: null, notes: null },
  { id: "l3", product: "Windows Server", editionGroup: "Server", buildNumber: 20348, versionLabel: "2022", endOfServicing: inDays(1800), esuEndDate: null, notes: null },
  { id: "l4", product: "Debian", editionGroup: "Any", buildNumber: 10, versionLabel: "10 (buster)", endOfServicing: inDays(-30), esuEndDate: null, notes: null },
];

const PACKAGES: PatchAgentPackage[] = [
  { fileName: "EasyPatch.Agent-1.10.0-x64.msi", version: "1.10.0", architecture: "x64", sizeBytes: 31_457_280, sha256: "a".repeat(64), isLatest: true, format: "msi", releaseKeyId: "K1", url: "/downloads/agent/EasyPatch.Agent-1.10.0-x64.msi" },
  { fileName: "easypatch-agent_1.10.0_amd64.deb", version: "1.10.0", architecture: "x64", sizeBytes: 12_000_000, sha256: "b".repeat(64), isLatest: true, format: "deb", url: "/downloads/agent/easypatch-agent_1.10.0_amd64.deb" },
  { fileName: "easypatch-agent-1.9.0.x86_64.rpm", version: "1.9.0", architecture: "x64", sizeBytes: 11_000_000, sha256: "c".repeat(64), isLatest: false, format: "rpm", releaseKeyId: "K0", signatureProblem: "Signed by a key EasyPatch does not trust.", url: "/downloads/agent/easypatch-agent-1.9.0.x86_64.rpm" },
];

const AUDIT: PatchAuditEntry[] = [
  { id: 3, createdAt: ago(1), actor: "jo", via: "easypatch", action: "policy.update", organizationId: "o1", organizationName: "Acme", ipAddress: "192.0.2.7", details: '{"field":"scanIntervalMinutes"}' },
  { id: 2, createdAt: ago(2), actor: "otto@example.com", via: "easyrmm", action: "endpoint.update", organizationId: "o1", organizationName: "Acme", deviceId: "d1", deviceName: "WEB-01", details: "{}" },
  { id: 1, createdAt: ago(3), actor: "EasyPatch", via: "system", action: "update.hold", targetType: "UpdateHold", targetId: "h1", details: "not json" },
];

function routes(session = SUPER, extra: Record<string, FakeHandler | FakeReply> = {}) {
  return {
    ...baseRoutes(session),
    "GET /patching": ok(READY),
    "GET /organizations": ok({ items: [org("o1", "Acme"), org("o2", "Globex")] }),
    "GET /patching/settings": ok(settingsView({ canEdit: session === SUPER })),
    "GET /patching/lifecycle": ok({ items: LIFECYCLE, canEdit: session === SUPER }),
    "GET /patching/agent-packages": ok({ items: PACKAGES }),
    "GET /patching/audit": ok({ items: AUDIT, page: 1, pageSize: 50, totalCount: 3, everything: session === SUPER }),
    ...extra,
  };
}

describe("Settings → Patching → Server", () => {
  it("shows the feeds and changes settings, checking them as EasyPatch does", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(SUPER, {
        "PUT /patching/settings": (r) => {
          const b = r.body as PatchServerSettings;
          return b.maxDeliveryAttempts === 7
            ? fail(422, "validation_failed", "Check the highlighted fields.", { maxDeliveryAttempts: "EasyPatch refused this." })
            : ok(settingsView({ settings: b }));
        },
      }),
    );
    await open("/settings?tab=patching&view=server");
    expect(await main().findByText(/Patching engine 1\.10\.0\./)).toBeInTheDocument();
    const feeds = main().getByRole("table", { name: "Vulnerability data downloads" });
    expect(within(feeds).getByText("CISA known exploited vulnerabilities")).toBeInTheDocument();
    expect(within(feeds).getByText("Every 6 hours, version 2026.11.18")).toBeInTheDocument();
    expect(within(feeds).getByText("1,484")).toBeInTheDocument();
    expect(within(feeds).getByText("Up to date")).toBeInTheDocument();
    expect(within(feeds).getByText("Failed")).toBeInTheDocument();
    expect(within(feeds).getByText(/The feed answered 503\./)).toBeInTheDocument();
    expect(main().getByText("Saved.")).toBeInTheDocument();
    expect(main().getByRole("button", { name: "Save settings" })).toBeDisabled();

    const installs = main().getByRole("spinbutton", { name: "Installs at once" });
    await user.clear(installs);
    await user.type(installs, "0");
    expect(main().getByText("Choose from 1 to 10,000.")).toBeInTheDocument();
    expect(main().getByText("Correct the values marked above to save.")).toBeInTheDocument();
    expect(main().getByRole("button", { name: "Save settings" })).toBeDisabled();
    await user.clear(installs);
    await user.type(installs, "80");
    const rotate = main().getByRole("spinbutton", { name: "Agents renew them" });
    await user.clear(rotate);
    await user.type(rotate, "400");
    expect(main().getByText("Choose from 1 to 180.")).toBeInTheDocument();
    await user.clear(rotate);
    await user.type(rotate, "30");
    await user.type(main().getByRole("textbox", { name: "Prepared by" }), "  Contoso IT  ");
    // Turning the rollout guard off hides its thresholds.
    await user.click(main().getByRole("checkbox", { name: "Hold a Windows update that fails" }));
    expect(main().queryByRole("spinbutton", { name: "Failed on at least" })).not.toBeInTheDocument();
    await user.click(main().getByRole("checkbox", { name: "Hold a Windows update that fails" }));
    expect(main().getByRole("spinbutton", { name: "Failed on at least" })).toHaveValue(3);

    const attempts = main().getByRole("spinbutton", { name: "Offers before a job fails" });
    await user.clear(attempts);
    await user.type(attempts, "7");
    await user.click(main().getByRole("button", { name: "Save settings" }));
    expect(await main().findByText("EasyPatch refused this.")).toBeInTheDocument();
    await user.clear(attempts);
    await user.type(attempts, "5");
    await user.click(main().getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText("Patching engine settings saved.")).toBeInTheDocument();
    expect(server.call("PUT /patching/settings", 1).body).toEqual({ ...SETTINGS, globalMaxConcurrentInstalls: 80, reportBrandName: "Contoso IT" });
  });

  it("discards changes", async () => {
    const user = userEvent.setup();
    installFakeApi(routes());
    await open("/settings?tab=patching&view=server");
    const days = await main().findByRole("spinbutton", { name: "Finished jobs" });
    await user.clear(days);
    await user.type(days, "60");
    expect(main().getByText("Unsaved changes.")).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Discard changes" }));
    expect(main().getByRole("spinbutton", { name: "Finished jobs" })).toHaveValue(180);
  });

  it("shows the settings to an organization's administrator without letting them change them", async () => {
    installFakeApi(routes(ORG_ADMIN, { "GET /patching/settings": ok(settingsView({ canEdit: false, settings: { ...SETTINGS, reportBrandName: "Contoso IT" } })) }));
    await open("/settings?tab=patching&view=server");
    expect(await main().findByText("Only super administrators change the patching engine's server settings.")).toBeInTheDocument();
    expect(main().getByText("50 devices")).toBeInTheDocument();
    expect(main().getByText("30 days before")).toBeInTheDocument();
    expect(main().getByText("Contoso IT")).toBeInTheDocument();
    expect(main().queryByRole("spinbutton")).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Save settings" })).not.toBeInTheDocument();
  });

  it("says when no vulnerability data is downloaded", async () => {
    const view = settingsView({ feeds: [], settings: { ...SETTINGS, vulnerabilityFeedsEnabled: false } });
    installFakeApi(routes(SUPER, { "GET /patching/settings": ok(view) }));
    await open("/settings?tab=patching&view=server");
    expect(await main().findByText("Nothing downloaded.")).toBeInTheDocument();
    expect(main().queryByText(/Only super administrators/)).not.toBeInTheDocument();
    expect(main().getByRole("checkbox", { name: "Download from Microsoft, CISA and Debian" })).not.toBeChecked();
  });
});

describe("Settings → Patching → OS lifecycle", () => {
  it("lists the dates, filters by product, and adds, edits and deletes entries", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(SUPER, {
        "POST /patching/lifecycle": (r) => {
          const b = r.body as PatchLifecycleInput;
          return b.buildNumber === 2404
            ? fail(422, "validation_failed", "Check the highlighted fields.", { buildNumber: "There is already an entry for this product, edition group and build." })
            : { status: 201, body: { id: "l9", ...b } };
        },
        "PUT /patching/lifecycle/:id": (r) => ok({ id: r.params.id, ...(r.body as object) }),
        "DELETE /patching/lifecycle/:id": noContent,
      }),
    );
    await open("/settings?tab=patching&view=lifecycle");
    const table = await main().findByRole("table", { name: "Operating system lifecycle" });
    const row = (name: string) => within(table).getByText(name).closest("tr") as HTMLElement;
    expect(within(row("Windows 10 22H2")).getAllByText("Extended updates only")).toHaveLength(2); // the column, and under the date on a phone
    expect(within(row("Windows 10 22H2")).getByText("Commercial ESU.")).toBeInTheDocument();
    expect(within(row("Windows 11 24H2")).getAllByText("Ends soon")).toHaveLength(2); // the column, and under the date on a phone
    expect(within(row("Windows Server 2022")).getAllByText("Supported")).toHaveLength(2); // the column, and under the date on a phone
    expect(within(row("Windows Server 2022")).getByText("Server")).toBeInTheDocument();
    expect(within(row("Debian 10 (buster)")).getAllByText("Ended")).toHaveLength(2); // the column, and under the date on a phone
    expect(within(row("Debian 10 (buster)")).getByText("Any edition")).toBeInTheDocument();

    await user.selectOptions(main().getByRole("combobox", { name: "Product" }), "Debian");
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    await user.selectOptions(main().getByRole("combobox", { name: "Product" }), "All products");

    await user.click(main().getByRole("button", { name: "Add entry" }));
    let dialog = await screen.findByRole("dialog", { name: "Add lifecycle entry" });
    expect(within(dialog).getByText("Windows' build number, as 26100 for 24H2.")).toBeInTheDocument();
    // A Linux release matches on product and release only: no edition.
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "Product" }), "Ubuntu");
    expect(within(dialog).queryByRole("combobox", { name: "Edition" })).not.toBeInTheDocument();
    expect(within(dialog).getByText("The release's year and month, as 2404 for 24.04.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Add entry" }));
    expect(within(dialog).getByText("Enter a build from 1 to 1,000,000.")).toBeInTheDocument();
    expect(within(dialog).getByText("Name the version, as 24H2 or 24.04 LTS.")).toBeInTheDocument();
    expect(within(dialog).getByText("Choose the date security updates end.")).toBeInTheDocument();
    expect(server.callsTo("POST /patching/lifecycle")).toHaveLength(0);
    await user.type(within(dialog).getByRole("spinbutton", { name: /Build/ }), "2404");
    await user.type(within(dialog).getByRole("textbox", { name: /Version/ }), "24.04 LTS");
    await user.type(within(dialog).getByLabelText(/Security updates end/), "2029-05-31");
    await user.type(within(dialog).getByLabelText("Extended updates end"), "2029-01-01");
    await user.click(within(dialog).getByRole("button", { name: "Add entry" }));
    expect(within(dialog).getByText("Extended updates end on or after the end of security updates.")).toBeInTheDocument();
    await user.clear(within(dialog).getByLabelText("Extended updates end"));
    await user.type(within(dialog).getByLabelText("Extended updates end"), "2034-04-30");
    await user.type(within(dialog).getByRole("textbox", { name: "Notes" }), "  Ubuntu Pro  ");
    await user.click(within(dialog).getByRole("button", { name: "Add entry" }));
    expect(await within(dialog).findByText("There is already an entry for this product, edition group and build.")).toBeInTheDocument();
    const build = within(dialog).getByRole("spinbutton", { name: /Build/ });
    await user.clear(build);
    await user.type(build, "2604");
    await user.click(within(dialog).getByRole("button", { name: "Add entry" }));
    expect(await screen.findByText("Ubuntu 24.04 LTS added.")).toBeInTheDocument();
    expect(server.call("POST /patching/lifecycle", 1).body).toEqual({
      product: "Ubuntu",
      editionGroup: "LTS",
      buildNumber: 2604,
      versionLabel: "24.04 LTS",
      endOfServicing: "2029-05-31",
      esuEndDate: "2034-04-30",
      notes: "Ubuntu Pro",
    });

    await user.click(main().getByRole("button", { name: "Edit Windows 11 24H2" }));
    dialog = await screen.findByRole("dialog", { name: "Edit lifecycle entry" });
    expect(within(dialog).getByRole("combobox", { name: "Edition" })).toHaveValue("HomePro");
    await user.selectOptions(within(dialog).getByRole("combobox", { name: "Edition" }), "Enterprise and Education");
    await user.click(within(dialog).getByRole("button", { name: "Save entry" }));
    expect(await screen.findByText("Windows 11 24H2 saved.")).toBeInTheDocument();
    expect(server.call("PUT /patching/lifecycle/:id").path).toBe("/patching/lifecycle/l2");
    expect(server.call("PUT /patching/lifecycle/:id").body).toMatchObject({ product: "Windows 11", editionGroup: "EnterpriseEducation", buildNumber: 26100, esuEndDate: null, notes: null });

    // An edited Linux entry keeps its edition group.
    await user.click(main().getByRole("button", { name: "Edit Debian 10 (buster)" }));
    dialog = await screen.findByRole("dialog", { name: "Edit lifecycle entry" });
    await user.click(within(dialog).getByRole("button", { name: "Save entry" }));
    expect(await screen.findByText("Debian 10 (buster) saved.")).toBeInTheDocument();
    expect(server.call("PUT /patching/lifecycle/:id", 1).body).toMatchObject({ product: "Debian", editionGroup: "Any", buildNumber: 10 });

    await user.click(main().getByRole("button", { name: "Delete Windows Server 2022" }));
    dialog = await screen.findByRole("dialog", { name: "Delete entry" });
    expect(dialog).toHaveTextContent("Devices on Windows Server 2022 (Server, build 20348) will show their support as unknown.");
    await user.click(within(dialog).getByRole("button", { name: "Delete entry" }));
    expect(await screen.findByText("Windows Server 2022 deleted.")).toBeInTheDocument();
    expect(server.call("DELETE /patching/lifecycle/:id").path).toBe("/patching/lifecycle/l3");
  });

  it("shows the dates to an organization's administrator without letting them change them", async () => {
    installFakeApi(routes(ORG_ADMIN));
    await open("/settings?tab=patching&view=lifecycle");
    expect(await main().findByText("Only super administrators change these dates.")).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Add entry" })).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: /^Edit / })).not.toBeInTheDocument();
  });

  it("says what no entries mean", async () => {
    installFakeApi(routes(SUPER, { "GET /patching/lifecycle": ok({ items: [], canEdit: true }) }));
    await open("/settings?tab=patching&view=lifecycle");
    expect(await main().findByText("No entries")).toBeInTheDocument();
    expect(main().getByText(/Without entries, every device's operating system support is unknown/)).toBeInTheDocument();
    expect(main().queryByText("Only super administrators change these dates.")).not.toBeInTheDocument();
  });
});

describe("Settings → Patching → Agent packages", () => {
  it("lists the packages with their downloads and signatures", async () => {
    installFakeApi(routes());
    await open("/settings?tab=patching&view=packages");
    const table = await main().findByRole("table", { name: "EasyPatch agent packages" });
    expect(within(table).getByRole("link", { name: "EasyPatch.Agent-1.10.0-x64.msi" })).toHaveAttribute("href", "/downloads/agent/EasyPatch.Agent-1.10.0-x64.msi");
    const row = (name: string) => within(table).getByRole("link", { name }).closest("tr") as HTMLElement;
    expect(within(row("EasyPatch.Agent-1.10.0-x64.msi")).getByText("Signed")).toHaveAttribute("title", "Release key K1");
    expect(within(row("EasyPatch.Agent-1.10.0-x64.msi")).getByText("Newest")).toBeInTheDocument();
    expect(within(row("EasyPatch.Agent-1.10.0-x64.msi")).getByText("30 MiB")).toBeInTheDocument();
    expect(within(row("easypatch-agent_1.10.0_amd64.deb")).getByText("Debian and Ubuntu")).toBeInTheDocument();
    expect(within(row("easypatch-agent_1.10.0_amd64.deb")).getByText("Unsigned")).toBeInTheDocument();
    expect(within(row("easypatch-agent-1.9.0.x86_64.rpm")).getByText("Not trusted")).toBeInTheDocument();
    expect(within(row("easypatch-agent-1.9.0.x86_64.rpm")).getByText("Signed by a key EasyPatch does not trust.")).toBeInTheDocument();
    expect(within(row("easypatch-agent-1.9.0.x86_64.rpm")).queryByText("Newest")).not.toBeInTheDocument();
  });

  it("says when there are none", async () => {
    installFakeApi(routes(SUPER, { "GET /patching/agent-packages": ok({ items: [] }) }));
    await open("/settings?tab=patching&view=packages");
    expect(await main().findByText("No agent packages")).toBeInTheDocument();
  });
});

describe("Settings → Patching → Audit log", () => {
  it("lists EasyPatch's entries with EasyRMM's names, filters them and pages through them", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(SUPER, {
        "GET /patching/audit": (r) =>
          ok({ items: r.query.get("page") === "2" ? AUDIT.slice(2) : AUDIT, page: Number(r.query.get("page") ?? 1), pageSize: 50, totalCount: 120, everything: true }),
      }),
    );
    await open("/settings?tab=patching&view=audit");
    const table = await main().findByRole("table", { name: "The patching engine's audit log" });
    const row = (text: string) => within(table).getByText(text).closest("tr") as HTMLElement;
    expect(within(row("Policy changed")).getByText("jo")).toBeInTheDocument();
    expect(within(row("Policy changed")).getByText("In the patching engine")).toBeInTheDocument();
    expect(within(row("Policy changed")).getByRole("link", { name: "Acme" })).toHaveAttribute("href", "/organizations/o1");
    expect(within(row("Policy changed")).getByText("192.0.2.7")).toBeInTheDocument();
    expect(within(row("Device changed")).getByText("Through EasyRMM")).toBeInTheDocument();
    expect(within(row("Device changed")).getByRole("link", { name: "WEB-01" })).toHaveAttribute("href", "/devices/d1");
    expect(within(row("Update held")).getByText("The patching engine, on its own")).toBeInTheDocument();
    expect(within(row("Update held")).getByText("UpdateHold h1")).toBeInTheDocument();
    expect(within(row("Update held")).getByText("not json")).toBeInTheDocument();
    expect(within(row("Policy changed")).getByText(/"field": "scanIntervalMinutes"/)).toBeInTheDocument();
    expect(main().queryByText(/You see the entries of organizations/)).not.toBeInTheDocument();
    expect(main().getByText("120 entries, newest first; page 1 of 3")).toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Older" }));
    expect(await main().findByText("120 entries, newest first; page 2 of 3")).toBeInTheDocument();
    expect(server.callsTo("GET /patching/audit").at(-1)?.query.get("page")).toBe("2");

    await user.selectOptions(main().getByRole("combobox", { name: "Area" }), "Updates and holds");
    await user.type(main().getByLabelText("From"), "2026-11-01");
    await user.type(main().getByLabelText("To"), "2026-11-18");
    const last = server.callsTo("GET /patching/audit").at(-1);
    expect(last?.query.get("area")).toBe("update.");
    expect(last?.query.get("page")).toBeNull();
    expect(last?.query.get("from")).toBe(new Date(2026, 10, 1).toISOString());
    expect(last?.query.get("to")).toBe(new Date(2026, 10, 19).toISOString());

    await user.clear(main().getByLabelText("To"));
    await user.type(main().getByLabelText("To"), "2026-10-01");
    expect(await main().findByText("Choose a To date on or after the From date.")).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Clear filters" }));
    expect(await main().findByRole("table", { name: "The patching engine's audit log" })).toBeInTheDocument();
  });

  it("says whose entries an organization's administrator sees", async () => {
    installFakeApi(routes(ORG_ADMIN, { "GET /patching/audit": ok({ items: [], page: 1, pageSize: 50, totalCount: 0, everything: false }) }));
    await open("/settings?tab=patching&view=audit");
    expect(await main().findByText("No entries yet")).toBeInTheDocument();
    expect(main().getByText(/You see the entries of organizations whose patching and audit log you see as a whole/)).toBeInTheDocument();
  });

  it("is not offered to those who do not audit", async () => {
    const user = userEvent.setup();
    const noAudit = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "patch.view", "patch.configure"] });
    installFakeApi(routes(noAudit, { "GET /patching/policies/default": fail(503, "patching_unavailable", "EasyPatch is not answering.") }));
    await open("/settings?tab=patching&view=audit");
    // An unknown or unavailable view is the default policy.
    expect(await main().findByRole("radio", { name: "Default policy", checked: true })).toBeInTheDocument();
    expect(main().queryByRole("radio", { name: "Audit log" })).not.toBeInTheDocument();
    // On a phone, the views are a list.
    const show = main().getByRole("combobox", { name: "Show" });
    expect(within(show).queryByRole("option", { name: "Audit log" })).not.toBeInTheDocument();
    await user.selectOptions(show, "Agent packages");
    expect(await main().findByRole("table", { name: "EasyPatch agent packages" })).toBeInTheDocument();
  });
});

describe("EasyPatch's action names", () => {
  it("read as what happened", () => {
    expect(engineActionLabel("lifecycle.create")).toBe("OS lifecycle entry added");
    expect(engineActionLabel("update.release")).toBe("Update released");
    expect(engineActionLabel("api_token.rotate_secret")).toBe("API token rotate secret");
    expect(engineActionLabel("billing.update")).toBe("billing.update");
    expect(engineActionLabel("logout")).toBe("logout");
  });
});
