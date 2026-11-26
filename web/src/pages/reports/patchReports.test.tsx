import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { PatchMonthlyReport, PatchMonthlyReportList, PatchReportSchedule, PatchStatus, PatchTrend, Report } from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { addresses, reportMonth } from "./PatchReports";

// The patch reports: the compliance and installations reports with the trend, monthly PDF
// reports, and their schedules under Settings → Patching.

const location = () => screen.getByTestId("location").textContent;

const READY: PatchStatus = { configured: true };

/** Manages and configures patching in Acme, and reads reports; not a super administrator. */
const MANAGER = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "report.view", "patch.view", "patch.manage", "patch.configure"],
});
const READER = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "report.view", "patch.view"] });

const ACME = org("o1", "Acme");

const compliance: Report = {
  name: "patch-compliance",
  title: "Patch compliance",
  columns: [
    { key: "device", label: "Device", type: "text" },
    { key: "compliance", label: "Compliance", type: "text" },
    { key: "notPatched", label: "Not patched because", type: "text" },
  ],
  rows: [
    ["WEB-01", "Updates missing", ""],
    ["NEW-01", "Not patched", "The EasyPatch agent is not on the device."],
  ],
  total: 2,
  truncated: false,
  generatedAt: "2026-11-19T10:00:00Z",
};

const installations: Report = {
  name: "patch-installations",
  title: "Patch installations",
  columns: [
    { key: "completed", label: "Finished", type: "time" },
    { key: "device", label: "Device", type: "text" },
    { key: "result", label: "Result", type: "text" },
  ],
  rows: [["2026-11-18T22:00:00Z", "WEB-01", "Installed"]],
  total: 1,
  truncated: false,
  generatedAt: "2026-11-19T10:00:00Z",
};

function trend(): PatchTrend {
  const day = (back: number) => {
    const d = new Date();
    d.setDate(d.getDate() - back);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  };
  const point = (back: number, compliant: number) => ({
    date: day(back),
    totalEndpoints: 4,
    compliant,
    missingUpdates: 4 - compliant,
    failedUpdates: 0,
    rebootRequired: 0,
    scanStale: 0,
    neverScanned: 0,
    offline: 0,
    missingRequiredUpdates: 4 - compliant,
    compliancePercent: (compliant / 4) * 100,
  });
  return { points: [point(2, 2), point(1, 3), point(0, 3)], organizations: 1 };
}

function monthly(extra: Partial<PatchMonthlyReport> = {}): PatchMonthlyReport {
  return {
    id: "r1",
    organizationId: "o1",
    organizationName: "Acme",
    periodStart: "2026-10-01",
    periodEnd: "2026-10-31",
    monthToDate: false,
    scheduled: false,
    generatedAt: "2026-11-02T09:00:00Z",
    generatedBy: "ada@example.com",
    fileName: "patch-report-acme-2026-10.pdf",
    sizeBytes: 182_000,
    deliveryStatus: "",
    recipients: [],
    canManage: true,
    ...extra,
  };
}

function schedule(extra: Partial<PatchReportSchedule> = {}): PatchReportSchedule {
  return {
    organizationId: "o1",
    organizationName: "Acme",
    enabled: false,
    recipients: [],
    dayOfMonth: 1,
    includeEndpointList: true,
    nextReportDate: null,
    nextReportPeriod: null,
    timeZone: "Europe/London",
    canEdit: true,
    ...extra,
  };
}

function routes(session = MANAGER, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(session),
    "GET /organizations": ok({ items: [ACME] }),
    "GET /patching": ok(READY),
    "GET /reports/:name": (r: FakeRequest) =>
      ok(r.params.name === "patch-installations" ? installations : r.params.name === "patch-compliance" ? compliance : { ...installations, name: r.params.name, title: "Device inventory" }),
    "GET /patching/reports/trend": ok(trend()),
    "GET /patching/reports/monthly": ok({ items: [monthly()], capped: false, canGenerate: ["o1"] } satisfies PatchMonthlyReportList),
    "GET /patching/report-schedules": ok([schedule()]),
    "GET /patching/reports/mail": ok({}),
    // An organization's page, where its schedule is (ADR-0072); its policy is not what these tests are about.
    "GET /organizations/:id": ok(ACME),
    "GET /organizations/:id/sites": ok({ items: [] }),
    "GET /patching/policies/organization/:id": fail(409, "easypatch_not_linked", "This organization is not in the patching engine yet."),
    "GET /patching/tags/of/organization/:id": ok({ tags: [], canAssign: false }),
    "GET /patching/organizations/:id/agent-install": ok({ organizationId: "o1", organizationName: "Acme", autoInstall: false, devices: { linked: 0, unlinked: 0, pending: 0 } }),
    "GET /patching/scope": ok({ organizationId: "o1", organizationName: "Acme", siteId: null, siteName: "", devices: 0, byPlatform: [], skipped: [], canManage: false }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

const WITHHELD =
  "EasyRMM's mail server signs in with a Microsoft 365 application, which the patching engine cannot do: the engine is given no mail server, so patching sends no email and no monthly reports until a later release moves them to EasyRMM.";

describe("patch reports", () => {
  it("offers the patch reports only with the patching engine", async () => {
    installFakeApi(routes(MANAGER, { "GET /patching": ok({ ...READY, configured: false }) }));
    renderApp("/reports");
    await screen.findByRole("table", { name: "Device inventory" });
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual(["Device inventory", "Device health"]);
  });

  it("shows compliance with its trend, and narrows it by compliance", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/reports?report=patch-compliance");
    const table = await screen.findByRole("table", { name: "Patch compliance" });
    expect(within(table).getByText("The EasyPatch agent is not on the device.")).toBeInTheDocument();
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual([
      "Device inventory",
      "Device health",
      "Patch compliance",
      "Patch installations",
      "Monthly patch reports",
    ]);
    expect(await screen.findByRole("group", { name: /Machines up to date, last 30 days/ })).toBeInTheDocument();
    expect(screen.getByText(/3 of 4 machines were up to date on the last day\./)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Download CSV" })).toHaveAttribute("href", "/api/v1/reports/patch-compliance/csv");

    await user.selectOptions(screen.getByLabelText("Compliance"), "Not patched");
    await waitFor(() => expect(server.callsTo("GET /reports/:name").at(-1)?.query.get("compliance")).toBe("unlinked"));
    expect(screen.getByRole("link", { name: "Download CSV" })).toHaveAttribute("href", "/api/v1/reports/patch-compliance/csv?compliance=unlinked");

    // A longer period asks for more days; a site says the trend is the whole organization's.
    await user.click(screen.getByRole("radio", { name: "90 days" }));
    await waitFor(() => expect(server.callsTo("GET /patching/reports/trend").at(-1)?.query.get("days")).toBe("90"));
    expect(location()).toBe("/reports?report=patch-compliance&compliance=unlinked&trend=90");
  });

  it("leaves the trend out for someone who sees no organization whole", async () => {
    installFakeApi(routes(READER, { "GET /patching/reports/trend": ok({ points: [], organizations: 0 }) }));
    renderApp("/reports?report=patch-compliance");
    await screen.findByRole("table", { name: "Patch compliance" });
    await waitFor(() => expect(screen.queryByText("Compliance trend")).not.toBeInTheDocument());
  });

  it("filters installations by period, category and result", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/reports?report=patch-installations");
    await screen.findByRole("table", { name: "Patch installations" });
    expect(screen.queryByText("Compliance trend")).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Finished in"), "The last 90 days");
    await user.selectOptions(screen.getByLabelText("Category"), "Servicing stack");
    await user.selectOptions(screen.getByLabelText("Result"), "Failed");
    await waitFor(() =>
      expect(screen.getByRole("link", { name: "Download CSV" })).toHaveAttribute(
        "href",
        "/api/v1/reports/patch-installations/csv?days=90&category=ServicingStack&result=Failed",
      ),
    );
    const last = server.callsTo("GET /reports/:name").at(-1)!;
    expect(last.params.name).toBe("patch-installations");
    expect(last.query.get("result")).toBe("Failed");
  });

  it("lists monthly reports, makes one and emails it", async () => {
    const user = userEvent.setup();
    const made = monthly({ id: "r2", periodStart: "2026-11-01", periodEnd: "2026-11-19", monthToDate: true });
    const server = installFakeApi(
      routes(MANAGER, {
        "POST /patching/reports/monthly": { status: 201, body: made },
        "POST /patching/reports/monthly/:id/send": (r: FakeRequest) => {
          const to = (r.body as { recipients: string[] }).recipients;
          return to.length === 0 ? fail(409, "mail_not_configured", "EasyRMM has no mail server to send reports with.") : ok({ ...made, recipients: to, deliveryStatus: "Pending" });
        },
      }),
    );
    renderApp("/reports?report=patch-monthly");
    const table = await screen.findByRole("table", { name: "Monthly patch reports" });
    expect(within(table).getByText(reportMonth(monthly()))).toBeInTheDocument();
    expect(within(table).getByText("Not emailed")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Download CSV" })).not.toBeInTheDocument();
    const pdf = within(table).getByRole("link", { name: `Download the ${reportMonth(monthly())} report of Acme` });
    expect(pdf).toHaveAttribute("href", "/api/v1/patching/reports/monthly/r1/pdf");

    await user.click(screen.getByRole("button", { name: "Make a report" }));
    const dialog = await screen.findByRole("dialog", { name: "Make a monthly report" });
    // The only organization the role may report on is chosen already.
    expect(within(dialog).getByLabelText("Organization")).toHaveValue("o1");
    await user.selectOptions(within(dialog).getByLabelText("Month"), "10");
    await user.click(within(dialog).getByLabelText(/List each device/));
    await user.click(within(dialog).getByRole("button", { name: "Make report" }));
    await waitFor(() => expect(server.callsTo("POST /patching/reports/monthly")).toHaveLength(1));
    expect(server.callsTo("POST /patching/reports/monthly")[0]!.body).toMatchObject({ organizationId: "o1", month: 10, includeEndpointList: false });
    expect(await screen.findByText(`The ${reportMonth(made)} report of Acme is ready.`)).toBeInTheDocument();

    await user.click(within(table).getByRole("button", { name: "Email" }));
    const email = await screen.findByRole("dialog", { name: "Email this report" });
    await user.click(within(email).getByRole("button", { name: "Send" }));
    expect(await within(email).findByText("EasyRMM has no mail server to send reports with.")).toBeInTheDocument();
    await user.type(within(email).getByLabelText("Recipients"), "cfo@example.com, ops@example.com");
    await user.click(within(email).getByRole("button", { name: "Send" }));
    await waitFor(() => expect(server.callsTo("POST /patching/reports/monthly/:id/send")).toHaveLength(2));
    expect(server.callsTo("POST /patching/reports/monthly/:id/send")[1]!.body).toEqual({ recipients: ["cfo@example.com", "ops@example.com"] });
    expect(await screen.findByText("Sending the report to cfo@example.com, ops@example.com.")).toBeInTheDocument();
  });

  it("deletes a monthly report after asking", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(MANAGER, { "DELETE /patching/reports/monthly/:id": noContent }));
    renderApp("/reports?report=patch-monthly");
    const table = await screen.findByRole("table", { name: "Monthly patch reports" });
    await user.click(within(table).getByRole("button", { name: `Delete the ${reportMonth(monthly())} report of Acme` }));
    const confirm = await screen.findByRole("dialog", { name: "Delete this report?" });
    await user.click(within(confirm).getByRole("button", { name: "Delete report" }));
    await waitFor(() => expect(server.callsTo("DELETE /patching/reports/monthly/:id")[0]?.params.id).toBe("r1"));
    expect(await screen.findByText("Report deleted.")).toBeInTheDocument();
  });

  it("shows readers the reports and their delivery, without making or emailing them", async () => {
    installFakeApi(
      routes(READER, {
        "GET /patching/reports/monthly": ok({
          items: [
            monthly({ canManage: false, scheduled: true, deliveryStatus: "Sent", sentAt: "2026-11-02T09:05:00Z", recipients: ["cfo@example.com"] }),
            monthly({ id: "r0", periodStart: "2026-09-01", canManage: false, deliveryStatus: "Failed", lastError: "Mailbox unavailable" }),
            monthly({ id: "r9", periodStart: "2026-08-01", canManage: false, deliveryStatus: "Pending" }),
          ],
          capped: true,
          canGenerate: [],
        }),
      }),
    );
    renderApp("/reports?report=patch-monthly");
    const table = await screen.findByRole("table", { name: "Monthly patch reports" });
    expect(within(table).getByText("Scheduled")).toBeInTheDocument();
    expect(within(table).getByText(/^Emailed/)).toHaveAttribute("title", "cfo@example.com");
    // Why it failed is shown, not only on hover.
    expect(within(table).getByText("Email failed")).toBeInTheDocument();
    expect(within(table).getByText("Mailbox unavailable")).toBeInTheDocument();
    expect(within(table).getByText("Sending")).toBeInTheDocument();
    expect(within(table).queryByRole("button", { name: "Email" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Make a report" })).not.toBeInTheDocument();
    expect(screen.getByText(/Only the newest reports are listed/)).toBeInTheDocument();
  });

  it("says why reports are not emailed while a Microsoft 365 application signs in", async () => {
    const user = userEvent.setup();
    installFakeApi(
      routes(MANAGER, {
        "GET /patching/reports/mail": ok({ withheld: WITHHELD }),
        "GET /patching/reports/monthly": ok({
          items: [monthly({ deliveryStatus: "Failed", scheduled: true, lastError: WITHHELD })],
          capped: false,
          canGenerate: ["o1"],
        }),
      }),
    );
    renderApp("/reports?report=patch-monthly");
    const table = await screen.findByRole("table", { name: "Monthly patch reports" });
    const alert = (await screen.findByText("Reports are not emailed: the patching engine has no mail server")).closest(".rounded-md")!;
    expect(within(alert as HTMLElement).getByText(WITHHELD)).toBeInTheDocument();
    // The scheduled report's failure says why.
    expect(within(table).getByText(WITHHELD)).toBeInTheDocument();
    await user.click(within(table).getByRole("button", { name: "Email" }));
    const email = await screen.findByRole("dialog", { name: "Email this report" });
    expect(within(email).getByText("Reports are not emailed: the patching engine has no mail server")).toBeInTheDocument();
  });

  it("says nothing of the engine's mail otherwise", async () => {
    installFakeApi(routes(MANAGER));
    renderApp("/reports?report=patch-monthly");
    await screen.findByRole("table", { name: "Monthly patch reports" });
    expect(screen.queryByText(/the patching engine has no mail server/)).not.toBeInTheDocument();
  });

  it("says when there are no monthly reports", async () => {
    installFakeApi(routes(MANAGER, { "GET /patching/reports/monthly": ok({ items: [], capped: false, canGenerate: ["o1"] }) }));
    renderApp("/reports?report=patch-monthly");
    expect(await screen.findByText("No monthly reports yet")).toBeInTheDocument();
    expect(screen.getByText(/schedule them under Settings → Patching/)).toBeInTheDocument();
  });

  it("names the report actions in the audit log", async () => {
    installFakeApi({
      ...routes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "audit.view"] })),
      "GET /audit": ok({
        items: [
          {
            id: 1,
            occurredAt: "2026-11-19T10:00:00Z",
            action: "patch.report_send",
            outcome: "success",
            actor: { type: "user", label: "ada@example.com" },
            targetType: "patch_report",
            targetId: "r1",
            details: { recipients: 2 },
          },
        ],
      }),
    });
    renderApp("/settings?tab=audit");
    expect(await screen.findByText("Emailed a monthly patch report")).toBeInTheDocument();
  });
});

describe("report schedules", () => {
  it("lists each organization's schedule and changes it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(MANAGER, {
        "PUT /patching/report-schedules/:id": (r: FakeRequest) => {
          const body = r.body as { recipients: string[]; dayOfMonth: number; enabled: boolean };
          if (body.enabled && body.recipients.length === 0) return fail(422, "validation_failed", "Check the fields.", { recipients: "Enter at least one email address." });
          return ok(schedule({ ...body, nextReportDate: "2026-12-05" }));
        },
      }),
    );
    renderApp("/organizations/o1?tab=patching");
    const table = await screen.findByRole("table", { name: "Monthly report schedules" });
    expect(within(table).getByText("Off")).toBeInTheDocument();
    expect(screen.getByText(/emailed through EasyRMM's mail server/)).toBeInTheDocument();

    await user.click(within(table).getByRole("button", { name: "Change Acme's schedule" }));
    const dialog = await screen.findByRole("dialog", { name: "Acme's monthly report" });
    await user.click(within(dialog).getByLabelText(/Make and email a report each month/));
    await user.selectOptions(within(dialog).getByLabelText("Day of the month"), "5th");
    await user.click(within(dialog).getByRole("button", { name: "Save schedule" }));
    expect(await within(dialog).findByText("Enter at least one email address.")).toBeInTheDocument();
    await user.type(within(dialog).getByLabelText("Recipients"), "cfo@example.com{enter}ops@example.com");
    await user.click(within(dialog).getByRole("button", { name: "Save schedule" }));
    await waitFor(() => expect(server.callsTo("PUT /patching/report-schedules/:id")).toHaveLength(2));
    expect(server.callsTo("PUT /patching/report-schedules/:id")[1]!.body).toEqual({
      enabled: true,
      dayOfMonth: 5,
      recipients: ["cfo@example.com", "ops@example.com"],
      includeEndpointList: true,
    });
    expect(await screen.findByText("Acme's report is made on the 5th of each month.")).toBeInTheDocument();
  });

  it("shows a schedule that is on, read-only to those who may not change it", async () => {
    installFakeApi(
      routes(MANAGER, {
        "GET /patching/report-schedules": ok([
          schedule({ enabled: true, dayOfMonth: 3, recipients: ["cfo@example.com"], includeEndpointList: false, nextReportDate: "2026-12-03", canEdit: false }),
        ]),
      }),
    );
    renderApp("/organizations/o1?tab=patching");
    const table = await screen.findByRole("table", { name: "Monthly report schedules" });
    expect(within(table).getByText("On the 3rd of each month")).toBeInTheDocument();
    expect(within(table).getByText("Summary only")).toBeInTheDocument();
    expect(within(table).getByText("cfo@example.com")).toBeInTheDocument();
    expect(within(table).getByText("Europe/London")).toBeInTheDocument();
    expect(within(table).queryByRole("button")).not.toBeInTheDocument();
    expect(screen.getByText(/emailed through EasyRMM's mail server/)).toBeInTheDocument();
  });

  it("says why scheduled reports are not emailed while a Microsoft 365 application signs in", async () => {
    installFakeApi(routes(MANAGER, { "GET /patching/reports/mail": ok({ withheld: WITHHELD }) }));
    renderApp("/organizations/o1?tab=patching");
    await screen.findByRole("table", { name: "Monthly report schedules" });
    const alert = (await screen.findByText("Reports are not emailed: the patching engine has no mail server")).closest(".rounded-md")!;
    expect(within(alert as HTMLElement).getByText(WITHHELD)).toBeInTheDocument();
  });

  it("says when the organization has no schedule", async () => {
    installFakeApi(routes(MANAGER, { "GET /patching/report-schedules": ok([]) }));
    renderApp("/organizations/o1?tab=patching");
    expect(await screen.findByText("No schedule for this organization")).toBeInTheDocument();
  });
});

describe("report schedules, old place", () => {
  it("sends Settings → Patching → Report schedules to the organization's page, or the list of organizations", async () => {
    installFakeApi(routes(MANAGER));
    renderApp("/settings?tab=patching&view=reports&organizationId=o1");
    expect(await screen.findByRole("table", { name: "Monthly report schedules" })).toBeInTheDocument();
    expect(screen.getByTestId("location")).toHaveTextContent("/organizations/o1?tab=patching");
  });
});

describe("report helpers", () => {
  it("splits addresses on lines, commas and spaces", () => {
    expect(addresses(" a@example.com,\nb@example.com ; c@example.com  ")).toEqual(["a@example.com", "b@example.com", "c@example.com"]);
    expect(addresses("")).toEqual([]);
  });

  it("names a report's month", () => {
    expect(reportMonth({ periodStart: "2026-11-01", monthToDate: true })).toMatch(/ so far$/);
    expect(reportMonth({ periodStart: "2026-10-01", monthToDate: false })).toContain("2026");
  });
});
