import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Report, ReportName } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { auditEntry } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const location = () => screen.getByTestId("location").textContent;

const EVERYTHING = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "software.view", "alert.view", "report.view", "audit.view"],
});

function report(name: ReportName, extra: Partial<Report> = {}): Report {
  const base: Record<ReportName, Pick<Report, "title" | "columns" | "rows">> = {
    devices: {
      title: "Device inventory",
      columns: [
        { key: "organization", label: "Organization", type: "text" },
        { key: "site", label: "Site", type: "text" },
        { key: "device", label: "Device", type: "text" },
        { key: "online", label: "Online", type: "bool" },
        { key: "lastSeen", label: "Last seen", type: "time" },
        { key: "memory", label: "Memory (GiB)", type: "number" },
        { key: "serial", label: "Serial number", type: "text" },
      ],
      rows: [
        ["Northwind Traders", "Head office", "WEB-01", true, "2026-11-16T12:00:00Z", 1536, "ABC123"],
        ["Northwind Traders", "Head office", "PRINTER", false, null, null, ""],
      ],
    },
    software: {
      title: "Installed software",
      columns: [
        { key: "device", label: "Device", type: "text" },
        { key: "platform", label: "Platform", type: "text" },
        { key: "package", label: "Package", type: "text" },
        { key: "version", label: "Version", type: "text" },
      ],
      rows: [["WEB-01", "Linux", "openssl", "3.5.1-1"]],
    },
    health: {
      title: "Device health",
      columns: [
        { key: "device", label: "Device", type: "text" },
        { key: "disk", label: "Disk used", type: "percent" },
      ],
      rows: [["WEB-01", 95.04]],
    },
    alerts: {
      title: "Alert history",
      columns: [
        { key: "opened", label: "Opened", type: "time" },
        { key: "device", label: "Device", type: "text" },
        { key: "alert", label: "Alert", type: "text" },
      ],
      rows: [["2026-11-16T10:00:00Z", "WEB-01", "Disk nearly full"]],
    },
    "patch-compliance": {
      title: "Patch compliance",
      columns: [
        { key: "device", label: "Device", type: "text" },
        { key: "compliance", label: "Compliance", type: "text" },
        { key: "notPatched", label: "Not patched because", type: "text" },
        { key: "missingRequired", label: "Required updates missing", type: "number" },
      ],
      rows: [
        ["WEB-01", "Updates missing", "", 2],
        ["PRINTER", "Not patched", "The EasyPatch agent is not on the device.", null],
      ],
    },
    "patch-installations": {
      title: "Patch installations",
      columns: [
        { key: "completed", label: "Finished", type: "time" },
        { key: "device", label: "Device", type: "text" },
        { key: "update", label: "Update", type: "text" },
        { key: "result", label: "Result", type: "text" },
      ],
      rows: [["2026-11-16T10:00:00Z", "WEB-01", "2026-11 Cumulative Update", "Installed"]],
    },
  };
  const b = base[name];
  return { name, ...b, total: b.rows.length, truncated: false, generatedAt: "2026-11-16T12:00:00Z", ...extra };
}

function routes(session = EVERYTHING, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(session),
    "GET /reports/:name": (r: FakeRequest) => ok(report(r.params.name as ReportName)),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

const csvLink = () => screen.getByRole("link", { name: "Download CSV" });

describe("reports", () => {
  it("shows the device inventory first, with a table and its CSV", async () => {
    installFakeApi(routes());
    renderApp("/reports");
    const table = await screen.findByRole("table", { name: "Device inventory" });
    expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
      "Organization",
      "Site",
      "Device",
      "Online",
      "Last seen",
      "Memory (GiB)",
      "Serial number",
    ]);
    const rows = within(table).getAllByRole("row");
    const web = within(rows[1]!).getAllByRole("cell").map((c) => c.textContent);
    expect(web[2]).toBe("WEB-01");
    expect(web[3]).toBe("Yes");
    expect(web[4]).not.toBe("2026-11-16T12:00:00Z");
    expect(web[5]).toBe((1536).toLocaleString());
    const printer = within(rows[2]!).getAllByRole("cell").map((c) => c.textContent);
    expect(printer.slice(3)).toEqual(["No", "—", "—", "—"]);
    expect(screen.getByText(/^2 rows\./)).toBeInTheDocument();
    expect(csvLink()).toHaveAttribute("href", "/api/v1/reports/devices/csv");
    expect(csvLink()).toHaveAttribute("download");
    expect(screen.getByRole("tab", { name: "Device inventory" })).toHaveAttribute("aria-selected", "true");
  });

  it("narrows a report and its CSV with the filters", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/reports");
    await screen.findByRole("table");
    await user.selectOptions(screen.getByLabelText("Platform"), "Linux");
    await waitFor(() => expect(server.callsTo("GET /reports/:name").at(-1)?.query.get("platform")).toBe("linux"));
    expect(csvLink()).toHaveAttribute("href", "/api/v1/reports/devices/csv?platform=linux");
    expect(location()).toBe("/reports?platform=linux");

    // Another report keeps the scope, drops the search, and takes its own filters.
    await user.type(screen.getByLabelText("Device"), "web");
    await waitFor(() => expect(server.callsTo("GET /reports/:name").at(-1)?.query.get("q")).toBe("web"));
    await user.click(screen.getByRole("tab", { name: "Installed software" }));
    expect(await screen.findByRole("table", { name: "Installed software" })).toBeInTheDocument();
    expect(location()).toBe("/reports?platform=linux&report=software");
    expect(screen.getByLabelText("Package")).toHaveValue("");
    await user.type(screen.getByLabelText("Package"), "openssl");
    await waitFor(() => expect(csvLink()).toHaveAttribute("href", "/api/v1/reports/software/csv?platform=linux&q=openssl"));

    await user.click(screen.getByRole("tab", { name: "Device health" }));
    await screen.findByRole("table", { name: "Device health" });
    expect(screen.queryByLabelText("Package")).not.toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Not seen for"), "A week or more");
    await user.selectOptions(screen.getByLabelText("Fullest disk"), "90% full or more");
    await waitFor(() => expect(csvLink()).toHaveAttribute("href", "/api/v1/reports/health/csv?platform=linux&offlineDays=7&diskPercent=90"));
    expect(within(screen.getByRole("table")).getByText("95%")).toBeInTheDocument();

    await user.click(screen.getByRole("tab", { name: "Alert history" }));
    await screen.findByRole("table", { name: "Alert history" });
    expect(screen.queryByLabelText("Platform")).not.toBeInTheDocument();
    expect(csvLink()).toHaveAttribute("href", "/api/v1/reports/alerts/csv");
    await user.selectOptions(screen.getByLabelText("Opened in"), "The last 90 days");
    await user.selectOptions(screen.getByLabelText("Severity"), "Critical");
    await waitFor(() => expect(csvLink()).toHaveAttribute("href", "/api/v1/reports/alerts/csv?days=90&severity=critical"));
    const last = server.callsTo("GET /reports/:name").at(-1)!;
    expect(last.params.name).toBe("alerts");
    expect(last.query.get("platform")).toBeNull();
  });

  it("offers only the reports the role can read", async () => {
    installFakeApi(routes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "report.view"] })));
    renderApp("/reports?report=alerts");
    await screen.findByRole("table", { name: "Device inventory" });
    expect(screen.getAllByRole("tab").map((t) => t.textContent)).toEqual(["Device inventory", "Device health"]);
    expect(screen.getByRole("navigation", { name: "Main" })).toHaveTextContent("Reports");
  });

  it("says when there is no report for the role", async () => {
    installFakeApi(routes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "report.view"] })));
    renderApp("/reports");
    expect(await screen.findByText("No reports for your role")).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Main" })).not.toHaveTextContent("Reports");
  });

  it("says when a report has more rows than it shows", async () => {
    const big = report("devices", { total: 4200 });
    installFakeApi(routes(EVERYTHING, { "GET /reports/:name": ok(big) }));
    renderApp("/reports");
    expect(await screen.findByText(/Showing the first 2 of 4,200 rows; the CSV has them all\./)).toBeInTheDocument();
  });

  it("says when a report is cut short", async () => {
    installFakeApi(routes(EVERYTHING, { "GET /reports/:name": ok(report("devices", { total: 100000, truncated: true })) }));
    renderApp("/reports");
    expect(await screen.findByText(/The report stops at 100,000 rows; narrow it with the filters\./)).toBeInTheDocument();
  });

  it("says when nothing matches, and shows errors", async () => {
    const user = userEvent.setup();
    installFakeApi(
      routes(EVERYTHING, {
        "GET /reports/:name": (r: FakeRequest) =>
          r.params.name === "software" ? fail(500, "internal", "Something went wrong.") : ok(report("devices", { rows: [], total: 0 })),
      }),
    );
    renderApp("/reports");
    expect(await screen.findByText("Nothing to report")).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Installed software" }));
    expect(await screen.findByText("Could not load this data")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("names downloaded reports in the audit log", async () => {
    installFakeApi({
      ...routes(),
      "GET /audit": ok({ items: [auditEntry(1, "report.export", { targetType: "report", targetId: "software", details: { report: "software", rows: 2 } })] }),
      "GET /organizations": ok({ items: [] }),
    });
    renderApp("/settings?tab=audit");
    expect(await screen.findByText("Downloaded report")).toBeInTheDocument();
    expect(screen.getByText("Installed software")).toBeInTheDocument();
  });
});
