import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { DevicePosture, Report } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { device, org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { postureBadge, POSTURE_PHRASES } from "./postureText";

const agent = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-26T10:00:00Z", enrolledAt: "2026-10-01T10:00:00Z" } as never;
const DEVICES = [
  device("d1", "WEB-01", { platform: "linux", agent, posture: { word: "does not meet", percent: 50, failing: 1, cannotTell: 1, checkedAt: "2026-11-26T09:00:00Z" } }),
  device("d2", "DB-01", { platform: "windows", agent, posture: { word: "meets", percent: 100, failing: 0, cannotTell: 0, checkedAt: "2026-11-26T09:00:00Z" } }),
  device("d3", "kiosk", { platform: "other" }),
];

const lists = {
  "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
  "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
};

const wordOf = (r: FakeRequest) => r.query.get("posture");

describe("security posture", () => {
  it("never says compliant, and keeps the compliance engine's words", () => {
    for (const phrase of Object.values(POSTURE_PHRASES)) expect(phrase.toLowerCase()).not.toContain("compliant");
    const b = postureBadge({ word: "cannot tell", percent: 40, failing: 0, cannotTell: 3 });
    expect(b.tone).toBe("warn");
    expect(b.label).toBe("40% · cannot tell");
    expect(b.title).toContain("unknown or stale");
    expect(postureBadge({ word: "cannot tell", percent: null, failing: 0, cannotTell: 0 }).label).toBe("Cannot tell");
  });

  it("shows the Security column and filters on the server", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      ...lists,
      "GET /remote-access/status": ok({ address: "https://mesh.example.test", connected: true, lastSyncAt: "2026-11-26T09:59:00Z", devices: 3, devicesOnline: 2 }),
      "GET /devices": (r: FakeRequest) => ok({ items: DEVICES.filter((d) => !wordOf(r) || (wordOf(r) === "meets" ? d.posture?.word === "meets" : d.posture?.word === "does not meet")) }),
    });
    renderApp("/devices");
    const table = await screen.findByRole("table");
    expect(within(table).getByRole("columnheader", { name: "Security" })).toBeInTheDocument();
    const web = within(table).getByRole("row", { name: /WEB-01/ });
    expect(within(web).getByText("50%")).toHaveAttribute("title", expect.stringContaining("Does not meet its security policy"));
    expect(within(table).getByRole("row", { name: /kiosk/ })).toHaveTextContent("—");

    await user.selectOptions(screen.getByLabelText("Security"), "Meets");
    await waitFor(() => expect(server.callsTo("GET /devices").at(-1)?.query.get("posture")).toBe("meets"));
    await waitFor(() => expect(screen.queryByRole("row", { name: /WEB-01/ })).not.toBeInTheDocument());
    expect(screen.getByTestId("location").textContent).toBe("/devices?posture=meets");
  });

  it("lists the reasons on the device's Hardening tab, heaviest first", async () => {
    const posture: DevicePosture = {
      covered: true,
      phrase: POSTURE_PHRASES["does not meet"],
      posture: {
        word: "does not meet",
        percent: 50,
        failing: 1,
        cannotTell: 1,
        checkedAt: "2026-11-26T09:00:00Z",
        meeting: 2,
        notApplicable: 0,
        reasons: [
          { controlId: "ssh", label: "SSH", state: "not_in_place", word: "does not meet", weight: 3, detail: "root login is allowed" },
          { controlId: "patching", label: "Patching", state: "stale", word: "cannot tell", weight: 3 },
        ],
      },
    };
    installFakeApi({
      ...baseRoutes(sessionView()),
      ...lists,
      "GET /devices/:id": ok(DEVICES[0]),
      "GET /devices/:id/posture": ok(posture),
      "GET /devices/:id/hardening": ok({ platform: null, modules: [], checkedAt: null, supported: null }),
      "GET /job-runs": ok({ items: [] }),
      "GET /devices/:id/inventory": ok(null),
    });
    renderApp("/devices/d1?tab=hardening");
    const card = await screen.findByText("Security posture");
    expect(card).toBeInTheDocument();
    const items = (await screen.findAllByRole("listitem")).filter((li) => li.textContent?.includes("SSH") || li.textContent?.includes("Patching"));
    expect(items[0]).toHaveTextContent("SSH");
    expect(items[0]).toHaveTextContent("Does not meet");
    expect(items[1]).toHaveTextContent("Result too old to count");
    expect(screen.getByText(/counts as not passing/)).toBeInTheDocument();
  });

  it("offers the Security report with its filter and CSV", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "report.view"] })),
      "GET /reports/:name": (r: FakeRequest) =>
        ok({
          name: "security" as const,
          title: "Security",
          columns: [
            { key: "device", label: "Device", type: "text" },
            { key: "score", label: "Score", type: "percent" },
          ],
          rows: [["WEB-01", 50]],
          total: 1,
          truncated: false,
          generatedAt: "2026-11-26T12:00:00Z",
        } satisfies Partial<Report>),
    });
    renderApp("/reports?report=security");
    await screen.findByRole("table", { name: "Security" });
    await user.selectOptions(screen.getByRole("combobox", { name: "Security" }), "Does not meet");
    await waitFor(() => expect(server.callsTo("GET /reports/:name").at(-1)?.query.get("posture")).toBe("does_not_meet"));
    expect(screen.getByRole("link", { name: "Download CSV" })).toHaveAttribute("href", "/api/v1/reports/security/csv?posture=does_not_meet");
  });
});
