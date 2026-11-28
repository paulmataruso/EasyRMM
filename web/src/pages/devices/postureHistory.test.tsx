import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import type { PostureHistoryList } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { device, org, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const agent = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-26T10:00:00Z", enrolledAt: "2026-10-01T10:00:00Z" } as never;
const D1 = device("d1", "WEB-01", { platform: "linux", agent });

function routes(history: PostureHistoryList) {
  return {
    ...baseRoutes(sessionView()),
    "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
    "GET /devices/:id": ok(D1),
    "GET /devices/:id/hardening": ok({ platform: null, modules: [], checkedAt: null, supported: null }),
    "GET /job-runs": ok({ items: [] }),
    "GET /devices/:id/inventory": ok(null),
    "GET /devices/:id/posture/history": ok(history),
  };
}

describe("posture history", () => {
  it("lists the changes, newest first, on the device's Security tab", async () => {
    const list: PostureHistoryList = {
      items: [
        { word: "meets", percent: 100, failing: 0, cannotTell: 0, checkedAt: "2026-11-27T10:00:00Z", recordedAt: "2026-11-27T10:05:00Z" },
        { word: "does not meet", percent: 72, failing: 1, cannotTell: 2, checkedAt: "2026-11-20T10:00:00Z", recordedAt: "2026-11-20T10:05:00Z" },
        { word: "cannot tell", percent: null, failing: 0, cannotTell: 0, checkedAt: null, recordedAt: "2026-11-10T10:05:00Z" },
      ],
    };
    const server = installFakeApi(routes(list));
    renderApp("/devices/d1?tab=hardening");
    await screen.findByText("Posture history");
    const table = (await screen.findByText("72%")).closest("table") as HTMLElement;
    const rows = within(table).getAllByRole("row");
    // The header, then newest first.
    expect(rows).toHaveLength(4);
    expect(rows[1]).toHaveTextContent("100%");
    expect(rows[2]).toHaveTextContent("72%");
    expect(rows[2]).toHaveTextContent("1");
    expect(rows[2]).toHaveTextContent("2");
    expect(rows[3]).toHaveTextContent("Cannot tell");
    expect(server.callsTo("GET /devices/:id/posture/history")).toHaveLength(1);
  });

  it("says so when nothing changed", async () => {
    installFakeApi(routes({ items: [] }));
    renderApp("/devices/d1?tab=hardening");
    expect(await screen.findByText(/No change in this device's posture has been recorded/)).toBeInTheDocument();
  });
});
