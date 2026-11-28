import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { TlsMoveProgress, TlsOverview } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, unreportedRoutes } from "../../test/fakeApi";
import { renderApp } from "../../test/render";

// Moving a name's certificate between sources (ADR-0055, 5b2).

const NAME = "rmm.example.test";
const OVERVIEW: TlsOverview = { mode: "internal", managed: false, names: [NAME], canAcme: true };
const MOVE: TlsMoveProgress = {
  name: NAME,
  source: "env",
  target: "acme",
  startedAt: "2026-11-27T10:00:00Z",
  notes: ["The trial order against Let's Encrypt's staging service was not run; the real order was placed directly."],
  waiting: 1,
  swapDelaySeconds: 0,
  devices: [
    { deviceId: "d1", hostname: "pc-1", state: "passed", scopes: ["agent"], lastSeen: "2026-11-27T10:00:00Z" },
    { deviceId: "d2", hostname: "pc-2", state: "failed", error: "x509: certificate signed by unknown authority", scopes: ["agent", "easypatch"] },
    { deviceId: "d3", hostname: "pc-old", state: "stale", scopes: ["agent"] },
  ],
};

const SUPER = sessionView({ globalPermissions: ["settings.manage"] });

function routes(extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(SUPER),
    ...unreportedRoutes(),
    "GET /settings/certificates": ok(OVERVIEW),
    "GET /settings/certificates/added-name": ok({ eligible: false }),
    "GET /settings/certificates/sources": ok({ names: [] }),
    "GET /settings/certificates/dns": ok({ credentials: [] }),
    "GET /settings/certificates/:name/move": fail(404, "not_found", "Not found."),
    ...extra,
  };
}

describe("Settings > Certificates > move", () => {
  it("starts a move to Let's Encrypt after a confirmation", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes({ "POST /settings/certificates/:name/move": { status: 202, body: { status: "waiting" } } }));
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    await user.selectOptions(await main.findByLabelText(`New source for ${NAME}`), "acme");
    await user.click(main.getByRole("button", { name: /Move/ }));
    await user.click(await screen.findByRole("button", { name: "Start the move" }));
    expect(server.call("POST /settings/certificates/:name/move").body).toEqual({ target: "acme" });
  });

  it("lists each device's verification, says stale ones do not block, and cancels", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes({ "GET /settings/certificates/:name/move": ok(MOVE), "DELETE /settings/certificates/:name/move": { status: 204 } }));
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText("pc-1")).toBeInTheDocument();
    expect(main.getByText("Passed")).toBeInTheDocument();
    expect(main.getByText(/signed by unknown authority/)).toBeInTheDocument();
    expect(main.getByText(/does not block/)).toBeInTheDocument();
    expect(main.getByText(/staging service was not run/)).toBeInTheDocument();
    await user.click(main.getByRole("button", { name: "Cancel the move" }));
    expect(server.call("DELETE /settings/certificates/:name/move").path).toBe(`/settings/certificates/${NAME}/move`);
  });
});
