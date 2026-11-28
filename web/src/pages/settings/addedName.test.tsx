import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { TlsAddedName, TlsNameCheck, TlsOverview } from "../../api/types";
import {
  baseRoutes,
  installFakeApi,
  ok,
  sessionView,
  unreportedRoutes,
} from "../../test/fakeApi";
import { renderApp } from "../../test/render";

// Adding a name to an IP install (ADR-0055, 5b3).

const OVERVIEW: TlsOverview = {
  mode: "internal",
  managed: false,
  names: [],
  canAcme: true,
};
const SUPER = sessionView({ globalPermissions: ["settings.manage"] });
const PAIR: TlsAddedName = {
  console: "rmm.example.test",
  mesh: "mesh.rmm.example.test",
  state: "pending",
  addedAt: "2026-11-27T10:00:00Z",
  held: { "rmm.example.test": true, "mesh.rmm.example.test": false },
  reachable: false,
  lastFetchError: "mesh.rmm.example.test: connection timed out",
  agentsAsked: 4,
  agentsPassed: 3,
};

function routes(extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(SUPER),
    ...unreportedRoutes(),
    "GET /settings/certificates": ok(OVERVIEW),
    "GET /settings/certificates/added-name": ok({ eligible: true }),
    "GET /settings/dns-providers": ok({ credentials: [] }),
    ...extra,
  };
}

describe("Settings > Certificates > added name", () => {
  it("checks the names, then adds them after a confirmation", async () => {
    const user = userEvent.setup();
    const checks: TlsNameCheck[] = [
      { name: "rmm.example.test", addresses: ["203.0.113.10"], points: true },
      {
        name: "mesh.rmm.example.test",
        addresses: ["203.0.113.10"],
        points: true,
      },
    ];
    const server = installFakeApi(
      routes({
        "POST /settings/certificates/added-name/check": ok({ checks }),
        "POST /settings/certificates/added-name": {
          status: 202,
          body: { status: "pending" },
        },
      }),
    );
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    const add = await main.findByRole("button", {
      name: /Agree and get certificates/,
    });
    expect(add).toBeDisabled();
    await user.type(main.getByLabelText("Console name"), "rmm.example.test");
    expect(main.getByLabelText("Remote-access name")).toHaveValue(
      "mesh.rmm.example.test",
    );
    await user.click(main.getByRole("button", { name: "Check the names" }));
    expect(await main.findAllByText("Points here")).toHaveLength(2);
    expect(
      server.call("POST /settings/certificates/added-name/check").body,
    ).toEqual({ console: "rmm.example.test", mesh: "mesh.rmm.example.test" });
    await user.click(add);
    await user.click(
      await screen.findByRole("button", { name: "Agree and get certificates" }),
    );
    expect(server.call("POST /settings/certificates/added-name").body).toEqual({
      console: "rmm.example.test",
      mesh: "mesh.rmm.example.test",
    });
  });

  it("keeps Add disabled while a name does not point at this server", async () => {
    const user = userEvent.setup();
    installFakeApi(
      routes({
        "POST /settings/certificates/added-name/check": ok({
          checks: [
            {
              name: "rmm.example.test",
              addresses: ["198.51.100.1"],
              points: false,
              error: "The name resolves, but not to an address of this server.",
            },
            {
              name: "mesh.rmm.example.test",
              addresses: [],
              points: false,
              error: "The name does not resolve yet.",
            },
          ],
        }),
      }),
    );
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    await user.type(
      await main.findByLabelText("Console name"),
      "rmm.example.test",
    );
    await user.click(main.getByRole("button", { name: "Check the names" }));
    expect(await main.findByText(/does not resolve yet/)).toBeInTheDocument();
    expect(
      main.getByRole("button", { name: /Agree and get certificates/ }),
    ).toBeDisabled();
  });

  it("shows the pair's progress and removes it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes({
        "GET /settings/certificates/added-name": ok({
          eligible: false,
          pair: PAIR,
        }),
        "DELETE /settings/certificates/added-name": { status: 204 },
      }),
    );
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    expect(
      await main.findByText("Waiting for certificates"),
    ).toBeInTheDocument();
    expect(main.getByText("Certificate in hand")).toBeInTheDocument();
    expect(main.getByText("Waiting for the certificate")).toBeInTheDocument();
    expect(main.getByText(/connection timed out/)).toBeInTheDocument();
    expect(main.getByText(/3 of 4 have/)).toBeInTheDocument();
    await user.click(main.getByRole("button", { name: "Remove name…" }));
    await user.click(
      await screen.findByRole("button", { name: "Remove name" }),
    );
    expect(server.call("DELETE /settings/certificates/added-name").path).toBe(
      "/settings/certificates/added-name",
    );
  });

  it("shows nothing on an install that has a DNS name", async () => {
    installFakeApi(
      routes({
        "GET /settings/certificates/added-name": ok({ eligible: false }),
      }),
    );
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    await main.findByText(/TLS mode/);
    expect(main.queryByText("Add a name")).not.toBeInTheDocument();
  });
});
