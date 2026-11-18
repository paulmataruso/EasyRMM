import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import type { EasyPatchConnection, EasyPatchOrganizations, PatchingSync } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const T = "2026-11-18T09:00:00Z";
const ENGINE: EasyPatchConnection = {
  configured: true,
  bundled: true,
  url: "http://127.0.0.1:18180",
  caCert: "",
  serverVersion: "1.10.0",
  publicUrl: "https://rmm.example.com",
  capabilities: ["scheduled-installs", "on-behalf-of"],
  canOperate: true,
  checkedAt: T,
};

const main = () => within(screen.getByRole("main"));

const IN_STEP: PatchingSync = { at: T, problems: [], archiving: 0, removing: 0 };

function routes(conn: EasyPatchConnection, sync: PatchingSync = IN_STEP, links: EasyPatchOrganizations = { easyPatch: [], links: [] }) {
  return {
    ...baseRoutes(sessionView()),
    "GET /settings/easypatch": ok(conn),
    "GET /settings/easypatch/organizations": ok(links),
    "GET /settings/easypatch/sync": ok(sync),
    "GET /settings/easypatch/devices": ok({ items: [] }),
    "GET /audit": ok({ items: [] }),
  };
}

describe("patching from the engine in this deployment", () => {
  it("shows the engine, with nothing to enter, no console and no sign-in to set up", async () => {
    installFakeApi(routes(ENGINE));
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByRole("heading", { name: "Patching engine" })).toBeInTheDocument();
    expect(main().getByText("Running")).toBeInTheDocument();
    expect(main().getByText("http://127.0.0.1:18180")).toBeInTheDocument();
    expect(main().getByText("EASYRMM_PATCHING=bundled")).toBeInTheDocument();
    expect(main().getByText("Signed one by one, with the person's role and organizations")).toBeInTheDocument();
    expect(main().queryByLabelText("API token")).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Open EasyPatch" })).not.toBeInTheDocument();
    expect(main().queryByRole("heading", { name: /sign-in/i })).not.toBeInTheDocument();
  });

  it("says when the engine refuses EasyRMM", async () => {
    installFakeApi(
      routes({ ...ENGINE, lastError: "The patching engine answered 401: The statement from EasyRMM is not valid.", lastErrorAt: "2026-11-18T09:05:00Z" }),
    );
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("Failing")).toBeInTheDocument();
    expect(main().getByText(/The patching engine answered 401/)).toBeInTheDocument();
  });

  it("keeps every organization's own in step, with nothing to link", async () => {
    installFakeApi({
      ...routes(ENGINE, { ...IN_STEP, archiving: 1, removing: 2 }, {
        easyPatch: [],
        links: [
          {
            organizationId: "o1",
            organizationName: "Contoso",
            easyPatchId: "e1",
            easyPatchName: "Contoso",
            linkedAt: T,
            autoInstall: true,
            devices: { linked: 3, unlinked: 0, pending: 0 },
          },
        ],
      }),
      "GET /organizations": ok({ items: [org("o1", "Contoso"), org("o2", "Fabrikam")] }),
    });
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText(/EasyRMM creates, renames and archives them/)).toBeInTheDocument();
    const rows = within(main().getByRole("table")).getAllByRole("row");
    expect(within(rows[1]!).getAllByText("Contoso")).toHaveLength(2);
    expect(within(rows[1]!).getByRole("checkbox", { name: "Install the EasyPatch agent automatically in Contoso" })).toBeChecked();
    expect(within(rows[2]!).getByText("Being created")).toBeInTheDocument();
    // Links are not chosen here.
    expect(main().queryByRole("combobox")).not.toBeInTheDocument();
    expect(main().getByRole("status")).toHaveTextContent(
      /In step .*; archiving 1 deleted organization or site and removing the EasyPatch agent from 2 devices\./,
    );
  });

  it("says what the engine is not in step with", async () => {
    installFakeApi(routes(ENGINE, { ...IN_STEP, problems: ["Creating organization \"Fabrikam\" in the patching engine: unavailable"] }));
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("The patching engine is not fully in step yet")).toBeInTheDocument();
    expect(main().getByText(/Creating organization "Fabrikam"/)).toBeInTheDocument();
  });
});
