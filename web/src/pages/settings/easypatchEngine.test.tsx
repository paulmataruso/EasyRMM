import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { EasyPatchConnection, EasyPatchOrganizations, PatchingSync } from "../../api/types";
import { baseRoutes, installFakeApi, noContent, ok, sessionView } from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const T = "2026-11-18T09:00:00Z";
const ENGINE: EasyPatchConnection = {
  configured: true,
  url: "http://127.0.0.1:18180",
  caCert: "",
  serverVersion: "1.10.0",
  publicUrl: "https://rmm.example.com",
  capabilities: ["scheduled-installs"],
  checkedAt: T,
};

const main = () => within(screen.getByRole("main"));

const IN_STEP: PatchingSync = { at: T, problems: [], archiving: 0, removing: 0 };

const LINKS: EasyPatchOrganizations = {
  easyPatch: [],
  links: [
    {
      organizationId: "o1",
      organizationName: "Northwind Traders",
      easyPatchId: "ep-o1",
      easyPatchName: "Northwind Traders",
      linkedAt: T,
      autoInstall: false,
      devices: { linked: 2, unlinked: 1, pending: 0 },
    },
  ],
};

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
  it("shows the engine, with nothing to enter, connect or remove", async () => {
    installFakeApi(routes(ENGINE));
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await screen.findByRole("heading", { name: "EasyPatch", level: 1 })).toBeInTheDocument();
    expect(await main().findByRole("heading", { name: "Patching engine" })).toBeInTheDocument();
    expect(main().getByText("Running")).toBeInTheDocument();
    expect(main().getByText("1.10.0")).toBeInTheDocument();
    expect(main().getByText("http://127.0.0.1:18180")).toBeInTheDocument();
    expect(main().getByText("EASYRMM_PATCHING_KEY")).toBeInTheDocument();
    expect(main().getByText("Signed one by one, with the person's role and organizations")).toBeInTheDocument();
    expect(main().getByText("Supported")).toBeInTheDocument();
    expect(main().getByText("The engine records the EasyRMM user")).toBeInTheDocument();
    expect(main().queryByRole("textbox")).not.toBeInTheDocument();
    expect(main().queryByLabelText(/token/i)).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: /^(Connect|Save|Remove)$/ })).not.toBeInTheDocument();
    expect(main().queryByRole("heading", { name: /sign-in/i })).not.toBeInTheDocument();
  });

  it("says when the engine cannot install later", async () => {
    installFakeApi(routes({ ...ENGINE, capabilities: [] }));
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("Not supported by this engine: installs start at once")).toBeInTheDocument();
  });

  it("says when the engine refuses EasyRMM, and checks it again", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes({ ...ENGINE, lastError: "The patching engine answered 401: The statement from EasyRMM is not valid.", lastErrorAt: "2026-11-18T09:05:00Z" }),
      "POST /settings/easypatch/check": ok(ENGINE),
    });
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("Failing")).toBeInTheDocument();
    expect(main().getByText(/The patching engine answered 401/)).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Check now" }));
    await waitFor(() => expect(server.callsTo("POST /settings/easypatch/check")).toHaveLength(1));
  });

  it("shows an error that has passed as no longer failing", async () => {
    installFakeApi(routes({ ...ENGINE, checkedAt: "2026-11-18T09:10:00Z", lastError: "Cannot reach the patching engine.", lastErrorAt: T }));
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("Running")).toBeInTheDocument();
    expect(main().getByText("Cannot reach the patching engine.")).toHaveClass("text-muted");
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

  it("turns automatic installs on for an organization the engine has, and lists devices that are not linked", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes(ENGINE, IN_STEP, LINKS),
      "GET /organizations": ok({ items: [org("o1", "Northwind Traders"), org("o2", "Contoso")] }),
      "GET /settings/easypatch/devices": ok({
        items: [
          {
            deviceId: "d3",
            deviceName: "APP-01",
            organizationName: "Northwind Traders",
            state: "unlinked",
            reason: "Host names differ.",
            checkedAt: T,
          },
          { deviceId: "d4", deviceName: "APP-02", organizationName: "Northwind Traders", state: "pending" },
        ],
      }),
      "PATCH /settings/easypatch/organizations/:id": noContent,
    });
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("Host names differ.")).toBeInTheDocument();
    expect(main().getByRole("link", { name: "APP-01" })).toHaveAttribute("href", "/devices/d3?tab=patches");
    expect(main().getByText("Checking")).toBeInTheDocument();
    expect(main().getByText(/2 devices patched/)).toBeInTheDocument();
    expect(main().getByText(/1 not linked/)).toBeInTheDocument();

    await user.click(main().getByLabelText("Install the EasyPatch agent automatically in Northwind Traders"));
    await waitFor(() => expect(server.callsTo("PATCH /settings/easypatch/organizations/:id")).toHaveLength(1));
    expect(server.call("PATCH /settings/easypatch/organizations/:id").params.id).toBe("o1");
    expect(server.call("PATCH /settings/easypatch/organizations/:id").body).toEqual({ autoInstall: true });
    expect(await screen.findByText(/EasyRMM installs the EasyPatch agent on devices in Northwind Traders that have none/)).toBeInTheDocument();
    // Contoso is not in the engine yet: nothing to turn on.
    expect(main().queryByLabelText("Install the EasyPatch agent automatically in Contoso")).not.toBeInTheDocument();
  });

  it("turns automatic installs off", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes(ENGINE, IN_STEP, { ...LINKS, links: LINKS.links.map((l) => ({ ...l, autoInstall: true })) }),
      "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
      "PATCH /settings/easypatch/organizations/:id": noContent,
    });
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    await user.click(await main().findByLabelText("Install the EasyPatch agent automatically in Northwind Traders"));
    await waitFor(() => expect(server.callsTo("PATCH /settings/easypatch/organizations/:id")).toHaveLength(1));
    expect(server.call("PATCH /settings/easypatch/organizations/:id").body).toEqual({ autoInstall: false });
    expect(await screen.findByText("EasyRMM no longer installs the EasyPatch agent in Northwind Traders by itself.")).toBeInTheDocument();
  });

  it("says when the engine's organizations could not be read", async () => {
    installFakeApi(routes(ENGINE, IN_STEP, { easyPatch: [], links: [], error: "The patching engine did not answer." }));
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("The patching engine's organizations could not be read")).toBeInTheDocument();
    expect(main().getByText("The patching engine did not answer.")).toBeInTheDocument();
  });

  it("says what the engine is not in step with", async () => {
    installFakeApi(routes(ENGINE, { ...IN_STEP, problems: ["Creating organization \"Fabrikam\" in the patching engine: unavailable"] }));
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("The patching engine is not fully in step yet")).toBeInTheDocument();
    expect(main().getByText(/Creating organization "Fabrikam"/)).toBeInTheDocument();
  });

  it("says when the deployment has no patching engine, with nothing to connect", async () => {
    const server = installFakeApi(routes({ configured: false, url: "", caCert: "", serverVersion: "", publicUrl: "", capabilities: [] }));
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("Patching is not available")).toBeInTheDocument();
    expect(main().getByText(/The patching engine is not set up in this deployment/)).toBeInTheDocument();
    expect(main().getByText("deploy/scripts/setup.sh")).toBeInTheDocument();
    expect(main().queryByRole("textbox")).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Check now" })).not.toBeInTheDocument();
    // Nothing else to ask the server for.
    expect(server.callsTo("GET /settings/easypatch/organizations")).toHaveLength(0);
    expect(server.callsTo("GET /settings/easypatch/devices")).toHaveLength(0);
  });
});
