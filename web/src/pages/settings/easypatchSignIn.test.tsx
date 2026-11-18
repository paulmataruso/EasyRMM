import { describe, expect, it, vi } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { EasyPatchConnection, EasyPatchSignIn, EasyPatchSignInClient, EasyPatchSignInSecret } from "../../api/types";
import { leaveFor } from "../../lib/leave";
import { baseRoutes, installFakeApi, noContent, ok, sessionView } from "../../test/fakeApi";
import { renderApp } from "../../test/render";

vi.mock("../../lib/leave", () => ({ leaveFor: vi.fn() }));

const T = "2026-11-17T09:00:00Z";
const ISSUER = "https://rmm.example.com";
const REDIRECT = "https://patch.example.com/api/v1/auth/sso/callback";
const CONNECTED: EasyPatchConnection = {
  configured: true,
  url: "https://patch.example.com",
  caCert: "",
  serverVersion: "1.10.0",
  publicUrl: "https://patch.example.com",
  capabilities: ["easyrmm-sign-in"],
  canOperate: true,
  checkedAt: T,
};
const CLIENT: EasyPatchSignInClient = {
  clientId: "easypatch-AbCdEfGhIjKl",
  redirectUri: REDIRECT,
  createdAt: T,
  createdBy: "ada@example.com",
};
const SECRET: EasyPatchSignInSecret = {
  ...CLIENT,
  issuer: ISSUER,
  clientSecret: "erms_first-secret-value",
};

const main = () => within(screen.getByRole("main"));

function routes(signIn: () => EasyPatchSignIn) {
  return {
    ...baseRoutes(sessionView()),
    "GET /settings/easypatch": ok(CONNECTED),
    "GET /settings/easypatch/organizations": ok({ easyPatch: [], links: [] }),
    "GET /settings/easypatch/devices": ok({ items: [] }),
    "GET /settings/easypatch/sign-in": () => ok(signIn()),
    "GET /audit": ok({ items: [] }),
  };
}

describe("sign-in to EasyPatch through EasyRMM", () => {
  it("says why it cannot be set up", async () => {
    installFakeApi(
      routes(() => ({
        available: false,
        reason: "This EasyPatch cannot sign people in through EasyRMM; update it.",
        issuer: ISSUER,
        client: null,
      })),
    );
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("This EasyPatch cannot sign people in through EasyRMM; update it.")).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Set up sign-in" })).not.toBeInTheDocument();
  });

  it("sets it up and shows the secret once", async () => {
    const user = userEvent.setup();
    let client: EasyPatchSignInClient | null = null;
    const server = installFakeApi({
      ...routes(() => ({
        available: true,
        issuer: ISSUER,
        redirectUri: REDIRECT,
        client,
      })),
      "POST /settings/easypatch/sign-in": () => {
        client = CLIENT;
        return { status: 201, body: SECRET };
      },
    });
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Set up sign-in" }));
    await waitFor(() => expect(server.callsTo("POST /settings/easypatch/sign-in")).toHaveLength(1));

    const dialog = await screen.findByRole("dialog", {
      name: "Enter these in EasyPatch",
    });
    expect(within(dialog).getByText("Copy the client secret now. It is shown only once.")).toBeInTheDocument();
    expect(within(dialog).getByText(ISSUER)).toBeInTheDocument();
    expect(within(dialog).getByText(CLIENT.clientId)).toBeInTheDocument();
    expect(within(dialog).getByText(SECRET.clientSecret)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());

    // Afterwards the details stay, the secret does not.
    expect(await main().findByText(CLIENT.clientId)).toBeInTheDocument();
    expect(main().getByText(REDIRECT)).toBeInTheDocument();
    expect(screen.queryByText(SECRET.clientSecret)).not.toBeInTheDocument();
  });

  it("replaces the secret and turns sign-in off, after confirming", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes(() => ({
        available: true,
        issuer: ISSUER,
        redirectUri: REDIRECT,
        client: CLIENT,
      })),
      "POST /settings/easypatch/sign-in/rotate": ok({
        ...SECRET,
        clientSecret: "erms_second-secret-value",
        rotatedAt: T,
      }),
      "DELETE /settings/easypatch/sign-in": noContent,
    });
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    await user.click(await main().findByRole("button", { name: "Replace secret…" }));
    const confirm = await screen.findByRole("dialog", {
      name: "Replace the client secret?",
    });
    expect(within(confirm).getByText(/stops working at once/)).toBeInTheDocument();
    await user.click(within(confirm).getByRole("button", { name: "Replace" }));
    await waitFor(() => expect(server.callsTo("POST /settings/easypatch/sign-in/rotate")).toHaveLength(1));
    const shown = await screen.findByRole("dialog", {
      name: "Enter these in EasyPatch",
    });
    expect(within(shown).getByText("erms_second-secret-value")).toBeInTheDocument();
    await user.click(within(shown).getByRole("button", { name: "Done" }));

    await user.click(main().getByRole("button", { name: "Turn off" }));
    const off = await screen.findByRole("dialog", {
      name: "Turn off sign-in through EasyRMM?",
    });
    await user.click(within(off).getByRole("button", { name: "Turn off" }));
    await waitFor(() => expect(server.callsTo("DELETE /settings/easypatch/sign-in")).toHaveLength(1));
    expect(await screen.findByText(/Sign-in through EasyRMM is off/)).toBeInTheDocument();
  });

  it("warns when EasyPatch's address changed since it was set up", async () => {
    installFakeApi(
      routes(() => ({
        available: true,
        issuer: ISSUER,
        redirectUri: "https://patch2.example.com/api/v1/auth/sso/callback",
        client: CLIENT,
      })),
    );
    renderApp("/settings?tab=easypatch");
    await screen.findByRole("main");
    expect(await main().findByText("EasyPatch's address changed")).toBeInTheDocument();
    expect(main().getByText("https://patch2.example.com/api/v1/auth/sso/callback")).toBeInTheDocument();
  });

  it("hands an interrupted EasyPatch sign-in back to the server with a full page load", async () => {
    installFakeApi(baseRoutes(sessionView()));
    const authorize = "/oauth2/authorize?client_id=easypatch-x&state=s&bounced=1";
    renderApp(authorize);
    await waitFor(() => expect(leaveFor).toHaveBeenCalledWith(authorize));
  });
});
