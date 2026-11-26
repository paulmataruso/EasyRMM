import { describe, expect, it, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView } from "../test/fakeApi";
import { renderApp } from "../test/render";
import { fakeAssertion, stubWebAuthn } from "../test/webauthn";

const leaveFor = vi.hoisted(() => vi.fn());
vi.mock("../lib/navigate", () => ({ leaveFor }));

const needed = () => fail(401, "step_up_required", "Confirm it is you.");
const ASSERTION = { publicKey: { challenge: "AQIDBAUGBwgJCgsMDQ4PEA", rpId: "localhost", userVerification: "preferred" } };

/** An account page whose "Confirm it is you" answers 401 step_up_required until `stepped` is set. */
function stepUpServer(extra: Parameters<typeof installFakeApi>[0] = {}, methods: string[] = ["totp"]) {
  let stepped = false;
  const server = installFakeApi({
    ...baseRoutes(sessionView()),
    "GET /auth/security-keys": ok({ items: [] }),
    "GET /auth/sessions": ok({ items: [] }),
    "POST /auth/step-up/check": () => (stepped ? noContent : needed()),
    "GET /auth/step-up": ok({ validUntil: null, methods, provider: "Authentik" }),
    "POST /auth/step-up/totp": (req) => {
      if ((req.body as { code: string }).code !== "123456") return fail(401, "invalid_code", "That code is not valid.");
      stepped = true;
      return ok({ validUntil: "2030-01-01T00:05:00Z", methods });
    },
    ...extra,
  });
  return { server, step: () => (stepped = true) };
}

describe("step-up dialog", () => {
  it("opens when a request needs it, takes the code and sends the request again once", async () => {
    const user = userEvent.setup();
    const { server } = stepUpServer();
    renderApp("/account");
    await user.click(await screen.findByRole("button", { name: "Confirm it is you" }));

    const dialog = await screen.findByRole("dialog", { name: "Confirm it is you" });
    expect(dialog).toHaveTextContent("5 minutes");
    await user.type(await screen.findByLabelText(/Code from your authenticator app/), "000000");
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    expect(await screen.findByText("That code is not valid.")).toBeInTheDocument();
    expect(server.callsTo("POST /auth/step-up/check")).toHaveLength(1);

    await user.type(screen.getByLabelText(/Code from your authenticator app/), "123456");
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Confirm it is you" })).not.toBeInTheDocument());
    // The original request, sent once more with the session's CSRF token.
    expect(server.callsTo("POST /auth/step-up/check")).toHaveLength(2);
    expect(server.call("POST /auth/step-up/totp", 1).headers["x-csrf-token"]).toBe("csrf-1");
    expect(await screen.findByText(/Confirmed\. Actions that need a second factor/)).toBeInTheDocument();
  });

  it("does not ask twice: a request still refused after the step-up fails for good", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /auth/security-keys": ok({ items: [] }),
      "GET /auth/sessions": ok({ items: [] }),
      "POST /auth/step-up/check": needed(),
      "GET /auth/step-up": ok({ validUntil: null, methods: ["totp"] }),
      "POST /auth/step-up/totp": ok({ validUntil: null, methods: ["totp"] }),
    });
    renderApp("/account");
    await user.click(await screen.findByRole("button", { name: "Confirm it is you" }));
    await user.type(await screen.findByLabelText(/Code from your authenticator app/), "123456");
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(server.callsTo("POST /auth/step-up/check")).toHaveLength(2));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Confirm it is you" })).not.toBeInTheDocument());
  });

  it("leaves the request refused when cancelled", async () => {
    const user = userEvent.setup();
    const { server } = stepUpServer();
    renderApp("/account");
    await user.click(await screen.findByRole("button", { name: "Confirm it is you" }));
    await screen.findByLabelText(/Code from your authenticator app/);
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Confirm it is you" })).not.toBeInTheDocument());
    expect(server.callsTo("POST /auth/step-up/check")).toHaveLength(1);
    expect(server.callsTo("POST /auth/step-up/totp")).toHaveLength(0);
  });

  it("confirms with a security key", async () => {
    const user = userEvent.setup();
    const creds = stubWebAuthn();
    creds.get.mockResolvedValue(fakeAssertion());
    const { server } = stepUpServer(
      {
        "POST /auth/step-up/webauthn/begin": ok(ASSERTION),
        "POST /auth/step-up/webauthn/finish": () => {
          step();
          return ok({ validUntil: null, methods: ["webauthn"] });
        },
      },
      ["webauthn"],
    );
    const step = () => {
      server.on("POST /auth/step-up/check", noContent);
    };
    renderApp("/account");
    await user.click(await screen.findByRole("button", { name: "Confirm it is you" }));
    await user.click(await screen.findByRole("button", { name: "Use a security key" }));
    await waitFor(() => expect(server.callsTo("POST /auth/step-up/check")).toHaveLength(2));
    const sent = server.call("POST /auth/step-up/webauthn/finish").body as { credential: { id: string } };
    expect(sent.credential.id).toBe("cred-1");
  });

  it("offers a provider sign-in, and a second factor when there is one too", async () => {
    const user = userEvent.setup();
    const { server } = stepUpServer({ "POST /auth/step-up/oidc/begin": ok({ authUrl: "https://idp.example/auth?x=1" }) }, ["totp", "oidc"]);
    renderApp("/account");
    await user.click(await screen.findByRole("button", { name: "Confirm it is you" }));
    await user.click(await screen.findByRole("radio", { name: "Sign in at Authentik" }));
    await user.click(screen.getByRole("button", { name: "Sign in again at Authentik" }));
    await waitFor(() => expect(leaveFor).toHaveBeenCalledWith("https://idp.example/auth?x=1"));
    expect(server.call("POST /auth/step-up/oidc/begin").body).toEqual({ returnTo: "/account" });
  });

  it("says so when the account has no second factor", async () => {
    const user = userEvent.setup();
    stepUpServer({}, []);
    renderApp("/account");
    await user.click(await screen.findByRole("button", { name: "Confirm it is you" }));
    expect(await screen.findByText("No second factor to confirm with")).toBeInTheDocument();
    expect(screen.getByText(/recovery codes cannot confirm this/)).toBeInTheDocument();
  });

  it("tells the person how a sign-in at the provider went when the browser comes back", async () => {
    stepUpServer();
    window.history.replaceState(null, "", "/account?stepup=failed&reason=identity");
    renderApp("/account");
    expect(await screen.findByText(/not the account you are signed in with/)).toBeInTheDocument();
    expect(window.location.search).toBe("");
  });
});
