import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { LinkedIdentity, SsoProvider, SsoProviderInput, SsoSettings } from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView } from "../../test/fakeApi";
import { renderApp } from "../../test/render";

const REDIRECT = "https://rmm.example.com/api/v1/auth/sso/callback";

const ENTRA: SsoProvider = {
  id: "8d3c1f0e-0000-4000-8000-000000000001",
  name: "Microsoft",
  issuer: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
  clientId: "c1",
  allowedDomains: ["example.com", "example.org"],
  trustEmail: true,
  trustMfa: false,
  enabled: true,
  createdAt: "2026-11-17T09:00:00Z",
  updatedAt: "2026-11-17T09:00:00Z",
};

const main = () => within(screen.getByRole("main"));

function settingsRoutes(settings: SsoSettings) {
  return { ...baseRoutes(sessionView()), "GET /settings/sso": ok(settings), "GET /audit": ok({ items: [] }) };
}

describe("single sign-on settings", () => {
  it("shows the redirect URI and adds a provider", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...settingsRoutes({ redirectUri: REDIRECT, providers: [] }),
      "POST /settings/sso/providers": ok(ENTRA),
    });
    renderApp("/settings?tab=sso");

    expect(await screen.findByRole("heading", { name: "Single sign-on", level: 1 })).toBeInTheDocument();
    expect(await main().findByText(REDIRECT)).toBeInTheDocument();
    expect(main().getByText("No single sign-on yet")).toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Add provider" }));
    // Pasted, as people do with these values (typing them key by key is slow under load).
    const paste = async (label: RegExp, text: string) => {
      await user.click(main().getByLabelText(label));
      await user.paste(text);
    };
    await paste(/^Name/, "Microsoft");
    await paste(/^Issuer URL/, ENTRA.issuer);
    await paste(/^Client ID/, "c1");
    await paste(/^Client secret/, "s3cret");
    await paste(/^Email domains/, "example.com, example.org\n");
    await user.click(main().getByLabelText(/Its email addresses belong to my organization/));
    // Second factor stays EasyRMM's unless the administrator says otherwise; the provider is offered at once.
    expect(main().getByLabelText(/It requires multi-factor authentication/)).not.toBeChecked();
    expect(main().getByLabelText(/Offer it on the sign-in page/)).toBeChecked();
    await user.click(main().getAllByRole("button", { name: "Add provider" }).at(-1)!);

    await waitFor(() => expect(server.callsTo("POST /settings/sso/providers")).toHaveLength(1));
    expect(server.callsTo("POST /settings/sso/providers")[0]!.body).toEqual({
      name: "Microsoft",
      issuer: ENTRA.issuer,
      clientId: "c1",
      clientSecret: "s3cret",
      allowedDomains: ["example.com", "example.org"],
      trustEmail: true,
      trustMfa: false,
      enabled: true,
    } satisfies SsoProviderInput);
    expect(await screen.findByText("Microsoft added. The sign-in page offers it now.")).toBeInTheDocument();
  });

  it("shows what the server refused next to the field", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...settingsRoutes({ redirectUri: REDIRECT, providers: [] }),
      "POST /settings/sso/providers": fail(422, "validation_failed", "Some fields need attention.", {
        issuer: "EasyRMM could not read this provider's OpenID configuration: 404 Not Found",
      }),
    });
    renderApp("/settings?tab=sso");
    await screen.findByRole("heading", { name: "Single sign-on", level: 1 });
    await user.click(await main().findByRole("button", { name: "Add provider" }));
    await user.click(main().getByLabelText(/^Issuer URL/));
    await user.paste("https://login.example.com/wrong");
    await user.click(main().getAllByRole("button", { name: "Add provider" }).at(-1)!);
    expect(await main().findByText(/could not read this provider's OpenID configuration/)).toBeInTheDocument();
  });

  it("edits a provider keeping its secret, and removes one", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...settingsRoutes({ redirectUri: REDIRECT, providers: [ENTRA] }),
      [`PUT /settings/sso/providers/${ENTRA.id}`]: ok({ ...ENTRA, trustMfa: true }),
      [`DELETE /settings/sso/providers/${ENTRA.id}`]: noContent,
    });
    renderApp("/settings?tab=sso");
    await screen.findByRole("heading", { name: "Single sign-on", level: 1 });

    const row = (await main().findByText("Microsoft")).closest("tr")!;
    expect(within(row).getByText("example.com, example.org")).toBeInTheDocument();
    expect(within(row).getByText("EasyRMM's")).toBeInTheDocument();
    expect(within(row).getByText("On")).toBeInTheDocument();

    await user.click(within(row).getByRole("button", { name: "Edit Microsoft" }));
    expect(main().getByLabelText(/^Client secret/)).toHaveAttribute("placeholder", "Stored");
    expect(main().getByLabelText(/^Email domains/)).toHaveValue("example.com\nexample.org");
    await user.click(main().getByLabelText(/It requires multi-factor authentication/));
    await user.click(main().getByRole("button", { name: "Save" }));
    await waitFor(() => expect(server.callsTo(`PUT /settings/sso/providers/${ENTRA.id}`)).toHaveLength(1));
    expect(server.callsTo(`PUT /settings/sso/providers/${ENTRA.id}`)[0]!.body).toMatchObject({ clientSecret: "", trustMfa: true, trustEmail: true });

    await user.click(within(row).getByRole("button", { name: "Remove Microsoft" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove Microsoft?" });
    await user.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(server.callsTo(`DELETE /settings/sso/providers/${ENTRA.id}`)).toHaveLength(1));
  });

  it("is not offered without settings.manage", async () => {
    installFakeApi({ ...baseRoutes(sessionView({ permissions: ["org.view", "audit.view"] })), "GET /audit": ok({ items: [] }) });
    renderApp("/settings?tab=sso");
    expect(await screen.findByRole("heading", { name: "Audit log", level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Single sign-on" })).not.toBeInTheDocument();
  });
});

describe("single sign-on on the sign-in page", () => {
  it("offers each provider, keeping where the person was going", async () => {
    installFakeApi({
      ...baseRoutes(null),
      "GET /auth/sso": ok({ providers: [{ id: ENTRA.id, name: "Microsoft", startUrl: `https://rmm.example.com/api/v1/auth/sso/${ENTRA.id}/start` }] }),
    });
    renderApp("/login?returnTo=%2Fdevices");
    const link = await screen.findByRole("link", { name: "Sign in with Microsoft" });
    expect(link).toHaveAttribute("href", `https://rmm.example.com/api/v1/auth/sso/${ENTRA.id}/start?returnTo=%2Fdevices`);
  });

  it("explains why a sign-in came back refused", async () => {
    installFakeApi(baseRoutes(null));
    renderApp("/login?sso_error=no_account");
    expect(await screen.findByText(/There is no EasyRMM account for the email address your identity provider gave/)).toBeInTheDocument();
  });

  it("has a general message for a reason it does not know", async () => {
    installFakeApi(baseRoutes(null));
    renderApp("/login?sso_error=something_new");
    expect(await screen.findByText("Single sign-on failed. Try again, or sign in with your password.")).toBeInTheDocument();
  });
});

describe("linked accounts on the account page", () => {
  const linked: LinkedIdentity = {
    providerId: ENTRA.id,
    providerName: "Microsoft",
    email: "alex@example.com",
    createdAt: "2026-11-17T09:00:00Z",
    lastUsedAt: "2026-11-17T10:00:00Z",
  };

  it("lists and unlinks them", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /auth/identities": ok({ items: [linked] }),
      "GET /auth/sso": ok({ providers: [{ id: ENTRA.id, name: "Microsoft", startUrl: "x" }, { id: "g", name: "Google", startUrl: "y" }] }),
      [`DELETE /auth/identities/${ENTRA.id}`]: noContent,
      "GET /auth/security-keys": ok({ items: [] }),
      "GET /auth/sessions": ok({ items: [] }),
    });
    renderApp("/account");
    const card = (await screen.findByRole("heading", { name: "Single sign-on" })).closest("section")!;
    expect(await within(card).findByText("as alex@example.com")).toBeInTheDocument();
    expect(within(card).getByText(/You can also sign in with Google/)).toBeInTheDocument();
    await user.click(within(card).getByRole("button", { name: "Unlink Microsoft" }));
    const dialog = await screen.findByRole("dialog", { name: "Unlink Microsoft?" });
    await user.click(within(dialog).getByRole("button", { name: "Unlink" }));
    await waitFor(() => expect(server.callsTo(`DELETE /auth/identities/${ENTRA.id}`)).toHaveLength(1));
  });

  it("stays out of the way when single sign-on is not set up", async () => {
    installFakeApi({ ...baseRoutes(sessionView()), "GET /auth/security-keys": ok({ items: [] }), "GET /auth/sessions": ok({ items: [] }) });
    renderApp("/account");
    expect(await screen.findByRole("heading", { name: "Security keys and passkeys" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Single sign-on" })).not.toBeInTheDocument();
  });
});
