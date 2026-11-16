import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView } from "../../test/fakeApi";
import { renderApp } from "../../test/render";
import { fakeAssertion, fakeAttestation, keysUsableHere, stubWebAuthn } from "../../test/webauthn";
import type { SessionView } from "../../api/types";

const location = () => screen.getByTestId("location").textContent;
const ASSERTION_OPTIONS = { publicKey: { challenge: "AQIDBAUGBwgJCgsMDQ4PEA", rpId: "localhost", userVerification: "required" } };
const CREATION_OPTIONS = {
  publicKey: {
    challenge: "AQIDBAUGBwgJCgsMDQ4PEA",
    rp: { id: "localhost", name: "EasyRMM" },
    user: { id: "dXNlcg", name: "alex@example.com", displayName: "Alex" },
  },
};
const cancelled = () => new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");

const halfSignedIn = (user: Partial<SessionView["user"]>) =>
  sessionView({ state: "mfa_required", permissions: [], isSuperAdmin: false, csrfToken: "csrf-mfa", user: { ...sessionView().user, ...user } });

describe("passkey sign-in", () => {
  it("signs in with a passkey alone and keeps the requested page", async () => {
    const user = userEvent.setup();
    const creds = stubWebAuthn();
    let session: SessionView | null = null;
    const server = installFakeApi({
      ...baseRoutes(null),
      "GET /auth/options": ok(keysUsableHere()),
      "GET /auth/session": () => (session ? ok(session) : fail(401, "unauthenticated", "Sign in.")),
      "POST /auth/passkey/begin": ok(ASSERTION_OPTIONS),
      "POST /auth/passkey/finish": () => {
        session = sessionView();
        return ok(session);
      },
    });
    renderApp("/organizations");
    const button = await screen.findByRole("button", { name: "Sign in with a passkey" });

    // Closing the browser's prompt is not an error.
    creds.get.mockRejectedValueOnce(cancelled());
    await user.click(button);
    expect(await screen.findByRole("button", { name: "Sign in with a passkey" })).toBeEnabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    creds.get.mockResolvedValueOnce(fakeAssertion());
    await user.click(button);
    await waitFor(() => expect(location()).toBe("/organizations"));
    const sent = server.call("POST /auth/passkey/finish").body as { credential: { rawId: string; response: Record<string, string> } };
    expect(sent.credential.rawId).toBe("AQID");
    expect(sent.credential.response.userHandle).toBe("dXNlcg");
    // The browser was asked with the server's challenge.
    expect(new Uint8Array(creds.get.mock.calls[1]![0].publicKey.challenge)[0]).toBe(1);
  });

  it("shows the server's refusal", async () => {
    const user = userEvent.setup();
    stubWebAuthn().get.mockResolvedValue(fakeAssertion());
    installFakeApi({
      ...baseRoutes(null),
      "GET /auth/options": ok(keysUsableHere()),
      "POST /auth/passkey/begin": ok(ASSERTION_OPTIONS),
      "POST /auth/passkey/finish": fail(401, "key_rejected", "That security key or passkey was not accepted. Try again, or use another way to sign in."),
    });
    renderApp("/login");
    await user.click(await screen.findByRole("button", { name: "Sign in with a passkey" }));
    expect(await screen.findByText(/That security key or passkey was not accepted/)).toBeInTheDocument();
  });

  it("is not offered where keys cannot work, and points to the address where they do", async () => {
    stubWebAuthn();
    installFakeApi({ ...baseRoutes(null) });
    renderApp("/login");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign in with a passkey" })).not.toBeInTheDocument();
    expect(screen.queryByText(/Passkeys work at/)).not.toBeInTheDocument();
  });

  it("links to the public address from another one", async () => {
    stubWebAuthn();
    installFakeApi({ ...baseRoutes(null), "GET /auth/options": ok({ ...keysUsableHere(), webauthn: { available: true, origin: "https://rmm.example.com" } }) });
    renderApp("/login");
    expect(await screen.findByRole("link", { name: "https://rmm.example.com" })).toHaveAttribute("href", "https://rmm.example.com/login");
    expect(screen.queryByRole("button", { name: "Sign in with a passkey" })).not.toBeInTheDocument();
  });
});

describe("security key as the second factor", () => {
  it("asks for the key first, and falls back to a recovery code", async () => {
    const user = userEvent.setup();
    const creds = stubWebAuthn();
    let session: SessionView = halfSignedIn({ totp: false, securityKeys: 1 });
    const server = installFakeApi({
      ...baseRoutes(null),
      "GET /auth/options": ok(keysUsableHere()),
      "GET /auth/session": () => ok(session),
      "POST /auth/mfa/webauthn/begin": ok({ publicKey: { ...ASSERTION_OPTIONS.publicKey, allowCredentials: [{ type: "public-key", id: "AQID" }] } }),
      "POST /auth/mfa/webauthn/finish": fail(401, "key_rejected", "That security key or passkey was not accepted. Try again, or use another way to sign in."),
      "POST /auth/mfa/verify": () => {
        session = sessionView();
        return ok(session);
      },
      "GET /audit": ok({ items: [] }),
      "GET /users": ok({ items: [] }),
    });
    renderApp("/login/mfa");
    expect(await screen.findByText("Use your security key or passkey.")).toBeInTheDocument();
    // No authenticator app on this account, so it is not offered.
    expect(screen.queryByRole("button", { name: "Use authenticator code" })).not.toBeInTheDocument();

    creds.get.mockResolvedValueOnce(fakeAssertion());
    await user.click(screen.getByRole("button", { name: "Use security key" }));
    expect(await screen.findByText(/was not accepted/)).toBeInTheDocument();
    expect(server.call("POST /auth/mfa/webauthn/finish").headers["x-csrf-token"]).toBe("csrf-mfa");
    expect(new Uint8Array(creds.get.mock.calls[0]![0].publicKey.allowCredentials[0]!.id)).toEqual(new Uint8Array([1, 2, 3]));

    await user.click(screen.getByRole("button", { name: "Use a recovery code" }));
    await user.type(screen.getByLabelText(/^Recovery code/), "abcd-efgh-ijkl");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("heading", { name: /Dashboard|Welcome|Overview/ })).toBeInTheDocument();
    expect(server.call("POST /auth/mfa/verify").body).toEqual({ code: "abcd-efgh-ijkl" });
  });

  it("finishes sign-in with the key", async () => {
    const user = userEvent.setup();
    stubWebAuthn().get.mockResolvedValue(fakeAssertion());
    let session: SessionView = halfSignedIn({ totp: true, securityKeys: 2 });
    installFakeApi({
      ...baseRoutes(null),
      "GET /auth/options": ok(keysUsableHere()),
      "GET /auth/session": () => ok(session),
      "POST /auth/mfa/webauthn/begin": ok(ASSERTION_OPTIONS),
      "POST /auth/mfa/webauthn/finish": () => {
        session = sessionView();
        return ok(session);
      },
    });
    renderApp("/login/mfa?returnTo=%2Forganizations");
    await user.click(await screen.findByRole("button", { name: "Use security key" }));
    await waitFor(() => expect(location()).toBe("/organizations"));
  });

  it("offers the app and the key both ways", async () => {
    const user = userEvent.setup();
    stubWebAuthn();
    installFakeApi({ ...baseRoutes(null), "GET /auth/options": ok(keysUsableHere()), "GET /auth/session": ok(halfSignedIn({ totp: true, securityKeys: 1 })) });
    renderApp("/login/mfa");
    await user.click(await screen.findByRole("button", { name: "Use authenticator code" }));
    expect(screen.getByLabelText(/^Verification code/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Use a security key" }));
    expect(screen.getByRole("button", { name: "Use security key" })).toBeInTheDocument();
  });

  it("starts with the app where keys cannot work", async () => {
    installFakeApi({ ...baseRoutes(null), "GET /auth/session": ok(halfSignedIn({ totp: true, securityKeys: 1 })) });
    renderApp("/login/mfa");
    expect(await screen.findByLabelText(/^Verification code/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Use a security key" })).toBeInTheDocument();
  });

  it("says where a key-only account's key works", async () => {
    stubWebAuthn();
    installFakeApi({
      ...baseRoutes(null),
      "GET /auth/options": ok({ ...keysUsableHere(), webauthn: { available: true, origin: "https://rmm.example.com" } }),
      "GET /auth/session": ok(halfSignedIn({ totp: false, securityKeys: 1 })),
    });
    renderApp("/login/mfa");
    expect(await screen.findByText(/Security keys and passkeys work only at https:\/\/rmm.example.com/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sign in there" })).toHaveAttribute("href", "https://rmm.example.com/login");
    expect(screen.getByRole("button", { name: "Use a recovery code" })).toBeInTheDocument();
  });
});

describe("security key at first sign-in", () => {
  it("lets the person choose a key, then holds the recovery codes", async () => {
    const user = userEvent.setup();
    const creds = stubWebAuthn();
    let session = sessionView({
      state: "mfa_enrollment",
      permissions: [],
      isSuperAdmin: false,
      user: { ...sessionView().user, mfaEnabled: false, totp: false },
    });
    const server = installFakeApi({
      ...baseRoutes(null),
      "GET /auth/options": ok(keysUsableHere()),
      "GET /auth/session": () => ok(session),
      "POST /auth/security-keys/begin": ok(CREATION_OPTIONS),
      "POST /auth/security-keys/finish": () => {
        session = sessionView({ csrfToken: "csrf-2", user: { ...sessionView().user, totp: false, securityKeys: 1 } });
        return ok({ key: { id: "k1", name: "YubiKey", createdAt: "2026-11-16T10:00:00Z", synced: false }, recoveryCodes: ["aaaa-bbbb", "cccc-dddd"], session });
      },
      "GET /audit": ok({ items: [] }),
      "GET /users": ok({ items: [] }),
    });
    renderApp("/");
    await user.click(await screen.findByRole("button", { name: /Security key or passkey/ }));
    const add = screen.getByRole("button", { name: "Add security key" });
    expect(add).toBeDisabled();
    // No password at this step: it was just entered.
    expect(screen.queryByLabelText(/^Password/)).not.toBeInTheDocument();
    await user.type(screen.getByLabelText(/^Key name/), "  YubiKey ");

    creds.create.mockRejectedValueOnce(new DOMException("Already registered.", "InvalidStateError"));
    await user.click(add);
    expect(await screen.findByText(/already registered to your account/)).toBeInTheDocument();

    creds.create.mockResolvedValueOnce(fakeAttestation());
    await user.click(add);
    expect(await screen.findByText("aaaa-bbbb")).toBeInTheDocument();
    expect(location()).toBe("/login/mfa-setup");
    expect(server.call("POST /auth/security-keys/begin").body).toEqual({ password: "" });
    const finish = server.call("POST /auth/security-keys/finish").body as { name: string; credential: { response: Record<string, unknown> } };
    expect(finish.name).toBe("YubiKey");
    expect(finish.credential.response.attestationObject).toBe("o2Nm");
    expect(new Uint8Array(creds.create.mock.calls[1]![0].publicKey.user.id)).toEqual(new Uint8Array([0x75, 0x73, 0x65, 0x72]));

    await user.click(screen.getByLabelText("I have saved these recovery codes"));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByRole("heading", { name: /Dashboard|Welcome|Overview/ })).toBeInTheDocument();
  });

  it("can switch to the app", async () => {
    const user = userEvent.setup();
    stubWebAuthn();
    installFakeApi({
      ...baseRoutes(null),
      "GET /auth/options": ok(keysUsableHere()),
      "GET /auth/session": ok(sessionView({ state: "mfa_enrollment", permissions: [], isSuperAdmin: false })),
      "POST /auth/mfa/totp/begin": ok({ secret: "JBSWY3DPEHPK3PXPJBSWY3DP", uri: "otpauth://totp/x", qrCodeSvg: "data:image/svg+xml;base64,PHN2Zy8+" }),
    });
    renderApp("/login/mfa-setup");
    await user.click(await screen.findByRole("button", { name: /Security key or passkey/ }));
    await user.click(screen.getByRole("button", { name: "Use an authenticator app instead" }));
    expect(await screen.findByText("JBSW Y3DP EHPK 3PXP JBSW Y3DP")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Use a security key or passkey instead" }));
    expect(screen.getByLabelText(/^Key name/)).toBeInTheDocument();
  });
});

describe("security keys on the account page", () => {
  const key = (id: string, name: string, extra: object = {}) => ({ id, name, createdAt: "2026-11-01T10:00:00Z", synced: false, ...extra });
  const routes = () => ({
    ...baseRoutes(sessionView({ user: { ...sessionView().user, totp: false, securityKeys: 2 } })),
    "GET /auth/options": ok(keysUsableHere()),
    "GET /auth/sessions": ok({ items: [] }),
    "GET /auth/security-keys": ok({ items: [key("k1", "YubiKey", { lastUsedAt: "2026-11-15T10:00:00Z" }), key("k2", "MacBook", { synced: true })] }),
    "GET /audit": ok({ items: [] }),
  });

  it("lists keys and adds one after the password", async () => {
    const user = userEvent.setup();
    const creds = stubWebAuthn();
    const server = installFakeApi({
      ...routes(),
      "POST /auth/security-keys/begin": (req) =>
        (req.body as { password: string }).password === "my password"
          ? ok(CREATION_OPTIONS)
          : fail(422, "validation_failed", "Check the form.", { password: "Your password is not correct." }),
      "POST /auth/security-keys/finish": ok({
        key: key("k3", "Phone"),
        recoveryCodes: [],
        session: sessionView({ user: { ...sessionView().user, totp: false, securityKeys: 3 } }),
      }),
    });
    renderApp("/account");
    const card = (await screen.findByRole("heading", { name: "Security keys and passkeys" })).closest("section") as HTMLElement;
    expect(await within(card).findByText("YubiKey")).toBeInTheDocument();
    expect(within(card).getByText("Synced")).toBeInTheDocument();
    expect(within(card).getByText(/not used yet/)).toBeInTheDocument();
    // With keys and no app, the app is offered as a backup.
    expect(screen.getByText("No authenticator app")).toBeInTheDocument();

    await user.click(within(card).getByRole("button", { name: "Add security key" }));
    const dialog = screen.getByRole("dialog", { name: "Add a security key or passkey" });
    await user.type(within(dialog).getByLabelText(/^Key name/), "YubiKey");
    expect(within(dialog).getByText("You already have a key with this name.")).toBeInTheDocument();
    await user.clear(within(dialog).getByLabelText(/^Key name/));
    await user.type(within(dialog).getByLabelText(/^Key name/), "Phone");
    await user.type(within(dialog).getByLabelText(/^Password/), "wrong");
    await user.click(within(dialog).getByRole("button", { name: "Add security key" }));
    expect(await within(dialog).findByText("Your password is not correct.")).toBeInTheDocument();
    expect(creds.create).not.toHaveBeenCalled();

    await user.clear(within(dialog).getByLabelText(/^Password/));
    await user.type(within(dialog).getByLabelText(/^Password/), "my password");
    creds.create.mockResolvedValueOnce(fakeAttestation());
    await user.click(within(dialog).getByRole("button", { name: "Add security key" }));
    // Not the first factor: no codes, the dialog just closes.
    await screen.findByRole("heading", { name: "Security keys and passkeys" });
    expect(screen.queryByRole("dialog", { name: "Add a security key or passkey" })).not.toBeInTheDocument();
    expect((server.call("POST /auth/security-keys/finish").body as { name: string }).name).toBe("Phone");
  });

  it("sets up an authenticator app next to the keys after the password", async () => {
    const user = userEvent.setup();
    stubWebAuthn();
    const server = installFakeApi({
      ...routes(),
      "POST /auth/mfa/totp/begin": (req) =>
        (req.body as { password?: string }).password === "my password"
          ? ok({ secret: "JBSWY3DPEHPK3PXPJBSWY3DP", uri: "otpauth://totp/x", qrCodeSvg: "data:image/svg+xml;base64,PHN2Zy8+" })
          : fail(422, "validation_failed", "Check the form.", { password: "Your password is not correct." }),
    });
    renderApp("/account");
    await user.click(await screen.findByRole("button", { name: "Set up authenticator" }));
    const dialog = screen.getByRole("dialog", { name: "Set up authenticator" });
    // Nothing is started until the password is in: a stolen session cannot add an authenticator.
    expect(server.callsTo("POST /auth/mfa/totp/begin")).toHaveLength(0);
    await user.type(within(dialog).getByLabelText(/^Password/), "wrong");
    await user.click(within(dialog).getByRole("button", { name: "Continue" }));
    expect(await within(dialog).findByText("Your password is not correct.")).toBeInTheDocument();
    expect(within(dialog).queryByText("JBSW Y3DP EHPK 3PXP JBSW Y3DP")).not.toBeInTheDocument();
    await user.clear(within(dialog).getByLabelText(/^Password/));
    await user.type(within(dialog).getByLabelText(/^Password/), "my password");
    await user.click(within(dialog).getByRole("button", { name: "Continue" }));
    expect(await within(dialog).findByText("JBSW Y3DP EHPK 3PXP JBSW Y3DP")).toBeInTheDocument();
    expect(within(dialog).getByLabelText(/^Verification code/)).toBeInTheDocument();
  });

  it("removes a key after the password, and explains the last one", async () => {
    const user = userEvent.setup();
    stubWebAuthn();
    let last = false;
    const server = installFakeApi({
      ...routes(),
      "POST /auth/security-keys/:id/remove": () =>
        last ? fail(409, "last_factor", "This is your only second factor. Add an authenticator app or another key before removing it.") : noContent,
    });
    renderApp("/account");
    await user.click(await screen.findByRole("button", { name: "Remove MacBook" }));
    let dialog = screen.getByRole("dialog", { name: "Remove MacBook" });
    const remove = within(dialog).getByRole("button", { name: "Remove key" });
    expect(remove).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/^Password/), "my password");
    await user.click(remove);
    expect(await screen.findByText("MacBook no longer signs you in.")).toBeInTheDocument();
    expect(server.call("POST /auth/security-keys/:id/remove").params.id).toBe("k2");
    expect(server.call("POST /auth/security-keys/:id/remove").body).toEqual({ password: "my password" });

    last = true;
    await user.click(screen.getByRole("button", { name: "Remove YubiKey" }));
    dialog = screen.getByRole("dialog", { name: "Remove YubiKey" });
    await user.type(within(dialog).getByLabelText(/^Password/), "my password");
    await user.click(within(dialog).getByRole("button", { name: "Remove key" }));
    expect(await within(dialog).findByText(/This is your only second factor/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
  });

  it("explains why keys cannot be added here", async () => {
    installFakeApi({
      ...routes(),
      "GET /auth/options": ok({
        ...keysUsableHere(),
        webauthn: { available: false, reason: "Security keys and passkeys need EasyRMM to be reached by a name (EASYRMM_PUBLIC_URL), not an IP address." },
      }),
    });
    renderApp("/account");
    expect(await screen.findByText(/need EasyRMM to be reached by a name/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add security key" })).not.toBeInTheDocument();
    // Existing keys can still be removed.
    expect(await screen.findByRole("button", { name: "Remove YubiKey" })).toBeInTheDocument();
  });

  it("links to the public address from another one", async () => {
    stubWebAuthn();
    installFakeApi({ ...routes(), "GET /auth/options": ok({ ...keysUsableHere(), webauthn: { available: true, origin: "https://rmm.example.com" } }) });
    renderApp("/account");
    expect(await screen.findByRole("link", { name: "Open your account there" })).toHaveAttribute("href", "https://rmm.example.com/account");
  });

  it("caps the number of keys", async () => {
    stubWebAuthn();
    installFakeApi({ ...routes(), "GET /auth/security-keys": ok({ items: Array.from({ length: 10 }, (_, i) => key(`k${i}`, `Key ${i}`)) }) });
    renderApp("/account");
    expect(await screen.findByText(/You have 10, the most allowed/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add security key" })).toBeDisabled();
  });
});
