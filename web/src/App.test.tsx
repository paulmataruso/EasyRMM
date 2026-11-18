import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Organization } from "./api/types";
import { safeReturnTo, passwordProblem } from "./pages/auth/AuthPages";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView } from "./test/fakeApi";
import { renderApp } from "./test/render";

const location = () => screen.getByTestId("location").textContent;

const org = (id: string, name: string, extra: Partial<Organization> = {}): Organization => ({
  id,
  name,
  timezone: "UTC",
  notes: "",
  siteCount: 0,
  canManage: true,
  canRename: true,
  createdAt: "2026-11-01T10:00:00Z",
  updatedAt: "2026-11-01T10:00:00Z",
  ...extra,
});

describe("safeReturnTo", () => {
  it("accepts same-site paths only", () => {
    expect(safeReturnTo("/organizations?q=a")).toBe("/organizations?q=a");
    for (const bad of [null, "", "https://evil.example", "//evil.example", "/\\evil.example", "/login/mfa", "organizations"]) {
      expect(safeReturnTo(bad)).toBe("/");
    }
  });
});

describe("passwordProblem", () => {
  it("mirrors the server policy for instant feedback", () => {
    expect(passwordProblem("short", "")).toMatch(/at least 12/);
    expect(passwordProblem("x".repeat(257), "")).toMatch(/at most 256/);
    expect(passwordProblem("a long enough passphrase", "different")).toMatch(/do not match/);
    expect(passwordProblem("a long enough passphrase", "a long enough passphrase")).toBeNull();
  });
});

describe("first-run setup", () => {
  it("routes to setup, creates the administrator, then pre-fills sign-in", async () => {
    const user = userEvent.setup();
    let required = true;
    const server = installFakeApi({
      ...baseRoutes(null),
      "GET /setup": () => ok({ required, passwordMinLength: 12 }),
      "POST /setup": () => {
        required = false;
        return { status: 201, body: {} };
      },
    });
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "Set up EasyRMM" })).toBeInTheDocument();
    expect(location()).toBe("/setup");

    await user.type(screen.getByLabelText(/^Setup token/), " token-123 ");
    await user.type(screen.getByLabelText(/^First organization/), "Contoso");
    await user.type(screen.getByLabelText(/^Your name/), "Alex Rivera");
    await user.type(screen.getByLabelText(/^Email/), "alex@example.com");
    await user.type(screen.getByLabelText(/^Password/), "correct horse battery");
    const submit = screen.getByRole("button", { name: "Create administrator" });
    await user.type(screen.getByLabelText(/^Confirm password/), "correct horse batter");
    expect(screen.getByText("The passwords do not match.")).toBeInTheDocument();
    expect(submit).toBeDisabled();
    await user.type(screen.getByLabelText(/^Confirm password/), "y");
    await user.click(submit);

    expect(await screen.findByText(/Setup is complete/)).toBeInTheDocument();
    expect(location()).toBe("/login");
    expect(screen.getByLabelText(/^Email/)).toHaveValue("alex@example.com");
    expect(screen.getByLabelText(/^Password/)).toHaveFocus();
    expect(server.call("POST /setup").body).toEqual({
      token: "token-123",
      email: "alex@example.com",
      displayName: "Alex Rivera",
      password: "correct horse battery",
      organizationName: "Contoso",
    });
  });

  it("shows the server's field errors", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(null),
      "GET /setup": ok({ required: true, passwordMinLength: 12 }),
      "POST /setup": fail(400, "validation_failed", "The request is invalid.", { token: "The setup token is not valid." }),
    });
    renderApp("/setup");
    await user.type(await screen.findByLabelText(/^Setup token/), "wrong");
    await user.type(screen.getByLabelText(/^Your name/), "Alex");
    await user.type(screen.getByLabelText(/^Email/), "alex@example.com");
    await user.type(screen.getByLabelText(/^Password/), "correct horse battery");
    await user.type(screen.getByLabelText(/^Confirm password/), "correct horse battery");
    await user.click(screen.getByRole("button", { name: "Create administrator" }));
    expect(await screen.findByText("The setup token is not valid.")).toBeInTheDocument();
    expect(screen.getByLabelText(/^Setup token/)).toHaveAttribute("aria-invalid", "true");
  });
});

describe("sign-in", () => {
  it("keeps the requested page through password and second factor", async () => {
    const user = userEvent.setup();
    let session: ReturnType<typeof sessionView> | null = null;
    const server = installFakeApi({
      ...baseRoutes(null),
      "GET /auth/session": () => (session ? ok(session) : fail(401, "unauthenticated", "Sign in.")),
      "POST /auth/login": () => ok(sessionView({ state: "mfa_required", permissions: [], isSuperAdmin: false, csrfToken: "csrf-mfa" })),
      "POST /auth/mfa/verify": (req) => {
        if ((req.body as { code: string }).code !== "123456") return fail(401, "invalid_code", "That code is not valid. Try the current code.");
        session = sessionView();
        return ok(session);
      },
      "GET /organizations": ok({ items: [org("o1", "Northwind Traders")] }),
    });
    renderApp("/organizations");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(location()).toBe("/login?returnTo=%2Forganizations");

    await user.type(screen.getByLabelText(/^Email/), " alex@example.com ");
    await user.type(screen.getByLabelText(/^Password/), "correct horse battery");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Two-factor verification" })).toBeInTheDocument();
    expect(location()).toBe("/login/mfa?returnTo=%2Forganizations");
    expect(server.call("POST /auth/login").body).toEqual({ email: "alex@example.com", password: "correct horse battery" });

    await user.type(screen.getByLabelText(/^Verification code/), "000000");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText("That code is not valid. Try the current code.")).toBeInTheDocument();
    expect(screen.getByLabelText(/^Verification code/)).toHaveValue("");
    // The MFA step sends the token from the half-signed-in session.
    expect(server.call("POST /auth/mfa/verify").headers["x-csrf-token"]).toBe("csrf-mfa");

    await user.type(screen.getByLabelText(/^Verification code/), "123456");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByRole("link", { name: "Northwind Traders" })).toBeInTheDocument();
    expect(location()).toBe("/organizations");
  });

  it("names empty fields instead of disabling the button", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(baseRoutes(null));
    renderApp("/login");
    const signIn = await screen.findByRole("button", { name: "Sign in" });
    expect(signIn).toBeEnabled();
    await user.click(signIn);
    expect(screen.getByText("Enter your email address.")).toBeInTheDocument();
    expect(screen.getByText("Enter your password.")).toBeInTheDocument();
    expect(screen.getByLabelText(/^Email/)).toHaveFocus();
    await user.type(screen.getByLabelText(/^Email/), "alex@example.com");
    await user.click(signIn);
    expect(screen.queryByText("Enter your email address.")).not.toBeInTheDocument();
    expect(screen.getByLabelText(/^Password/)).toHaveFocus();
    expect(server.callsTo("POST /auth/login")).toHaveLength(0);
  });

  it("shows the server's message for a failed sign-in", async () => {
    const user = userEvent.setup();
    installFakeApi({ ...baseRoutes(null), "POST /auth/login": fail(401, "invalid_credentials", "The email or password is not correct.") });
    renderApp("/login");
    await user.type(await screen.findByLabelText(/^Email/), "alex@example.com");
    await user.type(screen.getByLabelText(/^Password/), "wrong password here");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("The email or password is not correct.")).toBeInTheDocument();
    expect(location()).toBe("/login");
  });

  it("offers the reset link only when the server can send email", async () => {
    installFakeApi({ ...baseRoutes(null), "GET /auth/options": ok({ passwordResetAvailable: true, mfaRequired: true, passwordMinLength: 12 }) });
    renderApp("/login?email=sam%40example.com");
    expect(await screen.findByRole("link", { name: "Forgot your password?" })).toHaveAttribute("href", "/forgot-password?email=sam%40example.com");
  });

  it("sends a signed-in user away from the sign-in page", async () => {
    installFakeApi({ ...baseRoutes(sessionView()), "GET /organizations": ok({ items: [] }) });
    renderApp("/login?returnTo=%2Forganizations");
    expect(await screen.findByRole("heading", { name: "Organizations", level: 1 })).toBeInTheDocument();
    expect(location()).toBe("/organizations");
  });

  it("returns to sign-in, with a reason, when the server ends the session", async () => {
    installFakeApi({ ...baseRoutes(sessionView()), "GET /organizations": fail(401, "unauthenticated", "Sign in to continue.") });
    renderApp("/organizations");
    expect(await screen.findByText("Your session ended. Sign in again to continue.")).toBeInTheDocument();
    expect(location()).toBe("/login?returnTo=%2Forganizations");
  });

  it("explains when the server cannot be reached", { timeout: 15000 }, async () => {
    installFakeApi({ "GET /setup": fail(503, "unavailable", "The database is not reachable.") });
    renderApp("/");
    // Server errors are retried twice with backoff before the error screen shows.
    expect(await screen.findByRole("heading", { name: "EasyRMM is unavailable" }, { timeout: 8000 })).toBeInTheDocument();
  });
});

describe("authenticator enrollment at first sign-in", () => {
  it("holds the recovery codes on screen until they are saved", async () => {
    const user = userEvent.setup();
    let session = sessionView({ state: "mfa_enrollment", permissions: [], isSuperAdmin: false });
    const server = installFakeApi({
      ...baseRoutes(null),
      "GET /auth/session": () => ok(session),
      "POST /auth/mfa/totp/begin": ok({ secret: "JBSWY3DPEHPK3PXPJBSWY3DP", uri: "otpauth://totp/x", qrCodeSvg: "data:image/svg+xml;base64,PHN2Zy8+" }),
      "POST /auth/mfa/totp/confirm": () => {
        session = sessionView({ csrfToken: "csrf-2" });
        return ok({ recoveryCodes: ["aaaa-bbbb", "cccc-dddd"], session });
      },
      "GET /organizations": ok({ items: [] }),
      "GET /sites": ok({ items: [] }),
      "GET /users": ok({ items: [] }),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/");
    expect(await screen.findByText("JBSW Y3DP EHPK 3PXP JBSW Y3DP")).toBeInTheDocument();
    expect(location()).toBe("/login/mfa-setup");

    await user.type(screen.getByLabelText(/^Verification code/), "123456");
    await user.click(screen.getByRole("button", { name: "Turn on two-factor authentication" }));
    expect(await screen.findByText("aaaa-bbbb")).toBeInTheDocument();
    // The session is fully signed in now, but the page must not move on by itself.
    expect(location()).toBe("/login/mfa-setup");
    expect(server.call("POST /auth/mfa/totp/confirm").body).toEqual({ code: "123456" });

    const done = screen.getByRole("button", { name: "Continue" });
    expect(done).toBeDisabled();
    await user.click(screen.getByLabelText("I have saved these recovery codes"));
    await user.click(done);
    expect(await screen.findByRole("heading", { name: /Dashboard|Welcome|Overview/ })).toBeInTheDocument();
    expect(location()).toBe("/");
  });
});

describe("password reset and invitation links", () => {
  it("reads the token from the fragment and finishes at sign-in", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...baseRoutes(null), "POST /auth/password-reset/complete": noContent });
    renderApp("/welcome#token=invite-token-1");
    expect(await screen.findByRole("heading", { name: "Welcome to EasyRMM" })).toBeInTheDocument();
    await user.type(screen.getByLabelText(/^New password/), "correct horse battery");
    await user.type(screen.getByLabelText(/^Confirm new password/), "correct horse battery");
    await user.click(screen.getByRole("button", { name: "Set password" }));
    expect(await screen.findByText("Your password is set. Sign in with it now.")).toBeInTheDocument();
    expect(location()).toBe("/login?reset=done");
    expect(server.call("POST /auth/password-reset/complete").body).toEqual({ token: "invite-token-1", password: "correct horse battery" });
  });

  it("explains an incomplete link", async () => {
    installFakeApi(baseRoutes(null));
    renderApp("/reset-password");
    expect(await screen.findByText(/This link is incomplete/)).toBeInTheDocument();
  });

  it("confirms a reset request without saying whether the account exists", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(null),
      "POST /auth/password-reset/request": ok({ message: "If that address has an account, a reset link is on its way." }),
    });
    renderApp("/forgot-password?email=sam%40example.com");
    expect(await screen.findByLabelText(/^Email/)).toHaveValue("sam@example.com");
    await user.click(screen.getByRole("button", { name: "Send reset link" }));
    expect(await screen.findByText("If that address has an account, a reset link is on its way.")).toBeInTheDocument();
  });
});

describe("navigation by permission", () => {
  it("hides Settings from people who cannot see users or the audit log", async () => {
    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view"] })),
      "GET /organizations": ok({ items: [org("o1", "Northwind Traders", { canManage: false })] }),
    });
    renderApp("/organizations");
    const nav = await screen.findByRole("navigation", { name: /main|primary/i });
    expect(within(nav).queryByRole("link", { name: "Settings" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New organization" })).not.toBeInTheDocument();
  });

  it("signs out and returns to sign-in", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({ ...baseRoutes(sessionView()), "GET /organizations": ok({ items: [] }) });
    renderApp("/organizations");
    await user.click(within(await screen.findByRole("navigation", { name: "Main" })).getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(location()).toMatch(/^\/login/));
    expect(server.callsTo("POST /auth/logout")).toHaveLength(1);
  });
});
