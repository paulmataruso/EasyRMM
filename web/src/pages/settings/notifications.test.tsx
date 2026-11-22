import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { MailServer, MailServerInput, MailServerTestInput, MailServerView } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { renderApp } from "../../test/render";
import { whyNotEmailed } from "./mailProblem";

const NONE: MailServerView = {
  inForce: "none",
  limits: {
    perMinute: 30,
    perDay: 9000,
    account: { adminPerHour: 60, organizationPerDay: 500, accountBurst: 3, accountEveryMinutes: 20, resetsPerHour: 30, organizationResetsPerHour: 10 },
  },
  usage: { lastMinute: 0, lastDay: 0, accountLastDay: 0, adminDayLimit: 8100, otherDayLimit: 7200 },
};

const STORED: MailServer = {
  host: "smtp.example.com",
  port: 587,
  security: "starttls",
  signIn: "password",
  username: "rmm@example.com",
  passwordSet: true,
  fromAddress: "rmm@example.com",
  fromName: "EasyRMM",
  updatedAt: new Date(Date.now() - 3600_000).toISOString(),
  updatedBy: "alex@example.com",
};

const CONSOLE: MailServerView = { ...NONE, inForce: "console", console: STORED, usage: { lastMinute: 2, lastDay: 1234, accountLastDay: 12, adminDayLimit: 8100, otherDayLimit: 7200 } };

function routes(view: MailServerView = NONE) {
  return {
    ...baseRoutes(sessionView()),
    "GET /settings/mail-server": ok(view),
    "GET /audit": ok({ items: [] }),
  };
}

const main = () => within(screen.getByRole("main"));

describe("mail server settings", () => {
  it("tries a mail server before saving it, then saves it", async () => {
    const user = userEvent.setup();
    let reply = ok({ ok: false, message: "the mail server refused the sign-in: 535 5.7.8 Authentication credentials invalid" });
    const server = installFakeApi({
      ...routes(),
      "POST /settings/mail-server/test": () => reply,
      "PUT /settings/mail-server": ok(CONSOLE),
    });
    renderApp("/settings?tab=notifications");

    expect(await screen.findByRole("heading", { name: "Notifications", level: 1 })).toBeInTheDocument();
    expect(await main().findByText("No mail server")).toBeInTheDocument();
    // STARTTLS on 587 at first; the port follows the security while it is the default.
    expect(main().getByLabelText(/^Port/)).toHaveValue("587");
    await user.selectOptions(main().getByLabelText(/^Security/), "tls");
    expect(main().getByLabelText(/^Port/)).toHaveValue("465");
    await user.selectOptions(main().getByLabelText(/^Security/), "starttls");

    await user.type(main().getByLabelText(/^Server/), "smtp.example.com");
    await user.type(main().getByLabelText(/^User name/), "rmm@example.com");
    await user.type(main().getByLabelText(/^Password/), "app-password");
    await user.type(main().getByLabelText(/^Send from/), "rmm@example.com");
    // The test message goes to the signed-in user's address at first.
    expect(main().getByLabelText(/^Send a test message to/)).toHaveValue("alex@example.com");
    await user.click(main().getByRole("button", { name: "Send test message" }));
    expect(await main().findByText("The test message did not go")).toBeInTheDocument();
    expect(main().getByText(/535 5\.7\.8/)).toBeInTheDocument();
    const input: MailServerInput = {
      host: "smtp.example.com",
      port: 587,
      security: "starttls",
      signIn: "password",
      username: "rmm@example.com",
      password: "app-password",
      fromAddress: "rmm@example.com",
      fromName: "EasyRMM",
    };
    expect(server.callsTo("POST /settings/mail-server/test")[0]!.body).toEqual({ to: "alex@example.com", server: input } satisfies MailServerTestInput);

    reply = ok({ ok: true, message: "Sent. smtp.example.com:587 took the message for alex@example.com and answered: 250 2.0.0 OK" });
    await user.click(main().getByRole("button", { name: "Send test message" }));
    expect(await main().findByText("Test message sent")).toBeInTheDocument();
    expect(main().getByText(/answered: 250 2\.0\.0 OK/)).toBeInTheDocument();

    // One every 30 seconds.
    reply = fail(429, "test_rate_limited", "A test message went less than 30 seconds ago. Try again in 21 seconds.");
    await user.click(main().getByRole("button", { name: "Send test message" }));
    expect(await main().findByText(/Try again in 21 seconds/)).toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Save" }));
    await waitFor(() => expect(server.callsTo("PUT /settings/mail-server")).toHaveLength(1));
    expect(server.callsTo("PUT /settings/mail-server")[0]!.body).toEqual(input);
    expect(await screen.findByText("Saved. EasyRMM sends mail through smtp.example.com.")).toBeInTheDocument();
  });

  it("keeps the stored password only for the same server, port, security and user, and removes the mail server", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes(CONSOLE),
      "PUT /settings/mail-server": ok(CONSOLE),
      "DELETE /settings/mail-server": ok(NONE),
    });
    renderApp("/settings?tab=notifications");

    expect(await screen.findByRole("heading", { name: "Notifications", level: 1 })).toBeInTheDocument();
    const password = await main().findByLabelText(/^Password/);
    expect(password).toHaveAttribute("placeholder", "Stored");
    expect(main().getByText(/A password is stored, encrypted/)).toBeInTheDocument();
    expect(main().getByText(/by alex@example\.com/)).toBeInTheDocument();
    expect(main().queryByText("No mail server")).not.toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Save" }));
    await waitFor(() => expect(server.callsTo("PUT /settings/mail-server")).toHaveLength(1));
    expect(server.callsTo("PUT /settings/mail-server")[0]!.body).toMatchObject({ host: "smtp.example.com", password: "" });

    // Another port or security: the stored password does not go with it.
    await user.clear(main().getByLabelText(/^Port/));
    await user.type(main().getByLabelText(/^Port/), "2525");
    expect(main().getByLabelText(/^Password/)).not.toHaveAttribute("placeholder", "Stored");
    expect(main().getByText(/Enter it again: the stored one is kept only for the same server, port, security and user name/)).toBeInTheDocument();
    await user.clear(main().getByLabelText(/^Port/));
    await user.type(main().getByLabelText(/^Port/), "587");
    expect(main().getByLabelText(/^Password/)).toHaveAttribute("placeholder", "Stored");
    await user.selectOptions(main().getByLabelText(/^Security/), "tls");
    expect(main().getByLabelText(/^Password/)).not.toHaveAttribute("placeholder", "Stored");
    await user.selectOptions(main().getByLabelText(/^Security/), "starttls");
    expect(main().getByLabelText(/^Password/)).toHaveAttribute("placeholder", "Stored");

    // Another server: the stored password does not go with it.
    await user.clear(main().getByLabelText(/^Server/));
    await user.type(main().getByLabelText(/^Server/), "smtp.other.example");
    expect(main().getByLabelText(/^Password/)).not.toHaveAttribute("placeholder", "Stored");

    // Without signing in, no user name or password is sent.
    await user.selectOptions(main().getByLabelText(/^Sign in/), "none");
    expect(main().queryByLabelText(/^User name/)).not.toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Save" }));
    await waitFor(() => expect(server.callsTo("PUT /settings/mail-server")).toHaveLength(2));
    expect(server.callsTo("PUT /settings/mail-server")[1]!.body).toMatchObject({ signIn: "none", username: "", password: "" });

    await user.click(main().getByRole("button", { name: "Remove" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/password reset stops/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(server.callsTo("DELETE /settings/mail-server")).toHaveLength(1));
    expect(await screen.findByText("The mail server is removed.")).toBeInTheDocument();
  });

  it("shows .env's mail server read-only, and still tests it", async () => {
    const user = userEvent.setup();
    const env: MailServerView = { ...NONE, inForce: "env", env: { ...STORED, host: "relay.example.com", port: 25, signIn: "none", username: "", passwordSet: false, updatedAt: undefined } };
    const server = installFakeApi({ ...routes(env), "POST /settings/mail-server/test": ok({ ok: true, message: "Sent." }) });
    renderApp("/settings?tab=notifications");

    expect(await screen.findByRole("heading", { name: "Notifications", level: 1 })).toBeInTheDocument();
    expect(await main().findByText("The mail server comes from .env")).toBeInTheDocument();
    expect(main().getByText("relay.example.com:25")).toBeInTheDocument();
    expect(main().getByText("EasyRMM <rmm@example.com>")).toBeInTheDocument();
    expect(main().queryByText("The patching engine cannot be given .env's mail server")).not.toBeInTheDocument();
    expect(main().queryByLabelText(/^Server/)).not.toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Save" })).not.toBeInTheDocument();

    await user.clear(main().getByLabelText(/^Send a test message to/));
    await user.type(main().getByLabelText(/^Send a test message to/), "ops@example.com");
    await user.click(main().getByRole("button", { name: "Send test message" }));
    expect(await main().findByText("Test message sent")).toBeInTheDocument();
    expect(server.callsTo("POST /settings/mail-server/test")[0]!.body).toEqual({ to: "ops@example.com" });
  });

  it("says when .env's mail server is longer than the patching engine takes", async () => {
    const envProblem =
      "EASYRMM_SMTP_PASSWORD is longer than 512 characters, the most the patching engine takes. EasyRMM sends with it, but the patching engine cannot be given this mail server, so patching sends no email or reports. Shorten it in .env and restart EasyRMM.";
    installFakeApi(routes({ ...NONE, inForce: "env", env: STORED, envProblem }));
    renderApp("/settings?tab=notifications");

    expect(await screen.findByRole("heading", { name: "Notifications", level: 1 })).toBeInTheDocument();
    const alert = (await main().findByText("The patching engine cannot be given .env's mail server")).closest<HTMLElement>('[role="alert"]')!;
    expect(within(alert).getByText(/EASYRMM_SMTP_PASSWORD is longer than 512 characters/)).toBeInTheDocument();
    expect(main().getByText("smtp.example.com:587")).toBeInTheDocument();
  });

  it("removes the console's mail server while .env's is in force, which changes nothing that is sent", async () => {
    const user = userEvent.setup();
    const env: MailServerView = { ...NONE, inForce: "env", env: { ...STORED, host: "relay.example.com", port: 25, signIn: "none", username: "", passwordSet: false } };
    const server = installFakeApi({ ...routes({ ...env, console: STORED }), "DELETE /settings/mail-server": ok(env) });
    renderApp("/settings?tab=notifications");

    expect(await screen.findByRole("heading", { name: "Notifications", level: 1 })).toBeInTheDocument();
    const card = (await main().findByRole("heading", { name: "Saved in the console, not in use" })).closest("section")!;
    expect(within(card).getByText(/It is not used while .env's is in force/)).toBeInTheDocument();
    expect(main().getByText("smtp.example.com:587")).toBeInTheDocument();
    await user.click(main().getByRole("button", { name: "Remove" }));
    const dialog = await screen.findByRole("dialog", { name: "Remove the console's mail server?" });
    expect(within(dialog).getByText(/This does not change the mail server in force: .env's stays/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(server.callsTo("DELETE /settings/mail-server")).toHaveLength(1));
    expect(await screen.findByText("The console's mail server is removed. .env's stays in force.")).toBeInTheDocument();
  });

  it("sets the limits and shows how much of them is used", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes(CONSOLE),
      "PUT /settings/mail-server/limits": (r) => {
        const b = r.body as { perMinute: number; perDay: number };
        return b.perDay < b.perMinute
          ? fail(422, "validation_failed", "Some fields need attention.", { perDay: "Allow at least as many messages a day as a minute." })
          : ok({ ...CONSOLE, limits: { ...CONSOLE.limits, ...b, updatedAt: new Date().toISOString(), updatedBy: "alex@example.com" } });
      },
    });
    renderApp("/settings?tab=notifications");

    expect(await screen.findByRole("heading", { name: "Notifications", level: 1 })).toBeInTheDocument();
    expect(await main().findByText("1,234 of 9,000")).toBeInTheDocument();
    expect(main().getByText("2 of 30")).toBeInTheDocument();
    expect(main().getByText(/12 invitations and password resets/)).toBeInTheDocument();
    expect(main().getByText(/administrators send stop at 8,100, 90% of the day's limit, at 60 an hour per administrator, and at 500 a day per organization/)).toBeInTheDocument();
    expect(main().getByText(/Other mail stops at 7,200, 80%/)).toBeInTheDocument();
    expect(main().getByText(/ask for may use the whole day, at most 30 an hour, and to one organization's accounts 10 an hour; nothing holds them for a day/)).toBeInTheDocument();
    expect(main().getByText(/One account gets at most 3 password emails at once, then one every 20 minutes/)).toBeInTheDocument();

    await user.clear(main().getByLabelText(/^A minute/));
    await user.type(main().getByLabelText(/^A minute/), "100");
    await user.clear(main().getByLabelText(/^A day/));
    await user.type(main().getByLabelText(/^A day/), "50");
    await user.click(main().getByRole("button", { name: "Save limits" }));
    expect(await main().findByText("Allow at least as many messages a day as a minute.")).toBeInTheDocument();

    await user.clear(main().getByLabelText(/^A day/));
    await user.type(main().getByLabelText(/^A day/), "2000");
    await user.click(main().getByRole("button", { name: "Save limits" }));
    expect(await screen.findByText("Up to 100 messages a minute and 2,000 a day.")).toBeInTheDocument();
    expect(server.callsTo("PUT /settings/mail-server/limits")[1]!.body).toEqual({ perMinute: 100, perDay: 2000 });
  });

  it("is a super administrator's setting", async () => {
    installFakeApi({
      ...routes(),
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "user.view", "audit.view"] })),
      "GET /users": ok({ items: [] }),
    });
    renderApp("/settings?tab=notifications");
    expect(await screen.findByRole("heading", { name: "Users", level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Notifications" })).not.toBeInTheDocument();
  });

  it("says why a link was not emailed", () => {
    expect(whyNotEmailed("no_mail_server", "sam@example.com")).toBe("EasyRMM has no mail server, so send it to sam@example.com yourself.");
    expect(whyNotEmailed(undefined, "sam@example.com")).toBe("EasyRMM has no mail server, so send it to sam@example.com yourself.");
    expect(whyNotEmailed("not_sent", "sam@example.com")).toBe("The mail server did not take the message, so send it to sam@example.com yourself.");
    const reason = "This account has been emailed as many password emails as one account may: 3 at once, then one every 20 minutes. Another can be emailed in 20 minutes.";
    expect(whyNotEmailed("not_sent", "sam@example.com", reason)).toBe(`It was not emailed: ${reason} Send it to sam@example.com yourself.`);
  });
});
