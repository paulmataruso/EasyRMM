import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { QuickAssistLink, QuickAssistSession } from "../../api/types";
import { baseRoutes, fail, installFakeApi, noContent, ok, sessionView } from "../../test/fakeApi";
import { org } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const TECH = sessionView({
  isSuperAdmin: false,
  permissions: ["org.view", "site.view", "device.view", "quickassist.view", "quickassist.link.create", "quickassist.session", "quickassist.install"],
});
const ACME = org("o1", "Acme");

const request: QuickAssistSession = {
  id: "s1", linkId: "l1", linkName: "Support for Contoso", organizationId: "o1", deviceId: "d1", deviceName: "FRONT-DESK", platform: "linux",
  state: "requested", elevated: false, test: true, requestedAt: "2026-11-26T10:00:00Z", acceptedBy: null, acceptedAt: null, endedAt: null,
  endReason: "", lastSeenAt: "2026-11-26T10:00:00Z", cleanup: "none", sourceIp: "203.0.113.5", disconnected: false,
  expiresAt: "2099-01-01T00:00:00Z", extended: false, lastActivityAt: "2026-11-26T10:00:00Z",
};

const routes = (sessions: QuickAssistSession[], extra = {}) => ({
  ...baseRoutes(TECH),
  "GET /organizations": ok({ items: [ACME] }),
  "GET /quickassist/settings": ok({ mode: "own_test", defaultLifeMinutes: 1440 }),
  "GET /quickassist/waiting": ok({ waiting: sessions.filter((s) => s.state === "requested").length }),
  "GET /organizations/:id/quickassist/sessions": ok({ sessions }),
  ...extra,
});

describe("Quick Assist", () => {
  it("shows the request, with a badge on the section, and never a code", async () => {
    installFakeApi(routes([request]));
    renderApp("/quickassist");
    const row = (await screen.findByText("FRONT-DESK")).closest("tr")!;
    expect(within(row).getByText(/Not elevated: screen and inventory only/)).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/session code: \d/i);
    expect(await screen.findByLabelText("1 waiting")).toBeInTheDocument();
  });

  it("accepts by typing the six digits, and says what is wrong when they are not", async () => {
    const user = userEvent.setup();
    let tries = 0;
    const server = installFakeApi(
      routes([request], {
        "POST /quickassist/sessions/:id/accept": () => (++tries === 1 ? fail(422, "wrong_code", "That is not the code on the user's screen. Tries left: 2.") : ok({ ...request, state: "active" })),
      }),
    );
    renderApp("/quickassist");
    await user.click(await screen.findByRole("button", { name: /Accept/ }));
    const input = await screen.findByLabelText("Code from the user's screen");
    const dialog = screen.getByRole("dialog");
    const submit = within(dialog).getByRole("button", { name: "Accept" });
    expect(submit).toBeDisabled();
    await user.type(input, "12ab345678");
    expect(input).toHaveValue("123456");
    await user.click(submit);
    expect(await screen.findByText(/Tries left: 2/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Accept" }));
    await waitFor(() => expect(screen.queryByLabelText("Code from the user's screen")).not.toBeInTheDocument());
    expect(server.callsTo("POST /quickassist/sessions/:id/accept").map((c) => c.body)).toEqual([{ code: "123456" }, { code: "123456" }]);
  });

  it("declines a request", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes([request], { "POST /quickassist/sessions/:id/decline": noContent }));
    renderApp("/quickassist");
    await user.click(await screen.findByRole("button", { name: /Decline/ }));
    await waitFor(() => expect(server.callsTo("POST /quickassist/sessions/:id/decline")).toHaveLength(1));
  });

  it("lists active sessions with End, and ended ones with the cleanup result", async () => {
    const active = { ...request, state: "active" as const, acceptedBy: "u-alex", elevated: true };
    const ended = { ...request, id: "s2", state: "ended" as const, endReason: "technician", cleanup: "verified" as const, endedAt: "2026-11-26T11:00:00Z" };
    const user = userEvent.setup();
    const server = installFakeApi(routes([active], { "POST /quickassist/sessions/:id/end": noContent, "POST /quickassist/sessions/:id/install": noContent }));
    renderApp("/quickassist?view=active");
    expect(await screen.findByText(/You hold it/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "End session" }));
    await waitFor(() => expect(server.callsTo("POST /quickassist/sessions/:id/end")).toHaveLength(1));
    await user.click(screen.getByRole("button", { name: "Install agent" }));
    await waitFor(() => expect(server.callsTo("POST /quickassist/sessions/:id/install")).toHaveLength(1));

    installFakeApi(routes([ended]));
    renderApp("/quickassist?view=ended");
    expect(await screen.findByText(/Ended by the technician\. Cleaned up, verified\./)).toBeInTheDocument();
  });

  it("offers Extend only near the end of a session, once", async () => {
    const user = userEvent.setup();
    const soon = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const far = { ...request, state: "active" as const, acceptedBy: "u-alex" };
    const near = { ...far, id: "s3", deviceName: "NEAR-END", expiresAt: soon };
    const done = { ...far, id: "s4", deviceName: "EXTENDED", expiresAt: soon, extended: true };
    const server = installFakeApi(routes([far, near, done], { "POST /quickassist/sessions/:id/extend": ok({ ...near, extended: true }) }));
    renderApp("/quickassist?view=active");
    const nearRow = (await screen.findByText("NEAR-END")).closest("tr")!;
    expect(within((await screen.findByText("FRONT-DESK")).closest("tr")!).queryByRole("button", { name: /Extend/ })).not.toBeInTheDocument();
    expect(within(screen.getByText("EXTENDED").closest("tr")!).getByRole("button", { name: "Extended" })).toBeDisabled();
    await user.click(within(nearRow).getByRole("button", { name: "Extend" }));
    await waitFor(() => expect(server.callsTo("POST /quickassist/sessions/:id/extend")).toHaveLength(1));
  });

  it("badges a stale permanent link", async () => {
    const link: QuickAssistLink = {
      id: "l8", organizationId: "o1", siteId: null, kind: "permanent", name: "Help desk", note: "", state: "active", paused: false, test: false,
      expiresAt: null, createdAt: "2026-01-01T10:00:00Z", usedAt: null, lastUsedAt: "2026-02-01T10:00:00Z", downloadCount: 3, stale: true,
    };
    installFakeApi(routes([], { "GET /organizations/:id/quickassist/links": ok({ links: [link] }) }));
    renderApp("/quickassist?view=links");
    expect(await screen.findByText("Stale")).toBeInTheDocument();
  });

  it("makes a one-time link with one click and shows it once", async () => {
    const user = userEvent.setup();
    const link: QuickAssistLink = {
      id: "l9", organizationId: "o1", siteId: null, kind: "one_time", name: "Help", note: "", state: "active", paused: false, test: true,
      expiresAt: "2026-11-27T10:00:00Z", createdAt: "2026-11-26T10:00:00Z", usedAt: null, lastUsedAt: null, downloadCount: 0, stale: false,
    };
    const server = installFakeApi(
      routes([], {
        "GET /organizations/:id/quickassist/links": ok({ links: [] }),
        "GET /quickassist/settings": ok({ mode: "own_test" }),
        "POST /organizations/:id/quickassist/links": { status: 201, body: { link, token: "qal_secret", path: "/qa/qal_secret" } },
      }),
    );
    renderApp("/quickassist");
    // One click, no name asked for, and the link is shown with its expiry.
    await user.click(await screen.findByRole("button", { name: "New link" }));
    expect(await screen.findByLabelText("Link")).toHaveValue(`${window.location.origin}/qa/qal_secret`);
    expect(screen.getByText(/Works once, until/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Copy/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New permanent link" })).not.toBeInTheDocument();
    expect(server.callsTo("POST /organizations/:id/quickassist/links").map((c) => c.body)).toEqual([{ kind: "one_time" }]);
  });

  it("is not in the menu without the permission", async () => {
    installFakeApi({ ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view"] })), "GET /organizations": ok({ items: [ACME] }) });
    renderApp("/quickassist");
    expect(await screen.findByText("Not available to your role")).toBeInTheDocument();
  });
});
