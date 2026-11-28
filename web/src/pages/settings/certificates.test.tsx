import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { TlsCheck, TlsNameStatus, TlsOverview } from "../../api/types";
import {
  baseRoutes,
  fail,
  installFakeApi,
  ok,
  sessionView,
  unreportedRoutes,
} from "../../test/fakeApi";
import { renderApp } from "../../test/render";

// Settings > Certificates and the banner across the console (ADR-0055).

const VALID: TlsNameStatus = {
  name: "rmm.example.test",
  state: "valid",
  imported: false,
  serial: "ab12",
  issuer: "R12",
  notBefore: "2026-11-01T00:00:00Z",
  notAfter: "2027-01-30T00:00:00Z",
  renewalDue: "2026-12-31T00:00:00Z",
  ariStart: "2026-12-29T00:00:00Z",
  ariEnd: "2026-12-31T00:00:00Z",
  failures: 0,
  alert: "none",
};
const MESH: TlsNameStatus = {
  ...VALID,
  name: "mesh.rmm.example.test",
  role: "remote access",
  pendingSerial: "cd34",
  pendingReadyAt: "2026-11-26T10:00:00Z",
};
const FAILING: TlsNameStatus = {
  name: "rmm.example.test",
  state: "failing",
  imported: false,
  failures: 3,
  failingSince: "2026-11-26T08:00:00Z",
  lastError:
    "HTTP 403 urn:ietf:params:acme:error:unauthorized - could not validate",
  alert: "warning",
  alertReason: "no certificate for an hour: orders are failing",
};
const WAITING: TlsNameStatus = {
  name: "rmm.example.test",
  state: "waiting_dns",
  imported: false,
  failures: 0,
  waitingDnsSince: "2026-11-26T08:00:00Z",
  alert: "none",
};

function overview(
  names: TlsNameStatus[],
  extra: Partial<TlsOverview["status"]> = {},
): TlsOverview {
  return {
    mode: "acme",
    managed: true,
    status: {
      directory: "https://acme-v02.api.letsencrypt.org/directory",
      email: "",
      account: true,
      held: false,
      names,
      warnings: [],
      now: "2026-11-26T12:00:00Z",
      ...extra,
    },
  };
}

const SUPER = sessionView({ globalPermissions: ["settings.manage"] });

function routes(o: TlsOverview, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(SUPER),
    ...unreportedRoutes(),
    "GET /users": ok({ items: [], total: 0 }),
    "GET /settings/certificates": ok(o),
    "GET /settings/certificates/added-name": ok({ eligible: false }),
    "GET /settings/dns-providers": ok({ credentials: [] }),
    ...extra,
  };
}

describe("Settings > Certificates", () => {
  it("shows each name's certificate, its renewal window and a certificate waiting for MeshCentral", async () => {
    installFakeApi(routes(overview([VALID, MESH])));
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText("rmm.example.test")).toBeInTheDocument();
    expect(main.getByText("remote access")).toBeInTheDocument();
    expect(
      main.getAllByText("Valid", { selector: "span" }).length,
    ).toBeGreaterThanOrEqual(2);
    expect(main.getAllByText(/in the window the CA suggests/)).toHaveLength(2);
    expect(
      main.getByText(/applied three minutes after MeshCentral's last read/),
    ).toBeInTheDocument();
    expect(
      main.getByText(/none: Let's Encrypt sends no expiry email/),
    ).toBeInTheDocument();
  });

  it("shows a failing name with the CA's last answer and retries it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(overview([FAILING]), {
        "POST /settings/certificates/:name/retry": {
          status: 202,
          body: { status: "started" },
        },
      }),
    );
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText("Failing")).toBeInTheDocument();
    expect(main.getByText(/could not validate/)).toBeInTheDocument();
    await user.click(main.getByRole("button", { name: /Retry now/ }));
    expect(server.call("POST /settings/certificates/:name/retry").path).toBe(
      "/settings/certificates/rmm.example.test/retry",
    );
  });

  it("refuses Retry now while 4 validations have failed within the hour, and says when", async () => {
    installFakeApi(
      routes(
        overview([{ ...FAILING, retryRefusedUntil: "2026-11-26T13:00:00Z" }]),
      ),
    );
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    expect(
      await main.findByText(/Retry now is refused until/),
    ).toBeInTheDocument();
    expect(main.getByRole("button", { name: /Retry now/ })).toBeDisabled();
  });

  it("offers Order anyway for a name that does not resolve, and orders it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes(overview([WAITING]), {
        "POST /settings/certificates/:name/order-anyway": {
          status: 202,
          body: { status: "started" },
        },
      }),
    );
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    expect(await main.findByText("Waiting for DNS")).toBeInTheDocument();
    await user.click(main.getByRole("button", { name: "Order anyway" }));
    expect(
      server.call("POST /settings/certificates/:name/order-anyway").path,
    ).toBe("/settings/certificates/rmm.example.test/order-anyway");
  });

  it("runs the checks and shows each with its fix", async () => {
    const user = userEvent.setup();
    const checks: TlsCheck[] = [
      {
        id: "resolves",
        title: "The name resolves on this server",
        status: "ok",
        detail: "rmm.example.test resolves to 203.0.113.9.",
      },
      {
        id: "records",
        title: "Its A and AAAA records point at this server",
        status: "fail",
        detail: "An AAAA record points elsewhere.",
        fix: "Correct or remove the AAAA record.",
      },
    ];
    installFakeApi(
      routes(overview([VALID]), {
        "POST /settings/certificates/:name/check": ok({ checks }),
      }),
    );
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    await user.click(await main.findByRole("button", { name: /Check/ }));
    expect(
      await main.findByText("Correct or remove the AAAA record."),
    ).toBeInTheDocument();
    expect(main.getByText("Failed")).toBeInTheDocument();
    expect(main.getByText("Passed")).toBeInTheDocument();
  });

  it("says why an attempt is refused", async () => {
    const user = userEvent.setup();
    installFakeApi(
      routes(overview([FAILING]), {
        "POST /settings/certificates/:name/retry": fail(
          409,
          "held",
          "tls: the server is held for an update; attempts wait for its end",
        ),
      }),
    );
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    await user.click(await main.findByRole("button", { name: /Retry now/ }));
    expect(await main.findByText(/held for an update/)).toBeInTheDocument();
  });

  it("explains modes in which the server obtains nothing", async () => {
    installFakeApi(routes({ mode: "manual", managed: false }));
    renderApp("/settings?tab=certificates");
    const main = within(await screen.findByRole("main"));
    expect(
      await main.findByText(/certificate files you gave it/),
    ).toBeInTheDocument();
  });
});

describe("the certificate banner", () => {
  it("shows across the console when a name needs attention", async () => {
    installFakeApi(routes(overview([FAILING])));
    renderApp("/settings?tab=users");
    expect(await screen.findByTestId("certificate-banner")).toHaveTextContent(
      "The certificate for rmm.example.test needs attention.",
    );
  });

  it("is absent when every certificate is well", async () => {
    installFakeApi(routes(overview([VALID])));
    renderApp("/settings?tab=users");
    await screen.findByRole("main");
    expect(screen.queryByTestId("certificate-banner")).not.toBeInTheDocument();
  });

  it("is never asked of someone without the platform right", async () => {
    const server = installFakeApi({
      ...routes(overview([FAILING])),
      ...baseRoutes(
        sessionView({
          isSuperAdmin: false,
          permissions: ["user.view", "org.view", "device.view", "site.view"],
        }),
      ),
    });
    renderApp("/settings?tab=users");
    await screen.findByRole("main");
    expect(screen.queryByTestId("certificate-banner")).not.toBeInTheDocument();
    expect(server.calls.some((c) => c.path === "/settings/certificates")).toBe(
      false,
    );
  });
});
