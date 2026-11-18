import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AuditForwarding, AuditForwardingInput } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { renderApp } from "../../test/render";

const UNSET: AuditForwarding = {
  configured: false,
  enabled: false,
  transport: "tls",
  host: "",
  port: 6514,
  facility: 13,
  caCert: "",
  clientCert: "",
  clientKeySet: false,
  hostname: "rmm.example.com",
  status: { lastId: 0, backlog: 1234, backlogMore: false, stored: 1234, storedMore: false, stopping: false },
};

const CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";

function routes(settings: AuditForwarding = UNSET) {
  return {
    ...baseRoutes(sessionView()),
    "GET /settings/audit-forwarding": ok(settings),
    "GET /audit": ok({ items: [] }),
  };
}

const main = () => within(screen.getByRole("main"));

describe("audit forwarding settings", () => {
  it("sets up forwarding, starting from every stored record", async () => {
    const user = userEvent.setup();
    const saved: AuditForwarding = {
      ...UNSET,
      configured: true,
      enabled: true,
      transport: "udp",
      host: "siem.example.com",
      port: 514,
      facility: 16,
      updatedAt: new Date().toISOString(),
      updatedBy: "alex@example.com",
    };
    const server = installFakeApi({ ...routes(), "PUT /settings/audit-forwarding": ok(saved) });
    renderApp("/settings?tab=forwarding");

    expect(await screen.findByRole("heading", { name: "Audit forwarding", level: 1 })).toBeInTheDocument();
    expect(await main().findByText("Off")).toBeInTheDocument();
    expect(main().getByText("rmm.example.com")).toBeInTheDocument();
    // TLS is the default, on its own port; the client key waits for a certificate.
    expect(main().getByLabelText(/^Transport/)).toHaveValue("tls");
    expect(main().getByLabelText(/^Port/)).toHaveValue("6514");
    expect(main().getByLabelText(/^Client key/)).toBeDisabled();
    expect(main().getByLabelText(/Every record in the log \(1,234\)/)).toBeChecked();

    await user.type(main().getByLabelText(/^Collector/), "siem.example.com");
    await user.selectOptions(main().getByLabelText(/^Transport/), "udp");
    // The port follows the transport while it is the default; TLS fields go.
    expect(main().getByLabelText(/^Port/)).toHaveValue("514");
    expect(main().queryByLabelText(/^CA certificate/)).not.toBeInTheDocument();
    expect(main().getByText(/No delivery confirmation and no encryption/)).toBeInTheDocument();
    await user.selectOptions(main().getByLabelText(/^Facility/), "16");
    await user.click(main().getByRole("button", { name: "Save" }));

    await waitFor(() => expect(server.callsTo("PUT /settings/audit-forwarding")).toHaveLength(1));
    expect(server.callsTo("PUT /settings/audit-forwarding")[0]!.body).toEqual({
      enabled: true,
      transport: "udp",
      host: "siem.example.com",
      port: 514,
      facility: 16,
      caCert: "",
      clientCert: "",
      clientKey: "",
      startFrom: "beginning",
    } satisfies AuditForwardingInput);
    expect(await screen.findByText("Forwarding the audit log to siem.example.com:514.")).toBeInTheDocument();
  });

  it("sends a test message with the form as it stands and shows the outcome", async () => {
    const user = userEvent.setup();
    let reply = ok({ ok: false, message: "Connection refused: nothing accepts TLS connections on siem:6514." });
    const server = installFakeApi({ ...routes(), "POST /settings/audit-forwarding/test": () => reply });
    renderApp("/settings?tab=forwarding");

    await user.type(await screen.findByLabelText(/^Collector/), "siem");
    await user.type(main().getByLabelText(/^CA certificate/), "x");
    await user.click(main().getByRole("button", { name: "Send test message" }));
    expect(await main().findByText("The test message did not go")).toBeInTheDocument();
    expect(main().getByText(/Connection refused/)).toBeInTheDocument();
    const body = server.callsTo("POST /settings/audit-forwarding/test")[0]!.body as AuditForwardingInput;
    expect(body).toMatchObject({ host: "siem", transport: "tls", port: 6514, caCert: "x" });

    reply = ok({ ok: true, message: "Connected over TLS, the collector's certificate checked out, and the message was sent." });
    await user.click(main().getByRole("button", { name: "Send test message" }));
    expect(await main().findByText("Test message sent")).toBeInTheDocument();

    // Validation errors land on their fields.
    reply = fail(422, "validation_failed", "Check the highlighted fields.", { host: "must be a host name or an IP address, without a scheme or port" });
    await user.click(main().getByRole("button", { name: "Send test message" }));
    expect(await main().findByText("must be a host name or an IP address, without a scheme or port")).toBeInTheDocument();
    expect(main().getByLabelText(/^Collector/)).toHaveAttribute("aria-invalid", "true");
  });

  it("shows a failing collector and keeps the stored client key", async () => {
    const user = userEvent.setup();
    const failing: AuditForwarding = {
      ...UNSET,
      configured: true,
      enabled: true,
      host: "siem.example.com",
      caCert: CERT,
      clientCert: CERT,
      clientKeySet: true,
      updatedAt: new Date(Date.now() - 3600_000).toISOString(),
      updatedBy: "alex@example.com",
      status: {
        lastId: 90,
        lastSentAt: new Date(Date.now() - 600_000).toISOString(),
        lastError: "The collector's certificate is not valid for siem.example.com.",
        lastErrorAt: new Date(Date.now() - 30_000).toISOString(),
        backlog: 12,
        backlogMore: false,
        oldestPendingAt: new Date(Date.now() - 540_000).toISOString(),
        stored: 102,
        storedMore: false,
        stopping: false,
      },
    };
    const server = installFakeApi({ ...routes(failing), "PUT /settings/audit-forwarding": ok(failing) });
    renderApp("/settings?tab=forwarding");

    expect(await screen.findByText("Failing")).toBeInTheDocument();
    expect(main().getByText(failing.status.lastError!)).toBeInTheDocument();
    expect(main().getByText(/12 records/)).toBeInTheDocument();
    expect(main().getByText(/by alex@example\.com/)).toBeInTheDocument();
    // Already on: no choice of where to start.
    expect(main().queryByText("Start with")).not.toBeInTheDocument();
    expect(main().getByLabelText(/^Client key/)).toHaveAttribute("placeholder", "Stored");
    expect(main().getByText(/A key is stored, encrypted/)).toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Save" }));
    await waitFor(() => expect(server.callsTo("PUT /settings/audit-forwarding")).toHaveLength(1));
    expect(server.callsTo("PUT /settings/audit-forwarding")[0]!.body).toMatchObject({ clientCert: CERT, clientKey: "", startFrom: "" });
  });

  it("says when forwarding that was turned off is still sending its last records", async () => {
    const stopping: AuditForwarding = {
      ...UNSET,
      configured: true,
      host: "siem.example.com",
      updatedAt: new Date().toISOString(),
      status: { ...UNSET.status, lastId: 90, backlog: 3, stopping: true },
    };
    installFakeApi(routes(stopping));
    renderApp("/settings?tab=forwarding");
    expect(await screen.findByText("Sending its last records")).toBeInTheDocument();
    expect(main().getByText(/3 records/)).toBeInTheDocument();
    // Turning it back on offers where to start again.
    await userEvent.setup().click(main().getByLabelText(/^Forward the audit log/));
    expect(main().getByText("Start with")).toBeInTheDocument();
  });

  it("is a super administrator's setting", async () => {
    installFakeApi({
      ...routes(),
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "user.view", "audit.view"] })),
      "GET /audit": ok({ items: [] }),
      "GET /users": ok({ items: [] }),
    });
    renderApp("/settings?tab=forwarding");
    // The part is not offered; the first one the user has opens instead.
    expect(await screen.findByRole("heading", { name: "Users", level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Audit forwarding" })).not.toBeInTheDocument();
  });
});
