import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Device, EnrollmentToken, EnrollmentTokenInput, TlsTrust } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView, unreportedRoutes, type FakeRequest } from "../../test/fakeApi";
import { device } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { checkResult, hasTrustToShow, platformOf } from "./DeviceTrust";

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const ADMIN = sessionView({ permissions: [...sessionView().permissions, "device.view", "enrollment.manage", "device.terminal"] });
const SECRET = "ert_AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIIIjjjjKKK";

const trust = (extra: Partial<TlsTrust> = {}): TlsTrust => ({
  capable: true,
  origin: "rmm.example.com",
  trusts: "ca-file",
  widened: false,
  checks: [],
  unprotected: false,
  canTerminal: true,
  platform: "linux",
  siteId: "s1",
  ...extra,
});

const check = (extra: Partial<TlsTrust["checks"][number]> = {}): TlsTrust["checks"][number] => ({
  scope: "agent",
  host: "rmm.example.com",
  purpose: "served",
  state: "passed",
  requestedAt: "2026-11-26T10:00:00Z",
  checkedAt: "2026-11-26T10:01:00Z",
  ...extra,
});

function token(input: EnrollmentTokenInput): EnrollmentToken {
  return {
    id: "t9", organizationId: "o1", organizationName: "Northwind Traders", siteId: "s1", siteName: "Head office", deviceGroupId: null, name: input.name,
    expiresAt: "2030-01-01T00:00:00Z", maxUses: input.maxUses, uses: 0, createdAt: "2026-11-01T10:00:00Z", lastUsedAt: null, revokedAt: null, status: "active", kept: true,
  };
}

function page(d: Device, t: TlsTrust, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(ADMIN),
    ...unreportedRoutes(),
    "GET /devices/:id": ok(d),
    "GET /devices/:id/tls-trust": ok(t),
    "GET /agent-downloads": ok({ serverUrl: "https://rmm.example.com", items: [] }),
    "GET /audit": ok({ items: [] }),
    ...extra,
  };
}

describe("certificate trust text", () => {
  it("words each result", () => {
    expect(checkResult({ state: "passed" })).toBe("Verified");
    expect(checkResult({ state: "failed", error: "x509: unknown authority" })).toBe("Cannot verify: x509: unknown authority");
    expect(checkResult({ state: "failed" })).toBe("Cannot verify");
    expect(checkResult({ state: "pending" })).toBe("Not reported yet");
  });

  it("shows the card only when there is something to say", () => {
    expect(hasTrustToShow(undefined)).toBe(false);
    expect(hasTrustToShow(trust())).toBe(false);
    expect(hasTrustToShow(trust({ checks: [check()] }))).toBe(true);
    expect(hasTrustToShow(trust({ refused: "expired" }))).toBe(true);
    expect(hasTrustToShow(trust({ reinstall: { reason: "r", fix: "f" } }))).toBe(true);
    expect(platformOf({ platform: "linux" })).toBe("linux");
    expect(platformOf({ platform: "windows" })).toBe("windows");
  });
});

describe("a device's certificate trust", () => {
  it("shows nothing for a device that has not been asked", async () => {
    installFakeApi(page(device("d1", "SRV-01", { platform: "linux", agent: AGENT }), trust()));
    renderApp("/devices/d1");
    expect(await screen.findByRole("heading", { name: "SRV-01" })).toBeInTheDocument();
    expect(screen.queryByText("Certificate trust")).not.toBeInTheDocument();
  });

  it("lists what each agent verified, flags a Linux EasyPatch result as a stand-in and says what the agent trusts", async () => {
    installFakeApi(
      page(
        device("d1", "SRV-01", { platform: "linux", agent: AGENT }),
        trust({
          widened: true,
          trusts: "system+ca-file",
          checks: [
            check(),
            check({ purpose: "fallback", state: "failed", error: "x509: certificate signed by unknown authority" }),
            check({ scope: "easypatch", host: "patch.example.com", standIn: true, state: "pending", checkedAt: undefined }),
          ],
          unprotected: true,
        }),
      ),
    );
    renderApp("/devices/d1");
    expect(await screen.findByText("Certificate trust")).toBeInTheDocument();
    expect(screen.getByText(/It trusts the computer's root certificates and the server's certificate authority\./)).toBeInTheDocument();
    expect(screen.getByText(/A move widened its trust\./)).toBeInTheDocument();
    expect(screen.getByText("Unprotected")).toBeInTheDocument();
    expect(screen.getByText("Verified")).toBeInTheDocument();
    expect(screen.getByText("Cannot verify: x509: certificate signed by unknown authority")).toBeInTheDocument();
    expect(screen.getByText("Not reported yet")).toBeInTheDocument();
    expect(screen.getByText("Checked by the EasyRMM agent")).toBeInTheDocument();
    expect(screen.queryByText("Reinstall through a remote session")).not.toBeInTheDocument();
  });

  it("shows what the agent refused", async () => {
    installFakeApi(page(device("d1", "SRV-01", { platform: "linux", agent: AGENT }), trust({ refused: "the trust instruction has expired", checks: [check({ state: "pending", checkedAt: undefined })] })));
    renderApp("/devices/d1");
    expect(await screen.findByText("The agent refused the last instruction")).toBeInTheDocument();
    expect(screen.getByText("the trust instruction has expired")).toBeInTheDocument();
  });

  it("offers Reinstall through a remote session to a device that is cut off, with a one-use token and the fix", async () => {
    const user = userEvent.setup();
    const t = trust({
      checks: [check({ state: "failed", error: "x509: certificate signed by unknown authority" })],
      reinstall: { reason: "The agent reported that it cannot verify the server's certificate, and it is not connected now.", fix: "Update the computer's root certificates, or reinstall with --ca-file." },
    });
    const server = installFakeApi(
      page(device("d1", "SRV-01", { platform: "linux", online: false, agent: AGENT }), t, {
        "POST /sites/:id/enrollment-tokens": (r: FakeRequest) => ({
          status: 201,
          body: { token: token(r.body as EnrollmentTokenInput), secret: SECRET, serverUrl: "https://rmm.example.com" },
        }),
      }),
    );
    renderApp("/devices/d1");
    const section = await screen.findByRole("region", { name: "Reinstall through a remote session" });
    expect(section).toHaveTextContent("it is not connected now");
    expect(section).toHaveTextContent("Update the computer's root certificates, or reinstall with --ca-file.");
    // A terminal button, the way remote sessions are opened.
    expect(within(section).getByRole("button", { name: "Terminal" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create install command" }));
    await waitFor(() => expect(server.callsTo("POST /sites/:id/enrollment-tokens")).toHaveLength(1));
    const sent = server.call("POST /sites/:id/enrollment-tokens").body as EnrollmentTokenInput;
    expect(sent).toMatchObject({ maxUses: 1, expiresInDays: 1, deviceGroupId: null });
    expect(server.call("POST /sites/:id/enrollment-tokens").params.id).toBe("s1");
    // The Linux device's command first, carrying the token.
    expect(await screen.findByText(new RegExp(`export EASYRMM_TOKEN='${SECRET}'`))).toBeInTheDocument();
  });

  it("says when no terminal can be opened, and shows a token's failure", async () => {
    const user = userEvent.setup();
    const t = trust({ canTerminal: false, reinstall: { reason: "r", fix: "f" }, checks: [check({ state: "failed", error: "e" })] });
    installFakeApi(
      page(device("d1", "SRV-01", { platform: "linux", online: false, canTerminal: false, agent: AGENT }), t, {
        "POST /sites/:id/enrollment-tokens": fail(403, "forbidden", "You may not create deployment tokens here."),
      }),
    );
    renderApp("/devices/d1");
    expect(await screen.findByText(/A terminal is not available on this device now/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create install command" }));
    expect(await screen.findByText("You may not create deployment tokens here.")).toBeInTheDocument();
  });
});
