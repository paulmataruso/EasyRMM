import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ApprovalToken, ApprovalTokenInput, EnrollmentRequest } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView, type FakeRequest } from "../../test/fakeApi";
import { group, site } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const PERMS = [...sessionView().permissions, "enrollment.manage" as const, "device.view" as const];
/** Manages enrollment on the whole server: decides on waiting devices. */
const APPROVER = sessionView({ permissions: PERMS, globalPermissions: ["enrollment.manage"] });
/** Manages enrollment in some organizations only. */
const ORG_ADMIN = sessionView({ permissions: PERMS, globalPermissions: [], isSuperAdmin: false });
const SECRET = "ert_AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIIIjjjjKKK";

function request(id: string, hostname: string, extra: Partial<EnrollmentRequest> = {}): EnrollmentRequest {
  return {
    id,
    code: `${id.toUpperCase()}AA-BBCC`,
    hostname,
    os: "Windows 11 Pro 24H2",
    platform: "windows",
    arch: "amd64",
    agentVersion: "1.4.0",
    sourceIp: "203.0.113.20",
    state: "pending",
    tokenId: "at1",
    tokenName: "Spring rollout",
    createdAt: "2026-11-15T09:00:00Z",
    lastSeenAt: "2026-11-15T09:30:00Z",
    online: true,
    matches: [],
    ...extra,
  };
}

function approvalToken(id: string, name: string, extra: Partial<ApprovalToken> = {}): ApprovalToken {
  return {
    id,
    name,
    expiresAt: "2030-01-01T00:00:00Z",
    maxUses: null,
    uses: 4,
    waiting: 2,
    createdByName: "Alex Rivera",
    createdAt: "2026-11-01T10:00:00Z",
    lastUsedAt: "2026-11-15T09:00:00Z",
    revokedAt: null,
    status: "active",
    ...extra,
  };
}

const WAITING = [
  request("r1", "FRONT-DESK-01", {
    matches: [{ deviceId: "d9", name: "FRONT-DESK-01", organizationName: "Northwind Traders", siteName: "Head office" }],
  }),
  request("r2", "KIOSK-02", { online: false, lastSeenAt: "2026-11-14T09:30:00Z" }),
];

function routes(extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(APPROVER),
    "GET /enrollment-requests/waiting": ok({ waiting: WAITING.length }),
    "GET /enrollment-requests": (r: FakeRequest) =>
      ok(
        r.query.get("state") === "rejected"
          ? {
              items: [request("r7", "OLD-PC", { state: "rejected", online: false, decidedAt: "2026-11-10T10:00:00Z", decidedByName: "Alex Rivera" })],
              waiting: WAITING.length,
            }
          : { items: WAITING, waiting: WAITING.length },
      ),
    "GET /sites": ok({ items: [site("s1", "o1", "Head office"), site("s2", "o1", "Warehouse"), site("s3", "o2", "Clinic", { organizationName: "Contoso Dental Group" })] }),
    "GET /sites/:id/device-groups": (r: FakeRequest) => ok({ items: r.params.id === "s2" ? [group("g1", "s2", "Scanners")] : [] }),
    ...extra,
  };
}

describe("devices waiting for approval", () => {
  it("lists waiting devices and approves a selection into a site", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes({
        "POST /enrollment-requests/approve": ok({ decided: ["r1", "r2"], devices: ["d1", "d2"], skipped: [] }),
      }),
    );
    renderApp("/devices/approvals");

    const front = await screen.findByRole("row", { name: /FRONT-DESK-01/ });
    expect(within(front).getByText("R1AA-BBCC")).toBeInTheDocument();
    expect(within(front).getAllByText("Waiting now").length).toBeGreaterThan(0);
    // A device with the same name may be a reinstall.
    expect(within(front).getByRole("link", { name: "FRONT-DESK-01" })).toHaveAttribute("href", "/devices/d9");
    expect(within(screen.getByRole("row", { name: /KIOSK-02/ })).getAllByText("not asking").length).toBeGreaterThan(0);

    // The devices tree has a row for them, with how many wait.
    expect(await screen.findByRole("button", { name: "Waiting for approval, 2 devices waiting" })).toHaveAttribute("aria-current", "page");

    await user.click(screen.getByRole("checkbox", { name: "Select all" }));
    expect(screen.getByText("2 selected")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Approve selected…" }));

    const dialog = await screen.findByRole("dialog", { name: "Approve 2 devices" });
    expect(within(dialog).getByRole("list", { name: "Devices to approve" })).toHaveTextContent("KIOSK-02");
    const approve = within(dialog).getByRole("button", { name: "Approve 2 devices" });
    expect(approve).toBeDisabled();
    await user.selectOptions(within(dialog).getByLabelText(/^Site/), "s2");
    await waitFor(() => expect(within(within(dialog).getByLabelText(/Device group/)).getAllByRole("option")).toHaveLength(2));
    await user.selectOptions(within(dialog).getByLabelText(/Device group/), "g1");
    await user.click(approve);

    await waitFor(() => expect(server.call("POST /enrollment-requests/approve").body).toEqual({ ids: ["r1", "r2"], siteId: "s2", deviceGroupId: "g1" }));
    expect(await screen.findByText("Approved 2 devices into Northwind Traders / Warehouse. They connect within seconds.")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("rejects one device after confirming", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes({ "POST /enrollment-requests/reject": ok({ decided: ["r2"], skipped: [] }) }));
    renderApp("/devices/approvals");

    await user.click(await screen.findByRole("button", { name: "Reject KIOSK-02" }));
    const dialog = await screen.findByRole("dialog", { name: "Reject KIOSK-02" });
    expect(dialog).toHaveTextContent("Its agent stops asking");
    await user.click(within(dialog).getByRole("button", { name: "Reject" }));
    await waitFor(() => expect(server.call("POST /enrollment-requests/reject").body).toEqual({ ids: ["r2"] }));
    expect(await screen.findByText("Rejected 1 device. Its agent stops asking.")).toBeInTheDocument();
  });

  it("lists rejected devices", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes());
    renderApp("/devices/approvals");
    await user.click(await screen.findByRole("tab", { name: "Rejected" }));
    const row = await screen.findByRole("row", { name: /OLD-PC/ });
    expect(within(row).getByText("by Alex Rivera")).toBeInTheDocument();
    expect(server.calls.some((r) => r.path === "/enrollment-requests" && r.query.get("state") === "rejected")).toBe(true);
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("says when none wait", async () => {
    installFakeApi(routes({ "GET /enrollment-requests": ok({ items: [], waiting: 0 }), "GET /enrollment-requests/waiting": ok({ waiting: 0 }) }));
    renderApp("/devices/approvals");
    expect(await screen.findByText("No devices waiting")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "approval token" })).toHaveAttribute("href", "/devices/add?mode=approval");
  });

  it("is only for those who manage enrollment on the whole server", async () => {
    installFakeApi({ ...baseRoutes(ORG_ADMIN) });
    renderApp("/devices/approvals");
    expect(await screen.findByText("Not available to your role")).toBeInTheDocument();
  });

  it("counts waiting devices in the main menu", async () => {
    installFakeApi(routes({ "GET /audit": ok({ items: [] }), "GET /users": ok({ items: [] }) }));
    renderApp("/");
    const devices = await screen.findByRole("link", { name: /^Devices/ });
    await waitFor(() => expect(devices).toHaveTextContent("2 devices waiting for approval"));
  });
});

describe("approval tokens", () => {
  it("creates an approval token and shows the generic install command", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      routes({
        "GET /agent-downloads": ok({ serverUrl: "https://rmm.example.com", items: [] }),
        "GET /enrollment-tokens": ok({ items: [] }),
        "GET /approval-tokens": ok({ items: [approvalToken("at1", "Spring rollout")] }),
        "POST /approval-tokens": (r: FakeRequest) => {
          const input = r.body as ApprovalTokenInput;
          return { status: 201, body: { token: approvalToken("at2", input.name, { uses: 0, waiting: 0 }), secret: SECRET, serverUrl: "https://rmm.example.com" } };
        },
      }),
    );
    renderApp("/devices/add");

    // The list of approval tokens links to the waiting devices.
    const listed = await screen.findByRole("row", { name: /Spring rollout/ });
    expect(within(listed).getByRole("link", { name: "2 devices" })).toHaveAttribute("href", "/devices/approvals");

    await user.click(screen.getByRole("radio", { name: "Wait for approval" }));
    expect(screen.queryByLabelText(/^Site/)).not.toBeInTheDocument();
    await user.type(screen.getByLabelText(/Token name/), "Autumn rollout");
    await user.click(screen.getByRole("button", { name: "Create token" }));

    await waitFor(() => expect(server.call("POST /approval-tokens").body).toEqual({ name: "Autumn rollout", expiresInDays: 7, maxUses: null }));
    expect(await screen.findByText(/Each one waits under/)).toBeInTheDocument();
    expect(screen.getAllByText(new RegExp(SECRET)).length).toBeGreaterThan(0);
    expect(screen.getByText("Wait for approval", { selector: "dd, dd *" })).toBeInTheDocument();
  });

  it("is not offered to organization administrators", async () => {
    installFakeApi({
      ...baseRoutes(ORG_ADMIN),
      "GET /sites": ok({ items: [site("s1", "o1", "Head office")] }),
      "GET /agent-downloads": ok({ serverUrl: "https://rmm.example.com", items: [] }),
      "GET /enrollment-tokens": ok({ items: [] }),
    });
    renderApp("/devices/add");
    expect(await screen.findByLabelText(/^Site/)).toBeInTheDocument();
    expect(screen.queryByRole("radio", { name: "Wait for approval" })).not.toBeInTheDocument();
    expect(screen.queryByText("Approval tokens")).not.toBeInTheDocument();
  });
});
