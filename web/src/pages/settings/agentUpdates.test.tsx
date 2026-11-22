import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AgentBuild, AgentUpdate, AgentUpdateSettings, DeviceAgent, SignedAgentBuild } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";

const BUILDS: AgentBuild[] = [
  { os: "linux", arch: "amd64", file: "easyrmm-agent-linux-amd64", size: 1, sha256: "aa", version: "v1.5.0" },
  { os: "windows", arch: "amd64", file: "easyrmm-agent-windows-amd64.exe", size: 1, sha256: "bb", version: "v1.5.0" },
];

const SETTINGS: AgentUpdateSettings = {
  mode: "automatic",
  maxConcurrent: 20,
  signedOnly: false,
  stored: false,
  updatedAt: null,
  version: "v1.5.0",
  builds: BUILDS,
  release: BUILDS,
  signed: [],
  withheld: [],
  fleet: { current: 40, updating: 3, queued: 2, available: 5, failed: 1, unsupported: 4 },
};

const main = () => within(screen.getByRole("main"));
/** The card that sums up the fleet. */
const agentsCard = () => within(main().getByRole("heading", { name: "Agents" }).closest("section") as HTMLElement);

describe("agent update settings", () => {
  it("shows the build and the fleet, and saves the rollout", async () => {
    const user = userEvent.setup();
    const saved: AgentUpdateSettings = { ...SETTINGS, mode: "manual", maxConcurrent: 5, stored: true, updatedAt: new Date().toISOString(), updatedBy: "alex@example.com" };
    let current = SETTINGS;
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/agent-updates": () => ok(current),
      "PUT /settings/agent-updates": () => {
        current = saved;
        return ok(saved);
      },
      "POST /settings/agent-updates/request-all": ok({ requested: 6 }),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/settings?tab=agent-updates");

    expect(await screen.findByRole("heading", { name: "Agent updates", level: 1 })).toBeInTheDocument();
    expect(await main().findByRole("heading", { name: "Agents" })).toBeInTheDocument();
    expect(agentsCard().getByText("v1.5.0")).toBeInTheDocument();
    // Windows first.
    expect(agentsCard().getByText("Windows x86-64").compareDocumentPosition(agentsCard().getByText("Linux x86-64")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    for (const [label, n] of [["Up to date", "40"], ["Updating", "3"], ["Waiting to update", "2"], ["Update available", "5"], ["Update failed", "1"], ["Cannot update itself", "4"]]) {
      const term = main().getByText(label!);
      expect(term.closest("div")).toHaveTextContent(n!);
    }
    expect(main().getByText(/predate self-update/)).toBeInTheDocument();
    expect(main().getByText("The default setting applies.")).toBeInTheDocument();
    expect(main().getByLabelText(/Automatically/)).toBeChecked();

    // Asking every outdated agent: available and failed ones.
    await user.click(main().getByRole("button", { name: "Update 6 outdated agents" }));
    await waitFor(() => expect(server.callsTo("POST /settings/agent-updates/request-all")).toHaveLength(1));
    expect(await screen.findByText("Asked 6 agents to update.")).toBeInTheDocument();

    await user.click(main().getByLabelText(/When asked/));
    const max = main().getByLabelText(/^Devices at once/);
    await user.clear(max);
    await user.type(max, "5x");
    await user.click(main().getByRole("button", { name: "Save" }));
    await waitFor(() => expect(server.callsTo("PUT /settings/agent-updates")).toHaveLength(1));
    expect(server.callsTo("PUT /settings/agent-updates")[0]!.body).toEqual({ mode: "manual", maxConcurrent: 5, signedOnly: false });
    expect(await main().findByText(/by alex@example.com/)).toBeInTheDocument();
  });

  it("says when the server has no builds, and shows validation errors", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/agent-updates": ok({ ...SETTINGS, version: "", builds: [], release: [], fleet: { none: 3 } }),
      "PUT /settings/agent-updates": fail(422, "validation_failed", "Check the highlighted fields.", { maxConcurrent: "Allow between 1 and 1000 devices at once." }),
    });
    renderApp("/settings?tab=agent-updates");
    expect(await screen.findByText("No agent builds")).toBeInTheDocument();
    expect(main().getByText("Version unknown")).toBeInTheDocument();
    expect(main().getByText("No build for the platform").closest("div")).toHaveTextContent("3");
    expect(main().queryByRole("button", { name: /outdated/ })).not.toBeInTheDocument();
    await user.clear(main().getByLabelText(/^Devices at once/));
    await user.click(main().getByRole("button", { name: "Save" }));
    expect(await main().findByText("Allow between 1 and 1000 devices at once.")).toBeInTheDocument();
  });

  it("is not offered without settings.manage", async () => {
    installFakeApi({ ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "user.view"] })), "GET /users": ok({ items: [] }) });
    renderApp("/settings?tab=agent-updates");
    expect(await screen.findByRole("heading", { name: "Users", level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Agent updates" })).not.toBeInTheDocument();
  });
});

const WINDOWS: AgentBuild[] = [
  { os: "windows", arch: "amd64", file: "easyrmm-agent-windows-amd64.exe", size: 1, sha256: "bb", version: "v1.5.0" },
  { os: "windows", arch: "arm64", file: "easyrmm-agent-windows-arm64.exe", size: 1, sha256: "dd", version: "v1.5.0" },
];

const SIGNER = {
  subject: "CN=Contoso IT\\, Ltd,O=Contoso,C=US",
  issuer: "CN=Example Code Signing CA,O=Example",
  thumbprint: "a9b8c7d6e5f4a3b2c1d0a9b8c7d6e5f4a3b2c1d0",
  notBefore: "2026-01-01T00:00:00Z",
  notAfter: "2099-01-01T00:00:00Z",
  timestamped: false,
};

const signedBuild = (extra: Partial<SignedAgentBuild> = {}): SignedAgentBuild => ({
  id: "s1",
  arch: "amd64",
  version: "v1.5.0",
  sha256: "ee",
  releaseSha256: "bb",
  size: 2,
  signer: SIGNER,
  uploadedAt: "2026-11-20T10:00:00Z",
  uploadedBy: "alex@example.com",
  served: true,
  ...extra,
});

/** Settings with Windows builds: amd64 handed out signed, arm64 as released. */
const SIGNED: AgentUpdateSettings = {
  ...SETTINGS,
  builds: [{ ...WINDOWS[0]!, sha256: "ee", signed: SIGNER }, WINDOWS[1]!],
  release: WINDOWS,
  signed: [signedBuild()],
};

const signedCard = () => within(main().getByRole("heading", { name: "Signed Windows builds" }).closest("section") as HTMLElement);
const row = (name: string) => within(signedCard().getByRole("table")).getByText(name).closest("tr") as HTMLElement;

describe("signed Windows builds", () => {
  it("shows what is handed out, offers the builds to sign, and uploads a signed one", async () => {
    const user = userEvent.setup();
    let current: AgentUpdateSettings = { ...SETTINGS, builds: WINDOWS, release: WINDOWS };
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/agent-updates": () => ok(current),
      "POST /settings/agent-updates/signed": () => {
        current = SIGNED;
        return { status: 201, body: signedBuild() };
      },
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/settings?tab=agent-updates");
    await screen.findByRole("main");
    expect(await main().findByRole("heading", { name: "Signed Windows builds" })).toBeInTheDocument();
    expect(within(row("Windows x86-64")).getByText("The release's build, unsigned")).toBeInTheDocument();
    const download = within(row("Windows ARM 64-bit")).getByRole("link", { name: "Download to sign" });
    expect(download).toHaveAttribute("href", "/api/v1/settings/agent-updates/release/easyrmm-agent-windows-arm64.exe");
    expect(signedCard().queryByText("Uploaded")).not.toBeInTheDocument();

    const file = new File([new Uint8Array([0x4d, 0x5a])], "easyrmm-agent-windows-amd64.exe");
    await user.upload(screen.getByTestId("signed-build-file"), file);
    await waitFor(() => expect(server.callsTo("POST /settings/agent-updates/signed")).toHaveLength(1));
    const call = server.callsTo("POST /settings/agent-updates/signed")[0]!;
    expect(call.body).toBe(file);
    expect(call.headers["content-type"]).toBe("application/octet-stream");
    expect(await screen.findByText("Uploaded. Windows x86-64 agents update to the signed build.")).toBeInTheDocument();

    // Handed out signed, by whom, and what the signature lacks.
    const amd64 = await waitFor(() => row("Windows x86-64"));
    await waitFor(() => expect(within(amd64).getByText("Signed")).toBeInTheDocument());
    expect(within(amd64).getByText("By Contoso IT, Ltd")).toBeInTheDocument();
    expect(signedCard().getByText("Signed by Contoso IT, Ltd, issued by Example Code Signing CA")).toBeInTheDocument();
    expect(signedCard().getByText(SIGNER.thumbprint)).toBeInTheDocument();
    expect(signedCard().getByText(/Not timestamped: Windows stops trusting this signature when the certificate expires/)).toBeInTheDocument();
    expect(within(signedCard().getByRole("list")).getByText("Handed out")).toBeInTheDocument();
  });

  it("says why an upload was refused", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/agent-updates": ok({ ...SETTINGS, builds: WINDOWS, release: WINDOWS }),
      "POST /settings/agent-updates/signed": fail(422, "validation_failed", "Some fields need attention.", { file: "This program has no Authenticode signature." }),
    });
    renderApp("/settings?tab=agent-updates");
    await screen.findByRole("main");
    await main().findByRole("heading", { name: "Signed Windows builds" });
    await user.upload(screen.getByTestId("signed-build-file"), new File(["x"], "agent.exe"));
    expect(await signedCard().findByText("This program has no Authenticode signature.")).toBeInTheDocument();
  });

  it("hands out signed builds only, shows what waits, and removes a signed build", async () => {
    const user = userEvent.setup();
    const older = signedBuild({ version: "v1.4.0", releaseSha256: "b0", signer: { ...SIGNER, timestamped: true } });
    const expired = signedBuild({ id: "s2", arch: "arm64", version: "v1.3.0", served: false, signer: { ...SIGNER, notAfter: "2020-01-01T00:00:00Z" } });
    const waiting: AgentUpdateSettings = {
      ...SETTINGS,
      signedOnly: true,
      builds: [{ ...WINDOWS[0]!, sha256: "ee", version: "v1.4.0", signed: SIGNER }],
      release: WINDOWS,
      signed: [older, expired],
      withheld: ["arm64"],
      fleet: { current: 3, waiting: 2 },
    };
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/agent-updates": ok(waiting),
      "PUT /settings/agent-updates": (req) => ok({ ...waiting, ...(req.body as object) }),
      "DELETE /settings/agent-updates/signed/:id": () => ({ status: 204, body: undefined }),
      "GET /audit": ok({ items: [] }),
    });
    renderApp("/settings?tab=agent-updates");
    await screen.findByRole("main");
    await main().findByRole("heading", { name: "Signed Windows builds" });
    expect(main().getByLabelText(/Hand out signed Windows builds only/)).toBeChecked();
    expect(within(row("Windows x86-64")).getByText("Signed v1.4.0")).toBeInTheDocument();
    expect(within(row("Windows x86-64")).getByText(/waiting for a signed build of v1.5.0/)).toBeInTheDocument();
    expect(within(row("Windows ARM 64-bit")).getByText("None")).toBeInTheDocument();
    expect(agentsCard().getByText("Waiting for a signed build").closest("div")).toHaveTextContent("2");
    expect(signedCard().getByText(/Timestamped: stays valid after the certificate expires/)).toBeInTheDocument();
    expect(signedCard().getByText(/the certificate expired on .*: Windows no longer trusts this signature/)).toBeInTheDocument();

    // Turned off again.
    await user.click(main().getByLabelText(/Hand out signed Windows builds only/));
    await user.click(main().getByRole("button", { name: "Save" }));
    await waitFor(() => expect(server.callsTo("PUT /settings/agent-updates")[0]?.body).toEqual({ mode: "automatic", maxConcurrent: 20, signedOnly: false }));

    // The expired build goes.
    const items = signedCard().getAllByRole("listitem");
    await user.click(within(items[1]!).getByRole("button", { name: "Remove" }));
    const dialog = screen.getByRole("dialog", { name: "Remove the signed ARM 64-bit build of v1.3.0?" });
    expect(within(dialog).getByText("It is not handed out now; nothing changes on Windows computers.")).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(server.callsTo("DELETE /settings/agent-updates/signed/:id")[0]?.params.id).toBe("s2"));
    expect(await screen.findByText("Removed the signed build.")).toBeInTheDocument();
  });

  it("is not shown without Windows builds", async () => {
    const linux = [BUILDS[0]!];
    installFakeApi({ ...baseRoutes(sessionView()), "GET /settings/agent-updates": ok({ ...SETTINGS, builds: linux, release: linux }) });
    renderApp("/settings?tab=agent-updates");
    await screen.findByRole("main");
    await main().findByRole("heading", { name: "Agents" });
    expect(main().queryByRole("heading", { name: "Signed Windows builds" })).not.toBeInTheDocument();
    expect(main().queryByLabelText(/Hand out signed Windows builds only/)).not.toBeInTheDocument();
  });
});

const agent = (update: AgentUpdate | null): DeviceAgent => ({
  version: "v1.4.0",
  arch: "amd64",
  sha256: update?.status === "unsupported" ? "" : "cc",
  online: true,
  lastSeenAt: "2026-11-01T10:00:00Z",
  enrolledAt: "2026-10-01T09:00:00Z",
  update,
  accepts: null,
  powerShell7: null,
});

function deviceRoutes(update: AgentUpdate | null, canUpdateAgent = true, extra: Record<string, unknown> = {}) {
  return {
    ...baseRoutes(sessionView()),
    "GET /devices/:id": ok(device("d1", "DB-01", { platform: "linux", agent: agent(update), canUpdateAgent })),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /audit": ok({ items: [] }),
    ...extra,
  } as Parameters<typeof installFakeApi>[0];
}

const details = async () => within((await screen.findByRole("heading", { name: "Details" })).closest("section") as HTMLElement);

describe("a device's agent update", () => {
  it("offers an available update and asks for it", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(
      deviceRoutes({ status: "available", version: "v1.5.0", attempts: 0, error: "", requested: false }, true, {
        "POST /devices/:id/agent-update": ok(device("d1", "DB-01", { agent: agent({ status: "queued", version: "v1.5.0", attempts: 0, error: "", requested: true }) })),
      }),
    );
    renderApp("/devices/d1");
    const d = await details();
    expect(await d.findByText("Update available")).toBeInTheDocument();
    expect(d.getByText("The server ships v1.5.0.")).toBeInTheDocument();
    await user.click(d.getByRole("button", { name: "Update agent" }));
    await waitFor(() => expect(server.callsTo("POST /devices/:id/agent-update")).toHaveLength(1));
    expect(await screen.findByText("DB-01 updates its agent within a few minutes.")).toBeInTheDocument();
  });

  it("shows a failed update and lets it be tried again", async () => {
    installFakeApi(deviceRoutes({ status: "failed", version: "v1.5.0", attempts: 3, error: "the new build does not run: exec format error", requested: false }));
    renderApp("/devices/d1");
    const d = await details();
    expect(await d.findByText("Update failed")).toBeInTheDocument();
    expect(d.getByText(/Failed 3 times\. the new build does not run/)).toBeInTheDocument();
    expect(d.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("explains an agent that cannot update itself, and offers nothing without device.edit", async () => {
    installFakeApi(deviceRoutes({ status: "unsupported", version: "v1.5.0", attempts: 0, error: "", requested: false }, false));
    renderApp("/devices/d1");
    const d = await details();
    expect(await d.findByText("Cannot update itself")).toBeInTheDocument();
    expect(d.getByText(/Run the install command on the device once more/)).toBeInTheDocument();
    expect(d.queryByRole("button", { name: /Update agent|Try again/ })).not.toBeInTheDocument();
  });

  it("says when the agent waits for a signed build", async () => {
    installFakeApi(deviceRoutes({ status: "waiting", version: "", attempts: 0, error: "", requested: false, waitingFor: "v1.5.0" }));
    renderApp("/devices/d1");
    const d = await details();
    expect(await d.findByText("Waiting for a signed build")).toBeInTheDocument();
    expect(d.getByText("Only signed Windows builds are handed out, and v1.5.0 is not signed yet: none is handed out for this device.")).toBeInTheDocument();
    expect(d.queryByRole("button", { name: /Update agent/ })).not.toBeInTheDocument();
  });

  it("says nothing when the agent is current or the server has no build", async () => {
    installFakeApi(deviceRoutes({ status: "current", version: "v1.5.0", attempts: 0, error: "", requested: false }));
    const { unmount } = renderApp("/devices/d1");
    const d = await details();
    expect(await d.findByText("v1.4.0")).toBeInTheDocument();
    expect(d.queryByText(/Up to date|Update available/)).not.toBeInTheDocument();
    unmount();
  });
});
