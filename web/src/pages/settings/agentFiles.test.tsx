import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AgentFiles } from "../../api/types";
import { baseRoutes, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { renderApp } from "../../test/render";

const LIST: AgentFiles = {
  canRefresh: true,
  entries: [
    { id: "1", source: "server", name: "easyrmm-agent-windows-amd64.exe", platform: "windows", arch: "amd64", version: "v1.5.0", size: 8_388_608, md5: "b".repeat(32), sha256: "a".repeat(64), signer: "CN=Acme Code Signing", computedAt: "2026-11-26T10:00:00Z", stale: false },
    { id: "2", source: "meshcentral", name: "meshagent-windows-amd64.exe", platform: "windows", arch: "amd64", version: "", size: 4_000_000, md5: "c".repeat(32), sha256: "d".repeat(64), computedAt: "2026-11-26T09:00:00Z", stale: true, staleReason: "MeshCentral could not be read" },
  ],
};

const main = () => within(screen.getByRole("main"));

describe("Settings, Agent files", () => {
  it("lists every file with both hashes and its source, marks what is stale, and refreshes for those who may", async () => {
    const user = userEvent.setup();
    let list = LIST;
    const server = installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/agent-files": () => ok(list),
      "POST /settings/agent-files/refresh": () => {
        list = { ...LIST, entries: LIST.entries.map((e) => ({ ...e, stale: false })) };
        return ok(list);
      },
    });
    renderApp("/settings?tab=agent-files");
    expect(await screen.findByRole("heading", { name: "Agent files", level: 1 })).toBeInTheDocument();
    expect(await main().findByText("easyrmm-agent-windows-amd64.exe")).toBeInTheDocument();
    expect(main().getByText("Signed by CN=Acme Code Signing")).toBeInTheDocument();
    expect(main().getByText("Served by this server")).toBeInTheDocument();
    expect(main().getByText("MeshCentral")).toBeInTheDocument();
    // Hashes are shortened on screen and whole in their title, for copying.
    expect(main().getByTitle("a".repeat(64))).toHaveTextContent("aaaaaaaaaaaa…");
    expect(main().getByTitle("b".repeat(32))).toBeInTheDocument();
    expect(main().getAllByRole("button", { name: "Copy" })).toHaveLength(4);
    expect(main().getByText("Some values are out of date")).toBeInTheDocument();
    expect(main().getByText("Stale")).toBeInTheDocument();

    await user.click(main().getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(server.callsTo("POST /settings/agent-files/refresh")).toHaveLength(1));
    await waitFor(() => expect(main().queryByText("Some values are out of date")).not.toBeInTheDocument());
  });

  it("is open to anyone with org.view, and has no Refresh for those who cannot manage settings", async () => {
    installFakeApi({
      ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] })),
      "GET /settings/agent-files": ok({ ...LIST, canRefresh: false }),
    });
    renderApp("/settings?tab=agent-files");
    expect(await screen.findByRole("heading", { name: "Agent files", level: 1 })).toBeInTheDocument();
    expect(await main().findByText("easyrmm-agent-windows-amd64.exe")).toBeInTheDocument();
    expect(main().queryByRole("button", { name: "Refresh" })).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Agent files" })).toBeInTheDocument();
  });

  it("is not offered to someone without org.view", async () => {
    installFakeApi({ ...baseRoutes(sessionView({ isSuperAdmin: false, permissions: ["user.view"] })), "GET /users": ok({ items: [] }) });
    renderApp("/settings");
    expect(await screen.findByRole("heading", { name: "Users", level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Agent files" })).not.toBeInTheDocument();
  });
});
