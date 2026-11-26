import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import { baseRoutes, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { renderApp } from "../../test/render";
import { REMOVE_MESHAGENT_SCRIPT } from "./leftBehind";

const ITEM = { id: "r1", name: "PC-WIN-01", organizationId: "o1", siteId: "s1", removedAt: "2026-11-20T10:00:00Z" };

describe("removed devices that may have left MeshAgent behind", () => {
  it("says so in plain words and offers the script", async () => {
    const session = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "device.retire"] });
    installFakeApi({ ...baseRoutes(session), "GET /removed-devices/left-behind": ok({ items: [ITEM] }) });
    renderApp("/devices");
    expect(await screen.findByText(/may still be installed on removed devices/i)).toBeInTheDocument();
    expect(screen.getByText(/PC-WIN-01, removed/)).toBeInTheDocument();
    expect(screen.getByText(/does not ask MeshCentral to remove it/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /copy the removal script/i })).toBeInTheDocument();
    expect(screen.getByLabelText("Removal script").textContent).toBe(REMOVE_MESHAGENT_SCRIPT);
  });

  it("shows nothing when none is left, and does not ask without the permission", async () => {
    const session = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });
    const server = installFakeApi({ ...baseRoutes(session) });
    renderApp("/devices");
    await screen.findByText(/Computers in the organizations/);
    expect(screen.queryByText(/may still be installed/i)).not.toBeInTheDocument();
    expect(server.callsTo("GET /removed-devices/left-behind")).toHaveLength(0);
  });

  it("removes only our own service, folder and keys, by exact name", () => {
    const s = REMOVE_MESHAGENT_SCRIPT;
    expect(s).toContain("$name = 'EasyRMMMeshAgent'");
    expect(s).toContain("EasyRMM\\MeshAgent");
    expect(s).toContain("-ieq $exe");
    for (const stock of ["Mesh Agent", "meshagentDiagnostic", "-like", "-match", "taskkill"]) expect(s).not.toContain(stock);
  });

  it("is the script of the operations guide", () => {
    const doc = readFileSync(resolve(process.cwd(), "../docs/operations/removing-our-meshagent.md"), "utf8");
    const block = /```powershell\n([\s\S]*?)```/.exec(doc)?.[1];
    expect(block).toBe(REMOVE_MESHAGENT_SCRIPT);
  });
});
