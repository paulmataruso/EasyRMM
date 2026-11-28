import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AgentSettingEntry, AgentSettingsDocument, AgentSettingsListing, AgentSettingsProblems } from "../../api/types";
import { baseRoutes, installFakeApi, noContent, ok, sessionView } from "../../test/fakeApi";
import { device, history, inventory, metrics, org } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { sourceText } from "./AgentSettingsPanel";
import { documentLine } from "./DeviceSettingsTab";

const AGENT = { version: "1.5.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const SERVER = device("d1", "DB-01", { platform: "linux", agent: AGENT });

const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "device.configure"] });
const READ_ONLY = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });

function entry(extra: Partial<AgentSettingEntry> = {}): AgentSettingEntry {
  return {
    key: "agent.heartbeat_seconds",
    title: "Heartbeat interval",
    description: "How often the agent checks in.",
    type: "integer",
    min: 30,
    max: 300,
    default: 60,
    set: null,
    inherited: { value: 60, from: null },
    enforcedBy: null,
    effective: { value: 60, from: null, raised: false },
    canWrite: true,
    canEnforce: false,
    permission: "device.configure",
    ...extra,
  };
}

const DOC: AgentSettingsDocument = { state: "applied", version: 4, appliedVersion: 4, issuedAt: null, appliedAt: new Date(Date.now() - 5 * 60_000).toISOString(), notAppliedHeartbeats: 0, problems: {} };

function listing(scope: AgentSettingsListing["scope"], items: AgentSettingEntry[], document?: AgentSettingsDocument): AgentSettingsListing {
  return { scope, limits: { minHeartbeatSeconds: 30 }, items, ...(document ? { document } : {}) };
}

function routes(session: ReturnType<typeof sessionView>, l: AgentSettingsListing) {
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(SERVER),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/agent-settings": ok(l),
  } as Parameters<typeof installFakeApi>[0];
}

describe("sourceText", () => {
  it("names where a value comes from, from the page's own point of view", () => {
    expect(sourceText(null, "device")).toBe("Default");
    expect(sourceText({ scope: "device" }, "device")).toBe("Set for this device");
    expect(sourceText({ scope: "site", name: "HQ" }, "device")).toBe("Inherited from site HQ");
    expect(sourceText({ scope: "organization", name: "Acme" }, "site")).toBe("Inherited from organization Acme");
    expect(sourceText({ scope: "platform" }, "device")).toBe("Set by your MSP");
    expect(sourceText({ scope: "site", name: "HQ" }, "site")).toBe("Set for this site");
  });
});

describe("documentLine", () => {
  it("words each state of the document", () => {
    expect(documentLine(DOC)).toMatchObject({ tone: "ok", text: expect.stringMatching(/^Applied .*5 minutes ago.* \(version 4\)$/) });
    expect(documentLine({ ...DOC, state: "waiting" })).toEqual({ tone: "warn", text: "Waiting for the device: it is offline" });
    expect(documentLine({ ...DOC, state: "not_applied", notAppliedHeartbeats: 3 })).toEqual({ tone: "danger", text: "Not applied (3 heartbeats since it was issued)" });
    expect(documentLine({ ...DOC, state: "unsupported" })).toEqual({ tone: "neutral", text: "This agent's version does not take settings" });
  });
});

describe("the device's Settings tab", () => {
  it("is for devices with the agent, and shows the document state and the value", async () => {
    installFakeApi(routes(TECH, listing("device", [entry({ effective: { value: 120, from: { scope: "site", name: "HQ" }, raised: false } })], DOC)));
    renderApp("/devices/d1?tab=settings");
    expect(await screen.findByText(/Applied .*5 minutes ago.*version 4/)).toBeInTheDocument();
    expect(screen.getByText("Heartbeat interval")).toBeInTheDocument();
    expect(screen.getByText("Inherited from site HQ")).toBeInTheDocument();
    expect(screen.getByText("120 seconds")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Use inherited" })).not.toBeInTheDocument();
  });

  it("sets a value, and clears it with Use inherited", async () => {
    const user = userEvent.setup();
    const sent: unknown[] = [];
    let cleared = 0;
    installFakeApi({
      ...routes(TECH, listing("device", [entry({ set: { value: 90, enforced: false, setBy: "alex", updatedAt: "2026-11-27T10:00:00Z", inEffect: true } })], DOC)),
      "PUT /devices/:id/agent-settings/:key": (req: { body?: unknown }) => {
        sent.push(req.body);
        return ok(entry());
      },
      "DELETE /devices/:id/agent-settings/:key": () => {
        cleared++;
        return noContent;
      },
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/devices/d1?tab=settings");
    const input = await screen.findByLabelText("Seconds");
    expect(input).toHaveValue(90);
    await user.clear(input);
    await user.type(input, "10");
    expect(screen.getByText("Use a whole number from 30 to 300.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
    await user.clear(input);
    await user.type(input, "150");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(sent).toEqual([{ value: 150, enforced: false }]));
    await user.click(screen.getByRole("button", { name: "Use inherited" }));
    await waitFor(() => expect(cleared).toBe(1));
  });

  it("is read-only without device.configure", async () => {
    installFakeApi(routes(READ_ONLY, listing("device", [entry()], { ...DOC, state: "not_applied", notAppliedHeartbeats: 3 })));
    renderApp("/devices/d1?tab=settings");
    expect(await screen.findByText("Not applied (3 heartbeats since it was issued)")).toBeInTheDocument();
    expect(screen.queryByLabelText("Seconds")).not.toBeInTheDocument();
    expect(screen.getByText(/You can see it, not change it/)).toBeInTheDocument();
  });

  it("explains an agent that does not take settings, with the update link", async () => {
    installFakeApi(routes(TECH, listing("device", [entry({ canWrite: false })], { ...DOC, state: "unsupported" })));
    renderApp("/devices/d1?tab=settings");
    expect(await screen.findByText("This agent's version does not take settings")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Update the agent" })).toHaveAttribute("href", "/settings?tab=agent-updates");
  });

  it("shows when a higher scope enforces the value", async () => {
    installFakeApi(
      routes(TECH, listing("device", [entry({ canWrite: false, enforcedBy: { scope: "organization", name: "Acme" }, effective: { value: 60, from: { scope: "organization", name: "Acme" }, raised: false } })], DOC)),
    );
    renderApp("/devices/d1?tab=settings");
    expect(await screen.findByText(/enforces this value for everything below it/)).toBeInTheDocument();
  });
});

describe("the organization's Agent settings tab", () => {
  it("offers Enforce for everything below and sends it", async () => {
    const user = userEvent.setup();
    const sent: unknown[] = [];
    installFakeApi({
      ...baseRoutes(sessionView({ permissions: ["org.view", "site.view", "device.view", "device.configure"] })),
      "GET /organizations/:id": ok(org("o1", "Northwind Traders")),
      "GET /organizations/:id/sites": ok({ items: [] }),
      "GET /organizations/:id/agent-settings": ok(listing("organization", [entry({ canEnforce: true })])),
      "PUT /organizations/:id/agent-settings/:key": (req: { body?: unknown }) => {
        sent.push(req.body);
        return ok(entry());
      },
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/organizations/o1?tab=agent-settings");
    const input = await screen.findByLabelText("Seconds");
    await user.clear(input);
    await user.type(input, "120");
    await user.click(screen.getByLabelText("Enforce for everything below"));
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(sent).toEqual([{ value: 120, enforced: true }]));
  });
});

describe("Settings > Agent settings", () => {
  it("lists the devices that do not take settings and those not applied", async () => {
    const problems: AgentSettingsProblems = {
      unsupported: [{ id: "d7", name: "OLD-01", organizationId: "o1", organizationName: "Acme", agentVersion: "1.0.0", notAppliedHeartbeats: 0 }],
      notApplied: [{ id: "d8", name: "LATE-01", organizationId: "o1", organizationName: "Acme", agentVersion: "1.5.0", notAppliedHeartbeats: 4 }],
    };
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /settings/agent-settings": ok(listing("platform", [entry({ canEnforce: true })])),
      "GET /settings/agent-settings/problems": ok(problems),
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/settings?tab=agent-settings");
    expect(await screen.findByRole("heading", { name: "Agent settings", level: 1 })).toBeInTheDocument();
    const notApplied = (await screen.findByRole("heading", { name: "Not applied (1)" })).closest("section") as HTMLElement;
    expect(within(notApplied).getByRole("link", { name: "LATE-01" })).toHaveAttribute("href", "/devices/d8?tab=settings");
    const unsupported = screen.getByRole("heading", { name: "Agent does not take settings (1)" }).closest("section") as HTMLElement;
    expect(within(unsupported).getByText("OLD-01")).toBeInTheDocument();
    expect(screen.getByLabelText(/Shortest heartbeat interval/)).toHaveValue(30);
  });
});

describe("the devices list", () => {
  it("filters to devices whose settings are not applied", async () => {
    const user = userEvent.setup();
    const asked: string[] = [];
    installFakeApi({
      ...baseRoutes(sessionView()),
      "GET /remote-access/status": ok({ address: "https://mesh.rmm.example.com", connected: true, lastSyncAt: "2026-11-01T09:59:00Z", devices: 0, devicesOnline: 0 }),
      "GET /devices": (req: { query: URLSearchParams }) => {
        asked.push(req.query.get("settings") ?? "");
        return ok({ items: [] });
      },
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/devices");
    await user.selectOptions(await screen.findByLabelText("Agent settings"), "not_applied");
    await waitFor(() => expect(asked).toContain("not_applied"));
  });
});
