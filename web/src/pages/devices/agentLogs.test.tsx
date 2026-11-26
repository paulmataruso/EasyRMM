import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { AgentLogPage, AgentLogRecord } from "../../api/types";
import { baseRoutes, installFakeApi, noContent, ok, sessionView } from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { clock, mergeNewestFirst } from "./agentLogsText";

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const SERVER = device("d1", "DB-01", { platform: "linux", agent: AGENT, canUpdateAgent: true, deviceGroupId: "g1", deviceGroupName: "Servers" });

const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "device.edit", "log.view"] });
const READ_ONLY = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });

function rec(id: number, message: string, extra: Partial<AgentLogRecord> = {}): AgentLogRecord {
  return { id, time: "2026-11-23T10:00:00.250Z", receivedAt: "2026-11-23T10:00:01Z", source: "agent", level: "info", message, attrs: {}, ...extra };
}

function page(items: AgentLogRecord[], extra: Partial<AgentLogPage> = {}): AgentLogPage {
  return { items, more: false, verbose: null, retentionDays: 14, online: true, ...extra };
}

function routes(session: ReturnType<typeof sessionView>, logs: AgentLogPage) {
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(SERVER),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/agent-logs": ok(logs),
  } as Parameters<typeof installFakeApi>[0];
}

describe("the Logs tab", () => {
  it("is for those who hold log.view", async () => {
    installFakeApi(routes(READ_ONLY, page([])));
    renderApp("/devices/d1");
    await screen.findByRole("tab", { name: "Overview" });
    expect(screen.queryByRole("tab", { name: "Logs" })).not.toBeInTheDocument();
  });

  it("shows the records newest first, with source, level and details", async () => {
    installFakeApi(
      routes(
        TECH,
        page([
          rec(1, "agent started"),
          rec(2, "scan failed", { source: "easypatch", level: "error", attrs: { job: "7" } }),
        ]),
      ),
    );
    renderApp("/devices/d1?tab=logs");
    const log = await screen.findByRole("log", { name: "Agent log records" });
    expect(within(log).getByText("agent started")).toBeInTheDocument();
    expect(within(log).getByText(/scan failed/)).toBeInTheDocument();
    expect(within(log).getByText(/job="7"/)).toBeInTheDocument();
    expect(within(log).getByText("EasyPatch agent")).toBeInTheDocument();
    expect(within(log).getAllByText(clock("2026-11-23T10:00:00.250Z"), { selector: "time" })).toHaveLength(2);
    expect(screen.getByText(/Kept for 14 days/)).toBeInTheDocument();
  });

  it("filters on the server and says when nothing matches", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(TECH, page([rec(1, "hello")])));
    renderApp("/devices/d1?tab=logs");
    await screen.findByText("hello");
    server.on("GET /devices/:id/agent-logs", ok(page([])));
    await user.selectOptions(screen.getByLabelText("Source"), "meshagent");
    await user.selectOptions(screen.getByLabelText("Level"), "warn");
    await screen.findByText("No records match");
    const last = server.callsTo("GET /devices/:id/agent-logs").at(-1)!;
    expect(last.query.get("source")).toBe("meshagent");
    expect(last.query.get("level")).toBe("warn");
  });

  it("downloads with the filters", async () => {
    const user = userEvent.setup();
    installFakeApi(routes(TECH, page([rec(1, "hello")])));
    const clicked: string[] = [];
    const click = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
      clicked.push(this.getAttribute("href") ?? "");
    };
    try {
      renderApp("/devices/d1?tab=logs");
      await screen.findByText("hello");
      await user.selectOptions(screen.getByLabelText("Level"), "error");
      await user.click(screen.getByRole("button", { name: "Download" }));
      await user.click(await screen.findByRole("menuitem", { name: /JSON lines/ }));
    } finally {
      HTMLAnchorElement.prototype.click = click;
    }
    expect(clicked).toHaveLength(1);
    expect(clicked[0]).toContain("/api/v1/devices/d1/agent-logs/download?");
    expect(clicked[0]).toContain("format=jsonl");
    expect(clicked[0]).toContain("level=error");
  });

  it("turns verbose logging on for the device, or its group, and off again", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes(TECH, page([rec(1, "hello")])),
      "PUT /devices/:id/agent-logs/verbose": ok({ until: "2026-11-23T12:00:00Z" }),
      "PUT /device-groups/:id/agent-logs/verbose": ok({ until: "2026-11-23T14:00:00Z" }),
      "DELETE /device-groups/:id/agent-logs/verbose": noContent,
    });
    renderApp("/devices/d1?tab=logs");
    await screen.findByText("hello");
    await user.click(screen.getByRole("button", { name: "Verbose for…" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByLabelText("For")).toHaveValue("2");
    await user.click(within(dialog).getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(server.call("PUT /devices/:id/agent-logs/verbose").body).toEqual({ hours: 2 }));
    expect(await screen.findByText("Verbose logging is on")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Verbose for…" }));
    const second = await screen.findByRole("dialog");
    await user.selectOptions(within(second).getByLabelText("For"), "4");
    await user.selectOptions(within(second).getByLabelText("On"), "group");
    await user.click(within(second).getByRole("button", { name: "Turn on" }));
    await waitFor(() => expect(server.call("PUT /device-groups/:id/agent-logs/verbose").body).toEqual({ hours: 4 }));
    expect(server.call("PUT /device-groups/:id/agent-logs/verbose").params.id).toBe("g1");
    expect(await screen.findByText(/set on the group Servers/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Turn off" }));
    await waitFor(() => expect(server.callsTo("DELETE /device-groups/:id/agent-logs/verbose")).toHaveLength(1));
    await waitFor(() => expect(screen.queryByText("Verbose logging is on")).not.toBeInTheDocument());
  });

  it("offers no verbose button without device.edit", async () => {
    installFakeApi(routes(TECH, page([rec(1, "hello")])));
    const view = { ...SERVER, canUpdateAgent: false };
    installFakeApi({ ...routes(TECH, page([rec(1, "hello")])), "GET /devices/:id": ok(view) });
    renderApp("/devices/d1?tab=logs");
    await screen.findByText("hello");
    expect(screen.queryByRole("button", { name: "Verbose for…" })).not.toBeInTheDocument();
  });
});

describe("the live tail", () => {
  beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
  afterEach(() => vi.useRealTimers());

  it("asks for what is newer every 2 seconds, telling the server someone watches, and stops when paused", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    const server = installFakeApi(routes(TECH, page([rec(5, "first")])));
    renderApp("/devices/d1?tab=logs");
    await screen.findByText("first");
    expect(server.callsTo("GET /devices/:id/agent-logs")[0]!.query.get("follow")).toBe("true");
    server.on("GET /devices/:id/agent-logs", (r) => ok(r.query.get("after") === "5" ? page([rec(6, "second")]) : page([])));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2100);
    });
    await screen.findByText("second");
    const tail = server.callsTo("GET /devices/:id/agent-logs").at(-1)!;
    expect(tail.query.get("after")).toBe("5");
    expect(tail.query.get("follow")).toBe("true");
    await user.click(screen.getByRole("button", { name: "Pause live tail" }));
    const n = server.callsTo("GET /devices/:id/agent-logs").length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(6000);
    });
    expect(server.callsTo("GET /devices/:id/agent-logs")).toHaveLength(n);
    expect(screen.getByText(/Paused/)).toBeInTheDocument();
  });
});

describe("the merged order of the Logs tab", () => {
  it("is by logged time, newest first, across sources, with the later-stored record first among equal times", () => {
    const at = (s: number) => `2026-11-23T10:00:0${s}.000Z`;
    // The easypatch records arrived in a late batch: higher ids, older times.
    const a = [rec(3, "agent 5s", { time: at(5) }), rec(1, "agent 1s", { time: at(1) })];
    const b = [rec(5, "mesh 3s", { time: at(3), source: "meshagent" }), rec(4, "patch 4s", { time: at(4), source: "easypatch" }), rec(2, "patch 1s", { time: at(1), source: "easypatch" })];
    expect(mergeNewestFirst(a, b).map((r) => r.message)).toEqual(["agent 5s", "patch 4s", "mesh 3s", "patch 1s", "agent 1s"]);
    // A record that is shown already is kept once.
    expect(mergeNewestFirst(a, a)).toHaveLength(2);
  });

  it("shows what the server sent, newest at the top", async () => {
    installFakeApi(
      routes(TECH, page([rec(9, "newest", { time: "2026-11-23T10:00:09.000Z" }), rec(2, "oldest", { time: "2026-11-23T10:00:01.000Z", source: "meshagent" })])),
    );
    renderApp("/devices/d1?tab=logs");
    const log = await screen.findByRole("log", { name: "Agent log records" });
    const text = log.textContent ?? "";
    expect(text.indexOf("newest")).toBeLessThan(text.indexOf("oldest"));
  });
});
