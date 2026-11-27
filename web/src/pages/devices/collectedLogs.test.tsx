import { describe, expect, it } from "vitest";
import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { CollectedLogEvent, CollectedLogPage, CollectedLogTimeline } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { collectedSourceName, MAX_BARS, timelineBars } from "./collectedLogsText";

const AGENT = { version: "1.4.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-01T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const SERVER = device("d1", "DB-01", { platform: "linux", agent: AGENT, canUpdateAgent: true });

const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "device.edit", "log.view"] });
const READ_ONLY = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view"] });

function event(message: string, extra: Partial<CollectedLogEvent> = {}): CollectedLogEvent {
  return { time: "2026-11-27T10:00:00Z", source: "linux.journal", level: "info", message, ...extra };
}

function page(items: CollectedLogEvent[], extra: Partial<CollectedLogPage> = {}): CollectedLogPage {
  return { items, more: false, truncated: false, canSeeSensitive: false, sources: ["linux.audit", "linux.journal"], ...extra };
}

const TIMELINE: CollectedLogTimeline = {
  since: "2026-11-27T08:00:00Z",
  until: "2026-11-27T11:00:00Z",
  buckets: [
    { hour: "2026-11-27T09:00:00Z", source: "linux.journal", level: "info", events: 8, bytes: 800 },
    { hour: "2026-11-27T09:00:00Z", source: "linux.auth", level: "warn", events: 2, bytes: 200 },
  ],
};

function routes(session: ReturnType<typeof sessionView>, logs: CollectedLogPage) {
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(SERVER),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "GET /devices/:id/collected-logs": ok(logs),
    "GET /devices/:id/collected-logs/timeline": ok(TIMELINE),
  } as Parameters<typeof installFakeApi>[0];
}

describe("the Collected logs tab", () => {
  it("is for those who hold log.view", async () => {
    installFakeApi(routes(READ_ONLY, page([])));
    renderApp("/devices/d1");
    await screen.findByRole("tab", { name: "Overview" });
    expect(screen.queryByRole("tab", { name: "Collected logs" })).not.toBeInTheDocument();
  });

  it("shows the events and the timeline, and opens an event's details", async () => {
    const user = userEvent.setup();
    installFakeApi(routes(TECH, page([event("nginx started", { fields: { unit: "nginx.service" } }), event("disk failure", { level: "error", source: "linux.audit" })])));
    renderApp("/devices/d1?tab=collected");
    const list = await screen.findByRole("list", { name: "Collected log events" });
    expect(within(list).getByText("nginx started")).toBeInTheDocument();
    expect(within(list).getByText("error")).toBeInTheDocument();
    expect(within(list).getByText("Linux audit")).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Events by time" })).toBeInTheDocument();
    await user.click(within(list).getAllByRole("button", { name: "Details" })[0]!);
    expect(within(list).getByText("nginx.service")).toBeInTheDocument();
  });

  it("searches and filters on the server, and says when nothing matches", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(TECH, page([event("hello")])));
    renderApp("/devices/d1?tab=collected");
    await screen.findByText("hello");
    server.on("GET /devices/:id/collected-logs", ok(page([])));
    await user.selectOptions(screen.getByLabelText("Source"), "linux.audit");
    await user.type(screen.getByLabelText("Search collected logs"), "failed{enter}");
    await screen.findByText("No events match");
    const last = server.callsTo("GET /devices/:id/collected-logs").at(-1)!;
    expect(last.query.get("source")).toBe("linux.audit");
    expect(last.query.get("q")).toBe("failed");
  });

  it("shows command lines only when the server sent them, and says what the search covers", async () => {
    installFakeApi(routes(TECH, page([event("EXECVE", { sensitive: { cmdline: "curl http://x" } })], { canSeeSensitive: true })));
    renderApp("/devices/d1?tab=collected");
    expect(await screen.findByLabelText("Search collected logs")).toHaveAttribute("placeholder", expect.stringContaining("command lines"));
  });

  it("loads older events from where the last page ended", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(TECH, page([event("newest")], { more: true, next: "2026-11-27T09:59:00Z" })));
    renderApp("/devices/d1?tab=collected");
    await screen.findByText("newest");
    server.on("GET /devices/:id/collected-logs", ok(page([event("older", { time: "2026-11-27T09:00:00Z" })])));
    await user.click(screen.getByRole("button", { name: "Load older events" }));
    await screen.findByText("older");
    expect(server.callsTo("GET /devices/:id/collected-logs").at(-1)!.query.get("until")).toBe("2026-11-27T09:59:00Z");
    expect(screen.queryByRole("button", { name: "Load older events" })).not.toBeInTheDocument();
  });

  it("explains an unavailable log store without breaking the page", async () => {
    installFakeApi({
      ...routes(TECH, page([])),
      "GET /devices/:id/collected-logs": fail(503, "logs_unavailable", "The log store is not available."),
      "GET /devices/:id/collected-logs/timeline": fail(503, "logs_unavailable", "The log store is not available."),
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/devices/d1?tab=collected");
    expect(await screen.findByText("The log store is not available", {}, { timeout: 4000 })).toBeInTheDocument();
  });
});

describe("timelineBars", () => {
  it("keeps empty hours and splits warnings and errors out", () => {
    const bars = timelineBars(TIMELINE.buckets, TIMELINE.since, TIMELINE.until);
    expect(bars).toHaveLength(3);
    expect(bars.map((b) => b.events)).toEqual([0, 10, 0]);
    expect(bars[1]?.attention).toBe(2);
  });

  it("filters on a source", () => {
    const bars = timelineBars(TIMELINE.buckets, TIMELINE.since, TIMELINE.until, "linux.journal");
    expect(bars[1]).toMatchObject({ events: 8, attention: 0 });
  });

  it("stays within the most bars for long ranges", () => {
    const bars = timelineBars([], "2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z");
    expect(bars.length).toBeLessThanOrEqual(MAX_BARS);
    expect(Date.parse(bars.at(-1)!.end)).toBeGreaterThanOrEqual(Date.parse("2026-11-01T00:00:00Z"));
  });

  it("gives nothing for an empty range", () => {
    expect(timelineBars([], "2026-11-27T10:00:00Z", "2026-11-27T10:00:00Z")).toEqual([]);
  });
});

describe("collectedSourceName", () => {
  it("reads a source as words", () => {
    expect(collectedSourceName("windows.security")).toBe("Windows security");
    expect(collectedSourceName("linux.journal")).toBe("Linux journal");
  });
});
