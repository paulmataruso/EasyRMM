import { describe, expect, it } from "vitest";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { EventlogEvent, EventlogRequest, EventlogResult, EventlogRun } from "../../api/types";
import { baseRoutes, fail, installFakeApi, ok, sessionView } from "../../test/fakeApi";
import { device, history, inventory, metrics } from "../../test/fixtures";
import { renderApp } from "../../test/render";
import { endText, eventAsText, eventTime, groupChannels, parseIds, posText } from "./eventlog/eventlogText";

const AGENT = { version: "1.5.0", arch: "amd64", sha256: "", online: true, lastSeenAt: "2026-11-26T10:00:00Z", enrolledAt: "2026-10-01T09:00:00Z", update: null, accepts: null, powerShell7: null };
const PC = device("d1", "PC-12", { platform: "windows", agent: AGENT, online: true });
const OFFLINE = device("d3", "PC-OFF", { platform: "windows", agent: AGENT, online: false });
const LINUX = device("d2", "TUX", { platform: "linux", agent: AGENT, online: true });

const TECH = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "log.view", "eventlog.view", "job.view", "job.view_sensitive", "job.manage"] });
const ADMIN = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "log.view", "eventlog.view", "log.view_sensitive", "job.view", "job.view_sensitive", "job.manage"] });
const READ_ONLY = sessionView({ isSuperAdmin: false, permissions: ["org.view", "site.view", "device.view", "job.view"] });

const CHANNELS: EventlogResult = {
  state: "reported",
  complete: true,
  kind: "eventlog_query",
  runStatus: "succeeded",
  op: "channels",
  sensitive: false,
  crash: { value: 1, set: true },
  channels: [
    { name: "Application", type: "admin", enabled: true, count: 1200, size: 1048576 },
    { name: "Security", type: "admin", enabled: true, count: 90000 },
    { name: "System", type: "admin", enabled: true, count: 3400 },
    { name: "Microsoft-Windows-PowerShell/Operational", type: "operational", enabled: true },
    { name: "Microsoft-Windows-Kernel-PnP/Configuration", type: "operational", enabled: true },
    { name: "Microsoft-Windows-X/Analytic", type: "analytic", enabled: false },
  ],
  end: { complete: true, returned: 6, read: 0, stoppedBy: "end" },
};

function ev(record: number, over: Partial<EventlogEvent> = {}): EventlogEvent {
  return {
    log: "System",
    channel: "System",
    record,
    provider: "Service Control Manager",
    id: 7034,
    version: 0,
    level: 2,
    task: 0,
    opcode: 0,
    keywords: "0x8080000000000000",
    keywordNames: ["Classic"],
    time: "2026-11-26T10:00:00.1234567Z",
    offset: -18000,
    computer: "PC-12.example.test",
    userSid: "S-1-5-18",
    user: "NT AUTHORITY\\SYSTEM",
    message: "The Print Spooler service terminated unexpectedly.",
    data: [{ name: "param1", value: "Print Spooler" }],
    xml: "<Event><System/></Event>",
    ...over,
  };
}

function page(events: EventlogEvent[], over: Partial<EventlogResult> = {}): EventlogResult {
  return {
    state: "reported",
    complete: true,
    kind: "eventlog_query",
    runStatus: "succeeded",
    op: "query",
    sensitive: false,
    readAt: "2026-11-26T14:02:11Z",
    clock: new Date().toISOString(),
    pos: [{ channel: "System", state: "ok" }],
    events,
    end: { complete: true, returned: events.length, read: events.length, stoppedBy: "end", cursor: { channels: [{ channel: "System", record: 1, done: true }] } },
    ...over,
  };
}

function routes(session: ReturnType<typeof sessionView>, dev = PC, results: Record<string, EventlogResult> = {}) {
  return {
    ...baseRoutes(session),
    "GET /devices/:id": ok(dev),
    "GET /devices/:id/inventory": ok({ inventory: inventory(), metrics: metrics() }),
    "GET /devices/:id/metrics": ok(history()),
    "POST /devices/:id/eventlog": (req: { body: unknown }): ReturnType<typeof ok> => {
      const q = req.body as EventlogRequest;
      const run: EventlogRun = { jobId: "j1", runId: q.previousRunId ? "r-page2" : `r-${q.op}`, op: q.op, sensitive: q.sensitive === true, expiresAt: "2026-11-26T14:04:00Z" };
      return ok(run);
    },
    "POST /job-runs/:id/cancel": ok({}),
    "GET /job-runs": ok({ items: [] }),
    "GET /job-runs/:id/eventlog": (req: { params: Record<string, string> }): ReturnType<typeof ok> =>
      ok(results[req.params.id ?? ""] ?? (req.params.id === "r-channels" ? CHANNELS : page([ev(2), ev(1, { id: 41, provider: "Microsoft-Windows-Kernel-Power", level: 1 })]))),
  } as Parameters<typeof installFakeApi>[0];
}

describe("the Event logs tab", () => {
  it("is for a Windows device and a holder of eventlog.view", async () => {
    installFakeApi(routes(READ_ONLY));
    renderApp("/devices/d1");
    await screen.findByRole("tab", { name: "Overview" });
    expect(screen.queryByRole("tab", { name: "Event logs" })).not.toBeInTheDocument();
  });

  it("is not on a Linux device", async () => {
    installFakeApi(routes(TECH, LINUX));
    renderApp("/devices/d2");
    await screen.findByRole("tab", { name: "Overview" });
    expect(screen.queryByRole("tab", { name: "Event logs" })).not.toBeInTheDocument();
  });

  it("lists the computer's logs by group, with the Security log locked for a technician, and reads nothing else", async () => {
    const server = installFakeApi(routes(TECH));
    renderApp("/devices/d1?tab=eventlog");
    const header = await screen.findByRole("group", { name: "Event log header" });
    expect(within(header).getByText("PC-12")).toBeInTheDocument();
    expect(within(header).getByText("On the computer")).toBeInTheDocument();
    const logs = await screen.findByRole("group", { name: "Logs to search" });
    expect(await within(logs).findByRole("checkbox", { name: "System" })).toBeChecked();
    expect(within(logs).getByRole("checkbox", { name: "Application" })).toBeChecked();
    const security = within(logs).getByRole("checkbox", { name: "Security" });
    expect(security).toBeDisabled();
    expect(within(logs).getByText(/needs permission to see the Security log/)).toBeInTheDocument();
    // Other logs are grouped by provider, and analytic logs hide.
    expect(within(logs).getByText("Microsoft-Windows-PowerShell")).toBeInTheDocument();
    expect(within(logs).queryByText("Microsoft-Windows-X")).not.toBeInTheDocument();
    expect(server.callsTo("POST /devices/:id/eventlog").map((c) => (c.body as EventlogRequest).op)).toEqual(["channels"]);
  });

  it("searches with the filters as typed, and lists the events newest first with their fields", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(TECH));
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    await user.click(screen.getByRole("checkbox", { name: "Error" }));
    await user.type(screen.getByLabelText("Event IDs"), "41, 100-200, -7036");
    await user.type(screen.getByLabelText("Provider"), "Kernel-Power");
    await user.selectOptions(screen.getByLabelText("Time range"), "7d");
    await user.type(screen.getByLabelText("Text"), "spooler");
    await user.click(screen.getByRole("button", { name: "Search" }));
    const q = (await waitFor(() => server.callsTo("POST /devices/:id/eventlog").filter((c) => (c.body as EventlogRequest).op === "query")[0]!)).body as EventlogRequest;
    expect(q).toEqual({
      op: "query",
      channels: ["System", "Application"],
      levels: [2],
      ids: [{ from: 41 }, { from: 100, to: 200 }],
      excludeIds: [{ from: 7036 }],
      providers: ["Kernel-Power"],
      time: { last: "7d" },
      text: "spooler",
    });
    const table = await screen.findByRole("table", { name: "Events" });
    const rows = within(table).getAllByRole("row");
    expect(rows).toHaveLength(3);
    expect(within(rows[1]!).getByText("Error")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("Service Control Manager")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("Critical")).toBeInTheDocument();
    expect(within(rows[2]!).getByText("Microsoft-Windows-Kernel-Power")).toBeInTheDocument();
    expect(screen.getByText(/Read at \d\d:\d\d:\d\d/)).toBeInTheDocument();
    // Two logs: the log is a column.
    expect(within(table).getByText("Log")).toBeInTheDocument();
  });

  it("rejects event IDs it cannot read before anything is sent", async () => {
    const user = userEvent.setup();
    const server = installFakeApi(routes(TECH));
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    await user.type(screen.getByLabelText("Event IDs"), "12x");
    expect(await screen.findByText(/"12x" is not an event ID/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Search" })).toBeDisabled();
    expect(server.callsTo("POST /devices/:id/eventlog").filter((c) => (c.body as EventlogRequest).op === "query")).toHaveLength(0);
  });

  it("shows an event's message, its fields and its XML, and copies it", async () => {
    const user = userEvent.setup();
    installFakeApi(routes(TECH));
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    await user.click(screen.getByRole("button", { name: "Search" }));
    const table = await screen.findByRole("table", { name: "Events" });
    await user.click(within(table).getAllByRole("row")[1]!);
    expect(await screen.findByText("The Print Spooler service terminated unexpectedly.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /Event 7034, Service Control Manager/ })).toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: "Details" }));
    expect(screen.getByRole("table", { name: "Event data" })).toHaveTextContent("Print Spooler");
    expect(screen.getByLabelText("Event XML")).toHaveTextContent("<Event><System/></Event>");
    expect(screen.getByRole("button", { name: "Copy" })).toBeInTheDocument();
  });

  it("shows a withheld message and field as hidden, and never their text", async () => {
    const user = userEvent.setup();
    const hidden = ev(5, {
      id: 4688,
      message: undefined,
      messageHidden: true,
      hidden: ["CommandLine"],
      data: [{ name: "CommandLine", value: "", hidden: true }, { name: "Other", value: "fine" }],
    });
    installFakeApi(routes(TECH, PC, { "r-query": page([hidden]) }));
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    await user.click(screen.getByRole("button", { name: "Search" }));
    const table = await screen.findByRole("table", { name: "Events" });
    await user.click(within(table).getAllByRole("row")[1]!);
    expect(await screen.findByText(/needs permission to see command lines and scripts/)).toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: "Details" }));
    const data = screen.getByRole("table", { name: "Event data" });
    expect(within(data).getByText("hidden: needs permission to see command lines and scripts")).toBeInTheDocument();
    expect(within(data).getByText("fine")).toBeInTheDocument();
  });

  it("asks for the next page by naming the run, and appends it", async () => {
    const user = userEvent.setup();
    const first = page([ev(3), ev(2)], { end: { complete: true, returned: 2, read: 2, stoppedBy: "page", cursor: { channels: [{ channel: "System", record: 2 }] } } });
    const second = page([ev(1, { id: 41 })]);
    const server = installFakeApi(routes(TECH, PC, { "r-query": first, "r-page2": second }));
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    await user.click(screen.getByRole("button", { name: "Search" }));
    await screen.findByRole("table", { name: "Events" });
    await user.click(screen.getByRole("button", { name: "More" }));
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Events" })).getAllByRole("row")).toHaveLength(4));
    const calls = server.callsTo("POST /devices/:id/eventlog").map((c) => c.body as EventlogRequest);
    expect(calls.at(-1)).toEqual({ op: "query", previousRunId: "r-query" });
    expect(screen.queryByRole("button", { name: "More" })).not.toBeInTheDocument();
  });

  it("says how far a bounded search got, and that nothing matched only when the range was searched", async () => {
    const user = userEvent.setup();
    const bounded = page([], { end: { complete: true, returned: 0, read: 100000, stoppedBy: "read", searchedBack: "2026-11-20T08:00:00Z", cursor: { channels: [{ channel: "System", record: 5 }] } } });
    installFakeApi(routes(TECH, PC, { "r-query": bounded }));
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    await user.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText(/Searched 100,000 events back to/)).toBeInTheDocument();
    expect(screen.getByText(/more may match/)).toBeInTheDocument();
  });

  it("says a log was not found, cleared, or refused", async () => {
    const user = userEvent.setup();
    const odd = page([], {
      pos: [
        { channel: "Nope", state: "not_found" },
        { channel: "System", state: "ok", cleared: true },
        { channel: "Locked", state: "denied" },
      ],
    });
    installFakeApi(routes(TECH, PC, { "r-query": odd }));
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    await user.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText("No log named Nope on this computer.")).toBeInTheDocument();
    expect(screen.getByText(/this log was cleared since the first page/)).toBeInTheDocument();
    expect(screen.getByText("Access denied to Locked.")).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Start again" }).length).toBeGreaterThan(0);
  });

  it("shows the server's refusal when the search itself is refused", async () => {
    const user = userEvent.setup();
    installFakeApi({
      ...routes(TECH),
      "POST /devices/:id/eventlog": (req: { body: unknown }) =>
        (req.body as EventlogRequest).op === "channels"
          ? ok({ ...CHANNELS, channels: [] })
          : fail(422, "validation_failed", "Refused by EasyRMM: the Security log needs permission.", { channels: "Refused by EasyRMM: the Security log needs permission." }),
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("group", { name: "Event log header" });
    await user.click(screen.getByRole("button", { name: "Search" }));
    expect(await screen.findByText(/Refused by EasyRMM/)).toBeInTheDocument();
  });

  it("offers command lines and scripts, and the Security log, only to one who holds log.view_sensitive, and asks for them", async () => {
    const user = userEvent.setup();
    installFakeApi(routes(TECH));
    const { unmount } = renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    expect(screen.queryByLabelText(/Show command lines and scripts/)).not.toBeInTheDocument();
    unmount();

    const server = installFakeApi(routes(ADMIN));
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    const security = await screen.findByRole("checkbox", { name: "Security" });
    expect(security).toBeEnabled();
    await user.click(security);
    expect(screen.getByLabelText(/Show command lines and scripts/)).toBeChecked();
    await user.click(screen.getByRole("button", { name: "Search" }));
    const q = (await waitFor(() => server.callsTo("POST /devices/:id/eventlog").filter((c) => (c.body as EventlogRequest).op === "query")[0]!)).body as EventlogRequest;
    expect(q.sensitive).toBe(true);
    expect(q.channels).toEqual(["System", "Application", "Security"]);
  });

  it("sends nothing while the device is offline", async () => {
    const server = installFakeApi(routes(TECH, OFFLINE));
    renderApp("/devices/d3?tab=eventlog");
    expect(await screen.findByText("This device is offline")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Search" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Refresh" })).toBeDisabled();
    expect(server.callsTo("POST /devices/:id/eventlog")).toHaveLength(0);
  });

  it("opens an event too large for the list by its record", async () => {
    const user = userEvent.setup();
    const big = ev(9, { tooLarge: true, message: undefined, messageNote: "too large for the list: open it", data: undefined });
    const full = page([ev(9, { message: "The whole event." })], { op: "event" });
    const r = routes(TECH, PC, { "r-query": page([big]), "r-event": full });
    const server = installFakeApi(r);
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    await user.click(screen.getByRole("button", { name: "Search" }));
    const table = await screen.findByRole("table", { name: "Events" });
    await user.click(within(table).getAllByRole("row")[1]!);
    await user.click(await screen.findByRole("button", { name: "Open it" }));
    expect(await screen.findByText("The whole event.")).toBeInTheDocument();
    const q = server.callsTo("POST /devices/:id/eventlog").map((c) => c.body as EventlogRequest).find((b) => b.op === "event");
    expect(q).toMatchObject({ op: "event", channels: ["System"], record: 9 });
  });

  it("cancels the run still open when the tab is left", async () => {
    const user = userEvent.setup();
    const server = installFakeApi({
      ...routes(TECH),
      "GET /job-runs/:id/eventlog": (req: { params: Record<string, string> }) => (req.params.id === "r-channels" ? ok(CHANNELS) : fail(409, "run_open", "The run has not finished.")),
    } as Parameters<typeof installFakeApi>[0]);
    renderApp("/devices/d1?tab=eventlog");
    await screen.findByRole("checkbox", { name: "System" });
    await user.click(screen.getByRole("button", { name: "Search" }));
    await waitFor(() => expect(server.callsTo("POST /devices/:id/eventlog").filter((c) => (c.body as EventlogRequest).op === "query")).toHaveLength(1));
    await user.click(screen.getByRole("tab", { name: "Overview" }));
    await waitFor(() => expect(server.callsTo("POST /job-runs/:id/cancel").length).toBeGreaterThan(0));
  });
});

describe("the event log's text", () => {
  it("reads event IDs, ranges and exclusions", () => {
    expect(parseIds("41, 100-200 -7036")).toEqual({ ids: [{ from: 41 }, { from: 100, to: 200 }], exclude: [{ from: 7036 }] });
    expect(parseIds("").ids).toEqual([]);
    expect(parseIds("9-3").error).toMatch(/not a valid/);
    expect(parseIds("70000").error).toMatch(/not a valid/);
    expect(parseIds("a").error).toMatch(/not an event ID/);
    expect(parseIds(Array.from({ length: 33 }, (_, i) => i + 1).join(",")).error).toMatch(/At most 32/);
  });

  it("groups channels: Windows Logs first, then by provider, with analytic logs behind a switch", () => {
    const g = groupChannels(CHANNELS.channels ?? [], false);
    expect(g.map((x) => x.title)).toEqual(["Windows Logs", "Microsoft-Windows-Kernel-PnP", "Microsoft-Windows-PowerShell"]);
    expect(g[0]!.channels.map((c) => c.name)).toEqual(["Application", "Security", "System"]);
    expect(groupChannels(CHANNELS.channels ?? [], true).map((x) => x.title)).toContain("Microsoft-Windows-X");
  });

  it("shows times in UTC, the computer's time with its offset, and keeps what was recorded", () => {
    const e = { time: "2026-11-26T10:00:00.123Z", offset: -18000 };
    expect(eventTime(e, "utc")).toBe("2026-11-26 10:00:00 UTC");
    expect(eventTime(e, "computer")).toBe("2026-11-26 05:00:00 (UTC-05:00)");
    expect(eventTime({ time: "2026-11-26T10:00:00Z" }, "computer")).toBe("2026-11-26 10:00:00 UTC");
  });

  it("says why a page stopped and what a channel's state is", () => {
    expect(endText({ complete: true, returned: 0, read: 5, stoppedBy: "end" }, "utc")).toBeNull();
    expect(endText({ complete: true, returned: 0, read: 1500, stoppedBy: "read", searchedBack: "2026-11-20T08:00:00Z" }, "utc")).toBe("Searched 1,500 events back to 2026-11-20 08:00:00 UTC; more may match.");
    expect(endText({ complete: false, returned: 0, read: 10, stoppedBy: "time" }, "utc")).toMatch(/time limit/);
    expect(posText({ channel: "A", state: "ok" })).toBeNull();
    expect(posText({ channel: "A", state: "ok", overwritten: true, oldestAt: "T" })).toMatch(/overwritten/);
    expect(posText({ channel: "A", state: "unavailable", reason: "Windows reads this log only while it is disabled." })).toMatch(/only while it is disabled/);
  });

  it("copies an event as text without a hidden message", () => {
    const t = eventAsText(ev(1), "utc");
    expect(t).toContain("Event ID:      7034");
    expect(t).toContain("The Print Spooler service terminated unexpectedly.");
    expect(eventAsText(ev(2, { message: undefined, messageHidden: true }), "utc")).toContain("(hidden: needs permission");
  });
});
