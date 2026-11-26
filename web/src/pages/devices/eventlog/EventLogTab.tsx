import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { ChevronDown, ChevronRight, Copy, Lock, ScrollText } from "lucide-react";
import { useAuth } from "../../../auth/AuthContext";
import { errorMessage } from "../../../api/client";
import type { Device, EventlogChannel, EventlogEnd, EventlogEvent, EventlogPos, EventlogRequest, EventlogResult } from "../../../api/types";
import { Alert, Badge, Button, Card, cx, EmptyState, Input, KeyValueList, Segmented, Select, Spinner, TableWrap } from "../../../components/ui";
import { formatRelative } from "../../../lib/format";
import { endText, eventAsText, eventTime, groupChannels, isSecurityChannel, LEVELS, levelName, levelTone, parseIds, posText, RANGES, sizeText, STATE_TEXT, type Zone } from "./eventlogText";
import { cancelRun, startOp } from "./runOp";
import { groupKeyEvents, groupRepeats, isProblem, keyEventsRequests, problemsRequest, repeatText, type EventGroup } from "./overview";

const DEFAULT_CHANNELS = ["System", "Application"];

/**
 * A Windows device's event logs, On the computer (ADR-0068): the channels, a query over one or several of them by level, ID,
 * provider and time with text matched after it, newest first in pages, and each event's fields, message and XML. Every page is
 * a job the agent runs as a builtin; the page follows it and says when it was read. Needs eventlog.view; the Security log and
 * command lines and scripts need log.view_sensitive.
 */
export function EventLogPanel({ device }: { device: Device }) {
  const { canAt } = useAuth();
  const holdsSensitive = canAt("log.view_sensitive", { organizationId: device.organizationId });
  const offline = !device.online;

  const [channels, setChannels] = useState<EventlogResult | null>(null);
  const [channelsError, setChannelsError] = useState<string | null>(null);
  const [showAnalytic, setShowAnalytic] = useState(false);
  const [picked, setPicked] = useState<string[]>(DEFAULT_CHANNELS);

  const [levels, setLevels] = useState<number[]>([]);
  const [idsText, setIdsText] = useState("");
  const [provider, setProvider] = useState("");
  const [range, setRange] = useState("24h");
  const [text, setText] = useState("");
  const [showSensitive, setShowSensitive] = useState(false);
  const [zone, setZone] = useState<Zone>("local");

  const [events, setEvents] = useState<EventlogEvent[]>([]);
  const [pos, setPos] = useState<EventlogPos[]>([]);
  const [end, setEnd] = useState<EventlogEnd | undefined>();
  const [last, setLast] = useState<{ runId: string; result: EventlogResult } | null>(null);
  const [searched, setSearched] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"overview" | "search">("overview");
  const [overview, setOverview] = useState<{ key: EventlogEvent[]; problems: EventlogEvent[]; notes: string[]; at?: string } | null>(null);
  const [overviewBusy, setOverviewBusy] = useState(false);
  const [selectedEv, setSelectedEv] = useState<EventlogEvent | null>(null);
  const [detail, setDetail] = useState<"general" | "details">("general");
  const [clockSkew, setClockSkew] = useState<number | null>(null);

  const abort = useRef<AbortController | null>(null);
  const openRuns = useRef(new Set<string>());
  const request = useRef<EventlogRequest | null>(null);

  // Leaving the tab cancels the run still open: the agent closes the child's input and Windows is told to stop.
  useEffect(
    () => () => {
      abort.current?.abort();
      for (const id of openRuns.current) void cancelRun(id);
    },
    [],
  );

  // The channel list comes once, and again on request.
  const loadChannels = useCallback(async () => {
    setChannelsError(null);
    try {
      const { run, result } = await startOp(device.id, { op: "channels" });
      openRuns.current.add(run.runId);
      const r = await result;
      openRuns.current.delete(run.runId);
      if (r.state !== "reported") setChannelsError(r.reason || STATE_TEXT[r.state]);
      else setChannels(r);
    } catch (e) {
      setChannelsError(errorMessage(e));
    }
  }, [device.id]);
  useEffect(() => {
    if (!offline) void loadChannels();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device.id, offline]);

  /** The overview reads on its own: the key events, then the problems, one query after the other (a newer query replaces an open one). */
  const loadOverview = useCallback(async () => {
    abort.current?.abort();
    const ac = new AbortController();
    abort.current = ac;
    setBusy(false);
    setOverviewBusy(true);
    setError(null);
    const notes: string[] = [];
    const read = async (req: EventlogRequest): Promise<EventlogEvent[]> => {
      const started = await startOp(device.id, req, ac.signal);
      openRuns.current.add(started.run.runId);
      const r = await started.result;
      openRuns.current.delete(started.run.runId);
      if (r.state !== "reported" && r.state !== "unknown") throw new Error(r.reason || STATE_TEXT[r.state]);
      if (r.clock) setClockSkew(Math.round((new Date(r.clock).getTime() - Date.now()) / 1000));
      for (const n of (r.pos ?? []).map(posText)) if (n) notes.push(n);
      const e = endText(r.end, "local");
      if (e) notes.push(e);
      setLast({ runId: started.run.runId, result: r });
      return r.events ?? [];
    };
    try {
      const seen = new Set<string>();
      const key: EventlogEvent[] = [];
      for (const req of keyEventsRequests(holdsSensitive)) {
        for (const e of await read(req)) {
          if (!seen.has(`${e.log}/${e.record}`)) {
            seen.add(`${e.log}/${e.record}`);
            key.push(e);
          }
        }
        setOverview((o) => ({ key: [...key], problems: o?.problems ?? [], notes: [...new Set(notes)] }));
      }
      const problems = (await read(problemsRequest())).filter(isProblem);
      setOverview({ key, problems, notes: [...new Set(notes)], at: new Date().toISOString() });
    } catch (e) {
      if (!(e instanceof DOMException && e.name === "AbortError")) setError(errorMessage(e));
    } finally {
      if (abort.current === ac) setOverviewBusy(false);
    }
  }, [device.id, holdsSensitive]);

  // The overview opens by itself and keeps itself current.
  useEffect(() => {
    if (view !== "overview" || offline) return;
    void loadOverview();
    const t = setInterval(() => void loadOverview(), 5 * 60_000);
    return () => clearInterval(t);
  }, [view, offline, loadOverview]);

  /** A count's link: the search that finds exactly those events, run at once. */
  const openFilter = (f: EventGroup["filter"]) => {
    abort.current?.abort();
    setPicked([f.log]);
    setLevels(f.level === undefined ? [] : [f.level]);
    setIdsText(String(f.id));
    setProvider(f.provider);
    setRange("24h");
    setText("");
    setView("search");
  };

  const wantsSecurity = picked.some(isSecurityChannel);
  const sensitive = holdsSensitive && (showSensitive || wantsSecurity);
  const idError = useMemo(() => parseIds(idsText).error, [idsText]);

  const build = (): EventlogRequest => {
    const { ids, exclude } = parseIds(idsText);
    const r: EventlogRequest = { op: "query", channels: picked };
    if (levels.length) r.levels = levels;
    if (ids.length) r.ids = ids;
    if (exclude.length) r.excludeIds = exclude;
    if (provider.trim()) r.providers = [provider.trim()];
    if (range !== "any") r.time = { last: range as "1h" };
    if (text.trim()) r.text = text.trim();
    if (sensitive) r.sensitive = true;
    return r;
  };

  const take = (r: EventlogResult, append: boolean) => {
    setEvents((prev) => (append ? [...prev, ...(r.events ?? [])] : (r.events ?? [])));
    setPos(r.pos ?? []);
    setEnd(r.end);
    if (r.clock) setClockSkew(Math.round((new Date(r.clock).getTime() - Date.now()) / 1000));
  };

  /** Runs the first page of the filters shown, or the next page of the last one. */
  const run = async (next: boolean) => {
    if (next && !last) return;
    abort.current?.abort();
    const ac = new AbortController();
    abort.current = ac;
    setOverviewBusy(false);
    setBusy(true);
    setError(null);
    try {
      const req = next ? ({ op: "query", previousRunId: last?.runId } as EventlogRequest) : build();
      if (!next) request.current = req;
      const started = await startOp(device.id, req, ac.signal);
      openRuns.current.add(started.run.runId);
      const r = await started.result;
      openRuns.current.delete(started.run.runId);
      setSearched(true);
      if (r.state === "reported" || r.state === "unknown") {
        take(r, next);
        if (!next) setSelectedEv(null);
        setLast({ runId: started.run.runId, result: r });
        if (r.state === "unknown") setError(r.reason ?? STATE_TEXT.unknown);
      } else {
        setError(r.reason || STATE_TEXT[r.state]);
      }
    } catch (e) {
      if (!(e instanceof DOMException && e.name === "AbortError")) setError(errorMessage(e));
    } finally {
      if (abort.current === ac) setBusy(false);
    }
  };

  // A search runs as the filters change, after a short pause; there is no button that only starts a read.
  useEffect(() => {
    if (view !== "search" || offline || !picked.length || idError) return;
    const t = setTimeout(() => void run(false), 500);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, offline, picked, levels, idsText, provider, range, text, sensitive]);

  const search = (e?: FormEvent) => {
    e?.preventDefault();
    if (idError || !picked.length || offline) return;
    void run(false);
  };

  const openEvent = async (ev: EventlogEvent) => {
    setError(null);
    try {
      const { result } = await startOp(device.id, { op: "event", channels: [ev.log], record: ev.record, ...(sensitive ? { sensitive: true } : {}) });
      const r = await result;
      const one = r.events?.[0];
      if (!one) {
        setError(r.errors?.[0]?.message ?? "This event is no longer in the log: it was overwritten or cleared.");
        return;
      }
      setEvents((prev) => prev.map((x) => (x.log === one.log && x.record === one.record ? one : x)));
      setSelectedEv(one);
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const groups = useMemo(() => groupChannels(channels?.channels ?? [], showAnalytic), [channels, showAnalytic]);
  /** A log chosen in the tree replaces the overview and loads at once; in a search it is added to or taken from the logs read. */
  const toggleChannel = (name: string) => {
    if (view === "overview") {
      setPicked([name]);
      setView("search");
      return;
    }
    setPicked((p) => (p.includes(name) ? p.filter((n) => n !== name) : p.length >= 10 ? p : [...p, name]));
  };
  const current = selectedEv ?? undefined;
  const selected = selectedEv ? events.findIndex((x) => x.log === selectedEv.log && x.record === selectedEv.record) : -1;
  const more = end?.cursor?.channels.some((c) => !c.done) === true;
  const readAt = last?.result.readAt;

  return (
    <div className="flex flex-col gap-4">
      <Card padded>
        <div className="flex flex-col gap-3" role="group" aria-label="Event log header">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-medium">{device.name}</span>
            <span className="text-muted">
              {device.organizationName} / {device.siteName}
            </span>
            <Badge tone={device.online ? "ok" : "warn"}>{device.online ? "Online" : "Offline"}</Badge>
            <Badge tone="info">On the computer</Badge>
            {clockSkew !== null && Math.abs(clockSkew) > 30 && (
              <Badge tone="warn" title="The computer's clock differs from the server's">
                Computer clock {clockSkew > 0 ? "ahead" : "behind"} by {Math.abs(clockSkew)} s
              </Badge>
            )}
            {readAt && (
              <span className="ml-auto text-muted" title={readAt}>
                Read at {new Date(readAt).toLocaleTimeString("en-GB")}
              </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Segmented<Zone>
              label="Time zone"
              value={zone}
              onChange={setZone}
              options={[
                { value: "local", label: "Your time" },
                { value: "computer", label: "Computer's time" },
                { value: "utc", label: "UTC" },
              ]}
            />
            <Segmented<"overview" | "search">
              label="View"
              value={view}
              onChange={setView}
              options={[
                { value: "overview", label: "Admin overview" },
                { value: "search", label: "All events" },
              ]}
            />
          </div>
          {offline && (
            <Alert tone="warn" title="This device is offline">
              Last seen {device.lastSeenAt ? formatRelative(device.lastSeenAt) : "never"}. Nothing is sent while it is offline.
            </Alert>
          )}
          {error && (
            <Alert tone="danger" title="The event log could not be read">
              {error}
            </Alert>
          )}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <Card title="Logs" padded={false} className="lg:col-span-1">
          <div className="flex flex-col gap-2 p-2 text-sm">
            <label className="flex items-center gap-2 text-xs text-muted">
              <input type="checkbox" checked={showAnalytic} onChange={(e) => setShowAnalytic(e.target.checked)} />
              Show analytic and debug logs
            </label>
            {!channels && !channelsError && !offline && <Spinner label="Listing the logs…" className="py-4" />}
            {channelsError && (
              <Alert tone="warn" title="The logs could not be listed">
                {channelsError}{" "}
                <button type="button" className="underline" onClick={() => void loadChannels()}>
                  Try again
                </button>
              </Alert>
            )}
            <div role="group" aria-label="Logs to search" className="max-h-[28rem] overflow-auto">
              {groups.map((g) => (
                <ChannelGroupView key={g.title} title={g.title} channels={g.channels} picked={picked} holds={holdsSensitive} toggle={toggleChannel} open={g.title === "Windows Logs"} />
              ))}
            </div>
            {channels?.crash?.set && picked.some(isSecurityChannel) && (
              <p className="text-xs text-muted">CrashOnAuditFail is {channels.crash.value} on this computer.</p>
            )}
          </div>
        </Card>

        <div className="flex min-w-0 flex-col gap-4 lg:col-span-3">
          {view === "overview" ? (
            <>
          <Overview
            data={overview}
            busy={overviewBusy}
            offline={offline}
            holdsSensitive={holdsSensitive}
            zone={zone}
            selected={selectedEv}
            onSelect={(e) => {
              setSelectedEv(e);
              setDetail("general");
            }}
            onFilter={openFilter}
          />
            </>
          ) : (
            <>
          <Card title="Filter">
            <form className="flex flex-col gap-3" onSubmit={search}>
              <div className="flex flex-wrap items-center gap-3">
                <fieldset className="flex flex-wrap items-center gap-2 text-sm">
                  <legend className="sr-only">Level</legend>
                  {LEVELS.map((l) => (
                    <label key={l.value} className="flex items-center gap-1">
                      <input type="checkbox" checked={levels.includes(l.value)} onChange={(e) => setLevels((s) => (e.target.checked ? [...s, l.value] : s.filter((x) => x !== l.value)))} />
                      {l.label}
                    </label>
                  ))}
                </fieldset>
                <Select aria-label="Time range" value={range} onChange={(e) => setRange(e.target.value)} className="w-auto">
                  {RANGES.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </Select>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Input aria-label="Event IDs" className="w-56" placeholder="Event IDs: 41, 100-200, -7036" value={idsText} onChange={(e) => setIdsText(e.target.value)} aria-invalid={idError ? true : undefined} />
                <Input aria-label="Provider" className="w-56" placeholder="Provider (source)" value={provider} onChange={(e) => setProvider(e.target.value)} maxLength={255} />
                <Input aria-label="Text" className="min-w-0 flex-1" placeholder="Text in the message or a value" maxLength={256} value={text} onChange={(e) => setText(e.target.value)} />
              </div>
              {idError && <p className="text-xs text-danger">{idError}</p>}
              {holdsSensitive && (
                <label className="flex items-center gap-2 text-xs">
                  <input type="checkbox" checked={showSensitive || wantsSecurity} disabled={wantsSecurity} onChange={(e) => setShowSensitive(e.target.checked)} />
                  Show command lines and scripts
                  <span className="text-muted">(recorded; needs permission to see command lines and scripts)</span>
                </label>
              )}
              {text.trim() && <p className="text-xs text-muted">Text is matched after Windows returns an event, so a text search reads fewer events and says how far back it searched.</p>}
            </form>
          </Card>

          <Card title={`Events${events.length ? ` (${events.length})` : ""}`} padded={false}>
            <Results
              events={view === "search" ? events : []}
              pos={pos}
              end={end}
              picked={picked}
              zone={zone}
              selected={selected}
              onSelect={(i) => {
                setSelectedEv(events[i] ?? null);
                setDetail("general");
              }}
              busy={busy}
              searched={searched}
              more={more}
              onMore={() => void run(true)}
              onRestart={() => search()}
            />
          </Card>

            </>
          )}
          {current && <Detail key={`${current.log}/${current.record}`} event={current} zone={zone} mode={detail} setMode={setDetail} onOpen={() => void openEvent(current)} />}
        </div>
      </div>
    </div>
  );
}

function Skeleton({ rows }: { rows: number }) {
  return (
    <div role="status" aria-label="Reading the logs" className="flex flex-col gap-2 p-3">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="h-6 animate-pulse rounded bg-raised" />
      ))}
    </div>
  );
}

/** The admin overview: key events pinned above the last day's Critical and Error events and System warnings. */
function Overview({ data, busy, offline, holdsSensitive, zone, selected, onSelect, onFilter }: {
  data: { key: EventlogEvent[]; problems: EventlogEvent[]; notes: string[]; at?: string } | null;
  busy: boolean;
  offline: boolean;
  holdsSensitive: boolean;
  zone: Zone;
  selected: EventlogEvent | null;
  onSelect: (e: EventlogEvent) => void;
  onFilter: (f: EventGroup["filter"]) => void;
}) {
  const clock = (iso: string) => new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  const keys = useMemo(() => (data ? groupKeyEvents(data.key, holdsSensitive) : []), [data, holdsSensitive]);
  const problems = useMemo(() => (data ? groupRepeats(data.problems, true) : []), [data]);
  const row = (g: EventGroup, label?: string) => (
    <tr key={g.key} aria-selected={selected?.log === g.newest.log && selected?.record === g.newest.record} className="cursor-pointer border-t border-line hover:bg-hover" onClick={() => onSelect(g.newest)}>
      <td className="px-2 py-1.5">
        <Badge tone={levelTone(g.newest.level)}>{levelName(g.newest)}</Badge>
      </td>
      <td className="px-2 py-1.5">
        <button type="button" className="text-left underline-offset-2 hover:underline" onClick={() => onSelect(g.newest)}>
          {label ?? g.newest.provider} <span className="text-muted">({g.newest.provider}, {g.newest.id}, {g.newest.log})</span>
        </button>
      </td>
      <td className="whitespace-nowrap px-2 py-1.5">{eventTime(g.newest, zone)}</td>
      <td className="whitespace-nowrap px-2 py-1.5">
        {g.count > 1 ? (
          <button type="button" className="underline" aria-label={`Show all ${g.count} events`} onClick={() => onFilter(g.filter)}>
            {repeatText(g, clock)}
          </button>
        ) : (
          <button type="button" className="underline-offset-2 hover:underline" aria-label="Show the events like this" onClick={() => onFilter(g.filter)}>
            {repeatText(g, clock)}
          </button>
        )}
      </td>
    </tr>
  );
  const head = (
    <thead className="bg-raised text-muted">
      <tr>
        <th className="px-2 py-1.5 font-medium">Level</th>
        <th className="px-2 py-1.5 font-medium">Event</th>
        <th className="px-2 py-1.5 font-medium">Latest</th>
        <th className="px-2 py-1.5 font-medium">Repeats</th>
      </tr>
    </thead>
  );
  if (offline) return null;
  return (
    <div className="flex flex-col gap-4" aria-label="Admin overview">
      <Card title="Key events, last 24 hours" padded={false}>
        {!data && <Skeleton rows={4} />}
        {data && keys.length === 0 && (
          <div className="p-3">
            <EmptyState compact title="No key events" icon={<ScrollText className="size-5" aria-hidden />}>
              No unexpected shutdowns, service or disk failures, crashes, update, policy, time or domain problems in the last 24 hours.
              {!holdsSensitive && " Failed sign-ins and lockouts need permission to see the Security log."}
            </EmptyState>
          </div>
        )}
        {keys.map((k) => (
          <div key={k.category} className="px-3 pb-2 pt-3">
            <h3 className="mb-1 text-xs font-medium">
              {k.category} <span className="text-muted">({k.total})</span>
            </h3>
            <TableWrap>
              <table className="w-full text-left text-xs" aria-label={k.category}>
                {head}
                <tbody>{k.groups.map((g) => row(g, g.label))}</tbody>
              </table>
            </TableWrap>
          </div>
        ))}
      </Card>
      <Card title="Critical and Error events, and System warnings, last 24 hours" padded={false}>
        {!data || (busy && data.problems.length === 0 && !data.at) ? (
          <Skeleton rows={6} />
        ) : problems.length === 0 ? (
          <div className="p-3">
            <EmptyState compact title="Nothing to report">No Critical or Error events in System or Application, and no System warnings, in the last 24 hours.</EmptyState>
          </div>
        ) : (
          <div className="p-3">
            <TableWrap>
              <table className="w-full text-left text-xs" aria-label="Problems">
                {head}
                <tbody>{problems.map((g) => row(g))}</tbody>
              </table>
            </TableWrap>
          </div>
        )}
      </Card>
      {data?.notes.map((n) => (
        <p key={n} className="text-xs text-muted">
          {n}
        </p>
      ))}
      {data?.at && <p className="text-xs text-muted">Read at {new Date(data.at).toLocaleTimeString("en-GB")}; it reads again by itself every 5 minutes.</p>}
    </div>
  );
}

function ChannelGroupView({ title, channels, picked, holds, toggle, open }: { title: string; channels: EventlogChannel[]; picked: string[]; holds: boolean; toggle: (n: string) => void; open: boolean }) {
  const [expanded, setExpanded] = useState(open);
  return (
    <div>
      <button type="button" className="flex w-full items-center gap-1 rounded px-1 py-1 text-left text-xs font-medium hover:bg-hover" onClick={() => setExpanded((v) => !v)} aria-expanded={expanded}>
        {expanded ? <ChevronDown className="size-3" aria-hidden /> : <ChevronRight className="size-3" aria-hidden />}
        {title}
      </button>
      {expanded && (
        <ul className="ml-4">
          {channels.map((c) => {
            const locked = isSecurityChannel(c.name) && !holds;
            const label = c.name.includes("/") && title !== "Windows Logs" ? c.name.slice(c.name.indexOf("/") + 1) : c.name;
            return (
              <li key={c.name}>
                <label className={cx("flex items-start gap-2 py-0.5 text-xs", locked && "opacity-70")} title={c.name}>
                  <input type="checkbox" checked={picked.includes(c.name)} disabled={locked || c.state === "denied"} onChange={() => toggle(c.name)} aria-label={c.name} />
                  <span className="min-w-0 break-words">
                    {label}
                    {locked && (
                      <span className="ml-1 inline-flex items-center gap-0.5 text-muted">
                        <Lock className="size-3" aria-hidden /> needs permission to see the Security log
                      </span>
                    )}
                    {c.state === "denied" && <span className="ml-1 text-muted">Unavailable: access denied</span>}
                    {!c.enabled && <span className="ml-1 text-muted">disabled</span>}
                    {c.count !== undefined && c.type !== "analytic" && <span className="ml-1 text-muted">{c.count.toLocaleString()} events{c.size ? `, ${sizeText(c.size)}` : ""}</span>}
                  </span>
                </label>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function Results({ events, pos, end, picked, zone, selected, onSelect, busy, searched, more, onMore, onRestart }: {
  events: EventlogEvent[];
  pos: EventlogPos[];
  end: EventlogEnd | undefined;
  picked: string[];
  zone: Zone;
  selected: number;
  onSelect: (i: number) => void;
  busy: boolean;
  searched: boolean;
  more: boolean;
  onMore: () => void;
  onRestart: () => void;
}) {
  const several = picked.length > 1;
  const notes = pos.map(posText).filter((x): x is string => x !== null);
  const stopped = endText(end, zone);
  const restart = pos.some((p) => p.cleared || p.overwritten);
  return (
    <div className="flex flex-col gap-2 p-3">
      {notes.map((n) => (
        <Alert key={n} tone="warn">
          {n}
          {restart && (
            <>
              {" "}
              <button type="button" className="underline" onClick={onRestart}>
                Start again
              </button>
            </>
          )}
        </Alert>
      ))}
      {!searched && !busy && <EmptyState compact title="Choose a log" icon={<ScrollText className="size-5" aria-hidden />}>Pick one or more logs on the left and set a filter; the events appear by themselves.</EmptyState>}
      {busy && events.length === 0 && <Skeleton rows={5} />}
      {searched && !busy && events.length === 0 && notes.length === 0 && (
        <EmptyState compact title="No events match">
          {end?.stoppedBy === "end" || end?.stoppedBy === "page" ? "The whole range was searched." : (stopped ?? "")}
          {pos.find((p) => p.oldestAt) && ` This log begins at ${pos.find((p) => p.oldestAt)?.oldestAt}, so nothing before it can be known from the computer.`}
        </EmptyState>
      )}
      {events.length > 0 && (
        <TableWrap>
          <table className="w-full text-left text-xs" aria-label="Events">
            <thead className="bg-raised text-muted">
              <tr>
                <th className="px-2 py-1.5 font-medium">Level</th>
                <th className="px-2 py-1.5 font-medium">Date and time</th>
                <th className="px-2 py-1.5 font-medium">Source</th>
                <th className="px-2 py-1.5 font-medium">Event ID</th>
                <th className="px-2 py-1.5 font-medium">Task category</th>
                {several && <th className="px-2 py-1.5 font-medium">Log</th>}
              </tr>
            </thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={`${e.log}/${e.record}`} aria-selected={selected === i} className={cx("cursor-pointer border-t border-line hover:bg-hover", selected === i && "bg-accent-soft")} onClick={() => onSelect(i)}>
                  <td className="px-2 py-1.5">
                    <Badge tone={levelTone(e.level)}>{levelName(e)}</Badge>
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5">
                    <button type="button" className="underline-offset-2 hover:underline" onClick={() => onSelect(i)}>
                      {eventTime(e, zone)}
                    </button>
                  </td>
                  <td className="px-2 py-1.5">{e.provider}</td>
                  <td className="px-2 py-1.5">{e.id}</td>
                  <td className="px-2 py-1.5">{e.taskName ?? (e.task ? e.task : "None")}</td>
                  {several && <td className="px-2 py-1.5">{e.log}</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
      {stopped && events.length > 0 && <p className="text-xs text-muted">{stopped}</p>}
      {end && ((end.hiddenEvents ?? 0) > 0 || (end.dropped ?? 0) > 0 || (end.unreadable ?? 0) > 0) && (
        <p className="text-xs text-muted">
          {(end.hiddenEvents ?? 0) > 0 && `${end.hiddenEvents} Security events were left out: they need permission to see the Security log. `}
          {(end.dropped ?? 0) > 0 && `${end.dropped} events were dropped from this text search because they held values you may not see. `}
          {(end.unreadable ?? 0) > 0 && `${end.unreadable} events could not be read.`}
        </p>
      )}
      {more && events.length > 0 && (
        <div>
          <Button onClick={onMore} disabled={busy}>
            {busy ? "Reading…" : "More"}
          </Button>
        </div>
      )}
    </div>
  );
}

function Detail({ event: e, zone, mode, setMode, onOpen }: { event: EventlogEvent; zone: Zone; mode: "general" | "details"; setMode: (m: "general" | "details") => void; onOpen: () => void }) {
  const copy = (s: string) => void navigator.clipboard?.writeText(s);
  return (
    <Card
      title={`Event ${e.id}, ${e.provider}`}
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <Segmented<"general" | "details"> label="Detail view" value={mode} onChange={setMode} options={[{ value: "general", label: "General" }, { value: "details", label: "Details" }]} />
          <Button size="sm" onClick={() => copy(eventAsText(e, zone))} icon={<Copy className="size-4" aria-hidden />}>
            Copy
          </Button>
          <Button size="sm" onClick={() => copy(e.xml)}>
            Copy XML
          </Button>
        </div>
      }
    >
      {mode === "general" ? (
        <div className="flex flex-col gap-3 text-sm">
          {e.messageHidden ? (
            <Alert tone="info" title="Hidden">
              This event holds command lines or scripts, and its message repeats them: needs permission to see command lines and scripts.
            </Alert>
          ) : e.message ? (
            <pre className="whitespace-pre-wrap break-words font-sans">{e.message}</pre>
          ) : (
            <p className="text-muted">{e.messageNote ?? "No description."}</p>
          )}
          {e.message && e.messageNote && <p className="text-xs text-muted">{e.messageNote}</p>}
          {e.messageCut && <p className="text-xs text-muted">The message was cut to fit.</p>}
          {e.tooLarge && (
            <Alert tone="warn" title="Too large for the list">
              Only the event's System fields were sent.{" "}
              <button type="button" className="underline" onClick={onOpen}>
                Open it
              </button>
            </Alert>
          )}
          <KeyValueList
            items={[
              ["Log", e.log],
              ["Source", e.provider],
              ["Logged", eventTime(e, zone)],
              ["Event ID", String(e.id)],
              ["Level", levelName(e)],
              ["Task category", e.taskName ?? String(e.task)],
              ["Keywords", (e.keywordNames?.length ? e.keywordNames : [e.keywords]).join(", ")],
              ["User", e.user || e.userSid || "N/A"],
              ["Computer", e.computer],
            ]}
          />
        </div>
      ) : (
        <div className="flex flex-col gap-3 text-sm">
          <KeyValueList
            items={[
              ["Record", String(e.record)],
              ["Channel", e.channel],
              ["Version", String(e.version)],
              ["Opcode", e.opcodeName ?? String(e.opcode)],
              ["Process / thread", `${e.pid ?? 0} / ${e.tid ?? 0}`],
              ["Time as recorded (UTC)", e.time],
              ...(e.providerGuid ? ([["Provider GUID", e.providerGuid]] as [string, string][]) : []),
            ]}
          />
          {(e.data?.length ?? 0) > 0 && (
            <table className="w-full text-left text-xs" aria-label="Event data">
              <tbody>
                {e.data?.map((d, i) => (
                  <tr key={i} className="border-t border-line align-top">
                    <th className="w-1/3 px-2 py-1 font-medium">{d.path || d.name || `Value ${i + 1}`}</th>
                    <td className="px-2 py-1 break-all">{d.hidden ? <span className="text-muted">hidden: needs permission to see command lines and scripts</span> : d.value}{d.cut && <span className="text-muted"> (cut)</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {(e.dataDropped ?? 0) > 0 && <p className="text-xs text-muted">{e.dataDropped} more values were not sent.</p>}
          <pre aria-label="Event XML" className="max-h-80 overflow-auto rounded-md bg-raised p-2 text-xs break-all whitespace-pre-wrap">{e.xml}</pre>
        </div>
      )}
    </Card>
  );
}
