import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { History } from "lucide-react";
import { api, ApiError, errorMessage } from "../../api/client";
import type { CollectedLogEvent, CollectedLogPage, CollectedLogTimeline, Device } from "../../api/types";
import { Alert, Badge, Button, Card, cx, EmptyState, Input, Select, Spinner, type Tone } from "../../components/ui";
import { formatDateTime } from "../../lib/format";
import { COLLECTED_SPANS, collectedSourceName, DEFAULT_COLLECTED_SPAN, timelineBars, type TimelineBar } from "./collectedLogsText";

const PAGE = 200;

const LEVEL_TONE: Record<CollectedLogEvent["level"], Tone> = { debug: "neutral", info: "info", warn: "warn", error: "danger" };

interface Range {
  since: string;
  until: string;
}

/** The range of a preset, ending now. */
function presetRange(value: string): Range {
  const span = COLLECTED_SPANS.find((s) => s.value === value) ?? COLLECTED_SPANS[2];
  const until = new Date();
  return { since: new Date(until.getTime() - span.hours * 3_600_000).toISOString(), until: until.toISOString() };
}

/**
 * A device's collected logs (ADR-0060): what the log collector read from the computer's own logs (Windows event
 * channels, Linux's journal and auditd), kept by the server in its log store. A timeline of what the device logged by
 * the hour, a source filter, a search, and the events, newest first. Reading needs log.view; command lines and script
 * text appear only for holders of log.view_sensitive, and are searched only for them. A bar of the timeline narrows
 * the list to its hours.
 */
export function CollectedLogsPanel({ device }: { device: Device }) {
  const base = `/devices/${device.id}/collected-logs`;
  const [span, setSpan] = useState(DEFAULT_COLLECTED_SPAN);
  const [source, setSource] = useState("");
  const [draft, setDraft] = useState("");
  const [q, setQ] = useState("");
  // A bar the reader chose narrows the range; null means the preset's own.
  const [focus, setFocus] = useState<Range | null>(null);
  const [range, setRange] = useState<Range>(() => presetRange(DEFAULT_COLLECTED_SPAN));
  const [rows, setRows] = useState<CollectedLogEvent[]>([]);
  const [page, setPage] = useState<Pick<CollectedLogPage, "more" | "next" | "truncated" | "canSeeSensitive" | "sources"> | null>(null);
  const [timeline, setTimeline] = useState<CollectedLogTimeline | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<unknown>(null);
  const [loadingMore, setLoadingMore] = useState(false);

  // A new preset starts a range ending now; "Refresh" does too.
  const restart = (value: string) => {
    setSpan(value);
    setRange(presetRange(value));
    setFocus(null);
  };

  const active = focus ?? range;
  const filterKey = `${active.since}|${active.until}|${source}|${q}`;

  useEffect(() => {
    const ctl = new AbortController();
    setState("loading");
    const common = { since: active.since, until: active.until, ...(source ? { source } : {}) };
    Promise.all([
      api.get<CollectedLogPage>(base, { ...common, ...(q ? { q } : {}), limit: PAGE }, ctl.signal),
      api.get<CollectedLogTimeline>(`${base}/timeline`, { since: range.since, until: range.until, ...(source ? { source } : {}) }, ctl.signal),
    ])
      .then(([p, t]) => {
        setRows(p.items);
        setPage({ more: p.more, next: p.next, truncated: p.truncated, canSeeSensitive: p.canSeeSensitive, sources: p.sources });
        setTimeline(t);
        setState("ready");
      })
      .catch((e: unknown) => {
        if (ctl.signal.aborted) return;
        setError(e);
        setState("error");
      });
    return () => ctl.abort();
  }, [base, filterKey, range.since, range.until]);

  const older = useCallback(() => {
    if (!page?.next) return;
    setLoadingMore(true);
    api
      .get<CollectedLogPage>(base, { since: active.since, until: page.next, ...(source ? { source } : {}), ...(q ? { q } : {}), limit: PAGE })
      .then((p) => {
        setRows((old) => [...old, ...p.items]);
        setPage((old) => (old ? { ...old, more: p.more, next: p.next, truncated: p.truncated } : old));
      })
      .catch(() => undefined)
      .finally(() => setLoadingMore(false));
  }, [base, page, active.since, source, q]);

  const bars = useMemo(() => (timeline ? timelineBars(timeline.buckets, range.since, range.until) : []), [timeline, range.since, range.until]);

  const search = (e: FormEvent) => {
    e.preventDefault();
    setQ(draft.trim());
  };

  if (state === "error" && error instanceof ApiError && error.code === "logs_unavailable") {
    return (
      <Alert tone="warn" title="The log store is not available">
        EasyRMM works without it, but collected logs cannot be read or stored until it is back. Ask an administrator to check the log database.
      </Alert>
    );
  }

  const filtered = source !== "" || q !== "";
  return (
    <Card title="Collected logs" padded={false}>
      <p className="px-3 pt-1 pb-2 text-sm text-muted">What the collector read from this computer's own logs, kept by the server.</p>
      <form className="flex flex-wrap items-end gap-2 border-b border-line p-3" onSubmit={search} role="search">
        <Select aria-label="Time range" value={span} onChange={(e) => restart(e.target.value)}>
          {COLLECTED_SPANS.map((s) => (
            <option key={s.value} value={s.value}>
              {s.label}
            </option>
          ))}
        </Select>
        <Select aria-label="Source" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="">All sources</option>
          {(page?.sources ?? []).map((s) => (
            <option key={s} value={s}>
              {collectedSourceName(s)}
            </option>
          ))}
        </Select>
        <Input
          type="search"
          aria-label="Search collected logs"
          placeholder={page?.canSeeSensitive ? "Search messages, details and command lines" : "Search messages and details"}
          maxLength={200}
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          className="min-w-56 flex-1"
        />
        <Button type="submit">
          Search
        </Button>
        <Button type="button" variant="ghost" onClick={() => restart(span)}>
          Refresh
        </Button>
      </form>

      <Timeline bars={bars} focus={focus} onFocus={setFocus} />

      {state === "loading" && rows.length === 0 && (
        <div className="flex justify-center p-8">
          <Spinner label="Loading collected logs" />
        </div>
      )}
      {state === "error" && <Alert tone="danger">{errorMessage(error)}</Alert>}
      {state === "ready" && rows.length === 0 && (
        <EmptyState title={filtered || focus ? "No events match" : "No collected logs in this range"} icon={<History className="size-8" aria-hidden />}>
          {filtered || focus
            ? "Try another source or range, or clear the search."
            : "Logs appear here once the collector is installed on the device and has sent its first blocks."}
        </EmptyState>
      )}
      {rows.length > 0 && (
        <ul className="divide-y divide-line" aria-label="Collected log events">
          {rows.map((e, i) => (
            <EventRow key={`${e.time}-${e.source}-${i}`} event={e} />
          ))}
        </ul>
      )}
      {page?.truncated && (
        <Alert tone="info">This range holds more than one search can open. The newest events are shown: choose a shorter range or a source.</Alert>
      )}
      {page?.more && (
        <div className="flex justify-center p-3">
          <Button variant="secondary" onClick={older} loading={loadingMore}>
            Load older events
          </Button>
        </div>
      )}
    </Card>
  );
}

/** What the device logged by the hour: a bar each, warnings and errors in a stronger colour. */
function Timeline({ bars, focus, onFocus }: { bars: TimelineBar[]; focus: Range | null; onFocus: (r: Range | null) => void }) {
  const peak = Math.max(1, ...bars.map((b) => b.events));
  if (bars.length === 0) return null;
  return (
    <div className="border-b border-line px-3 py-2">
      <div className="mb-1 flex items-center justify-between text-xs text-subtle">
        <span>Events by time</span>
        {focus && (
          <button type="button" className="text-accent hover:underline" onClick={() => onFocus(null)}>
            Show the whole range
          </button>
        )}
      </div>
      <div className="flex h-16 items-end gap-px" role="group" aria-label="Events by time">
        {bars.map((b) => {
          const selected = focus?.since === b.start;
          return (
            <button
              key={b.start}
              type="button"
              className={cx("group relative flex h-full min-w-0 flex-1 items-end rounded-sm hover:bg-surface-2", selected && "bg-surface-2")}
              aria-label={`${formatDateTime(b.start)}: ${b.events} events${b.attention ? `, ${b.attention} warnings or errors` : ""}`}
              aria-pressed={selected}
              title={`${formatDateTime(b.start)}: ${b.events} events`}
              onClick={() => onFocus(selected ? null : { since: b.start, until: b.end })}
            >
              <span className="flex w-full flex-col justify-end" style={{ height: `${(b.events / peak) * 100}%`, minHeight: b.events ? 2 : 0 }}>
                <span className="w-full bg-warn" style={{ height: `${b.events ? (b.attention / b.events) * 100 : 0}%` }} />
                <span className="w-full flex-1 bg-accent/60" />
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function EventRow({ event: e }: { event: CollectedLogEvent }) {
  const [open, setOpen] = useState(false);
  const fields = Object.entries(e.fields ?? {});
  const sensitive = Object.entries(e.sensitive ?? {});
  const details = fields.length + sensitive.length > 0;
  return (
    <li className="px-3 py-2 text-sm">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <time className="font-mono text-xs text-subtle" dateTime={e.time}>
          {new Date(e.time).toLocaleString()}
        </time>
        <Badge tone={LEVEL_TONE[e.level]}>{e.level}</Badge>
        <span className="text-xs text-subtle">{collectedSourceName(e.source)}</span>
        {e.id && <span className="font-mono text-xs text-subtle">{e.id}</span>}
        <span className="min-w-0 flex-1 break-words text-fg">{e.message}</span>
        {details && (
          <button type="button" className="text-xs text-accent hover:underline" aria-expanded={open} onClick={() => setOpen((v) => !v)}>
            {open ? "Hide details" : "Details"}
          </button>
        )}
      </div>
      {open && (
        <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 rounded-md bg-surface-2 p-2 font-mono text-xs">
          {fields.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-subtle">{k}</dt>
              <dd className="break-all">{v}</dd>
            </div>
          ))}
          {sensitive.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-subtle">{k}</dt>
              <dd className="break-all">{v}</dd>
            </div>
          ))}
        </dl>
      )}
    </li>
  );
}
