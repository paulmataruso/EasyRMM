import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Download, Pause, Play, ScrollText, Gauge } from "lucide-react";
import { api, apiUrl, errorMessage, fieldError } from "../../api/client";
import { useApiMutation } from "../../api/hooks";
import type { AgentLogLevel, AgentLogPage, AgentLogRecord, AgentLogSource, Device } from "../../api/types";
import { Dialog } from "../../components/Dialog";
import { MenuButton } from "../../components/Menu";
import { useToast } from "../../components/Toast";
import { Alert, Badge, Button, Card, cx, EmptyState, InlineError, Input, Select, SelectField, Spinner, type Tone } from "../../components/ui";
import { formatDateTime } from "../../lib/format";
import { clock, DEFAULT_VERBOSE_HOURS, LOG_LEVELS, LOG_SOURCES, LOG_SPANS, sourceName, VERBOSE_HOURS } from "./agentLogsText";

/** How many records one read brings, and how many the page keeps. */
const PAGE = 300;
const KEEP = 3000;
/** How often the live tail asks. The agent sends every 2 seconds while the tail is open. */
const LIVE_EVERY = 2000;

const LEVEL_TONE: Record<AgentLogLevel, Tone> = { debug: "neutral", info: "info", warn: "warn", error: "danger" };

interface Filters {
  source: "" | AgentLogSource;
  level: "" | AgentLogLevel;
  span: string;
  q: string;
}

const NO_FILTERS: Filters = { source: "", level: "", span: "any", q: "" };

function params(f: Filters, extra: Record<string, string | number | boolean> = {}): Record<string, string | number | boolean> {
  const p: Record<string, string | number | boolean> = { ...extra };
  if (f.source) p.source = f.source;
  if (f.level) p.level = f.level;
  if (f.q.trim()) p.q = f.q.trim();
  const span = LOG_SPANS.find((s) => s.value === f.span);
  if (span && span.minutes > 0) p.since = new Date(Date.now() - span.minutes * 60_000).toISOString();
  return p;
}

/**
 * A device's agent logs (ADR-0069): the EasyRMM agent's own records and the lines it read from the EasyPatch agent's
 * log and MeshAgent's. A live tail while the page is open (the agent then sends every 2 seconds), filters, verbose
 * logging for a few hours, and a download as text or JSON lines. Reading needs log.view; turning verbose logging on
 * needs device.edit.
 */
export function AgentLogsPanel({ device }: { device: Device }) {
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [live, setLive] = useState(true);
  const [rows, setRows] = useState<AgentLogRecord[]>([]);
  const [meta, setMeta] = useState<Pick<AgentLogPage, "verbose" | "retentionDays" | "online"> | null>(null);
  const [more, setMore] = useState(false);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<unknown>(null);
  const [verboseOpen, setVerboseOpen] = useState(false);
  const toast = useToast();
  const path = `/devices/${device.id}/agent-logs`;
  const newest = useRef(0);
  const scroller = useRef<HTMLDivElement>(null);
  const pinned = useRef(true);

  // A new set of filters starts over with the newest records.
  const filtersKey = JSON.stringify(filters);
  useEffect(() => {
    const ctl = new AbortController();
    setState("loading");
    api
      .get<AgentLogPage>(path, params(filters, { limit: PAGE, follow: live }), ctl.signal)
      .then((page) => {
        newest.current = page.items.at(-1)?.id ?? 0;
        setRows(page.items);
        setMore(page.more);
        setMeta({ verbose: page.verbose, retentionDays: page.retentionDays, online: page.online });
        setState("ready");
      })
      .catch((e: unknown) => {
        if (ctl.signal.aborted) return;
        setError(e);
        setState("error");
      });
    return () => ctl.abort();
  }, [path, filtersKey]);

  // The live tail: what is newer than the last record, every 2 seconds. Asking with follow tells the server
  // someone is watching, so that the agent sends often.
  useEffect(() => {
    if (!live || state !== "ready") return;
    const ctl = new AbortController();
    const timer = window.setInterval(() => {
      api
        .get<AgentLogPage>(path, params(filters, { after: newest.current, limit: PAGE, follow: true }), ctl.signal)
        .then((page) => {
          setMeta({ verbose: page.verbose, retentionDays: page.retentionDays, online: page.online });
          if (page.items.length === 0) return;
          newest.current = page.items.at(-1)?.id ?? newest.current;
          setRows((old) => [...old, ...page.items].slice(-KEEP));
        })
        .catch(() => undefined); // the next tick asks again
    }, LIVE_EVERY);
    return () => {
      ctl.abort();
      window.clearInterval(timer);
    };
  }, [live, state, path, filtersKey]);

  // Stay at the bottom while records arrive, unless the reader scrolled up.
  useEffect(() => {
    const el = scroller.current;
    if (el && pinned.current) el.scrollTop = el.scrollHeight;
  }, [rows]);

  const earlier = useCallback(() => {
    const before = rows[0]?.id;
    if (!before) return;
    api
      .get<AgentLogPage>(path, params(filters, { before, limit: PAGE }))
      .then((page) => {
        setRows((old) => [...page.items, ...old].slice(-KEEP));
        setMore(page.more);
        pinned.current = false;
      })
      .catch((e: unknown) => toast.error(errorMessage(e)));
  }, [rows, path, filters, toast]);

  const stop = useApiMutation(
    () => (meta?.verbose?.scope === "group" ? api.del(`/device-groups/${meta.verbose.groupId}/agent-logs/verbose`) : api.del(`${path}/verbose`)),
    {
      onSuccess: () => {
        toast.success("Verbose logging turned off.");
        setMeta((m) => (m ? { ...m, verbose: null } : m));
      },
    },
  );

  const download = (format: "text" | "jsonl") => {
    const a = document.createElement("a");
    a.href = apiUrl(`${path}/download`, params(filters, { format }));
    a.download = "";
    document.body.append(a);
    a.click();
    a.remove();
  };

  const set = <K extends keyof Filters>(k: K, v: Filters[K]) => setFilters((f) => ({ ...f, [k]: v }));
  const filtered = JSON.stringify(filters) !== JSON.stringify(NO_FILTERS);

  return (
    <div className="flex flex-col gap-4">
      <Card
        title="Agent logs"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              aria-pressed={live}
              icon={live ? <Pause className="size-4" aria-hidden /> : <Play className="size-4" aria-hidden />}
              onClick={() => setLive((v) => !v)}
            >
              {live ? "Pause live tail" : "Resume live tail"}
            </Button>
            {device.canUpdateAgent && (
              <Button size="sm" icon={<Gauge className="size-4" aria-hidden />} onClick={() => setVerboseOpen(true)}>
                Verbose for…
              </Button>
            )}
            <MenuButton
              size="sm"
              label="Download logs"
              icon={<Download className="size-4" aria-hidden />}
              items={[
                { id: "text", label: "As text (.log)", onSelect: () => download("text") },
                { id: "jsonl", label: "As JSON lines (.jsonl)", onSelect: () => download("jsonl") },
              ]}
            >
              Download
            </MenuButton>
          </div>
        }
      >
        <div className="mb-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <Select aria-label="Source" value={filters.source} onChange={(e) => set("source", e.target.value as Filters["source"])}>
            <option value="">All sources</option>
            {LOG_SOURCES.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </Select>
          <Select aria-label="Level" value={filters.level} onChange={(e) => set("level", e.target.value as Filters["level"])}>
            <option value="">All levels</option>
            {LOG_LEVELS.map((l) => (
              <option key={l.value} value={l.value}>
                {l.label}
              </option>
            ))}
          </Select>
          <Select aria-label="Time" value={filters.span} onChange={(e) => set("span", e.target.value)}>
            {LOG_SPANS.map((s) => (
              <option key={s.value} value={s.value}>
                {s.label}
              </option>
            ))}
          </Select>
          <Input type="search" aria-label="Search the logs" placeholder="Search messages and details" maxLength={200} value={filters.q} onChange={(e) => set("q", e.target.value)} />
        </div>

        <Status device={device} meta={meta} live={live} onStop={() => stop.mutate(undefined)} stopping={stop.isPending} />
        {stop.isError && <InlineError error={stop.error} />}

        {state === "loading" && <Spinner />}
        {state === "error" && <Alert tone="danger">{errorMessage(error)}</Alert>}
        {state === "ready" && rows.length === 0 && (
          <EmptyState title={filtered ? "No records match" : "No logs yet"} icon={<ScrollText className="size-8" aria-hidden />}>
            {filtered
              ? "Change or clear the filters to see more."
              : meta?.online === false
                ? "The device is offline. Its logs arrive when its agent reports again."
                : "The agent sends its log every 30 seconds, and every 2 seconds while this page is open."}
          </EmptyState>
        )}
        {state === "ready" && rows.length > 0 && (
          <div
            ref={scroller}
            role="log"
            aria-label="Agent log records"
            aria-live="off"
            tabIndex={0}
            onScroll={(e) => {
              const el = e.currentTarget;
              pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
            }}
            className="max-h-[32rem] overflow-auto rounded-md border border-line bg-raised font-mono text-xs leading-5"
          >
            {more && (
              <div className="sticky top-0 border-b border-line bg-raised p-1.5 text-center">
                <Button size="sm" onClick={earlier}>
                  Load earlier records
                </Button>
              </div>
            )}
            {rows.map((r) => (
              <LogRow key={r.id} r={r} />
            ))}
          </div>
        )}
        <p className="mt-3 text-xs text-muted">
          Kept for {meta?.retentionDays ?? 14} days. Secrets such as tokens and passwords are removed on the device and again on the server.
        </p>
      </Card>
      {verboseOpen && <VerboseDialog device={device} onClose={() => setVerboseOpen(false)} onDone={(until, scope) => setMeta((m) => (m ? { ...m, verbose: { until, scope } } : m))} />}
    </div>
  );
}

function LogRow({ r }: { r: AgentLogRecord }) {
  const attrs = Object.entries(r.attrs ?? {});
  return (
    <div className={cx("flex gap-2 border-b border-line/50 px-2 py-0.5 last:border-b-0", r.level === "error" && "bg-danger-soft/40")}>
      <time dateTime={r.time} title={formatDateTime(r.time)} className="shrink-0 text-muted tabular-nums">
        {clock(r.time)}
      </time>
      <span className="w-14 shrink-0">
        <Badge tone={LEVEL_TONE[r.level]}>{r.level}</Badge>
      </span>
      <span className="w-28 shrink-0 truncate text-muted" title={sourceName(r.source)}>
        {sourceName(r.source)}
      </span>
      <span className="min-w-0 flex-1 whitespace-pre-wrap break-words">
        {r.message}
        {attrs.length > 0 && <span className="text-muted">{attrs.map(([k, v]) => ` ${k}=${JSON.stringify(v)}`).join("")}</span>}
      </span>
    </div>
  );
}

function Status({ device, meta, live, onStop, stopping }: {
  device: Device;
  meta: Pick<AgentLogPage, "verbose" | "online"> | null;
  live: boolean;
  onStop: () => void;
  stopping: boolean;
}) {
  const v = meta?.verbose ?? null;
  return (
    <div className="mb-3 flex flex-col gap-2">
      {v && (
        <Alert tone="info" title="Verbose logging is on">
          <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>
              Until {formatDateTime(v.until)}, set on {v.scope === "group" ? `the group ${device.deviceGroupName ?? ""}`.trim() : "this device"}. The agent then returns to Info by itself.
            </span>
            {device.canUpdateAgent && (
              <Button size="sm" onClick={onStop} loading={stopping}>
                Turn off
              </Button>
            )}
          </span>
        </Alert>
      )}
      {meta && !meta.online && (
        <Alert tone="warn">This device is offline. Records already sent are shown; new ones arrive when its agent reports again.</Alert>
      )}
      <p className="text-xs text-muted" aria-live="polite">
        {live ? "Live: the page asks every 2 seconds, and the agent sends as often while it is open." : "Paused: nothing new is shown."}
      </p>
    </div>
  );
}

function VerboseDialog({ device, onClose, onDone }: { device: Device; onClose: () => void; onDone: (until: string, scope: "device" | "group") => void }) {
  const toast = useToast();
  const [hours, setHours] = useState(DEFAULT_VERBOSE_HOURS);
  const [scope, setScope] = useState<"device" | "group">("device");
  const start = useApiMutation(
    () =>
      api.put<{ until: string }>(scope === "group" && device.deviceGroupId ? `/device-groups/${device.deviceGroupId}/agent-logs/verbose` : `/devices/${device.id}/agent-logs/verbose`, { hours }),
    {
      onSuccess: (r) => {
        toast.success(`Verbose logging is on until ${formatDateTime(r.until)}.`);
        onDone(r.until, scope);
        onClose();
      },
    },
  );
  function submit(e: FormEvent) {
    e.preventDefault();
    start.mutate(undefined);
  }
  return (
    <Dialog
      open
      onClose={onClose}
      title="Verbose logging"
      description="The EasyRMM agent logs at Debug for a while, which shows more of what it does. It returns to Info by itself, and turning it on is recorded in the audit log."
    >
      <form onSubmit={submit} noValidate className="flex flex-col gap-3.5">
        <SelectField label="For" value={String(hours)} onChange={(e) => setHours(Number(e.target.value))} error={fieldError(start.error, "hours")}>
          {VERBOSE_HOURS.map((h) => (
            <option key={h} value={h}>
              {h === 1 ? "1 hour" : `${h} hours`}
              {h === DEFAULT_VERBOSE_HOURS ? " (default)" : ""}
            </option>
          ))}
        </SelectField>
        {device.deviceGroupId && (
          <SelectField label="On" value={scope} onChange={(e) => setScope(e.target.value as "device" | "group")} hint="A group's setting covers every device in it, including ones added meanwhile.">
            <option value="device">{device.name} only</option>
            <option value="group">Every device in {device.deviceGroupName ?? "its group"}</option>
          </SelectField>
        )}
        <InlineError error={start.error} fields={["hours"]} />
        <div className="flex justify-end gap-2 border-t border-line pt-3">
          <Button onClick={onClose} disabled={start.isPending}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={start.isPending}>
            Turn on
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
