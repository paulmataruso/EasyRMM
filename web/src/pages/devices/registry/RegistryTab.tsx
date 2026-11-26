import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { ChevronDown, ChevronRight, Download, FolderTree, Link2, Lock, RefreshCw, Search } from "lucide-react";
import { apiUrl, errorMessage } from "../../../api/client";
import type { Device, RegistryHive, RegistryQuery, RegistryResult, RegistryValue, RegistryView } from "../../../api/types";
import { Alert, Badge, Button, Card, cx, EmptyState, Input, Segmented, Spinner, TableWrap } from "../../../components/ui";
import { formatDateTime, formatRelative } from "../../../lib/format";
import { HIVE_NAMES, locationKey, locationText, same, STATE_TEXT, stoppedText, typeName, valueData, valueName, viewName, type Location } from "./registryText";
import { startQuery } from "./runQuery";

/** The roots the tree offers. HKEY_CLASSES_ROOT is the computer's part, as ADR-0067 says; HKEY_CURRENT_USER asks which user. */
const ROOTS: { id: string; label: string; hive: RegistryHive | "HKCU" }[] = [
  { id: "HKLM", label: HIVE_NAMES.HKLM, hive: "HKLM" },
  { id: "HKU", label: HIVE_NAMES.HKU, hive: "HKU" },
  { id: "HKCR", label: "HKEY_CLASSES_ROOT (the computer's part)", hive: "HKCR" },
  { id: "HKCC", label: HIVE_NAMES.HKCC, hive: "HKCC" },
  { id: "HKCU", label: "HKEY_CURRENT_USER (choose a user)", hive: "HKCU" },
];

interface Loaded {
  result: RegistryResult;
}

/**
 * A Windows device's registry (ADR-0067): a tree of keys and a list of values, an address bar, search and export.
 * Every read is a job the agent runs as a builtin; the page follows it and says when it was read. Needs registry.view.
 */
export function RegistryPanel({ device }: { device: Device }) {
  const [view, setView] = useState<RegistryView>("64");
  const [selected, setSelected] = useState<Location | null>(null);
  const [address, setAddress] = useState("");
  const [loaded, setLoaded] = useState<Record<string, Loaded>>({});
  const [busy, setBusy] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [filter, setFilter] = useState("");
  const [term, setTerm] = useState("");
  const [found, setFound] = useState<{ result: RegistryResult; at: Location; term: string } | null>(null);
  const [searching, setSearching] = useState(false);
  const [exporting, setExporting] = useState(false);
  const open = useRef<string | null>(null);

  const cacheKey = useCallback((l: Location) => `${view}|${locationKey(l)}`, [view]);

  const queryOf = useCallback((l: Location, extra: Partial<RegistryQuery> = {}): RegistryQuery => ({ op: "list", view, hive: l.hive, path: l.path, ...extra }), [view]);

  /** Reads one key and keeps what came back; a read that is no longer wanted is canceled if it has not started. */
  const load = useCallback(
    async (l: Location, force = false) => {
      const key = cacheKey(l);
      if (!force && loaded[key]) return;
      setBusy((b) => ({ ...b, [key]: true }));
      setError(null);
      try {
        const { run, result } = await startQuery(device.id, queryOf(l));
        open.current = run.runId;
        const r = await result;
        setLoaded((m) => ({ ...m, [key]: { result: r } }));
      } catch (e) {
        setError(errorMessage(e));
      } finally {
        setBusy((b) => ({ ...b, [key]: false }));
      }
    },
    [cacheKey, device.id, loaded, queryOf],
  );

  // A new view is another set of keys: start again from the same place.
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    if (selected) void load(selected, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view]);

  const select = (l: Location) => {
    setSelected(l);
    setAddress(locationText(l));
    setFilter("");
    void load(l);
  };

  const go = async (e: FormEvent) => {
    e.preventDefault();
    if (!address.trim()) return;
    setError(null);
    try {
      const { run, result } = await startQuery(device.id, { op: "list", view, text: address.trim() });
      const loc: Location = { hive: run.hive, path: run.path };
      setSelected(loc);
      setAddress(locationText(loc));
      setBusy((b) => ({ ...b, [cacheKey(loc)]: true }));
      const r = await result;
      setLoaded((m) => ({ ...m, [cacheKey(loc)]: { result: r } }));
      setBusy((b) => ({ ...b, [cacheKey(loc)]: false }));
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  const current = selected ? loaded[cacheKey(selected)]?.result : undefined;
  const loadingNow = selected ? busy[cacheKey(selected)] === true : false;
  const values = useMemo(() => {
    const all = current?.values ?? [];
    const f = filter.trim().toLowerCase();
    return f ? all.filter((v) => valueName(v).toLowerCase().includes(f) || valueData(v).toLowerCase().includes(f)) : all;
  }, [current, filter]);

  const readValue = async (v: RegistryValue) => {
    if (!selected) return;
    setError(null);
    try {
      const { result } = await startQuery(device.id, queryOf(selected, { op: "value", valueName: v.name }));
      const r = await result;
      const one = r.values?.[0];
      if (!one) return;
      setLoaded((m) => {
        const k = cacheKey(selected);
        const cur = m[k];
        if (!cur) return m;
        return { ...m, [k]: { result: { ...cur.result, values: cur.result.values?.map((x) => (x.name === v.name ? one : x)) } } };
      });
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  const search = async (e: FormEvent) => {
    e.preventDefault();
    if (!selected || !term.trim()) return;
    setSearching(true);
    setError(null);
    try {
      const { result } = await startQuery(device.id, queryOf(selected, { op: "search", term: term.trim() }));
      setFound({ result: await result, at: selected, term: term.trim() });
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSearching(false);
    }
  };

  const exportKey = async (format: "reg" | "json") => {
    if (!selected) return;
    setExporting(true);
    setError(null);
    try {
      const { run, result } = await startQuery(device.id, queryOf(selected, { op: "export" }));
      const r = await result;
      if (r.state !== "reported") throw new Error(r.reason || STATE_TEXT[r.state]);
      if (!r.complete) throw new Error("The export did not finish: export a smaller key.");
      const a = document.createElement("a");
      a.href = apiUrl(`/job-runs/${run.runId}/export`, { format });
      a.download = "";
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setExporting(false);
    }
  };

  const offline = !device.online;

  return (
    <div className="flex flex-col gap-4">
      <Card padded>
        <div className="flex flex-col gap-3" role="group" aria-label="Registry header">
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <span className="font-medium">{device.name}</span>
            <span className="text-muted">
              {device.organizationName} / {device.siteName}
            </span>
            <Badge tone={device.online ? "ok" : "warn"}>{device.online ? "Online" : "Offline"}</Badge>
            <Badge tone="info" title={view === "32" ? "The x86 view: keys under HKEY_LOCAL_MACHINE\\SOFTWARE are under WOW6432Node" : "The machine's own view"}>
              {viewName(view)}
            </Badge>
            {current?.key && (
              <span className="text-muted" title={current.key.kernel}>
                Physical key <code className="break-all">{current.key.kernel}</code>
              </span>
            )}
            {current?.readAt && (
              <span className="ml-auto text-muted" title={formatDateTime(current.readAt)}>
                Read at {new Date(current.readAt).toLocaleTimeString("en-GB")}
              </span>
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Segmented<RegistryView>
              label="Registry view"
              value={view}
              onChange={setView}
              options={[
                { value: "64", label: "64-bit" },
                { value: "32", label: "32-bit" },
              ]}
            />
            <form className="flex min-w-0 flex-1 gap-2" onSubmit={(e) => void go(e)}>
              <Input aria-label="Address" className="min-w-0 flex-1 font-mono" placeholder="HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft" value={address} onChange={(e) => setAddress(e.target.value)} disabled={offline} />
              <Button type="submit" disabled={offline || !address.trim()}>
                Go
              </Button>
            </form>
            <Button onClick={() => selected && void load(selected, true)} disabled={offline || !selected || loadingNow} icon={<RefreshCw className="size-4" aria-hidden />}>
              Refresh
            </Button>
          </div>
          {offline && (
            <Alert tone="warn" title="This device is offline">
              Last seen {device.lastSeenAt ? formatRelative(device.lastSeenAt) : "never"}. No reads are sent while it is offline.
            </Alert>
          )}
          {error && (
            <Alert tone="danger" title="The registry could not be read">
              {error}
            </Alert>
          )}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="Keys" padded={false} className="lg:col-span-1">
          <div role="tree" aria-label="Registry keys" className="max-h-[32rem] overflow-auto p-2 text-sm">
            {ROOTS.map((r) =>
              r.hive === "HKCU" ? (
                <UserRoots key={r.id} label={r.label} deviceId={device.id} view={view} offline={offline} selected={selected} onSelect={select} />
              ) : (
                <KeyNode
                  key={r.id}
                  label={r.label}
                  loc={{ hive: r.hive, path: [] }}
                  depth={0}
                  view={view}
                  loaded={loaded}
                  busy={busy}
                  expanded={expanded}
                  setExpanded={setExpanded}
                  selected={selected}
                  onSelect={select}
                  load={load}
                  offline={offline}
                />
              ),
            )}
          </div>
        </Card>

        <div className="flex min-w-0 flex-col gap-4 lg:col-span-2">
          <Card
            title={selected ? locationText(selected) : "Values"}
            actions={
              selected && (
                <div className="flex flex-wrap items-center gap-2">
                  <Button size="sm" onClick={() => void exportKey("reg")} disabled={offline || exporting} icon={<Download className="size-4" aria-hidden />}>
                    Export .reg
                  </Button>
                  <Button size="sm" onClick={() => void exportKey("json")} disabled={offline || exporting}>
                    Export JSON
                  </Button>
                </div>
              )
            }
            padded={false}
          >
            {!selected && <EmptyState compact title="Choose a key" icon={<FolderTree className="size-5" aria-hidden />}>Open a hive on the left, or type a path above.</EmptyState>}
            {selected && loadingNow && !current && <Spinner label="Reading the key…" className="p-4" />}
            {selected && current && <ResultBody result={current} filter={filter} setFilter={setFilter} values={values} onOpen={(name) => select({ hive: selected.hive, path: [...selected.path, name] })} readValue={(v) => void readValue(v)} />}
          </Card>

          {selected && (
            <Card title="Search">
              <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => void search(e)}>
                <Input aria-label="Search term" className="min-w-0 flex-1" placeholder="Part of a key name, value name or text" maxLength={256} value={term} onChange={(e) => setTerm(e.target.value)} disabled={offline} />
                <Button type="submit" disabled={offline || searching || !term.trim()} icon={<Search className="size-4" aria-hidden />}>
                  Search below this key
                </Button>
              </form>
              {searching && <Spinner label="Searching…" className="mt-3" />}
              {found && !searching && <SearchResults found={found} onOpen={(path) => select({ hive: found.at.hive, path })} />}
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function ResultBody({ result, filter, setFilter, values, onOpen, readValue }: { result: RegistryResult; filter: string; setFilter: (s: string) => void; values: RegistryValue[]; onOpen: (name: string) => void; readValue: (v: RegistryValue) => void }) {
  if (result.state !== "reported" && result.state !== "unknown") {
    return (
      <div className="p-4">
        <Alert tone={result.state === "refused" ? "warn" : "info"} title={STATE_TEXT[result.state]}>
          {result.reason}
        </Alert>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-3 p-3">
      {result.state === "unknown" && (
        <Alert tone="warn" title={STATE_TEXT.unknown}>
          {result.reason}
        </Alert>
      )}
      {(result.subkeys?.length ?? 0) > 0 && (
        <ul aria-label="Subkeys" className="flex flex-wrap gap-1.5">
          {result.subkeys?.map((s) => (
            <li key={s.name}>
              <button
                type="button"
                className={cx("inline-flex items-center gap-1 rounded-md border border-line px-2 py-1 text-xs hover:bg-hover", s.state === "refused" && "opacity-60")}
                disabled={s.state === "refused" || s.state === "denied"}
                onClick={() => onOpen(s.name)}
                title={s.state === "link" ? `Link to ${s.target}` : s.rule ? `Refused by EasyRMM: ${s.rule}` : s.state === "denied" ? "Access denied" : undefined}
              >
                {s.state === "link" && <Link2 className="size-3" aria-hidden />}
                {s.state === "refused" && <Lock className="size-3" aria-hidden />}
                {s.label ? `${s.name} (${s.label}, loaded)` : s.name}
                {s.state === "refused" && <span className="text-muted">Refused by EasyRMM</span>}
                {s.state === "denied" && <span className="text-muted">access denied</span>}
                {s.state === "link" && <span className="text-muted">link</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
      {result.end?.moreSubkeys && <p className="text-xs text-muted">More subkeys than one page shows; use the address bar or search.</p>}
      <div className="flex items-center gap-2">
        <Input aria-label="Filter the values shown" className="max-w-xs" placeholder="Filter the values shown" value={filter} onChange={(e) => setFilter(e.target.value)} />
        <span className="text-xs text-muted">{result.key ? `${result.key.values.toLocaleString("en-US")} values, ${result.key.subkeys.toLocaleString("en-US")} subkeys` : ""}</span>
      </div>
      <TableWrap>
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="text-xs text-muted">
              <th className="py-1 pr-3">Name</th>
              <th className="py-1 pr-3">Type</th>
              <th className="py-1">Data</th>
            </tr>
          </thead>
          <tbody>
            {values.map((v) => (
              <tr key={v.name} className="border-t border-line align-top">
                <td className="py-1 pr-3 font-mono break-all">{valueName(v)}</td>
                <td className="py-1 pr-3 whitespace-nowrap">{typeName(v.type)}</td>
                <td className="py-1 font-mono break-all">
                  {v.masked ? <Badge tone="neutral" icon={<Lock className="size-3" aria-hidden />}>Masked</Badge> : valueData(v)}
                  {v.noData && !v.denied && (
                    <Button size="sm" className="ml-2" onClick={() => readValue(v)}>
                      Read
                    </Button>
                  )}
                  {v.cut && <span className="ml-1 text-xs text-muted">(cut)</span>}
                </td>
              </tr>
            ))}
            {values.length === 0 && (
              <tr>
                <td colSpan={3} className="py-3 text-center text-muted">
                  {filter ? "No value matches the filter." : "This key has no values."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </TableWrap>
      {result.end?.moreValues && <p className="text-xs text-muted">More values than one page shows.</p>}
    </div>
  );
}

function SearchResults({ found, onOpen }: { found: { result: RegistryResult; at: Location; term: string }; onOpen: (path: string[]) => void }) {
  const r = found.result;
  if (r.state !== "reported" && r.state !== "unknown") {
    return <p className="mt-3 text-sm text-muted">{r.reason || STATE_TEXT[r.state]}</p>;
  }
  const matches = r.matches ?? [];
  return (
    <div className="mt-3 flex flex-col gap-2 text-sm">
      <p className="text-muted">
        {matches.length.toLocaleString("en-US")} {matches.length === 1 ? "match" : "matches"} for “{found.term}”
        {r.end?.visited ? ` in ${r.end.visited.toLocaleString("en-US")} keys` : ""}.
        {r.end?.stoppedBy && (
          <>
            {" "}
            Stopped at {stoppedText(r.end.stoppedBy)}
            {r.end.firstUnvisited ? <>; the first key it did not visit: <code>{r.end.firstUnvisited.join("\\")}</code></> : ""}.
          </>
        )}
      </p>
      <ul aria-label="Search matches" className="max-h-72 overflow-auto">
        {matches.map((m, i) => (
          <li key={i} className="flex flex-wrap items-baseline gap-2 border-t border-line py-1">
            <Badge tone="neutral">{m.kind === "key" ? "Key name" : m.kind === "valueName" ? "Value name" : m.kind === "data" ? "Data" : "Link, not followed"}</Badge>
            <button type="button" className="font-mono text-xs break-all text-accent hover:underline" onClick={() => onOpen(m.path)}>
              {m.path.join("\\") || "(the key searched)"}
            </button>
            {m.name !== undefined && m.kind !== "key" && m.kind !== "link" && <span className="font-mono text-xs">{m.name === "" ? "(Default)" : m.name}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

function KeyNode(props: {
  label: string;
  loc: Location;
  depth: number;
  view: RegistryView;
  loaded: Record<string, Loaded>;
  busy: Record<string, boolean>;
  expanded: Record<string, boolean>;
  setExpanded: (f: (e: Record<string, boolean>) => Record<string, boolean>) => void;
  selected: Location | null;
  onSelect: (l: Location) => void;
  load: (l: Location, force?: boolean) => Promise<void>;
  offline: boolean;
  state?: "link" | "denied" | "refused" | "";
  rule?: string;
}) {
  const { label, loc, depth, view, loaded, busy, expanded, setExpanded, selected, onSelect, load, offline, state, rule } = props;
  const key = `${view}|${locationKey(loc)}`;
  const isOpen = expanded[key] === true;
  const result = loaded[key]?.result;
  const blocked = state === "refused" || state === "denied";
  const toggle = () => {
    setExpanded((e) => ({ ...e, [key]: !isOpen }));
    if (!isOpen && !loaded[key] && !offline) void load(loc);
  };
  return (
    <div role="none">
      <div role="treeitem" aria-expanded={isOpen} aria-selected={selected !== null && same(selected, loc)} className="flex items-center" style={{ paddingLeft: depth * 12 }}>
        <button type="button" className="p-1 text-muted" aria-label={isOpen ? `Collapse ${label}` : `Expand ${label}`} onClick={toggle} disabled={blocked || offline}>
          {isOpen ? <ChevronDown className="size-4" aria-hidden /> : <ChevronRight className="size-4" aria-hidden />}
        </button>
        <button
          type="button"
          className={cx("min-w-0 flex-1 truncate rounded px-1.5 py-0.5 text-left hover:bg-hover", selected && same(selected, loc) && "bg-hover font-medium", blocked && "opacity-60")}
          onClick={() => {
            if (!offline) onSelect(loc);
          }}
          disabled={blocked || offline}
          title={rule ? `Refused by EasyRMM: ${rule}` : state === "denied" ? "Access denied" : state === "link" ? "A link: opened only where it stays in the same hive and passes the refusals" : label}
        >
          {label}
          {state === "refused" && <span className="ml-1 text-xs text-muted">Refused by EasyRMM</span>}
        </button>
        {busy[key] && <Spinner label="Reading…" className="size-4" />}
      </div>
      {isOpen && result?.subkeys && (
        <div role="group">
          {result.subkeys.map((s) => (
            <KeyNode key={s.name} {...props} label={s.label ? `${s.name} (${s.label})` : s.name} loc={{ hive: loc.hive, path: [...loc.path, s.name] }} depth={depth + 1} state={s.state} rule={s.rule} />
          ))}
        </div>
      )}
    </div>
  );
}

/** HKEY_CURRENT_USER: the SYSTEM account's hive is not the user's, so a loaded user hive is chosen under HKEY_USERS. */
function UserRoots({ label, deviceId, view, offline, selected, onSelect }: { label: string; deviceId: string; view: RegistryView; offline: boolean; selected: Location | null; onSelect: (l: Location) => void }) {
  const [open, setOpen] = useState(false);
  const [users, setUsers] = useState<{ sid: string; label?: string }[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const toggle = async () => {
    setOpen(!open);
    if (open || users || offline) return;
    try {
      const { result } = await startQuery(deviceId, { op: "list", view, hive: "HKU", path: [] });
      const r = await result;
      setUsers((r.subkeys ?? []).filter((s) => !s.name.toUpperCase().endsWith("_CLASSES") && s.state !== "refused").map((s) => ({ sid: s.name, label: s.label })));
    } catch (e) {
      setErr(errorMessage(e));
    }
  };
  return (
    <div role="none">
      <div role="treeitem" aria-expanded={open} className="flex items-center">
        <button type="button" className="p-1 text-muted" aria-label={open ? `Collapse ${label}` : `Expand ${label}`} onClick={() => void toggle()} disabled={offline}>
          {open ? <ChevronDown className="size-4" aria-hidden /> : <ChevronRight className="size-4" aria-hidden />}
        </button>
        <span className="px-1.5 py-0.5">{label}</span>
      </div>
      {open && (
        <div role="group" className="pl-6">
          {err && <p className="text-xs text-danger">{err}</p>}
          {users?.length === 0 && <p className="text-xs text-muted">No user hive is loaded.</p>}
          {users?.map((u) => (
            <button
              key={u.sid}
              type="button"
              className={cx("block w-full truncate rounded px-1.5 py-0.5 text-left hover:bg-hover", selected?.hive === "HKU" && selected.path[0] === u.sid && "bg-hover font-medium")}
              onClick={() => onSelect({ hive: "HKU", path: [u.sid] })}
            >
              {u.label ? `${u.label}, loaded` : `${u.sid}, loaded`}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
