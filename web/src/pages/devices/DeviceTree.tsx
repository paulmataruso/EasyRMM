import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router";
import { Building2, ChevronRight, ChevronsDownUp, ListTree, MapPin, Monitor, PanelRightClose, PanelRightOpen, Search, X } from "lucide-react";
import { useList, useOrganizations, usePrefetch, useSites } from "../../api/hooks";
import type { Device } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Button, cx, Dot, ErrorState, IconButton, Input, Spinner } from "../../components/ui";
import { plural } from "../../lib/format";
import { platformName } from "./platform";
import { ancestors, buildTree, filterTree, indexTree, initialExpanded, selectedKey, visibleRows, type TreeNode } from "./tree";

/**
 * The device tree dock: organizations, sites and devices on the right of the devices pages. On wide screens it
 * docks beside the page and stays open (remembered in this browser) while moving between the list and devices; on
 * narrow screens it opens over the page and closes after each choice.
 */

const STORAGE_KEY = "easyrmm.deviceTree";
const TOGGLE_ID = "device-tree-toggle";
const DOCK_ID = "device-tree";
/** Tailwind's lg breakpoint, where the sidebar docks too. */
const WIDE = "(min-width: 64rem)";

interface DeviceTreeState {
  open: boolean;
  overlay: boolean;
  toggle: () => void;
  close: () => void;
}

const DeviceTreeContext = createContext<DeviceTreeState | null>(null);

function readDocked(): boolean {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "open";
  } catch {
    return false;
  }
}

function storeDocked(open: boolean) {
  try {
    if (open) window.localStorage.setItem(STORAGE_KEY, "open");
    else window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage unavailable: the dock still opens for this page view.
  }
}

function useMediaQuery(query: string): boolean {
  const supported = typeof window.matchMedia === "function";
  const [matches, setMatches] = useState(() => (supported ? window.matchMedia(query).matches : true));
  useEffect(() => {
    if (!supported) return;
    const list = window.matchMedia(query);
    const onChange = () => setMatches(list.matches);
    onChange();
    list.addEventListener("change", onChange);
    return () => list.removeEventListener("change", onChange);
  }, [query, supported]);
  return matches;
}

/** Whether the page at this path shows the device tree. */
export function isDeviceTreeRoute(pathname: string): boolean {
  return pathname === "/devices" || /^\/devices\/(?!add$)[^/]+$/.test(pathname);
}

export function DeviceTreeProvider({ children }: { children: ReactNode }) {
  const wide = useMediaQuery(WIDE);
  const [docked, setDocked] = useState(readDocked);
  const [overlay, setOverlay] = useState(false);
  const location = useLocation();

  // Over the page, the tree is a way to get somewhere: it closes once the reader has gone there.
  useEffect(() => setOverlay(false), [location.pathname, location.search]);

  const value = useMemo<DeviceTreeState>(() => {
    const open = wide ? docked : overlay;
    const set = (next: boolean) => {
      if (wide) {
        setDocked(next);
        storeDocked(next);
      } else {
        setOverlay(next);
      }
    };
    return { open, overlay: !wide, toggle: () => set(!open), close: () => set(false) };
  }, [wide, docked, overlay]);

  return <DeviceTreeContext.Provider value={value}>{children}</DeviceTreeContext.Provider>;
}

/** The page-header button that shows and hides the tree. */
export function DeviceTreeToggle() {
  const tree = useContext(DeviceTreeContext);
  if (!tree) return null;
  return (
    <Button
      id={TOGGLE_ID}
      icon={tree.open ? <PanelRightClose className="size-4" aria-hidden /> : <PanelRightOpen className="size-4" aria-hidden />}
      aria-pressed={tree.open}
      aria-controls={tree.open ? DOCK_ID : undefined}
      onClick={tree.toggle}
      title={tree.open ? "Hide the device tree" : "Browse organizations, sites and devices as a tree"}
      className="aria-pressed:border-accent/40 aria-pressed:bg-accent-soft"
    >
      Tree
    </Button>
  );
}

/** Where the layout puts the dock: beside the page content, on the devices pages only. */
export function DeviceTreeDock() {
  const tree = useContext(DeviceTreeContext);
  const { can } = useAuth();
  const { pathname } = useLocation();
  if (!tree?.open || !can("device.view") || !isDeviceTreeRoute(pathname)) return null;

  const dismiss = () => {
    tree.close();
    document.getElementById(TOGGLE_ID)?.focus();
  };

  if (!tree.overlay) {
    return (
      <aside id={DOCK_ID} aria-label="Device tree" className="dock-enter flex w-80 shrink-0 flex-col border-l border-line bg-surface">
        <TreePanel onClose={dismiss} />
      </aside>
    );
  }
  return (
    <div
      className="fixed inset-0 z-40 lg:hidden"
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          dismiss();
        }
      }}
    >
      <div className="absolute inset-0 bg-black/50" onClick={dismiss} aria-hidden />
      <aside id={DOCK_ID} aria-label="Device tree" className="dock-enter absolute inset-y-0 right-0 flex w-80 max-w-[85vw] flex-col border-l border-line bg-surface shadow-xl">
        <TreePanel onClose={dismiss} autoFocus />
      </aside>
    </div>
  );
}

const indent = { 1: "pl-1", 2: "pl-5", 3: "pl-9" } as const;

function TreePanel({ onClose, autoFocus = false }: { onClose: () => void; autoFocus?: boolean }) {
  const orgs = useOrganizations();
  const sites = useSites();
  const devices = useList<Device>("/devices", undefined, { refetchInterval: 30_000 });
  const navigate = useNavigate();
  const location = useLocation();
  const prefetch = usePrefetch();
  const filterId = useId();
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string> | null>(null);
  // While filtering, the way to each match is open unless the reader closes it; their changes last until the
  // filter text changes.
  const [filterChanges, setFilterChanges] = useState<{ query: string; open: Map<string, boolean> }>({ query: "", open: new Map() });
  const [focusKey, setFocusKey] = useState<string | null>(null);
  const rowRefs = useRef(new Map<string, HTMLDivElement>());

  const ready = !orgs.isPending && !sites.isPending && !devices.isPending;
  const roots = useMemo(() => buildTree(orgs.items, sites.items, devices.items), [orgs.items, sites.items, devices.items]);
  const index = useMemo(() => indexTree(roots), [roots]);
  const filtered = useMemo(() => filterTree(roots, query), [roots, query]);
  const filtering = query.trim() !== "";
  const selected = selectedKey(location.pathname, location.search);

  useEffect(() => {
    if (ready && expanded === null) setExpanded(initialExpanded(roots));
  }, [ready, expanded, roots]);

  // Open the way to whatever the page is showing, so the tree always says where you are. Only when the page
  // changes: closing a branch afterwards is the reader's choice.
  const revealed = useRef<string | null>(null);
  useEffect(() => {
    if (!selected || !expanded || revealed.current === selected || !index.has(selected)) return;
    revealed.current = selected;
    const chain = ancestors(index, selected);
    if (chain.some((k) => !expanded.has(k))) setExpanded(new Set([...expanded, ...chain]));
  }, [selected, index, expanded]);

  const changes = filterChanges.query === query ? filterChanges.open : null;
  const isOpen = useCallback(
    (key: string) => (filtering ? (changes?.get(key) ?? filtered.expand.has(key)) : (expanded?.has(key) ?? false)),
    [filtering, changes, filtered.expand, expanded],
  );
  const rows = useMemo(() => visibleRows(filtered.roots, isOpen), [filtered.roots, isOpen]);

  useEffect(() => {
    if (selected) rowRefs.current.get(selected)?.scrollIntoView({ block: "nearest" });
  }, [selected, rows.length]);

  const setOpen = useCallback(
    (key: string, value: boolean) => {
      if (filtering) {
        setFilterChanges((prev) => ({ query, open: new Map(prev.query === query ? prev.open : []).set(key, value) }));
        return;
      }
      setExpanded((prev) => {
        const next = new Set(prev ?? []);
        if (value) next.add(key);
        else next.delete(key);
        return next;
      });
    },
    [filtering, query],
  );

  function collapseAll() {
    if (filtering) setFilterChanges({ query, open: new Map([...filtered.expand].map((k) => [k, false])) });
    else setExpanded(new Set());
  }

  function activate(node: TreeNode) {
    if (node.kind === "device") {
      navigate(`/devices/${encodeURIComponent(node.id)}`);
      return;
    }
    showList(node.organizationId, node.kind === "site" ? node.id : null);
  }

  /** The devices list for an organization or site, keeping the list's other filters when it is already open. */
  function showList(organizationId: string | null, siteId: string | null) {
    const onList = location.pathname === "/devices";
    const params = new URLSearchParams(onList ? location.search : "");
    for (const [k, v] of [["organizationId", organizationId], ["siteId", siteId]] as const) {
      if (v) params.set(k, v);
      else params.delete(k);
    }
    const qs = params.toString();
    navigate(qs ? `/devices?${qs}` : "/devices", { replace: onList });
  }

  const tabbable = rows.some((r) => r.node.key === focusKey) ? focusKey : rows.some((r) => r.node.key === selected) ? selected : (rows[0]?.node.key ?? null);

  function focusRow(key: string | null | undefined) {
    if (!key) return;
    setFocusKey(key);
    rowRefs.current.get(key)?.focus();
  }

  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    const i = rows.findIndex((r) => r.node.key === (document.activeElement as HTMLElement | null)?.dataset.key);
    const row = rows[i];
    if (!row) return;
    const node = row.node;
    const hasChildren = node.children.length > 0;
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        return focusRow(rows[i + 1]?.node.key);
      case "ArrowUp":
        e.preventDefault();
        return focusRow(rows[i - 1]?.node.key);
      case "Home":
        e.preventDefault();
        return focusRow(rows[0]?.node.key);
      case "End":
        e.preventDefault();
        return focusRow(rows.at(-1)?.node.key);
      case "ArrowRight":
        e.preventDefault();
        if (!hasChildren) return;
        if (!isOpen(node.key)) return setOpen(node.key, true);
        return focusRow(rows[i + 1]?.node.key);
      case "ArrowLeft":
        e.preventDefault();
        if (hasChildren && isOpen(node.key)) return setOpen(node.key, false);
        return focusRow(node.parent);
      case "Enter":
        e.preventDefault();
        return activate(node);
    }
  }

  const total = roots.reduce((n, o) => n + o.total, 0);
  const online = roots.reduce((n, o) => n + o.online, 0);
  const readout = filtering
    ? filtered.matches === 0
      ? "Nothing matches"
      : plural(filtered.matches, "match", "matches")
    : `${plural(roots.length, "organization")}, ${plural(total, "device")}, ${online.toLocaleString()} online`;
  const failed = orgs.isError || sites.isError || devices.isError;

  return (
    <>
      <header className="flex h-12 shrink-0 items-center gap-2 border-b border-line pr-2 pl-4">
        <ListTree className="size-4 text-muted" aria-hidden />
        <h2 className="flex-1 text-sm font-semibold text-fg">Device tree</h2>
        <IconButton
          label="Collapse all"
          onClick={collapseAll}
          disabled={rows.length === filtered.roots.length}
        >
          <ChevronsDownUp className="size-4" aria-hidden />
        </IconButton>
        <IconButton label="Close the device tree" onClick={onClose}>
          <X className="size-4" aria-hidden />
        </IconButton>
      </header>
      <div className="shrink-0 border-b border-line px-3 pt-3 pb-2">
        <label htmlFor={filterId} className="sr-only">
          Filter the tree
        </label>
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-subtle" aria-hidden />
          <Input
            id={filterId}
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                focusRow(tabbable);
              }
            }}
            placeholder="Filter by name or hostname"
            className="pl-8"
            autoFocus={autoFocus}
          />
        </div>
        <p className="mt-1.5 text-xs text-muted tabular-nums" aria-live="polite">
          {ready && !failed ? readout : " "}
          {ready && devices.items.length >= 5000 && <span className="text-warn"> (the first 5,000 devices)</span>}
        </p>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto p-2">
        {!ready ? (
          <Spinner />
        ) : failed ? (
          <ErrorState
            compact
            error={orgs.error ?? sites.error ?? devices.error}
            onRetry={() => {
              void orgs.refetch();
              void sites.refetch();
              void devices.refetch();
            }}
          />
        ) : roots.length === 0 ? (
          <p className="px-2 py-6 text-center text-sm text-muted">No organizations yet.</p>
        ) : (
          <>
            {!filtering && (
              <button
                type="button"
                onClick={() => showList(null, null)}
                aria-current={selected === "all" ? "page" : undefined}
                className={cx(rowClasses(selected === "all"), "mb-0.5 w-full pl-1")}
              >
                <span className="size-4 shrink-0" aria-hidden />
                <Monitor className="size-3.5 shrink-0 text-subtle" aria-hidden />
                <span className="min-w-0 flex-1 truncate text-left">All devices</span>
                <Count online={online} total={total} />
              </button>
            )}
            {rows.length === 0 ? (
              <p className="px-2 py-6 text-center text-sm text-muted">Nothing matches &ldquo;{query.trim()}&rdquo;.</p>
            ) : (
              <div role="tree" aria-label="Organizations, sites and devices" onKeyDown={onKeyDown}>
                {rows.map(({ node, position, siblings }) => {
                  const hasChildren = node.children.length > 0;
                  const expandedRow = hasChildren && isOpen(node.key);
                  const isSelected = node.key === selected;
                  const d = node.device;
                  return (
                    <div
                      key={node.key}
                      ref={(el) => {
                        if (el) rowRefs.current.set(node.key, el);
                        else rowRefs.current.delete(node.key);
                      }}
                      data-key={node.key}
                      role="treeitem"
                      aria-level={node.level}
                      aria-posinset={position}
                      aria-setsize={siblings}
                      aria-expanded={hasChildren ? expandedRow : undefined}
                      aria-selected={isSelected}
                      tabIndex={node.key === tabbable ? 0 : -1}
                      title={d ? deviceTitle(d) : undefined}
                      onClick={() => {
                        setFocusKey(node.key);
                        activate(node);
                      }}
                      onFocus={() => {
                        setFocusKey(node.key);
                        if (d) prefetch(`/devices/${d.id}`);
                      }}
                      onMouseEnter={d ? () => prefetch(`/devices/${d.id}`) : undefined}
                      className={cx(rowClasses(isSelected), indent[node.level])}
                    >
                      {hasChildren ? (
                        <span
                          aria-hidden
                          onClick={(e) => {
                            e.stopPropagation();
                            setFocusKey(node.key);
                            setOpen(node.key, !expandedRow);
                          }}
                          className="inline-flex size-4 shrink-0 items-center justify-center rounded text-subtle hover:bg-hover hover:text-fg"
                        >
                          <ChevronRight className={cx("size-3.5 transition-transform", expandedRow && "rotate-90")} />
                        </span>
                      ) : (
                        <span className="size-4 shrink-0" aria-hidden />
                      )}
                      {node.kind === "org" ? (
                        <Building2 className="size-3.5 shrink-0 text-subtle" aria-hidden />
                      ) : node.kind === "site" ? (
                        <MapPin className="size-3.5 shrink-0 text-subtle" aria-hidden />
                      ) : (
                        <span className="inline-flex size-3.5 shrink-0 items-center justify-center">
                          <Dot tone={node.online ? "ok" : "neutral"} />
                        </span>
                      )}
                      <span className="min-w-0 flex-1 truncate">{node.name}</span>
                      {d ? <span className="sr-only">, {node.online ? "online" : "offline"}</span> : <Count online={node.online} total={node.total} />}
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}

function deviceTitle(d: Device): string {
  return [d.hostname && d.hostname.toLowerCase() !== d.name.toLowerCase() ? d.hostname : null, d.osDescription || platformName(d.platform)]
    .filter(Boolean)
    .join(" · ");
}

function rowClasses(selected: boolean): string {
  return cx(
    "flex h-7 cursor-pointer items-center gap-1.5 rounded-md pr-2 text-sm select-none focus-visible:-outline-offset-2",
    selected ? "bg-accent-soft font-medium text-fg" : "text-fg hover:bg-hover",
  );
}

/** Online and total devices under an organization or site. */
function Count({ online, total }: { online: number; total: number }) {
  return (
    <>
      <span aria-hidden className="shrink-0 text-xs font-normal text-muted tabular-nums" title={`${online.toLocaleString()} of ${plural(total, "device")} online`}>
        {total === 0 ? "0" : `${online.toLocaleString()}/${total.toLocaleString()}`}
      </span>
      <span className="sr-only">, {total === 0 ? "no devices" : `${online.toLocaleString()} of ${plural(total, "device")} online`}</span>
    </>
  );
}
