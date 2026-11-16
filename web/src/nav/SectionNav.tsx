import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import {
  ArrowLeft,
  Bell,
  Building2,
  ChevronRight,
  ChevronsDownUp,
  FileCode2,
  Hourglass,
  Library,
  ListChecks,
  MapPin,
  Monitor,
  MonitorSmartphone,
  Send,
  Plus,
  ScreenShare,
  ScrollText,
  Search,
  Settings,
  UsersRound,
} from "lucide-react";
import { useList, useOrganizations, usePrefetch, useSites, useWaitingDevices } from "../api/hooks";
import type { Device, DeviceAlertCount, Permission, Script } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { cx, Dot, ErrorState, Spinner } from "../components/ui";
import { plural } from "../lib/format";
import { platformName } from "../pages/devices/platform";
import { useCanWriteScripts } from "../pages/scripts/ScriptsPage";
import { canQuickConnect, QuickConnectPanel } from "./QuickConnect";
import { selectedKey, targetHref, type SectionId, type Target } from "./sections";
import { ancestors, buildTree, filterTree, indexTree, initialExpanded, visibleRows, type TreeNode } from "./tree";
import { scrollbarWidth, textMeasure, treeWidth, type RowSpec } from "./width";

const META: Record<SectionId, { title: string; icon: ReactNode }> = {
  organizations: { title: "Organizations", icon: <Building2 className="size-4" aria-hidden /> },
  devices: { title: "Devices", icon: <Monitor className="size-4" aria-hidden /> },
  alerts: { title: "Alerts", icon: <Bell className="size-4" aria-hidden /> },
  scripts: { title: "Scripts", icon: <FileCode2 className="size-4" aria-hidden /> },
  jobs: { title: "Jobs", icon: <ListChecks className="size-4" aria-hidden /> },
  settings: { title: "Settings", icon: <Settings className="size-4" aria-hidden /> },
};

const ALL_LABEL: Record<Exclude<SectionId, "settings">, string> = {
  organizations: "All organizations",
  devices: "All devices",
  alerts: "All alerts",
  scripts: "All scripts",
  jobs: "All jobs",
};

/**
 * A section's own navigation, in place of the main menu (ADR-0021): Back returns to the main menu, the rest narrows
 * or moves within the section. A tree reports the width its longest name needs through onWidth.
 */
export function SectionNav({
  section,
  onBack,
  focusBack,
  onFocused,
  onWidth,
}: {
  section: SectionId;
  onBack: () => void;
  focusBack: boolean;
  onFocused: () => void;
  onWidth?: (px: number) => void;
}) {
  const back = useRef<HTMLButtonElement>(null);
  // Entering a section from the main menu puts focus on Back, where the menu item was.
  useEffect(() => {
    if (!focusBack) return;
    back.current?.focus();
    onFocused();
  }, [focusBack, onFocused]);
  return (
    <div className="nav-enter flex min-h-0 flex-1 flex-col">
      <div className="shrink-0 px-2 pt-1">
        <button
          ref={back}
          type="button"
          onClick={onBack}
          aria-label="Back to the main menu"
          className="flex items-center gap-1.5 rounded-md px-2 py-1.5 text-sm text-sidebar-fg hover:bg-sidebar-active/60 hover:text-white"
        >
          <ArrowLeft className="size-4" aria-hidden />
          Back
        </button>
      </div>
      {section === "settings" ? <SettingsNav /> : <SectionTree section={section} onWidth={onWidth} />}
    </div>
  );
}

function SectionHeader({ section, children }: { section: SectionId; children?: ReactNode }) {
  return (
    <div className="flex h-10 shrink-0 items-center gap-2 pr-2 pl-4">
      <span className="text-sidebar-fg/70">{META[section].icon}</span>
      <h2 className="min-w-0 flex-1 truncate text-sm font-semibold text-white">{META[section].title}</h2>
      {children}
    </div>
  );
}

const iconButton =
  "inline-flex size-7 shrink-0 items-center justify-center rounded-md text-sidebar-fg/80 hover:bg-white/10 hover:text-white disabled:pointer-events-none disabled:opacity-35";

function rowClasses(selected: boolean): string {
  return cx(
    "group flex h-7 cursor-pointer items-center gap-1.5 rounded-md pr-1.5 text-sm select-none",
    selected ? "bg-sidebar-active font-medium text-white" : "text-sidebar-fg hover:bg-sidebar-active/60 hover:text-white",
  );
}

const indent = { 1: "pl-1", 2: "pl-4", 3: "pl-7" } as const;

interface Badge {
  text: string;
  label: string;
  tone?: "count" | "critical" | "warning";
}

/** A row's count, for the eye; the row's own label (see rowLabel) says it in words. */
function BadgeView({ badge }: { badge: Badge | null }) {
  if (!badge) return null;
  if (badge.tone === "critical" || badge.tone === "warning") {
    return (
      <span
        aria-hidden
        title={badge.label}
        className={cx(
          "min-w-5 shrink-0 rounded-full px-1.5 text-center text-xs leading-5 font-semibold tabular-nums",
          badge.tone === "critical" ? "bg-danger text-white" : "bg-white/15 text-white",
        )}
      >
        {badge.text}
      </span>
    );
  }
  return (
    <span aria-hidden title={badge.label} className="shrink-0 text-xs font-normal text-sidebar-fg/70 tabular-nums">
      {badge.text}
    </span>
  );
}

function specBadge(b: Badge | null): RowSpec["badge"] {
  return b && { text: b.text, pill: b.tone === "critical" || b.tone === "warning" };
}

/** What a row is called to assistive technology: its name, a device's state, and its count in words. */
function rowLabel(name: string, badge: Badge | null, online?: boolean): string {
  return [name, online === undefined ? null : online ? "online" : "offline", badge?.label].filter(Boolean).join(", ");
}

const count = (n: number) => (n > 99 ? "99+" : n.toLocaleString());

function alertBadge(active: number, critical: number): Badge | null {
  if (active === 0) return null;
  return {
    text: count(active),
    label: `${plural(active, "active alert")}${critical > 0 ? `, ${critical.toLocaleString()} critical` : ""}`,
    tone: critical > 0 ? "critical" : "warning",
  };
}

function onlineBadge(online: number, total: number): Badge {
  return {
    text: total === 0 ? "0" : `${online.toLocaleString()}/${total.toLocaleString()}`,
    label: total === 0 ? "no devices" : `${online.toLocaleString()} of ${plural(total, "device")} online`,
  };
}

function SectionTree({ section, onWidth }: { section: Exclude<SectionId, "settings">; onWidth?: (px: number) => void }) {
  const { can, canGlobal } = useAuth();
  const waiting = useWaitingDevices(section === "devices" && canGlobal("enrollment.manage"));
  const navigate = useNavigate();
  const location = useLocation();
  const prefetch = usePrefetch();
  const canWriteScripts = useCanWriteScripts();
  const filterId = useId();

  const wantsDevices = can("device.view") && section !== "scripts";
  const orgs = useOrganizations();
  const sites = useSites();
  const devices = useList<Device>(wantsDevices ? "/devices" : null, undefined, { refetchInterval: 30_000 });
  const alertCounts = useList<DeviceAlertCount>(section === "alerts" ? "/alerts/devices" : null, undefined, { refetchInterval: 30_000 });
  const scripts = useList<Script>(section === "scripts" ? "/scripts" : null);

  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string> | null>(null);
  // While filtering, the way to each match is open unless the reader closes it; their changes last until the filter
  // text changes.
  const [filterChanges, setFilterChanges] = useState<{ query: string; open: Map<string, boolean> }>({ query: "", open: new Map() });
  const [focusKey, setFocusKey] = useState<string | null>(null);
  const [connect, setConnect] = useState<{ device: Device; anchor: HTMLElement } | null>(null);
  const rowRefs = useRef(new Map<string, HTMLDivElement>());
  const scrollArea = useRef<HTMLDivElement>(null);

  const selected = selectedKey(section, location.pathname, location.search);
  const byDevice = useMemo(() => new Map(alertCounts.items.map((c) => [c.deviceId, c])), [alertCounts.items]);
  const leaf = useMemo<(d: Device) => boolean>(() => {
    switch (section) {
      case "devices":
      case "jobs":
        return () => true;
      // The devices that need attention, and the one the list is narrowed to.
      case "alerts":
        return (d) => byDevice.has(d.id) || selected === `d:${d.id}`;
      default:
        return () => false;
    }
  }, [section, byDevice, selected]);

  const loading = orgs.isPending || sites.isPending || (wantsDevices && devices.isPending) || (section === "alerts" && alertCounts.isPending);
  const failed = orgs.isError || sites.isError || devices.isError || alertCounts.isError || scripts.isError;
  const roots = useMemo(() => buildTree(orgs.items, sites.items, devices.items, leaf), [orgs.items, sites.items, devices.items, leaf]);
  const index = useMemo(() => indexTree(roots), [roots]);
  const filtered = useMemo(() => filterTree(roots, query), [roots, query]);
  const filtering = query.trim() !== "";

  // Section counts for organizations and sites.
  const badges = useMemo(() => {
    const out = new Map<string, Badge | null>();
    if (section === "alerts") {
      const sum = new Map<string, { active: number; critical: number }>();
      const add = (key: string, c: DeviceAlertCount) => {
        const v = sum.get(key) ?? { active: 0, critical: 0 };
        sum.set(key, { active: v.active + c.active, critical: v.critical + c.critical });
      };
      for (const c of alertCounts.items) {
        add(`o:${c.organizationId}`, c);
        add(`s:${c.siteId}`, c);
        add(`d:${c.deviceId}`, c);
        add("all", c);
      }
      for (const [k, v] of sum) out.set(k, alertBadge(v.active, v.critical));
    } else if (section === "scripts") {
      const n = new Map<string, number>();
      const bump = (k: string) => n.set(k, (n.get(k) ?? 0) + 1);
      for (const s of scripts.items) {
        bump("all");
        if (s.level === "shared") bump("shared");
        if (s.organizationId) bump(`o:${s.organizationId}`);
        if (s.siteId) bump(`s:${s.siteId}`);
      }
      for (const [k, v] of n) out.set(k, { text: count(v), label: plural(v, "script") });
    }
    return out;
  }, [section, alertCounts.items, scripts.items]);

  const total = roots.reduce((n, o) => n + o.total, 0);
  const online = roots.reduce((n, o) => n + o.online, 0);

  function badgeFor(node: TreeNode | "all" | "shared" | "approvals"): Badge | null {
    const key = typeof node === "string" ? node : node.key;
    if (node === "approvals") return waiting > 0 ? { text: count(waiting), label: `${plural(waiting, "device")} waiting`, tone: "warning" } : null;
    switch (section) {
      case "devices":
        if (typeof node === "object" && node.kind === "device") return null;
        return typeof node === "object" ? onlineBadge(node.online, node.total) : onlineBadge(online, total);
      case "organizations": {
        if (!wantsDevices || devices.isPending) return null;
        const n = typeof node === "object" ? node.total : total;
        return { text: n.toLocaleString(), label: plural(n, "device") };
      }
      case "alerts":
      case "scripts":
        return badges.get(key) ?? null;
      case "jobs":
        return null;
    }
  }

  useEffect(() => {
    if (!loading && expanded === null) setExpanded(initialExpanded(roots));
  }, [loading, expanded, roots]);

  // The sidebar widens for long names: every row of the tree counts, open or not, so the width holds still while
  // branches open and close or the filter narrows the list. Measured before paint, so it never visibly jumps.
  useLayoutEffect(() => {
    if (!onWidth || loading || failed || !scrollArea.current) return;
    const specs: RowSpec[] = [{ text: ALL_LABEL[section], level: 1, badge: specBadge(badgeFor("all")) }];
    for (const x of extras) specs.push({ text: x.label, level: 1, badge: specBadge(badgeFor(x.key)) });
    const walk = (nodes: TreeNode[]) => {
      for (const node of nodes) {
        const d = node.device;
        specs.push({ text: node.name, level: node.level, badge: specBadge(badgeFor(node)), quick: section === "devices" && d !== undefined && canQuickConnect(d) });
        walk(node.children);
      }
    };
    walk(roots);
    onWidth(treeWidth(specs, textMeasure(getComputedStyle(scrollArea.current).fontFamily), scrollbarWidth()));
    // badgeFor and extras follow from the dependencies listed.
  }, [onWidth, loading, failed, roots, section, badges, online, total, wantsDevices, devices.isPending, waiting, selected]);

  // Open the way to whatever the page is showing, so the tree always says where you are. Only when the page changes:
  // closing a branch afterwards is the reader's choice.
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
    if (selected) rowRefs.current.get(selected)?.scrollIntoView?.({ block: "nearest" });
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

  function go(target: Target) {
    const href = targetHref(section, target, location.pathname, location.search);
    // Narrowing the list the reader is on replaces its history entry rather than piling them up.
    const list = href.split("?")[0];
    navigate(href, { replace: list === location.pathname && section !== "organizations" });
  }

  function activate(node: TreeNode) {
    if (node.kind === "device") {
      const d = node.device!;
      go({ kind: "device", id: d.id, organizationId: d.organizationId, siteId: d.siteId });
    } else if (node.kind === "site") go({ kind: "site", id: node.id, organizationId: node.organizationId });
    else go({ kind: "org", id: node.id });
  }

  const tabbable = rows.some((r) => r.node.key === focusKey) ? focusKey : rows.some((r) => r.node.key === selected) ? selected : (rows[0]?.node.key ?? null);

  function focusRow(key: string | null | undefined) {
    if (!key) return;
    setFocusKey(key);
    rowRefs.current.get(key)?.focus();
  }

  function openConnect(node: TreeNode) {
    const el = rowRefs.current.get(node.key);
    if (section === "devices" && node.device && el && canQuickConnect(node.device)) setConnect({ device: node.device, anchor: el });
  }

  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    const i = rows.findIndex((r) => r.node.key === (document.activeElement as HTMLElement | null)?.dataset.key);
    const row = rows[i];
    if (!row) return;
    const node = row.node;
    const hasChildren = node.children.length > 0;
    if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) {
      e.preventDefault();
      return openConnect(node);
    }
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

  const readout = filtering
    ? filtered.matches === 0
      ? "Nothing matches"
      : plural(filtered.matches, "match", "matches")
    : section === "devices"
      ? `${plural(total, "device")}, ${online.toLocaleString()} online`
      : section === "alerts"
        ? alertCounts.items.length === 0
          ? "No active alerts"
          : `${plural(alertCounts.items.reduce((n, c) => n + c.active, 0), "active alert")} on ${plural(alertCounts.items.length, "device")}`
        : section === "scripts"
          ? plural(scripts.items.length, "script")
          : `${plural(roots.length, "organization")}, ${plural(
              roots.reduce((n, o) => n + o.children.length, 0),
              "site",
            )}`;

  const placeholder = section === "organizations" || section === "scripts" ? "Filter by name" : "Filter by name or hostname";
  const extras: { key: "shared" | "approvals"; label: string; icon: ReactNode; target: Target }[] = [];
  if (section === "scripts") extras.push({ key: "shared", label: "Shared library", icon: <Library className="size-3.5 shrink-0" aria-hidden />, target: { kind: "shared" } });
  // Devices waiting for approval belong to no organization yet, so they sit beside the tree, not in it; the row shows
  // while any wait, or while its page is open.
  if (section === "devices" && (waiting > 0 || selected === "approvals")) {
    extras.push({ key: "approvals", label: "Waiting for approval", icon: <Hourglass className="size-3.5 shrink-0" aria-hidden />, target: { kind: "approvals" } });
  }

  return (
    <>
      <SectionHeader section={section}>
        {section === "devices" && can("enrollment.manage") && (
          <Link to="/devices/add" className={iconButton} aria-label="Add devices" title="Add devices">
            <Plus className="size-4" aria-hidden />
          </Link>
        )}
        {section === "scripts" && canWriteScripts && (
          <Link to="/scripts/new" className={iconButton} aria-label="New script" title="New script">
            <Plus className="size-4" aria-hidden />
          </Link>
        )}
        {section === "organizations" && can("org.create") && (
          <Link to="/organizations?new=1" className={iconButton} aria-label="New organization" title="New organization">
            <Plus className="size-4" aria-hidden />
          </Link>
        )}
        <button type="button" className={iconButton} aria-label="Collapse all" title="Collapse all" onClick={collapseAll} disabled={rows.length === filtered.roots.length}>
          <ChevronsDownUp className="size-4" aria-hidden />
        </button>
      </SectionHeader>
      <div className="shrink-0 px-3 pb-2">
        <label htmlFor={filterId} className="sr-only">
          Filter the tree
        </label>
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-sidebar-fg/50" aria-hidden />
          <input
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
            placeholder={placeholder}
            className="h-8 w-full rounded-md border border-white/10 bg-white/5 pr-2 pl-8 text-sm text-white placeholder:text-sidebar-fg/50 focus:border-accent focus:ring-2 focus:ring-accent/30 focus:outline-none"
          />
        </div>
        <p className="mt-1.5 truncate text-xs text-sidebar-fg/70 tabular-nums" aria-live="polite">
          {!loading && !failed ? readout : " "}
          {!loading && devices.items.length >= 5000 && <span className="text-warn"> (the first 5,000 devices)</span>}
        </p>
      </div>
      <div ref={scrollArea} className="min-h-0 flex-1 overflow-y-auto px-2 pb-2">
        {loading ? (
          <Spinner />
        ) : failed ? (
          <div className="rounded-md bg-surface">
            <ErrorState
              compact
              error={orgs.error ?? sites.error ?? devices.error ?? alertCounts.error ?? scripts.error}
              onRetry={() => {
                void orgs.refetch();
                void sites.refetch();
                if (wantsDevices) void devices.refetch();
                if (section === "alerts") void alertCounts.refetch();
                if (section === "scripts") void scripts.refetch();
              }}
            />
          </div>
        ) : (
          <>
            {!filtering && (
              <>
                <button
                  type="button"
                  onClick={() => go({ kind: "all" })}
                  aria-current={selected === "all" ? "page" : undefined}
                  aria-label={rowLabel(ALL_LABEL[section], badgeFor("all"))}
                  className={cx(rowClasses(selected === "all"), "mb-0.5 w-full pl-1")}
                >
                  <span className="size-4 shrink-0" aria-hidden />
                  <span className="text-sidebar-fg/60">{META[section].icon}</span>
                  <span className="min-w-0 flex-1 truncate text-left">{ALL_LABEL[section]}</span>
                  <BadgeView badge={badgeFor("all")} />
                </button>
                {extras.map((x) => (
                  <button
                    key={x.key}
                    type="button"
                    onClick={() => go(x.target)}
                    aria-current={selected === x.key ? "page" : undefined}
                    aria-label={rowLabel(x.label, badgeFor(x.key))}
                    className={cx(rowClasses(selected === x.key), "mb-0.5 w-full pl-1")}
                  >
                    <span className="size-4 shrink-0" aria-hidden />
                    <span className="text-sidebar-fg/60">{x.icon}</span>
                    <span className="min-w-0 flex-1 truncate text-left">{x.label}</span>
                    <BadgeView badge={badgeFor(x.key)} />
                  </button>
                ))}
              </>
            )}
            {roots.length === 0 ? (
              <p className="px-2 py-6 text-center text-sm text-sidebar-fg/70">No organizations yet.</p>
            ) : rows.length === 0 ? (
              <p className="px-2 py-6 text-center text-sm text-sidebar-fg/70">Nothing matches &ldquo;{query.trim()}&rdquo;.</p>
            ) : (
              <div role="tree" aria-label={`${META[section].title}: organizations, sites${section === "devices" || section === "jobs" || section === "alerts" ? " and devices" : ""}`} onKeyDown={onKeyDown}>
                {rows.map(({ node, position, siblings }) => {
                  const hasChildren = node.children.length > 0;
                  const expandedRow = hasChildren && isOpen(node.key);
                  const isSelected = node.key === selected;
                  const d = node.device;
                  const quick = section === "devices" && d !== undefined && canQuickConnect(d);
                  const connecting = connect !== null && d !== undefined && connect.device.id === d.id;
                  const badge = badgeFor(node);
                  return (
                    <div
                      key={node.key}
                      ref={(el) => {
                        if (el) rowRefs.current.set(node.key, el);
                        else rowRefs.current.delete(node.key);
                      }}
                      data-key={node.key}
                      role="treeitem"
                      aria-label={rowLabel(node.name, badge, d ? node.online > 0 : undefined)}
                      aria-level={node.level}
                      aria-posinset={position}
                      aria-setsize={siblings}
                      aria-expanded={hasChildren ? expandedRow : undefined}
                      aria-selected={isSelected}
                      aria-keyshortcuts={quick ? "Shift+F10" : undefined}
                      aria-haspopup={quick ? "dialog" : undefined}
                      tabIndex={node.key === tabbable ? 0 : -1}
                      title={d ? deviceTitle(d) : node.name}
                      onClick={() => {
                        setFocusKey(node.key);
                        activate(node);
                      }}
                      onContextMenu={
                        quick
                          ? (e) => {
                              e.preventDefault();
                              setFocusKey(node.key);
                              openConnect(node);
                            }
                          : undefined
                      }
                      onFocus={() => {
                        setFocusKey(node.key);
                        if (d && section === "devices") prefetch(`/devices/${d.id}`);
                      }}
                      onMouseEnter={d && section === "devices" ? () => prefetch(`/devices/${d.id}`) : undefined}
                      className={cx(rowClasses(isSelected), indent[node.level], connecting && "bg-sidebar-active/60 text-white")}
                    >
                      {hasChildren ? (
                        <span
                          aria-hidden
                          onClick={(e) => {
                            e.stopPropagation();
                            setFocusKey(node.key);
                            setOpen(node.key, !expandedRow);
                          }}
                          className="inline-flex size-4 shrink-0 items-center justify-center rounded text-sidebar-fg/60 hover:bg-white/10 hover:text-white"
                        >
                          <ChevronRight className={cx("size-3.5 transition-transform", expandedRow && "rotate-90")} />
                        </span>
                      ) : (
                        <span className="size-4 shrink-0" aria-hidden />
                      )}
                      {node.kind === "org" ? (
                        <Building2 className="size-3.5 shrink-0 text-sidebar-fg/60" aria-hidden />
                      ) : node.kind === "site" ? (
                        <MapPin className="size-3.5 shrink-0 text-sidebar-fg/60" aria-hidden />
                      ) : (
                        <span className="inline-flex size-3.5 shrink-0 items-center justify-center">
                          <Dot tone={node.online ? "ok" : "neutral"} />
                        </span>
                      )}
                      <span className="min-w-0 flex-1 truncate">{node.name}</span>
                      <BadgeView badge={badge} />
                      {quick && (
                        <button
                          type="button"
                          tabIndex={-1}
                          aria-label={`Quick connect to ${d.name}`}
                          title="Quick connect"
                          onClick={(e) => {
                            e.stopPropagation();
                            setFocusKey(node.key);
                            if (connecting) setConnect(null);
                            else openConnect(node);
                          }}
                          className={cx(
                            "-my-1 inline-flex size-6 shrink-0 items-center justify-center rounded text-sidebar-fg/80 hover:bg-white/15 hover:text-white",
                            connecting || isSelected ? "opacity-100" : "opacity-0 group-hover:opacity-100 group-focus:opacity-100 pointer-coarse:opacity-100",
                          )}
                        >
                          <ScreenShare className="size-3.5" aria-hidden />
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </div>
      {connect && (
        <QuickConnectPanel
          device={connect.device}
          anchor={connect.anchor}
          onClose={(returnFocus) => {
            const anchor = connect.anchor;
            setConnect(null);
            if (returnFocus) anchor.focus();
          }}
        />
      )}
    </>
  );
}

function deviceTitle(d: Device): string {
  return [d.hostname && d.hostname.toLowerCase() !== d.name.toLowerCase() ? d.hostname : null, d.osDescription || platformName(d.platform)]
    .filter(Boolean)
    .join(" · ");
}

/** Settings' parts, as the page's tabs list them. */
export function settingsParts(can: (p: Permission) => boolean): { id: string; label: string; icon: ReactNode }[] {
  return [
    { id: "users", label: "Users", icon: <UsersRound className="size-4" aria-hidden />, show: can("user.view") },
    { id: "audit", label: "Audit log", icon: <ScrollText className="size-4" aria-hidden />, show: can("audit.view") },
    { id: "remote", label: "Remote access", icon: <MonitorSmartphone className="size-4" aria-hidden />, show: can("settings.manage") },
    { id: "forwarding", label: "Audit forwarding", icon: <Send className="size-4" aria-hidden />, show: can("settings.manage") },
  ]
    .filter((p) => p.show)
    .map(({ id, label, icon }) => ({ id, label, icon }));
}

function SettingsNav() {
  const { can } = useAuth();
  const location = useLocation();
  const parts = settingsParts(can);
  const first = parts[0]?.id;
  const requested = new URLSearchParams(location.search).get("tab");
  const current = location.pathname.startsWith("/users/") ? "users" : parts.some((p) => p.id === requested) ? requested : first;
  return (
    <>
      <SectionHeader section="settings" />
      <ul className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-2">
        {parts.map((p) => (
          <li key={p.id}>
            <Link
              to={p.id === first ? "/settings" : `/settings?tab=${p.id}`}
              aria-current={current === p.id ? "page" : undefined}
              className={cx(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm",
                current === p.id ? "bg-sidebar-active font-medium text-white" : "text-sidebar-fg hover:bg-sidebar-active/60 hover:text-white",
              )}
            >
              <span className={current === p.id ? "text-white" : "text-sidebar-fg/70"}>{p.icon}</span>
              {p.label}
            </Link>
          </li>
        ))}
      </ul>
    </>
  );
}
