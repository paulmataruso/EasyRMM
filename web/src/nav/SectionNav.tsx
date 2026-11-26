import { useQueries } from "@tanstack/react-query";
import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import {
  ArrowLeft,
  ArrowUpCircle,
  Bell,
  Building2,
  ChevronRight,
  ChevronsDownUp,
  FileCode2,
  Fingerprint,
  FolderTree,
  Hourglass,
  KeyRound,
  Library,
  LifeBuoy,
  ListChecks,
  LoaderCircle,
  MoreHorizontal,
  Pencil,
  Trash2,
  FolderPlus,
  MoveRight,
  LogIn,
  Mail,
  MapPin,
  Monitor,
  MonitorSmartphone,
  Send,
  Plus,
  ScreenShare,
  ScrollText,
  Search,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  UsersRound,
} from "lucide-react";
import { api } from "../api/client";
import { useApi, useDeviceAlertCounts, useList, useOrganizations, usePrefetch, useSites, useWaitingDevices } from "../api/hooks";
import type { Device, DeviceAlertCount, DeviceGroup, DeviceTreeData, List, Permission, Script } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { cx, Dot, ErrorState, Spinner } from "../components/ui";
import { plural } from "../lib/format";
import { platformName } from "../pages/devices/platform";
import { useCanWriteScripts } from "../pages/scripts/ScriptsPage";
import { canQuickConnect, QuickConnectPanel } from "./QuickConnect";
import { selectedKey, targetHref, type SectionId, type Target } from "./sections";
import { ancestors, buildTree, filterTree, indexTree, initialExpanded, orgKey, siteKey, visibleRows, type TreeNode } from "./tree";
import { useDebounced } from "./useDebounced";
import { DeleteGroupDialog, DeviceGroupDialog } from "../pages/organizations/GroupDialogs";
import { ConfirmDialog } from "../components/Dialog";
import { useToast } from "../components/Toast";
import { MoveDialog } from "./MoveDialog";
import { consequences, draggingDevices, dragged, endDrag, movedText, startDrag, useMoveDevices, widest, type Movable, type MoveTarget } from "./move";
import { RowMenu, type RowMenuItem } from "./RowMenu";
import { scrollbarWidth, textMeasure, treeWidth, type RowSpec } from "./width";

const META: Record<SectionId, { title: string; icon: ReactNode }> = {
  organizations: { title: "Organizations", icon: <Building2 className="size-4" aria-hidden /> },
  devices: { title: "Devices", icon: <Monitor className="size-4" aria-hidden /> },
  alerts: { title: "Alerts", icon: <Bell className="size-4" aria-hidden /> },
  scripts: { title: "Scripts", icon: <FileCode2 className="size-4" aria-hidden /> },
  jobs: { title: "Jobs", icon: <ListChecks className="size-4" aria-hidden /> },
  patching: { title: "Patching", icon: <ShieldCheck className="size-4" aria-hidden /> },
  quickassist: { title: "Quick Assist", icon: <LifeBuoy className="size-4" aria-hidden /> },
  settings: { title: "Settings", icon: <Settings className="size-4" aria-hidden /> },
};

const ALL_LABEL: Record<Exclude<SectionId, "settings" | "quickassist">, string> = {
  organizations: "All organizations",
  devices: "All devices",
  alerts: "All alerts",
  scripts: "All scripts",
  jobs: "All jobs",
  patching: "All organizations",
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
      {section === "settings" ? <SettingsNav /> : section === "quickassist" ? <QuickAssistNav /> : <SectionTree section={section} onWidth={onWidth} />}
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

const indent = { 1: "pl-1", 2: "pl-4", 3: "pl-7", 4: "pl-10" } as const;

/** A row's height in pixels (h-7); the windowing below depends on it. */
const ROW_HEIGHT = 28;
/** A tree with fewer rows than this renders them all; a longer one only those on screen and a few beyond. */
const WINDOW_AFTER = 120;
const OVERSCAN = 8;


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

function SectionTree({ section, onWidth }: { section: Exclude<SectionId, "settings" | "quickassist">; onWidth?: (px: number) => void }) {
  const { can, canGlobal } = useAuth();
  const waiting = useWaitingDevices(section === "devices" && canGlobal("enrollment.manage"));
  const navigate = useNavigate();
  const location = useLocation();
  const prefetch = usePrefetch();
  const canWriteScripts = useCanWriteScripts();
  const filterId = useId();

  const wantsDevices = can("device.view");
  const orgs = useOrganizations();
  const sites = useSites();
  const tree = useApi<DeviceTreeData>(wantsDevices ? "/device-tree" : null, undefined, { refetchInterval: 30_000 });
  const alertCounts = useDeviceAlertCounts(section === "alerts");
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
  const treeEl = useRef<HTMLDivElement>(null);
  const toast = useToast();
  // Moving devices and managing groups (ADR-0069).
  const canMove = can("device.edit");
  const canGroups = can("site.manage");
  const [menu, setMenu] = useState<{ node: TreeNode; anchor: HTMLElement } | null>(null);
  const [picker, setPicker] = useState<{ devices: Movable[]; organizationId?: string } | null>(null);
  const [confirming, setConfirming] = useState<{ devices: Movable[]; target: MoveTarget } | null>(null);
  const [dropKey, setDropKey] = useState<string | null>(null);
  const [groupForm, setGroupForm] = useState<{ siteId: string; group?: DeviceGroup } | null>(null);
  const [groupToDelete, setGroupToDelete] = useState<{ group: DeviceGroup; siteName: string } | null>(null);
  const mover = useMoveDevices((r, req) => {
    toast.success(movedText(r, req));
    setConfirming(null);
  });

  const selected = selectedKey(section, location.pathname, location.search);
  const byDevice = useMemo(() => new Map(alertCounts.items.map((c) => [c.deviceId, c])), [alertCounts.items]);

  const loading = orgs.isPending || sites.isPending || (wantsDevices && tree.isPending) || (section === "alerts" && alertCounts.isPending);
  const failed = orgs.isError || sites.isError || tree.isError || alertCounts.isError || scripts.isError;

  // The structure: everything but devices, which load as their node opens.
  const skeleton = useMemo(
    () => buildTree(orgs.items, sites.items, [], { groups: tree.data?.groups ?? [], counts: tree.data?.counts ?? [] }),
    [orgs.items, sites.items, tree.data],
  );
  const skeletonIndex = useMemo(() => indexTree(skeleton), [skeleton]);

  const text = query.trim();
  const searchText = useDebounced(text, 250);
  const filtering = text !== "";
  const changes = filterChanges.query === query ? filterChanges.open : null;

  // A node's devices load once it is open (ADR-0069), and stay for the filter to search; the filter's own matches come
  // from the server, which finds devices in nodes that are closed.
  const wanted = useMemo(() => {
    const out: TreeNode[] = [];
    for (const n of skeletonIndex.values()) {
      if ((n.kind !== "site" && n.kind !== "group") || n.own === 0) continue;
      if ((expanded?.has(n.key) ?? false) || (filtering && changes?.get(n.key) === true)) out.push(n);
    }
    return out;
  }, [skeletonIndex, filtering, changes, expanded]);
  const nodeLists = useQueries({
    queries: wanted.map((n) => {
      const params = n.kind === "group" ? { groupId: n.id } : { siteId: n.id, ungrouped: "true" };
      return {
        queryKey: ["devices", "tree", n.key],
        queryFn: ({ signal }: { signal: AbortSignal }) => api.get<List<Device>>("/devices", params, signal),
        refetchInterval: 30_000,
        staleTime: 10_000,
      };
    }),
  });
  const found = useList<Device>(wantsDevices && searchText !== "" ? "/devices" : null, { q: searchText }, { keepPrevious: true });
  // The device the page is about, wherever its node is, so the tree can show and open the way to it.
  const selectedId = selected?.startsWith("d:") ? selected.slice(2) : null;
  const selectedDevice = useApi<Device>(wantsDevices && selectedId ? `/devices/${selectedId}` : null, undefined, { staleTime: 30_000 });
  const nodeKeys = wanted.map((n) => n.key).join(",");

  const devices = useMemo(() => {
    const byId = new Map<string, Device>();
    const add = (d: Device) => {
      // A reply can include devices from elsewhere (a stale list after a move); keep those whose node asked.
      if (!byId.has(d.id)) byId.set(d.id, d);
    };
    nodeLists.forEach((q, i) => {
      const n = wanted[i];
      if (!n) return;
      for (const d of q.data?.items ?? []) {
        if (n.kind === "group" ? d.deviceGroupId === n.id : d.siteId === n.id && !d.deviceGroupId) add(d);
      }
    });
    if (filtering) for (const d of found.items) add(d);
    if (selectedDevice.data) add(selectedDevice.data);
    return [...byId.values()];
    // nodeLists changes identity every render; its contents change with the data and the nodes asked.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodeLists.map((q) => q.dataUpdatedAt).join(","), nodeKeys, filtering, found.items, selectedDevice.data]);
  const loadingKeys = useMemo(() => new Set(wanted.filter((_, i) => nodeLists[i]?.isPending).map((n) => n.key)), [wanted, nodeLists]);

  const roots = useMemo(
    () => buildTree(orgs.items, sites.items, devices, { groups: tree.data?.groups ?? [], counts: tree.data?.counts ?? [] }),
    [orgs.items, sites.items, devices, tree.data],
  );
  const index = useMemo(() => indexTree(roots), [roots]);
  const filtered = useMemo(() => filterTree(roots, query), [roots, query]);

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
        if (c.groupId) add(`g:${c.groupId}`, c);
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
        if (!wantsDevices || tree.isPending || (typeof node === "object" && node.kind === "device")) return null;
        const n = typeof node === "object" ? node.total : total;
        return { text: n.toLocaleString(), label: plural(n, "device") };
      }
      case "alerts":
      case "scripts":
        return badges.get(key) ?? null;
      case "jobs":
      case "patching":
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
  }, [onWidth, loading, failed, roots, section, badges, online, total, wantsDevices, tree.isPending, waiting, selected]);

  // Open the way to whatever the page is showing, so the tree always says where you are. Only when the page changes:
  // closing a branch afterwards is the reader's choice.
  const revealed = useRef<string | null>(null);
  useEffect(() => {
    if (!selected || !expanded || revealed.current === selected || !index.has(selected)) return;
    revealed.current = selected;
    const chain = ancestors(index, selected);
    if (chain.some((k) => !expanded.has(k))) setExpanded(new Set([...expanded, ...chain]));
  }, [selected, index, expanded]);

  const isOpen = useCallback(
    (key: string) => (filtering ? (changes?.get(key) ?? filtered.expand.has(key)) : (expanded?.has(key) ?? false)),
    [filtering, changes, filtered.expand, expanded],
  );
  const rows = useMemo(() => visibleRows(filtered.roots, isOpen), [filtered.roots, isOpen]);

  // Only the rows on screen, and a few beyond, are rendered once the tree is long (ADR-0069).
  const [view, setView] = useState({ first: 0, count: 40 });
  const windowed = rows.length > WINDOW_AFTER;
  const start = windowed ? Math.max(0, view.first - OVERSCAN) : 0;
  const end = windowed ? Math.min(rows.length, view.first + view.count + OVERSCAN) : rows.length;
  const measureView = useCallback(() => {
    const el = scrollArea.current;
    if (!el) return;
    const first = Math.floor(Math.max(0, el.scrollTop - (treeEl.current?.offsetTop ?? 0)) / ROW_HEIGHT);
    const count = Math.ceil((el.clientHeight || 600) / ROW_HEIGHT) + 1;
    setView((v) => (v.first === first && v.count === count ? v : { first, count }));
  }, []);
  useEffect(() => {
    measureView();
    const el = scrollArea.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(measureView);
    ro.observe(el);
    return () => ro.disconnect();
  }, [measureView, rows.length, loading]);
  /** Scrolls the tree so that a row is on screen, rendered or not. */
  const scrollToRow = useCallback(
    (i: number, centre: boolean) => {
      const el = scrollArea.current;
      if (!el || i < 0) return;
      const top = (treeEl.current?.offsetTop ?? 0) + i * ROW_HEIGHT;
      const height = el.clientHeight || 600;
      if (centre) el.scrollTop = Math.max(0, top - height / 2);
      else if (top < el.scrollTop) el.scrollTop = top;
      else if (top + ROW_HEIGHT > el.scrollTop + height) el.scrollTop = top + ROW_HEIGHT - height;
      measureView();
    },
    [measureView],
  );
  const pendingFocus = useRef<string | null>(null);
  useEffect(() => {
    const key = pendingFocus.current;
    const el = key ? rowRefs.current.get(key) : undefined;
    if (el) {
      pendingFocus.current = null;
      el.focus();
    }
  });

  useEffect(() => {
    if (!selected) return;
    const el = rowRefs.current.get(selected);
    if (el) el.scrollIntoView?.({ block: "nearest" });
    else scrollToRow(rows.findIndex((r) => r.node.key === selected), false);
  }, [selected, rows.length, scrollToRow]); // eslint-disable-line react-hooks/exhaustive-deps

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
      go({ kind: "device", id: d.id, organizationId: d.organizationId, siteId: d.siteId, groupId: d.deviceGroupId });
    } else if (node.kind === "group") go({ kind: "group", id: node.id, organizationId: node.organizationId, siteId: node.siteId! });
    else if (node.kind === "site") go({ kind: "site", id: node.id, organizationId: node.organizationId });
    else go({ kind: "org", id: node.id });
  }

  const tabbable = rows.some((r) => r.node.key === focusKey) ? focusKey : rows.some((r) => r.node.key === selected) ? selected : (rows[0]?.node.key ?? null);
  // The tab stop is on screen: the first rendered row when the usual one is not.
  const shown = rows.slice(start, end);
  const tabStop = shown.some((r) => r.node.key === tabbable) ? tabbable : (shown[0]?.node.key ?? null);

  function focusRow(key: string | null | undefined) {
    if (!key) return;
    setFocusKey(key);
    const el = rowRefs.current.get(key);
    if (el) return el.focus();
    // Not rendered: scroll to it, and the effect above focuses it once it is.
    pendingFocus.current = key;
    scrollToRow(
      rows.findIndex((r) => r.node.key === key),
      true,
    );
  }

  const movable = (d: Device): Movable => d;

  /** What a row's menu offers; none when the caller may do nothing with the row. */
  function menuItems(node: TreeNode): RowMenuItem[] {
    const items: RowMenuItem[] = [];
    const d = node.device;
    if (d) {
      if (canMove) items.push({ key: "move", label: "Move to…", icon: <MoveRight className="size-4" aria-hidden />, onSelect: () => setPicker({ devices: [movable(d)] }) });
      if (section === "devices" && canQuickConnect(d)) {
        items.push({ key: "connect", label: "Quick connect", icon: <ScreenShare className="size-4" aria-hidden />, onSelect: () => openConnect(node) });
      }
    } else if (node.kind === "site" && canGroups) {
      items.push({ key: "new-group", label: "New group", icon: <FolderPlus className="size-4" aria-hidden />, onSelect: () => setGroupForm({ siteId: node.id }) });
    } else if (node.kind === "group" && canGroups) {
      const g = tree.data?.groups.find((x) => x.id === node.id);
      const group: DeviceGroup = { id: node.id, organizationId: node.organizationId, siteId: node.siteId!, name: node.name, description: g?.description ?? "", createdAt: "", updatedAt: "" };
      const siteName = index.get(siteKey(node.siteId!))?.name ?? "";
      items.push(
        { key: "rename", label: "Rename", icon: <Pencil className="size-4" aria-hidden />, onSelect: () => setGroupForm({ siteId: node.siteId!, group }) },
        { key: "delete", label: "Delete", icon: <Trash2 className="size-4" aria-hidden />, tone: "danger", onSelect: () => setGroupToDelete({ group, siteName }) },
      );
    }
    return items;
  }

  /** Opens a row's menu; a row with only Quick connect keeps opening that panel at once. */
  function openMenu(node: TreeNode): boolean {
    const el = rowRefs.current.get(node.key);
    const items = menuItems(node);
    if (!el || items.length === 0) return false;
    if (items.length === 1 && items[0]!.key === "connect") {
      openConnect(node);
      return true;
    }
    setMenu({ node, anchor: el });
    return true;
  }

  /** The place a tree node stands for; null for an organization, which has several sites to choose from. */
  function targetOf(node: TreeNode): MoveTarget | null {
    if (node.kind !== "site" && node.kind !== "group") return null;
    const org = index.get(orgKey(node.organizationId));
    const site = index.get(siteKey(node.siteId!));
    if (!org || !site) return null;
    return { organizationId: org.id, organizationName: org.name, siteId: site.id, siteName: site.name, groupId: node.kind === "group" ? node.id : null, groupName: node.kind === "group" ? node.name : "" };
  }

  function dropOn(node: TreeNode) {
    const devices = dragged();
    endDrag();
    setDropKey(null);
    if (devices.length === 0 || !canMove) return;
    if (node.kind === "org") return setPicker({ devices, organizationId: node.id });
    const target = targetOf(node);
    if (!target) return;
    const kind = widest(devices, target);
    if (kind === "none") return toast.info(`Already in ${target.groupName || target.siteName}.`);
    // Another site or organization has consequences; the reader confirms them.
    if (kind === "group") mover.mutate({ devices, target });
    else setConfirming({ devices, target });
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
    const hasChildren = node.expandable;
    if (e.key === "ContextMenu" || (e.key === "F10" && e.shiftKey)) {
      e.preventDefault();
      openMenu(node);
      return;
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
        return node.children.length > 0 ? focusRow(rows[i + 1]?.node.key) : undefined;
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

  const placeholder = "Filter by name or hostname";
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
        </p>
      </div>
      <div ref={scrollArea} onScroll={windowed ? measureView : undefined} className="relative min-h-0 flex-1 overflow-y-auto px-2 pb-2">
        {loading ? (
          <Spinner />
        ) : failed ? (
          <div className="rounded-md bg-surface">
            <ErrorState
              compact
              error={orgs.error ?? sites.error ?? tree.error ?? alertCounts.error ?? scripts.error}
              onRetry={() => {
                void orgs.refetch();
                void sites.refetch();
                if (wantsDevices) void tree.refetch();
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
              <div
                ref={treeEl}
                role="tree"
                aria-label={`${META[section].title}: organizations, sites, groups and devices`}
                onKeyDown={onKeyDown}
                style={windowed ? { paddingTop: start * ROW_HEIGHT, paddingBottom: (rows.length - end) * ROW_HEIGHT } : undefined}
              >
                {shown.map(({ node, position, siblings }) => {
                  const hasChildren = node.expandable;
                  const expandedRow = hasChildren && isOpen(node.key);
                  const isSelected = node.key === selected;
                  const d = node.device;
                  const quick = section === "devices" && d !== undefined && canQuickConnect(d);
                  const items = menuItems(node);
                  const target = node.kind === "device" ? false : node.kind === "org" || targetOf(node) !== null;
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
                      aria-keyshortcuts={items.length > 0 ? "Shift+F10" : undefined}
                      aria-haspopup={items.length > 1 || (items.length === 1 && !quick) ? "menu" : quick ? "dialog" : undefined}
                      tabIndex={node.key === tabStop ? 0 : -1}
                      title={d ? deviceTitle(d) : node.name}
                      onClick={() => {
                        setFocusKey(node.key);
                        activate(node);
                      }}
                      onContextMenu={
                        items.length > 0
                          ? (e) => {
                              e.preventDefault();
                              setFocusKey(node.key);
                              openMenu(node);
                            }
                          : undefined
                      }
                      draggable={canMove && d !== undefined}
                      onDragStart={
                        canMove && d
                          ? (e) => {
                              startDrag(e.dataTransfer, [movable(d)]);
                            }
                          : undefined
                      }
                      onDragEnd={d ? endDrag : undefined}
                      onDragOver={
                        canMove && target
                          ? (e) => {
                              if (!draggingDevices(e.dataTransfer)) return;
                              e.preventDefault();
                              e.dataTransfer.dropEffect = "move";
                              if (dropKey !== node.key) setDropKey(node.key);
                            }
                          : undefined
                      }
                      onDragLeave={target ? () => setDropKey((k) => (k === node.key ? null : k)) : undefined}
                      onDrop={
                        canMove && target
                          ? (e) => {
                              e.preventDefault();
                              dropOn(node);
                            }
                          : undefined
                      }
                      onFocus={() => {
                        setFocusKey(node.key);
                        if (d && section === "devices") prefetch(`/devices/${d.id}`);
                      }}
                      onMouseEnter={d && section === "devices" ? () => prefetch(`/devices/${d.id}`) : undefined}
                      className={cx(rowClasses(isSelected), indent[node.level], connecting && "bg-sidebar-active/60 text-white", dropKey === node.key && "bg-accent/40 text-white ring-2 ring-accent")}
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
                          {expandedRow && loadingKeys.has(node.key) ? (
                            <LoaderCircle className="size-3.5 animate-spin" />
                          ) : (
                            <ChevronRight className={cx("size-3.5 transition-transform", expandedRow && "rotate-90")} />
                          )}
                        </span>
                      ) : (
                        <span className="size-4 shrink-0" aria-hidden />
                      )}
                      {node.kind === "org" ? (
                        <Building2 className="size-3.5 shrink-0 text-sidebar-fg/60" aria-hidden />
                      ) : node.kind === "site" ? (
                        <MapPin className="size-3.5 shrink-0 text-sidebar-fg/60" aria-hidden />
                      ) : node.kind === "group" ? (
                        <FolderTree className="size-3.5 shrink-0 text-sidebar-fg/60" aria-hidden />
                      ) : (
                        <span className="inline-flex size-3.5 shrink-0 items-center justify-center">
                          <Dot tone={node.online ? "ok" : "neutral"} />
                        </span>
                      )}
                      {/* A device with an active critical alert pulses in red; its red count and its label say so too. */}
                      <span className={cx("min-w-0 flex-1 truncate", d && section === "alerts" && (byDevice.get(d.id)?.critical ?? 0) > 0 && "alert-active-pulse alert-active-pulse--sidebar")}>
                        {node.name}
                      </span>
                      <BadgeView badge={badge} />
                      {items.length > 0 && !(items.length === 1 && quick) && (
                        <button
                          type="button"
                          tabIndex={-1}
                          aria-label={`Actions for ${node.name}`}
                          title="Actions"
                          onClick={(e) => {
                            e.stopPropagation();
                            setFocusKey(node.key);
                            if (menu?.node.key === node.key) setMenu(null);
                            else openMenu(node);
                          }}
                          className={cx(
                            "-my-1 inline-flex size-6 shrink-0 items-center justify-center rounded text-sidebar-fg/80 hover:bg-white/15 hover:text-white",
                            isSelected || menu?.node.key === node.key ? "opacity-100" : "opacity-0 group-hover:opacity-100 group-focus:opacity-100 pointer-coarse:opacity-100",
                          )}
                        >
                          <MoreHorizontal className="size-3.5" aria-hidden />
                        </button>
                      )}
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
      {menu && (
        <RowMenu
          anchor={menu.anchor}
          label={`Actions for ${menu.node.name}`}
          items={menuItems(menu.node)}
          onClose={(returnFocus) => {
            const anchor = menu.anchor;
            setMenu(null);
            if (returnFocus) anchor.focus();
          }}
        />
      )}
      <MoveDialog devices={picker?.devices ?? []} open={picker !== null} organizationId={picker?.organizationId} onClose={() => setPicker(null)} />
      <ConfirmDialog
        open={confirming !== null}
        onClose={() => {
          setConfirming(null);
          mover.reset();
        }}
        onConfirm={() => confirming && mover.mutate(confirming)}
        title={confirming ? `Move ${confirming.devices.length === 1 ? confirming.devices[0]!.name : plural(confirming.devices.length, "device")} to ${confirming.target.groupName || confirming.target.siteName}?` : "Move"}
        confirmLabel="Move"
        loading={mover.isPending}
        error={mover.error}
      >
        {confirming && (
          <ul className="list-disc space-y-1 pl-5">
            {consequences(confirming.devices, confirming.target).map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        )}
      </ConfirmDialog>
      <DeviceGroupDialog open={groupForm !== null} siteId={groupForm?.siteId ?? ""} group={groupForm?.group} onClose={() => setGroupForm(null)} />
      <DeleteGroupDialog group={groupToDelete?.group ?? null} siteName={groupToDelete?.siteName ?? ""} onClose={() => setGroupToDelete(null)} />
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
    { id: "agent-updates", label: "Agent updates", icon: <ArrowUpCircle className="size-4" aria-hidden />, show: can("settings.manage") },
    { id: "agent-files", label: "Agent files", icon: <Fingerprint className="size-4" aria-hidden />, show: can("org.view") },
    { id: "notifications", label: "Notifications", icon: <Mail className="size-4" aria-hidden />, show: can("settings.manage") },
    { id: "forwarding", label: "Audit forwarding", icon: <Send className="size-4" aria-hidden />, show: can("settings.manage") },
    { id: "alert-policies", label: "Alert policies", icon: <Bell className="size-4" aria-hidden />, show: can("monitoring.view") },
    { id: "patching", label: "Patching", icon: <SlidersHorizontal className="size-4" aria-hidden />, show: can("patch.configure") },
    { id: "keystore", label: "Keystore", icon: <KeyRound className="size-4" aria-hidden />, show: can("settings.manage") },
    { id: "sso", label: "Single sign-on", icon: <LogIn className="size-4" aria-hidden />, show: can("settings.manage") },
  ]
    .filter((p) => p.show)
    .map(({ id, label, icon }) => ({ id, label, icon }));
}

/** Quick Assist's own tree (ADR-0080): its links, the requests waiting, the sessions running and the ones that ended. */
export const QUICK_ASSIST_VIEWS = [
  { id: "requests", label: "Requests" },
  { id: "active", label: "Active" },
  { id: "links", label: "Links" },
  { id: "ended", label: "Ended" },
] as const;

function QuickAssistNav() {
  const location = useLocation();
  const waiting = useApi<{ waiting: number }>("/quickassist/waiting", undefined, { refetchInterval: 5_000 });
  const requested = new URLSearchParams(location.search).get("view");
  const current = QUICK_ASSIST_VIEWS.some((v) => v.id === requested) ? requested : "requests";
  const count = waiting.data?.waiting ?? 0;
  return (
    <>
      <SectionHeader section="quickassist" />
      <ul className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-2">
        {QUICK_ASSIST_VIEWS.map((v) => (
          <li key={v.id}>
            <Link
              to={v.id === "requests" ? "/quickassist" : `/quickassist?view=${v.id}`}
              aria-current={current === v.id ? "page" : undefined}
              className={cx(
                "flex items-center justify-between gap-2.5 rounded-md px-3 py-2 text-sm",
                current === v.id ? "bg-sidebar-active font-medium text-white" : "text-sidebar-fg hover:bg-sidebar-active/60 hover:text-white",
              )}
            >
              {v.label}
              {v.id === "requests" && count > 0 && (
                <span className="rounded-full bg-accent px-1.5 text-xs text-white" aria-label={`${count} waiting`}>
                  {count}
                </span>
              )}
            </Link>
          </li>
        ))}
      </ul>
    </>
  );
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
