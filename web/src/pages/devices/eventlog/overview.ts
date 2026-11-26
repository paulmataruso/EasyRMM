import type { EventlogEvent, EventlogIdRange, EventlogRequest } from "../../../api/types";

/**
 * The admin overview of a Windows device's event logs: what an administrator diagnosing an issue wants first. Its requests are
 * typed filters like any other search and go through the same server checks, permission and audit; nothing here is XPath.
 */

export interface KeyEvent {
  /** What the group is called. */
  category: string;
  /** What the event means. */
  label: string;
  log: "System" | "Application" | "Security";
  providers: string[];
  ids: number[];
  /** Read only with the permission to see the Security log. */
  sensitive?: boolean;
}

export const KEY_EVENTS: KeyEvent[] = [
  { category: "Unexpected shutdowns and restarts", label: "Unexpected shutdown", log: "System", providers: ["EventLog"], ids: [6008] },
  { category: "Unexpected shutdowns and restarts", label: "Restarted without a clean shutdown", log: "System", providers: ["Microsoft-Windows-Kernel-Power"], ids: [41] },
  { category: "Unexpected shutdowns and restarts", label: "Restart or shutdown started by a process", log: "System", providers: ["User32"], ids: [1074] },
  { category: "Service crashes and failures", label: "Service stopped unexpectedly or failed", log: "System", providers: ["Service Control Manager"], ids: [7031, 7034, 7000, 7009, 7023] },
  { category: "Disk and NTFS errors", label: "Disk error", log: "System", providers: ["disk"], ids: [7, 11, 51, 153] },
  { category: "Disk and NTFS errors", label: "NTFS error", log: "System", providers: ["Ntfs", "Microsoft-Windows-Ntfs"], ids: [55, 98] },
  { category: "Application crashes and hangs", label: "Application crash", log: "Application", providers: ["Application Error"], ids: [1000] },
  { category: "Application crashes and hangs", label: "Application hang", log: "Application", providers: ["Application Hang"], ids: [1002] },
  { category: "Application crashes and hangs", label: "Windows Error Reporting", log: "Application", providers: ["Windows Error Reporting"], ids: [1001] },
  { category: "Windows Update failures", label: "Update failed", log: "System", providers: ["Microsoft-Windows-WindowsUpdateClient"], ids: [20] },
  { category: "Group Policy failures", label: "Group Policy failed", log: "System", providers: ["Microsoft-Windows-GroupPolicy"], ids: [1129, 1053, 1055] },
  { category: "Time sync problems", label: "Time service problem", log: "System", providers: ["Microsoft-Windows-Time-Service"], ids: [36, 47, 129] },
  { category: "Domain and Netlogon problems", label: "Netlogon problem", log: "System", providers: ["NETLOGON", "Netlogon"], ids: [5719, 5722, 5805] },
  { category: "Failed sign-ins and lockouts", label: "Failed sign-in", log: "Security", providers: ["Microsoft-Windows-Security-Auditing"], ids: [4625], sensitive: true },
  { category: "Failed sign-ins and lockouts", label: "Account locked out", log: "Security", providers: ["Microsoft-Windows-Security-Auditing"], ids: [4740], sensitive: true },
];

export const OVERVIEW_RANGE = "24h" as const;

/** The key events a person may see: the Security ones only with the sensitive permission. */
export function keyEventsFor(holdsSensitive: boolean): KeyEvent[] {
  return KEY_EVENTS.filter((k) => holdsSensitive || !k.sensitive);
}

/**
 * The most event IDs one query names. Windows refuses a structured query of more than about 22 expressions ("the specified query
 * is invalid"), and the time range is one; so the key events are read in several queries, one log at a time, each by ID only.
 */
export const KEY_IDS_PER_QUERY = 12;

/** The queries that read the key events: their IDs, a few at a time, over the log they live in. The page keeps exact matches. */
export function keyEventsRequests(holdsSensitive: boolean): EventlogRequest[] {
  const keys = keyEventsFor(holdsSensitive);
  const out: EventlogRequest[] = [];
  for (const log of [...new Set(keys.map((k) => k.log))]) {
    const ids = [...new Set(keys.filter((k) => k.log === log).flatMap((k) => k.ids))].sort((a, b) => a - b);
    for (let i = 0; i < ids.length; i += KEY_IDS_PER_QUERY) {
      const r: EventlogRequest = { op: "query", channels: [log], ids: ids.slice(i, i + KEY_IDS_PER_QUERY).map((from) => ({ from })), time: { last: OVERVIEW_RANGE } };
      if (log === "Security") r.sensitive = true;
      out.push(r);
    }
  }
  return out;
}

/** Critical, Error and Warning events of System and Application in the last 24 hours; the page drops Application warnings. */
export function problemsRequest(): EventlogRequest {
  return { op: "query", channels: ["System", "Application"], levels: [1, 2, 3], time: { last: OVERVIEW_RANGE } };
}

const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** The key event an event is, if any: its log, source and ID must all match. */
export function matchKeyEvent(e: Pick<EventlogEvent, "log" | "provider" | "id">, keys: KeyEvent[] = KEY_EVENTS): KeyEvent | undefined {
  return keys.find((k) => same(k.log, e.log) && k.ids.includes(e.id) && k.providers.some((p) => same(p, e.provider)));
}

/** Whether the overview lists a problem event: Critical and Error anywhere, Warnings from System only. */
export function isProblem(e: Pick<EventlogEvent, "log" | "level">): boolean {
  return e.level === 1 || e.level === 2 || (e.level === 3 && same(e.log, "System"));
}

export interface EventGroup {
  key: string;
  /** The newest event of the group, which the row opens. */
  newest: EventlogEvent;
  count: number;
  /** When the group's oldest event happened. */
  since: string;
  /** What a count links to: the filters that find exactly these events. */
  filter: { log: string; provider: string; id: number; level?: number };
}

/** Repeats of one event (the same log, source and ID, and for problems the same level) become one row, newest first. */
export function groupRepeats(events: EventlogEvent[], withLevel: boolean): EventGroup[] {
  const by = new Map<string, EventGroup>();
  for (const e of events) {
    const key = [e.log.toLowerCase(), e.provider.toLowerCase(), e.id, withLevel ? e.level : ""].join("|");
    const g = by.get(key);
    if (!g) {
      by.set(key, { key, newest: e, count: 1, since: e.time, filter: { log: e.log, provider: e.provider, id: e.id, ...(withLevel ? { level: e.level } : {}) } });
      continue;
    }
    g.count++;
    if (Date.parse(e.time) > Date.parse(g.newest.time)) g.newest = e;
    if (Date.parse(e.time) < Date.parse(g.since)) g.since = e.time;
  }
  return [...by.values()].sort((a, b) => Date.parse(b.newest.time) - Date.parse(a.newest.time));
}

export interface KeyEventGroup {
  category: string;
  groups: (EventGroup & { label: string })[];
  total: number;
}

/** The key events found, grouped by category and then by repeats; categories with nothing found are left out. */
export function groupKeyEvents(events: EventlogEvent[], holdsSensitive: boolean): KeyEventGroup[] {
  const keys = keyEventsFor(holdsSensitive);
  const hits = events.filter((e) => matchKeyEvent(e, keys));
  const out = new Map<string, KeyEventGroup>();
  for (const g of groupRepeats(hits, false)) {
    const k = matchKeyEvent(g.newest, keys);
    if (!k) continue;
    const c = out.get(k.category) ?? { category: k.category, groups: [], total: 0 };
    c.groups.push({ ...g, label: k.label });
    c.total += g.count;
    out.set(k.category, c);
  }
  const order = [...new Set(keys.map((k) => k.category))];
  return [...out.values()].sort((a, b) => order.indexOf(a.category) - order.indexOf(b.category));
}

/** "×12 since 09:14", or the event's own time when it happened once. */
export function repeatText(g: Pick<EventGroup, "count" | "since">, clock: (iso: string) => string): string {
  return g.count > 1 ? `×${g.count} since ${clock(g.since)}` : "once";
}
