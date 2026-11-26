import type { EventlogChannel, EventlogEnd, EventlogEvent, EventlogIdRange, EventlogPos, EventlogState } from "../../../api/types";

/** What each state is called on the page (ADR-0068, States). */
export const STATE_TEXT: Record<EventlogState, string> = {
  reported: "Reported by the computer",
  unavailable: "Unavailable",
  not_found: "Not found",
  refused: "Refused by EasyRMM",
  unknown: "Unknown",
};

export const LEVELS: { value: number; label: string }[] = [
  { value: 1, label: "Critical" },
  { value: 2, label: "Error" },
  { value: 3, label: "Warning" },
  { value: 4, label: "Information" },
  { value: 5, label: "Verbose" },
];

/** The level as Event Viewer names it: Information is 0 or 4. */
export function levelName(e: Pick<EventlogEvent, "level" | "levelName">): string {
  if (e.levelName) return e.levelName;
  return e.level === 0 ? "Information" : (LEVELS.find((l) => l.value === e.level)?.label ?? String(e.level));
}

export function levelTone(level: number): "danger" | "warn" | "info" | "neutral" {
  if (level === 1 || level === 2) return "danger";
  if (level === 3) return "warn";
  if (level === 0 || level === 4) return "info";
  return "neutral";
}

export const RANGES: { value: string; label: string }[] = [
  { value: "1h", label: "Last hour" },
  { value: "12h", label: "Last 12 hours" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "any", label: "Any time" },
];

/** Event IDs and ranges as a person types them: "41, 100-200", and "-7036" to leave one out. */
export function parseIds(text: string): { ids: EventlogIdRange[]; exclude: EventlogIdRange[]; error?: string } {
  const ids: EventlogIdRange[] = [];
  const exclude: EventlogIdRange[] = [];
  for (const raw of text.split(/[,\s]+/).filter(Boolean)) {
    const neg = raw.startsWith("-");
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(neg ? raw.slice(1) : raw);
    if (!m) return { ids, exclude, error: `"${raw}" is not an event ID or a range such as 100-200.` };
    const from = Number(m[1]);
    const to = m[2] === undefined ? undefined : Number(m[2]);
    if (from > 65535 || (to !== undefined && (to > 65535 || to < from))) return { ids, exclude, error: `"${raw}" is not a valid event ID or range.` };
    (neg ? exclude : ids).push(to === undefined ? { from } : { from, to });
  }
  if (ids.length > 32 || exclude.length > 32) return { ids, exclude, error: "At most 32 event IDs or ranges to include and 32 to leave out." };
  return { ids, exclude };
}

/** A computer's channels grouped as the console shows them: Windows Logs first, then the others by provider. */
export interface ChannelGroup {
  title: string;
  channels: EventlogChannel[];
}

const WINDOWS_LOGS = ["Application", "Security", "Setup", "System", "ForwardedEvents"];

export function groupChannels(all: EventlogChannel[], showAnalytic: boolean): ChannelGroup[] {
  const logs: EventlogChannel[] = [];
  const byProvider = new Map<string, EventlogChannel[]>();
  for (const c of all) {
    if (!showAnalytic && (c.type === "analytic" || c.type === "debug")) continue;
    const win = WINDOWS_LOGS.find((n) => n.toLowerCase() === c.name.toLowerCase());
    if (win) {
      logs.push(c);
      continue;
    }
    const i = c.name.indexOf("/");
    const provider = i > 0 ? c.name.slice(0, i) : c.name;
    byProvider.set(provider, [...(byProvider.get(provider) ?? []), c]);
  }
  logs.sort((a, b) => WINDOWS_LOGS.findIndex((n) => n.toLowerCase() === a.name.toLowerCase()) - WINDOWS_LOGS.findIndex((n) => n.toLowerCase() === b.name.toLowerCase()));
  const out: ChannelGroup[] = [];
  if (logs.length) out.push({ title: "Windows Logs", channels: logs });
  for (const [title, channels] of [...byProvider.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    out.push({ title, channels: channels.sort((a, b) => a.name.localeCompare(b.name)) });
  }
  return out;
}

export function isSecurityChannel(name: string): boolean {
  const n = name.toLowerCase();
  return n === "security" || n.startsWith("archive-security-");
}

/** The time shown for an event, in the chosen zone, to the second. */
export type Zone = "local" | "computer" | "utc";

export function eventTime(e: Pick<EventlogEvent, "time" | "offset">, zone: Zone): string {
  const t = new Date(e.time);
  if (Number.isNaN(t.getTime())) return e.time;
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  const fmt = (d: Date) => `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  if (zone === "utc") return `${fmt(t)} UTC`;
  if (zone === "computer") {
    if (e.offset === undefined) return `${fmt(t)} UTC`;
    return `${fmt(new Date(t.getTime() + e.offset * 1000))} (${offsetText(e.offset)})`;
  }
  return t.toLocaleString("en-GB", { dateStyle: "short", timeStyle: "medium" });
}

export function offsetText(seconds: number): string {
  const sign = seconds < 0 ? "-" : "+";
  const a = Math.abs(seconds);
  return `UTC${sign}${String(Math.floor(a / 3600)).padStart(2, "0")}:${String(Math.floor((a % 3600) / 60)).padStart(2, "0")}`;
}

/** What the page says about how far a page got (ADR-0068, States). */
export function endText(end: EventlogEnd | undefined, zone: Zone): string | null {
  if (!end) return null;
  const back = end.searchedBack ? eventTime({ time: end.searchedBack }, zone === "computer" ? "utc" : zone) : "";
  switch (end.stoppedBy) {
    case "read":
      return `Searched ${end.read.toLocaleString()} events back to ${back}; more may match.`;
    case "time":
      return `The time limit was reached after ${end.read.toLocaleString()} events${back ? `, back to ${back}` : ""}; more may match.`;
    case "cancel":
      return "The search was canceled.";
    default:
      return null;
  }
}

/** A channel's state in a query, as the page says it. */
export function posText(p: EventlogPos): string | null {
  if (p.cleared) return `${p.channel}: this log was cleared since the first page. Start again.`;
  if (p.overwritten) return `${p.channel}: events after ${p.oldestAt ?? "the first page"} were overwritten since the first page.`;
  switch (p.state) {
    case "not_found":
      return `No log named ${p.channel} on this computer.`;
    case "denied":
      return `Access denied to ${p.channel}.`;
    case "unavailable":
      return p.reason ?? `${p.channel} is unavailable.`;
    default:
      return null;
  }
}

/** An event as text for copying: the fields shown, then the message. */
export function eventAsText(e: EventlogEvent, zone: Zone): string {
  const lines = [
    `Log Name:      ${e.log}`,
    `Source:        ${e.provider}`,
    `Date:          ${eventTime(e, zone)}`,
    `Event ID:      ${e.id}`,
    `Task Category: ${e.taskName ?? e.task}`,
    `Level:         ${levelName(e)}`,
    `Keywords:      ${(e.keywordNames ?? [e.keywords]).join(", ")}`,
    `User:          ${e.user || e.userSid || "N/A"}`,
    `Computer:      ${e.computer}`,
    "",
  ];
  if (e.messageHidden) lines.push("(hidden: needs permission to see command lines and scripts)");
  else if (e.message) lines.push(e.message);
  else if (e.messageNote) lines.push(e.messageNote);
  return lines.join("\n");
}

/** Bytes as a person reads them. */
export function sizeText(n: number | undefined): string {
  if (n === undefined) return "";
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GiB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MiB`;
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(0)} KiB`;
  return `${n} B`;
}
