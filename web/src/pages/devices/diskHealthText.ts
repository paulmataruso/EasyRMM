// Words for disk health (ADR-0065): every state and reason in one place, shared by the Disks card, a disk's panel, the
// Devices list and alerts. The operations guide's disk health page uses the same words.
import type { DiskDay, DiskFact, DiskHealth, DiskHealthFilter, DiskHealthSummary, DiskState, FactState, TextFact } from "../../api/types";
import type { Tone } from "../../components/ui";
import { formatShortDate, formatShortDateTime, plural } from "../../lib/format";

export interface StateWords {
  label: string;
  tone: Tone;
  /** What the state means, in a sentence. */
  means: string;
}

/** Every state a disk or a fact shows (ADR-0065, "The five states"). */
export const STATES: Record<FactState, StateWords> = {
  healthy: { label: "Healthy", tone: "ok", means: "Read and checked, and within every rule." },
  warning: { label: "Warning", tone: "warn", means: "Read and checked, and a rule for wear or damage holds." },
  failing: { label: "Failing", tone: "danger", means: "Read and checked, and the drive's own verdict is that it is failing." },
  unknown: { label: "Unknown", tone: "info", means: "EasyRMM can read this here, and this time it could not tell. It may clear at the next reading." },
  unsupported: { label: "Unsupported", tone: "neutral", means: "The disk, by what it is, has no such data. This does not change for this disk." },
  unavailable: {
    label: "Unavailable",
    tone: "neutral",
    means: "The data exists, but EasyRMM cannot reach it from where the agent runs. Something else has to change first, such as the controller's own tools.",
  },
  reported: { label: "Reported", tone: "neutral", means: "Read, and EasyRMM does not judge it." },
};

/** A state's words; one a newer server sends shows as its code. */
export function stateWords(state: string): StateWords {
  return Object.hasOwn(STATES, state) ? STATES[state as FactState] : { label: state, tone: "neutral", means: "" };
}

/**
 * Why a disk or a fact shows its state, in words that follow "Unavailable: " or "Unknown: ". The agent's codes are
 * internal/agentproto/hardware.go's; the server's rules (server/internal/hardware/judge.go) name why a disk or a fact is
 * warning or failing, where the disk's detail says it in a sentence.
 */
export const REASONS: Record<string, string> = {
  container: "the agent runs in a container",
  virtual_disk: "a virtual machine's emulated disk",
  virtual_machine: "a virtual machine that does not pass the disk's health through",
  storage_spaces: "a Storage Spaces virtual disk",
  memory_card: "an SD or MMC card",
  raid_controller: "behind a RAID controller",
  storage_driver: "a storage driver refused the query",
  device_refused: "the disk refused the query",
  protocol_not_read: "a SAS or other SCSI disk, not read yet",
  usb_bridge: "behind a USB bridge, not read yet",
  no_smart: "the drive has no SMART",
  smart_off: "SMART is turned off on the drive",
  asleep: "asleep, not woken",
  timeout: "timed out",
  timed_out_recently: "timed out in the last 24 hours, left alone until then",
  io_error: "an I/O error",
  access_denied: "the agent is not allowed to query the disk",
  bad_checksum: "the answer's checksum was wrong",
  bad_answer: "the answer was too short or malformed",
  agent_error: "the agent failed reading it",
  other_disk: "another disk answered under this name",
  not_kept: "the drive does not keep this",
  not_valid: "the drive holds no valid value for this now",
  not_exposed: "the operating system does not show this",
  no_verdict: "the drive's verdict could not be read",
  stale: "not read for over 2 hours",
  missing: "not in the device's latest report",
  invalid_report: "the agent's report could not be used",
  critical_warning: "NVMe critical warning",
  smart_status: "SMART status: threshold exceeded",
  prefail_attribute: "a pre-fail attribute at or below its threshold",
  attribute: "an attribute at or below its threshold",
  temperature: "at or over the drive's own temperature limit",
  wear: "90% or more of rated endurance used",
  media_errors: "NVMe media errors",
  reallocated_sectors: "reallocated sectors",
  pending_sectors: "sectors pending reallocation",
  uncorrectable_sectors: "uncorrectable sectors",
};

/** A reason in words; a code a newer server or agent sends shows as itself. */
export function reasonText(code: string | undefined): string {
  if (!code) return "";
  return Object.hasOwn(REASONS, code) ? (REASONS[code] as string) : code;
}

/** A state with its reason: "Unavailable: behind a RAID controller", or "Healthy" alone. */
export function stateText(state: string, reason?: string): string {
  const label = stateWords(state).label;
  const why = reasonText(reason);
  return why ? `${label}: ${why}` : label;
}

/** What the Disks card and a disk's panel show for a disk (ADR-0065, "What the console shows for a disk"). */
export interface DiskShown {
  tone: Tone;
  /** The state in a word, then the rest of its line: together "Failing, last read 2 May 14:30". */
  head: string;
  rest: string;
  /** What made it warning or failing, or what the agent added about a disk it could not read. */
  detail: string;
  /** Readings since the last judged one that could not tell. */
  note: string;
  /** When the reading shown arrived, for a line that does not say it. */
  asOf: string;
}

/** A disk's state in words, the first that applies: missing; unsupported or unavailable; failing or warning, however
 * old; healthy; unknown. */
export function diskShown(d: DiskHealth, now: Date = new Date()): DiskShown {
  const when = (at: string | null) => formatShortDateTime(at, now);
  const base = { detail: "", note: "", asOf: "" };
  if (d.missingSince) {
    const [level, at] = d.judgedLevel && d.judgedAt ? [d.judgedLevel, d.judgedAt] : [d.latest.state, d.latest.receivedAt];
    return {
      ...base,
      tone: level === "failing" || level === "warning" ? stateWords(level).tone : "info",
      head: "Missing",
      rest: ` since ${formatShortDate(d.missingSince, now)}; last read ${stateWords(level).label}, ${when(at)}`,
    };
  }
  const words = stateWords(d.state);
  const asOf = `As of ${when(d.latest.receivedAt)}`;
  switch (d.state) {
    case "unsupported":
    case "unavailable":
      return { ...base, tone: words.tone, head: words.label, rest: reasonText(d.reason) ? `: ${reasonText(d.reason)}` : "", detail: d.detail, asOf };
    case "failing":
    case "warning":
    case "healthy":
      return {
        ...base,
        tone: words.tone,
        head: words.label,
        rest: `, last read ${when(d.judgedAt)}`,
        detail: d.state === "healthy" ? "" : d.detail || reasonText(d.reason),
        note: sinceNote(d),
      };
    case "unknown":
      if (d.reason === "stale" && d.judgedAt) return { ...base, tone: words.tone, head: words.label, rest: `: not read since ${when(d.judgedAt)}`, note: sinceNote(d) };
      return { ...base, tone: words.tone, head: words.label, rest: reasonText(d.reason) ? `: ${reasonText(d.reason)}` : "", detail: d.detail, note: sinceNote(d), asOf };
    default:
      return { ...base, tone: words.tone, head: words.label, rest: reasonText(d.reason) ? `: ${reasonText(d.reason)}` : "", detail: d.detail, asOf };
  }
}

/** The whole line: "Failing, last read 2 May 14:30". */
export function diskLine(d: DiskHealth, now?: Date): string {
  const s = diskShown(d, now);
  return s.head + s.rest;
}

/** "The 3 readings since could not tell; the latest: timed out." for a disk whose later readings could not tell. */
export function sinceNote(d: Pick<DiskHealth, "since" | "judgedAt" | "latest">): string {
  if (d.since <= 0 || !d.judgedAt) return "";
  const why = reasonText(d.latest.reason) || stateWords(d.latest.state).label.toLowerCase();
  return d.since === 1 ? `The reading since could not tell: ${why}.` : `The ${d.since.toLocaleString()} readings since could not tell; the latest: ${why}.`;
}

/** A disk's firmware revision, or why there is none; null from an agent too old to report it. */
export function firmwareText(f: TextFact | undefined): string | null {
  if (!f) return null;
  if (f.state === "read") return f.value || stateText("unknown");
  return stateText(f.state, f.reason);
}

// A device's disk health (ADR-0065, "A device's disk health") ------------------------------------------------------

/** How the Devices list sorts by disk health: failing, warning, unknown, unavailable, healthy, unsupported, then a
 * state a newer server sends, then not reported. */
const RANK: DiskState[] = ["failing", "warning", "unknown", "unavailable", "healthy", "unsupported"];
const NOT_REPORTED_RANK = RANK.length + 1;

export interface DeviceDiskHealth {
  label: string;
  tone: Tone;
  /** Every disk counted: "2 disks failing, 3 disks healthy". */
  title: string;
  rank: number;
}

/**
 * A device's label: the highest of its disks' states in the order failing, warning, unknown, healthy, with the disks
 * in the other two counted after it ("Healthy, 3 disks unavailable"); a device with none in those four is Unavailable
 * if any disk is, else Unsupported, with its count ("Unavailable, 4 disks"); one whose agent reported none is Not
 * reported.
 */
export function deviceDiskHealth(s: DiskHealthSummary | null): DeviceDiskHealth {
  if (!s) return { label: "Not reported", tone: "neutral", title: "The device's agent has reported no disk health.", rank: NOT_REPORTED_RANK };
  const n = (state: DiskState) => s.states[state] ?? 0;
  const title = RANK.filter((st) => n(st) > 0)
    .map((st) => `${plural(n(st), "disk")} ${STATES[st].label.toLowerCase()}`)
    .join(", ");
  const head = stateWords(s.label);
  const rank = RANK.indexOf(s.label);
  const parts = [head.label];
  if (s.label === "unavailable" || s.label === "unsupported") parts.push(plural(n(s.label), "disk"));
  for (const other of ["unavailable", "unsupported"] as const) {
    if (other !== s.label && n(other) > 0) parts.push(`${plural(n(other), "disk")} ${other}`);
  }
  return { label: parts.join(", "), tone: head.tone, title, rank: rank < 0 ? RANK.length : rank };
}

/** The Devices list's disk health filter. Unavailable and Unsupported find a device with any disk in that state. */
export const DISK_FILTERS: { value: DiskHealthFilter; label: string }[] = [
  { value: "failing", label: "Failing" },
  { value: "warning", label: "Warning" },
  { value: "unknown", label: "Unknown" },
  { value: "healthy", label: "Healthy" },
  { value: "unavailable", label: "Unavailable" },
  { value: "unsupported", label: "Unsupported" },
  { value: "not_reported", label: "Not reported" },
];

// A disk's facts ----------------------------------------------------------------------------------------------------

/** The NVMe critical warning's bits, as the server names them. */
const CRITICAL_WARNING_BITS = [
  "available spare below its threshold",
  "temperature",
  "reliability degraded",
  "media read-only",
  "volatile memory backup failed",
  "persistent memory region read-only or unreliable",
  "bit 6 (reserved)",
  "bit 7 (reserved)",
];

const count = (v: number) => v.toLocaleString();
const capital = (s: string) => (s ? s[0]!.toUpperCase() + s.slice(1) : s);

/** Bytes with decimal units, as drives rate what may be written to them: "18.4 TB". */
export function decimalSize(bytes: number): string {
  const units = ["bytes", "kB", "MB", "GB", "TB", "PB", "EB"];
  let v = bytes;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return i === 0 ? `${v} bytes` : `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
}

interface FactWords {
  label: string;
  value: (v: number) => string;
}

/** Each fact of a reading, in the order the server lists them. */
export const FACTS: Record<string, FactWords> = {
  criticalWarning: {
    label: "Critical warning (NVMe)",
    value: (v) => (v === 0 ? "None" : capital(CRITICAL_WARNING_BITS.filter((_, i) => v & (1 << i)).join(", "))),
  },
  smartStatus: { label: "SMART status", value: (v) => (v === 1 ? "Threshold exceeded" : "Passed") },
  // Thresholds carry no value: the fact says whether READ ATTRIBUTE THRESHOLDS was read.
  thresholds: { label: "Attribute thresholds", value: () => "Read" },
  temperature: { label: "Temperature", value: (v) => `${v} °C` },
  temperatureLimit: { label: "The drive's temperature limit", value: (v) => (v > 0 ? `${v} °C` : "None set") },
  wear: { label: "Wear", value: (v) => (v >= 255 ? "Over 254% of rated endurance used" : `${v}% of rated endurance used`) },
  availableSpare: { label: "Available spare", value: (v) => `${v}%` },
  availableSpareThreshold: { label: "Available spare threshold", value: (v) => `${v}%` },
  mediaErrors: { label: "Media errors", value: count },
  reallocatedSectors: { label: "Reallocated sectors", value: count },
  pendingSectors: { label: "Pending sectors", value: count },
  uncorrectableSectors: { label: "Uncorrectable sectors", value: count },
  driveErrors: { label: "Errors in the drive's log", value: count },
  powerOnHours: { label: "Power-on hours", value: count },
  // NVMe counts data units of 1,000 units of 512 bytes.
  dataWritten: { label: "Data written", value: (v) => decimalSize(v * 512_000) },
  unsafeShutdowns: { label: "Unsafe shutdowns", value: count },
  powerMode: { label: "Power mode", value: (v) => ({ 0: "Standby", 128: "Idle", 255: "Active or idle" })[v] ?? `0x${v.toString(16).toUpperCase()}` },
};

/** A fact's name and value in words; a fact a newer server sends shows as its name and number. */
export function factText(f: DiskFact): { label: string; value: string } {
  const words = Object.hasOwn(FACTS, f.name) ? FACTS[f.name] : undefined;
  if (!words) return { label: f.name, value: f.value === null ? "—" : String(f.value) };
  if (f.name === "thresholds") return { label: words.label, value: f.state === "reported" ? words.value(0) : "—" };
  return { label: words.label, value: f.value === null ? "—" : words.value(f.value) };
}

/** ATA attributes whose meaning the makers share (ADR-0065, "What is read"); the rest are the maker's own. */
export const ATTRIBUTES: Record<number, string> = {
  5: "Reallocated sectors",
  9: "Power-on hours",
  190: "Airflow temperature",
  194: "Temperature",
  197: "Pending sectors",
  198: "Offline uncorrectable sectors",
};

/** How a disk answered (DiskHealth.route). */
export const ROUTES: Record<string, string> = {
  device: "Windows, asked of the device",
  adapter: "Windows, asked of its adapter",
  ata: "Windows, ATA pass-through",
  nvme: "Linux, the NVMe admin command",
  sg: "Linux, ATA pass-through over SCSI generic",
};

export const PROTOCOLS: Record<string, string> = { nvme: "NVMe", ata: "ATA" };

/** A UTC day of a disk's history: "3 May". */
export function formatDay(day: string, now: Date = new Date()): string {
  const d = new Date(day);
  if (Number.isNaN(d.getTime())) return day;
  return d.toLocaleDateString(undefined, { day: "numeric", month: "short", ...(d.getUTCFullYear() !== now.getUTCFullYear() && { year: "numeric" }), timeZone: "UTC" });
}

/** The columns of a disk's last 30 days, those with a value on any day. */
export const HISTORY_COLUMNS: { key: Exclude<keyof DiskDay, "day" | "state" | "powerOnHours">; label: string; value: (v: number) => string }[] = [
  { key: "temperature", label: "Highest temperature", value: (v) => `${v} °C` },
  { key: "wear", label: "Wear", value: (v) => `${v}%` },
  { key: "reallocatedSectors", label: "Reallocated sectors", value: count },
  { key: "mediaErrors", label: "Media errors", value: count },
  { key: "pendingSectors", label: "Pending sectors", value: count },
  { key: "uncorrectableSectors", label: "Uncorrectable sectors", value: count },
  { key: "driveErrors", label: "Errors in the drive's log", value: count },
];

export function historyColumns(days: DiskDay[]) {
  return HISTORY_COLUMNS.filter((c) => days.some((d) => d[c.key] !== null));
}
