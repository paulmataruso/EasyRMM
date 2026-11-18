export function parseDate(value: string | null | undefined): Date | null {
  if (!value) return null;
  const d = new Date(value);
  // Go encodes a zero time.Time as 0001-01-01; treat it as missing.
  return Number.isNaN(d.getTime()) || d.getUTCFullYear() < 1970 ? null : d;
}

export function formatDateTime(value: string | null | undefined): string {
  const d = parseDate(value);
  if (!d) return "—";
  return d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function formatDate(value: string | null | undefined): string {
  const d = parseDate(value);
  if (!d) return "—";
  return d.toLocaleDateString(undefined, { dateStyle: "medium" });
}

const RELATIVE_UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31_536_000],
  ["month", 2_592_000],
  ["week", 604_800],
  ["day", 86_400],
  ["hour", 3_600],
  ["minute", 60],
  ["second", 1],
];

export function formatRelative(value: string | null | undefined, now: number = Date.now()): string {
  const d = parseDate(value);
  if (!d) return "never";
  const seconds = Math.round((d.getTime() - now) / 1000);
  if (Math.abs(seconds) < 45) return "just now";
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [unit, size] of RELATIVE_UNITS) {
    if (Math.abs(seconds) >= size) return rtf.format(Math.round(seconds / size), unit);
  }
  return rtf.format(seconds, "second");
}

export function formatNumber(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : value.toLocaleString();
}

const SIZE_UNITS = ["KiB", "MiB", "GiB", "TiB", "PiB"];

/** A size in bytes with binary units, as operating systems show disks and memory: "7.8 GiB". */
export function formatSize(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;
  let value = bytes;
  let unit = "B";
  for (const u of SIZE_UNITS) {
    if (value < 1024) break;
    value /= 1024;
    unit = u;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${unit}`;
}

/** A duration in seconds as its two largest units: "3 d 4 h", "2 h 5 min", "45 s". */
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86_400);
  const h = Math.floor((s % 86_400) / 3_600);
  const m = Math.floor((s % 3_600) / 60);
  if (d > 0) return h > 0 ? `${d} d ${h} h` : `${d} d`;
  if (h > 0) return m > 0 ? `${h} h ${m} min` : `${h} h`;
  if (m > 0) return `${m} min`;
  return `${s} s`;
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${count.toLocaleString()} ${count === 1 ? one : many}`;
}

/** A short, human description of a browser user agent ("Firefox on Windows"). */
export function describeUserAgent(ua: string | null | undefined): string {
  if (!ua) return "Unknown device";
  const browser = /Edg\//.test(ua)
    ? "Edge"
    : /OPR\//.test(ua)
      ? "Opera"
      : /Firefox\//.test(ua)
        ? "Firefox"
        : /Chrome\//.test(ua)
          ? "Chrome"
          : /Safari\//.test(ua)
            ? "Safari"
            : /curl\//.test(ua)
              ? "curl"
              : null;
  const os = /Windows/.test(ua)
    ? "Windows"
    : /iPhone|iPad/.test(ua)
      ? "iOS"
      : /Mac OS X/.test(ua)
        ? "macOS"
        : /Android/.test(ua)
          ? "Android"
          : /Linux/.test(ua)
            ? "Linux"
            : null;
  if (browser && os) return `${browser} on ${os}`;
  return browser ?? os ?? (ua.length > 60 ? `${ua.slice(0, 57)}…` : ua);
}

/** Browser time zones, with UTC first. Falls back to a short list when Intl cannot enumerate them. */
export function timeZones(): string[] {
  try {
    const zones = Intl.supportedValuesOf("timeZone");
    return ["UTC", ...zones.filter((z) => z !== "UTC")];
  } catch {
    return ["UTC", "Europe/London", "America/New_York", "America/Chicago", "America/Denver", "America/Los_Angeles"];
  }
}

export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}
