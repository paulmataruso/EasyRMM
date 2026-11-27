import type { CollectedLogBucket } from "../../api/types";

/** The ranges the Collected logs tab offers. */
export const COLLECTED_SPANS = [
  { value: "1h", label: "Last hour", hours: 1 },
  { value: "6h", label: "Last 6 hours", hours: 6 },
  { value: "24h", label: "Last 24 hours", hours: 24 },
  { value: "7d", label: "Last 7 days", hours: 24 * 7 },
  { value: "30d", label: "Last 30 days", hours: 24 * 30 },
] as const;

export const DEFAULT_COLLECTED_SPAN = "24h";

/** A bar of the timeline: a stretch of whole hours. */
export interface TimelineBar {
  /** Start of the stretch, ISO. */
  start: string;
  /** End of the stretch, ISO (exclusive). */
  end: string;
  events: number;
  /** Events at warn and error, which the bar shows apart. */
  attention: number;
}

const HOUR = 3_600_000;

/** At most this many bars, so that thirty days stay readable. */
export const MAX_BARS = 48;

/**
 * Groups hourly facts into bars covering since..until: one bar per hour while that fits, otherwise stretches of equal
 * whole hours. Empty stretches are kept, so that a quiet period reads as quiet and not as missing.
 */
export function timelineBars(buckets: CollectedLogBucket[], since: string, until: string, source = ""): TimelineBar[] {
  const from = Math.floor(Date.parse(since) / HOUR) * HOUR;
  const to = Math.ceil(Date.parse(until) / HOUR) * HOUR;
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) return [];
  const hours = Math.round((to - from) / HOUR);
  const per = Math.max(1, Math.ceil(hours / MAX_BARS));
  const count = Math.ceil(hours / per);
  const bars: TimelineBar[] = Array.from({ length: count }, (_, i) => ({
    start: new Date(from + i * per * HOUR).toISOString(),
    end: new Date(Math.min(from + (i + 1) * per * HOUR, to)).toISOString(),
    events: 0,
    attention: 0,
  }));
  for (const b of buckets) {
    if (source && b.source !== source) continue;
    const i = Math.floor((Date.parse(b.hour) - from) / (per * HOUR));
    if (i < 0 || i >= count) continue;
    const bar = bars[i];
    if (!bar) continue;
    bar.events += b.events;
    if (b.level === "warn" || b.level === "error") bar.attention += b.events;
  }
  return bars;
}

/** "windows.security" as "Windows security". */
export function collectedSourceName(source: string): string {
  const [family, ...rest] = source.split(".");
  const words = [family, ...rest].join(" ").replace(/[-_]/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
}
