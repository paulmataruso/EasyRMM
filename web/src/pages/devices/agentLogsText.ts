import type { AgentLogLevel, AgentLogSource } from "../../api/types";

/** The sources of a record, as the console names them. */
export const LOG_SOURCES: { value: AgentLogSource; label: string }[] = [
  { value: "agent", label: "EasyRMM agent" },
  { value: "easypatch", label: "EasyPatch agent" },
  { value: "meshagent", label: "MeshAgent" },
];

export const sourceName = (s: string): string => LOG_SOURCES.find((x) => x.value === s)?.label ?? s;

/** The level filter's choices: a level and everything above it. */
export const LOG_LEVELS: { value: AgentLogLevel; label: string }[] = [
  { value: "debug", label: "Debug and above" },
  { value: "info", label: "Info and above" },
  { value: "warn", label: "Warnings and errors" },
  { value: "error", label: "Errors only" },
];

/** How far back the time filter reaches. */
export const LOG_SPANS: { value: string; label: string; minutes: number }[] = [
  { value: "any", label: "Any time", minutes: 0 },
  { value: "15m", label: "Last 15 minutes", minutes: 15 },
  { value: "1h", label: "Last hour", minutes: 60 },
  { value: "24h", label: "Last 24 hours", minutes: 24 * 60 },
  { value: "7d", label: "Last 7 days", minutes: 7 * 24 * 60 },
];

/** The hours verbose logging may run for (1 to 24, 2 by default). */
export const VERBOSE_HOURS = [1, 2, 4, 8, 12, 24];
export const DEFAULT_VERBOSE_HOURS = 2;

/** A record's time as HH:MM:SS.mmm in the viewer's zone. */
export function clock(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

/** The highest record id of a list, the cursor of the live tail (it counts the order records were stored in). */
export function highestId(items: { id: number }[], from: number): number {
  return items.reduce((m, r) => Math.max(m, r.id), from);
}

/**
 * The merged view of every source: newest logged time first, and among equal times the record stored later first (the
 * higher id), the same order the server reads in. Records already shown are kept once.
 */
export function mergeNewestFirst<T extends { id: number; time: string }>(a: T[], b: T[]): T[] {
  const seen = new Map<number, T>();
  for (const r of [...a, ...b]) seen.set(r.id, r);
  return [...seen.values()].sort((x, y) => {
    const d = Date.parse(y.time) - Date.parse(x.time);
    return d !== 0 ? d : y.id - x.id;
  });
}
