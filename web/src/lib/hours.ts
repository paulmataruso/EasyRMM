// Business hours (ADR-0066): a weekly schedule of up to four periods a day. The server checks and normalizes them;
// this only names and shows them.

import type { BusinessHours, OpeningPeriod, Weekday } from "../api/types";

export const WEEKDAYS: readonly { day: Weekday; short: string; long: string }[] = [
  { day: "monday", short: "Mon", long: "Monday" },
  { day: "tuesday", short: "Tue", long: "Tuesday" },
  { day: "wednesday", short: "Wed", long: "Wednesday" },
  { day: "thursday", short: "Thu", long: "Thursday" },
  { day: "friday", short: "Fri", long: "Friday" },
  { day: "saturday", short: "Sat", long: "Saturday" },
  { day: "sunday", short: "Sun", long: "Sunday" },
];

/** The most periods the server keeps for one day. */
export const MAX_PERIODS_PER_DAY = 4;

/** A copy safe to edit; null becomes a week with nothing open. */
export function copyHours(hours: BusinessHours | null): BusinessHours {
  const out: BusinessHours = { monday: [], tuesday: [], wednesday: [], thursday: [], friday: [], saturday: [], sunday: [] };
  for (const { day } of WEEKDAYS) out[day] = (hours?.[day] ?? []).map((p) => ({ ...p }));
  return out;
}

/** Null when no day has a period, which is how the server keeps "no hours". */
export function hoursOrNull(hours: BusinessHours): BusinessHours | null {
  return WEEKDAYS.some(({ day }) => hours[day].length > 0) ? hours : null;
}

function periodsText(periods: OpeningPeriod[]): string {
  return periods.length === 0 ? "Closed" : periods.map((p) => `${p.start}–${p.end}`).join(", ");
}

/** Consecutive days with the same periods, as lines such as ["Mon–Fri", "09:00–17:00"]. */
export function summarizeHours(hours: BusinessHours): [string, string][] {
  const lines: [string, string][] = [];
  let first = 0;
  for (let i = 1; i <= WEEKDAYS.length; i++) {
    const text = periodsText(hours[WEEKDAYS[first]!.day]);
    if (i < WEEKDAYS.length && periodsText(hours[WEEKDAYS[i]!.day]) === text) continue;
    const days = i - 1 === first ? WEEKDAYS[first]!.short : `${WEEKDAYS[first]!.short}–${WEEKDAYS[i - 1]!.short}`;
    lines.push([days, text]);
    first = i;
  }
  return lines;
}
