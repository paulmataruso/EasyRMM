import { describe, expect, it } from "vitest";
import { timeTicks } from "./TimeChart";

const HOUR = 3_600_000;
const t1 = Date.parse("2026-11-16T04:10:00Z");

describe("timeTicks", () => {
  it("steps by quarter hours, four hours or days with the span", () => {
    const gaps = (ticks: { at: number }[]) => new Set(ticks.slice(1).map((t, i) => t.at - (ticks[i]?.at ?? 0)));
    expect(gaps(timeTicks(t1 - HOUR, t1))).toEqual(new Set([15 * 60_000]));
    expect(gaps(timeTicks(t1 - 24 * HOUR, t1))).toEqual(new Set([4 * HOUR]));
    for (const gap of gaps(timeTicks(t1 - 7 * 24 * HOUR, t1))) expect([23, 24, 25]).toContain(gap / HOUR);
  });

  it("falls on round local times inside the period", () => {
    for (const t of timeTicks(t1 - 24 * HOUR, t1)) {
      const d = new Date(t.at);
      expect(d.getMinutes()).toBe(0);
      expect(d.getHours() % 4).toBe(0);
      expect(t.at).toBeGreaterThanOrEqual(t1 - 24 * HOUR);
      expect(t.at).toBeLessThanOrEqual(t1);
    }
  });

  it("drops labels that would not fit side by side", () => {
    const all = timeTicks(t1 - 24 * HOUR, t1);
    expect(all.length).toBeGreaterThanOrEqual(6);
    const narrow = timeTicks(t1 - 24 * HOUR, t1, 200);
    expect(narrow.length * 76).toBeLessThanOrEqual(200 + 76);
    expect(narrow.length).toBeLessThan(all.length);
    expect(narrow[0]).toEqual(all[0]);
    expect(timeTicks(t1 - 24 * HOUR, t1, 2000)).toEqual(all);
  });
});
