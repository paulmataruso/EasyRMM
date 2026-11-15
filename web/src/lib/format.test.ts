import { describe, expect, it } from "vitest";
import { describeUserAgent, formatDateTime, formatNumber, formatRelative, parseDate, plural, timeZones } from "./format";

describe("parseDate", () => {
  it("treats Go's zero time and garbage as missing", () => {
    expect(parseDate("0001-01-01T00:00:00Z")).toBeNull();
    expect(parseDate("not a date")).toBeNull();
    expect(parseDate(null)).toBeNull();
    expect(parseDate("2026-11-15T10:00:00Z")?.toISOString()).toBe("2026-11-15T10:00:00.000Z");
  });

  it("renders a dash for missing dates", () => {
    expect(formatDateTime(null)).toBe("—");
    expect(formatDateTime("0001-01-01T00:00:00Z")).toBe("—");
  });
});

describe("formatRelative", () => {
  const now = Date.parse("2026-11-15T12:00:00Z");
  it("rounds to the largest sensible unit", () => {
    expect(formatRelative("2026-11-15T11:59:50Z", now)).toBe("just now");
    expect(formatRelative("2026-11-15T11:55:00Z", now)).toMatch(/5 minutes ago/);
    expect(formatRelative("2026-11-15T09:00:00Z", now)).toMatch(/3 hours ago/);
    expect(formatRelative("2026-11-16T12:00:00Z", now)).toMatch(/tomorrow|in 1 day/);
    expect(formatRelative(null, now)).toBe("never");
  });
});

describe("plural and formatNumber", () => {
  it("picks the right form", () => {
    expect(plural(1, "site")).toBe("1 site");
    expect(plural(0, "site")).toBe("0 sites");
    expect(plural(2, "entry", "entries")).toBe("2 entries");
    expect(formatNumber(undefined)).toBe("—");
  });
});

describe("describeUserAgent", () => {
  it("names common browsers and systems", () => {
    expect(describeUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36 Edg/131.0")).toBe(
      "Edge on Windows",
    );
    expect(describeUserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Gecko/20100101 Firefox/133.0")).toBe("Firefox on macOS");
    expect(describeUserAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36")).toBe("Chrome on Linux");
    expect(describeUserAgent("curl/8.5.0")).toBe("curl");
    expect(describeUserAgent("")).toBe("Unknown device");
    expect(describeUserAgent("x".repeat(80))).toHaveLength(58);
  });
});

describe("timeZones", () => {
  it("lists UTC first without duplicates", () => {
    const zones = timeZones();
    expect(zones[0]).toBe("UTC");
    expect(zones.filter((z) => z === "UTC")).toHaveLength(1);
    expect(zones.length).toBeGreaterThan(5);
  });
});
