import { describe, expect, it } from "vitest";
import {
  describeUserAgent,
  formatDateTime,
  formatDuration,
  formatNumber,
  formatRelative,
  formatShortDate,
  formatShortDateTime,
  formatSize,
  parseDate,
  plural,
  timeZones,
} from "./format";

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

describe("short dates", () => {
  const now = new Date("2026-11-15T12:00:00Z");
  it("give the year only when it is not this year's", () => {
    expect(formatShortDateTime("2026-05-02T14:30:00Z", now)).toBe(
      new Date("2026-05-02T14:30:00Z").toLocaleString(undefined, { day: "numeric", month: "short", hour: "numeric", minute: "2-digit" }),
    );
    expect(formatShortDateTime("2026-05-02T14:30:00Z", now)).not.toContain("2026");
    expect(formatShortDateTime("2025-05-02T14:30:00Z", now)).toContain("2025");
    expect(formatShortDate("2026-05-03T12:00:00Z", now)).toBe(new Date("2026-05-03T12:00:00Z").toLocaleDateString(undefined, { day: "numeric", month: "short" }));
    expect(formatShortDate("2024-05-03T12:00:00Z", now)).toContain("2024");
    expect(formatShortDateTime(null)).toBe("—");
    expect(formatShortDate("0001-01-01T00:00:00Z")).toBe("—");
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

describe("formatSize", () => {
  it("uses binary units with one decimal below ten", () => {
    expect(formatSize(0)).toBe("0 B");
    expect(formatSize(1023)).toBe("1023 B");
    expect(formatSize(1536)).toBe("1.5 KiB");
    expect(formatSize(8 * 1024 ** 3)).toBe("8.0 GiB");
    expect(formatSize(128 * 1024 ** 3)).toBe("128 GiB");
    expect(formatSize(960 * 1000 ** 3)).toBe("894 GiB");
    expect(formatSize(3 * 1024 ** 5)).toBe("3.0 PiB");
    expect(formatSize(5 * 1024 ** 6)).toBe("5120 PiB");
  });

  it("renders a dash for nonsense", () => {
    expect(formatSize(-1)).toBe("—");
    expect(formatSize(Number.NaN)).toBe("—");
    expect(formatSize(null)).toBe("—");
  });
});

describe("formatDuration", () => {
  it("shows the two largest units", () => {
    expect(formatDuration(45)).toBe("45 s");
    expect(formatDuration(300)).toBe("5 min");
    expect(formatDuration(3_600)).toBe("1 h");
    expect(formatDuration(7_500)).toBe("2 h 5 min");
    expect(formatDuration(86_400 * 3)).toBe("3 d");
    expect(formatDuration(86_400 * 3 + 3_600 * 4 + 59)).toBe("3 d 4 h");
    expect(formatDuration(-5)).toBe("0 s");
  });
});
