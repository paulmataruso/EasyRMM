import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { COUNTRY_CODES, countryName, countryOptions } from "./countries";
import { copyHours, hoursOrNull, noHours, summarizeHours } from "./hours";

describe("countries", () => {
  it("offers exactly the codes the server accepts", () => {
    const source = readFileSync(resolve(process.cwd(), "../server/internal/docs/countries.go"), "utf8");
    const server = [...source.matchAll(/^\t"([A-Z ]+)"/gm)].flatMap((m) => (m[1] ?? "").trim().split(" "));
    expect(COUNTRY_CODES).toHaveLength(249);
    expect([...COUNTRY_CODES]).toEqual(server);
    expect(new Set(COUNTRY_CODES).size).toBe(249);
  });

  it("names countries and sorts the picker by name", () => {
    expect(countryName("GB")).not.toBe("");
    const options = countryOptions();
    expect(options).toHaveLength(249);
    const sorted = [...options].sort((a, b) => a.name.localeCompare(b.name));
    expect(options).toEqual(sorted);
  });
});

describe("business hours", () => {
  it("groups days with the same periods", () => {
    const hours = noHours();
    for (const day of ["monday", "tuesday", "wednesday", "thursday", "friday"] as const) hours[day] = [{ start: "09:00", end: "17:00" }];
    hours.saturday = [
      { start: "10:00", end: "12:00" },
      { start: "13:00", end: "15:00" },
    ];
    expect(summarizeHours(hours)).toEqual([
      ["Mon–Fri", "09:00–17:00"],
      ["Sat", "10:00–12:00, 13:00–15:00"],
      ["Sun", "Closed"],
    ]);
  });

  it("keeps a week with nothing open as no hours", () => {
    expect(hoursOrNull(noHours())).toBeNull();
    const hours = copyHours(null);
    hours.sunday = [{ start: "22:00", end: "02:00" }];
    expect(hoursOrNull(hours)).toBe(hours);
    expect(summarizeHours(hours)).toEqual([
      ["Mon–Sat", "Closed"],
      ["Sun", "22:00–02:00"],
    ]);
  });

  it("copies so that edits leave the original alone", () => {
    const original = noHours();
    original.monday = [{ start: "08:00", end: "16:00" }];
    const copy = copyHours(original);
    copy.monday[0]!.start = "07:00";
    expect(original.monday[0]!.start).toBe("08:00");
  });
});
