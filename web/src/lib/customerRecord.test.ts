import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { COUNTRY_CODES, countryName, countryOptions } from "./countries";
import { copyHours, hoursOrNull, summarizeHours } from "./hours";
import { mailtoHref, telHref, websiteHref } from "./links";

const noHours = () => copyHours(null);

describe("links", () => {
  it("encodes an address in a mailto: link so that it cannot add headers", () => {
    expect(mailtoHref("help@example.com")).toBe("mailto:help@example.com");
    expect(mailtoHref("o'brien+it@example.com")).toBe("mailto:o'brien%2Bit@example.com");
    expect(mailtoHref("x?bcc=evil@example.com")).toBe("mailto:x%3Fbcc%3Devil@example.com");
    expect(mailtoHref("a@example.com&cc=evil@example.com")).toBe("mailto:a%40example.com%26cc%3Devil@example.com");
    expect(mailtoHref("x?bcc=evil")).toBe("mailto:x%3Fbcc%3Devil");
  });

  it("dials the digits", () => {
    expect(telHref("+44 20 5550 0100")).toBe("tel:+442055500100");
    expect(telHref("(555) 0100 ext. 12")).toBe("tel:555010012");
  });

  it("links a website only over http or https", () => {
    expect(websiteHref("https://example.com/support")).toBe("https://example.com/support");
    expect(websiteHref("http://example.com")).toBe("http://example.com/");
    for (const bad of ["javascript:alert(1)", "JavaScript:alert(1)", "data:text/html,x", "ftp://example.com", "example.com", ""]) {
      expect(websiteHref(bad)).toBeNull();
    }
  });
});

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
