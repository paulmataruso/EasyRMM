import { describe, expect, it } from "vitest";
import { counts, device, jobRun, script } from "../../test/fixtures";
import {
  cannotRunReason,
  formatBytes,
  formatElapsed,
  formatSeconds,
  isOpen,
  jobState,
  parseArgs,
  runElapsed,
  scriptCovers,
  scriptScope,
  utf8Length,
} from "./scriptText";

describe("script text", () => {
  it("says where a script runs and whether it covers a device", () => {
    const shared = script("a", "A");
    const acme = script("b", "B", { level: "organization", organizationId: "o1", organizationName: "Northwind Traders" });
    const hq = script("c", "C", { level: "site", organizationId: "o1", organizationName: "Northwind Traders", siteId: "s1", siteName: "Head office" });
    expect([scriptScope(shared), scriptScope(acme), scriptScope(hq)]).toEqual(["All organizations", "Northwind Traders", "Northwind Traders / Head office"]);
    const there = device("d1", "PC");
    const elsewhere = device("d2", "PC2", { organizationId: "o2", siteId: "s9" });
    expect([shared, acme, hq].map((s) => scriptCovers(s, there))).toEqual([true, true, true]);
    expect([shared, acme, hq].map((s) => scriptCovers(s, elsewhere))).toEqual([true, false, false]);
  });

  it("explains why a device cannot run scripts", () => {
    const agent = { version: "1", arch: "amd64", sha256: "", online: true, lastSeenAt: null, enrolledAt: "2026-10-01T00:00:00Z", update: null };
    expect(cannotRunReason(device("d", "x", { platform: "linux", agent, canRunScripts: true }))).toBeNull();
    expect(cannotRunReason(device("d", "x", { platform: "linux", agent: null, canRunScripts: false }))).toMatch(/no EasyRMM agent/);
    expect(cannotRunReason(device("d", "x", { platform: "linux", agent, canRunScripts: false }))).toMatch(/role/);
    expect(cannotRunReason(device("d", "x", { platform: "windows", agent, canRunScripts: true }))).toBeNull();
    expect(cannotRunReason(device("d", "x", { platform: "macos", agent, canRunScripts: true }))).toBe("Scripts run on Windows and Linux devices.");
    expect(cannotRunReason(device("d", "x", { platform: "windows", agent, canRunScripts: true }), "powershell")).toBeNull();
    expect(cannotRunReason(device("d", "x", { platform: "windows", agent, canRunScripts: true }), "bash")).toBe("Bash scripts run on Linux devices.");
    expect(cannotRunReason(device("d", "x", { platform: "linux", agent, canRunScripts: true }), "cmd")).toBe("Command Prompt (cmd) scripts run on Windows devices.");
  });

  it("formats durations, sizes and elapsed times", () => {
    expect([formatSeconds(45), formatSeconds(60), formatSeconds(300), formatSeconds(5400), formatSeconds(3661), formatSeconds(0)]).toEqual([
      "45 seconds",
      "1 minute",
      "5 minutes",
      "1 hour 30 minutes",
      "1 hour 1 minute 1 second",
      "0 seconds",
    ]);
    expect([formatElapsed(400), formatElapsed(12_000), formatElapsed(184_000), formatElapsed(180_000), formatElapsed(7_500_000), formatElapsed(7_200_000)]).toEqual([
      "under 1 s",
      "12 s",
      "3 min 4 s",
      "3 min",
      "2 h 5 min",
      "2 h",
    ]);
    expect([formatBytes(1), formatBytes(900), formatBytes(1536), formatBytes(65536), formatBytes(3 * 1024 * 1024)]).toEqual([
      "1 byte",
      "900 bytes",
      "1.5 KiB",
      "64 KiB",
      "3.0 MiB",
    ]);
    expect(utf8Length("é€")).toBe(5);
  });

  it("measures runs from start to finish, or to now while running", () => {
    expect(runElapsed(jobRun("r", "d", "PC", "queued"))).toBeNull();
    expect(runElapsed(jobRun("r", "d", "PC", "succeeded"))).toBe(65_000);
    const running = jobRun("r", "d", "PC", "running");
    expect(runElapsed(running, Date.parse("2026-11-01T10:00:12Z"))).toBe(10_000);
    expect([isOpen("running"), isOpen("sent"), isOpen("lost")]).toEqual([true, true, false]);
  });

  it("takes arguments one per line, as typed", () => {
    expect(parseArgs("")).toEqual([]);
    expect(parseArgs("-p\r\n\n  two words  \n$HOME\n")).toEqual(["-p", "  two words  ", "$HOME"]);
  });

  it("sums a job up from its runs", () => {
    const state = (c: Parameters<typeof counts>[0], total: number, finished: boolean) => jobState({ counts: counts(c), total, finished }).label;
    expect(state({ queued: 2 }, 2, false)).toBe("Waiting");
    expect(state({ queued: 1, running: 1 }, 2, false)).toBe("Running");
    expect(state({ succeeded: 2 }, 2, true)).toBe("Succeeded");
    expect(state({ succeeded: 1, failed: 1 }, 2, true)).toBe("Some failed");
    expect(state({ expired: 1, canceled: 1 }, 2, true)).toBe("Failed");
    expect(state({ succeeded: 1, canceled: 1 }, 2, true)).toBe("Partly canceled");
    expect(state({ canceled: 2 }, 2, true)).toBe("Canceled");
  });
});
