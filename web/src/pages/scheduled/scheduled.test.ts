import { describeSchedule, describeStep } from "./ScheduledTasksPage";

describe("describeSchedule", () => {
  it("names the zone the time is read in", () => {
    expect(describeSchedule({ kind: "daily", at: "03:00" }, "America/New_York")).toBe("Every day at 03:00 (America/New_York)");
    expect(describeSchedule({ kind: "weekly", at: "22:00", days: [1, 5] }, "UTC")).toBe("Mon, Fri at 22:00 (UTC)");
    expect(describeSchedule({ kind: "monthly", at: "01:30", dayOfMonth: 31 }, "UTC")).toBe("Day 31 of each month at 01:30 (UTC)");
    expect(describeSchedule({ kind: "once", date: "2026-02-01", at: "10:00" }, "UTC")).toBe("Once, 2026-02-01 10:00 (UTC)");
  });

  it("says intervals in the largest whole unit", () => {
    expect(describeSchedule({ kind: "interval", everyMinutes: 120 }, "UTC")).toBe("Every 2 hour(s)");
    expect(describeSchedule({ kind: "interval", everyMinutes: 45 }, "UTC")).toBe("Every 45 minutes");
    expect(describeSchedule({ kind: "interval", everyMinutes: 2880 }, "UTC")).toBe("Every 2 day(s)");
  });
});

describe("describeStep", () => {
  it("says what each kind of step does", () => {
    expect(describeStep({ stepKind: "script", step: {}, scriptName: "Clean temp" })).toBe("Clean temp");
    expect(describeStep({ stepKind: "restart", step: {}, scriptName: "" })).toBe("Restart");
    expect(describeStep({ stepKind: "shutdown", step: { platform: "linux" }, scriptName: "" })).toBe("Shut down (Linux only)");
    expect(describeStep({ stepKind: "service", step: { action: "service_stop", service: "Spooler", platform: "windows" }, scriptName: "" })).toBe(
      "Stop service Spooler (Windows only)",
    );
    const software = { action: "install", manager: "system", package: "jq", version: "1.7" } as const;
    expect(describeStep({ stepKind: "software", step: { software }, scriptName: "" })).toBe("Install jq 1.7");
  });
});
