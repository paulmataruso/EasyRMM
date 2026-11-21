import { describe, expect, it } from "vitest";
import type { Device, DiskDay, DiskHealthSummary } from "../../api/types";
import { formatShortDate, formatShortDateTime } from "../../lib/format";
import { device, diskHealth } from "../../test/fixtures";
import { sortDevices } from "./DevicesPage";
import {
  decimalSize,
  deviceDiskHealth,
  DISK_FILTERS,
  diskLine,
  diskShown,
  factText,
  firmwareText,
  formatDay,
  historyColumns,
  reasonText,
  REASONS,
  sinceNote,
  stateText,
  stateWords,
  STATES,
} from "./diskHealthText";

const NOW = new Date("2026-11-01T12:00:00Z");
const JUDGED = "2026-11-01T10:00:00Z";
const LATER = "2026-11-01T11:30:00Z";
const when = (at: string) => formatShortDateTime(at, NOW);

/** Every reason the agent sends (internal/agentproto/hardware.go) and the server's rules (hardware/judge.go). */
const AGENT_REASONS = [
  "container",
  "virtual_disk",
  "virtual_machine",
  "storage_spaces",
  "memory_card",
  "raid_controller",
  "storage_driver",
  "device_refused",
  "protocol_not_read",
  "usb_bridge",
  "no_smart",
  "smart_off",
  "asleep",
  "timeout",
  "timed_out_recently",
  "io_error",
  "access_denied",
  "bad_checksum",
  "bad_answer",
  "agent_error",
  "not_kept",
  "not_valid",
  "not_exposed",
  "no_verdict",
  "stale",
  "missing",
  "invalid_report",
];
const RULES = [
  "critical_warning",
  "smart_status",
  "prefail_attribute",
  "attribute",
  "temperature",
  "wear",
  "media_errors",
  "reallocated_sectors",
  "pending_sectors",
  "uncorrectable_sectors",
];

describe("disk health words", () => {
  it("names every state", () => {
    expect(Object.fromEntries(Object.entries(STATES).map(([k, v]) => [k, v.label]))).toEqual({
      healthy: "Healthy",
      warning: "Warning",
      failing: "Failing",
      unknown: "Unknown",
      unsupported: "Unsupported",
      unavailable: "Unavailable",
      reported: "Reported",
    });
    for (const s of Object.values(STATES)) expect(s.means).not.toBe("");
    expect(stateWords("failing").tone).toBe("danger");
    expect(stateWords("warning").tone).toBe("warn");
    expect(stateWords("healthy").tone).toBe("ok");
    // A state a newer server sends shows as its code, and no inherited property is taken for one.
    expect(stateWords("degraded")).toEqual({ label: "degraded", tone: "neutral", means: "" });
    expect(stateWords("constructor").label).toBe("constructor");
  });

  it("puts every reason the agent and the server send in words", () => {
    expect(Object.keys(REASONS).sort()).toEqual([...AGENT_REASONS, ...RULES].sort());
    for (const code of [...AGENT_REASONS, ...RULES]) {
      expect(reasonText(code), code).not.toBe(code);
      expect(reasonText(code), code).toMatch(/^[a-zA-Z0-9]/);
    }
    expect(stateText("unavailable", "raid_controller")).toBe("Unavailable: behind a RAID controller");
    expect(stateText("unsupported", "virtual_disk")).toBe("Unsupported: a virtual machine's emulated disk");
    expect(stateText("unknown", "asleep")).toBe("Unknown: asleep, not woken");
    expect(stateText("unsupported", "not_kept")).toBe("Unsupported: the drive does not keep this");
    expect(stateText("failing", "critical_warning")).toBe("Failing: NVMe critical warning");
    expect(stateText("healthy")).toBe("Healthy");
    expect(stateText("healthy", "")).toBe("Healthy");
    // A code a newer agent sends shows as itself, safely.
    expect(reasonText("hba_firmware")).toBe("hba_firmware");
    expect(reasonText("__proto__")).toBe("__proto__");
    expect(reasonText(undefined)).toBe("");
    expect(stateText("unknown", "toString")).toBe("Unknown: toString");
  });

  it("shows a failing disk with when it was last read, what made it fail and the readings since that could not tell", () => {
    const d = diskHealth("k1", "nvme0n1", {
      state: "failing",
      reason: "critical_warning",
      detail: "NVMe critical warning: media read-only",
      judgedLevel: "failing",
      judgedAt: JUDGED,
      since: 3,
      latest: { state: "unknown", reason: "timeout", detail: "", readAt: LATER, receivedAt: LATER },
    });
    expect(diskShown(d, NOW)).toEqual({
      tone: "danger",
      head: "Failing",
      rest: `, last read ${when(JUDGED)}`,
      detail: "NVMe critical warning: media read-only",
      note: "The 3 readings since could not tell; the latest: timed out.",
      asOf: "",
    });
    expect(diskLine(d, NOW)).toBe(`Failing, last read ${when(JUDGED)}`);
    // Without the server's sentence, the rule's words.
    expect(diskShown({ ...d, detail: "", since: 1 }, NOW)).toMatchObject({ detail: "NVMe critical warning", note: "The reading since could not tell: timed out." });
    const warning = diskShown({ ...d, state: "warning", reason: "pending_sectors", detail: "Pending sectors 8", judgedLevel: "warning", since: 0 }, NOW);
    expect(warning).toMatchObject({ tone: "warn", head: "Warning", detail: "Pending sectors 8", note: "" });
  });

  it("shows a healthy disk, and one not read for over 2 hours as unknown with its last reading", () => {
    const healthy = diskHealth("k1", "nvme0n1", { judgedAt: JUDGED });
    expect(diskShown(healthy, NOW)).toMatchObject({ tone: "ok", head: "Healthy", rest: `, last read ${when(JUDGED)}`, detail: "", note: "" });
    const stale = diskHealth("k1", "nvme0n1", { state: "unknown", reason: "stale", judgedAt: JUDGED, since: 4, latest: { state: "unknown", reason: "asleep", detail: "", readAt: LATER, receivedAt: LATER } });
    expect(diskLine(stale, NOW)).toBe(`Unknown: not read since ${when(JUDGED)}`);
    expect(diskShown(stale, NOW).note).toBe("The 4 readings since could not tell; the latest: asleep, not woken.");
  });

  it("shows a disk that could not be read with why, and when", () => {
    const raid = diskHealth("k2", "sda", {
      state: "unavailable",
      reason: "raid_controller",
      judgedLevel: null,
      judgedAt: null,
      latest: { state: "unavailable", reason: "raid_controller", detail: "", readAt: LATER, receivedAt: LATER },
    });
    expect(diskShown(raid, NOW)).toEqual({ tone: "neutral", head: "Unavailable", rest: ": behind a RAID controller", detail: "", note: "", asOf: `As of ${when(LATER)}` });
    expect(diskLine({ ...raid, state: "unsupported", reason: "storage_spaces" }, NOW)).toBe("Unsupported: a Storage Spaces virtual disk");
    expect(diskShown({ ...raid, state: "unavailable", reason: "storage_driver", detail: "Windows error 1117" }, NOW).detail).toBe("Windows error 1117");
    const never = diskHealth("k3", "sdb", { state: "unknown", reason: "no_verdict", judgedLevel: null, judgedAt: null, latest: { state: "unknown", reason: "no_verdict", detail: "", readAt: LATER, receivedAt: LATER } });
    expect(diskShown(never, NOW)).toMatchObject({ tone: "info", head: "Unknown", rest: ": the drive's verdict could not be read", note: "", asOf: `As of ${when(LATER)}` });
    expect(diskLine({ ...never, reason: "" }, NOW)).toBe("Unknown");
    // A state a newer server sends shows as its code.
    expect(diskLine({ ...never, state: "degraded" as never, reason: "" }, NOW)).toBe("degraded");
  });

  it("shows a missing disk with since when and the level it was last read with", () => {
    const gone = diskHealth("k4", "sdc", {
      state: "unknown",
      reason: "missing",
      judgedLevel: "failing",
      judgedAt: JUDGED,
      missingSince: "2026-11-01T11:00:00Z",
      since: 2,
    });
    expect(diskShown(gone, NOW)).toMatchObject({
      tone: "danger",
      head: "Missing",
      rest: ` since ${formatShortDate("2026-11-01T11:00:00Z", NOW)}; last read Failing, ${when(JUDGED)}`,
      note: "",
    });
    // Never judged: the latest reading's state.
    const never = { ...gone, judgedLevel: null, judgedAt: null, latest: { state: "unavailable" as const, reason: "usb_bridge", detail: "", readAt: LATER, receivedAt: LATER } };
    expect(diskShown(never, NOW)).toMatchObject({ tone: "info", rest: ` since ${formatShortDate("2026-11-01T11:00:00Z", NOW)}; last read Unavailable, ${when(LATER)}` });
  });

  it("says nothing of readings since when there are none", () => {
    const latest = { state: "unknown" as const, reason: "", detail: "", readAt: LATER, receivedAt: LATER };
    expect(sinceNote({ since: 0, judgedAt: JUDGED, latest })).toBe("");
    expect(sinceNote({ since: 2, judgedAt: null, latest })).toBe("");
    expect(sinceNote({ since: 2, judgedAt: JUDGED, latest })).toBe("The 2 readings since could not tell; the latest: unknown.");
  });

  it("puts firmware in words, and nothing for an agent too old to report it", () => {
    expect(firmwareText(undefined)).toBeNull();
    expect(firmwareText({ state: "read", value: "GDC5602Q" })).toBe("GDC5602Q");
    expect(firmwareText({ state: "read" })).toBe("Unknown");
    expect(firmwareText({ state: "unavailable", reason: "raid_controller" })).toBe("Unavailable: behind a RAID controller");
    expect(firmwareText({ state: "unsupported", reason: "virtual_disk" })).toBe("Unsupported: a virtual machine's emulated disk");
    expect(firmwareText({ state: "unknown", reason: "invalid_report" })).toBe("Unknown: the agent's report could not be used");
  });
});

describe("a device's disk health", () => {
  const s = (label: DiskHealthSummary["label"], states: DiskHealthSummary["states"]): DiskHealthSummary => ({ label, states });

  it("labels a device by its worst disk, counting the disks that cannot be read after it", () => {
    expect(deviceDiskHealth(s("healthy", { healthy: 2, unavailable: 3 }))).toEqual({
      label: "Healthy, 3 disks unavailable",
      tone: "ok",
      title: "3 disks unavailable, 2 disks healthy",
      rank: 4,
    });
    expect(deviceDiskHealth(s("failing", { failing: 1, healthy: 2, unsupported: 1 }))).toMatchObject({ label: "Failing, 1 disk unsupported", tone: "danger", rank: 0 });
    expect(deviceDiskHealth(s("warning", { warning: 1, unavailable: 1, unsupported: 2 }))).toMatchObject({ label: "Warning, 1 disk unavailable, 2 disks unsupported", rank: 1 });
    expect(deviceDiskHealth(s("unknown", { unknown: 1, healthy: 1 }))).toMatchObject({ label: "Unknown", tone: "info", rank: 2 });
    expect(deviceDiskHealth(s("healthy", { healthy: 4 }))).toMatchObject({ label: "Healthy", title: "4 disks healthy" });
    expect(deviceDiskHealth(s("unavailable", { unavailable: 4 }))).toMatchObject({ label: "Unavailable, 4 disks", tone: "neutral", rank: 3 });
    expect(deviceDiskHealth(s("unavailable", { unavailable: 2, unsupported: 1 }))).toMatchObject({ label: "Unavailable, 2 disks, 1 disk unsupported" });
    expect(deviceDiskHealth(s("unsupported", { unsupported: 2 }))).toMatchObject({ label: "Unsupported, 2 disks", rank: 5 });
    expect(deviceDiskHealth(null)).toEqual({ label: "Not reported", tone: "neutral", title: "The device's agent has reported no disk health.", rank: 7 });
    // A label a newer server sends shows as itself, after the six and before not reported.
    expect(deviceDiskHealth(s("degraded" as never, {}))).toMatchObject({ label: "degraded", rank: 6 });
  });

  it("sorts devices failing, warning, unknown, unavailable, healthy, unsupported, not reported, keeping the name order among equals", () => {
    const d = (name: string, summary: DiskHealthSummary | null): Device => device(name, name, { diskHealth: summary });
    const list = [
      d("a-none", null),
      d("b-healthy", s("healthy", { healthy: 1 })),
      d("c-unsupported", s("unsupported", { unsupported: 1 })),
      d("d-failing", s("failing", { failing: 1 })),
      d("e-unavailable", s("unavailable", { unavailable: 1 })),
      d("f-unknown", s("unknown", { unknown: 1 })),
      d("g-warning", s("warning", { warning: 1 })),
      d("h-failing", s("failing", { failing: 2 })),
    ];
    expect(sortDevices(list, "worst").map((x) => x.name)).toEqual(["d-failing", "h-failing", "g-warning", "f-unknown", "e-unavailable", "b-healthy", "c-unsupported", "a-none"]);
    expect(sortDevices(list, "best").map((x) => x.name)).toEqual(["a-none", "c-unsupported", "b-healthy", "e-unavailable", "f-unknown", "g-warning", "d-failing", "h-failing"]);
    expect(sortDevices(list, null)).toBe(list);
  });

  it("offers the seven filters", () => {
    expect(DISK_FILTERS.map((f) => `${f.value}=${f.label}`)).toEqual([
      "failing=Failing",
      "warning=Warning",
      "unknown=Unknown",
      "healthy=Healthy",
      "unavailable=Unavailable",
      "unsupported=Unsupported",
      "not_reported=Not reported",
    ]);
  });
});

describe("a disk's facts", () => {
  const f = (name: string, value: number | null, state = "reported") => factText({ name, value, state: state as never });

  it("puts every fact's name and value in words", () => {
    expect(f("criticalWarning", 0, "healthy")).toEqual({ label: "Critical warning (NVMe)", value: "None" });
    expect(f("criticalWarning", 8, "failing").value).toBe("Media read-only");
    expect(f("criticalWarning", 0b1000_0101, "failing").value).toBe("Available spare below its threshold, reliability degraded, bit 7 (reserved)");
    expect(f("smartStatus", 0, "healthy").value).toBe("Passed");
    expect(f("smartStatus", 1, "failing").value).toBe("Threshold exceeded");
    expect(f("thresholds", null)).toEqual({ label: "Attribute thresholds", value: "Read" });
    expect(f("thresholds", null, "unknown").value).toBe("—");
    expect(f("temperature", 41, "healthy")).toEqual({ label: "Temperature", value: "41 °C" });
    expect(f("temperatureLimit", 70).value).toBe("70 °C");
    expect(f("temperatureLimit", 0).value).toBe("None set");
    expect(f("wear", 12, "healthy").value).toBe("12% of rated endurance used");
    expect(f("wear", 255, "warning").value).toBe("Over 254% of rated endurance used");
    expect(f("availableSpare", 100).value).toBe("100%");
    expect(f("availableSpareThreshold", 10)).toEqual({ label: "Available spare threshold", value: "10%" });
    expect(f("mediaErrors", 0, "healthy").label).toBe("Media errors");
    expect(f("reallocatedSectors", 1234, "warning").value).toBe((1234).toLocaleString());
    expect(f("pendingSectors", null, "unsupported")).toEqual({ label: "Pending sectors", value: "—" });
    expect(f("uncorrectableSectors", 0, "healthy").label).toBe("Uncorrectable sectors");
    expect(f("driveErrors", 3).label).toBe("Errors in the drive's log");
    expect(f("powerOnHours", 8760).label).toBe("Power-on hours");
    expect(f("dataWritten", 36_000_000).value).toBe("18.4 TB");
    expect(f("unsafeShutdowns", 12).label).toBe("Unsafe shutdowns");
    expect(f("powerMode", 0).value).toBe("Standby");
    expect(f("powerMode", 128).value).toBe("Idle");
    expect(f("powerMode", 255).value).toBe("Active or idle");
    expect(f("powerMode", 64).value).toBe("0x40");
    // A fact a newer server sends shows as its name and number.
    expect(f("spinRetries", 2)).toEqual({ label: "spinRetries", value: "2" });
    expect(f("spinRetries", null)).toEqual({ label: "spinRetries", value: "—" });
  });

  it("writes sizes in decimal units and days in UTC", () => {
    expect(decimalSize(999)).toBe("999 bytes");
    expect(decimalSize(1_500)).toBe("1.50 kB");
    expect(decimalSize(512_000_000)).toBe("512.0 MB");
    expect(formatDay("2026-05-03T00:00:00Z", NOW)).toBe(new Date(Date.UTC(2026, 4, 3)).toLocaleDateString(undefined, { day: "numeric", month: "short", timeZone: "UTC" }));
    expect(formatDay("2025-05-03T00:00:00Z", NOW)).toContain("2025");
    expect(formatDay("not a day", NOW)).toBe("not a day");
  });

  it("shows only the history columns with a value", () => {
    const day = (extra: Partial<DiskDay>): DiskDay => ({
      day: "2026-11-01T00:00:00Z",
      state: "healthy",
      temperature: null,
      wear: null,
      reallocatedSectors: null,
      mediaErrors: null,
      pendingSectors: null,
      uncorrectableSectors: null,
      driveErrors: null,
      powerOnHours: 100,
      ...extra,
    });
    expect(historyColumns([day({ temperature: 40, mediaErrors: 0 }), day({ wear: 3 })]).map((c) => c.label)).toEqual(["Highest temperature", "Wear", "Media errors"]);
    expect(historyColumns([])).toEqual([]);
  });
});
