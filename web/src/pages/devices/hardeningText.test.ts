import { describe, expect, it } from "vitest";
import { containerName, distributionName, MODULES, moduleInfo, RECOMMENDED, stateMeta, summarize } from "./hardeningText";

const at = "2026-11-01T10:00:00Z";

describe("hardening words", () => {
  it("lists the server's 19 modules in its order, the recommended ones first, each optional one with its risk", () => {
    expect(MODULES.map((m) => m.id)).toEqual([
      "ssh",
      "firewall",
      "fail2ban",
      "kernel",
      "audit",
      "permissions",
      "services",
      "kernel-modules",
      "sudo",
      "time",
      "shared-memory",
      "usb-storage",
      "mac",
      "integrity",
      "lockout",
      "luks",
      "host-firewall",
      "selinux-apparmor",
      "auto-updates",
    ]);
    expect(RECOMMENDED).toEqual(MODULES.slice(0, 10).map((m) => m.id));
    for (const m of MODULES) {
      expect(m.does, m.id).not.toBe("");
      expect(Boolean(m.risk), m.id).toBe(!m.recommended);
    }
    // A module a newer server knows keeps its name.
    expect(moduleInfo("bootloader")).toEqual({ id: "bootloader", name: "bootloader", does: "", recommended: false });
    expect(moduleInfo("kernel-modules").name).toBe("Kernel modules");
  });

  it("sums a device's modules up for the Devices list", () => {
    expect(summarize({ checkedAt: at, states: { in_place: 10 } })).toMatchObject({ label: "10 of 10 in place", tone: "ok", title: "10 in place" });
    expect(summarize({ checkedAt: at, states: { in_place: 7, partly: 2, not_in_place: 1, not_applicable: 3 } })).toMatchObject({
      label: "7 of 10 in place",
      tone: "warn",
      title: "7 in place, 2 partly in place, 1 not in place, 3 not applicable",
    });
    // What cannot be applied here does not count against the device.
    expect(summarize({ checkedAt: at, states: { in_place: 4, managed_elsewhere: 1, not_supported: 1 } })).toMatchObject({ label: "4 of 4 in place", tone: "ok" });
    expect(summarize({ checkedAt: at, states: { in_place: 7, failed: 2 } })).toMatchObject({ label: "2 failed", tone: "danger" });
    expect(summarize({ checkedAt: at, states: { in_place: 7, failed: 1, half_applied: 1 } })).toMatchObject({ label: "Half applied", tone: "danger" });
    expect(summarize({ checkedAt: at, states: { not_applicable: 6 } })).toMatchObject({ label: "Not applicable", tone: "neutral" });
    expect(summarize({ checkedAt: at, states: {} })).toMatchObject({ label: "Not applicable", title: "" });
  });

  it("names states, distributions and containers", () => {
    expect(stateMeta("not_supported").label).toBe("Not supported on this version");
    // A state a newer server reports keeps its name.
    expect(stateMeta("drifted" as never)).toEqual({ label: "drifted", tone: "neutral", title: "" });
    expect(distributionName({ id: "rocky", versionId: "9.6" })).toBe("Rocky Linux 9.6");
    expect(distributionName({ id: "arch", versionId: "" })).toBe("arch");
    expect(distributionName({ id: "", versionId: "" })).toBe("An unknown distribution");
    expect(containerName("none")).toBeNull();
    expect(containerName("docker")).toBe("Docker container");
    expect(containerName("other")).toBe("A container");
  });
});
