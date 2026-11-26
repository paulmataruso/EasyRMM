// Words for the Defender module's console (ADR-0074).

import type { ManagedBy } from "./types";

export const MANAGED_TEXT: Record<ManagedBy, string> = {
  group_policy: "Managed by Group Policy",
  mdm: "Managed by Intune",
  defender_for_endpoint: "Managed by Defender for Endpoint",
  configmgr: "Managed by Configuration Manager",
  tamper_protection: "Locked by Tamper Protection",
  unknown_owner: "Owner unknown",
};

export const TAMPER_NOTE =
  "Changed in the Windows Security app on the computer, in Intune or in the Defender portal, never from here.";

/** `DisableRealtimeMonitoring` as "Disable realtime monitoring". */
export function humanize(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/^./, (c) => c.toUpperCase())
    .replace(/(^|\s)([A-Z])(?=[a-z])/g, (m, s: string, c: string) => s + (s ? c.toLowerCase() : c));
}

export const GROUP_LABEL: Record<string, string> = {
  protection: "Protection switches",
  cloud: "Cloud protection",
  features: "Features",
  threats: "What to do with threats",
  retention: "Retention",
  schedule: "Schedules and updates",
  performance: "Performance",
  servers: "Servers",
};

/** What a Windows Defender Operational event ID means, in Microsoft's words, shortened. */
export const EVENT_TEXT: Record<number, string> = {
  1000: "Scan started",
  1001: "Scan finished",
  1002: "Scan stopped before it finished",
  1006: "Malware found by the engine",
  1007: "Action taken on a threat",
  1008: "Action on a threat failed",
  1015: "Suspicious behavior detected",
  1116: "Malware detected",
  1117: "Action taken to protect the computer",
  1118: "Action on a threat failed (noncritical)",
  1119: "Action on a threat failed (critical)",
  1121: "An Attack Surface Reduction rule blocked something",
  2000: "Signatures updated",
  2001: "Signature update failed",
  2002: "Engine updated",
  2003: "Engine update failed",
  2006: "Platform update failed",
  3002: "Real-time protection failed",
  3007: "Real-time protection recovered",
  5000: "Real-time protection enabled",
  5001: "Real-time protection disabled",
  5004: "Real-time protection configuration changed",
  5007: "Configuration changed",
  5008: "Antimalware engine failed",
  5009: "Antivirus scanning enabled",
  5010: "Scanning for malware disabled",
  5011: "Antivirus scanning enabled",
  5012: "Scanning for viruses disabled",
  5013: "Tamper Protection blocked a change",
  5100: "Platform expires soon",
  5101: "Platform expired",
};

export const SEVERITY_TEXT: Record<number, string> = { 1: "Low", 2: "Moderate", 4: "High", 5: "Severe" };

/** What the module offers for a setting a Windows policy has not claimed. Mirrors the server's field table. */
export interface FieldRule {
  kind: "bool" | "int" | "enum" | "minutes";
  min?: number;
  max?: number;
  values?: string[];
  weakensTrue?: boolean;
  weakening?: string[];
}

const MODES = ["Disabled", "Enabled", "AuditMode"];
const ACTIONS = ["Clean", "Quarantine", "Remove", "Allow", "UserDefined", "NoAction"];
const bool = (weakensTrue = false): FieldRule => ({ kind: "bool", weakensTrue });
const int = (min: number, max: number, weakening?: string[]): FieldRule => ({ kind: "int", min, max, weakening });
const minutes: FieldRule = { kind: "minutes", min: 0, max: 1439 };

export const FIELD_RULES: Record<string, FieldRule> = {
  DisableRealtimeMonitoring: bool(true),
  DisableBehaviorMonitoring: bool(true),
  DisableIOAVProtection: bool(true),
  DisableScriptScanning: bool(true),
  DisableBlockAtFirstSeen: bool(true),
  DisableArchiveScanning: bool(true),
  DisableEmailScanning: bool(true),
  DisableRemovableDriveScanning: bool(true),
  DisableScanningNetworkFiles: bool(true),
  DisableScanningMappedNetworkDrivesForFullScan: bool(true),
  MAPSReporting: int(0, 2, ["0"]),
  SubmitSamplesConsent: int(0, 3),
  CloudBlockLevel: { kind: "enum", values: ["Default", "Moderate", "High", "HighPlus", "ZeroTolerance"], weakening: ["Default"] },
  CloudExtendedTimeout: int(0, 50),
  PUAProtection: { kind: "enum", values: MODES, weakening: ["Disabled", "AuditMode"] },
  EnableNetworkProtection: { kind: "enum", values: MODES, weakening: ["Disabled", "AuditMode"] },
  LowThreatDefaultAction: { kind: "enum", values: ACTIONS, weakening: ["Allow", "NoAction", "UserDefined"] },
  ModerateThreatDefaultAction: { kind: "enum", values: ACTIONS, weakening: ["Allow", "NoAction", "UserDefined"] },
  HighThreatDefaultAction: { kind: "enum", values: ACTIONS, weakening: ["Allow", "NoAction", "UserDefined"] },
  SevereThreatDefaultAction: { kind: "enum", values: ACTIONS, weakening: ["Allow", "NoAction", "UserDefined"] },
  QuarantinePurgeItemsAfterDelay: int(0, 365),
  ScanPurgeItemsAfterDelay: int(0, 365),
  ScanScheduleDay: int(0, 8),
  ScanScheduleTime: minutes,
  ScanScheduleQuickScanTime: minutes,
  ScanParameters: int(1, 2),
  RemediationScheduleDay: int(0, 8),
  RemediationScheduleTime: minutes,
  DisableCatchupFullScan: bool(true),
  DisableCatchupQuickScan: bool(true),
  SignatureScheduleDay: int(0, 8),
  SignatureScheduleTime: minutes,
  SignatureUpdateInterval: int(1, 24),
  SignatureUpdateCatchupInterval: int(1, 30),
  RandomizeScheduleTaskTimes: bool(),
  CheckForSignaturesBeforeRunningScan: bool(),
  MeteredConnectionUpdates: bool(),
  ScanAvgCPULoadFactor: int(0, 100),
  ScanOnlyIfIdleEnabled: bool(),
  EnableLowCpuPriority: bool(),
  DisableCpuThrottleOnIdleScans: bool(),
  EnableFullScanOnBatteryPower: bool(),
  DisableRestorePoint: bool(),
  DisableAutoExclusions: bool(true),
};

/** Whether setting the value lowers protection, so the change is the weakening action (a tier 3 change). */
export function weakens(field: string, value: string): boolean {
  const r = FIELD_RULES[field];
  if (!r) return false;
  if (r.kind === "bool") return !!r.weakensTrue && value === "true";
  return !!r.weakening?.includes(value);
}

/** The ASR modes that lower protection. */
export const ASR_MODES = ["Disabled", "Enabled", "AuditMode", "Warn"];
export const asrWeakens = (mode: string) => mode === "AuditMode" || mode === "Disabled";

/** The rules the module may set (the server's catalogue, from Microsoft's reference): a rule not yet configured is offered from here. */
export const ASR_RULES: { id: string; name: string }[] = [
  { id: "56a863a9-875e-4185-98a7-b882c64b5ce5", name: "Block abuse of exploited vulnerable signed drivers" },
  { id: "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", name: "Block Adobe Reader from creating child processes" },
  { id: "d4f940ab-401b-4efc-aadc-ad5f3c50688a", name: "Block all Office applications from creating child processes" },
  { id: "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", name: "Block credential stealing from the Windows local security authority subsystem" },
  { id: "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", name: "Block executable content from email client and webmail" },
  { id: "01443614-cd74-433a-b99e-2ecdc07bfc25", name: "Block executable files from running unless they meet a prevalence, age or trusted list criterion" },
  { id: "5beb7efe-fd9a-4556-801d-275e5ffc04cc", name: "Block execution of potentially obfuscated scripts" },
  { id: "d3e037e1-3eb8-44c8-a917-57927947596d", name: "Block JavaScript or VBScript from launching downloaded executable content" },
  { id: "3b576869-a4ec-4529-8536-b80a7769e899", name: "Block Office applications from creating executable content" },
  { id: "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", name: "Block Office applications from injecting code into other processes" },
  { id: "26190899-1602-49e8-8b27-eb1d0a1ce869", name: "Block Office communication application from creating child processes" },
  { id: "e6db77e5-3df2-4cf1-b95a-636979351e5b", name: "Block persistence through WMI event subscription" },
  { id: "d1e49aac-8f56-4280-b9ba-993a6d77406c", name: "Block process creations originating from PSExec and WMI commands" },
  { id: "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", name: "Block untrusted and unsigned processes that run from USB" },
  { id: "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", name: "Block Win32 API calls from Office macros" },
  { id: "c1db55ab-c21a-4637-bb3f-a12568109d35", name: "Use advanced protection against ransomware" },
  { id: "a8f5898e-1dc8-49a9-9878-85004b8a61e6", name: "Block Webshell creation for Servers" },
  { id: "33ddedf1-c6e0-47cb-833e-de6133960387", name: "Block rebooting machine in Safe Mode" },
  { id: "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", name: "Block use of copied or impersonated system tools" },
];
