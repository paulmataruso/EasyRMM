// The typed results of the Defender module's reads (ADR-0074), as the server stores them.

export type ManagedBy =
  | "group_policy"
  | "mdm"
  | "defender_for_endpoint"
  | "configmgr"
  | "tamper_protection"
  | "unknown_owner";

export interface PrefField {
  name: string;
  group: string;
  value: string | number | boolean | null;
  supported: boolean;
  managedBy: ManagedBy | null;
  unavailable?: string;
}
export interface DefenderPreferences {
  fields: PrefField[];
  tamperProtected: boolean | null;
}

export interface AsrRuleState {
  id: string;
  name: string;
  known: boolean;
  mode: string;
  managedBy: ManagedBy | null;
}
export interface AsrRead {
  supported: boolean;
  rules: AsrRuleState[];
}

export interface PathItem {
  path: string;
  ours: boolean;
}
export interface CfaRead {
  supported: boolean;
  mode: string;
  managedBy: ManagedBy | null;
  protectedFolders: PathItem[];
  allowedApplications: PathItem[];
}

export interface Exclusion {
  value: string;
  ours: boolean;
  managedBy: ManagedBy | null;
}
export type ExclusionKind = "path" | "process" | "extension" | "asr_only";
export interface ExclusionsRead {
  path: Exclusion[];
  process: Exclusion[];
  extension: Exclusion[];
  asrOnly: Exclusion[];
  unavailable: ExclusionKind[];
  localMergeDisabled: boolean | null;
  tamperProtected: boolean | null;
}

export interface Threat {
  id: number;
  name: string;
  severity: number | null;
  category: number | null;
  active: boolean;
  executed: boolean | null;
  detectedAt: string | null;
  changedAt: string | null;
}
export interface ThreatsRead {
  threats: Threat[];
}
export interface QuarantineRead {
  items: { name: string; path: string }[];
}

export interface Change {
  applied: boolean;
  reason: string;
  before: unknown;
  after: unknown;
}

export interface DefenderEvent {
  id: number;
  eventId: number;
  at: string;
  severity: number;
  threatName?: string;
  category?: string;
  action?: string;
  summary: Record<string, unknown>;
  sensitive?: Record<string, string>;
  ours: boolean;
  backfill: boolean;
}
export interface DefenderEvents {
  items: DefenderEvent[];
  gap: string | null;
}

export interface FleetRow {
  deviceId: string;
  name: string;
  siteId: string;
  siteName: string;
  runningMode: string;
  realTimeProtection: boolean | null;
  tamperProtected: boolean | null;
  signatureAgeDays: number | null;
  quickScanAgeDays: number | null;
  readAt: string | null;
  openAlerts: number;
  threats30Days: number;
}
export interface DefenderFleet {
  items: FleetRow[];
  protected: number;
  notProtected: number;
  signaturesOld: number;
  threats30Days: number;
  unknown: number;
}

export interface ScanDone {
  scanType: string;
  finishedAt: string;
}
export interface SignaturesUpdated {
  before: string;
  after: string;
  updated: boolean;
}
