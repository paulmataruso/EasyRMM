// The shapes of ADR-0075's results, as the server's activedirectory package decodes them.

export interface PasswordPolicy {
  minLength: number;
  complexity: boolean;
  historyCount: number;
  maxAgeDays: number | null;
  lockoutThreshold: number;
  lockoutDurationMinutes: number;
  lockoutObservationMinutes: number;
}

export interface DirectoryStatus {
  domain: string;
  domainSid: string;
  forest: string;
  forestRootSid: string;
  domainMode: string;
  forestMode: string;
  controller: string;
  readOnly: boolean;
  globalCatalog: boolean;
  pdcEmulator: string;
  recycleBinEnabled: boolean;
  passwordPolicy: PasswordPolicy;
}

/** `none`, `service` (a second confirmation) or `protected` (refused, never offered). */
export type ProtectionLevel = "none" | "service" | "protected";

export interface UserRow {
  id: string;
  sam: string;
  name: string;
  upn: string;
  enabled: boolean;
  lockedOut: boolean;
  passwordExpired: boolean;
  protection: ProtectionLevel;
  reason: string;
}

export interface UserPage {
  items: UserRow[];
  next: string | null;
  scanned: number;
  domainSid: string;
}

export interface GroupRow {
  id: string;
  sam: string;
  name: string;
  scope: string;
  category: string;
  description: string;
  protection: ProtectionLevel;
  reason: string;
}

export interface GroupPage {
  items: GroupRow[];
  next: string | null;
  scanned: number;
  domainSid: string;
}

export interface GroupMember {
  id: string;
  sam: string;
  name: string;
  kind: "user" | "computer" | "group" | "foreign" | "other";
  key: string;
}

export interface MemberPage {
  items: GroupMember[];
  next: string | null;
  total: number;
}

export type CheckState = "ok" | "warning" | "critical" | "unknown" | "not_applicable" | "could_not_run";

export interface HealthCheck {
  name: string;
  state: CheckState;
  detail: string;
}

export interface DirectoryHealth {
  controller: string;
  domain: string;
  checks: HealthCheck[];
  replication: {
    failureCount: number;
    oldestFailureAt: string | null;
    partners: { partner: string; lastSuccessAt: string | null; lastResult: number }[];
  };
}

export interface ResetResult {
  mustChange: boolean;
  unlocked: boolean;
}

export interface ComputerRow {
  id: string;
  sam: string;
  name: string;
  dnsName: string;
  os: string;
  enabled: boolean;
  controller: boolean;
}
export interface ComputerPage {
  items: ComputerRow[];
  next: string | null;
  scanned: number;
}

export interface OuItem {
  dn: string;
  name: string;
  kind: "ou" | "container";
  protectedFromDelete: boolean;
  writable: boolean;
}
export interface OuTree {
  parent: string;
  items: OuItem[];
}

export interface PrivilegedGroup {
  id: string;
  name: string;
  tier: number;
  total: number;
  changedAt: string | null;
  members: { id: string; name: string; kind: string }[];
}
export interface Privileged {
  groups: PrivilegedGroup[];
}

export interface UserDetail {
  id: string;
  sam: string;
  upn: string;
  name: string;
  displayName: string;
  givenName: string;
  surname: string;
  description: string;
  mail: string;
  telephone: string;
  title: string;
  department: string;
  company: string;
  office: string;
  ou: string;
  groups: string[];
  protection: ProtectionLevel;
  reason: string;
}

export interface DomainController {
  deviceId: string;
  siteId: string;
  name: string;
  controller: string;
  readOnly: boolean;
  online: boolean;
  pdc: boolean;
  health: "healthy" | "unhealthy" | "unknown";
}
export interface AdDomain {
  sid: string;
  name: string;
  controllers: DomainController[];
  pinned: string | null;
  chosen: string | null;
  why: string;
  lockedOut: number | null;
  replicationFailures: number | null;
  worst: string;
}
export interface AdDomains {
  enabled: boolean;
  domains: AdDomain[];
}
