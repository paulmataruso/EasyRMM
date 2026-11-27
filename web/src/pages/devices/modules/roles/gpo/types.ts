// The typed results of the Group Policy module (ADR-0083, slice 1): what the scripts print, as the server stores it.

export interface GpoStatus {
  domain: string;
  domainDn: string;
  controller: string;
  gpoCount: number;
  empty: number;
  unlinked: number | null;
  targets: number;
}

export interface GpoVersion {
  directory: number;
  sysvol: number;
}

export interface GpoLink {
  gpoId: string;
  gpoName: string;
  target: string;
  targetName: string;
  kind: "domain" | "ou" | "site";
  enabled: boolean;
  enforced: boolean;
  order: number;
}

export interface Gpo {
  id: string;
  name: string;
  status: "AllSettingsEnabled" | "UserSettingsDisabled" | "ComputerSettingsDisabled" | "AllSettingsDisabled";
  description: string;
  owner: string;
  created: string | null;
  modified: string | null;
  computer: GpoVersion;
  user: GpoVersion;
  wmiFilter: string;
  default: boolean;
  linkCount: number;
  links: GpoLink[];
}

export interface GpoPage {
  total: number;
  offset: number;
  next: number | null;
  items: Gpo[];
  walked: boolean;
}

export interface Trustee {
  name: string;
  sid: string;
  type: "user" | "group" | "computer" | "well_known" | "other";
  permission: string;
  inherited: boolean;
  denied: boolean;
  apply: boolean;
}

export interface ReportLink {
  name: string;
  path: string;
  enabled: boolean;
  enforced: boolean;
  sensitive: boolean;
}

export interface GpoDetail extends Gpo {
  reportLinks: ReportLink[];
  trustees: Trustee[];
}

export interface LinkTarget {
  dn: string;
  name: string;
  kind: "domain" | "ou" | "site";
  sensitive: boolean;
  inheritanceBlocked: boolean;
  links: GpoLink[];
}

export interface LinkTree {
  domain: string;
  total: number;
  offset: number;
  next: number | null;
  targets: LinkTarget[];
}

export interface WmiFilter {
  id: string;
  name: string;
  description: string;
  queries: string[];
}

export interface SettingNode {
  label: string;
  value?: string;
  state?: string;
  children?: SettingNode[];
}

export interface ReportExtension {
  name: string;
  kind: string;
  noApi: boolean;
  settings: SettingNode[];
}

export interface ReportConfig {
  enabled: boolean;
  version: GpoVersion;
  extensions: ReportExtension[];
}

export interface GpoReport {
  id: string;
  name: string;
  created: string;
  modified: string;
  computer: ReportConfig;
  user: ReportConfig;
  links: ReportLink[];
  findings: string[];
  truncated: boolean;
  settings: number;
  total: number;
}

export interface GpoBackup {
  id: string;
  backupId: string;
  gpoId: string;
  gpoName: string;
  kind: "automatic" | "manual";
  action: string;
  actorLabel: string;
  reason: string;
  size: number;
  sha256: string;
  computerVersion: number;
  userVersion: number;
  createdAt: string;
  parts: number;
}

export interface GpoRequest {
  id: string;
  deviceId: string;
  action: string;
  label: string;
  params: Record<string, unknown>;
  sensitivity: "default_policy" | "sensitive_link" | "organization";
  summary: string;
  reason: string;
  status: "pending" | "approved" | "rejected" | "expired";
  requestedBy: string;
  requestedLabel: string;
  createdAt: string;
  expiresAt: string;
  decidedLabel: string;
  decidedReason: string;
  decidedAt: string | null;
  runId: string | null;
  canDecide: boolean;
}

export interface GpoSettings {
  approvalSensitive: boolean;
  approvalAll: boolean;
}

export interface GpoSummary {
  enabled: boolean;
  domains: { domain: string; deviceId: string; controller: string; gpoCount: number; empty: number; unlinked: number | null; readAt: string | null }[];
  pendingApprovals: number;
}

export interface WmiFilters {
  filters: WmiFilter[];
}
