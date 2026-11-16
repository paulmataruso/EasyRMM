// Shapes of the EasyRMM API (server/internal/...). Keep in step with the Go json tags.

export type Permission =
  | "org.view"
  | "org.manage"
  | "org.create"
  | "site.view"
  | "site.manage"
  | "device.view"
  | "device.edit"
  | "device.retire"
  | "device.remote_desktop"
  | "device.terminal"
  | "device.files"
  | "script.view"
  | "script.manage"
  | "script.run"
  | "job.view"
  | "job.manage"
  | "software.view"
  | "software.manage"
  | "patch.view"
  | "patch.manage"
  | "monitoring.view"
  | "monitoring.manage"
  | "alert.view"
  | "alert.manage"
  | "enrollment.manage"
  | "user.view"
  | "user.manage"
  | "audit.view"
  | "report.view"
  | "settings.manage";

export type Role = "super_admin" | "org_admin" | "site_admin" | "technician" | "read_only";
export type ScopeKind = "global" | "organization" | "site";
export type SessionState = "mfa_required" | "mfa_enrollment" | "active";

export interface List<T> {
  items: T[];
  next?: string;
}

export interface AuthUser {
  id: string;
  email: string;
  displayName: string;
  status: string;
  mfaEnabled: boolean;
}

export interface SessionView {
  state: SessionState;
  user: AuthUser;
  csrfToken: string;
  expiresAt: string;
  permissions: Permission[];
  isSuperAdmin: boolean;
  /** Optional parts of the server that are turned on. */
  features: Features;
}

export interface Features {
  /** MeshCentral is configured, so remote sessions can be offered. */
  remoteAccess: boolean;
}

export interface AuthOptions {
  passwordResetAvailable: boolean;
  mfaRequired: boolean;
  passwordMinLength: number;
}

export interface SetupStatus {
  required: boolean;
  passwordMinLength: number;
}

export interface TotpEnrollment {
  secret: string;
  uri: string;
  qrCodeSvg: string;
}

export interface RecoveryCodes {
  recoveryCodes: string[];
}

export interface ConfirmTotpResult extends RecoveryCodes {
  session: SessionView;
}

export interface SessionItem {
  id: string;
  state: SessionState;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  idleExpiresAt: string;
  sourceIp?: string;
  userAgent: string;
  current: boolean;
}

export interface Organization {
  id: string;
  name: string;
  notes: string;
  siteCount: number;
  createdAt: string;
  updatedAt: string;
  canManage: boolean;
}

export interface OrganizationInput {
  name: string;
  notes: string;
}

export interface Site {
  id: string;
  organizationId: string;
  organizationName: string;
  name: string;
  timezone: string;
  address: string;
  notes: string;
  deviceGroupCount: number;
  createdAt: string;
  updatedAt: string;
  canManage: boolean;
}

export interface SiteInput {
  name: string;
  timezone: string;
  address: string;
  notes: string;
}

export interface DeviceGroup {
  id: string;
  organizationId: string;
  siteId: string;
  name: string;
  description: string;
  createdAt: string;
  updatedAt: string;
}

export interface DeviceGroupInput {
  name: string;
  description: string;
}

export interface Assignment {
  role: Role;
  organizationId?: string;
  organizationName?: string;
  siteId?: string;
  siteName?: string;
}

export interface User {
  id: string;
  email: string;
  displayName: string;
  status: "active" | "disabled";
  mfaEnabled: boolean;
  passwordSet: boolean;
  locked: boolean;
  lastLoginAt: string | null;
  createdAt: string;
  assignments: Assignment[];
  hiddenAssignments: number;
  canManage: boolean;
  isSelf: boolean;
}

export interface InviteInput {
  email: string;
  displayName: string;
  assignments: Assignment[];
}

export interface InviteResult {
  user?: User;
  link?: string;
  emailed: boolean;
}

export interface RoleView {
  role: Role;
  name: string;
  description: string;
  rank: number;
  scopes: ScopeKind[];
  permissions: Permission[];
}

export type AuditOutcome = "success" | "failure" | "denied";

export interface AuditEntry {
  id: number;
  occurredAt: string;
  actorType: "user" | "agent" | "system";
  actorId?: string;
  actorLabel: string;
  organizationId?: string;
  siteId?: string;
  deviceId?: string;
  action: string;
  targetType: string;
  targetId: string;
  outcome: AuditOutcome;
  sourceIp?: string;
  userAgent: string;
  details: Record<string, unknown> | null;
}

export interface AuditVerifyResult {
  checked: number;
  firstBadId?: number;
}

export type Platform = "windows" | "linux" | "macos" | "other";
export type RemoteKind = "desktop" | "terminal" | "files";

export interface Device {
  id: string;
  organizationId: string;
  organizationName: string;
  siteId: string;
  siteName: string;
  deviceGroupId: string | null;
  deviceGroupName?: string;
  name: string;
  hostname: string;
  osDescription: string;
  platform: Platform;
  /** The EasyRMM agent or remote access reported in recently. */
  online: boolean;
  /** The EasyRMM agent, when the device enrolled with one. */
  agent: DeviceAgent | null;
  remoteAgent: boolean;
  remoteOnline: boolean;
  lastSeenAt: string | null;
  createdAt: string;
  updatedAt: string;
  canDesktop: boolean;
  canTerminal: boolean;
  canFiles: boolean;
}

export interface DeviceAgent {
  version: string;
  arch: string;
  online: boolean;
  lastSeenAt: string | null;
  enrolledAt: string;
}

export type EnrollmentTokenStatus = "active" | "expired" | "revoked" | "used_up";

export interface EnrollmentToken {
  id: string;
  organizationId: string;
  organizationName: string;
  siteId: string;
  siteName: string;
  deviceGroupId: string | null;
  deviceGroupName?: string;
  name: string;
  expiresAt: string;
  maxUses: number | null;
  uses: number;
  createdByName?: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  status: EnrollmentTokenStatus;
}

export interface EnrollmentTokenInput {
  name: string;
  deviceGroupId: string | null;
  expiresInDays: number;
  maxUses: number | null;
}

/** A created token; the secret is in no other response. */
export interface NewEnrollmentToken {
  token: EnrollmentToken;
  secret: string;
  serverUrl: string;
}

export interface AgentBuild {
  os: string;
  arch: string;
  file: string;
  size: number;
  sha256: string;
}

/** An address the server answers on: its public URL, or one of its IP addresses (ADR-0016). */
export interface ServerAddress {
  url: string;
  /** curl public-key pin when the address uses the server's own certificate authority. */
  pin?: string;
}

/** The server's own certificate authority, used for IP addresses. */
export interface CertificateAuthority {
  fingerprint: string;
  url: string;
}

export interface AgentDownloads {
  serverUrl: string;
  items: AgentBuild[];
  /** Every address, the public URL first. */
  addresses: ServerAddress[];
  /** The address this console was opened at. */
  current: string;
  certificateAuthority: CertificateAuthority | null;
}

export interface RemoteLaunch {
  grantId: string;
  url: string;
  expiresAt: string;
  kind: RemoteKind;
  deviceId: string;
  /** The session's origin uses the server's own certificate authority (an IP address), which the browser must trust. */
  internalCa?: boolean;
}

export interface RemoteAccessStatus {
  address: string;
  connected: boolean;
  lastSyncAt?: string;
  lastError?: string;
  lastErrorAt?: string;
  devices: number;
  devicesOnline: number;
}
