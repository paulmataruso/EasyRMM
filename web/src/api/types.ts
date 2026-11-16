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
  /** The caller may run scripts here and the device has the EasyRMM agent. */
  canRunScripts: boolean;
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
  /** The same key's pin for the Windows PowerShell command: the hex SHA-256 of the public key. */
  keyPin?: string;
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

// Scripts and jobs (ADR-0017) --------------------------------------------------------------------

export type Shell = "powershell" | "cmd" | "bash" | "sh" | "python3";
/** Where a script can run: everywhere, in one organization, or in one site. */
export type ScriptLevel = "shared" | "organization" | "site";

export interface Script {
  id: string;
  level: ScriptLevel;
  organizationId: string | null;
  organizationName?: string;
  siteId: string | null;
  siteName?: string;
  name: string;
  description: string;
  shell: Shell;
  /** Only in the response for one script. */
  body?: string;
  sha256: string;
  /** Body size in bytes. */
  size: number;
  timeoutSeconds: number;
  createdAt: string;
  updatedAt: string;
  canEdit: boolean;
  canRun: boolean;
}

export interface ScriptInput {
  organizationId: string | null;
  siteId: string | null;
  name: string;
  description: string;
  shell: Shell;
  body: string;
  timeoutSeconds: number;
}

export type ScriptPatch = Partial<Pick<ScriptInput, "name" | "description" | "shell" | "body" | "timeoutSeconds">>;

export type RunStatus = "queued" | "sent" | "running" | "succeeded" | "failed" | "timed_out" | "canceled" | "expired" | "lost";

export interface Job {
  id: string;
  /** Null once the script is deleted; the job keeps its own copy. */
  scriptId: string | null;
  scriptName: string;
  shell: Shell;
  sha256: string;
  args: string[];
  timeoutSeconds: number;
  /** When devices that have not picked the job up stop being waited for. */
  expiresAt: string;
  createdBy: string;
  createdAt: string;
  /** A count for every status, over the runs the caller can see. */
  counts: Record<RunStatus, number>;
  total: number;
  finished: boolean;
  /** Only in the response for one job. */
  body?: string;
  runs?: JobRun[];
  canCancel: boolean;
}

export interface JobRun {
  id: string;
  jobId: string;
  deviceId: string;
  deviceName: string;
  organizationId: string;
  organizationName: string;
  siteId: string;
  siteName: string;
  scriptName: string;
  status: RunStatus;
  createdAt: string;
  expiresAt: string;
  sentAt: string | null;
  deliveries: number;
  startedAt: string | null;
  finishedAt: string | null;
  exitCode: number | null;
  error: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  cancelRequested: boolean;
  /** Output and the job are only in the response for one run. */
  stdout?: string;
  stderr?: string;
  job?: Job;
  canCancel: boolean;
}

export interface JobInput {
  scriptId: string;
  deviceIds: string[];
  args: string[];
  /** 0 keeps the script's timeout. */
  timeoutSeconds: number;
  /** 0 is the server's default (24 hours). */
  waitHours: number;
}

// --- Inventory and telemetry (ADR-0018) ----------------------------------------------------

export interface SystemInfo {
  manufacturer: string;
  model: string;
  serial: string;
  biosVendor: string;
  biosVersion: string;
  biosDate: string;
  virtualization: string;
}

export interface Disk {
  name: string;
  model: string;
  serial: string;
  sizeBytes: number;
  kind: "" | "ssd" | "hdd" | "nvme";
  removable: boolean;
}

export interface NetworkInterface {
  name: string;
  mac: string;
  addresses: string[];
  up: boolean;
  speedMbps: number;
}

export interface Inventory {
  system: SystemInfo;
  cpu: { model: string; sockets: number; cores: number; threads: number };
  memoryBytes: number;
  os: { name: string; id: string; version: string; kernel: string; timezone: string };
  disks: Disk[];
  interfaces: NetworkInterface[];
  gateways: string[];
  dnsServers: string[];
  packageManager: "" | "windows" | "dpkg" | "rpm" | "apk" | "pacman";
  packageCount: number;
  receivedAt: string;
}

export interface Filesystem {
  mount: string;
  device: string;
  type: string;
  totalBytes: number;
  usedBytes: number;
}

export interface DeviceMetrics {
  at: string;
  cpuPercent: number;
  memoryTotal: number;
  memoryUsed: number;
  swapTotal: number;
  swapUsed: number;
  load1: number;
  load5: number;
  load15: number;
  uptimeSeconds: number;
  processes: number;
  filesystems: Filesystem[];
}

export interface DeviceInventory {
  inventory: Inventory | null;
  metrics: DeviceMetrics | null;
}

export interface Package {
  name: string;
  version: string;
  arch: string;
  /** Windows programs only. */
  publisher?: string;
}

export type MetricsRange = "1h" | "24h" | "7d";

export interface MetricSample {
  at: string;
  cpuPercent: number;
  memoryPercent: number;
  swapPercent: number;
  diskPercent: number;
  load1: number;
}

export interface MetricsHistory {
  range: MetricsRange;
  bucketSeconds: number;
  from: string;
  to: string;
  samples: MetricSample[];
}

export interface SoftwareSummary {
  name: string;
  version: string;
  devices: number;
}

export interface SoftwareSearch {
  items: SoftwareSummary[];
  truncated: boolean;
}

export interface SoftwareDevice {
  deviceId: string;
  deviceName: string;
  organizationId: string;
  organizationName: string;
  siteId: string;
  siteName: string;
  version: string;
  arch: string;
}

// Monitoring and alerts (ADR-0019) ----------------------------------------------------------------

/** What a policy watches: no check-in, or processor, memory or the fullest disk at a percentage. */
export type AlertKind = "offline" | "cpu" | "memory" | "disk";
export type AlertSeverity = "warning" | "critical";
export type AlertStatus = "open" | "acknowledged" | "resolved";
export type AlertResolution = "cleared" | "manual" | "not_covered" | "policy_off" | "policy_changed" | "policy_deleted";

export interface AlertPolicy {
  id: string;
  /** Which devices it covers: every device, one organization's, or one site's. */
  level: ScriptLevel;
  organizationId: string | null;
  organizationName?: string;
  siteId: string | null;
  siteName?: string;
  name: string;
  description: string;
  kind: AlertKind;
  /** Percent for processor, memory and disk; null for offline. */
  threshold: number | null;
  minutes: number;
  severity: AlertSeverity;
  enabled: boolean;
  /** Unresolved alerts it has raised on devices the caller can see. */
  activeAlerts: number;
  createdAt: string;
  updatedAt: string;
  canEdit: boolean;
}

export interface AlertPolicyInput {
  organizationId?: string | null;
  siteId?: string | null;
  name: string;
  description: string;
  kind: AlertKind;
  threshold: number | null;
  minutes: number;
  severity: AlertSeverity;
  enabled: boolean;
}

/** One policy's condition on one device. */
export interface AlertEntry {
  id: string;
  policyId: string | null;
  deviceId: string;
  deviceName: string;
  organizationId: string;
  organizationName: string;
  siteId: string;
  siteName: string;
  name: string;
  kind: AlertKind;
  threshold: number | null;
  minutes: number;
  severity: AlertSeverity;
  status: AlertStatus;
  /** The value that raised it and the latest: percent, or minutes without a check-in. */
  value: number;
  lastValue: number;
  openedAt: string;
  acknowledgedAt: string | null;
  acknowledgedBy?: string;
  resolvedAt: string | null;
  resolvedBy?: string;
  resolution?: AlertResolution;
  canManage: boolean;
}

/** Active alerts on one device (GET /alerts/devices), for the alerts tree. */
export interface DeviceAlertCount {
  deviceId: string;
  organizationId: string;
  siteId: string;
  active: number;
  critical: number;
}

/** A device the caller recently opened a remote session on (GET /devices/recent-connections). */
export interface RecentConnection {
  device: Device;
  kind: RemoteKind;
  at: string;
}

export interface AlertSummary {
  active: number;
  critical: number;
  warning: number;
  acknowledged: number;
  devices: number;
}
