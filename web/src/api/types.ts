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
  | "patch.configure"
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
  /** Has a second factor of either kind. */
  mfaEnabled: boolean;
  /** An authenticator app is set up. */
  totp: boolean;
  /** Registered security keys and passkeys. */
  securityKeys: number;
  /** Offer a passkey after sign-in: the server supports them, the user has none and has not put the offer off. */
  passkeyPrompt?: boolean;
}

export interface SessionView {
  state: SessionState;
  user: AuthUser;
  csrfToken: string;
  expiresAt: string;
  permissions: Permission[];
  /** Permissions held platform-wide, not only in some organizations or sites. */
  globalPermissions: Permission[];
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
  webauthn?: WebAuthnStatus;
}

/** Whether security keys and passkeys can be used (ADR-0032), and at which address. */
export interface WebAuthnStatus {
  available: boolean;
  origin?: string;
  reason?: string;
}

export interface SecurityKey {
  id: string;
  name: string;
  createdAt: string;
  lastUsedAt?: string;
  /** Copied between the person's devices by their platform or password manager. */
  synced: boolean;
}

export interface SecurityKeyAdded {
  key: SecurityKey;
  /** Issued when this is the account's first second factor; otherwise empty. */
  recoveryCodes: string[];
  session: SessionView;
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
  /** Names are unique on the server, so only Super Administrators rename. */
  canRename: boolean;
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
/** A remote session: MeshAgent's desktop, Windows Remote Desktop (RDP), a terminal, or files. */
export type RemoteKind = "desktop" | "rdp" | "terminal" | "files";

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
  /** The caller may update the device's agent (device.edit) and it has one (ADR-0027). */
  canUpdateAgent: boolean;
  /** The caller may install and remove software here (software.manage), on Windows or Linux with the agent (ADR-0028). */
  canManageSoftware: boolean;
}

export interface DeviceAgent {
  version: string;
  arch: string;
  /** SHA-256 of the agent's executable; empty for agents too old to update themselves. */
  sha256: string;
  online: boolean;
  lastSeenAt: string | null;
  enrolledAt: string;
  /** Where the agent stands against the server's build; null when the server has none for its platform. */
  update: AgentUpdate | null;
}

/** Where an agent stands against the build the server serves (ADR-0027). */
export type AgentUpdateStatus = "current" | "available" | "queued" | "updating" | "failed" | "unsupported";

export interface AgentUpdate {
  status: AgentUpdateStatus;
  /** The server's build's version, "" when unknown. */
  version: string;
  attempts: number;
  error: string;
  requested: boolean;
}

export type AgentUpdateMode = "automatic" | "manual" | "off";

export interface AgentUpdatePolicy {
  mode: AgentUpdateMode;
  maxConcurrent: number;
}

/** The rollout's setting and the fleet's state. Fleet keys are statuses, and "none" for devices without a build. */
export interface AgentUpdateSettings extends AgentUpdatePolicy {
  stored: boolean;
  updatedAt: string | null;
  updatedBy?: string;
  version: string;
  builds: AgentBuild[];
  fleet: Partial<Record<AgentUpdateStatus | "none", number>>;
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

/**
 * A token for a generic install command: devices that use it wait until someone approves them
 * into a site (ADR-0024).
 */
export interface ApprovalToken {
  id: string;
  name: string;
  expiresAt: string;
  maxUses: number | null;
  uses: number;
  /** Devices that used it and still wait for a decision. */
  waiting: number;
  createdByName?: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
  status: EnrollmentTokenStatus;
}

export interface ApprovalTokenInput {
  name: string;
  expiresInDays: number;
  maxUses: number | null;
}

/** A created approval token; the secret is in no other response. */
export interface NewApprovalToken {
  token: ApprovalToken;
  secret: string;
  serverUrl: string;
}

export type EnrollmentRequestState = "pending" | "rejected";

/** An existing device with the same name as a waiting one: perhaps a reinstall. */
export interface EnrollmentRequestMatch {
  deviceId: string;
  name: string;
  organizationName: string;
  siteName: string;
}

/** A device that ran a generic install command and waits for approval. */
export interface EnrollmentRequest {
  id: string;
  /** The device code the agent printed, for telling machines apart. */
  code: string;
  hostname: string;
  os: string;
  platform: string;
  arch: string;
  agentVersion: string;
  sourceIp?: string;
  state: EnrollmentRequestState;
  tokenId: string;
  tokenName: string;
  createdAt: string;
  lastSeenAt: string;
  /** The agent asked within the last two minutes. */
  online: boolean;
  decidedAt?: string;
  decidedByName?: string;
  matches: EnrollmentRequestMatch[];
}

export interface EnrollmentRequestList {
  items: EnrollmentRequest[];
  /** Devices waiting for a decision, whichever list was asked for. */
  waiting: number;
}

export interface ApproveInput {
  ids: string[];
  siteId: string;
  deviceGroupId: string | null;
}

export interface EnrollmentDecision {
  decided: string[];
  devices?: string[];
  /** Requests someone else decided first, or that were gone. */
  skipped: string[];
}

export interface AgentBuild {
  os: string;
  arch: string;
  file: string;
  size: number;
  sha256: string;
  /** The builds' version from the server's VERSION file, "" when unknown. */
  version: string;
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
  /** The certificate in PEM, for Linux, Firefox and the agent's --ca-file. */
  url: string;
  /** The same certificate in DER, a .crt file Windows and macOS install with a double click. */
  certUrl: string;
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

// Audit forwarding (ADR-0023) ---------------------------------------------------------------------

export type SyslogTransport = "tls" | "tcp" | "udp";

export interface AuditForwarding {
  configured: boolean;
  enabled: boolean;
  transport: SyslogTransport;
  host: string;
  port: number;
  facility: number;
  caCert: string;
  clientCert: string;
  clientKeySet: boolean;
  /** Sent as each message's HOSTNAME. */
  hostname: string;
  updatedAt?: string;
  updatedBy?: string;
  status: {
    lastId: number;
    lastSentAt?: string;
    lastError?: string;
    lastErrorAt?: string;
    backlog: number;
    backlogMore: boolean;
    oldestPendingAt?: string;
    stored: number;
    storedMore: boolean;
    /** Turned off, and still delivering the records up to the change that turned it off. */
    stopping: boolean;
  };
}

export interface AuditForwardingInput {
  enabled: boolean;
  transport: SyslogTransport;
  host: string;
  port: number;
  facility: number;
  caCert: string;
  clientCert: string;
  clientKey: string;
  startFrom: "" | "now" | "beginning";
}

export interface AuditForwardingTest {
  ok: boolean;
  message: string;
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
  /** A library script, or a software action run with one of EasyRMM's own scripts (ADR-0028). */
  kind: JobKind;
  /** The software action; null for script jobs. */
  software: SoftwareAction | null;
  /** Null once the script is deleted (the job keeps its own copy), and for software actions. */
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

export type JobKind = "script" | "software";

export type SoftwareVerb = "install" | "upgrade" | "uninstall";

/** winget and Chocolatey on Windows; "system" is a Linux device's own: apt-get, dnf, yum or zypper. */
export type SoftwareManager = "winget" | "chocolatey" | "system";

export interface SoftwareAction {
  action: SoftwareVerb;
  manager: SoftwareManager;
  package: string;
  /** For installs only; absent takes the newest. */
  version?: string;
}

export interface SoftwareInput extends SoftwareAction {
  deviceIds: string[];
  /** 0 is the server's default (1 hour). */
  timeoutSeconds: number;
  /** 0 is the server's default (24 hours). */
  waitHours: number;
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

// --- Reports (ADR-0029) --------------------------------------------------------------------

export type ReportName = "devices" | "software" | "health" | "alerts";

export interface ReportColumn {
  key: string;
  /** Names the unit when there is one: "Memory (GiB)". */
  label: string;
  type: "text" | "number" | "percent" | "time" | "bool";
}

export type ReportValue = string | number | boolean | null;

export interface Report {
  name: ReportName;
  title: string;
  columns: ReportColumn[];
  /** The first rows only (1,000); the CSV has them all. */
  rows: ReportValue[][];
  /** Every row of the report, up to 100,000. */
  total: number;
  /** The report has more than 100,000 rows. */
  truncated: boolean;
  generatedAt: string;
}

// ---------------------------------------------------------------------------------------------
// EasyPatch (ADR-0030)
// ---------------------------------------------------------------------------------------------

/** The EasyPatch server EasyRMM patches through. The API token is never sent back. */
export interface EasyPatchConnection {
  configured: boolean;
  /** Patching comes from the engine in this deployment (EASYRMM_PATCHING=bundled): the deployment sets it up, Settings cannot change it. */
  bundled: boolean;
  url: string;
  caCert: string;
  serverVersion: string;
  publicUrl: string;
  /** Optional features the server lists: "scheduled-installs", "on-behalf-of". */
  capabilities: string[];
  /** The token is an Admin token; a ReadOnly one only reads. */
  canOperate: boolean;
  checkedAt?: string;
  lastError?: string;
  lastErrorAt?: string;
  updatedAt?: string;
  updatedBy?: string;
}

export interface EasyPatchConnectionInput {
  url: string;
  /** Empty keeps the stored token, on the same server. */
  token: string;
  caCert: string;
}

export interface EasyPatchOrganization {
  id: string;
  name: string;
  isActive: boolean;
  siteCount: number;
  endpointCount: number;
}

export interface EasyPatchOrganizationLink {
  organizationId: string;
  organizationName: string;
  easyPatchId: string;
  easyPatchName: string;
  linkedAt: string;
  linkedBy?: string;
  /** EasyRMM installs the EasyPatch agent on the organization's devices that have none (ADR-0031). */
  autoInstall: boolean;
  devices: { linked: number; unlinked: number; pending: number };
}

export interface EasyPatchOrganizations {
  easyPatch: EasyPatchOrganization[];
  links: EasyPatchOrganizationLink[];
  /** Why EasyPatch's organizations could not be read. */
  error?: string;
}

/** Whether EasyRMM patches a device: linked to its EasyPatch endpoint, refused (with a reason), being checked, or no EasyPatch agent. */
export type PatchLink = "linked" | "unlinked" | "pending" | "none";

export interface EasyPatchDeviceLink {
  deviceId: string;
  deviceName: string;
  organizationName: string;
  state: PatchLink;
  reason?: string;
  endpointId?: string;
  checkedAt?: string;
}

export interface PatchStatus {
  configured: boolean;
  canOperate: boolean;
  canSchedule: boolean;
  /** EasyPatch's own console, to open in a new tab. */
  consoleUrl?: string;
}

export type ComplianceStatus = "Compliant" | "MissingUpdates" | "FailedUpdates" | "RebootRequired" | "ScanStale" | "NeverScanned";

/** Where EasyRMM's agent is with installing the EasyPatch agent (ADR-0031). */
export type AgentInstallState = "waiting" | "sent" | "succeeded" | "failed";

export interface AgentInstall {
  state: AgentInstallState;
  /** Started by the organization's automatic installs rather than by someone. */
  automatic: boolean;
  requestedBy?: string;
  requestedAt: string;
  attempts: number;
  sentAt?: string;
  finishedAt?: string;
  error?: string;
  /** Why a waiting install has not been sent, such as an agent too old to install. */
  note?: string;
}

/** An EasyPatch endpoint as its lists summarise it. */
export interface PatchEndpoint {
  id: string;
  hostname: string;
  organizationId: string;
  organizationName: string;
  siteName: string;
  status: string;
  operatingSystem: string;
  platform: string;
  agentVersion: string;
  agentOutdated: boolean;
  isOnline: boolean;
  lastCheckInAt: string | null;
  lastScanAt: string | null;
  complianceStatus: ComplianceStatus;
  missingRequiredCount: number;
  missingTotalCount: number;
  missingDeferredCount: number;
  failedCount: number;
  rebootPending: boolean;
  knownExploitedMissingCount: number;
  currentActivity: string;
}

export interface PatchFleetDevice {
  deviceId: string;
  name: string;
  organizationId: string;
  organizationName: string;
  siteId: string;
  siteName: string;
  platform: Platform;
  link: PatchLink;
  reason?: string;
  /** The caller may scan and install here (patch.manage). */
  canManage: boolean;
  endpoint?: PatchEndpoint;
  checkedAt?: string;
  /** The EasyPatch agent's install, when one was asked for. */
  install?: AgentInstall;
}

export interface PatchFleet {
  devices: PatchFleetDevice[];
  truncated: boolean;
  /** EasyPatch organizations that could not be read, with why. */
  errors: string[];
}

export interface PatchEndpointDetail {
  summary: PatchEndpoint;
  serialNumber: string;
  lastScanAttemptAt: string | null;
  lastScanError: string;
  rebootReasons: string[] | null;
  rebootPendingSince: string | null;
  installedCount: number;
  pendingRebootUpdateCount: number;
  complianceEvaluatedAt: string | null;
}

/** When EasyPatch installs updates on its own, from the endpoint's effective policy. */
export interface PatchPolicy {
  autoInstallEnabled: boolean;
  /** 0 is Sunday. */
  maintenanceDays: number[] | null;
  /** "HH:mm" in timeZone. */
  maintenanceStart: string | null;
  maintenanceDurationMinutes: number | null;
  timeZone: string;
  scanIntervalMinutes: number;
  allowedCategories: string[] | null;
  includeOptional: boolean;
  installDelayDays: number;
  securityInstallDelayDays: number;
}

export interface DevicePatching {
  deviceId: string;
  link: PatchLink;
  reason?: string;
  checkedAt?: string;
  canManage: boolean;
  canSchedule: boolean;
  endpoint?: PatchEndpointDetail;
  policy?: PatchPolicy;
  /** The EasyPatch agent's install, when one was asked for. */
  install?: AgentInstall;
  /** Why EasyPatch could not be read just now. */
  error?: string;
}

export type PatchUpdateState =
  "Missing" | "Failed" | "PendingVerification" | "PendingReboot" | "Installed" | "Superseded" | "NotApplicable" | "Excluded" | "Reoffered";

export interface PatchUpdate {
  updateGuid: string;
  title: string;
  kbNumber: string;
  category: string;
  msrcSeverity: string;
  releaseDate: string | null;
  sizeBytes: number | null;
  rebootLikely: boolean;
  supportUrl: string;
  state: PatchUpdateState;
  isRequired: boolean;
  isExcluded: boolean;
  firstDetectedAt: string;
  stateChangedAt: string;
  installedAt: string | null;
  failedAttempts: number;
  errorCode: string;
  errorMessage: string;
  activeJob: { jobId: string; jobStatus: string; itemStatus: string; downloadPercent: number | null; installPercent: number | null; jobType: string } | null;
  package: { name: string; version: string; installedVersion: string; repository: string; advisories: string[] | null } | null;
  deferredUntil: string | null;
  cveIds: string[] | null;
  knownExploited: boolean;
  holdReason: string;
}

export interface PatchHistoryEntry {
  id: number;
  updateGuid: string | null;
  title: string;
  kbNumber: string;
  operation: string;
  resultCode: number;
  result: string;
  hResult: string;
  errorDescription: string;
  date: string;
}

export interface PatchPage<T> {
  items: T[];
  page: number;
  pageSize: number;
  totalCount: number;
}

export interface PatchJob {
  id: string;
  endpointId: string;
  hostname: string;
  type: string;
  status: string;
  trigger: string;
  requestedBy: string;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
  expiresAt: string;
  progressPercent: number | null;
  phase: string;
  progressMessage: string;
  errorCode: string;
  errorMessage: string;
  rebootRequired: boolean;
  timedOut: boolean;
  cancelRequested: boolean;
  itemCount: number;
  succeededCount: number;
  failedCount: number;
}

/** A job with the EasyRMM device it runs on, from the patching job list. */
export interface PatchJobView extends PatchJob {
  deviceId: string;
  deviceName: string;
  canManage: boolean;
}

export interface PatchJobItem {
  updateGuid: string;
  title: string;
  kbNumber: string;
  category: string;
  status: string;
  skipReason: string;
  resultCode: number | null;
  errorCode: string;
  errorMessage: string;
  rebootRequired: boolean;
  downloadPercent: number | null;
  installPercent: number | null;
  startedAt: string | null;
  completedAt: string | null;
}

export interface PatchJobDetail {
  summary: PatchJob;
  installMode: string;
  notBefore: string | null;
  deliveredAt: string | null;
  lastProgressAt: string | null;
  items: PatchJobItem[];
  events: { id: number; type: string; severity: string; message: string; createdAt: string }[];
  deviceId: string;
  deviceName: string;
  canManage: boolean;
}

export interface PatchActionInput {
  deviceIds: string[];
  updateIds?: string[];
  scheduledAt?: string;
}

export interface PatchActionResult {
  succeeded: number;
  failed: number;
  results: { deviceId: string; deviceName: string; ok: boolean; jobId?: string; message?: string }[];
}

/** Whether to show the EasyRMM | EasyPatch switch, and whether EasyPatch was answering. */
export interface ProductSwitch {
  show: boolean;
  /** False when a call to EasyPatch failed since its last good check. */
  answering: boolean;
  failingSince?: string;
}

/** Where a link from EasyPatch opens the console; `notice` says why it is not the page the link named. */
export interface EasyPatchLanding {
  path: string;
  notice?: string;
}

/** EasyPatch's registration with EasyRMM's sign-in provider (ADR-0036), without its secret. */
export interface EasyPatchSignInClient {
  clientId: string;
  redirectUri: string;
  createdAt: string;
  createdBy?: string;
  rotatedAt?: string;
  rotatedBy?: string;
}

/** Settings → EasyPatch → Sign-in. */
export interface EasyPatchSignIn {
  /** EasyPatch is set up and can sign people in through EasyRMM; otherwise `reason` says why not. */
  available: boolean;
  reason?: string;
  issuer: string;
  /** Where EasyPatch receives sign-ins, from its current address. */
  redirectUri?: string;
  client: EasyPatchSignInClient | null;
}

/** A new or rotated client, with its secret: shown once. */
export interface EasyPatchSignInSecret extends EasyPatchSignInClient {
  issuer: string;
  clientSecret: string;
}

/** What EasyRMM's restart (only if a restart is pending) would do to one device. */
export interface RestartCheck {
  deviceId: string;
  deviceName: string;
  /** It would restart; otherwise `reason` says why not. */
  restart: boolean;
  reason?: string;
  /** A server, or any device when EasyPatch cannot tell (`serversKnown`): it restarts only when confirmed by name. */
  server: boolean;
  online: boolean;
}

export interface RestartPlan {
  devices: RestartCheck[];
  /** False with EasyPatch before 1.10.0, which cannot say which devices are servers. */
  serversKnown: boolean;
}

export interface RestartInput {
  deviceIds: string[];
  scheduledAt?: string;
  /** The servers the person ticked; any server not listed stops the whole request. */
  confirmServers?: string[];
}

/** An identity provider for single sign-on (ADR-0034). The client secret is never returned. */
export interface SsoProvider {
  id: string;
  name: string;
  issuer: string;
  clientId: string;
  allowedDomains: string[];
  trustEmail: boolean;
  trustMfa: boolean;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

/** Creates or changes a provider; an empty clientSecret keeps the stored one. */
export interface SsoProviderInput {
  name: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  allowedDomains: string[];
  trustEmail: boolean;
  trustMfa: boolean;
  enabled: boolean;
}

export interface SsoSettings {
  /** What administrators register with every provider. */
  redirectUri: string;
  providers: SsoProvider[];
}

/** An enabled provider on the sign-in page. */
export interface SsoButton {
  id: string;
  name: string;
  /** Begins the sign-in, at the public URL. */
  startUrl: string;
}

/** A provider account linked to the signed-in user. */
export interface LinkedIdentity {
  providerId: string;
  providerName: string;
  email: string;
  createdAt: string;
  lastUsedAt?: string | null;
}
