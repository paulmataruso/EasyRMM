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
  | "job.view_sensitive"
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
  /** IANA time zone; patching's monthly reports use it. */
  timezone: string;
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
  timezone: string;
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
  /** Why the link was not emailed, when it was not. */
  mailProblem?: MailProblem;
  /** The limit that stopped it, in words, when one did. */
  mailReason?: string;
}

/** Why a link was not emailed: there is no mail server, or it did not take the message. */
export type MailProblem = "no_mail_server" | "not_sent";

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
  /** The caller may check the device's hardening (script.run), on Linux with the agent (ADR-0051). */
  canCheckHardening: boolean;
  /** The caller may remove the device (device.retire; ADR-0050). */
  canRemove: boolean;
  /** The removal under way, while the device waits for its agent to uninstall itself (ADR-0050). */
  removal: DeviceRemoval | null;
  /** What hardening jobs found here, summed up; null until one reported (ADR-0051). */
  hardening: HardeningSummary | null;
  /** Its disks' health, summed up; null while its agent has reported none (ADR-0065). */
  diskHealth: DiskHealthSummary | null;
}

/**
 * A device's disk health (ADR-0065, "A device's disk health"): the highest of its disks' shown states in the order
 * failing, warning, unknown, healthy, else unavailable if any disk is, else unsupported; and how many disks show each
 * state.
 */
export interface DiskHealthSummary {
  label: DiskState;
  states: Partial<Record<DiskState, number>>;
}

/** The Devices list's disk health filter: a label, or a device whose agent reported none. Unavailable and unsupported
 * find a device with any disk in that state. */
export type DiskHealthFilter = DiskState | "not_reported";

/** When a device's latest hardening job reported, and how many modules are in each state. */
export interface HardeningSummary {
  checkedAt: string;
  states: Partial<Record<HardeningState, number>>;
}

/** The Devices list's hardening filter. */
export type HardeningFilter = "attention" | "in_place" | "unchecked";

/** A device's removal, while its agent has not confirmed it (ADR-0050). */
export interface DeviceRemoval {
  requestedAt: string;
  /** When a heartbeat answer first carried the instruction; null until the agent checks in. */
  sentAt: string | null;
  /** The agent could not uninstall itself: when it said so, and why. */
  reportedAt: string | null;
  error: string;
}

/** What asking to remove a device did: the device waits for its agent, or had none and is gone. */
export interface DeviceRemovalResult {
  status: "asked" | "removed";
  device?: Device;
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
  /**
   * The job capabilities the agent's build said it takes, with its polls (ADR-0064): "job.pwsh" for PowerShell 7 scripts.
   * Null when the build it runs now has not said, as an agent of a release before this one never does.
   */
  accepts: string[] | null;
  /** Whether the last inventory listed a usable PowerShell 7; null when it listed no PowerShell (an older agent, or none yet). */
  powerShell7: boolean | null;
  /**
   * Where no PowerShell 7 is usable but one is blocked, why: what it would load fails the agent's check, or a file of it is
   * open in another program, has more than one hard link or could not be checked, and PowerShell 7 scripts fail there without
   * falling back to Windows PowerShell 5.1 (ADR-0064). Absent otherwise.
   */
  powerShell7Blocked?: string;
}

/**
 * Where an agent stands against the build the server serves (ADR-0027). "waiting": only signed Windows builds are handed
 * out and none is for its architecture yet (ADR-0049).
 */
export type AgentUpdateStatus = "current" | "available" | "queued" | "updating" | "failed" | "unsupported" | "waiting";

export interface AgentUpdate {
  status: AgentUpdateStatus;
  /** The server's build's version, "" when unknown. */
  version: string;
  attempts: number;
  error: string;
  requested: boolean;
  /** The release's version while only signed builds are handed out and none was signed from it yet. */
  waitingFor?: string;
}

export type AgentUpdateMode = "automatic" | "manual" | "off";

export interface AgentUpdatePolicy {
  mode: AgentUpdateMode;
  maxConcurrent: number;
  /** Hand out signed Windows builds only (ADR-0049). */
  signedOnly: boolean;
}

/** The rollout's setting and the fleet's state. Fleet keys are statuses, and "none" for devices without a build. */
export interface AgentUpdateSettings extends AgentUpdatePolicy {
  stored: boolean;
  updatedAt: string | null;
  updatedBy?: string;
  version: string;
  /** The builds handed out: a signed Windows build in place of the release's. */
  builds: AgentBuild[];
  /** The release's builds, whatever is handed out: its Windows builds are what an operator signs. */
  release: AgentBuild[];
  /** The signed Windows builds the server keeps, newest first. */
  signed: SignedAgentBuild[];
  /** Windows architectures with no build handed out: only signed builds are, and there is none for them. */
  withheld: string[];
  fleet: Partial<Record<AgentUpdateStatus | "none", number>>;
}

/** The certificate that signed a Windows build (ADR-0049). */
export interface AgentSigner {
  subject: string;
  issuer: string;
  /** SHA-1 of the certificate, as Windows shows it. */
  thumbprint: string;
  notBefore: string;
  notAfter: string;
  timestamped: boolean;
}

/** A Windows build an operator signed and uploaded (ADR-0049). */
export interface SignedAgentBuild {
  id: string;
  arch: string;
  version: string;
  sha256: string;
  releaseSha256: string;
  size: number;
  signer: AgentSigner;
  uploadedAt: string;
  uploadedBy?: string;
  /** The server hands it out now. */
  served: boolean;
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
  /** The secret was kept, so an active token's install commands can be shown again (ADR-0047). */
  kept: boolean;
}

export interface EnrollmentTokenInput {
  name: string;
  deviceGroupId: string | null;
  expiresInDays: number;
  maxUses: number | null;
}

/** A token with its secret: when it is created, and when it is shown again. */
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
  /** The secret was kept, so an active token's install commands can be shown again (ADR-0047). */
  kept: boolean;
}

export interface ApprovalTokenInput {
  name: string;
  expiresInDays: number;
  maxUses: number | null;
}

/** An approval token with its secret: when it is created, and when it is shown again. */
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
  /** The operator's signature on a Windows build they signed (ADR-0049); absent for the release's build. */
  signed?: AgentSigner;
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

// The mail server (ADR-0053) ---------------------------------------------------------------------

/** STARTTLS required, TLS from the first byte, or none (only to a relay on this machine). */
export type MailSecurity = "starttls" | "tls" | "none";
export type MailSignIn = "none" | "password";

export interface MailServer {
  host: string;
  port: number;
  security: MailSecurity;
  signIn: MailSignIn;
  username: string;
  /** A password is stored; it is never shown. */
  passwordSet: boolean;
  fromAddress: string;
  fromName: string;
  updatedAt?: string;
  updatedBy?: string;
}

export interface MailServerView {
  /** Where the mail server in force comes from: .env (which wins), the console, or nowhere. */
  inForce: "env" | "console" | "none";
  env?: MailServer;
  console?: MailServer;
  /** What of .env's mail server the patching engine will not take; EasyRMM still sends with it. */
  envProblem?: string;
  limits: {
    perMinute: number;
    perDay: number;
    updatedAt?: string;
    updatedBy?: string;
    /** The limits on invitations and password emails, which follow the day's limit. */
    account: AccountMailLimits;
  };
  usage: {
    lastMinute: number;
    lastDay: number;
    /** Of the last 24 hours' messages, invitations and password resets. */
    accountLastDay: number;
    /** Where administrators' invitations and password links stop: 90% of the day's limit. Password resets people ask for may use all of it. */
    adminDayLimit: number;
    /** Where other mail stops: 80% of the day's limit. */
    otherDayLimit: number;
  };
}

/** Each is the smaller of a fixed number and a share of the day's limit (ADR-0053). */
export interface AccountMailLimits {
  /** Invitations and password links one administrator may email an hour. */
  adminPerHour: number;
  /** Invitations and password links administrators other than super administrators may email to one organization's accounts a day. */
  organizationPerDay: number;
  /** Password emails, resets people ask for and administrators' links together, to one account: this many at once, */
  accountBurst: number;
  /** then one every this many minutes. */
  accountEveryMinutes: number;
  /** Password resets people ask for, on the whole platform, an hour. */
  resetsPerHour: number;
  /** Password resets people ask for, to one organization's accounts, an hour. No limit a day holds resets. */
  organizationResetsPerHour: number;
}

export interface MailServerInput {
  host: string;
  port: number;
  security: MailSecurity;
  signIn: MailSignIn;
  username: string;
  /** Write-only; empty keeps the stored one while the host, port, security and user name stay the same. */
  password: string;
  fromAddress: string;
  fromName: string;
}

export interface MailServerTestInput {
  to: string;
  /** The form as it stands; absent tests the mail server in force. */
  server?: MailServerInput;
}

export interface MailServerTest {
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

export type Shell = "powershell" | "pwsh" | "cmd" | "bash" | "sh" | "python3";
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
  /** A PowerShell 7 script that may run in Windows PowerShell 5.1 where no usable PowerShell 7 is found (ADR-0064). */
  pwshFallback: boolean;
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
  pwshFallback: boolean;
  body: string;
  timeoutSeconds: number;
}

export type ScriptPatch = Partial<Pick<ScriptInput, "name" | "description" | "shell" | "pwshFallback" | "body" | "timeoutSeconds">>;

export type RunStatus = "queued" | "sent" | "running" | "succeeded" | "failed" | "timed_out" | "canceled" | "expired" | "lost";

export interface Job {
  id: string;
  /** A library script, or a software action or hardening run with one of EasyRMM's own scripts (ADR-0028, ADR-0051). */
  kind: JobKind;
  /** The software action; null for other jobs. */
  software: SoftwareAction | null;
  /** What a hardening job does; null for other jobs. */
  hardening: HardeningJob | null;
  /** Null once the script is deleted (the job keeps its own copy), and for EasyRMM's own scripts. */
  scriptId: string | null;
  scriptName: string;
  shell: Shell;
  /** The script's fallback setting, copied into the job. */
  pwshFallback: boolean;
  sha256: string;
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
  /** Only in the response for one job. The values come from GET /jobs/{id}/arguments (ADR-0063). */
  argCount?: number;
  /** Whether the caller may read the values: they hold job.view_sensitive where one of the runs they see is. */
  canViewArguments?: boolean;
  /**
   * Only in the response for one job: whether GET /jobs/{id}/output.zip would hold something, a finished run the caller
   * sees at a site where they hold job.view_sensitive (ADR-0064).
   */
  canDownloadOutput?: boolean;
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
  cancelRequested: boolean;
  /** The program the agent started, as it reported it (ADR-0064); null when it reported none, as older agents do. */
  program: RunProgram | null;
  /**
   * Why a queued run is not delivered: "unable" when the device's agent said it cannot run it, "unreported" when the build
   * it runs has not said. Absent otherwise.
   */
  held?: "unable" | "unreported";
  /** The job is only in the response for one run. */
  job?: Job;
  /**
   * Only in the response for one run: whether the caller holds job.view_sensitive at its site. The output itself comes
   * from GET /job-runs/{id}/output, each read audited (ADR-0063).
   */
  canViewOutput?: boolean;
  /** Only in the response for one run: whether the caller may remove its output (job.view_sensitive and job.manage at its site). */
  canRemoveOutput?: boolean;
  /** Only with canViewOutput: the size of each stream, and when the output was removed. */
  stdoutBytes?: number;
  stderrBytes?: number;
  outputRemovedAt?: string | null;
  canCancel: boolean;
}

/** The program a run started (agentproto.Interpreter). cmd and the Linux shells report the path only. */
export interface RunProgram {
  /** PowerShell only. */
  edition?: "Desktop" | "Core";
  version?: string;
  arch?: "x64" | "arm64" | "x86";
  path: string;
  /** A PowerShell 7 script ran in Windows PowerShell 5.1, as it allows, since no usable PowerShell 7 was found. */
  fallback?: boolean;
}

/** What a run printed (GET /job-runs/{id}/output). */
export interface JobRunOutput {
  stdout: string;
  stderr: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
}

/** A job's argument values (GET /jobs/{id}/arguments). */
export interface JobArguments {
  args: string[];
}

export type JobKind = "script" | "software" | "hardening";

/** A hardening job (ADR-0051). Only checks so far: they report and change nothing. */
export interface HardeningJob {
  mode: "check";
  /** In the order the script runs them. */
  modules: string[];
  options: HardeningOptions;
}

export interface HardeningOptions {
  /** Ports and ranges the firewall leaves open besides those in use. */
  allowTcp?: string[];
  allowUdp?: string[];
  /** Addresses and ranges fail2ban never bans. */
  trusted?: string[];
  rootPasswordOff?: boolean;
  passwordOff?: boolean;
  epel?: boolean;
}

/** Asks for a hardening job (POST /jobs/hardening). */
export interface HardeningInput {
  deviceIds: string[];
  mode: HardeningJob["mode"];
  modules: string[];
  options: HardeningOptions;
  /** Hours to wait for an offline device; 0 is the server's default. */
  waitHours: number;
}

/** A module's state, as the hardening script reports it. */
export type HardeningState =
  | "in_place"
  | "partly"
  | "not_in_place"
  | "not_applicable"
  | "managed_elsewhere"
  | "not_supported"
  | "half_applied"
  | "failed";

/** The computer as the hardening script saw it. */
export interface HardeningPlatform {
  /** os-release's ID and VERSION_ID: "debian", "12". */
  id: string;
  versionId: string;
  family: "debian" | "rhel" | "fedora" | "other";
  /** "none", or the kind of container the script ran in ("lxc", "docker", …). */
  container: string;
  /** full: check, apply and undo; check_only: check runs, apply and undo do not; unsupported: neither apply nor undo. */
  support: "full" | "check_only" | "unsupported";
}

/** The firewall's ports: left open to TCP and UDP, published by Docker past the input hook, and services enabled but not running. */
export interface HardeningPorts {
  tcp?: string[];
  udp?: string[];
  /** "tcp/8080". */
  docker?: string[];
  /** Unit names, "minidlna.service". */
  unknown?: string[];
}

/** Failed sign-ins in a Windows computer's Security log (ADR-0054, Accounts). */
export interface HardeningExposure {
  /** Failed sign-ins from public addresses, or 10 or more for one account within 15 minutes. */
  exposed: boolean;
  /** The failed sign-ins from public addresses: the accounts tried and the addresses. */
  accounts: string[];
  addresses: string[];
  /** Accounts with 10 or more failed sign-ins within 15 minutes. */
  bursts?: string[];
  /** How far back the log was read; null, with sinceReason, where the oldest record read is dated after the check. */
  since: string | null;
  sinceReason?: string;
}

/** One module as the job that last covered it found it. */
export interface HardeningModule {
  module: string;
  state: HardeningState;
  reason?: string;
  /** What is not in place. */
  missing?: string[];
  /** What apply would change. */
  changes?: string[];
  /** The firewall's only. */
  ports?: HardeningPorts;
  /** Windows' accounts module only. */
  exposure?: HardeningExposure;
  /** Null once the job is deleted. */
  jobId: string | null;
  checkedAt: string;
}

/** What hardening jobs found on a device (GET /devices/{id}/hardening). */
export interface DeviceHardening {
  /** Platform, jobId and checkedAt are the latest job's; null until one reported. */
  platform: HardeningPlatform | null;
  jobId: string | null;
  checkedAt: string | null;
  /** Each module the device was checked for, in the order the script runs them. */
  modules: HardeningModule[];
}

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
  /** The drive's firmware revision, a fact with its state (ADR-0065); absent from agents older than it. */
  firmware?: TextFact;
}

/** A fact as the agent reports it (ADR-0065): read with its value, or why not. */
export interface TextFact {
  state: "read" | "unknown" | "unsupported" | "unavailable";
  reason?: string;
  value?: string;
}

// Disk health (ADR-0065) ---------------------------------------------------------------------------

/** What a disk shows, or a judged fact: unhealthy is sent as its level, warning or failing. */
export type DiskState = "healthy" | "warning" | "failing" | "unknown" | "unsupported" | "unavailable";
/** A fact's state: a judged one's, or reported for a fact EasyRMM reads and does not judge. */
export type FactState = DiskState | "reported";

/** A disk's latest reading, whatever it found. */
export interface DiskReading {
  /** The reading's level, or the disk as a whole when it was not read. */
  state: DiskState;
  reason: string;
  detail: string;
  /** By the agent's clock. */
  readAt: string;
  receivedAt: string;
}

/** One fact of a reading: its state, why, and its value when it was read. */
export interface DiskFact {
  name: string;
  state: FactState;
  reason?: string;
  value: number | null;
}

/** One ATA SMART attribute, judged against its threshold when the thresholds were read (else reported). */
export interface DiskAttribute {
  id: number;
  /** Bit 0: pre-fail. */
  flags: number;
  value: number;
  worst: number;
  threshold?: number;
  /** The 48-bit raw value. */
  raw: number;
  preFail: boolean;
  state: FactState;
}

/** One disk as the console shows it (GET /devices/{id}/disks). */
export interface DiskHealth {
  /** The disk's identity; unstable when it comes from its name, for want of a serial. */
  key: string;
  unstable: boolean;
  name: string;
  model: string;
  serial: string;
  /** What to show, and why; detail is a sentence for warning and failing. */
  state: DiskState;
  reason: string;
  detail: string;
  latest: DiskReading;
  /** The last reading that read the drive's verdict; null before one did. */
  judgedLevel: "healthy" | "warning" | "failing" | "unknown" | null;
  judgedAt: string | null;
  /** How many readings since judgedAt could not tell. */
  since: number;
  /** When a report first left the disk out; null while it is listed. */
  missingSince: string | null;
  protocol: "" | "nvme" | "ata";
  route: string;
  /** Facts and attributes are from the latest reading that read the disk, at factsAt. */
  factsAt: string | null;
  facts: DiskFact[];
  attributes: DiskAttribute[];
}

/** A disk's history on one UTC day: the day's worst state, highest temperature and last counts. */
export interface DiskDay {
  day: string;
  state: DiskState;
  temperature: number | null;
  wear: number | null;
  reallocatedSectors: number | null;
  mediaErrors: number | null;
  pendingSectors: number | null;
  uncorrectableSectors: number | null;
  driveErrors: number | null;
  powerOnHours: number | null;
}

/** An open alert on a disk. */
export interface DiskAlert {
  id: string;
  name: string;
  checkName: string;
  severity: AlertSeverity;
  status: AlertStatus;
  detail: string;
  openedAt: string;
}

/** A disk's panel (GET /devices/{id}/disks/{key}): the disk, its last 30 days newest first, and its open alerts (null
 * when the caller may not view alerts there). */
export interface DiskHealthDetail extends DiskHealth {
  history: DiskDay[];
  alerts: DiskAlert[] | null;
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
  /**
   * Windows PowerShell and the PowerShell 7 installs the agent found (ADR-0064), Windows PowerShell first, then the one a
   * PowerShell 7 script runs in. Absent from an agent that reports none: a Linux agent, or one too old to report them.
   */
  powerShell?: PowerShellInstall[];
  receivedAt: string;
}

/** A PowerShell the agent found (agentproto.PowerShellInstall). */
export interface PowerShellInstall {
  edition: "Desktop" | "Core";
  version: string;
  arch: "" | "x64" | "arm64" | "x86";
  path: string;
  preview?: boolean;
  /** A Microsoft Store (MSIX) install: reported, never run. */
  store?: boolean;
  /** Whether a script may run in it; otherwise reason says why not. */
  usable: boolean;
  reason?: string;
  /**
   * Not usable, and not passed over for Windows PowerShell 5.1: what it would load, its module folders or configuration,
   * fails the agent's check, or a file of it is open in another program, or it (or the folder installs are in) could not be
   * read or checked. A run moves to another install only where one passes every check; otherwise it fails, and does not
   * fall back to Windows PowerShell 5.1.
   */
  blocked?: boolean;
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

/** What a policy watches: no check-in, processor, memory or the fullest disk at a percentage, or each disk's health
 * with one of its checks (ADR-0065). */
export type AlertKind = "offline" | "cpu" | "memory" | "disk" | "disk_health";
/** A disk health policy's check: failing (no threshold), errors and pending (a count), wear (a percentage),
 * temperature (°C, or the drive's own limit without a threshold). */
export type DiskCheck = "failing" | "errors" | "pending" | "wear" | "temperature";
export type AlertSeverity = "warning" | "critical";
export type AlertStatus = "open" | "acknowledged" | "resolved";
/** subject_gone: a disk missing from the device's hardware reports for 14 days. */
export type AlertResolution = "cleared" | "manual" | "not_covered" | "policy_off" | "policy_changed" | "policy_deleted" | "subject_gone";

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
  /** The disk health check; null for the other kinds. */
  checkName: DiskCheck | null;
  /** Percent for processor, memory and disk; null for offline. For disk health the count, percentage or °C its check
   * takes: null for failing, and for a temperature check that uses each drive's own limit. */
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
  /** Disk health only. */
  checkName?: DiskCheck | null;
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
  /** The disk health check; null for the other kinds. */
  checkName: DiskCheck | null;
  threshold: number | null;
  minutes: number;
  severity: AlertSeverity;
  status: AlertStatus;
  /** For disk health: the disk's identity, its name in words ("PhysicalDrive1 · Samsung SSD 870 EVO 1TB") and what holds
   * ("Pending sectors 8, uncorrectable sectors 0"). Empty for the other kinds. */
  subject: string;
  subjectLabel: string;
  detail: string;
  /** The value that raised it and the latest: percent, or minutes without a check-in; for disk health the count,
   * percentage or °C its check watches, 1 for failing. */
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

/** The measurement a processor, memory or disk use alert watches, around its window (GET /alerts/{id}/metrics): from
 * the policy's minutes before it opened until it resolved or now, with some time either side. */
export interface AlertMetrics {
  metric: "cpu" | "memory" | "disk";
  threshold: number | null;
  from: string;
  to: string;
  bucketSeconds: number;
  /** The window starts later than the alert's: earlier measurements are no longer kept. */
  trimmed: boolean;
  samples: { at: string; value: number }[];
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

export type ReportName = "devices" | "software" | "health" | "alerts" | "patch-compliance" | "patch-installations";

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
// EasyPatch, the patching engine in this deployment (ADR-0038, ADR-0046)
// ---------------------------------------------------------------------------------------------

/** The patching engine EasyRMM calls on this server. The deployment sets it up; Settings only shows it. */
export interface EasyPatchConnection {
  /** False only when the deployment has no patching engine. */
  configured: boolean;
  url: string;
  caCert: string;
  serverVersion: string;
  publicUrl: string;
  checkedAt?: string;
  lastError?: string;
  lastErrorAt?: string;
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

/** How keeping the patching engine in step with EasyRMM goes (ADR-0040). */
export interface PatchingSync {
  /** When the last pass ended. */
  at?: string;
  /** What the last pass could not do; the next one tries again. */
  problems: string[];
  /** Deleted organizations and sites the engine has yet to archive. */
  archiving: number;
  /** EasyPatch agents being removed. */
  removing: number;
}

/** Patching stopped for a device: its EasyPatch agent removed, and none installed again. */
export interface PatchingStop {
  at: string;
  by?: string;
}

/** EasyRMM removing a device's EasyPatch agent. */
export interface AgentRemoval {
  reason: "opted_out" | "moved" | "deleted";
  state: "pending" | "uninstalling";
  requestedAt: string;
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
  /** False only when the deployment has no patching engine. */
  configured: boolean;
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
  /** Patching is stopped for the device. */
  stopped?: PatchingStop;
  /** EasyRMM is removing the device's EasyPatch agent. */
  removal?: AgentRemoval;
}

export interface PatchFleet {
  devices: PatchFleetDevice[];
  /**
   * EasyPatch endpoints of organizations the caller sees whole that no EasyRMM device is linked to; only without site,
   * group, status or name filters.
   */
  unmatched: PatchUnmatchedEndpoint[];
  truncated: boolean;
  /** EasyPatch organizations that could not be read, with why. */
  errors: string[];
}

/** An EasyPatch endpoint with no EasyRMM device; organizationId and organizationName are EasyRMM's. */
export interface PatchUnmatchedEndpoint extends PatchEndpoint {
  /** The caller may remove it (device.retire in its organization; ADR-0050). */
  canRemove: boolean;
  /** Its agent is being asked to uninstall itself. */
  removal?: AgentRemoval;
}

/** One update across the devices in a scope (Patching → Updates). */
export interface PatchFleetUpdate {
  updateGuid: string;
  title: string;
  kbNumber: string;
  category: string;
  msrcSeverity: string;
  releaseDate: string | null;
  sizeBytes: number | null;
  missingCount: number;
  failedCount: number;
  installedCount: number;
  /** Installed and waiting for a restart. */
  pendingRebootCount: number;
  excludedCount: number;
  package: { name: string; version: string; installedVersion: string; repository: string; advisories: string[] | null } | null;
  cveCount: number;
  knownExploited: boolean;
  reofferedCount: number;
  onHold: boolean;
}

/** A CVE an update fixes; kev: in CISA's Known Exploited Vulnerabilities catalog. */
export interface PatchVulnerability {
  cveId: string;
  title: string;
  severity: string;
  cvssBase: number | null;
  msrcExploited: boolean;
  kev: boolean;
  kevDateAdded: string | null;
  kevDueDate: string | null;
  kevRansomware: boolean;
  kevName: string;
}

/** An update EasyPatch does not install automatically: in one organization (EasyRMM's), or in every one. */
export interface PatchHold {
  id: string;
  updateGuid: string;
  title: string;
  kbNumber: string;
  organizationId: string | null;
  organizationName: string;
  /** Automatic: EasyPatch's rollout guard, after installs failed. */
  source: "Automatic" | "Manual" | string;
  reason: string;
  failedEndpoints: number | null;
  attemptedEndpoints: number | null;
  createdAt: string;
  createdBy: string;
  releasedAt: string | null;
  releasedBy: string;
  canRelease: boolean;
}

export interface PatchUpdateView {
  summary: PatchFleetUpdate;
  description: string;
  supportUrl: string;
  kbNumbers: string[];
  products: string[];
  msClassification: string;
  rebootLikely: boolean;
  supersededUpdateGuids: string[];
  vulnerabilities: PatchVulnerability[];
  holds: PatchHold[];
  /** May install or remove updates somewhere; each device says where. */
  canManage: boolean;
  /** May hold it: patch.configure in an organization, or everywhere. */
  canHold: boolean;
  /** The organizations it can be held in, by name. */
  holdIn: { id: string; name: string }[];
  /** May hold it in every organization (super administrators). */
  canHoldEverywhere: boolean;
}

/** A device, or an EasyPatch endpoint without one (deviceId null), that reports an update. */
export interface PatchUpdateDevice {
  endpointId: string;
  hostname: string;
  deviceId: string | null;
  deviceName: string;
  organizationName: string;
  siteName: string;
  platform: string;
  isOnline: boolean;
  state: PatchUpdateState;
  isRequired: boolean;
  isExcluded: boolean;
  failedAttempts: number;
  errorCode: string;
  errorMessage: string;
  stateChangedAt: string;
  canManage: boolean;
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
  /** The job the endpoint is working on, if any. */
  activeJob: PatchJob | null;
  /** What the agent can do: PATCH_AGENT_CAN. */
  agentCapabilities: string[] | null;
  /** Signed-in sessions, and those with the EasyPatch tray, at the latest check-in; null until the agent reports them. */
  signedInUsers: number | null;
  trayConnectedSessions: number | null;
  /** The endpoint has its own policy layer. */
  hasOwnPolicy: boolean;
  agentUpdate: PatchAgentUpdate | null;
  /** What a pending restart is for; null when none is. */
  restart: PatchRestartDetails | null;
  /** How the agent applied the policy's Windows Update settings (Windows only). */
  windowsUpdatePolicy: {
    groups: { group: string; state: string; message: string; appliedAt: string | null; conflictingValues: string[] | null }[] | null;
    mdmUpdatePoliciesPresent: boolean;
  } | null;
}

/** What EasyPatch agents report they can do. */
export const PATCH_AGENT_CAN = { notifyUser: "notify-user", uninstallUpdates: "uninstall-updates", tray: "tray", restart: "restart" } as const;

/** Whether the agent can update itself, and to what. */
export interface PatchAgentUpdate {
  supported: boolean;
  /** The "Agent updates" policy is Automatic. */
  automaticUpdates: boolean;
  /** The newer signed package an update would install; empty with a code and message saying why not. */
  availableVersion: string;
  code: string;
  message: string;
  packageFormat: string;
}

export interface PatchRestartDetails {
  updates: { updateGuid: string | null; title: string; kbNumbers: string[] | null; source: string; installedAt: string | null }[] | null;
  /** Pending Windows servicing packages that name no KB. */
  servicingPackages: string[] | null;
  /** The first 25 file operations Windows has queued. */
  fileOperations: { action: string; path: string }[] | null;
  fileOperationCount: number;
  /** The agent reports what Windows has queued (Windows agent 1.5.3 and later). */
  detailsSupported: boolean;
}

/** A recurring restart. "HH:mm" in the policy's time zone; days 0 (Sunday) to 6. */
export interface PatchRestartSchedule {
  enabled: boolean;
  days: number[] | null;
  time: string;
  /** OnlyIfPending or Always. */
  condition: string;
  /** Immediate, Countdown, PromptWithDeadline or PromptNoDeadline. */
  mode: string;
  countdownMinutes: number;
  deadlineMinutes: number;
  expiryMinutes: number;
}

/** Windows Update's own settings that EasyPatch manages; a null group is not managed. */
export interface PatchWindowsUpdate {
  automaticUpdates: { mode: string; scheduledInstallDay: number; scheduledInstallHour: number } | null;
  featureUpdates: { deferDays: number | null; targetProductVersion: string; targetReleaseVersion: string } | null;
  qualityUpdates: { deferDays: number | null; disablePause: boolean } | null;
  restartBehavior: { noAutoRestartWithSignedInUsers: boolean; activeHoursStart: number | null; activeHoursEnd: number | null } | null;
}

/** An endpoint's effective EasyPatch policy, with the layer each value comes from. */
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
  checkInIntervalSeconds: number;
  inventoryIntervalMinutes: number;
  jitterPercent: number;
  excludedKbs: string[] | null;
  acceptEulas: boolean;
  scanStaleAfterHours: number;
  maxConcurrentInstallsPerSite: number;
  trayIconEnabled: boolean;
  installNotificationsEnabled: boolean;
  agentAutoUpdateEnabled: boolean;
  knownExploitedSkipsDelay: boolean;
  /** Hours before the maintenance window that Windows agents download updates; 0 is off. */
  preDownloadHours: number;
  restartSchedule: PatchRestartSchedule | null;
  windowsUpdate: PatchWindowsUpdate | null;
  windowsUpdateValues: { group: string; path: string; name: string; value: string }[] | null;
  applicationUpdates: { enabled: boolean; approvedApps: string[] | null } | null;
  /** The layer that set each value (Global, Organization, Site, Tag or Endpoint), keyed by its name; EasyPatch writes the keys in PascalCase. */
  sources: Record<string, string> | null;
  /** The tag whose policy set a value. */
  sourceTags: Record<string, string> | null;
}

/** The levels of an EasyPatch policy. */
export type PolicyLevel = "default" | "organization" | "site" | "device" | "tag";

type WindowsUpdateGroups = { [K in keyof PatchWindowsUpdate]: NonNullable<PatchWindowsUpdate[K]> };

/** One group of Windows Update settings at one level: not managed leaves Windows alone, even when a level above manages it. */
export interface PatchGroupSetting<T> {
  managed: boolean;
  value: T | null;
}

/** One level's own policy: null inherits. The window, the restart schedule, application updates and each Windows Update group are set as a whole. */
export interface PatchPolicyLayer {
  checkInIntervalSeconds: number | null;
  scanIntervalMinutes: number | null;
  inventoryIntervalMinutes: number | null;
  jitterPercent: number | null;
  allowedCategories: string[] | null;
  includeOptional: boolean | null;
  /** Added to the levels' above: a level cannot lift what it inherits. */
  excludedKbs: string[] | null;
  acceptEulas: boolean | null;
  autoInstallEnabled: boolean | null;
  /** Set means this level has a window; an empty list is no window. */
  maintenanceDays: number[] | null;
  maintenanceStart: string | null;
  maintenanceDurationMinutes: number | null;
  preDownloadHours: number | null;
  installDelayDays: number | null;
  securityInstallDelayDays: number | null;
  knownExploitedSkipsDelay: boolean | null;
  scanStaleAfterHours: number | null;
  maxConcurrentInstallsPerSite: number | null;
  trayIconEnabled: boolean | null;
  installNotificationsEnabled: boolean | null;
  agentAutoUpdateEnabled: boolean | null;
  restartSchedule: PatchRestartSchedule | null;
  windowsUpdate: { [K in keyof WindowsUpdateGroups]: PatchGroupSetting<WindowsUpdateGroups[K]> | null } | null;
  applicationUpdates: { enabled: boolean; approvedApps: string[] | null } | null;
}

/** A level's policy for the editor: its own values and what it inherits, already resolved by the server. */
export interface PatchPolicyView {
  level: PolicyLevel;
  name: string;
  own: PatchPolicyLayer;
  hasOwn: boolean;
  updatedAt?: string;
  /** Every value set. */
  inherited: PatchPolicyLayer;
  /** The level each inherited value comes from ("Default policy", "Organization", "Site", "Tag Ring 1", "EasyPatch's defaults"), keyed by its field. */
  inheritedFrom: Record<string, string>;
  /** The time zone of the window and the restart schedule; empty when each device's own applies. */
  timeZone?: string;
  /** False for a device that is not a Windows computer. */
  windows: boolean;
  canEdit: boolean;
  organizationId?: string;
}

export type TagColor = "gray" | "blue" | "green" | "amber" | "red" | "purple" | "teal" | "pink";

/** An EasyPatch tag. Counts are 0 for someone who does not see every organization. */
export interface PatchTag {
  id: string;
  name: string;
  color: TagColor;
  description: string | null;
  /** The highest priority's policy applies last and wins. */
  priority: number;
  endpointCount: number;
  siteCount: number;
  organizationCount: number;
  hasPolicy: boolean;
  createdAt: string;
}

/** One day of compliance, added up over the organizations a report covers. */
export interface PatchTrendPoint {
  /** 2006-01-02 */
  date: string;
  totalEndpoints: number;
  compliant: number;
  missingUpdates: number;
  failedUpdates: number;
  rebootRequired: number;
  scanStale: number;
  neverScanned: number;
  offline: number;
  missingRequiredUpdates: number;
  compliancePercent: number;
}

export interface PatchTrend {
  points: PatchTrendPoint[];
  /** The organizations the caller sees whole, which the trend adds up. */
  organizations: number;
}

export type PatchDeliveryStatus = "Pending" | "Sending" | "Sent" | "Failed";

export interface PatchMonthlyReport {
  id: string;
  organizationId: string;
  organizationName: string;
  /** The month's first day and last (today for a report of the month so far), as 2006-01-02. */
  periodStart: string;
  periodEnd: string;
  monthToDate: boolean;
  scheduled: boolean;
  generatedAt: string;
  generatedBy?: string;
  fileName: string;
  sizeBytes: number;
  deliveryStatus?: PatchDeliveryStatus | "";
  recipients: string[];
  sentAt?: string | null;
  lastError?: string;
  canManage: boolean;
}

export interface PatchMonthlyReportList {
  items: PatchMonthlyReport[];
  /** There are older reports than the list holds. */
  capped: boolean;
  /** The organizations the caller may make reports of. */
  canGenerate: string[];
}

export interface PatchReportSchedule {
  organizationId: string;
  organizationName: string;
  enabled: boolean;
  recipients: string[];
  /** 1 to 28: the day the month before's report is made and emailed. */
  dayOfMonth: number;
  includeEndpointList: boolean;
  /** In the organization's time zone, as 2006-01-02. */
  nextReportDate?: string | null;
  nextReportPeriod?: string | null;
  timeZone: string;
  canEdit: boolean;
}

/** EasyPatch's server settings as Settings → Patching → Server shows them. */
export interface PatchServerSettings {
  globalMaxConcurrentInstalls: number;
  jobDefaultExpiryHours: number;
  runningJobTimeoutHours: number;
  waitingForRebootExpiryDays: number;
  deliveryLeaseMinutes: number;
  maxDeliveryAttempts: number;
  offlineThresholdMinutes: number;
  credentialLifetimeDays: number;
  credentialRotateBeforeDays: number;
  retentionEventsDays: number;
  retentionAuditDays: number;
  retentionJobsDays: number;
  retentionScansDays: number;
  retentionHistoryDays: number;
  retentionReportsMonths: number;
  vulnerabilityFeedsEnabled: boolean;
  /** The "Prepared by" line of monthly reports; null leaves it out. */
  reportBrandName: string | null;
  rolloutGuardEnabled: boolean;
  rolloutGuardMinFailedEndpoints: number;
  rolloutGuardFailurePercent: number;
  rolloutGuardWindowDays: number;
}

/** A vulnerability feed EasyPatch's worker downloads: kev, msrc or debian. */
export interface PatchVulnerabilityFeed {
  name: string;
  lastAttemptAt?: string | null;
  lastSuccessAt?: string | null;
  lastError?: string;
  version?: string;
  itemCount: number;
}

export interface PatchSettingsView {
  settings: PatchServerSettings;
  feeds: PatchVulnerabilityFeed[];
  version: string;
  /** Only super administrators change them. */
  canEdit: boolean;
}

/** An operating system build's end of servicing, matched by product, edition group and build. Dates are 2006-01-02. */
export interface PatchLifecycleInput {
  product: string;
  editionGroup: string;
  buildNumber: number;
  versionLabel: string;
  endOfServicing: string;
  esuEndDate: string | null;
  notes: string | null;
}

export interface PatchLifecycleEntry extends PatchLifecycleInput {
  id: string;
}

export interface PatchLifecycleList {
  items: PatchLifecycleEntry[];
  /** Only super administrators change it. */
  canEdit: boolean;
}

/** An EasyPatch agent package, with where to download it. */
export interface PatchAgentPackage {
  fileName: string;
  version: string;
  architecture: string;
  sizeBytes: number;
  sha256: string;
  isLatest: boolean;
  /** msi, deb, rpm or pkg. */
  format: string;
  releaseKeyId?: string;
  signatureProblem?: string;
  url: string;
}

/** An entry of EasyPatch's own audit log. */
export interface PatchAuditEntry {
  id: number;
  createdAt: string;
  /** An EasyRMM user's name (via easyrmm), an EasyPatch user or API token (easypatch), or EasyPatch itself (system). */
  actor: string;
  via: "easyrmm" | "easypatch" | "system";
  action: string;
  targetType?: string;
  targetId?: string;
  organizationId?: string;
  organizationName?: string;
  deviceId?: string;
  deviceName?: string;
  /** JSON, as EasyPatch recorded it. */
  details?: string;
  ipAddress?: string;
}

export interface PatchAuditPage {
  items: PatchAuditEntry[];
  page: number;
  pageSize: number;
  totalCount: number;
  /** Includes the entries of no organization, for those who audit everywhere. */
  everything: boolean;
}

// EasyPatch's alerts, alert rules and notification channels.

export type PatchAlertSeverity = "Critical" | "Warning" | "Info";
export type PatchAlertStatus = "Open" | "Acknowledged" | "Resolved";
export type PatchAlertRuleKind =
  | "EndpointOffline"
  | "InstallFailed"
  | "SecurityUpdateMissing"
  | "ScanStale"
  | "RestartPending"
  | "OsUnsupported"
  | "KnownExploitedMissing"
  | "UpdateHeld";

export interface PatchAlert {
  id: string;
  ruleId: string | null;
  ruleName: string | null;
  ruleType: PatchAlertRuleKind;
  severity: PatchAlertSeverity;
  status: PatchAlertStatus;
  title: string;
  details: string | null;
  /** EasyRMM's organization. */
  organizationId: string;
  organizationName: string;
  /** The EasyRMM device, when the endpoint is one; none for an organization's alert. */
  deviceId?: string;
  deviceName?: string;
  /** EasyPatch's name for the endpoint, which an endpoint with no EasyRMM device has only. */
  hostname: string | null;
  openedAt: string;
  lastSeenAt: string;
  resolvedAt: string | null;
  acknowledgedAt: string | null;
  acknowledgedBy: string | null;
  canAcknowledge: boolean;
}

export interface PatchAlertList {
  items: PatchAlert[];
  /** More match than were listed. */
  capped: boolean;
}

/** Unresolved alerts: open leaves out the acknowledged; the severities count both. */
export interface PatchAlertCounts {
  open: number;
  acknowledged: number;
  critical: number;
  warning: number;
  info: number;
  capped: boolean;
}

export interface PatchAlertRuleType {
  type: PatchAlertRuleKind;
  thresholdUnit: "hours" | "days" | null;
  thresholdMin: number | null;
  thresholdMax: number | null;
  thresholdDefault: number | null;
  /** Looks at devices one by one, so it can be limited to a tag. */
  supportsTag: boolean;
}

export interface PatchAlertRuleInput {
  name: string;
  type: PatchAlertRuleKind;
  enabled: boolean;
  severity: PatchAlertSeverity;
  threshold: number | null;
  /** EasyRMM's organization; none covers every one. */
  organizationId: string | null;
  tagId: string | null;
  channelIds: string[];
  notifyOnResolve: boolean;
  /** 0 never reminds. */
  renotifyHours: number;
}

export interface PatchAlertRule extends PatchAlertRuleInput {
  id: string;
  thresholdUnit: string | null;
  organizationName?: string;
  /** Covers an EasyPatch organization EasyRMM does not link. */
  unlinkedOrganization?: boolean;
  tagName?: string;
  unresolvedAlerts: number;
  updatedAt: string;
}

export interface PatchChannelRef {
  id: string;
  name: string;
  type: "Email" | "Webhook";
  enabled: boolean;
}

export interface PatchAlertRuleList {
  items: PatchAlertRule[];
  types: PatchAlertRuleType[];
  channels: PatchChannelRef[];
}

export type PatchWebhookFormat = "Generic" | "Slack" | "Teams";
/** A message to a notification channel; the worker retries one that failed until its attempts run out. */
export type PatchNotificationStatus = "Pending" | "Sent" | "Failed";

export interface PatchChannel {
  id: string;
  name: string;
  type: "Email" | "Webhook";
  enabled: boolean;
  emailRecipients: string[];
  webhookFormat: PatchWebhookFormat | null;
  /** EasyPatch never gives a webhook's address back, only its host. */
  webhookHost: string | null;
  hasSigningSecret: boolean;
  createdAt: string;
  updatedAt: string;
  lastDelivery: { status: PatchNotificationStatus; createdAt: string; lastError: string | null } | null;
}

export interface PatchChannelInput {
  name: string;
  type: "Email" | "Webhook";
  enabled: boolean;
  emailRecipients: string[];
  webhookFormat: PatchWebhookFormat | null;
  /** None on a change keeps the stored address. */
  webhookUrl: string | null;
}

export interface PatchChannelSaved {
  channel: PatchChannel;
  /** A generic webhook's signing key, shown this once. */
  signingSecret: string | null;
}

export interface PatchDelivery {
  id: string;
  channelId: string;
  channelName: string;
  kind: "AlertsOpened" | "AlertsResolved" | "AlertsReminder" | "Test";
  subject: string;
  status: PatchNotificationStatus;
  attempts: number;
  lastError: string | null;
  createdAt: string;
  nextAttemptAt: string;
  sentAt: string | null;
}

export interface PatchDeliveryPage {
  items: PatchDelivery[];
  page: number;
  pageSize: number;
  totalCount: number;
}

export interface PatchNotifications {
  channels: PatchChannel[];
  /**
   * The mail server email channels send through: EasyRMM's, given to EasyPatch at start and after every change. problem says why
   * EasyRMM could not give it, after several tries in a row, which removed the engine's.
   */
  mail: { host: string; port: number; security: string; fromAddress: string; fromName: string; problem?: string };
  allowPrivateNetworkWebhooks: boolean;
}

export interface PatchTagList {
  items: PatchTag[];
  canManage: boolean;
}

export interface PatchTagRef {
  id: string;
  name: string;
  color: TagColor;
  /** "Site" or "Organization" for a device's tag it has through them. */
  inheritedFrom?: string;
}

export interface PatchAssignedTags {
  tags: PatchTagRef[];
  canAssign: boolean;
}

/** What installing on a device would do, from its last scan; the agent scans again before installing. */
export interface PatchInstallPreview {
  /** AllEligible or Selected. */
  mode: string;
  items: { updateGuid: string; title: string; kbNumber: string; category: string; sizeBytes: number | null; rebootBehavior: number | null; state: string }[];
  /** Updates left out, with EasyPatch's reason code. */
  skipped: { updateGuid: string; title: string; kbNumber: string; category: string; reason: string }[];
  totalSizeBytes: number;
  rebootLikelyCount: number;
  warnings: string[];
  filter: { categories: string[] | null; includeOptional: boolean } | null;
  lastScanAt: string | null;
}

/** A message EasyPatch can show to the users of a Windows computer: there is no free text. */
export interface PatchMessagePreset {
  preset: string;
  title: string;
  /** "{time}" stands for the restart time when needsRestartTime. */
  body: string;
  needsRestartTime: boolean;
}

export interface DevicePatching {
  deviceId: string;
  link: PatchLink;
  reason?: string;
  checkedAt?: string;
  canManage: boolean;
  endpoint?: PatchEndpointDetail;
  policy?: PatchPolicy;
  /** The EasyPatch agent's install, when one was asked for. */
  install?: AgentInstall;
  /** Patching is stopped for the device. */
  stopped?: PatchingStop;
  /** EasyRMM is removing the device's EasyPatch agent. */
  removal?: AgentRemoval;
  /** Why EasyPatch could not be read just now. */
  error?: string;
}

export type PatchUpdateState =
  "Missing" | "Failed" | "PendingVerification" | "PendingReboot" | "Installed" | "Superseded" | "NotApplicable" | "Excluded" | "Reoffered";

export interface PatchUpdate {
  updateGuid: string;
  title: string;
  kbNumber: string;
  kbNumbers: string[] | null;
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
  /** CISA's date for fixing an exploited vulnerability (YYYY-MM-DD). */
  kevDueDate: string;
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

/** The newest jobs that match, at most 200; `capped` when older ones were left out. */
export interface PatchJobList {
  items: PatchJobView[];
  capped: boolean;
}

export interface PatchJobDetail {
  summary: PatchJob;
  installMode: string;
  notBefore: string | null;
  deliveredAt: string | null;
  acknowledgedAt: string | null;
  lastProgressAt: string | null;
  /** How many times the job was handed to the agent. */
  deliveryCount: number;
  /** The job this one runs again. */
  retryOfJobId: string | null;
  cancelRequestedAt: string | null;
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

/** Where a link from EasyPatch opens the console; `notice` says why it is not the page the link named. */
export interface EasyPatchLanding {
  path: string;
  notice?: string;
}

/** What a restart would do to one device. */
export interface RestartCheck {
  deviceId: string;
  deviceName: string;
  /** It would restart; otherwise `reason` says why not. */
  restart: boolean;
  reason?: string;
  /** A server: it restarts only when confirmed by name. */
  server: boolean;
  online: boolean;
}

export interface RestartPlan {
  devices: RestartCheck[];
}

/** How a restart treats the people signed in. */
export type RestartMode = "Countdown" | "PromptWithDeadline" | "PromptNoDeadline" | "Immediate";

export interface RestartInput {
  deviceIds: string[];
  mode?: RestartMode;
  /** OnlyIfPending (the default): only if a restart is still pending when the job runs; Always: whatever the device reports. */
  condition?: "OnlyIfPending" | "Always";
  /** Countdown: 1 to 60 minutes. */
  countdownMinutes?: number;
  /** PromptWithDeadline: 15 minutes to 7 days. */
  deadlineMinutes?: number;
  /** How long a restart waits for an offline device: 15 minutes to 24 hours (EasyPatch's default is two hours). */
  expiresAfterMinutes?: number;
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
  /** Set up by the deployment (Authentik in this deployment, ADR-0044): shown, but not changed or removed here. */
  managed: boolean;
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
