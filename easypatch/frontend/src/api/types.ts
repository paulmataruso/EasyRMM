// TypeScript mirror of backend/API/Contracts/AdminDtos.cs and the enums it references.
// The admin API always writes every field; absent values are explicit nulls.

export type Guid = string;
/** ISO-8601 timestamp (UTC). */
export type Instant = string;
/** ISO date (yyyy-MM-dd). */
export type DateOnly = string;

// ---------------------------------------------------------------------------------------------
// Enums (C# member names serialized as strings)
// ---------------------------------------------------------------------------------------------

export const USER_ROLES = ['SuperAdmin', 'Admin', 'ReadOnly'] as const;
export type UserRole = (typeof USER_ROLES)[number];

export const ENDPOINT_STATUSES = ['Active', 'Revoked', 'Decommissioned'] as const;
export type EndpointStatus = (typeof ENDPOINT_STATUSES)[number];

export const ENDPOINT_UPDATE_STATES = [
  'Missing',
  'Failed',
  'PendingVerification',
  'PendingReboot',
  'Installed',
  'Superseded',
  'NotApplicable',
  'Excluded',
  'Reoffered',
] as const;
export type EndpointUpdateState = (typeof ENDPOINT_UPDATE_STATES)[number];

export const COMPLIANCE_STATUSES = [
  'NeverScanned',
  'ScanStale',
  'FailedUpdates',
  'MissingUpdates',
  'RebootRequired',
  'Compliant',
] as const;
export type ComplianceStatus = (typeof COMPLIANCE_STATUSES)[number];

export const OS_SUPPORT_STATUSES = ['Unknown', 'Supported', 'ExtendedSecurityUpdates', 'Unsupported'] as const;
export type OsSupportStatus = (typeof OS_SUPPORT_STATUSES)[number];

export const ESU_OVERRIDES = ['Auto', 'Enrolled', 'NotEnrolled'] as const;
export type EsuOverride = (typeof ESU_OVERRIDES)[number];

export const POLICY_SCOPES = ['Global', 'Organization', 'Site', 'Endpoint', 'Tag'] as const;
export type PolicyScope = (typeof POLICY_SCOPES)[number];

export const ENROLLMENT_REQUEST_STATUSES = ['Pending', 'Approved', 'Rejected', 'Expired'] as const;
export type EnrollmentRequestStatus = (typeof ENROLLMENT_REQUEST_STATUSES)[number];

export const EVENT_SEVERITIES = ['Info', 'Warning', 'Error'] as const;
export type EventSeverity = (typeof EVENT_SEVERITIES)[number];

export const UPDATE_CATEGORIES = [
  'Security',
  'Critical',
  'Cumulative',
  'Definition',
  'ServicingStack',
  'DotNet',
  'Feature',
  'Driver',
  'Other',
  'Application',
] as const;
export type UpdateCategory = (typeof UPDATE_CATEGORIES)[number];

/** Categories a policy can allow. Application (winget) updates are approved per application instead (see ApplicationUpdateSettings). */
export const POLICY_CATEGORIES: readonly UpdateCategory[] = UPDATE_CATEGORIES.filter((c) => c !== 'Application');

/** Categories installed by default (everything except Feature and Driver). */
export const DEFAULT_INSTALL_CATEGORIES: readonly UpdateCategory[] = [
  'Security',
  'Critical',
  'Cumulative',
  'Definition',
  'ServicingStack',
  'DotNet',
  'Other',
];

export const JOB_TYPES = ['UpdateScan', 'InstallUpdates', 'InventoryRefresh', 'Restart', 'NotifyUser', 'AgentUpdate', 'UninstallAgent', 'UninstallUpdate', 'DownloadUpdates'] as const;
export type JobType = (typeof JOB_TYPES)[number];

export const JOB_STATUSES = [
  'Queued',
  'Delivered',
  'Acknowledged',
  'Running',
  'Completed',
  'Failed',
  'Cancelled',
  'Expired',
  'WaitingForReboot',
] as const;
export type JobStatus = (typeof JOB_STATUSES)[number];

export const ACTIVE_JOB_STATUSES: readonly JobStatus[] = ['Queued', 'Delivered', 'Acknowledged', 'Running'];

export const JOB_TRIGGERS = ['Manual', 'Scheduled', 'System'] as const;
export type JobTrigger = (typeof JOB_TRIGGERS)[number];

// Restarts, messages and Windows Update policy (shared/EasyPatch.Contracts/Agent/UserExperience.cs, Policy/WindowsUpdatePolicy.cs)

export const RESTART_MODES = ['PromptWithDeadline', 'Countdown', 'PromptNoDeadline', 'Immediate'] as const;
export type RestartMode = (typeof RESTART_MODES)[number];

export const RESTART_CONDITIONS = ['Always', 'OnlyIfPending'] as const;
export type RestartCondition = (typeof RESTART_CONDITIONS)[number];

export const USER_MESSAGE_PRESETS = ['UpdatesInstalling', 'UpdatesInstalled', 'RestartRequired', 'SaveYourWork', 'MaintenanceTonight', 'RestartScheduled'] as const;
export type UserMessagePreset = (typeof USER_MESSAGE_PRESETS)[number];

/** Agent features; the server only sends restart and message jobs to agents that declare them. */
export const AGENT_CAPABILITIES = {
  restart: 'restart',
  notifyUser: 'notify-user',
  windowsUpdatePolicy: 'windows-update-policy',
  tray: 'tray',
  selfUpdate: 'self-update',
  applicationUpdates: 'app-updates',
  uninstall: 'uninstall',
  uninstallUpdates: 'uninstall-updates',
  downloadUpdates: 'download-updates',
} as const;

export const WINDOWS_UPDATE_POLICY_GROUPS = ['AutomaticUpdates', 'FeatureUpdates', 'QualityUpdates', 'RestartBehavior'] as const;
export type WindowsUpdatePolicyGroup = (typeof WINDOWS_UPDATE_POLICY_GROUPS)[number];

export const AUTO_UPDATE_MODES = ['Disabled', 'NotifyDownload', 'AutoDownloadNotifyInstall', 'AutoDownloadScheduleInstall'] as const;
export type AutoUpdateMode = (typeof AUTO_UPDATE_MODES)[number];

export type WindowsUpdatePolicyState = 'NotManaged' | 'Applied' | 'Conflict' | 'Error';

export interface RestartScheduleDto {
  /** False at a lower level switches off a schedule inherited from above. */
  enabled: boolean;
  /** 0 = Sunday … 6 = Saturday. */
  days: number[];
  /** "HH:mm" in the site (or organization) time zone. */
  time: string;
  condition: RestartCondition;
  mode: RestartMode;
  countdownMinutes: number;
  deadlineMinutes: number;
  /** If the endpoint is offline at the scheduled time, the restart is abandoned after this long. */
  expiryMinutes: number;
}

export interface AutomaticUpdatesSettings {
  mode: AutoUpdateMode;
  /** 0 every day, 1 Sunday … 7 Saturday. */
  scheduledInstallDay: number;
  scheduledInstallHour: number;
}

export interface FeatureUpdateSettings {
  deferDays: number | null;
  targetProductVersion: string | null;
  targetReleaseVersion: string | null;
}

export interface QualityUpdateSettings {
  deferDays: number | null;
  disablePause: boolean;
}

export interface RestartBehaviorSettings {
  noAutoRestartWithSignedInUsers: boolean;
  activeHoursStart: number | null;
  activeHoursEnd: number | null;
}

export interface WindowsUpdateGroupSettings {
  AutomaticUpdates: AutomaticUpdatesSettings;
  FeatureUpdates: FeatureUpdateSettings;
  QualityUpdates: QualityUpdateSettings;
  RestartBehavior: RestartBehaviorSettings;
}

/** One group at one policy level. `managed: false` explicitly leaves Windows alone even if a higher level manages the group. */
export interface PolicyGroupSetting<T> {
  managed: boolean;
  value: T | null;
}

/** Windows Update settings at one policy level; a null group inherits. */
export interface PolicyWindowsUpdate {
  automaticUpdates: PolicyGroupSetting<AutomaticUpdatesSettings> | null;
  featureUpdates: PolicyGroupSetting<FeatureUpdateSettings> | null;
  qualityUpdates: PolicyGroupSetting<QualityUpdateSettings> | null;
  restartBehavior: PolicyGroupSetting<RestartBehaviorSettings> | null;
}

/** Effective settings: a null group is not managed. */
export interface WindowsUpdatePolicySettings {
  automaticUpdates: AutomaticUpdatesSettings | null;
  featureUpdates: FeatureUpdateSettings | null;
  qualityUpdates: QualityUpdateSettings | null;
  restartBehavior: RestartBehaviorSettings | null;
}

export interface PolicyRegistryValueDto {
  group: WindowsUpdatePolicyGroup;
  path: string;
  name: string;
  /** "(not set)" when EasyPatch deletes the value. */
  value: string;
}

export interface WindowsUpdatePolicyGroupStatus {
  group: WindowsUpdatePolicyGroup;
  state: WindowsUpdatePolicyState;
  message: string | null;
  appliedAt: Instant | null;
  conflictingValues: string[];
}

export interface WindowsUpdatePolicyReport {
  groups: WindowsUpdatePolicyGroupStatus[];
  mdmUpdatePoliciesPresent: boolean;
}

export interface RestartRequest {
  mode: RestartMode;
  condition: RestartCondition;
  countdownMinutes: number | null;
  deadlineMinutes: number | null;
  /** Null restarts now; otherwise the agent receives the job at this time. */
  scheduledAt: Instant | null;
  expiresAfterMinutes: number | null;
  force: boolean;
}

export interface NotifyRequest {
  preset: UserMessagePreset;
  restartAt: Instant | null;
}

export interface UserMessagePresetDto {
  preset: UserMessagePreset;
  title: string;
  /** For RestartScheduled the body contains "{time}". */
  body: string;
  needsRestartTime: boolean;
}

export const JOB_ITEM_STATUSES = [
  'Pending',
  'Downloading',
  'Downloaded',
  'Installing',
  'Succeeded',
  'Failed',
  'Skipped',
  'Cancelled',
] as const;
export type JobItemStatus = (typeof JOB_ITEM_STATUSES)[number];

export const INSTALL_MODES = ['AllEligible', 'Selected'] as const;
export type InstallMode = (typeof INSTALL_MODES)[number];

// ---------------------------------------------------------------------------------------------
// Common
// ---------------------------------------------------------------------------------------------

export interface PagedResult<T> {
  items: T[];
  page: number;
  pageSize: number;
  totalCount: number;
}

// ---------------------------------------------------------------------------------------------
// Authentication and account
// ---------------------------------------------------------------------------------------------

/** Users sign in with their email address (case does not matter); the username is only the account's display name. */
export interface LoginRequest {
  email: string;
  password: string;
}

export interface LoginResponse {
  mfaRequired: boolean;
  mfaSetupRequired: boolean;
  user: CurrentUserDto;
}

export interface MfaCodeRequest {
  code: string;
}

export interface CurrentUserDto {
  id: Guid;
  username: string;
  email: string;
  role: UserRole;
  /** A second factor is set up: an authenticator app or a security key / passkey. */
  mfaEnabled: boolean;
  mfaCompleted: boolean;
  mfaSetupRequired: boolean;
  mustChangePassword: boolean;
  organizationIds: Guid[];
  lastLoginAt: Instant | null;
  /** An authenticator app (TOTP) is set up. */
  totpEnabled: boolean;
  /** Security keys and passkeys registered to the account. */
  securityKeyCount: number;
  /** Of those, the ones that sign in without a password (discoverable). */
  passkeyCount: number;
  /** Offer to set up a passkey now (none yet, passkeys work on this server, no "Not now" in the last 30 days). */
  passkeyPrompt: boolean;
  /** False for an account created by single sign-on that has no password. */
  hasPassword: boolean;
}

/** Whether passkeys and security keys work with this server (HTTPS and a DNS name are required). */
export interface WebAuthnStatusDto {
  available: boolean;
  rpId: string | null;
  /** ip_address, not_https or invalid_public_url when unavailable. */
  reason: string | null;
  message: string | null;
}

export interface WebAuthnCredentialDto {
  id: Guid;
  name: string;
  /** Signs in without a password. Otherwise a security key used as the second factor. */
  isPasskey: boolean;
  /** Synced to other devices by a password manager or the platform. */
  isSynced: boolean;
  transports: string[];
  createdAt: Instant;
  lastUsedAt: Instant | null;
}

export interface WebAuthnRegisterResponse {
  credential: WebAuthnCredentialDto;
  /** Shown once, when this is the account's first second factor. */
  recoveryCodes: string[] | null;
}

export interface MfaSetupResponse {
  secret: string;
  otpAuthUri: string;
  qrCodeDataUri: string;
}

export interface RecoveryCodesResponse {
  recoveryCodes: string[];
}

export interface MfaDisableRequest {
  password: string;
  code: string;
}

export interface PasswordConfirmRequest {
  password: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
}

export interface ResetPasswordRequest {
  token: string;
  newPassword: string;
}

export interface SessionDto {
  id: Guid;
  createdAt: Instant;
  lastSeenAt: Instant;
  expiresAt: Instant;
  ipAddress: string | null;
  userAgent: string | null;
  current: boolean;
}

// ---------------------------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------------------------

export interface UserDto {
  id: Guid;
  username: string;
  email: string;
  role: UserRole;
  isActive: boolean;
  /** An authenticator app or at least one security key / passkey. */
  mfaEnabled: boolean;
  createdAt: Instant;
  lastLoginAt: Instant | null;
  lockoutUntil: Instant | null;
  organizationIds: Guid[];
  totpEnabled: boolean;
  securityKeyCount: number;
  /** Accounts at single sign-on providers linked to this user. */
  externalLoginCount: number;
}

export interface CreateUserRequest {
  username: string;
  email: string;
  role: UserRole;
  password: string | null;
  organizationIds: Guid[] | null;
}

export interface ResetLinkResponse {
  url: string;
  expiresAt: Instant;
}

export interface CreateUserResponse {
  user: UserDto;
  resetLink: ResetLinkResponse | null;
}

// API tokens (scripts and integrations)

export const API_TOKEN_ROLES = ['ReadOnly', 'Admin'] as const satisfies readonly UserRole[];
export type ApiTokenRole = (typeof API_TOKEN_ROLES)[number];

export interface ApiTokenDto {
  id: Guid;
  name: string;
  /** The first characters of the secret, to recognize the token. */
  prefix: string;
  role: UserRole;
  allOrganizations: boolean;
  organizationIds: Guid[];
  createdAt: Instant;
  createdBy: string | null;
  expiresAt: Instant;
  lastUsedAt: Instant | null;
  lastUsedIp: string | null;
  revokedAt: Instant | null;
  revokedBy: string | null;
  status: 'Active' | 'Expired' | 'Revoked';
}

export interface CreateApiTokenRequest {
  name: string;
  role: ApiTokenRole;
  /** Empty for every organization. */
  organizationIds: Guid[];
  expiresInDays: number;
}

export interface CreateApiTokenResponse {
  token: ApiTokenDto;
  /** Shown once; the server keeps only a hash. */
  secret: string;
}

export interface UpdateUserRequest {
  email: string | null;
  role: UserRole | null;
  isActive: boolean | null;
}

export interface OrganizationAccessRequest {
  organizationIds: Guid[];
}

// ---------------------------------------------------------------------------------------------
// Organizations, sites, policies
// ---------------------------------------------------------------------------------------------

export interface OrganizationSummaryDto {
  id: Guid;
  name: string;
  description: string | null;
  timeZone: string;
  isActive: boolean;
  siteCount: number;
  endpointCount: number;
  onlineCount: number;
  offlineCount: number;
  compliantCount: number;
  nonCompliantCount: number;
  missingRequiredUpdates: number;
  failedCount: number;
  rebootRequiredCount: number;
  compliancePercent: number;
  lastActivityAt: Instant | null;
  createdAt: Instant;
}

export interface SiteDto {
  id: Guid;
  organizationId: Guid;
  organizationName: string;
  name: string;
  description: string | null;
  address: string | null;
  timeZone: string;
  isActive: boolean;
  endpointCount: number;
  /** Active endpoints of the site whose operating system reports a pending restart. */
  rebootPendingCount: number;
  createdAt: Instant;
  archivedAt: Instant | null;
  /** The site's own tags; every endpoint of the site has them. */
  tags?: TagRefDto[] | null;
}

export interface OrganizationDto {
  id: Guid;
  name: string;
  description: string | null;
  contactName: string | null;
  contactEmail: string | null;
  notes: string | null;
  timeZone: string;
  isActive: boolean;
  createdAt: Instant;
  updatedAt: Instant;
  archivedAt: Instant | null;
  sites: SiteDto[];
  summary: OrganizationSummaryDto;
  /** The organization's own tags; every endpoint of the organization has them. */
  tags?: TagRefDto[] | null;
}

export interface OrganizationRequest {
  name: string;
  description: string | null;
  contactName: string | null;
  contactEmail: string | null;
  notes: string | null;
  timeZone: string | null;
}

export interface SiteRequest {
  name: string;
  description: string | null;
  address: string | null;
  timeZone: string | null;
}

export interface PolicyValues {
  checkInIntervalSeconds: number | null;
  scanIntervalMinutes: number | null;
  inventoryIntervalMinutes: number | null;
  jitterPercent: number | null;
  allowedCategories: string[] | null;
  includeOptional: boolean | null;
  acceptEulas: boolean | null;
  autoInstallEnabled: boolean | null;
  /** 0 = Sunday … 6 = Saturday. */
  maintenanceDays: number[] | null;
  /** "HH:mm" in the site (or organization) time zone. */
  maintenanceStart: string | null;
  maintenanceDurationMinutes: number | null;
  scanStaleAfterHours: number | null;
  maxConcurrentInstallsPerSite: number | null;
  trayIconEnabled: boolean | null;
  installNotificationsEnabled: boolean | null;
  /** Replaces the inherited schedule as a whole; null inherits. */
  restartSchedule: RestartScheduleDto | null;
  windowsUpdate: PolicyWindowsUpdate | null;
  /** "Agent updates": true = Automatic, false = Manual, null inherits (the global default is Automatic). */
  agentAutoUpdateEnabled: boolean | null;
  /** Rollout delay (days after an update is first seen) for non-security updates; 0-365, null inherits. */
  installDelayDays: number | null;
  /** Rollout delay for security updates (including monthly cumulative updates); 0-90, null inherits. */
  securityInstallDelayDays: number | null;
  /** Updates fixing a CISA known-exploited vulnerability skip the rollout delay; null inherits (the global default is true). */
  knownExploitedSkipsDelay: boolean | null;
  /** Third-party application updates through winget; replaces the inherited setting as a whole, null inherits (the global default is off). */
  applicationUpdates: ApplicationUpdateSettings | null;
  /** With automatic installation: download updates this many hours before the maintenance window opens (Windows agents 1.8.0+);
   * 0 = off, 0-24, null inherits (the global default is off). */
  preDownloadHours: number | null;
}

/** winget application updates: only the approved package IDs are checked and upgraded, and only where already installed. */
export interface ApplicationUpdateSettings {
  enabled: boolean;
  /** winget package IDs such as Mozilla.Firefox (at most 100). */
  approvedApps: string[];
}

export interface PolicyDto extends PolicyValues {
  id: Guid | null;
  scope: PolicyScope;
  organizationId: Guid | null;
  siteId: Guid | null;
  endpointId: Guid | null;
  excludedKbs: string[];
  updatedAt: Instant | null;
  tagId?: Guid | null;
}

export interface PolicyRequest extends PolicyValues {
  excludedKbs: string[] | null;
}

export interface EffectivePolicyDto {
  checkInIntervalSeconds: number;
  scanIntervalMinutes: number;
  inventoryIntervalMinutes: number;
  jitterPercent: number;
  allowedCategories: UpdateCategory[];
  includeOptional: boolean;
  excludedKbs: string[];
  acceptEulas: boolean;
  autoInstallEnabled: boolean;
  maintenanceDays: number[] | null;
  maintenanceStart: string | null;
  maintenanceDurationMinutes: number | null;
  timeZone: string;
  scanStaleAfterHours: number;
  maxConcurrentInstallsPerSite: number;
  /** Keyed by policy field name (server casing may be PascalCase); value is the scope that supplied it. */
  sources: Record<string, PolicyScope>;
  trayIconEnabled: boolean;
  installNotificationsEnabled: boolean;
  restartSchedule: RestartScheduleDto | null;
  windowsUpdate: WindowsUpdatePolicySettings | null;
  /** Registry values EasyPatch sets on the endpoint for the managed groups. */
  windowsUpdateValues: PolicyRegistryValueDto[] | null;
  agentAutoUpdateEnabled: boolean;
  installDelayDays: number;
  securityInstallDelayDays: number;
  /** For values supplied by a tag policy: field name → tag name. */
  sourceTags: Record<string, string> | null;
  knownExploitedSkipsDelay: boolean;
  applicationUpdates: ApplicationUpdateSettings | null;
  preDownloadHours: number;
}

// ---------------------------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------------------------

export const TAG_COLORS = ['gray', 'blue', 'green', 'amber', 'red', 'purple', 'teal', 'pink'] as const;
export type TagColor = (typeof TAG_COLORS)[number];

export interface TagRefDto {
  id: Guid;
  name: string;
  color: string;
  /** On an endpoint's tags: set when the endpoint has the tag through its site or organization. */
  inheritedFrom?: 'Site' | 'Organization' | null;
}

export interface TagDto extends TagRefDto {
  description: string | null;
  /** Higher priority tag policies override lower ones on endpoints with several tags. */
  priority: number;
  /** Endpoints with the tag, directly or through their site or organization. 0 for organization-restricted users. */
  endpointCount: number;
  hasPolicy: boolean;
  createdAt: Instant;
  /** Sites and organizations tagged with it (0 for organization-restricted users). */
  siteCount: number;
  organizationCount: number;
}

export interface TagRequest {
  name: string;
  color: string;
  description: string | null;
  priority: number;
}

/** A tag policy that applies to an endpoint, in resolution order (later entries override earlier ones). */
export interface TagPolicyLayerDto {
  tag: TagRefDto;
  priority: number;
  policy: PolicyDto;
}

/** The tags of an organization or site (replaces the whole set). */
export interface TagAssignmentRequest {
  tagIds: Guid[];
}

export interface BulkEndpointTagsRequest {
  endpointIds: Guid[];
  addTagIds: Guid[] | null;
  removeTagIds: Guid[] | null;
}

// ---------------------------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------------------------

export interface EndpointSummaryDto {
  id: Guid;
  hostname: string;
  organizationId: Guid;
  organizationName: string;
  siteId: Guid | null;
  siteName: string | null;
  status: EndpointStatus;
  operatingSystem: string | null;
  osVersion: string | null;
  osBuild: string | null;
  architecture: string | null;
  agentVersion: string | null;
  agentOutdated: boolean;
  isOnline: boolean;
  lastCheckInAt: Instant | null;
  lastScanAt: Instant | null;
  complianceStatus: ComplianceStatus;
  missingRequiredCount: number;
  missingTotalCount: number;
  failedCount: number;
  rebootPending: boolean;
  osSupportStatus: OsSupportStatus;
  currentActivity: string | null;
  lastSeenIp: string | null;
  /** "Windows", "Linux" or "macOS" (see ENDPOINT_PLATFORMS). */
  platform: string;
  /** Allowed updates still inside their rollout delay (not counted as missing). */
  missingDeferredCount: number;
  tags: TagRefDto[];
  /** Outstanding allowed updates that fix a CISA known-exploited vulnerability. */
  knownExploitedMissingCount: number;
}

/** shared/EasyPatch.Contracts/Agent/AgentDtos.cs AgentPlatforms. The macOS agent is experimental. */
export const ENDPOINT_PLATFORMS = { windows: 'Windows', linux: 'Linux', macOS: 'macOS' } as const;

/** shared/EasyPatch.Contracts/Agent/AgentRelease.cs package formats ("pkg": the experimental macOS agent). */
export const AGENT_PACKAGE_FORMATS = { msi: 'msi', deb: 'deb', rpm: 'rpm', pkg: 'pkg' } as const;

/** Update source type a Linux agent reports (its apt or dnf repositories). */
export const UPDATE_SOURCE_PACKAGE_REPOSITORIES = 'PackageRepositories';

/** Update source type the macOS agent reports (Apple's software update service, through softwareupdate). */
export const UPDATE_SOURCE_APPLE_SOFTWARE_UPDATE = 'AppleSoftwareUpdate';

/** macOS-only endpoint details (null for Windows and Linux endpoints). The macOS agent is experimental. */
export interface MacOSDetailsDto {
  /** Always "macos". */
  osId: string | null;
  /** sw_vers ProductVersion, e.g. "15.7.2". */
  osVersion: string | null;
  /** sw_vers BuildVersion, e.g. "24G325". */
  osBuild: string | null;
  /** The Darwin kernel release. */
  kernelVersion: string | null;
  /** "softwareupdate". */
  packageManager: string | null;
  /** How the agent's private key is protected ("file-permissions"). */
  keyProtection: string | null;
}

/** Linux-only endpoint details (null for Windows and macOS endpoints). */
export interface LinuxDetailsDto {
  /** os-release ID, e.g. "ubuntu", "debian", "rhel", "rocky". */
  osId: string | null;
  /** os-release VERSION_ID. */
  osVersion: string | null;
  kernelVersion: string | null;
  /** "apt" or "dnf". */
  packageManager: string | null;
  /** How the agent's private key is protected: "systemd-creds-host" or "file-permissions". */
  keyProtection: string | null;
}

export interface CredentialDto {
  credentialId: string;
  keyFingerprint: string;
  createdAt: Instant;
  expiresAt: Instant;
  revokedAt: Instant | null;
  revokedReason: string | null;
  lastUsedAt: Instant | null;
}

/** A file Windows changes during the next restart. */
export interface PendingFileOperation {
  /** "Delete" or "Replace". */
  action: string;
  path: string;
}

export interface RestartUpdateDto {
  /** Null for a KB known only from a pending servicing package. */
  updateGuid: string | null;
  title: string;
  kbNumbers: string[];
  /** Installed (takes effect after the restart), WindowsUpdate (listed by Windows Update) or Servicing (a pending servicing package). */
  source: string;
  installedAt: string | null;
}

export interface RestartDetailsDto {
  updates: RestartUpdateDto[];
  /** Pending Windows servicing packages that name no KB. */
  servicingPackages: string[];
  /** The first 25 file operations. */
  fileOperations: PendingFileOperation[];
  fileOperationCount: number;
  /** The agent reports what Windows has queued (Windows agent 1.5.3 and later). */
  detailsSupported: boolean;
}

export interface EndpointDetailDto {
  summary: EndpointSummaryDto;
  dnsDomain: string | null;
  domainJoined: boolean | null;
  osEdition: string | null;
  osProductType: string | null;
  osInstallDate: Instant | null;
  serialNumber: string | null;
  manufacturer: string | null;
  model: string | null;
  processorName: string | null;
  totalMemoryBytes: number | null;
  systemDriveTotalBytes: number | null;
  systemDriveFreeBytes: number | null;
  isVirtualMachine: boolean | null;
  timeZoneId: string | null;
  lastBootAt: Instant | null;
  agentInstalledAt: Instant | null;
  enrolledAt: Instant;
  lastInventoryAt: Instant | null;
  lastScanAttemptAt: Instant | null;
  lastScanError: string | null;
  rebootReasons: string[];
  rebootPendingSince: Instant | null;
  updateSourceType: string | null;
  updateSourceServer: string | null;
  microsoftUpdateRegistered: boolean;
  wufbPoliciesConfigured: boolean;
  deferQualityUpdatesDays: number | null;
  deferFeatureUpdatesDays: number | null;
  targetReleaseVersion: string | null;
  automaticUpdatesMode: string | null;
  managedByMdm: boolean;
  windowsUpdateServiceStartMode: string | null;
  windowsUpdateServiceState: string | null;
  osEndOfServicing: DateOnly | null;
  esuLicenseDetected: boolean;
  esuOverride: EsuOverride;
  installedCount: number;
  pendingRebootUpdateCount: number;
  complianceEvaluatedAt: Instant | null;
  notes: string | null;
  credentials: CredentialDto[];
  activeJob: JobSummaryDto | null;
  agentCapabilities: string[];
  /** Signed-in users (counts only) and sessions with the EasyPatch tray, from the latest check-in. */
  signedInUsers: number | null;
  trayConnectedSessions: number | null;
  windowsUpdatePolicy: WindowsUpdatePolicyReport | null;
  windowsUpdatePolicyReportedAt: Instant | null;
  hasOwnPolicy: boolean;
  agentUpdate: AgentUpdateInfoDto | null;
  /** Null for Windows and macOS endpoints. */
  linux: LinuxDetailsDto | null;
  /** winget application updates (null for Linux and macOS endpoints). */
  applications?: ApplicationUpdatesStatusDto | null;
  /** What a pending restart is for; null when no restart is pending. */
  restart?: RestartDetailsDto | null;
  /** Null for Windows and Linux endpoints (and from servers before the macOS agent). */
  macOS?: MacOSDetailsDto | null;
}

export interface ApplicationUpdatesStatusDto {
  /** The effective policy enables application updates with at least one approved application. */
  enabled: boolean;
  /** The agent can check and upgrade applications (agent 1.4.0 or newer). */
  supported: boolean;
  approvedApps: number;
  wingetVersion: string | null;
  lastCheckAt: Instant | null;
  lastError: string | null;
  /** Why the agent could not install winget (agent 1.7.0 and newer). */
  wingetSetupError: string | null;
  /** Why the server could not download its own copy of winget (shown with a setup error). */
  serverCopyError: string | null;
}

/** Whether the agent can update itself and to which version (see the "Agent updates" policy). */
export interface AgentUpdateInfoDto {
  /** The agent is 1.2.0 or newer and was built with a release key. */
  supported: boolean;
  architecture: string | null;
  releaseKeyIds: string[];
  /** The effective "Agent updates" policy is Automatic. */
  automaticUpdates: boolean;
  /** The signed package an update would install, or null with a code and message saying why not. */
  availableVersion: string | null;
  code: string | null;
  message: string | null;
  /** The agent's package format: "msi", "deb", "rpm" or "pkg". */
  packageFormat: string | null;
}

export interface AgentUpdateRequest {
  /** A specific package version; null installs the newest signed package. */
  version: string | null;
}

export interface BulkAgentUpdateRequest extends AgentUpdateRequest {
  endpointIds: Guid[];
}

export interface UpdateEndpointRequest {
  siteId: Guid | null;
  notes: string | null;
  esuOverride: EsuOverride | null;
}

export interface RevokeEndpointRequest {
  reason: string | null;
}

export interface JobOverlayDto {
  jobId: Guid;
  jobStatus: JobStatus;
  itemStatus: JobItemStatus;
  downloadPercent: number | null;
  installPercent: number | null;
  jobType: JobType;
}

export interface EndpointUpdateDto {
  updateGuid: Guid;
  revisionNumber: number;
  title: string;
  description: string | null;
  kbNumber: string | null;
  kbNumbers: string[];
  category: UpdateCategory;
  msClassification: string | null;
  msrcSeverity: string | null;
  releaseDate: Instant | null;
  sizeBytes: number | null;
  rebootLikely: boolean;
  supportUrl: string | null;
  state: EndpointUpdateState;
  isRequired: boolean;
  isExcluded: boolean;
  firstDetectedAt: Instant;
  stateChangedAt: Instant;
  installedAt: Instant | null;
  failedAttempts: number;
  errorCode: string | null;
  errorMessage: string | null;
  activeJob: JobOverlayDto | null;
  /** The Linux package behind the update; null for Windows updates. */
  package: PackageInfoDto | null;
  /** Set while the update is inside its rollout delay (it is not required until then). */
  deferredUntil: Instant | null;
  /** CVEs the update fixes on this endpoint (see docs/compliance.md for the sources per platform). */
  cveIds: string[] | null;
  /** One of the CVEs is in the CISA Known Exploited Vulnerabilities catalog. */
  knownExploited: boolean;
  /** Earliest CISA remediation due date of those CVEs. */
  kevDueDate: string | null;
  /** Set when the update is missing or failed and on hold for the endpoint's organization: why it is held. */
  holdReason: string | null;
}

/** A Linux package update. `installedVersion` is the endpoint's current version (endpoint views only). */
export interface PackageInfoDto {
  name: string;
  architecture: string | null;
  /** The version the update installs. */
  version: string | null;
  installedVersion: string | null;
  repository: string | null;
  /** Security advisories (e.g. USN, DSA, RHSA) that the update fixes. */
  advisories: string[];
}

export interface UpdateHistoryDto {
  id: number;
  updateGuid: Guid | null;
  title: string;
  kbNumber: string | null;
  operation: string;
  resultCode: number;
  result: string;
  hResult: string | null;
  errorDescription: string | null;
  date: Instant;
}

export interface EndpointEventDto {
  id: number;
  endpointId: Guid;
  hostname: string | null;
  type: string;
  severity: EventSeverity;
  message: string;
  jobId: Guid | null;
  createdAt: Instant;
}

export interface InstallUpdatesRequest {
  mode: InstallMode;
  updateGuids: Guid[] | null;
  force: boolean;
}

export interface ExclusionRequest {
  updateGuid: Guid;
  reason: string | null;
}

export interface BulkEndpointsRequest {
  endpointIds: Guid[];
  force: boolean;
}

export interface BulkItemResult {
  endpointId: Guid;
  hostname: string | null;
  success: boolean;
  jobId: Guid | null;
  errorCode: string | null;
  message: string | null;
}

export interface BulkResultDto {
  succeeded: number;
  failed: number;
  results: BulkItemResult[];
}

// "Restart all that need it" (backend/API/Endpoints/RestartPendingEndpoints.cs)

export interface RestartPendingEndpointDto {
  id: Guid;
  hostname: string;
  siteId: Guid | null;
  siteName: string | null;
  platform: string;
  operatingSystem: string | null;
  /** Windows Server or a domain controller. */
  isServer: boolean;
  isOnline: boolean;
  rebootPendingSince: Instant | null;
  /** The agent supports restart jobs. */
  canRestart: boolean;
}

export interface RestartPendingDto {
  total: number;
  /** At most 1000 of `total`. */
  endpoints: RestartPendingEndpointDto[];
}

/** The endpoints the administrator confirmed; the server always uses the OnlyIfPending condition. */
export interface RestartPendingRequest {
  siteId: Guid | null;
  endpointIds: Guid[];
  restart: RestartRequest;
}

// Install preview (backend/Infrastructure/Services/InstallPreviewService.cs)

export interface InstallFilterOptions {
  categories: UpdateCategory[];
  includeOptional: boolean;
  excludedKbs: string[];
  excludedUpdateGuids: Guid[];
  acceptEulas: boolean;
}

export interface PreviewItem {
  updateGuid: Guid;
  revisionNumber: number;
  title: string;
  kbNumber: string | null;
  category: UpdateCategory;
  sizeBytes: number | null;
  rebootBehavior: number | null;
  state: EndpointUpdateState;
}

export interface PreviewSkip {
  updateGuid: Guid;
  title: string;
  kbNumber: string | null;
  category: UpdateCategory;
  reason: string;
}

export interface InstallPreview {
  mode: InstallMode;
  items: PreviewItem[];
  skipped: PreviewSkip[];
  totalSizeBytes: number;
  rebootLikelyCount: number;
  warnings: string[];
  filter: InstallFilterOptions | null;
  lastScanAt: Instant | null;
}

// ---------------------------------------------------------------------------------------------
// Fleet update management
// ---------------------------------------------------------------------------------------------

export interface FleetUpdateDto {
  updateGuid: Guid;
  title: string;
  kbNumber: string | null;
  category: UpdateCategory;
  msrcSeverity: string | null;
  releaseDate: Instant | null;
  sizeBytes: number | null;
  missingCount: number;
  failedCount: number;
  installedCount: number;
  pendingRebootCount: number;
  excludedCount: number;
  /** Endpoints where Windows offers it again after a successful installation. */
  reofferedCount: number;
  /** The Linux package behind the update; null for Windows updates. */
  package: PackageInfoDto | null;
  cveCount: number;
  /** Fixes a CISA known-exploited vulnerability on at least one endpoint in scope. */
  knownExploited: boolean;
  /** On hold for every organization or one in scope: not installed automatically. */
  onHold: boolean;
}

export interface FleetUpdateDetailDto {
  summary: FleetUpdateDto;
  description: string | null;
  supportUrl: string | null;
  kbNumbers: string[];
  products: string[];
  msClassification: string | null;
  rebootLikely: boolean;
  supersededUpdateGuids: Guid[];
  /** Known-exploited first, then by CVSS. */
  vulnerabilities: VulnerabilityDto[] | null;
  /** Active holds the administrator can see (every organization, or organizations they can access). */
  holds: UpdateHoldDto[] | null;
}

export const UPDATE_HOLD_SOURCES = ['Automatic', 'Manual'] as const;
export type UpdateHoldSource = (typeof UPDATE_HOLD_SOURCES)[number];

/** backend/API/Contracts/AdminDtos.cs — an update EasyPatch does not install automatically. `organizationId` null: every organization. */
export interface UpdateHoldDto {
  id: Guid;
  updateGuid: Guid;
  title: string | null;
  kbNumber: string | null;
  organizationId: Guid | null;
  organizationName: string | null;
  /** Automatic: created by the rollout guard (with the failure counts that triggered it). */
  source: UpdateHoldSource;
  reason: string;
  failedEndpoints: number | null;
  attemptedEndpoints: number | null;
  createdAt: Instant;
  createdBy: string;
  releasedAt: Instant | null;
  releasedBy: string | null;
  canRelease: boolean;
}

export interface CreateUpdateHoldRequest {
  organizationId: Guid | null;
  reason: string;
}

/** A CVE an update fixes. Title, severity and CVSS come from MSRC (Windows CVEs only); kev* from the CISA KEV catalog. */
export interface VulnerabilityDto {
  cveId: string;
  title: string | null;
  severity: string | null;
  cvssBase: number | null;
  msrcExploited: boolean;
  kev: boolean;
  kevDateAdded: string | null;
  kevDueDate: string | null;
  kevRansomware: boolean;
  kevName: string | null;
}

/** Synchronization state of a vulnerability feed ("msrc", "kev" or "debian"). */
export interface VulnerabilityFeedDto {
  name: string;
  lastAttemptAt: Instant | null;
  lastSuccessAt: Instant | null;
  lastError: string | null;
  version: string | null;
  itemCount: number;
}

export interface FleetUpdateEndpointDto {
  endpointId: Guid;
  hostname: string;
  organizationName: string;
  siteName: string | null;
  isOnline: boolean;
  state: EndpointUpdateState;
  isRequired: boolean;
  isExcluded: boolean;
  failedAttempts: number;
  errorCode: string | null;
  errorMessage: string | null;
  stateChangedAt: Instant;
}

export interface FleetInstallRequest {
  organizationId: Guid | null;
  siteId: Guid | null;
  endpointIds: Guid[] | null;
}

// ---------------------------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------------------------

export interface JobSummaryDto {
  id: Guid;
  endpointId: Guid;
  hostname: string;
  organizationId: Guid;
  organizationName: string;
  type: JobType;
  status: JobStatus;
  trigger: JobTrigger;
  requestedBy: string;
  createdAt: Instant;
  startedAt: Instant | null;
  completedAt: Instant | null;
  expiresAt: Instant;
  progressPercent: number | null;
  phase: string | null;
  progressMessage: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  rebootRequired: boolean;
  timedOut: boolean;
  cancelRequested: boolean;
  itemCount: number;
  succeededCount: number;
  failedCount: number;
}

export interface JobItemDto {
  updateGuid: Guid;
  title: string;
  kbNumber: string | null;
  category: UpdateCategory;
  status: JobItemStatus;
  skipReason: string | null;
  resultCode: number | null;
  errorCode: string | null;
  errorMessage: string | null;
  rebootRequired: boolean;
  downloadPercent: number | null;
  installPercent: number | null;
  startedAt: Instant | null;
  completedAt: Instant | null;
}

export interface JobDetailDto {
  summary: JobSummaryDto;
  installMode: InstallMode | null;
  notBefore: Instant | null;
  deliveredAt: Instant | null;
  acknowledgedAt: Instant | null;
  lastProgressAt: Instant | null;
  deliveryCount: number;
  retryOfJobId: Guid | null;
  cancelRequestedAt: Instant | null;
  items: JobItemDto[];
  events: EndpointEventDto[];
}

// ---------------------------------------------------------------------------------------------
// Agent management
// ---------------------------------------------------------------------------------------------

export interface EnrollmentTokenDto {
  id: Guid;
  organizationId: Guid;
  organizationName: string;
  siteId: Guid | null;
  siteName: string | null;
  tokenPrefix: string;
  description: string | null;
  maxUses: number;
  useCount: number;
  createdAt: Instant;
  expiresAt: Instant;
  lastUsedAt: Instant | null;
  revokedAt: Instant | null;
  state: string;
}

export interface CreateTokensRequest {
  organizationId: Guid;
  siteId: Guid | null;
  description: string | null;
  expiresInHours: number;
  maxUses: number;
  count: number;
}

export interface CreatedTokenDto {
  token: EnrollmentTokenDto;
  plaintextToken: string;
  msiExecCommand: string;
  /** Enrolls an installed Linux agent; the token is piped in so it never shows in the process list. */
  linuxEnrollCommand: string | null;
  /** Enrolls an installed macOS agent (experimental) the same way; null when the server has no macOS (pkg) package. */
  macEnrollCommand?: string | null;
}

export interface DeploymentCodeDto {
  id: Guid;
  code: string;
  name: string;
  organizationId: Guid;
  organizationName: string;
  siteId: Guid | null;
  siteName: string | null;
  maxPendingRequests: number;
  allowedSourceCidrs: string[];
  createdAt: Instant;
  expiresAt: Instant | null;
  revokedAt: Instant | null;
  pendingCount: number;
  approvedCount: number;
  state: string;
  oneLiner: string;
  scriptUrl: string;
  /** `curl … | sudo sh` command that installs and enrolls a Linux agent. */
  linuxOneLiner: string | null;
  linuxScriptUrl: string | null;
  /** `curl … | sudo sh` command for the experimental macOS agent; null (like macScriptUrl) when the server has no pkg package. */
  macOneLiner?: string | null;
  macScriptUrl?: string | null;
}

export interface CreateDeploymentCodeRequest {
  organizationId: Guid;
  siteId: Guid | null;
  name: string;
  expiresInDays: number | null;
  allowedSourceCidrs: string[] | null;
  maxPendingRequests: number | null;
}

export interface InstallScriptResponse {
  script: string;
  oneLiner: string;
  scriptUrl: string;
  packageFileName: string;
  packageVersion: string;
  sha256: string;
  requireSignature: boolean;
  /** "Windows", "Linux" or "macOS". For Linux and macOS, packageFileName and sha256 list every package the script can install. */
  platform: string;
  /** Windows: the downloads skip the certificate check and the agent trusts the server's published CA. */
  skipCertificateCheck: boolean;
}

export interface EnrollmentRequestDto {
  id: Guid;
  requestId: string;
  hostname: string;
  keyFingerprint: string;
  serialNumber: string | null;
  manufacturer: string | null;
  model: string | null;
  osCaption: string | null;
  agentVersion: string;
  sourceIp: string | null;
  status: EnrollmentRequestStatus;
  organizationId: Guid;
  organizationName: string;
  siteId: Guid | null;
  siteName: string | null;
  deploymentCodeName: string;
  createdAt: Instant;
  lastSeenAt: Instant;
  expiresAt: Instant;
  decidedAt: Instant | null;
  rejectReason: string | null;
  endpointId: Guid | null;
  existingEndpointId: Guid | null;
}

export interface ApproveRequest {
  organizationId: Guid | null;
  siteId: Guid | null;
}

export interface RejectRequest {
  reason: string | null;
}

export interface BulkApproveRequest {
  ids: Guid[];
}

export interface AgentPackageDto {
  fileName: string;
  version: string;
  architecture: string;
  sizeBytes: number;
  sha256: string;
  modifiedAt: Instant;
  downloadUrl: string;
  isLatest: boolean;
  /** The release key in the package's .sig file; null when it is not signed (agents will not update to it). */
  releaseKeyId: string | null;
  /** Why a .sig file next to the package was ignored. */
  signatureProblem: string | null;
  /** "msi", "deb", "rpm" or "pkg". */
  format: string;
}

export interface AgentVersionCountDto {
  version: string;
  count: number;
  isLatest: boolean;
}

// ---------------------------------------------------------------------------------------------
// Dashboard, reports, audit, settings
// ---------------------------------------------------------------------------------------------

export interface DashboardSummaryDto {
  organizations: number;
  endpoints: number;
  online: number;
  offline: number;
  compliant: number;
  missingUpdates: number;
  failedUpdates: number;
  rebootRequired: number;
  scanStale: number;
  neverScanned: number;
  compliancePercent: number;
  missingRequiredUpdates: number;
  queuedJobs: number;
  runningJobs: number;
  failedJobs24h: number;
  pendingApprovals: number;
  unsupportedOs: number;
  outdatedAgents: number;
  leastCompliantOrganizations: OrganizationSummaryDto[];
  /** Endpoints missing an update that fixes a CISA known-exploited vulnerability. */
  knownExploitedEndpoints: number;
}

export interface ComplianceReportRow {
  endpointId: Guid;
  hostname: string;
  organizationName: string;
  siteName: string | null;
  operatingSystem: string | null;
  osBuild: string | null;
  complianceStatus: ComplianceStatus;
  missingRequiredCount: number;
  missingTotalCount: number;
  failedCount: number;
  rebootPending: boolean;
  isOnline: boolean;
  osSupportStatus: OsSupportStatus;
  lastScanAt: Instant | null;
  lastCheckInAt: Instant | null;
  /** "Windows", "Linux" or "macOS". On Linux, osBuild is the kernel version; on macOS the Apple build. */
  platform: string;
}

export interface ComplianceReportDto {
  total: number;
  compliant: number;
  compliancePercent: number;
  byStatus: Partial<Record<ComplianceStatus, number>>;
  rows: ComplianceReportRow[];
}

export interface ComplianceTrendPoint {
  date: DateOnly;
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

export interface InstallationReportRow {
  jobId: Guid;
  endpointId: Guid;
  hostname: string;
  organizationName: string;
  siteName: string | null;
  updateGuid: Guid;
  title: string;
  kbNumber: string | null;
  category: UpdateCategory;
  status: JobItemStatus;
  skipReason: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  rebootRequired: boolean;
  requestedBy: string;
  completedAt: Instant | null;
}

export interface AuditLogDto {
  id: number;
  userId: Guid | null;
  username: string | null;
  organizationId: Guid | null;
  endpointId: Guid | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  details: string | null;
  ipAddress: string | null;
  correlationId: string | null;
  createdAt: Instant;
}

export interface OsLifecycleDto {
  id: Guid;
  product: string;
  editionGroup: string;
  buildNumber: number;
  versionLabel: string;
  endOfServicing: DateOnly;
  esuEndDate: DateOnly | null;
  notes: string | null;
}

export interface OsLifecycleRequest {
  product: string;
  editionGroup: string;
  buildNumber: number;
  versionLabel: string;
  endOfServicing: DateOnly;
  esuEndDate: DateOnly | null;
  notes: string | null;
}

/** backend/Core/Domain/ServerSettings.cs */
export interface ServerSettings {
  globalMaxConcurrentInstalls: number;
  jobDefaultExpiryHours: number;
  runningJobTimeoutHours: number;
  waitingForRebootExpiryDays: number;
  deliveryLeaseMinutes: number;
  maxDeliveryAttempts: number;
  offlineThresholdMinutes: number;
  credentialLifetimeDays: number;
  credentialRotateBeforeDays: number;
  enrollmentRequestExpiryDays: number;
  requireMfa: boolean;
  sessionIdleMinutes: number;
  sessionAbsoluteHours: number;
  retentionEventsDays: number;
  retentionAuditDays: number;
  retentionJobsDays: number;
  retentionScansDays: number;
  retentionHistoryDays: number;
  /** Download CISA KEV, MSRC and Debian Security Tracker data (worker, outbound HTTPS). */
  vulnerabilityFeedsEnabled: boolean;
  /** Monthly reports older than this are deleted (1-120). */
  retentionReportsMonths: number;
  /** "Prepared by" line on monthly reports; null to leave it out. */
  reportBrandName: string | null;
  /** Hold a Windows update for every organization when it fails on too many endpoints. */
  rolloutGuardEnabled: boolean;
  /** At least this many endpoints whose latest installation failed (1-1000). */
  rolloutGuardMinFailedEndpoints: number;
  /** And at least this percentage of the endpoints that installed it (1-100). */
  rolloutGuardFailurePercent: number;
  /** Installations in this many days count (1-90). */
  rolloutGuardWindowDays: number;
}

export interface ServerInfoDto {
  version: string;
  publicUrl: string;
  serverTime: Instant;
}

// ---------------------------------------------------------------------------------------------
// Alerts and notifications (backend/API/Contracts/NotificationDtos.cs)
// ---------------------------------------------------------------------------------------------

export const ALERT_RULE_TYPES = [
  'EndpointOffline',
  'InstallFailed',
  'SecurityUpdateMissing',
  'ScanStale',
  'RestartPending',
  'EnrollmentPending',
  'OsUnsupported',
  'KnownExploitedMissing',
  'UpdateHeld',
] as const;
export type AlertRuleType = (typeof ALERT_RULE_TYPES)[number];

export const ALERT_RULE_TYPE_LABELS: Record<AlertRuleType, string> = {
  EndpointOffline: 'Endpoint offline',
  InstallFailed: 'Update installation failed',
  SecurityUpdateMissing: 'Security update missing',
  ScanStale: 'Scan stale',
  RestartPending: 'Restart pending',
  EnrollmentPending: 'Enrollment waiting for approval',
  OsUnsupported: 'Operating system unsupported',
  KnownExploitedMissing: 'Known-exploited vulnerability unpatched',
  UpdateHeld: 'Update on hold',
};

export const ALERT_SEVERITIES = ['Critical', 'Warning', 'Info'] as const;
export type AlertSeverity = (typeof ALERT_SEVERITIES)[number];

export const ALERT_STATUSES = ['Open', 'Acknowledged', 'Resolved'] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];

/** Values of the alerts list "status" filter. */
export const ALERT_STATUS_FILTERS = ['unresolved', 'open', 'acknowledged', 'resolved', 'all'] as const;
export type AlertStatusFilter = (typeof ALERT_STATUS_FILTERS)[number];

export type NotificationChannelType = 'Email' | 'Webhook';
export const WEBHOOK_FORMATS = ['Generic', 'Slack', 'Teams'] as const;
export type WebhookFormat = (typeof WEBHOOK_FORMATS)[number];
export const SMTP_SECURITY = ['StartTls', 'SslOnConnect', 'None'] as const;
export type SmtpSecurity = (typeof SMTP_SECURITY)[number];
export type NotificationKind = 'AlertsOpened' | 'AlertsResolved' | 'AlertsReminder' | 'Test';
export const DELIVERY_STATUSES = ['Pending', 'Sent', 'Failed'] as const;
export type DeliveryStatus = (typeof DELIVERY_STATUSES)[number];

export interface AlertDto {
  id: Guid;
  ruleId: Guid | null;
  ruleName: string | null;
  ruleType: AlertRuleType;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  details: string | null;
  organizationId: Guid;
  organizationName: string;
  endpointId: Guid | null;
  hostname: string | null;
  openedAt: Instant;
  lastSeenAt: Instant;
  resolvedAt: Instant | null;
  acknowledgedAt: Instant | null;
  acknowledgedBy: string | null;
}

/** Unresolved alerts the user can see; `open` excludes acknowledged alerts. */
export interface AlertSummaryDto {
  open: number;
  acknowledged: number;
  critical: number;
  warning: number;
  info: number;
}

export interface AcknowledgeAlertsResult {
  acknowledged: number;
}

export interface NotificationSettingsDto {
  smtpHost: string | null;
  smtpPort: number;
  smtpSecurity: SmtpSecurity;
  smtpUsername: string | null;
  smtpPasswordConfigured: boolean;
  fromAddress: string | null;
  fromName: string | null;
  allowPrivateNetworkWebhooks: boolean;
  updatedAt: Instant;
  /** Any certificate from the SMTP server is accepted (encrypted, but the server's identity is not verified). */
  smtpSkipCertificateValidation: boolean;
}

/** `smtpPassword`: null keeps the stored password, "" removes it. */
export interface NotificationSettingsRequest {
  smtpHost: string | null;
  smtpPort: number;
  smtpSecurity: SmtpSecurity;
  smtpUsername: string | null;
  smtpPassword: string | null;
  fromAddress: string | null;
  fromName: string | null;
  allowPrivateNetworkWebhooks: boolean;
  /** Ignored by the server when smtpSecurity is None. */
  smtpSkipCertificateValidation: boolean;
}

export interface DeliverySummaryDto {
  status: DeliveryStatus;
  createdAt: Instant;
  lastError: string | null;
}

export interface NotificationChannelDto {
  id: Guid;
  name: string;
  type: NotificationChannelType;
  enabled: boolean;
  emailRecipients: string[];
  webhookFormat: WebhookFormat | null;
  webhookHost: string | null;
  hasSigningSecret: boolean;
  createdAt: Instant;
  updatedAt: Instant;
  lastDelivery: DeliverySummaryDto | null;
}

/** `webhookUrl`: required when creating a webhook channel; null on update keeps the stored URL. */
export interface NotificationChannelRequest {
  name: string;
  type: NotificationChannelType;
  enabled: boolean;
  emailRecipients: string[] | null;
  webhookFormat: WebhookFormat | null;
  webhookUrl: string | null;
}

/** `signingSecret` (generic webhooks) is returned only when it is created or rotated. */
export interface NotificationChannelSavedDto {
  channel: NotificationChannelDto;
  signingSecret: string | null;
}

export interface NotificationDeliveryDto {
  id: Guid;
  channelId: Guid;
  channelName: string;
  kind: NotificationKind;
  subject: string;
  status: DeliveryStatus;
  attempts: number;
  lastError: string | null;
  createdAt: Instant;
  nextAttemptAt: Instant;
  sentAt: Instant | null;
}

export interface AlertRuleDto {
  id: Guid;
  name: string;
  type: AlertRuleType;
  enabled: boolean;
  severity: AlertSeverity;
  threshold: number | null;
  thresholdUnit: string | null;
  organizationId: Guid | null;
  tagId: Guid | null;
  channelIds: Guid[];
  notifyOnResolve: boolean;
  renotifyHours: number;
  unresolvedAlerts: number;
  updatedAt: Instant;
}

export interface AlertRuleRequest {
  name: string;
  type: AlertRuleType;
  enabled: boolean;
  severity: AlertSeverity;
  threshold: number | null;
  organizationId: Guid | null;
  tagId: Guid | null;
  channelIds: Guid[] | null;
  notifyOnResolve: boolean;
  renotifyHours: number;
}

export interface AlertRuleTypeDto {
  type: AlertRuleType;
  thresholdUnit: string | null;
  thresholdMin: number | null;
  thresholdMax: number | null;
  thresholdDefault: number | null;
  supportsTag: boolean;
}

// ---------------------------------------------------------------------------------------------
// Monthly reports (backend/API/Contracts/AdminDtos.cs)
// ---------------------------------------------------------------------------------------------

export interface ReportScheduleDto {
  organizationId: Guid;
  enabled: boolean;
  recipients: string[];
  /** 1-28, in the organization's time zone. */
  dayOfMonth: number;
  includeEndpointList: boolean;
  enabledAt: Instant | null;
  lastScheduledPeriod: DateOnly | null;
  /** Date (organization time zone) the next report is sent; null when off or without recipients. */
  nextReportDate: DateOnly | null;
  /** First day of the month the next report covers. */
  nextReportPeriod: DateOnly | null;
  timeZone: string;
  updatedAt: Instant | null;
}

export interface ReportScheduleRequest {
  enabled: boolean;
  recipients: string[];
  dayOfMonth: number;
  includeEndpointList: boolean;
}

export interface MonthlyReportDto {
  id: Guid;
  organizationId: Guid;
  organizationName: string;
  periodStart: DateOnly;
  periodEnd: DateOnly;
  monthToDate: boolean;
  scheduled: boolean;
  generatedAt: Instant;
  generatedBy: string | null;
  fileName: string;
  sizeBytes: number;
  sha256: string;
  /** Null: not emailed. */
  deliveryStatus: DeliveryStatus | null;
  recipients: string[];
  attempts: number;
  queuedAt: Instant | null;
  sentAt: Instant | null;
  lastError: string | null;
}

export interface GenerateReportRequest {
  organizationId: Guid;
  year: number;
  month: number;
  includeEndpointList?: boolean | null;
}

export interface SendReportRequest {
  recipients?: string[] | null;
}

// ---------------------------------------------------------------------------------------------
// Single sign-on (OpenID Connect)
// ---------------------------------------------------------------------------------------------

/** An enabled provider: a "Sign in with …" button on the sign-in page. */
export interface SsoProviderSummaryDto {
  id: Guid;
  displayName: string;
}

export interface SsoProviderDto {
  id: Guid;
  displayName: string;
  issuer: string;
  clientId: string;
  /** The secret itself is never returned. */
  clientSecretConfigured: boolean;
  scopes: string;
  enabled: boolean;
  trustEmailClaim: boolean;
  providerEnforcesMfa: boolean;
  autoProvision: boolean;
  defaultRole: UserRole;
  allowedDomains: string[];
  linkedUsers: number;
  createdAt: Instant;
  updatedAt: Instant;
}

export interface SsoSettingsDto {
  /** Register this redirect URI at every provider. */
  redirectUri: string;
  providers: SsoProviderDto[];
}

export interface SsoProviderRequest {
  displayName: string;
  issuer: string;
  clientId: string;
  /** null keeps the stored secret; an empty string removes it (public client). */
  clientSecret: string | null;
  scopes: string | null;
  enabled: boolean;
  trustEmailClaim: boolean;
  providerEnforcesMfa: boolean;
  autoProvision: boolean;
  defaultRole: UserRole;
  allowedDomains: string[];
}

export interface SsoProbeDto {
  ok: boolean;
  issuer: string | null;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  signingKeys: number;
  message: string;
}

export interface ExternalLoginDto {
  id: Guid;
  providerId: Guid;
  providerName: string;
  issuer: string;
  subject: string;
  email: string | null;
  createdAt: Instant;
  lastUsedAt: Instant | null;
}
