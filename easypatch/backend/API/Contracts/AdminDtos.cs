using EasyPatch.Contracts;
using EasyPatch.Contracts.Policy;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;

namespace EasyPatch.Api.Contracts;

// Administrator API data transfer objects. JSON is camelCase with string enums (see ContractJson).

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Page, int PageSize, int TotalCount);

// ---------------------------------------------------------------------------------------------
// Authentication and account
// ---------------------------------------------------------------------------------------------

/// <summary>Sign in with the account's email address (case does not matter) and password.</summary>
public sealed record LoginRequest(string Email, string Password);

public sealed record LoginResponse(bool MfaRequired, bool MfaSetupRequired, CurrentUserDto User);

public sealed record MfaCodeRequest(string Code);

/// <param name="MfaEnabled">The user has a second factor: an authenticator app (<paramref name="TotpEnabled"/>) or a security key or
/// passkey (<paramref name="SecurityKeyCount"/>).</param>
/// <param name="PasskeyCount">Security keys and passkeys that can sign in without a password (discoverable credentials).</param>
/// <param name="PasskeyPrompt">Offer to set up a passkey now: passkeys work on this server, the user has none and has not answered
/// "Not now" in the last 30 days.</param>
public sealed record CurrentUserDto(
    Guid Id,
    string Username,
    string Email,
    UserRole Role,
    bool MfaEnabled,
    bool MfaCompleted,
    bool MfaSetupRequired,
    bool MustChangePassword,
    IReadOnlyList<Guid> OrganizationIds,
    DateTimeOffset? LastLoginAt,
    bool TotpEnabled = false,
    int SecurityKeyCount = 0,
    int PasskeyCount = 0,
    bool PasskeyPrompt = false,
    bool HasPassword = true);

/// <summary>Whether passkeys and security keys can be used with this server (they need HTTPS and a DNS name).</summary>
/// <param name="Reason"><c>ip_address</c>, <c>not_https</c> or <c>invalid_public_url</c> when unavailable.</param>
public sealed record WebAuthnStatusDto(bool Available, string? RpId, string? Reason, string? Message);

/// <param name="IsPasskey">Discoverable: signs in without an email address or password. Otherwise a security key used as the
/// second factor.</param>
/// <param name="IsSynced">Synced to the user's other devices by their password manager or platform.</param>
public sealed record WebAuthnCredentialDto(Guid Id, string Name, bool IsPasskey, bool IsSynced, IReadOnlyList<string> Transports,
    DateTimeOffset CreatedAt, DateTimeOffset? LastUsedAt);

/// <param name="Passkey">A passkey (discoverable, with PIN or biometrics) instead of a security key used only as a second factor.</param>
/// <param name="Password">The current password, required when the account already has a second factor.</param>
public sealed record WebAuthnRegisterOptionsRequest(bool Passkey, string? Password);

/// <param name="Credential">The browser's <c>PublicKeyCredential</c> in its JSON form (<c>toJSON()</c>).</param>
public sealed record WebAuthnRegisterRequest(string? Name, System.Text.Json.JsonElement Credential);

/// <param name="RecoveryCodes">Shown once, when this is the account's first second factor.</param>
public sealed record WebAuthnRegisterResponse(WebAuthnCredentialDto Credential, IReadOnlyList<string>? RecoveryCodes);

public sealed record WebAuthnRenameRequest(string Name);

public sealed record WebAuthnAssertionRequest(System.Text.Json.JsonElement Credential);

public sealed record MfaSetupResponse(string Secret, string OtpAuthUri, string QrCodeDataUri);

public sealed record RecoveryCodesResponse(IReadOnlyList<string> RecoveryCodes);

public sealed record MfaDisableRequest(string Password, string Code);

public sealed record PasswordConfirmRequest(string Password);

public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword);

/// <summary>Change the signed-in user's own email address, confirmed with the current password.</summary>
public sealed record ChangeEmailRequest(string CurrentPassword, string NewEmail);

public sealed record ResetPasswordRequest(string Token, string NewPassword);

public sealed record SessionDto(Guid Id, DateTimeOffset CreatedAt, DateTimeOffset LastSeenAt, DateTimeOffset ExpiresAt, string? IpAddress, string? UserAgent,
    bool Current);

// ---------------------------------------------------------------------------------------------
// Users (SuperAdmin)
// ---------------------------------------------------------------------------------------------

/// <param name="MfaEnabled">An authenticator app or at least one security key or passkey.</param>
public sealed record UserDto(
    Guid Id,
    string Username,
    string Email,
    UserRole Role,
    bool IsActive,
    bool MfaEnabled,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastLoginAt,
    DateTimeOffset? LockoutUntil,
    IReadOnlyList<Guid> OrganizationIds,
    bool TotpEnabled,
    int SecurityKeyCount,
    int ExternalLoginCount);

public sealed record CreateUserRequest(string Username, string Email, UserRole Role, string? Password, IReadOnlyList<Guid>? OrganizationIds);

/// <summary>When no password is supplied, <see cref="ResetLink"/> carries a one-time link the new user opens to set one.</summary>
public sealed record CreateUserResponse(UserDto User, ResetLinkResponse? ResetLink);

/// <summary>An API token. The secret is never returned after creation.</summary>
/// <param name="Status">Active, Expired or Revoked.</param>
public sealed record ApiTokenDto(
    Guid Id,
    string Name,
    string Prefix,
    UserRole Role,
    bool AllOrganizations,
    IReadOnlyList<Guid> OrganizationIds,
    DateTimeOffset CreatedAt,
    string? CreatedBy,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? LastUsedAt,
    string? LastUsedIp,
    DateTimeOffset? RevokedAt,
    string? RevokedBy,
    string Status);

/// <param name="Role">ReadOnly or Admin.</param>
/// <param name="OrganizationIds">Organizations the token can access; empty for every organization.</param>
/// <param name="ExpiresInDays">1 to 365.</param>
public sealed record CreateApiTokenRequest(string Name, UserRole Role, IReadOnlyList<Guid>? OrganizationIds, int ExpiresInDays);

/// <param name="Secret">The token to send as <c>Authorization: Bearer …</c>. Shown once; EasyPatch keeps only a hash.</param>
public sealed record CreateApiTokenResponse(ApiTokenDto Token, string Secret);

public sealed record UpdateUserRequest(string? Email, UserRole? Role, bool? IsActive);

public sealed record ResetLinkResponse(string Url, DateTimeOffset ExpiresAt);

public sealed record OrganizationAccessRequest(IReadOnlyList<Guid> OrganizationIds);

// ---------------------------------------------------------------------------------------------
// Organizations, sites, policies
// ---------------------------------------------------------------------------------------------

public sealed record OrganizationSummaryDto(
    Guid Id,
    string Name,
    string? Description,
    string TimeZone,
    bool IsActive,
    int SiteCount,
    int EndpointCount,
    int OnlineCount,
    int OfflineCount,
    int CompliantCount,
    int NonCompliantCount,
    int MissingRequiredUpdates,
    int FailedCount,
    int RebootRequiredCount,
    double CompliancePercent,
    DateTimeOffset? LastActivityAt,
    DateTimeOffset CreatedAt);

public sealed record OrganizationDto(
    Guid Id,
    string Name,
    string? Description,
    string? ContactName,
    string? ContactEmail,
    string? Notes,
    string TimeZone,
    bool IsActive,
    DateTimeOffset CreatedAt,
    DateTimeOffset UpdatedAt,
    DateTimeOffset? ArchivedAt,
    IReadOnlyList<SiteDto> Sites,
    OrganizationSummaryDto Summary,
    IReadOnlyList<TagRefDto>? Tags = null);

public sealed record OrganizationRequest(string Name, string? Description, string? ContactName, string? ContactEmail, string? Notes, string? TimeZone);

public sealed record SiteDto(
    Guid Id,
    Guid OrganizationId,
    string OrganizationName,
    string Name,
    string? Description,
    string? Address,
    string TimeZone,
    bool IsActive,
    int EndpointCount,
    int RebootPendingCount,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ArchivedAt,
    IReadOnlyList<TagRefDto>? Tags = null);

public sealed record SiteRequest(string Name, string? Description, string? Address, string? TimeZone);

/// <summary>A policy layer. Null values inherit from the parent scope. <c>MaintenanceStart</c> is "HH:mm" in the site
/// (or organization) time zone; days use 0 = Sunday … 6 = Saturday.</summary>
public sealed record PolicyDto(
    Guid? Id,
    PolicyScope Scope,
    Guid? OrganizationId,
    Guid? SiteId,
    int? CheckInIntervalSeconds,
    int? ScanIntervalMinutes,
    int? InventoryIntervalMinutes,
    int? JitterPercent,
    IReadOnlyList<string>? AllowedCategories,
    bool? IncludeOptional,
    IReadOnlyList<string> ExcludedKbs,
    bool? AcceptEulas,
    bool? AutoInstallEnabled,
    IReadOnlyList<int>? MaintenanceDays,
    string? MaintenanceStart,
    int? MaintenanceDurationMinutes,
    int? ScanStaleAfterHours,
    int? MaxConcurrentInstallsPerSite,
    DateTimeOffset? UpdatedAt,
    Guid? EndpointId = null,
    bool? TrayIconEnabled = null,
    bool? InstallNotificationsEnabled = null,
    RestartScheduleDto? RestartSchedule = null,
    PolicyWindowsUpdate? WindowsUpdate = null,
    bool? AgentAutoUpdateEnabled = null,
    int? InstallDelayDays = null,
    int? SecurityInstallDelayDays = null,
    Guid? TagId = null,
    bool? KnownExploitedSkipsDelay = null,
    ApplicationUpdateSettings? ApplicationUpdates = null,
    int? PreDownloadHours = null);

/// <summary>Recurring restart. <c>Time</c> is "HH:mm" in the site (or organization) time zone; days use 0 = Sunday … 6 = Saturday.</summary>
public sealed record RestartScheduleDto(
    bool Enabled,
    IReadOnlyList<int> Days,
    string Time,
    RestartCondition Condition,
    RestartMode Mode,
    int CountdownMinutes,
    int DeadlineMinutes,
    int ExpiryMinutes);

/// <summary>A Windows Update policy registry value EasyPatch sets (or deletes) under HKLM.</summary>
public sealed record PolicyRegistryValueDto(WindowsUpdatePolicyGroup Group, string Path, string Name, string Value);

public sealed record PolicyRequest(
    int? CheckInIntervalSeconds,
    int? ScanIntervalMinutes,
    int? InventoryIntervalMinutes,
    int? JitterPercent,
    IReadOnlyList<string>? AllowedCategories,
    bool? IncludeOptional,
    IReadOnlyList<string>? ExcludedKbs,
    bool? AcceptEulas,
    bool? AutoInstallEnabled,
    IReadOnlyList<int>? MaintenanceDays,
    string? MaintenanceStart,
    int? MaintenanceDurationMinutes,
    int? ScanStaleAfterHours,
    int? MaxConcurrentInstallsPerSite,
    bool? TrayIconEnabled = null,
    bool? InstallNotificationsEnabled = null,
    RestartScheduleDto? RestartSchedule = null,
    PolicyWindowsUpdate? WindowsUpdate = null,
    bool? AgentAutoUpdateEnabled = null,
    int? InstallDelayDays = null,
    int? SecurityInstallDelayDays = null,
    bool? KnownExploitedSkipsDelay = null,
    ApplicationUpdateSettings? ApplicationUpdates = null,
    int? PreDownloadHours = null);

public sealed record EffectivePolicyDto(
    int CheckInIntervalSeconds,
    int ScanIntervalMinutes,
    int InventoryIntervalMinutes,
    int JitterPercent,
    IReadOnlyList<UpdateCategory> AllowedCategories,
    bool IncludeOptional,
    IReadOnlyList<string> ExcludedKbs,
    bool AcceptEulas,
    bool AutoInstallEnabled,
    IReadOnlyList<int>? MaintenanceDays,
    string? MaintenanceStart,
    int? MaintenanceDurationMinutes,
    string TimeZone,
    int ScanStaleAfterHours,
    int MaxConcurrentInstallsPerSite,
    IReadOnlyDictionary<string, PolicyScope> Sources,
    bool TrayIconEnabled = true,
    bool InstallNotificationsEnabled = true,
    RestartScheduleDto? RestartSchedule = null,
    WindowsUpdatePolicySettings? WindowsUpdate = null,
    IReadOnlyList<PolicyRegistryValueDto>? WindowsUpdateValues = null,
    bool AgentAutoUpdateEnabled = true,
    int InstallDelayDays = 0,
    int SecurityInstallDelayDays = 0,
    IReadOnlyDictionary<string, string>? SourceTags = null,
    bool KnownExploitedSkipsDelay = true,
    ApplicationUpdateSettings? ApplicationUpdates = null,
    int PreDownloadHours = 0);

// ---------------------------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------------------------

/// <param name="InheritedFrom">Null for an endpoint's own tag; "Site" or "Organization" when the endpoint has it through its
/// site or organization.</param>
public sealed record TagRefDto(Guid Id, string Name, string Color, string? InheritedFrom = null);

/// <param name="EndpointCount">Endpoints with the tag, directly or through their site or organization.</param>
public sealed record TagDto(Guid Id, string Name, string Color, string? Description, int Priority, int EndpointCount, bool HasPolicy,
    DateTimeOffset CreatedAt, int SiteCount = 0, int OrganizationCount = 0);

public sealed record TagRequest(string Name, string Color, string? Description, int Priority);

public sealed record EndpointTagsRequest(IReadOnlyList<Guid> TagIds);

/// <summary>The tags of an organization or site (replaces the whole set).</summary>
public sealed record TagAssignmentRequest(IReadOnlyList<Guid> TagIds);

public sealed record BulkEndpointTagsRequest(IReadOnlyList<Guid> EndpointIds, IReadOnlyList<Guid>? AddTagIds, IReadOnlyList<Guid>? RemoveTagIds);

public sealed record BulkEndpointTagsResult(int Changed);

/// <summary>A tag policy that applies to an endpoint, in resolution order (later entries override earlier ones).</summary>
public sealed record TagPolicyLayerDto(TagRefDto Tag, int Priority, PolicyDto Policy);

// ---------------------------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------------------------

public sealed record EndpointSummaryDto(
    Guid Id,
    string Hostname,
    Guid OrganizationId,
    string OrganizationName,
    Guid? SiteId,
    string? SiteName,
    EndpointStatus Status,
    string? OperatingSystem,
    string? OsVersion,
    string? OsBuild,
    string? Architecture,
    string? AgentVersion,
    bool AgentOutdated,
    bool IsOnline,
    DateTimeOffset? LastCheckInAt,
    DateTimeOffset? LastScanAt,
    ComplianceStatus ComplianceStatus,
    int MissingRequiredCount,
    int MissingTotalCount,
    int FailedCount,
    bool RebootPending,
    OsSupportStatus OsSupportStatus,
    string? CurrentActivity,
    string? LastSeenIp,
    string Platform = "Windows",
    int MissingDeferredCount = 0,
    IReadOnlyList<TagRefDto>? Tags = null,
    int KnownExploitedMissingCount = 0);

public sealed record CredentialDto(string CredentialId, string KeyFingerprint, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, DateTimeOffset? RevokedAt,
    string? RevokedReason, DateTimeOffset? LastUsedAt);

public sealed record EndpointDetailDto(
    EndpointSummaryDto Summary,
    string? DnsDomain,
    bool? DomainJoined,
    string? OsEdition,
    string? OsProductType,
    DateTimeOffset? OsInstallDate,
    string? SerialNumber,
    string? Manufacturer,
    string? Model,
    string? ProcessorName,
    long? TotalMemoryBytes,
    long? SystemDriveTotalBytes,
    long? SystemDriveFreeBytes,
    bool? IsVirtualMachine,
    string? TimeZoneId,
    DateTimeOffset? LastBootAt,
    DateTimeOffset? AgentInstalledAt,
    DateTimeOffset EnrolledAt,
    DateTimeOffset? LastInventoryAt,
    DateTimeOffset? LastScanAttemptAt,
    string? LastScanError,
    IReadOnlyList<string> RebootReasons,
    DateTimeOffset? RebootPendingSince,
    string? UpdateSourceType,
    string? UpdateSourceServer,
    bool MicrosoftUpdateRegistered,
    bool WufbPoliciesConfigured,
    int? DeferQualityUpdatesDays,
    int? DeferFeatureUpdatesDays,
    string? TargetReleaseVersion,
    string? AutomaticUpdatesMode,
    bool ManagedByMdm,
    string? WindowsUpdateServiceStartMode,
    string? WindowsUpdateServiceState,
    DateOnly? OsEndOfServicing,
    bool EsuLicenseDetected,
    EsuOverride EsuOverride,
    int InstalledCount,
    int PendingRebootUpdateCount,
    DateTimeOffset? ComplianceEvaluatedAt,
    string? Notes,
    IReadOnlyList<CredentialDto> Credentials,
    JobSummaryDto? ActiveJob,
    IReadOnlyList<string> AgentCapabilities,
    int? SignedInUsers,
    int? TrayConnectedSessions,
    WindowsUpdatePolicyReport? WindowsUpdatePolicy,
    DateTimeOffset? WindowsUpdatePolicyReportedAt,
    bool HasOwnPolicy,
    AgentUpdateInfoDto? AgentUpdate = null,
    LinuxDetailsDto? Linux = null,
    ApplicationUpdatesStatusDto? Applications = null,
    RestartDetailsDto? Restart = null,
    MacOSDetailsDto? MacOS = null);

/// <summary>What a pending restart is for. Null when no restart is pending.</summary>
/// <param name="Updates">Updates waiting for the restart.</param>
/// <param name="ServicingPackages">Pending Windows servicing packages that name no KB.</param>
/// <param name="FileOperations">Files Windows replaces or deletes during the restart (the first 25).</param>
/// <param name="FileOperationCount">All pending file operations.</param>
/// <param name="DetailsSupported">The agent reports what Windows has queued (Windows agent 1.5.3 and later). Without it only
/// installed updates that wait for the restart are known.</param>
public sealed record RestartDetailsDto(IReadOnlyList<RestartUpdateDto> Updates, IReadOnlyList<string> ServicingPackages,
    IReadOnlyList<EasyPatch.Contracts.Agent.PendingFileOperation> FileOperations, int FileOperationCount, bool DetailsSupported);

/// <param name="UpdateGuid">Null for a KB known only from a servicing package.</param>
/// <param name="Source"><c>Installed</c>: installed, takes effect after the restart; <c>WindowsUpdate</c>: Windows Update lists it as
/// waiting for the restart; <c>Servicing</c>: a pending Windows servicing package names its KB.</param>
public sealed record RestartUpdateDto(Guid? UpdateGuid, string Title, IReadOnlyList<string> KbNumbers, string Source, DateTimeOffset? InstalledAt);

/// <summary>Application (winget) update checks of a Windows endpoint. <c>Enabled</c>: the effective policy turns them on with
/// approved applications; <c>Supported</c>: the agent has the <c>app-updates</c> capability (1.4.0 and later).</summary>
/// <param name="WingetSetupError">Why the agent could not install winget (agent 1.7.0 and later).</param>
/// <param name="ServerCopyError">Why the server could not download its own copy of winget, shown with a setup error.</param>
public sealed record ApplicationUpdatesStatusDto(bool Enabled, bool Supported, int ApprovedApps, string? WingetVersion, DateTimeOffset? LastCheckAt,
    string? LastError, string? WingetSetupError = null, string? ServerCopyError = null);

/// <summary>Linux-only endpoint details (null for Windows and macOS endpoints).</summary>
/// <param name="KeyProtection">How the agent's private key is protected: systemd-creds-host or file-permissions.</param>
public sealed record LinuxDetailsDto(string? OsId, string? OsVersion, string? KernelVersion, string? PackageManager, string? KeyProtection);

/// <summary>macOS-only endpoint details (null for Windows and Linux endpoints). The macOS agent is experimental.</summary>
/// <param name="OsId">Always <c>macos</c>.</param>
/// <param name="OsVersion">The <c>sw_vers</c> ProductVersion, e.g. <c>15.7.2</c>.</param>
/// <param name="OsBuild">The macOS build (<c>sw_vers</c> BuildVersion, e.g. <c>24G325</c>).</param>
/// <param name="KernelVersion">The Darwin kernel release.</param>
/// <param name="PackageManager"><c>softwareupdate</c>.</param>
/// <param name="KeyProtection">How the agent's private key is protected (<c>file-permissions</c>).</param>
public sealed record MacOSDetailsDto(string? OsId, string? OsVersion, string? OsBuild, string? KernelVersion, string? PackageManager, string? KeyProtection);

/// <summary>Whether the endpoint's agent can update itself, and to what.</summary>
/// <param name="AvailableVersion">The version an agent update would install now (null when none).</param>
/// <param name="Code">Why no update is available (e.g. <c>agent_up_to_date</c>, <c>package_not_signed</c>).</param>
public sealed record AgentUpdateInfoDto(
    bool Supported,
    string? Architecture,
    IReadOnlyList<string> ReleaseKeyIds,
    bool AutomaticUpdates,
    string? AvailableVersion,
    string? Code,
    string? Message,
    string? PackageFormat = null);

public sealed record UpdateEndpointRequest(Guid? SiteId, string? Notes, EsuOverride? EsuOverride);

public sealed record RevokeEndpointRequest(string? Reason);

public sealed record JobOverlayDto(Guid JobId, JobStatus JobStatus, JobItemStatus ItemStatus, int? DownloadPercent, int? InstallPercent,
    JobType JobType = JobType.InstallUpdates);

public sealed record EndpointUpdateDto(
    Guid UpdateGuid,
    int RevisionNumber,
    string Title,
    string? Description,
    string? KbNumber,
    IReadOnlyList<string> KbNumbers,
    UpdateCategory Category,
    string? MsClassification,
    string? MsrcSeverity,
    DateTimeOffset? ReleaseDate,
    long? SizeBytes,
    bool RebootLikely,
    string? SupportUrl,
    EndpointUpdateState State,
    bool IsRequired,
    bool IsExcluded,
    DateTimeOffset FirstDetectedAt,
    DateTimeOffset StateChangedAt,
    DateTimeOffset? InstalledAt,
    int FailedAttempts,
    string? ErrorCode,
    string? ErrorMessage,
    JobOverlayDto? ActiveJob,
    PackageInfoDto? Package = null,
    DateTimeOffset? DeferredUntil = null,
    IReadOnlyList<string>? CveIds = null,
    bool KnownExploited = false,
    DateOnly? KevDueDate = null,
    string? HoldReason = null);

/// <summary>Linux package behind an update. <c>InstalledVersion</c> is the endpoint's version (endpoint views only).</summary>
public sealed record PackageInfoDto(string Name, string? Architecture, string? Version, string? InstalledVersion, string? Repository,
    IReadOnlyList<string> Advisories);

public sealed record UpdateHistoryDto(long Id, Guid? UpdateGuid, string Title, string? KbNumber, string Operation, int ResultCode, string Result, string? HResult,
    string? ErrorDescription, DateTimeOffset Date);

public sealed record EndpointEventDto(long Id, Guid EndpointId, string? Hostname, string Type, EventSeverity Severity, string Message, Guid? JobId,
    DateTimeOffset CreatedAt);

public sealed record InstallUpdatesRequest(InstallMode Mode, IReadOnlyList<Guid>? UpdateGuids, bool Force);

public sealed record ExclusionRequest(Guid UpdateGuid, string? Reason);

/// <param name="Block">Also exclude the update on the endpoint so EasyPatch does not install it again.</param>
public sealed record UninstallUpdateRequest(bool Block = true, string? Reason = null);

public sealed record BulkEndpointsRequest(IReadOnlyList<Guid> EndpointIds, bool Force);

/// <summary>Restart an endpoint now or at <c>ScheduledAt</c>. If it is offline, the restart is abandoned after <c>ExpiresAfterMinutes</c>.</summary>
public sealed record RestartRequest(
    RestartMode Mode,
    RestartCondition Condition,
    int? CountdownMinutes,
    int? DeadlineMinutes,
    DateTimeOffset? ScheduledAt,
    int? ExpiresAfterMinutes,
    bool Force);

/// <summary>Show a preset message. <c>RestartAt</c> fills in the <see cref="UserMessagePreset.RestartScheduled"/> text.</summary>
public sealed record NotifyRequest(UserMessagePreset Preset, DateTimeOffset? RestartAt);

public sealed record BulkRestartRequest(IReadOnlyList<Guid> EndpointIds, RestartRequest Restart);

/// <summary>An endpoint whose operating system reports a pending restart. <c>IsServer</c>: Windows Server or a domain controller;
/// <c>CanRestart</c>: the agent supports restart jobs (Windows agent 1.1.0 and later, Linux and macOS agents).</summary>
public sealed record RestartPendingEndpointDto(Guid Id, string Hostname, Guid? SiteId, string? SiteName, string Platform, string? OperatingSystem,
    bool IsServer, bool IsOnline, DateTimeOffset? RebootPendingSince, bool CanRestart);

/// <summary>The endpoints of an organization (or site) that need a restart. <c>Endpoints</c> holds at most 1000 of <c>Total</c>.</summary>
public sealed record RestartPendingDto(int Total, IReadOnlyList<RestartPendingEndpointDto> Endpoints);

/// <summary>Restart the listed endpoints, which the administrator confirmed, of an organization or one of its sites. Endpoints that
/// are not in the scope or no longer report a pending restart are skipped. The restart condition is always
/// <see cref="RestartCondition.OnlyIfPending"/>.</summary>
public sealed record RestartPendingRequest(Guid? SiteId, IReadOnlyList<Guid> EndpointIds, RestartRequest Restart);

public sealed record BulkNotifyRequest(IReadOnlyList<Guid> EndpointIds, NotifyRequest Message);

/// <param name="Version">A specific package version; the newest suitable package when omitted.</param>
public sealed record AgentUpdateRequest(string? Version);

public sealed record BulkAgentUpdateRequest(IReadOnlyList<Guid> EndpointIds, string? Version);

public sealed record UserMessagePresetDto(UserMessagePreset Preset, string Title, string Body, bool NeedsRestartTime);

public sealed record BulkItemResult(Guid EndpointId, string? Hostname, bool Success, Guid? JobId, string? ErrorCode, string? Message);

public sealed record BulkResultDto(int Succeeded, int Failed, IReadOnlyList<BulkItemResult> Results);

// ---------------------------------------------------------------------------------------------
// Fleet update management
// ---------------------------------------------------------------------------------------------

public sealed record FleetUpdateDto(
    Guid UpdateGuid,
    string Title,
    string? KbNumber,
    UpdateCategory Category,
    string? MsrcSeverity,
    DateTimeOffset? ReleaseDate,
    long? SizeBytes,
    int MissingCount,
    int FailedCount,
    int InstalledCount,
    int PendingRebootCount,
    int ExcludedCount,
    PackageInfoDto? Package = null,
    int CveCount = 0,
    bool KnownExploited = false,
    int ReofferedCount = 0,
    bool OnHold = false);

/// <param name="Holds">Active holds of the update the administrator can see (for every organization or one they can access).</param>
public sealed record FleetUpdateDetailDto(FleetUpdateDto Summary, string? Description, string? SupportUrl, IReadOnlyList<string> KbNumbers,
    IReadOnlyList<string> Products, string? MsClassification, bool RebootLikely, IReadOnlyList<Guid> SupersededUpdateGuids,
    IReadOnlyList<VulnerabilityDto>? Vulnerabilities = null, IReadOnlyList<UpdateHoldDto>? Holds = null);

/// <summary>An update EasyPatch does not install automatically. <c>OrganizationId</c> null: for every organization. Automatic holds
/// come from the rollout guard and carry the failure counts that triggered them.</summary>
public sealed record UpdateHoldDto(Guid Id, Guid UpdateGuid, string? Title, string? KbNumber, Guid? OrganizationId, string? OrganizationName,
    UpdateHoldSource Source, string Reason, int? FailedEndpoints, int? AttemptedEndpoints, DateTimeOffset CreatedAt, string CreatedBy,
    DateTimeOffset? ReleasedAt, string? ReleasedBy, bool CanRelease);

/// <param name="OrganizationId">The organization to hold the update for; null holds it for every organization (super administrators).</param>
public sealed record CreateUpdateHoldRequest(Guid? OrganizationId, string? Reason);

/// <summary>A CVE an update fixes. <c>Kev</c>: in the CISA Known Exploited Vulnerabilities catalog; <c>KevDueDate</c> is the
/// remediation date CISA sets for US federal agencies. Title, severity and CVSS come from MSRC (Windows CVEs only).</summary>
public sealed record VulnerabilityDto(string CveId, string? Title, string? Severity, decimal? CvssBase, bool MsrcExploited, bool Kev,
    DateOnly? KevDateAdded, DateOnly? KevDueDate, bool KevRansomware, string? KevName);

/// <summary>Synchronization state of a vulnerability feed (msrc, kev, debian).</summary>
public sealed record VulnerabilityFeedDto(string Name, DateTimeOffset? LastAttemptAt, DateTimeOffset? LastSuccessAt, string? LastError, string? Version,
    int ItemCount);

public sealed record FleetUpdateEndpointDto(
    Guid EndpointId,
    string Hostname,
    string OrganizationName,
    string? SiteName,
    bool IsOnline,
    EndpointUpdateState State,
    bool IsRequired,
    bool IsExcluded,
    int FailedAttempts,
    string? ErrorCode,
    string? ErrorMessage,
    DateTimeOffset StateChangedAt);

public sealed record FleetInstallRequest(Guid? OrganizationId, Guid? SiteId, IReadOnlyList<Guid>? EndpointIds);

/// <param name="Block">Also exclude the update on each endpoint so EasyPatch does not install it again.</param>
/// <param name="Hold">Also put the update on hold so EasyPatch does not install it automatically on other endpoints: for the organization,
/// or for every organization when none is given (super administrators).</param>
public sealed record FleetUninstallRequest(Guid? OrganizationId, Guid? SiteId, IReadOnlyList<Guid>? EndpointIds, bool Block = true, string? Reason = null,
    bool Hold = false);

// ---------------------------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------------------------

public sealed record JobSummaryDto(
    Guid Id,
    Guid EndpointId,
    string Hostname,
    Guid OrganizationId,
    string OrganizationName,
    JobType Type,
    JobStatus Status,
    JobTrigger Trigger,
    string RequestedBy,
    DateTimeOffset CreatedAt,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt,
    DateTimeOffset ExpiresAt,
    int? ProgressPercent,
    string? Phase,
    string? ProgressMessage,
    string? ErrorCode,
    string? ErrorMessage,
    bool RebootRequired,
    bool TimedOut,
    bool CancelRequested,
    int ItemCount,
    int SucceededCount,
    int FailedCount);

public sealed record JobItemDto(
    Guid UpdateGuid,
    string Title,
    string? KbNumber,
    UpdateCategory Category,
    JobItemStatus Status,
    string? SkipReason,
    int? ResultCode,
    string? ErrorCode,
    string? ErrorMessage,
    bool RebootRequired,
    int? DownloadPercent,
    int? InstallPercent,
    DateTimeOffset? StartedAt,
    DateTimeOffset? CompletedAt);

public sealed record JobDetailDto(
    JobSummaryDto Summary,
    InstallMode? InstallMode,
    DateTimeOffset? NotBefore,
    DateTimeOffset? DeliveredAt,
    DateTimeOffset? AcknowledgedAt,
    DateTimeOffset? LastProgressAt,
    int DeliveryCount,
    Guid? RetryOfJobId,
    DateTimeOffset? CancelRequestedAt,
    IReadOnlyList<JobItemDto> Items,
    IReadOnlyList<EndpointEventDto> Events);

// ---------------------------------------------------------------------------------------------
// Agent management
// ---------------------------------------------------------------------------------------------

public sealed record EnrollmentTokenDto(
    Guid Id,
    Guid OrganizationId,
    string OrganizationName,
    Guid? SiteId,
    string? SiteName,
    string TokenPrefix,
    string? Description,
    int MaxUses,
    int UseCount,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? LastUsedAt,
    DateTimeOffset? RevokedAt,
    string State);

public sealed record CreateTokensRequest(Guid OrganizationId, Guid? SiteId, string? Description, int ExpiresInHours, int MaxUses, int Count);

/// <param name="LinuxEnrollCommand">Enrolls an installed Linux agent; the token is piped in so it never shows in the process list.</param>
/// <param name="MacEnrollCommand">Enrolls an installed macOS agent (experimental) the same way; null when the server has no
/// macOS (pkg) agent package.</param>
public sealed record CreatedTokenDto(EnrollmentTokenDto Token, string PlaintextToken, string MsiExecCommand, string? LinuxEnrollCommand = null,
    string? MacEnrollCommand = null);

/// <param name="MacOneLiner"><c>curl … | sudo sh</c> command that installs the experimental macOS agent; null (like
/// <paramref name="MacScriptUrl"/>) when the server has no macOS (pkg) agent package.</param>
public sealed record DeploymentCodeDto(
    Guid Id,
    string Code,
    string Name,
    Guid OrganizationId,
    string OrganizationName,
    Guid? SiteId,
    string? SiteName,
    int MaxPendingRequests,
    IReadOnlyList<string> AllowedSourceCidrs,
    DateTimeOffset CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RevokedAt,
    int PendingCount,
    int ApprovedCount,
    string State,
    string OneLiner,
    string ScriptUrl,
    string? LinuxOneLiner = null,
    string? LinuxScriptUrl = null,
    string? MacOneLiner = null,
    string? MacScriptUrl = null);

public sealed record CreateDeploymentCodeRequest(Guid OrganizationId, Guid? SiteId, string Name, int? ExpiresInDays, IReadOnlyList<string>? AllowedSourceCidrs,
    int? MaxPendingRequests);

public sealed record InstallScriptResponse(string Script, string OneLiner, string ScriptUrl, string PackageFileName, string PackageVersion, string Sha256,
    bool RequireSignature, string Platform = "Windows", bool SkipCertificateCheck = false);

public sealed record EnrollmentRequestDto(
    Guid Id,
    string RequestId,
    string Hostname,
    string KeyFingerprint,
    string? SerialNumber,
    string? Manufacturer,
    string? Model,
    string? OsCaption,
    string AgentVersion,
    string? SourceIp,
    EnrollmentRequestStatus Status,
    Guid OrganizationId,
    string OrganizationName,
    Guid? SiteId,
    string? SiteName,
    string DeploymentCodeName,
    DateTimeOffset CreatedAt,
    DateTimeOffset LastSeenAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? DecidedAt,
    string? RejectReason,
    Guid? EndpointId,
    Guid? ExistingEndpointId);

public sealed record ApproveRequest(Guid? OrganizationId, Guid? SiteId);

public sealed record RejectRequest(string? Reason);

public sealed record BulkApproveRequest(IReadOnlyList<Guid> Ids);

/// <param name="ReleaseKeyId">The release key in the package's <c>.sig</c> file (null: not signed, so agents will not
/// update to it).</param>
public sealed record AgentPackageDto(string FileName, string Version, string Architecture, long SizeBytes, string Sha256, DateTimeOffset ModifiedAt,
    string DownloadUrl, bool IsLatest, string? ReleaseKeyId = null, string? SignatureProblem = null, string Format = "msi");

public sealed record AgentVersionCountDto(string Version, int Count, bool IsLatest);

// ---------------------------------------------------------------------------------------------
// Dashboard and reports
// ---------------------------------------------------------------------------------------------

public sealed record DashboardSummaryDto(
    int Organizations,
    int Endpoints,
    int Online,
    int Offline,
    int Compliant,
    int MissingUpdates,
    int FailedUpdates,
    int RebootRequired,
    int ScanStale,
    int NeverScanned,
    double CompliancePercent,
    int MissingRequiredUpdates,
    int QueuedJobs,
    int RunningJobs,
    int FailedJobs24h,
    int PendingApprovals,
    int UnsupportedOs,
    int OutdatedAgents,
    IReadOnlyList<OrganizationSummaryDto> LeastCompliantOrganizations,
    int KnownExploitedEndpoints = 0);

public sealed record ComplianceReportRow(
    Guid EndpointId,
    string Hostname,
    string OrganizationName,
    string? SiteName,
    string? OperatingSystem,
    string? OsBuild,
    ComplianceStatus ComplianceStatus,
    int MissingRequiredCount,
    int MissingTotalCount,
    int FailedCount,
    bool RebootPending,
    bool IsOnline,
    OsSupportStatus OsSupportStatus,
    DateTimeOffset? LastScanAt,
    DateTimeOffset? LastCheckInAt,
    string Platform = "Windows");

public sealed record ComplianceReportDto(
    int Total,
    int Compliant,
    double CompliancePercent,
    IReadOnlyDictionary<ComplianceStatus, int> ByStatus,
    IReadOnlyList<ComplianceReportRow> Rows);

public sealed record ComplianceTrendPoint(DateOnly Date, int TotalEndpoints, int Compliant, int MissingUpdates, int FailedUpdates, int RebootRequired, int ScanStale,
    int NeverScanned, int Offline, int MissingRequiredUpdates, double CompliancePercent);

public sealed record InstallationReportRow(
    Guid JobId,
    Guid EndpointId,
    string Hostname,
    string OrganizationName,
    string? SiteName,
    Guid UpdateGuid,
    string Title,
    string? KbNumber,
    UpdateCategory Category,
    JobItemStatus Status,
    string? SkipReason,
    string? ErrorCode,
    string? ErrorMessage,
    bool RebootRequired,
    string RequestedBy,
    DateTimeOffset? CompletedAt);

public sealed record AuditLogDto(long Id, Guid? UserId, string? Username, Guid? OrganizationId, Guid? EndpointId, string Action, string? TargetType, string? TargetId,
    string? Details, string? IpAddress, string? CorrelationId, DateTimeOffset CreatedAt);

public sealed record OsLifecycleDto(Guid Id, string Product, string EditionGroup, int BuildNumber, string VersionLabel, DateOnly EndOfServicing, DateOnly? EsuEndDate,
    string? Notes);

public sealed record OsLifecycleRequest(string Product, string EditionGroup, int BuildNumber, string VersionLabel, DateOnly EndOfServicing, DateOnly? EsuEndDate,
    string? Notes);

public sealed record ServerInfoDto(string Version, string PublicUrl, DateTimeOffset ServerTime);

/// <summary>Monthly report schedule of an organization. <c>NextReportDate</c> is a date in the organization's time zone.</summary>
public sealed record ReportScheduleDto(
    Guid OrganizationId, bool Enabled, IReadOnlyList<string> Recipients, int DayOfMonth, bool IncludeEndpointList, DateTimeOffset? EnabledAt,
    DateOnly? LastScheduledPeriod, DateOnly? NextReportDate, DateOnly? NextReportPeriod, string TimeZone, DateTimeOffset? UpdatedAt);

public sealed record ReportScheduleRequest(bool Enabled, IReadOnlyList<string>? Recipients, int DayOfMonth, bool IncludeEndpointList);

public sealed record MonthlyReportDto(
    Guid Id, Guid OrganizationId, string OrganizationName, DateOnly PeriodStart, DateOnly PeriodEnd, bool MonthToDate, bool Scheduled,
    DateTimeOffset GeneratedAt, string? GeneratedBy, string FileName, long SizeBytes, string Sha256, DeliveryStatus? DeliveryStatus,
    IReadOnlyList<string> Recipients, int Attempts, DateTimeOffset? QueuedAt, DateTimeOffset? SentAt, string? LastError);

public sealed record GenerateReportRequest(Guid OrganizationId, int Year, int Month, bool? IncludeEndpointList = null);

public sealed record SendReportRequest(IReadOnlyList<string>? Recipients = null);
