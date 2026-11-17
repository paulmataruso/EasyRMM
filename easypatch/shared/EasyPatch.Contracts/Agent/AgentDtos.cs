using EasyPatch.Contracts.Policy;

namespace EasyPatch.Contracts.Agent;

// ---------------------------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------------------------

/// <summary>First request from a new agent. Exactly one of <see cref="EnrollmentToken"/> or
/// <see cref="DeploymentCode"/> must be supplied.</summary>
public sealed record EnrollRequest
{
    /// <summary>Secret, use-limited token (immediate activation).</summary>
    public string? EnrollmentToken { get; init; }

    /// <summary>Non-secret deployment code (creates a pending request that an admin must approve).</summary>
    public string? DeploymentCode { get; init; }

    /// <summary>Base64 SubjectPublicKeyInfo of the agent's ECDSA P-256 key. The private key never leaves the device.</summary>
    public required string PublicKey { get; init; }

    public required string AgentVersion { get; init; }

    public required DeviceIdentity Device { get; init; }
}

/// <summary>Operating system families the agent runs on.</summary>
public static class AgentPlatforms
{
    public const string Windows = "Windows";
    public const string Linux = "Linux";

    /// <summary>The macOS agent (1.9.0 and later). Experimental: in development and not for production use.</summary>
    public const string MacOS = "macOS";

    /// <summary>The platform an agent reported: <see cref="Windows"/> when it did not say (agents before 1.3.0 only ran on
    /// Windows), null for an unknown value.</summary>
    public static string? Normalize(string? platform) => platform switch
    {
        null => Windows,
        Windows or Linux or MacOS => platform,
        _ => null,
    };
}

public sealed record DeviceIdentity
{
    public required string Hostname { get; init; }
    public string? DnsDomain { get; init; }
    public string? SmbiosUuid { get; init; }
    public string? SerialNumber { get; init; }
    public string? Manufacturer { get; init; }
    public string? Model { get; init; }
    public string? OsCaption { get; init; }
    public string? OsBuild { get; init; }
    public string? Architecture { get; init; }

    /// <summary><see cref="AgentPlatforms"/> value; absent from Windows agents before 1.3.0.</summary>
    public string? Platform { get; init; }

    /// <summary>Linux: os-release <c>ID</c>, e.g. <c>ubuntu</c>, <c>debian</c>, <c>rhel</c>, <c>rocky</c>; <c>macos</c> on macOS.</summary>
    public string? OsId { get; init; }

    /// <summary>Linux: os-release <c>VERSION_ID</c>, e.g. <c>24.04</c>, <c>12</c>, <c>9.4</c>; macOS: <c>sw_vers</c> ProductVersion, e.g. <c>15.7.2</c>.</summary>
    public string? OsVersion { get; init; }
}

/// <summary>Returned by enroll and by the pending-enrollment status poll.</summary>
public sealed record EnrollResponse
{
    public required EnrollmentState State { get; init; }

    /// <summary><c>c_…</c> for an active credential, <c>r_…</c> for a pending enrollment request.</summary>
    public required string CredentialId { get; init; }

    public Guid? EndpointId { get; init; }
    public Guid? OrganizationId { get; init; }
    public DateTimeOffset? CredentialExpiresAt { get; init; }
    public AgentConfig? Config { get; init; }
    public required string KeyFingerprint { get; init; }
    public string? Message { get; init; }
    public DateTimeOffset ServerTime { get; init; }
}

// ---------------------------------------------------------------------------------------------
// Check-in (heartbeat + job poll)
// ---------------------------------------------------------------------------------------------

public sealed record AgentConfig
{
    public int CheckInIntervalSeconds { get; init; } = 60;
    public int ActiveJobCheckInIntervalSeconds { get; init; } = 15;
    public int ScanIntervalMinutes { get; init; } = 360;
    public int InventoryIntervalMinutes { get; init; } = 1440;
    public int JitterPercent { get; init; } = 10;

    public UserExperienceConfig UserExperience { get; init; } = new();

    /// <summary>Windows Update settings to enforce. Null (or a null group) means leave Windows' configuration alone.</summary>
    public WindowsUpdatePolicySettings? WindowsUpdate { get; init; }

    /// <summary>Third-party application updates (winget, Windows agents 1.4.0 and later). Null: off.</summary>
    public ApplicationUpdatesConfig? Applications { get; init; }
}

/// <summary>Which applications the agent checks for newer versions. Only applications already installed are upgraded;
/// nothing is ever installed that was not there before.</summary>
public sealed record ApplicationUpdatesConfig
{
    public bool Enabled { get; init; }

    /// <summary>winget package IDs (see <see cref="ApplicationIds.IsValid"/>).</summary>
    public IReadOnlyList<string> ApprovedApps { get; init; } = [];
}

public sealed record CheckInRequest
{
    public required string AgentVersion { get; init; }
    public DateTimeOffset? LastBootAt { get; init; }
    public bool RebootPending { get; init; }
    public IReadOnlyList<string> RebootReasons { get; init; } = [];

    /// <summary>What is queued for the restart (Windows agent 1.5.3 and later; only while <see cref="RebootPending"/>).</summary>
    public RebootDetails? RebootDetails { get; init; }

    /// <summary>Jobs the agent currently holds in its durable state. Server re-delivers any in-flight job not listed.</summary>
    public IReadOnlyList<Guid> ActiveJobIds { get; init; } = [];

    /// <summary>Short human-readable activity, e.g. "Idle", "Scanning", "Installing KB5044284".</summary>
    public string? CurrentActivity { get; init; }

    /// <summary><see cref="AgentCapabilities"/> this agent supports. Agents that send none get only the original job types.</summary>
    public IReadOnlyList<string> Capabilities { get; init; } = [];

    public UserSessionInfo? Sessions { get; init; }

    /// <summary>Windows Update policy enforcement status; sent only when it has changed.</summary>
    public WindowsUpdatePolicyReport? WindowsUpdatePolicy { get; init; }

    /// <summary>Package architecture of this agent build (<c>x64</c> or <c>arm64</c>): agent updates use the same one.</summary>
    public string? AgentArchitecture { get; init; }

    /// <summary>IDs of the release keys this agent accepts updates from (see <see cref="AgentRelease.KeyId"/>).
    /// Empty when the agent cannot update itself.</summary>
    public IReadOnlyList<string> ReleaseKeyIds { get; init; } = [];

    /// <summary>Package format agent updates must use (<see cref="AgentRelease.FormatMsi"/>, <c>deb</c> or <c>rpm</c>).
    /// Absent from agents before 1.3.0, which are all Windows (MSI).</summary>
    public string? AgentPackageFormat { get; init; }

    /// <summary>The machine-wide winget (Windows agent 1.7.0 and later, once it has checked).</summary>
    public WingetStatusReport? Winget { get; init; }
}

public sealed record CheckInResponse
{
    public DateTimeOffset ServerTime { get; init; }
    public required AgentConfig Config { get; init; }

    /// <summary>Jobs to execute (newly leased or re-delivered). The agent processes them one at a time.</summary>
    public IReadOnlyList<AgentJob> Jobs { get; init; } = [];

    /// <summary>Jobs the agent holds that an administrator asked to cancel.</summary>
    public IReadOnlyList<Guid> CancelJobIds { get; init; } = [];

    /// <summary>The credential is close to expiry; the agent should rotate its key.</summary>
    public bool RotateCredential { get; init; }

    public AgentVersionInfo? LatestAgent { get; init; }
}

public sealed record AgentVersionInfo
{
    public required string Version { get; init; }
    public string? FileName { get; init; }
    public string? Sha256 { get; init; }
}

// ---------------------------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------------------------

public sealed record AgentJob
{
    public required Guid JobId { get; init; }
    public required JobType Type { get; init; }
    public JobTrigger Trigger { get; init; }
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }

    /// <summary>Present for <see cref="JobType.InstallUpdates"/> and <see cref="JobType.DownloadUpdates"/>.</summary>
    public InstallUpdatesPayload? Install { get; init; }

    /// <summary>Present for <see cref="JobType.Restart"/>.</summary>
    public RestartPayload? Restart { get; init; }

    /// <summary>Present for <see cref="JobType.NotifyUser"/>.</summary>
    public NotifyUserPayload? Notify { get; init; }

    /// <summary>Present for <see cref="JobType.AgentUpdate"/>.</summary>
    public AgentUpdatePayload? AgentUpdate { get; init; }

    /// <summary>Present for <see cref="JobType.UninstallUpdate"/>.</summary>
    public UninstallUpdatePayload? UninstallUpdate { get; init; }
}

/// <summary>The one installed update a <see cref="JobType.UninstallUpdate"/> job removes.</summary>
public sealed partial record UninstallUpdatePayload
{
    public required Guid UpdateGuid { get; init; }
    public required string Title { get; init; }

    /// <summary>Digits only (no "KB" prefix); needed to find the update's servicing package when Windows Update cannot remove it.</summary>
    public string? KbNumber { get; init; }

    /// <summary>Reported back on the job item unchanged.</summary>
    public UpdateCategory Category { get; init; }

    public static bool IsValid(UninstallUpdatePayload? payload) =>
        payload is not null && payload.UpdateGuid != Guid.Empty && !string.IsNullOrWhiteSpace(payload.Title) && payload.Title.Length <= 1000 &&
        (payload.KbNumber is null || KbDigits().IsMatch(payload.KbNumber));

    [System.Text.RegularExpressions.GeneratedRegex(@"^\d{1,10}$")]
    private static partial System.Text.RegularExpressions.Regex KbDigits();
}

public sealed record InstallUpdatesPayload
{
    public InstallMode Mode { get; init; }
    public IReadOnlyList<Guid> SelectedUpdateGuids { get; init; } = [];
    public required InstallFilterOptions Filter { get; init; }

    /// <summary>Do not start installing new updates after this time (end of a maintenance window). For a download job: do not
    /// start new downloads after this time (start of the maintenance window).</summary>
    public DateTimeOffset? NotAfter { get; init; }
}

public sealed record InstallFilterOptions
{
    public IReadOnlyList<UpdateCategory> Categories { get; init; } = [];
    public bool IncludeOptional { get; init; }
    public IReadOnlyList<string> ExcludedKbs { get; init; } = [];
    public IReadOnlyList<Guid> ExcludedUpdateGuids { get; init; } = [];
    public bool AcceptEulas { get; init; } = true;

    /// <summary>winget package IDs whose updates may be installed (empty: none). Agents before 1.4.0 ignore it; they never
    /// report application updates.</summary>
    public IReadOnlyList<string> ApprovedApplications { get; init; } = [];
}

public sealed record JobAckResponse
{
    public bool Accepted { get; init; }
    public string? Reason { get; init; }
}

/// <summary>Progress / result report. <see cref="Sequence"/> increases monotonically per job; the
/// server ignores reports with a sequence it has already processed.</summary>
public sealed record JobStatusReport
{
    public required long Sequence { get; init; }
    public required JobStatus Status { get; init; }
    public string? Phase { get; init; }
    public int? Percent { get; init; }
    public string? Message { get; init; }
    public string? ErrorCode { get; init; }
    public string? ErrorMessage { get; init; }
    public bool RebootRequired { get; init; }
    public IReadOnlyList<JobItemReport> Items { get; init; } = [];
    public JobResultSummary? Result { get; init; }
}

public sealed record JobItemReport
{
    public required Guid UpdateGuid { get; init; }
    public int RevisionNumber { get; init; }
    public required string Title { get; init; }
    public string? KbNumber { get; init; }
    public UpdateCategory Category { get; init; }
    public required JobItemStatus Status { get; init; }

    /// <summary>One of <see cref="SkipReasons"/> when <see cref="Status"/> is Skipped.</summary>
    public string? SkipReason { get; init; }

    /// <summary>WUA OperationResultCode (0 NotStarted, 1 InProgress, 2 Succeeded, 3 SucceededWithErrors, 4 Failed, 5 Aborted).</summary>
    public int? ResultCode { get; init; }

    /// <summary>HRESULT formatted as 0xXXXXXXXX.</summary>
    public string? ErrorCode { get; init; }
    public string? ErrorMessage { get; init; }
    public bool RebootRequired { get; init; }

    /// <summary>How much of the update has downloaded (0-100), when the update source reports it.</summary>
    public int? DownloadPercent { get; init; }

    /// <summary>How much of the update has installed (0-100), when the update source reports it.</summary>
    public int? InstallPercent { get; init; }

    public DateTimeOffset? StartedAt { get; init; }
    public DateTimeOffset? CompletedAt { get; init; }
}

public sealed record JobResultSummary
{
    public int Planned { get; init; }
    public int Succeeded { get; init; }
    public int Failed { get; init; }
    public int Skipped { get; init; }
    public bool RebootRequired { get; init; }
    public Guid? PostInstallScanId { get; init; }
}

public static class SkipReasons
{
    public const string AlreadyInstalled = "AlreadyInstalled";
    public const string PendingReboot = "PendingReboot";
    public const string NotApplicable = "NotApplicable";
    public const string NotSelected = "NotSelected";
    public const string CategoryNotAllowed = "CategoryNotAllowed";
    public const string OptionalNotAllowed = "OptionalNotAllowed";
    public const string Excluded = "Excluded";
    public const string RequiresUserInput = "RequiresUserInput";
    public const string EulaNotAccepted = "EulaNotAccepted";
    public const string MaintenanceWindowClosed = "MaintenanceWindowClosed";
    public const string Cancelled = "Cancelled";
    public const string ApplicationNotApproved = "ApplicationNotApproved";

    /// <summary>Server only: Windows offered the update again after a successful installation; only installed when selected.</summary>
    public const string Reoffered = "Reoffered";

    /// <summary>An uninstall job found the update not installed (already removed).</summary>
    public const string NotInstalled = "NotInstalled";

    /// <summary>Server only: the update is on hold (rollout guard or an administrator); only installed when selected.</summary>
    public const string Held = "Held";

    /// <summary>A download job reached the start of the maintenance window first; the installation downloads the update.</summary>
    public const string WindowStarted = "WindowStarted";

    public static string Describe(string? reason) => reason switch
    {
        AlreadyInstalled => "Already installed",
        PendingReboot => "Installed, waiting for a restart",
        NotApplicable => "No longer offered by the update source",
        NotSelected => "Not selected",
        CategoryNotAllowed => "Category not allowed by policy",
        OptionalNotAllowed => "Optional update not allowed by policy",
        Excluded => "Excluded",
        RequiresUserInput => "Requires interactive user input",
        EulaNotAccepted => "License agreement not accepted by policy",
        MaintenanceWindowClosed => "Maintenance window closed",
        ApplicationNotApproved => "Application not approved by policy",
        Reoffered => "Offered again after a successful installation (select it to install it anyway)",
        NotInstalled => "Not installed",
        Held => "On hold (not installed automatically)",
        WindowStarted => "Not downloaded before the maintenance window started (the installation downloads it)",
        Cancelled => "Cancelled",
        null => "",
        _ => reason,
    };
}

// ---------------------------------------------------------------------------------------------
// Scans and history
// ---------------------------------------------------------------------------------------------

public sealed record ScanResultReport
{
    /// <summary>Agent-generated ID; makes ingestion idempotent across retries.</summary>
    public required Guid ScanId { get; init; }
    public Guid? JobId { get; init; }
    public ScanTrigger Trigger { get; init; }
    public DateTimeOffset StartedAt { get; init; }
    public DateTimeOffset CompletedAt { get; init; }
    public bool Succeeded { get; init; }
    public string? ErrorCode { get; init; }
    public string? ErrorMessage { get; init; }
    public UpdateSourceInfo? Source { get; init; }

    /// <summary>Result of "IsInstalled=0 and IsHidden=0" (includes updates installed but awaiting reboot,
    /// flagged with <see cref="ReportedUpdate.RebootRequired"/>).</summary>
    public IReadOnlyList<ReportedUpdate> Missing { get; init; } = [];

    /// <summary>Result of "IsInstalled=1".</summary>
    public IReadOnlyList<ReportedUpdate> Installed { get; init; } = [];

    /// <summary>Outcome of the application (winget) part of the scan; null when application updates are off.</summary>
    public ApplicationScanReport? Applications { get; init; }
}

/// <summary>Application updates in a scan. When <see cref="Succeeded"/> is false the server keeps the application states
/// it knew rather than treating unreported applications as gone.</summary>
public sealed record ApplicationScanReport
{
    public bool Succeeded { get; init; }
    public string? ErrorCode { get; init; }
    public string? ErrorMessage { get; init; }

    /// <summary>winget version, e.g. <c>1.9.25200</c>.</summary>
    public string? WingetVersion { get; init; }

    /// <summary>Approved applications checked.</summary>
    public int Checked { get; init; }
}

public sealed record ReportedUpdate
{
    public required Guid UpdateGuid { get; init; }
    public int RevisionNumber { get; init; }
    public required string Title { get; init; }
    public string? Description { get; init; }
    public IReadOnlyList<string> KbNumbers { get; init; } = [];
    public IReadOnlyList<UpdateCategoryRef> Categories { get; init; } = [];
    public bool IsDriver { get; init; }
    public bool BrowseOnly { get; init; }
    public bool IsMandatory { get; init; }
    public bool IsDownloaded { get; init; }
    public bool IsInstalled { get; init; }

    /// <summary>WUA IUpdate.RebootRequired: installed, but a restart is required to complete it.</summary>
    public bool RebootRequired { get; init; }
    public bool EulaAccepted { get; init; } = true;
    public bool CanRequestUserInput { get; init; }

    /// <summary>InstallationBehavior.RebootBehavior: 0 NeverReboots, 1 AlwaysRequiresReboot, 2 CanRequestReboot.</summary>
    public int? RebootBehavior { get; init; }
    public string? MsrcSeverity { get; init; }

    /// <summary>IUpdate.LastDeploymentChangeTime — closest available proxy for a release date.</summary>
    public DateTimeOffset? LastDeploymentChangeTime { get; init; }
    public long? MaxDownloadSize { get; init; }
    public string? SupportUrl { get; init; }
    public IReadOnlyList<Guid> SupersededUpdateGuids { get; init; } = [];

    /// <summary>Linux: the package this update upgrades. Null for Windows updates.</summary>
    public PackageUpdateInfo? Package { get; init; }

    /// <summary>Windows: the third-party application this update upgrades (winget). Null for Windows Update updates.</summary>
    public ApplicationUpdateInfo? Application { get; init; }
}

/// <summary>A newer version of an installed application, from the winget community repository. The update's GUID identifies
/// this version of this package (<see cref="ApplicationIds.UpdateGuidFor"/>).</summary>
public sealed record ApplicationUpdateInfo
{
    /// <summary>winget package ID, e.g. <c>Mozilla.Firefox</c>.</summary>
    public required string Id { get; init; }

    /// <summary>The version this update installs.</summary>
    public required string Version { get; init; }

    /// <summary>The version installed when the scan ran.</summary>
    public string? InstalledVersion { get; init; }

    /// <summary>Always <c>winget</c> (the community repository; the Microsoft Store source is never used).</summary>
    public string Source { get; init; } = ApplicationIds.Source;
}

/// <summary>A newer version of an installed Linux package. The update's GUID identifies exactly this version of the
/// package for this distribution release, so the same upgrade on two machines is the same update.</summary>
public sealed record PackageUpdateInfo
{
    /// <summary>Package name without architecture, e.g. <c>openssl</c>.</summary>
    public required string Name { get; init; }

    /// <summary>Package architecture as the package manager names it (<c>amd64</c>, <c>x86_64</c>, <c>noarch</c>, …).</summary>
    public required string Architecture { get; init; }

    /// <summary>The version this upgrade installs (Debian version or RPM <c>epoch:version-release</c>).</summary>
    public required string Version { get; init; }

    /// <summary>The version installed when the scan ran.</summary>
    public string? InstalledVersion { get; init; }

    /// <summary>Where the new version comes from, e.g. <c>Debian-Security:12/bookworm-security</c> or <c>baseos</c>.</summary>
    public string? Repository { get; init; }

    /// <summary>True when the upgrade includes a security fix (a security repository or a security advisory).</summary>
    public bool Security { get; init; }

    /// <summary>Distribution advisories the upgrade resolves, e.g. <c>RLSA-2024:1234</c> (dnf only).</summary>
    public IReadOnlyList<string> Advisories { get; init; } = [];

    /// <summary>CVE IDs fixed between the installed version and this version, from the distribution's advisories (dnf,
    /// agent 1.4.0 and later; at most <see cref="MaxCves"/>). Empty when unknown.</summary>
    public IReadOnlyList<string> Cves { get; init; } = [];

    /// <summary>Debian and Ubuntu: the source package the binary package is built from (e.g. <c>openssl</c> for
    /// <c>libssl3</c>), used to look up security tracker data (agent 1.4.0 and later).</summary>
    public string? SourcePackage { get; init; }

    public const int MaxCves = 200;
}

public sealed record UpdateCategoryRef
{
    public Guid Id { get; init; }
    public required string Name { get; init; }

    /// <summary>WUA category type, e.g. "UpdateClassification", "Product", "ProductFamily", "Company".</summary>
    public string? Type { get; init; }
}

public sealed record UpdateSourceInfo
{
    public UpdateSourceType Type { get; init; }
    public string? WsusServer { get; init; }
    public bool MicrosoftUpdateRegistered { get; init; }
    public bool WufbPoliciesConfigured { get; init; }
    public int? DeferQualityUpdatesDays { get; init; }
    public int? DeferFeatureUpdatesDays { get; init; }
    public string? TargetReleaseVersion { get; init; }

    /// <summary>NotConfigured, Disabled, NotifyDownload, AutoDownloadNotifyInstall, AutoDownloadScheduleInstall, LocalAdminChooses, Unknown.</summary>
    public string? AutomaticUpdatesMode { get; init; }
    public bool ManagedByMdm { get; init; }
}

public sealed record HistoryReport
{
    public IReadOnlyList<HistoryEntryReport> Entries { get; init; } = [];
}

public sealed record HistoryEntryReport
{
    public Guid? UpdateGuid { get; init; }
    public int? RevisionNumber { get; init; }
    public required string Title { get; init; }
    public string? KbNumber { get; init; }

    /// <summary>Installation, Uninstallation or Other.</summary>
    public required string Operation { get; init; }

    /// <summary>WUA OperationResultCode.</summary>
    public int ResultCode { get; init; }
    public string? HResult { get; init; }
    public DateTimeOffset Date { get; init; }
    public string? ClientApplicationId { get; init; }
}

// ---------------------------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------------------------

public sealed record InventoryReport
{
    public required string Hostname { get; init; }
    public string? DnsDomain { get; init; }
    public bool? DomainJoined { get; init; }
    public string? OsCaption { get; init; }

    /// <summary>Registry EditionID, e.g. Professional, Enterprise, EnterpriseS, ServerStandard.</summary>
    public string? OsEdition { get; init; }

    /// <summary>Registry DisplayVersion, e.g. 24H2.</summary>
    public string? OsDisplayVersion { get; init; }
    public int? OsBuildNumber { get; init; }
    public int? OsUbr { get; init; }

    /// <summary>Workstation, DomainController or Server.</summary>
    public string? OsProductType { get; init; }
    public DateTimeOffset? OsInstallDate { get; init; }
    public string? Architecture { get; init; }
    public string? Manufacturer { get; init; }
    public string? Model { get; init; }
    public string? SerialNumber { get; init; }
    public string? SmbiosUuid { get; init; }
    public string? ProcessorName { get; init; }
    public long? TotalMemoryBytes { get; init; }
    public long? SystemDriveTotalBytes { get; init; }
    public long? SystemDriveFreeBytes { get; init; }
    public DateTimeOffset? LastBootAt { get; init; }
    public string? TimeZoneId { get; init; }
    public bool? IsVirtualMachine { get; init; }
    public bool? EsuLicenseDetected { get; init; }
    public IReadOnlyList<string> EsuLicenseNames { get; init; } = [];
    public string? WindowsUpdateServiceStartMode { get; init; }
    public string? WindowsUpdateServiceState { get; init; }
    public required string AgentVersion { get; init; }
    public DateTimeOffset? AgentInstalledAt { get; init; }
    public bool RebootPending { get; init; }
    public IReadOnlyList<string> RebootReasons { get; init; } = [];

    /// <summary>What is queued for the restart (Windows agent 1.5.3 and later; only while <see cref="RebootPending"/>).</summary>
    public RebootDetails? RebootDetails { get; init; }
    public UpdateSourceInfo? UpdateSource { get; init; }

    /// <summary><see cref="AgentPlatforms"/> value; absent from Windows agents before 1.3.0.</summary>
    public string? Platform { get; init; }

    /// <summary>Linux: os-release <c>ID</c> (<c>ubuntu</c>, <c>debian</c>, <c>rhel</c>, <c>rocky</c>, <c>almalinux</c>, <c>ol</c>); <c>macos</c> on macOS.</summary>
    public string? OsId { get; init; }

    /// <summary>Linux: os-release <c>VERSION_ID</c>; macOS: <c>sw_vers</c> ProductVersion (<c>15.7.2</c>).</summary>
    public string? OsVersion { get; init; }

    /// <summary>macOS: the build (<c>sw_vers</c> BuildVersion, e.g. <c>24G325</c>).</summary>
    public string? OsBuildVersion { get; init; }

    /// <summary>Linux: running kernel release (<c>uname -r</c>); macOS: the Darwin kernel release.</summary>
    public string? KernelVersion { get; init; }

    /// <summary>Linux: <c>apt</c> or <c>dnf</c>; macOS: <c>softwareupdate</c>.</summary>
    public string? PackageManager { get; init; }

    /// <summary>How the agent's private key is protected at rest: <c>dpapi</c>, <c>systemd-creds-tpm2</c>,
    /// <c>systemd-creds-host</c> or <c>file-permissions</c>.</summary>
    public string? KeyProtection { get; init; }
}

// ---------------------------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------------------------

public sealed record RotateCredentialRequest
{
    public required string PublicKey { get; init; }
}

public sealed record RotateCredentialResponse
{
    public required string CredentialId { get; init; }
    public DateTimeOffset ExpiresAt { get; init; }
    public required string KeyFingerprint { get; init; }
}

public sealed record UnenrollRequest
{
    public string? Reason { get; init; }
}

/// <summary>Machine-readable error codes in ProblemDetails "code" for agent routes.</summary>
public static class AgentErrorCodes
{
    public const string InvalidSignature = "invalid_signature";
    public const string ClockSkew = "clock_skew";
    public const string ReplayedNonce = "replayed_nonce";
    public const string UnknownCredential = "unknown_credential";
    public const string CredentialRevoked = "credential_revoked";
    public const string CredentialExpired = "credential_expired";
    public const string EndpointRevoked = "endpoint_revoked";
    public const string EnrollmentInvalid = "enrollment_invalid";
    public const string EnrollmentRejected = "enrollment_rejected";
    public const string JobNotFound = "job_not_found";
    public const string JobCancelled = "job_cancelled";
    public const string RateLimited = "rate_limited";
    public const string ValidationFailed = "validation_failed";
}

public static class AgentRoutes
{
    public const string Prefix = "api/v1/agents";
    public const string Enroll = Prefix + "/enroll";
    public const string EnrollmentStatus = Prefix + "/enrollment/status";
    public const string CheckIn = Prefix + "/check-in";
    public const string Inventory = Prefix + "/inventory";
    public const string ScanResults = Prefix + "/updates/scan-results";
    public const string History = Prefix + "/updates/history";
    public const string RotateCredential = Prefix + "/credentials/rotate";
    public const string Unenroll = Prefix + "/unenroll";

    public static string JobAck(Guid jobId) => $"{Prefix}/jobs/{jobId:D}/ack";
    public static string JobStatus(Guid jobId) => $"{Prefix}/jobs/{jobId:D}/status";
}
