namespace EasyPatch.Core.Entities;

public sealed class Endpoint
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Organization? Organization { get; set; }
    public Guid? SiteId { get; set; }
    public Site? Site { get; set; }
    public EndpointStatus Status { get; set; } = EndpointStatus.Active;

    /// <summary><see cref="EasyPatch.Contracts.Agent.AgentPlatforms"/>: Windows, Linux or macOS (experimental).</summary>
    public string Platform { get; set; } = EasyPatch.Contracts.Agent.AgentPlatforms.Windows;

    // Identity / inventory
    public required string Hostname { get; set; }
    public string? DnsDomain { get; set; }
    public bool? DomainJoined { get; set; }
    public string? OperatingSystem { get; set; }
    public string? OsEdition { get; set; }
    public string? OsVersion { get; set; }
    public string? OsBuild { get; set; }
    public int? OsBuildNumber { get; set; }
    public string? OsProductType { get; set; }
    public DateTimeOffset? OsInstallDate { get; set; }
    public string? Architecture { get; set; }
    public string? SerialNumber { get; set; }
    public string? Manufacturer { get; set; }
    public string? Model { get; set; }
    public string? SmbiosUuid { get; set; }
    public string? ProcessorName { get; set; }
    public long? TotalMemoryBytes { get; set; }
    public long? SystemDriveTotalBytes { get; set; }
    public long? SystemDriveFreeBytes { get; set; }
    public bool? IsVirtualMachine { get; set; }
    public string? TimeZoneId { get; set; }
    public DateTimeOffset? LastBootAt { get; set; }

    /// <summary>Linux: os-release ID (ubuntu, debian, rhel, rocky, almalinux, ol); macos on macOS.</summary>
    public string? OsId { get; set; }

    /// <summary>Linux: running kernel release; macOS: the Darwin kernel release.</summary>
    public string? KernelVersion { get; set; }

    /// <summary>Linux: apt or dnf; macOS: softwareupdate.</summary>
    public string? PackageManager { get; set; }

    /// <summary>Windows: version of the machine-wide winget, from the last application update check (agent 1.4.0 and
    /// later) or the agent's own winget check at check-in (1.7.0 and later).</summary>
    public string? WingetVersion { get; set; }

    /// <summary>Windows: why the agent could not install winget (agent 1.7.0 and later); null when winget is ready.</summary>
    public string? WingetSetupError { get; set; }

    /// <summary>When the agent last checked applications for updates.</summary>
    public DateTimeOffset? ApplicationScanAt { get; set; }

    /// <summary>Why the last application update check failed (null after a successful one or when application updates are off).</summary>
    public string? ApplicationScanError { get; set; }

    /// <summary>How the agent protects its private key at rest (dpapi, systemd-creds-host, file-permissions).</summary>
    public string? KeyProtection { get; set; }

    // Agent
    public string? AgentVersion { get; set; }
    public DateTimeOffset? AgentInstalledAt { get; set; }
    public DateTimeOffset EnrolledAt { get; set; }
    public Guid? EnrollmentTokenId { get; set; }
    public Guid? EnrollmentRequestId { get; set; }
    public DateTimeOffset? LastCheckInAt { get; set; }
    public string? LastSeenIp { get; set; }
    public bool IsOnline { get; set; }
    public string? CurrentActivity { get; set; }
    public DateTimeOffset? LastInventoryAt { get; set; }

    // Windows Update state
    public DateTimeOffset? LastScanAt { get; set; }
    public DateTimeOffset? LastScanAttemptAt { get; set; }
    public string? LastScanError { get; set; }
    public bool RebootPending { get; set; }
    public List<string> RebootReasons { get; set; } = [];

    /// <summary>JSON <see cref="EasyPatch.Contracts.Agent.RebootDetails"/>: the updates, servicing packages and files the pending
    /// restart is for (Windows agent 1.5.3 and later); null when no restart is pending or the agent does not report them.</summary>
    public string? RebootDetails { get; set; }
    public DateTimeOffset? RebootPendingSince { get; set; }
    public string? UpdateSourceType { get; set; }
    public string? UpdateSourceServer { get; set; }
    public bool MicrosoftUpdateRegistered { get; set; }
    public bool WufbPoliciesConfigured { get; set; }
    public int? DeferQualityUpdatesDays { get; set; }
    public int? DeferFeatureUpdatesDays { get; set; }
    public string? TargetReleaseVersion { get; set; }
    public string? AutomaticUpdatesMode { get; set; }
    public bool ManagedByMdm { get; set; }
    public string? WindowsUpdateServiceStartMode { get; set; }
    public string? WindowsUpdateServiceState { get; set; }

    /// <summary><see cref="EasyPatch.Contracts.Agent.AgentCapabilities"/> from the latest check-in.</summary>
    public List<string> AgentCapabilities { get; set; } = [];

    /// <summary>Package architecture of the agent build (<c>x64</c> or <c>arm64</c>), for agent updates.</summary>
    public string? AgentArchitecture { get; set; }

    /// <summary>Package format agent updates must use (msi, deb, rpm or pkg).</summary>
    public string? AgentPackageFormat { get; set; }

    /// <summary>Release keys the agent accepts updates from (<see cref="EasyPatch.Contracts.Agent.AgentRelease.KeyId"/>).</summary>
    public List<string> AgentReleaseKeyIds { get; set; } = [];
    public int? SignedInUsers { get; set; }
    public int? TrayConnectedSessions { get; set; }

    /// <summary>Latest <see cref="EasyPatch.Contracts.Policy.WindowsUpdatePolicyReport"/> (JSON).</summary>
    public string? WindowsUpdatePolicyStatus { get; set; }
    public DateTimeOffset? WindowsUpdatePolicyReportedAt { get; set; }

    // Lifecycle
    public OsSupportStatus OsSupportStatus { get; set; }
    public DateOnly? OsEndOfServicing { get; set; }
    public bool EsuLicenseDetected { get; set; }
    public EsuOverride EsuOverride { get; set; }

    // Denormalized compliance (recomputed after scans, job results and policy changes)
    public ComplianceStatus ComplianceStatus { get; set; } = ComplianceStatus.NeverScanned;
    public int MissingRequiredCount { get; set; }
    public int MissingTotalCount { get; set; }
    public int FailedCount { get; set; }
    public int InstalledCount { get; set; }
    public int PendingRebootUpdateCount { get; set; }

    /// <summary>Missing updates policy allows but whose rollout delay has not passed (not counted as required).</summary>
    public int MissingDeferredCount { get; set; }

    /// <summary>Missing updates that fix a vulnerability in the CISA Known Exploited Vulnerabilities catalog (excluded
    /// updates and updates outside the policy's categories do not count).</summary>
    public int KnownExploitedMissingCount { get; set; }
    public DateTimeOffset? ComplianceEvaluatedAt { get; set; }

    public string? Notes { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

public sealed class AgentCredential
{
    public Guid Id { get; set; }

    /// <summary>Public identifier sent in X-EasyPatch-Credential (c_…).</summary>
    public required string CredentialId { get; set; }
    public Guid EndpointId { get; set; }
    public Endpoint? Endpoint { get; set; }

    /// <summary>SubjectPublicKeyInfo of the device's ECDSA P-256 key. No secret material is stored.</summary>
    public required byte[] PublicKey { get; set; }
    public required string Algorithm { get; set; }
    public required string KeyFingerprint { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
    public Guid? ReplacedById { get; set; }
}

public sealed class EnrollmentToken
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid? SiteId { get; set; }
    public required string TokenHash { get; set; }

    /// <summary>First characters of the token for identification in the UI.</summary>
    public required string TokenPrefix { get; set; }
    public string? Description { get; set; }
    public int MaxUses { get; set; } = 1;
    public int UseCount { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public Guid? CreatedByUserId { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? LastUsedAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

/// <summary>Non-secret code used by the tokenless PowerShell/RMM installer. Enrollments require admin approval.</summary>
public sealed class DeploymentCode
{
    public Guid Id { get; set; }
    public required string Code { get; set; }
    public required string Name { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid? SiteId { get; set; }
    public int MaxPendingRequests { get; set; } = 500;

    /// <summary>Optional CIDR allow-list (e.g. the customer's public IPs).</summary>
    public List<string> AllowedSourceCidrs { get; set; } = [];
    public DateTimeOffset CreatedAt { get; set; }
    public Guid? CreatedByUserId { get; set; }
    public DateTimeOffset? ExpiresAt { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
}

public sealed class EnrollmentRequest
{
    public Guid Id { get; set; }

    /// <summary>Public identifier (r_…) the pending agent signs status polls with.</summary>
    public required string RequestId { get; set; }
    public Guid DeploymentCodeId { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid? SiteId { get; set; }
    public required byte[] PublicKey { get; set; }
    public required string KeyFingerprint { get; set; }
    public required string Hostname { get; set; }

    /// <summary>JSON of the reported <see cref="EasyPatch.Contracts.Agent.DeviceIdentity"/>.</summary>
    public required string DeviceJson { get; set; }
    public string? SerialNumber { get; set; }
    public string? OsCaption { get; set; }
    public required string AgentVersion { get; set; }
    public string? SourceIp { get; set; }
    public EnrollmentRequestStatus Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset LastSeenAt { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? DecidedAt { get; set; }
    public Guid? DecidedByUserId { get; set; }
    public string? RejectReason { get; set; }
    public Guid? EndpointId { get; set; }
}

public sealed class EndpointEvent
{
    public long Id { get; set; }
    public Guid EndpointId { get; set; }
    public Guid OrganizationId { get; set; }
    public required string Type { get; set; }
    public EventSeverity Severity { get; set; }
    public required string Message { get; set; }
    public string? Details { get; set; }
    public Guid? JobId { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
}
