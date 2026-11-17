using EasyPatch.Contracts;

namespace EasyPatch.Core.Entities;

/// <summary>Catalog entry for one revision of a Windows update, or one version of a Linux package for one distribution
/// release.</summary>
public sealed class Update
{
    public Guid Id { get; set; }
    public Guid UpdateGuid { get; set; }
    public int RevisionNumber { get; set; }
    public required string Title { get; set; }
    public string? Description { get; set; }
    public List<string> KbNumbers { get; set; } = [];
    public UpdateCategory Category { get; set; }
    public string? MsClassification { get; set; }
    public List<string> Products { get; set; } = [];
    public string? MsrcSeverity { get; set; }

    /// <summary>WUA LastDeploymentChangeTime (closest proxy to release date).</summary>
    public DateTimeOffset? ReleaseDate { get; set; }
    public long? MaxDownloadSizeBytes { get; set; }
    public bool IsDriver { get; set; }
    public bool IsOptional { get; set; }
    public bool IsMandatory { get; set; }
    public int? RebootBehavior { get; set; }
    public string? SupportUrl { get; set; }
    public List<Guid> SupersededUpdateGuids { get; set; } = [];

    /// <summary>Linux: package name (null for Windows updates).</summary>
    public string? PackageName { get; set; }

    /// <summary>Linux: the version this update installs.</summary>
    public string? PackageVersion { get; set; }

    /// <summary>Linux: package architecture (amd64, x86_64, noarch, …).</summary>
    public string? PackageArchitecture { get; set; }

    /// <summary>Linux: repository the version comes from.</summary>
    public string? PackageRepository { get; set; }

    /// <summary>Linux: distribution advisories (e.g. RHSA-2024:1234).</summary>
    public List<string> Advisories { get; set; } = [];

    /// <summary>Debian and Ubuntu: source package (reported by agent 1.4.0 and later).</summary>
    public string? PackageSource { get; set; }

    /// <summary>CVEs the update fixes on at least one endpoint (for display; at most 200). Exposure is tracked per endpoint
    /// in <see cref="EndpointUpdate.CveIds"/>.</summary>
    public List<string> CveIds { get; set; } = [];

    /// <summary>The update fixes a CISA known-exploited vulnerability on at least one endpoint.</summary>
    public bool KnownExploited { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }

    public string? PrimaryKb => KbNumbers.Count > 0 ? KbNumbers[0] : null;
}

/// <summary>State of one update on one endpoint. Unique per (endpoint, update GUID).</summary>
public sealed class EndpointUpdate
{
    public Guid Id { get; set; }
    public Guid EndpointId { get; set; }
    public Guid UpdateGuid { get; set; }

    /// <summary>Catalog row of the most recently reported revision.</summary>
    public Guid UpdateId { get; set; }
    public Update? Update { get; set; }
    public EndpointUpdateState State { get; set; }

    /// <summary>Policy says this update should be installed (counts toward compliance).</summary>
    public bool IsRequired { get; set; }
    public bool IsExcluded { get; set; }
    public DateTimeOffset FirstDetectedAt { get; set; }
    public DateTimeOffset LastDetectedAt { get; set; }
    public DateTimeOffset StateChangedAt { get; set; }
    public DateTimeOffset? InstalledAt { get; set; }
    public Guid? LastScanId { get; set; }
    public Guid? LastJobId { get; set; }
    public DateTimeOffset? LastAttemptAt { get; set; }
    public int FailedAttempts { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }

    /// <summary>Linux: the package version installed at the latest scan that reported this update.</summary>
    public string? InstalledVersion { get; set; }

    /// <summary>Start of the rollout delay: when the fleet first saw this update, or earlier when it replaced an update that
    /// was still outstanding on this endpoint (so a long delay still makes progress across monthly or weekly releases).</summary>
    public DateTimeOffset? DelayBasisAt { get; set; }

    /// <summary>Set while policy allows the update but its rollout delay has not passed; it is not required until then.</summary>
    public DateTimeOffset? DeferredUntil { get; set; }

    /// <summary>CVEs this update fixes on this endpoint (at most 200): from MSRC for Windows, from the agent's dnf
    /// advisories for RHEL-family and Fedora, from the Debian Security Tracker for Debian.</summary>
    public List<string> CveIds { get; set; } = [];

    /// <summary>One of <see cref="CveIds"/> is in the CISA KEV catalog.</summary>
    public bool KnownExploited { get; set; }

    /// <summary>Earliest CISA due date among the known-exploited CVEs.</summary>
    public DateOnly? KevDueDate { get; set; }
}

public sealed class UpdateExclusion
{
    public Guid Id { get; set; }
    public Guid EndpointId { get; set; }
    public Guid UpdateGuid { get; set; }
    public string? Reason { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public Guid? CreatedByUserId { get; set; }
}

public enum UpdateHoldSource
{
    /// <summary>The rollout guard held it because installations failed on too many endpoints.</summary>
    Automatic,

    /// <summary>An administrator held it.</summary>
    Manual,
}

/// <summary>
/// An update held back from automatic installation: scheduled installs and "install all" skip it, and jobs queued before the hold
/// skip it when they are delivered. Installing it explicitly is still possible. A hold applies to one organization, or to every
/// organization when <see cref="OrganizationId"/> is null, until it is released.
/// </summary>
public sealed class UpdateHold
{
    public Guid Id { get; set; }
    public Guid UpdateGuid { get; set; }
    public Guid? OrganizationId { get; set; }
    public UpdateHoldSource Source { get; set; }
    public required string Reason { get; set; }

    /// <summary>Automatic holds: endpoints where the latest installation of the update failed, and endpoints that tried it.</summary>
    public int? FailedEndpoints { get; set; }
    public int? AttemptedEndpoints { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public Guid? CreatedByUserId { get; set; }
    public required string CreatedBy { get; set; }
    public DateTimeOffset? ReleasedAt { get; set; }
    public Guid? ReleasedByUserId { get; set; }
    public string? ReleasedBy { get; set; }
}

public sealed class UpdateScan
{
    public Guid Id { get; set; }
    public Guid EndpointId { get; set; }
    public Guid AgentScanId { get; set; }
    public Guid? JobId { get; set; }
    public ScanTrigger Trigger { get; set; }
    public ScanStatus Status { get; set; }
    public DateTimeOffset StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset ReceivedAt { get; set; }
    public int TotalInstalled { get; set; }
    public int TotalMissing { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
    public string? UpdateSource { get; set; }
}

public sealed class UpdateHistoryEntry
{
    public long Id { get; set; }
    public Guid EndpointId { get; set; }
    public Guid? UpdateGuid { get; set; }
    public int? RevisionNumber { get; set; }
    public required string Title { get; set; }
    public string? KbNumber { get; set; }
    public required string Operation { get; set; }
    public int ResultCode { get; set; }
    public string? HResult { get; set; }
    public DateTimeOffset Date { get; set; }
    public string? ClientApplicationId { get; set; }

    /// <summary>Dedupe key: hash of endpoint-independent identity fields.</summary>
    public required string Fingerprint { get; set; }
}

public sealed class Job
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Guid EndpointId { get; set; }
    public Endpoint? Endpoint { get; set; }
    public Guid? SiteId { get; set; }
    public JobType Type { get; set; }
    public JobStatus Status { get; set; }
    public JobTrigger Trigger { get; set; }
    public Guid? RequestedByUserId { get; set; }
    public required string RequestedBy { get; set; }
    public int Priority { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public DateTimeOffset? DeliveredAt { get; set; }
    public DateTimeOffset? LeaseExpiresAt { get; set; }
    public DateTimeOffset? AcknowledgedAt { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset? LastProgressAt { get; set; }
    public int DeliveryCount { get; set; }
    public int RetryCount { get; set; }
    public Guid? RetryOfJobId { get; set; }

    /// <summary>JSON payload (e.g. <see cref="EasyPatch.Contracts.Agent.InstallUpdatesPayload"/>).</summary>
    public string? Payload { get; set; }

    /// <summary>JSON <see cref="EasyPatch.Contracts.Agent.JobResultSummary"/>.</summary>
    public string? Result { get; set; }
    public int? ProgressPercent { get; set; }
    public string? Phase { get; set; }
    public string? ProgressMessage { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
    public string? DedupeKey { get; set; }
    public long LastSequence { get; set; }
    public bool RebootRequired { get; set; }
    public bool TimedOut { get; set; }
    public DateTimeOffset? CancelRequestedAt { get; set; }
    public Guid? CancelRequestedByUserId { get; set; }

    /// <summary>PostgreSQL xmin optimistic concurrency token.</summary>
    public uint Version { get; set; }

    public List<JobUpdate> Updates { get; set; } = [];
}

public sealed class JobUpdate
{
    public Guid Id { get; set; }
    public Guid JobId { get; set; }
    public Guid UpdateGuid { get; set; }
    public int RevisionNumber { get; set; }
    public required string Title { get; set; }
    public string? KbNumber { get; set; }
    public UpdateCategory Category { get; set; }
    public JobItemStatus Status { get; set; }
    public string? SkipReason { get; set; }
    public int? ResultCode { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
    public bool RebootRequired { get; set; }
    public int? DownloadPercent { get; set; }
    public int? InstallPercent { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? CompletedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
