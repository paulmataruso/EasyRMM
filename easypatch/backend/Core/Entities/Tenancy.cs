namespace EasyPatch.Core.Entities;

public sealed class Organization
{
    public Guid Id { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public string? ContactName { get; set; }
    public string? ContactEmail { get; set; }
    public string? Notes { get; set; }

    /// <summary>IANA time zone used for maintenance windows of endpoints without a site.</summary>
    public string TimeZone { get; set; } = "UTC";
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? ArchivedAt { get; set; }
    public List<Site> Sites { get; set; } = [];
}

public sealed class Site
{
    public Guid Id { get; set; }
    public Guid OrganizationId { get; set; }
    public Organization? Organization { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public string? Address { get; set; }

    /// <summary>IANA time zone used for maintenance windows.</summary>
    public string TimeZone { get; set; } = "UTC";
    public bool IsActive { get; set; } = true;
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public DateTimeOffset? ArchivedAt { get; set; }
}

/// <summary>Layered policy. Global row has every field set; organization, site and endpoint rows override non-null fields.</summary>
public sealed class Policy
{
    public Guid Id { get; set; }
    public PolicyScope Scope { get; set; }
    public Guid? OrganizationId { get; set; }
    public Guid? SiteId { get; set; }
    public Guid? EndpointId { get; set; }
    public Guid? TagId { get; set; }

    public int? CheckInIntervalSeconds { get; set; }
    public int? ScanIntervalMinutes { get; set; }
    public int? InventoryIntervalMinutes { get; set; }
    public int? JitterPercent { get; set; }

    /// <summary>Allowed <see cref="EasyPatch.Contracts.UpdateCategory"/> names for automatic / "install all".</summary>
    public List<string>? AllowedCategories { get; set; }
    public bool? IncludeOptional { get; set; }

    /// <summary>KB numbers excluded at this level (merged across levels).</summary>
    public List<string> ExcludedKbs { get; set; } = [];
    public bool? AcceptEulas { get; set; }

    public bool? AutoInstallEnabled { get; set; }

    /// <summary>Automatic installs wait until a non-security update has been available this many days (rollout delay).</summary>
    public int? InstallDelayDays { get; set; }

    /// <summary>Rollout delay for security updates.</summary>
    public int? SecurityInstallDelayDays { get; set; }

    /// <summary>Updates that fix a CISA known-exploited vulnerability are required at once, without the rollout delay.</summary>
    public bool? KnownExploitedSkipsDelay { get; set; }

    /// <summary>Maintenance window days (0 = Sunday … 6 = Saturday). Window fields override as a unit.</summary>
    public List<int>? MaintenanceDays { get; set; }
    public TimeOnly? MaintenanceStart { get; set; }
    public int? MaintenanceDurationMinutes { get; set; }

    /// <summary>With automatic installation: download the updates this many hours before the maintenance window opens (0 = off).</summary>
    public int? PreDownloadHours { get; set; }

    public int? ScanStaleAfterHours { get; set; }
    public int? MaxConcurrentInstallsPerSite { get; set; }

    public bool? TrayIconEnabled { get; set; }
    public bool? InstallNotificationsEnabled { get; set; }

    /// <summary>Agents install new signed agent versions on their own (false: only when an administrator asks).</summary>
    public bool? AgentAutoUpdateEnabled { get; set; }

    /// <summary>Recurring restart, overriding the level above as a unit (null = inherit).</summary>
    public Domain.RestartScheduleSettings? RestartSchedule { get; set; }

    /// <summary>Windows Update settings to enforce, per group (a missing group inherits).</summary>
    public Domain.PolicyWindowsUpdate? WindowsUpdate { get; set; }

    /// <summary>Third-party application updates (winget), overriding the level above as a unit (null = inherit).</summary>
    public Domain.ApplicationUpdateSettings? ApplicationUpdates { get; set; }

    public DateTimeOffset UpdatedAt { get; set; }
    public Guid? UpdatedByUserId { get; set; }
}

/// <summary>Singleton row holding <see cref="Domain.ServerSettings"/> as JSON.</summary>
public sealed class ServerSettingsRow
{
    public int Id { get; set; } = 1;
    public required string Data { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public Guid? UpdatedByUserId { get; set; }
}

public sealed class OsLifecycleEntry
{
    public Guid Id { get; set; }

    /// <summary>"Windows 10", "Windows 11", "Windows Server", or a Linux distribution ("Debian", "Ubuntu",
    /// "Red Hat Enterprise Linux", "Rocky Linux", "AlmaLinux", "Oracle Linux").</summary>
    public required string Product { get; set; }

    /// <summary>HomePro, EnterpriseEducation, LTSC, IoTLTSC, Server, LTS (Ubuntu) or Any.</summary>
    public required string EditionGroup { get; set; }

    /// <summary>Windows build number; for Linux the release (major version, or YYMM for Ubuntu).</summary>
    public int BuildNumber { get; set; }
    public required string VersionLabel { get; set; }
    public DateOnly EndOfServicing { get; set; }

    /// <summary>Last day paid Extended Security Updates are available, if an ESU program exists.</summary>
    public DateOnly? EsuEndDate { get; set; }
    public string? Notes { get; set; }
}

public sealed class ComplianceSnapshot
{
    public long Id { get; set; }
    public DateOnly Date { get; set; }
    public Guid OrganizationId { get; set; }
    public int TotalEndpoints { get; set; }
    public int Compliant { get; set; }
    public int MissingUpdates { get; set; }
    public int FailedUpdates { get; set; }
    public int RebootRequired { get; set; }
    public int ScanStale { get; set; }
    public int NeverScanned { get; set; }
    public int Offline { get; set; }
    public int MissingRequiredUpdates { get; set; }
}
