using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Policy;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Entities;

namespace EasyPatch.Core.Domain;

public sealed record MaintenanceWindowSettings(IReadOnlyList<DayOfWeek> Days, TimeOnly Start, int DurationMinutes)
{
    public bool IsConfigured => Days.Count > 0 && DurationMinutes > 0;
}

/// <summary>Fully resolved policy for one endpoint, with the scope each value came from.</summary>
public sealed record EffectivePolicy
{
    public int CheckInIntervalSeconds { get; init; }
    public int ScanIntervalMinutes { get; init; }
    public int InventoryIntervalMinutes { get; init; }
    public int JitterPercent { get; init; }
    public IReadOnlyList<UpdateCategory> AllowedCategories { get; init; } = [];
    public bool IncludeOptional { get; init; }
    public IReadOnlyList<string> ExcludedKbs { get; init; } = [];
    public bool AcceptEulas { get; init; }
    public bool AutoInstallEnabled { get; init; }

    /// <summary>Rollout delay (days) for non-security updates; 0 = install as soon as they are found.</summary>
    public int InstallDelayDays { get; init; }

    /// <summary>Rollout delay (days) for security updates.</summary>
    public int SecurityInstallDelayDays { get; init; }

    /// <summary>Updates fixing a CISA known-exploited vulnerability skip the rollout delay.</summary>
    public bool KnownExploitedSkipsDelay { get; init; } = true;

    public bool HasInstallDelay => InstallDelayDays > 0 || SecurityInstallDelayDays > 0;
    public MaintenanceWindowSettings? MaintenanceWindow { get; init; }

    /// <summary>Hours before the maintenance window opens to download the updates (Windows agents); 0 = off.</summary>
    public int PreDownloadHours { get; init; }
    public int ScanStaleAfterHours { get; init; }
    public int MaxConcurrentInstallsPerSite { get; init; }
    public bool TrayIconEnabled { get; init; } = true;
    public bool InstallNotificationsEnabled { get; init; } = true;

    /// <summary>The agent installs newer signed agent packages on its own.</summary>
    public bool AgentAutoUpdateEnabled { get; init; } = true;

    /// <summary>Enabled recurring restart, or null.</summary>
    public RestartScheduleSettings? RestartSchedule { get; init; }

    /// <summary>Windows Update settings to enforce (null groups are not managed).</summary>
    public WindowsUpdatePolicySettings WindowsUpdate { get; init; } = new();

    /// <summary>Third-party application updates (winget); off unless enabled with approved applications.</summary>
    public ApplicationUpdateSettings ApplicationUpdates { get; init; } = new();
    public IReadOnlyDictionary<string, PolicyScope> Sources { get; init; } = new Dictionary<string, PolicyScope>();

    /// <summary>For values that came from a tag policy: the tag's name.</summary>
    public IReadOnlyDictionary<string, string> SourceTags { get; init; } = new Dictionary<string, string>();

    public AgentConfig ToAgentConfig() => new()
    {
        CheckInIntervalSeconds = CheckInIntervalSeconds,
        ActiveJobCheckInIntervalSeconds = Math.Min(15, CheckInIntervalSeconds),
        ScanIntervalMinutes = ScanIntervalMinutes,
        InventoryIntervalMinutes = InventoryIntervalMinutes,
        JitterPercent = JitterPercent,
        UserExperience = new UserExperienceConfig { TrayIcon = TrayIconEnabled, InstallNotifications = InstallNotificationsEnabled },
        WindowsUpdate = Enum.GetValues<WindowsUpdatePolicyGroup>().Any(WindowsUpdate.IsManaged) ? WindowsUpdate : null,
        Applications = ApplicationUpdates.IsActive ? new ApplicationUpdatesConfig { Enabled = true, ApprovedApps = ApplicationUpdates.ApprovedApps } : null,
    };

    public InstallFilterOptions ToFilter(IEnumerable<Guid>? excludedUpdateGuids = null) => new()
    {
        Categories = AllowedCategories,
        IncludeOptional = IncludeOptional,
        ExcludedKbs = ExcludedKbs,
        ExcludedUpdateGuids = excludedUpdateGuids?.ToArray() ?? [],
        AcceptEulas = AcceptEulas,
        ApprovedApplications = ApplicationUpdates.IsActive ? ApplicationUpdates.ApprovedApps : [],
    };
}

public static class PolicyDefaults
{
    public static Policy CreateGlobal(DateTimeOffset now) => new()
    {
        Id = Guid.Parse("00000000-0000-0000-0000-000000000001"),
        Scope = PolicyScope.Global,
        CheckInIntervalSeconds = 60,
        ScanIntervalMinutes = 360,
        InventoryIntervalMinutes = 1440,
        JitterPercent = 10,
        AllowedCategories = UpdateClassifier.DefaultInstallCategories.Select(c => c.ToString()).ToList(),
        IncludeOptional = false,
        ExcludedKbs = [],
        AcceptEulas = true,
        AutoInstallEnabled = false,
        InstallDelayDays = 0,
        SecurityInstallDelayDays = 0,
        KnownExploitedSkipsDelay = true,
        MaintenanceDays = [],
        MaintenanceStart = new TimeOnly(2, 0),
        MaintenanceDurationMinutes = 180,
        PreDownloadHours = 0,
        ScanStaleAfterHours = 48,
        MaxConcurrentInstallsPerSite = 10,
        TrayIconEnabled = true,
        InstallNotificationsEnabled = true,
        AgentAutoUpdateEnabled = true,
        UpdatedAt = now,
    };
}

/// <summary>A tag's policy layer for one endpoint.</summary>
public sealed record TagPolicyLayer(string TagName, int Priority, Policy Policy);

public static class PolicyResolver
{
    /// <summary>Order in which tag layers are applied: lower priority first, so the highest priority wins; on equal priority
    /// the tag whose name sorts first wins.</summary>
    public static IEnumerable<TagPolicyLayer> OrderTags(IEnumerable<TagPolicyLayer> tags) =>
        tags.OrderBy(t => t.Priority).ThenByDescending(t => t.TagName, StringComparer.OrdinalIgnoreCase);

    /// <summary>Resolves global → organization → site → tags → endpoint. Scalars: most specific non-null wins.
    /// Excluded KB lists are merged. The maintenance window, the restart schedule and each Windows Update group
    /// override as a unit.</summary>
    public static EffectivePolicy Resolve(Policy global, Policy? organization, Policy? site, Policy? endpoint = null,
        IReadOnlyList<TagPolicyLayer>? tags = null)
    {
        ArgumentNullException.ThrowIfNull(global);
        var sources = new Dictionary<string, PolicyScope>();
        var sourceTags = new Dictionary<string, string>();
        var layers = new List<(Policy Policy, PolicyScope Scope, string? TagName)> { (global, PolicyScope.Global, null) };
        if (organization is not null)
        {
            layers.Add((organization, PolicyScope.Organization, null));
        }

        if (site is not null)
        {
            layers.Add((site, PolicyScope.Site, null));
        }

        foreach (var tag in OrderTags(tags ?? []))
        {
            layers.Add((tag.Policy, PolicyScope.Tag, tag.TagName));
        }

        if (endpoint is not null)
        {
            layers.Add((endpoint, PolicyScope.Endpoint, null));
        }

        void Source(string name, PolicyScope scope, string? tagName)
        {
            sources[name] = scope;
            if (tagName is null)
            {
                sourceTags.Remove(name);
            }
            else
            {
                sourceTags[name] = tagName;
            }
        }

        T Pick<T>(string name, Func<Policy, T?> selector, T fallback)
            where T : struct
        {
            var value = fallback;
            Source(name, PolicyScope.Global, null);
            foreach (var (policy, layerScope, tagName) in layers)
            {
                if (selector(policy) is { } v)
                {
                    value = v;
                    Source(name, layerScope, tagName);
                }
            }

            return value;
        }

        IReadOnlyList<UpdateCategory> categories = UpdateClassifier.DefaultInstallCategories;
        Source(nameof(EffectivePolicy.AllowedCategories), PolicyScope.Global, null);
        foreach (var (policy, layerScope, tagName) in layers)
        {
            if (policy.AllowedCategories is { } names)
            {
                categories = ParseCategories(names);
                Source(nameof(EffectivePolicy.AllowedCategories), layerScope, tagName);
            }
        }

        MaintenanceWindowSettings? window = null;
        Source(nameof(EffectivePolicy.MaintenanceWindow), PolicyScope.Global, null);
        foreach (var (policy, layerScope, tagName) in layers)
        {
            if (policy.MaintenanceDays is { } days)
            {
                window = new MaintenanceWindowSettings(
                    days.Where(d => d is >= 0 and <= 6).Distinct().Order().Select(d => (DayOfWeek)d).ToArray(),
                    policy.MaintenanceStart ?? new TimeOnly(2, 0),
                    policy.MaintenanceDurationMinutes ?? 180);
                Source(nameof(EffectivePolicy.MaintenanceWindow), layerScope, tagName);
            }
        }

        RestartScheduleSettings? restart = null;
        Source(nameof(EffectivePolicy.RestartSchedule), PolicyScope.Global, null);
        foreach (var (policy, layerScope, tagName) in layers)
        {
            if (policy.RestartSchedule is { } schedule)
            {
                restart = schedule;
                Source(nameof(EffectivePolicy.RestartSchedule), layerScope, tagName);
            }
        }

        var applications = new ApplicationUpdateSettings();
        Source(nameof(EffectivePolicy.ApplicationUpdates), PolicyScope.Global, null);
        foreach (var (policy, layerScope, tagName) in layers)
        {
            if (policy.ApplicationUpdates is { } apps)
            {
                applications = apps;
                Source(nameof(EffectivePolicy.ApplicationUpdates), layerScope, tagName);
            }
        }

        T? Group<T>(string name, Func<PolicyWindowsUpdate, PolicyGroupSetting<T>?> selector)
            where T : class
        {
            T? value = null;
            Source("WindowsUpdate." + name, PolicyScope.Global, null);
            foreach (var (policy, layerScope, tagName) in layers)
            {
                if (policy.WindowsUpdate is { } wu && selector(wu) is { } group)
                {
                    value = group.Managed ? group.Value : null;
                    Source("WindowsUpdate." + name, layerScope, tagName);
                }
            }

            return value;
        }

        var windowsUpdate = new WindowsUpdatePolicySettings
        {
            AutomaticUpdates = Group(nameof(WindowsUpdatePolicyGroup.AutomaticUpdates), w => w.AutomaticUpdates),
            FeatureUpdates = Group(nameof(WindowsUpdatePolicyGroup.FeatureUpdates), w => w.FeatureUpdates),
            QualityUpdates = Group(nameof(WindowsUpdatePolicyGroup.QualityUpdates), w => w.QualityUpdates),
            RestartBehavior = Group(nameof(WindowsUpdatePolicyGroup.RestartBehavior), w => w.RestartBehavior),
        };

        var excluded = layers
            .SelectMany(l => l.Policy.ExcludedKbs)
            .Select(KbNumber.Normalize)
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new EffectivePolicy
        {
            CheckInIntervalSeconds = Pick(nameof(EffectivePolicy.CheckInIntervalSeconds), p => p.CheckInIntervalSeconds, 60),
            ScanIntervalMinutes = Pick(nameof(EffectivePolicy.ScanIntervalMinutes), p => p.ScanIntervalMinutes, 360),
            InventoryIntervalMinutes = Pick(nameof(EffectivePolicy.InventoryIntervalMinutes), p => p.InventoryIntervalMinutes, 1440),
            JitterPercent = Pick(nameof(EffectivePolicy.JitterPercent), p => p.JitterPercent, 10),
            AllowedCategories = categories,
            IncludeOptional = Pick(nameof(EffectivePolicy.IncludeOptional), p => p.IncludeOptional, false),
            ExcludedKbs = excluded,
            AcceptEulas = Pick(nameof(EffectivePolicy.AcceptEulas), p => p.AcceptEulas, true),
            AutoInstallEnabled = Pick(nameof(EffectivePolicy.AutoInstallEnabled), p => p.AutoInstallEnabled, false),
            InstallDelayDays = Pick(nameof(EffectivePolicy.InstallDelayDays), p => p.InstallDelayDays, 0),
            SecurityInstallDelayDays = Pick(nameof(EffectivePolicy.SecurityInstallDelayDays), p => p.SecurityInstallDelayDays, 0),
            KnownExploitedSkipsDelay = Pick(nameof(EffectivePolicy.KnownExploitedSkipsDelay), p => p.KnownExploitedSkipsDelay, true),
            MaintenanceWindow = window is { IsConfigured: true } ? window : null,
            PreDownloadHours = Pick(nameof(EffectivePolicy.PreDownloadHours), p => p.PreDownloadHours, 0),
            ScanStaleAfterHours = Pick(nameof(EffectivePolicy.ScanStaleAfterHours), p => p.ScanStaleAfterHours, 48),
            MaxConcurrentInstallsPerSite = Pick(nameof(EffectivePolicy.MaxConcurrentInstallsPerSite), p => p.MaxConcurrentInstallsPerSite, 10),
            TrayIconEnabled = Pick(nameof(EffectivePolicy.TrayIconEnabled), p => p.TrayIconEnabled, true),
            InstallNotificationsEnabled = Pick(nameof(EffectivePolicy.InstallNotificationsEnabled), p => p.InstallNotificationsEnabled, true),
            AgentAutoUpdateEnabled = Pick(nameof(EffectivePolicy.AgentAutoUpdateEnabled), p => p.AgentAutoUpdateEnabled, true),
            RestartSchedule = restart is { Enabled: true } ? restart : null,
            WindowsUpdate = windowsUpdate,
            ApplicationUpdates = applications,
            Sources = sources,
            SourceTags = sourceTags,
        };
    }

    public static IReadOnlyList<UpdateCategory> ParseCategories(IEnumerable<string> names) =>
        names.Select(n => Enum.TryParse<UpdateCategory>(n, ignoreCase: true, out var c) ? (UpdateCategory?)c : null)
            .OfType<UpdateCategory>()
            .Distinct()
            .ToArray();

    public static IReadOnlyList<string> ValidatePolicy(Policy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var errors = new List<string>();
        void Range(string name, int? value, int min, int max)
        {
            if (value is { } v && (v < min || v > max))
            {
                errors.Add($"{name} must be between {min} and {max}.");
            }
        }

        Range(nameof(policy.CheckInIntervalSeconds), policy.CheckInIntervalSeconds, 15, 3600);
        Range(nameof(policy.ScanIntervalMinutes), policy.ScanIntervalMinutes, 30, 10080);
        Range(nameof(policy.InventoryIntervalMinutes), policy.InventoryIntervalMinutes, 60, 10080);
        Range(nameof(policy.JitterPercent), policy.JitterPercent, 0, 50);
        Range(nameof(policy.MaintenanceDurationMinutes), policy.MaintenanceDurationMinutes, 15, 1440);
        Range(nameof(policy.PreDownloadHours), policy.PreDownloadHours, 0, 24);
        Range(nameof(policy.ScanStaleAfterHours), policy.ScanStaleAfterHours, 1, 720);
        Range(nameof(policy.MaxConcurrentInstallsPerSite), policy.MaxConcurrentInstallsPerSite, 1, 1000);
        Range(nameof(policy.InstallDelayDays), policy.InstallDelayDays, 0, 365);
        Range(nameof(policy.SecurityInstallDelayDays), policy.SecurityInstallDelayDays, 0, 90);
        if (policy.AllowedCategories is { } cats &&
            cats.Any(c => !Enum.TryParse<UpdateCategory>(c, ignoreCase: true, out var parsed) || parsed == UpdateCategory.Application))
        {
            errors.Add("AllowedCategories contains an unknown category (application updates are set under ApplicationUpdates).");
        }

        if (policy.MaintenanceDays is { } days && days.Any(d => d is < 0 or > 6))
        {
            errors.Add("MaintenanceDays must be 0 (Sunday) to 6 (Saturday).");
        }

        if (policy.ExcludedKbs.Any(kb => KbNumber.Normalize(kb) is null))
        {
            errors.Add("ExcludedKbs must contain KB numbers such as KB5044284.");
        }

        if (policy.RestartSchedule is { } restart)
        {
            errors.AddRange(restart.Validate());
        }

        if (policy.WindowsUpdate is { } windowsUpdate)
        {
            errors.AddRange(windowsUpdate.Validate());
        }

        if (policy.ApplicationUpdates is { } applicationUpdates)
        {
            errors.AddRange(applicationUpdates.Validate());
        }

        return errors;
    }
}
