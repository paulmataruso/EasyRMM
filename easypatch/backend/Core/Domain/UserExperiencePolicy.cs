using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Policy;

namespace EasyPatch.Core.Domain;

/// <summary>Recurring restart configured in policy. Stored as JSON; a lower level replaces it as a unit.</summary>
public sealed record RestartScheduleSettings
{
    /// <summary>False at a lower level switches off a schedule inherited from above.</summary>
    public bool Enabled { get; init; }

    /// <summary>0 = Sunday … 6 = Saturday, in the site's (or organization's) time zone.</summary>
    public IReadOnlyList<int> Days { get; init; } = [];

    public TimeOnly Time { get; init; } = new(3, 0);
    public RestartCondition Condition { get; init; } = RestartCondition.OnlyIfPending;
    public RestartMode Mode { get; init; } = RestartMode.PromptWithDeadline;
    public int CountdownMinutes { get; init; } = 5;
    public int DeadlineMinutes { get; init; } = 240;

    /// <summary>If the computer is off or offline at the scheduled time, give up after this long.</summary>
    public int ExpiryMinutes { get; init; } = 120;

    public RestartPayload ToPayload() => new()
    {
        Mode = Mode,
        Condition = Condition,
        CountdownMinutes = CountdownMinutes,
        DeadlineMinutes = DeadlineMinutes,
    };

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (!Enabled)
        {
            return errors;
        }

        if (Days.Count == 0)
        {
            errors.Add("Choose at least one day for the restart schedule.");
        }

        if (Days.Any(d => d is < 0 or > 6))
        {
            errors.Add("Restart schedule days must be 0 (Sunday) to 6 (Saturday).");
        }

        if (ExpiryMinutes is < 15 or > 1440)
        {
            errors.Add("A scheduled restart can wait 15 minutes to 24 hours for an offline computer.");
        }

        errors.AddRange(RestartPayload.Validate(ToPayload()));
        return errors;
    }
}

/// <summary>One Windows Update settings group at one policy level.</summary>
/// <remarks><c>Managed = false</c> explicitly leaves Windows alone even if a higher level manages the group.</remarks>
public sealed record PolicyGroupSetting<T>
    where T : class
{
    public bool Managed { get; init; }
    public T? Value { get; init; }
}

/// <summary>Windows Update settings at one policy level. A null group inherits from the level above.</summary>
public sealed record PolicyWindowsUpdate
{
    public PolicyGroupSetting<AutomaticUpdatesSettings>? AutomaticUpdates { get; init; }
    public PolicyGroupSetting<FeatureUpdateSettings>? FeatureUpdates { get; init; }
    public PolicyGroupSetting<QualityUpdateSettings>? QualityUpdates { get; init; }
    public PolicyGroupSetting<RestartBehaviorSettings>? RestartBehavior { get; init; }

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        void Check<T>(PolicyGroupSetting<T>? group, string name)
            where T : class
        {
            if (group is { Managed: true, Value: null })
            {
                errors.Add($"Windows Update {name}: choose the settings to apply, or set the group to not configured.");
            }
        }

        Check(AutomaticUpdates, "Automatic Updates");
        Check(FeatureUpdates, "feature updates");
        Check(QualityUpdates, "quality updates");
        Check(RestartBehavior, "restart behavior");
        errors.AddRange(WindowsUpdatePolicyRegistry.Validate(new WindowsUpdatePolicySettings
        {
            AutomaticUpdates = AutomaticUpdates?.Value,
            FeatureUpdates = FeatureUpdates?.Value,
            QualityUpdates = QualityUpdates?.Value,
            RestartBehavior = RestartBehavior?.Value,
        }));
        return errors;
    }
}
