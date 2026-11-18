using EasyPatch.Core.Entities;

namespace EasyPatch.Core.Domain;

/// <summary>Alert rule metadata: threshold meaning and limits, and the rules created on install.</summary>
public static class AlertRuleCatalog
{
    public sealed record ThresholdSpec(string Unit, int Min, int Max, int Default);

    /// <summary>Threshold unit and range per rule type; null when the type has no threshold.</summary>
    public static ThresholdSpec? Threshold(AlertRuleType type) => type switch
    {
        AlertRuleType.EndpointOffline => new ThresholdSpec("hours", 1, 720, 24),
        AlertRuleType.SecurityUpdateMissing => new ThresholdSpec("days", 0, 365, 14),
        AlertRuleType.RestartPending => new ThresholdSpec("days", 1, 90, 7),
        AlertRuleType.OsUnsupported => new ThresholdSpec("days", 0, 365, 30),
        _ => null,
    };

    /// <summary>Rules that look at one endpoint (all except <see cref="AlertRuleType.EnrollmentPending"/> and
    /// <see cref="AlertRuleType.UpdateHeld"/>, which raise one alert per organization).</summary>
    public static bool IsEndpointRule(AlertRuleType type) => type is not (AlertRuleType.EnrollmentPending or AlertRuleType.UpdateHeld);

    public static IReadOnlyList<string> Validate(AlertRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(rule.Name) || rule.Name.Length > 100)
        {
            errors.Add("Name must be 1-100 characters.");
        }

        if (!Enum.IsDefined(rule.Type))
        {
            errors.Add("Unknown rule type.");
            return errors;
        }

        var spec = Threshold(rule.Type);
        if (spec is null && rule.Threshold is not null)
        {
            errors.Add("This rule type has no threshold.");
        }
        else if (spec is not null && (rule.Threshold is not { } t || t < spec.Min || t > spec.Max))
        {
            errors.Add($"Threshold must be between {spec.Min} and {spec.Max} {spec.Unit}.");
        }

        if (rule.RenotifyHours is < 0 or > 720)
        {
            errors.Add("Reminder interval must be between 0 (never) and 720 hours.");
        }

        if (rule.ChannelIds.Count > 20)
        {
            errors.Add("At most 20 channels per rule.");
        }

        if (rule.TagId is not null && !IsEndpointRule(rule.Type))
        {
            errors.Add("This rule type cannot be limited to a tag.");
        }

        return errors;
    }

    /// <summary>Default rules (enabled, without channels: alerts show in the console until channels are added).</summary>
    public static IReadOnlyList<AlertRule> Defaults(DateTimeOffset at) =>
    [
        Rule("7c3e1a52-6f0e-4d7b-9a01-000000000001", "Endpoint offline", AlertRuleType.EndpointOffline, AlertSeverity.Warning, at),
        Rule("7c3e1a52-6f0e-4d7b-9a01-000000000002", "Update installation failed", AlertRuleType.InstallFailed, AlertSeverity.Warning, at),
        Rule("7c3e1a52-6f0e-4d7b-9a01-000000000003", "Security update missing", AlertRuleType.SecurityUpdateMissing, AlertSeverity.Critical, at),
        Rule("7c3e1a52-6f0e-4d7b-9a01-000000000004", "Scan stale", AlertRuleType.ScanStale, AlertSeverity.Warning, at),
        Rule("7c3e1a52-6f0e-4d7b-9a01-000000000005", "Restart pending", AlertRuleType.RestartPending, AlertSeverity.Info, at),
        Rule("7c3e1a52-6f0e-4d7b-9a01-000000000006", "Enrollment waiting for approval", AlertRuleType.EnrollmentPending, AlertSeverity.Info, at),
        Rule("7c3e1a52-6f0e-4d7b-9a01-000000000007", "Operating system unsupported", AlertRuleType.OsUnsupported, AlertSeverity.Warning, at),
        Rule("7c3e1a52-6f0e-4d7b-9a01-000000000008", "Known-exploited vulnerability unpatched", AlertRuleType.KnownExploitedMissing,
            AlertSeverity.Critical, at),
        Rule("7c3e1a52-6f0e-4d7b-9a01-000000000009", "Update on hold", AlertRuleType.UpdateHeld, AlertSeverity.Warning, at),
    ];

    private static AlertRule Rule(string id, string name, AlertRuleType type, AlertSeverity severity, DateTimeOffset at) => new()
    {
        Id = Guid.Parse(id),
        Name = name,
        Type = type,
        Enabled = true,
        Severity = severity,
        Threshold = Threshold(type)?.Default,
        CreatedAt = at,
        UpdatedAt = at,
    };
}
