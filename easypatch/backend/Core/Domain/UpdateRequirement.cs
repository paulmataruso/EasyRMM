using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Entities;

namespace EasyPatch.Core.Domain;

/// <summary>Result of <see cref="UpdateRequirement.Evaluate"/> for one update on one endpoint.</summary>
/// <param name="Excluded">An administrator excluded the update (by GUID or KB).</param>
/// <param name="Required">Policy wants the update installed now: it counts toward compliance and scheduled installs.</param>
/// <param name="DeferredUntil">Policy allows the update, but its rollout delay ends at this time (not required yet).</param>
public readonly record struct RequirementDecision(bool Excluded, bool Required, DateTimeOffset? DeferredUntil);

/// <summary>
/// The single place that decides whether an update is required on an endpoint. Used by scan ingestion, compliance
/// recomputation, the install preview and the scheduler, so they always agree.
/// </summary>
public static class UpdateRequirement
{
    public const string SecurityClassification = "Security Updates";

    /// <summary>A security fix: Microsoft's "Security Updates" classification (monthly cumulative updates included), or a
    /// Linux package upgrade from a security repository or advisory.</summary>
    public static bool IsSecurity(Update update)
    {
        ArgumentNullException.ThrowIfNull(update);
        return update.Category == UpdateCategory.Security ||
               string.Equals(update.MsClassification, SecurityClassification, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Rollout delay that applies to an update. Definition updates (antivirus signatures) are never delayed, nor
    /// (see <see cref="Evaluate"/>) are fixes for known-exploited vulnerabilities when the policy says so.</summary>
    public static int DelayDays(Update update, EffectivePolicy policy)
    {
        ArgumentNullException.ThrowIfNull(update);
        ArgumentNullException.ThrowIfNull(policy);
        if (update.Category == UpdateCategory.Definition)
        {
            return 0;
        }

        return IsSecurity(update) ? policy.SecurityInstallDelayDays : policy.InstallDelayDays;
    }

    public static RequirementDecision Evaluate(Update update, EndpointUpdate row, EffectivePolicy policy, InstallFilterOptions filter, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(update);
        ArgumentNullException.ThrowIfNull(row);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(filter);
        var excluded = InstallFilter.IsExcluded(row.UpdateGuid, update.KbNumbers, filter);
        if (excluded || InstallFilter.EvaluatePolicy(update.Category, update.IsOptional, filter, ApplicationId(update)) is not null)
        {
            return new RequirementDecision(excluded, false, null);
        }

        var delay = row.KnownExploited && policy.KnownExploitedSkipsDelay ? 0 : DelayDays(update, policy);
        if (delay <= 0)
        {
            return new RequirementDecision(false, true, null);
        }

        var due = (row.DelayBasisAt ?? row.FirstDetectedAt).AddDays(delay);
        return now >= due ? new RequirementDecision(false, true, null) : new RequirementDecision(false, false, due);
    }

    /// <summary>Key of a Linux package "line" (same package and architecture on one endpoint): a newer version of the
    /// same line replaces the older one, like a superseding Windows update. Null for Windows updates.</summary>
    public static string? LineKey(Update? update) =>
        update?.PackageName is { } name ? name + ":" + (update.PackageArchitecture ?? "") : null;

    public static string? LineKey(PackageUpdateInfo? package) =>
        package is null ? null : package.Name + ":" + package.Architecture;

    /// <summary>Line key of a reported update: the Linux package line, or the application (winget ID) for application updates.</summary>
    public static string? LineKey(ReportedUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        return update.Application is { } app ? app.Id + ":" : LineKey(update.Package);
    }

    /// <summary>The winget package ID of an application update (stored as the package name), otherwise null.</summary>
    public static string? ApplicationId(Update? update) => update?.Category == UpdateCategory.Application ? update.PackageName : null;
}
