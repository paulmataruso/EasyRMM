using EasyPatch.Contracts.Agent;

namespace EasyPatch.Core.Domain;

/// <summary>Third-party application updates (winget) in policy. Stored as JSON; a lower level replaces it as a unit. Only
/// applications on the approved list are checked and upgraded, and only where they are already installed.</summary>
public sealed record ApplicationUpdateSettings
{
    /// <summary>False at a lower level switches off application updates inherited from above.</summary>
    public bool Enabled { get; init; }

    /// <summary>winget package IDs, e.g. <c>Mozilla.Firefox</c>.</summary>
    public IReadOnlyList<string> ApprovedApps { get; init; } = [];

    public bool IsActive => Enabled && ApprovedApps.Count > 0;

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        if (ApprovedApps.Count > ApplicationIds.MaxApproved)
        {
            errors.Add($"ApplicationUpdates.ApprovedApps may contain at most {ApplicationIds.MaxApproved} applications.");
        }

        if (ApprovedApps.Any(id => !ApplicationIds.IsValid(id)))
        {
            errors.Add("ApplicationUpdates.ApprovedApps must contain winget package IDs such as Mozilla.Firefox.");
        }

        return errors;
    }

    /// <summary>Trims, validates and removes duplicates (ignoring case).</summary>
    public ApplicationUpdateSettings Normalized() =>
        this with { ApprovedApps = ApplicationIds.Normalize(ApprovedApps) ?? ApprovedApps.Select(a => a.Trim()).ToList() };
}
