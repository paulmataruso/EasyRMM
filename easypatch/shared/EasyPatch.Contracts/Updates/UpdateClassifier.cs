using EasyPatch.Contracts.Agent;

namespace EasyPatch.Contracts.Updates;

/// <summary>Well-known Microsoft update classification category IDs (stable across languages).</summary>
public static class MicrosoftClassifications
{
    public static readonly Guid CriticalUpdates = new("e6cf1350-c01b-414d-a61f-263d14d133b4");
    public static readonly Guid DefinitionUpdates = new("e0789628-ce08-4437-be74-2495b842f43b");
    public static readonly Guid Drivers = new("ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0");
    public static readonly Guid FeaturePacks = new("b54e7d24-7add-428f-8b75-90a396fa584f");
    public static readonly Guid SecurityUpdates = new("0fa1201d-4330-4fa8-8ae9-b877473b6441");
    public static readonly Guid ServicePacks = new("68c5b0a3-d1a6-4553-ae49-01d3a7827828");
    public static readonly Guid Tools = new("b4832bd8-e735-4761-8daf-37f882276dab");
    public static readonly Guid UpdateRollups = new("28bc880e-0592-4cbf-8f95-c79b17911d5f");
    public static readonly Guid Updates = new("cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83");
    public static readonly Guid Upgrades = new("3689bdc8-b205-4af4-8d4a-a63924c5e9d5");

    private static readonly Dictionary<Guid, string> Names = new()
    {
        [CriticalUpdates] = "Critical Updates",
        [DefinitionUpdates] = "Definition Updates",
        [Drivers] = "Drivers",
        [FeaturePacks] = "Feature Packs",
        [SecurityUpdates] = "Security Updates",
        [ServicePacks] = "Service Packs",
        [Tools] = "Tools",
        [UpdateRollups] = "Update Rollups",
        [Updates] = "Updates",
        [Upgrades] = "Upgrades",
    };

    public static string? NameOf(Guid id) => Names.GetValueOrDefault(id);
}

/// <summary>
/// Maps WUA update metadata to <see cref="UpdateCategory"/>. Used by both the agent (install filtering)
/// and the server (inventory, compliance, install preview) so both always agree.
/// The agent requests metadata in en-US so title heuristics are stable.
/// </summary>
public static class UpdateClassifier
{
    public static UpdateCategory Classify(ReportedUpdate update)
    {
        ArgumentNullException.ThrowIfNull(update);
        if (update.Application is not null)
        {
            return UpdateCategory.Application;
        }

        if (update.Package is { } package)
        {
            // Linux packages: the agent decides from the repository (apt) or the distribution's advisories (dnf).
            return package.Security ? UpdateCategory.Security : UpdateCategory.Other;
        }

        return Classify(update.Title, update.IsDriver, update.Categories);
    }

    public static UpdateCategory Classify(string? title, bool isDriver, IReadOnlyList<UpdateCategoryRef> categories)
    {
        ArgumentNullException.ThrowIfNull(categories);
        title ??= string.Empty;
        var classification = GetMicrosoftClassificationId(categories);

        if (isDriver || classification == MicrosoftClassifications.Drivers)
        {
            return UpdateCategory.Driver;
        }

        if (classification == MicrosoftClassifications.Upgrades ||
            title.StartsWith("Feature update to Windows", StringComparison.OrdinalIgnoreCase))
        {
            return UpdateCategory.Feature;
        }

        if (classification == MicrosoftClassifications.DefinitionUpdates ||
            title.Contains("Security Intelligence Update", StringComparison.OrdinalIgnoreCase))
        {
            return UpdateCategory.Definition;
        }

        if (title.Contains("Servicing Stack Update", StringComparison.OrdinalIgnoreCase))
        {
            return UpdateCategory.ServicingStack;
        }

        if (title.Contains(".NET Framework", StringComparison.OrdinalIgnoreCase) ||
            title.Contains("for .NET", StringComparison.OrdinalIgnoreCase) ||
            categories.Any(c => IsProduct(c) && c.Name.Contains(".NET", StringComparison.OrdinalIgnoreCase)))
        {
            return UpdateCategory.DotNet;
        }

        if (title.Contains("Cumulative Update", StringComparison.OrdinalIgnoreCase))
        {
            return UpdateCategory.Cumulative;
        }

        if (classification == MicrosoftClassifications.SecurityUpdates)
        {
            return UpdateCategory.Security;
        }

        if (classification == MicrosoftClassifications.CriticalUpdates)
        {
            return UpdateCategory.Critical;
        }

        return UpdateCategory.Other;
    }

    /// <summary>Returns the Microsoft classification category ID, matching by ID first and English name second.</summary>
    public static Guid? GetMicrosoftClassificationId(IReadOnlyList<UpdateCategoryRef> categories)
    {
        ArgumentNullException.ThrowIfNull(categories);
        foreach (var category in categories)
        {
            if (MicrosoftClassifications.NameOf(category.Id) is not null)
            {
                return category.Id;
            }
        }

        foreach (var category in categories)
        {
            if (!string.Equals(category.Type, "UpdateClassification", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var match = category.Name switch
            {
                "Critical Updates" => MicrosoftClassifications.CriticalUpdates,
                "Definition Updates" => MicrosoftClassifications.DefinitionUpdates,
                "Drivers" => MicrosoftClassifications.Drivers,
                "Feature Packs" => MicrosoftClassifications.FeaturePacks,
                "Security Updates" => MicrosoftClassifications.SecurityUpdates,
                "Service Packs" => MicrosoftClassifications.ServicePacks,
                "Tools" => MicrosoftClassifications.Tools,
                "Update Rollups" => MicrosoftClassifications.UpdateRollups,
                "Updates" => MicrosoftClassifications.Updates,
                "Upgrades" => MicrosoftClassifications.Upgrades,
                _ => Guid.Empty,
            };
            if (match != Guid.Empty)
            {
                return match;
            }
        }

        return null;
    }

    public static string? GetMicrosoftClassificationName(IReadOnlyList<UpdateCategoryRef> categories)
    {
        var id = GetMicrosoftClassificationId(categories);
        if (id is { } value)
        {
            return MicrosoftClassifications.NameOf(value);
        }

        return categories.FirstOrDefault(c => string.Equals(c.Type, "UpdateClassification", StringComparison.OrdinalIgnoreCase))?.Name;
    }

    public static IReadOnlyList<string> GetProducts(IReadOnlyList<UpdateCategoryRef> categories) =>
        categories.Where(IsProduct).Select(c => c.Name).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    private static bool IsProduct(UpdateCategoryRef c) =>
        string.Equals(c.Type, "Product", StringComparison.OrdinalIgnoreCase);

    /// <summary>Default categories eligible for "Install All": everything except drivers and feature updates.</summary>
    public static IReadOnlyList<UpdateCategory> DefaultInstallCategories { get; } =
    [
        UpdateCategory.Security,
        UpdateCategory.Critical,
        UpdateCategory.Cumulative,
        UpdateCategory.Definition,
        UpdateCategory.ServicingStack,
        UpdateCategory.DotNet,
        UpdateCategory.Other,
    ];
}
