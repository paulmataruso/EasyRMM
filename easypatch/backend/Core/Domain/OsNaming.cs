namespace EasyPatch.Core.Domain;

public static class OsNaming
{
    /// <summary>Builds a display name; corrects the registry "Windows 10" product name on Windows 11 builds.</summary>
    public static string? Describe(string? caption, int? buildNumber, string? productType)
    {
        if (string.IsNullOrWhiteSpace(caption))
        {
            return null;
        }

        var name = caption.Replace("Microsoft ", string.Empty, StringComparison.OrdinalIgnoreCase).Trim();
        if (buildNumber >= 22000 && (productType is null || productType.Equals("Workstation", StringComparison.OrdinalIgnoreCase)))
        {
            name = name.Replace("Windows 10", "Windows 11", StringComparison.OrdinalIgnoreCase);
        }

        return name;
    }
}
