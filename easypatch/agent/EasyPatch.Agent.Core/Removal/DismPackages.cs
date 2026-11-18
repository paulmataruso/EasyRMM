using System.Text.RegularExpressions;

namespace EasyPatch.Agent.Core.Removal;

/// <summary>A servicing package listed by <c>dism /Online /Get-Packages</c>.</summary>
public sealed record DismPackage(string Identity, string State, string? ReleaseType)
{
    /// <summary>The version after the last "~" (for example 26100.2314.1.10).</summary>
    public string Version => Identity[(Identity.LastIndexOf('~') + 1)..];
}

/// <summary>Reads DISM's package listings (run with <c>/English</c>) and finds the packages that belong to a KB.</summary>
public static partial class DismPackages
{
    public const string Installed = "Installed";
    public const string InstallPending = "Install Pending";
    public const string UninstallPending = "Uninstall Pending";

    /// <summary>CBS_E_CANNOT_UNINSTALL: the package is permanent.</summary>
    public const int PermanentPackage = unchecked((int)0x800F0825);

    /// <summary>DISM finished and a restart is needed to complete the operation.</summary>
    public const int RestartRequired = 3010;

    /// <summary>Parses the list output of <c>/Get-Packages</c> ("Package Identity : …" followed by "State : …").
    /// Identities that are not plain package names are ignored, so nothing else can reach a DISM command line.</summary>
    public static IReadOnlyList<DismPackage> Parse(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var packages = new List<DismPackage>();
        string? identity = null;
        string? state = null;
        string? releaseType = null;

        void Flush()
        {
            if (identity is not null && state is not null && IsSafeIdentity(identity))
            {
                packages.Add(new DismPackage(identity, state, releaseType));
            }

            identity = state = releaseType = null;
        }

        foreach (var raw in output.Split('\n'))
        {
            var line = raw.Trim();
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0)
            {
                continue;
            }

            var key = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            switch (key)
            {
                case "Package Identity":
                    Flush();
                    identity = value;
                    break;
                case "State" when identity is not null:
                    state = value;
                    break;
                case "Release Type" when identity is not null:
                    releaseType = value;
                    break;
            }
        }

        Flush();
        return packages;
    }

    /// <summary>A package name as Windows writes it: letters, digits and <c>_ ~ . -</c> only.</summary>
    public static bool IsSafeIdentity(string identity) => SafeIdentity().IsMatch(identity);

    /// <summary>Installed (or installed and waiting for a restart): DISM can remove it.</summary>
    public static bool IsRemovable(DismPackage package) =>
        package.State is Installed or InstallPending;

    /// <summary>Packages named after the KB (<c>Package_for_KB5034441~…</c>, not <c>Package_for_KB50344410</c>). Windows itself
    /// refuses to remove the permanent ones, such as servicing stack updates.</summary>
    public static IReadOnlyList<DismPackage> NamedForKb(IEnumerable<DismPackage> packages, string kb) =>
        packages.Where(p => p.Identity.StartsWith("Package_for_KB" + kb, StringComparison.OrdinalIgnoreCase) &&
                            (p.Identity.Length == ("Package_for_KB" + kb).Length || !char.IsAsciiDigit(p.Identity[("Package_for_KB" + kb).Length])))
            .ToList();

    /// <summary>Cumulative update packages (<c>Package_for_RollupFix</c>, <c>Package_for_DotNetRollup…</c>) that are installed or
    /// queued for removal: their names carry a build number rather than the KB, so each is confirmed before removal.</summary>
    public static IReadOnlyList<DismPackage> RollupCandidates(IEnumerable<DismPackage> packages) =>
        packages.Where(p => (p.Identity.StartsWith("Package_for_RollupFix~", StringComparison.OrdinalIgnoreCase) ||
                             p.Identity.StartsWith("Package_for_DotNetRollup", StringComparison.OrdinalIgnoreCase)) &&
                            (IsRemovable(p) || p.State == UninstallPending))
            .ToList();

    /// <summary>The build in a cumulative update's title, such as "26100.2314" from
    /// "2024-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617) (26100.2314)".</summary>
    public static string? BuildFromTitle(string title)
    {
        ArgumentNullException.ThrowIfNull(title);
        var match = TitleBuild().Match(title);
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>True when a rollup package's version is the title's build (26100.2314 matches 26100.2314.1.10).</summary>
    public static bool IsBuild(DismPackage package, string build) =>
        package.Identity.StartsWith("Package_for_RollupFix~", StringComparison.OrdinalIgnoreCase) &&
        package.Version.StartsWith(build + ".", StringComparison.Ordinal);

    /// <summary>True when <c>/Get-PackageInfo</c> output names the KB (its description and support link do, for example
    /// "Fix for KB5046617" and "?kbid=5046617").</summary>
    public static bool MentionsKb(string packageInfo, string kb)
    {
        ArgumentNullException.ThrowIfNull(packageInfo);
        foreach (Match match in KbReference().Matches(packageInfo))
        {
            if (match.Groups[1].Value == kb)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>The "Error: …" line and the message after it, without DISM's banner and progress bars.</summary>
    public static string Summarize(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var lines = output.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Where(l => !l.StartsWith('[') && !l.StartsWith("Deployment Image Servicing", StringComparison.Ordinal) &&
                        !l.StartsWith("Version:", StringComparison.Ordinal) && !l.StartsWith("Image Version:", StringComparison.Ordinal))
            .ToList();
        var error = lines.FindIndex(l => l.StartsWith("Error", StringComparison.OrdinalIgnoreCase));
        var relevant = error >= 0 ? lines.Skip(error).Take(3) : lines.TakeLast(3);
        var text = string.Join(" ", relevant);
        return text.Length > 500 ? text[..500] + "…" : text.Length == 0 ? "no output." : text;
    }

    [GeneratedRegex(@"^[A-Za-z0-9_~.\-]{1,400}$")]
    private static partial Regex SafeIdentity();

    [GeneratedRegex(@"\((\d{5}\.\d{1,5})\)")]
    private static partial Regex TitleBuild();

    [GeneratedRegex(@"(?:\bKB|kbid=|/help/|/kb/)(\d{1,10})(?!\d)", RegexOptions.IgnoreCase)]
    private static partial Regex KbReference();
}
