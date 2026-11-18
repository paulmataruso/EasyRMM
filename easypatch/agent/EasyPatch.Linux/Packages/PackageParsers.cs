using System.Text.Json;
using System.Text.RegularExpressions;
using EasyPatch.Contracts.Updates;

namespace EasyPatch.Linux.Packages;

/// <summary>An upgrade the package manager would install.</summary>
/// <param name="Name">Package name without architecture.</param>
/// <param name="Architecture">Package architecture (amd64, all, x86_64, noarch, …).</param>
/// <param name="InstalledVersion">Installed version (null when unknown).</param>
/// <param name="Version">The version the upgrade installs.</param>
/// <param name="Origins">apt: origins of the new version (e.g. <c>Debian-Security:12/bookworm-security</c>); dnf: the repository id.</param>
public sealed record PackageUpgrade(string Name, string Architecture, string? InstalledVersion, string Version, IReadOnlyList<string> Origins)
{
    public bool Security { get; init; }

    /// <summary>Highest advisory severity (dnf): Critical, Important, Moderate or Low.</summary>
    public string? Severity { get; init; }

    public IReadOnlyList<string> Advisories { get; init; } = [];

    /// <summary>CVE IDs fixed by this upgrade (dnf advisories).</summary>
    public IReadOnlyList<string> Cves { get; init; } = [];

    /// <summary>Source package (apt).</summary>
    public string? Source { get; init; }

    /// <summary>Key used for lookups: <c>name:arch</c>.</summary>
    public string Key => Name + ":" + Architecture;
}

/// <summary>Validation of names before they are used as command arguments.</summary>
public static partial class PackageNames
{
    [GeneratedRegex(@"^[a-z0-9][a-z0-9+.\-]{0,199}$", RegexOptions.CultureInvariant)]
    private static partial Regex DebianNameRegex();

    [GeneratedRegex(@"^[A-Za-z0-9_][A-Za-z0-9._+\-]{0,199}$", RegexOptions.CultureInvariant)]
    private static partial Regex RpmNameRegex();

    [GeneratedRegex(@"^[a-z0-9_]{1,32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ArchitectureRegex();

    [GeneratedRegex(@"^[A-Za-z0-9.+~:_\-^]{1,200}$", RegexOptions.CultureInvariant)]
    private static partial Regex VersionRegex();

    public static bool IsDebianName(string? name) => name is not null && DebianNameRegex().IsMatch(name);

    public static bool IsRpmName(string? name) => name is not null && RpmNameRegex().IsMatch(name) && !name.StartsWith('-');

    public static bool IsArchitecture(string? architecture) => architecture is not null && ArchitectureRegex().IsMatch(architecture);

    public static bool IsVersion(string? version) => version is not null && VersionRegex().IsMatch(version);
}

/// <summary>Parsers for apt output (run with LC_ALL=C).</summary>
public static partial class AptParsers
{
    /// <summary>Parses <c>dpkg-query -W -f='${Package}\t${Architecture}\t${source:Package}\n'</c> into <c>name:arch</c> → source
    /// package. Invalid names are skipped.</summary>
    public static IReadOnlyDictionary<string, string> ParseSourcePackages(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in output.Split('\n'))
        {
            var parts = line.Trim().Split('\t');
            if (parts.Length != 3 || !PackageNames.IsDebianName(parts[0]) || !PackageNames.IsDebianName(parts[2]) || !PackageNames.IsArchitecture(parts[1]))
            {
                continue;
            }

            result[parts[0] + ":" + parts[1]] = parts[2];
        }

        return result;
    }

    // Inst libssl3 [3.0.17-1~deb12u2] (3.0.22-1~deb12u2 Debian-Security:12/oldstable-security [amd64])
    // Inst libc6 [2.39-0ubuntu8.9] (2.39-0ubuntu8.12 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
    // Inst linux-image-6.1.0-30-amd64 (6.1.124-1 Debian:12.9/stable [amd64])     (a new package)
    [GeneratedRegex(@"^Inst (?<name>\S+) (?:\[(?<old>[^\]]*)\] )?\((?<new>\S+)(?: (?<origins>[^\[]*?))? \[(?<arch>[^\]]+)\]\)",
        RegexOptions.CultureInvariant)]
    private static partial Regex InstRegex();

    /// <summary>Upgrades of installed packages in <c>apt-get -s upgrade</c> output. Lines for packages that are not
    /// installed yet (new dependencies) are left out: they are pulled in by the upgrades that need them.</summary>
    public static IReadOnlyList<PackageUpgrade> ParseSimulation(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var list = new List<PackageUpgrade>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            var match = InstRegex().Match(raw.TrimEnd('\r'));
            if (!match.Success || !match.Groups["old"].Success)
            {
                continue;
            }

            var name = match.Groups["name"].Value;
            var colon = name.IndexOf(':', StringComparison.Ordinal);
            if (colon > 0)
            {
                name = name[..colon];
            }

            var architecture = match.Groups["arch"].Value;
            var version = match.Groups["new"].Value;
            var installed = match.Groups["old"].Value;
            if (!PackageNames.IsDebianName(name) || !PackageNames.IsArchitecture(architecture) || !PackageNames.IsVersion(version) ||
                !seen.Add(name + ":" + architecture))
            {
                continue;
            }

            var origins = match.Groups["origins"].Success
                ? match.Groups["origins"].Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                : [];
            list.Add(new PackageUpgrade(name, architecture, installed.Length == 0 ? null : installed, version, origins)
            {
                Security = origins.Any(IsSecurityOrigin),
            });
        }

        return list;
    }

    /// <summary>An origin such as <c>Debian-Security:12/bookworm-security</c> or <c>Ubuntu:24.04/noble-security</c>.</summary>
    public static bool IsSecurityOrigin(string origin)
    {
        var slash = origin.LastIndexOf('/');
        var suite = slash >= 0 ? origin[(slash + 1)..] : origin;
        return suite.EndsWith("-security", StringComparison.Ordinal);
    }

    /// <summary>One version available from one repository (<c>apt-cache madison</c>).</summary>
    public sealed record MadisonEntry(string Name, string Version, string Suite, string Architecture);

    /// <summary>Parses <c>apt-cache madison</c>: <c> libexpat1 | 2.5.0-1+deb12u5 | http://deb.debian.org/debian-security bookworm-security/main amd64 Packages</c>.</summary>
    public static IReadOnlyList<MadisonEntry> ParseMadison(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var list = new List<MadisonEntry>();
        foreach (var raw in output.Split('\n'))
        {
            var parts = raw.Split('|', StringSplitOptions.TrimEntries);
            if (parts.Length != 3)
            {
                continue;
            }

            var source = parts[2].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (source.Length < 4 || source[^1] != "Packages")
            {
                continue;
            }

            var suite = source[1].Split('/')[0];
            list.Add(new MadisonEntry(parts[0], parts[1], suite, source[^2]));
        }

        return list;
    }

    /// <summary>True when a security repository offers a version of the package newer than the installed one: the
    /// upgrade then includes a security fix, even if the newest version comes from a point release.</summary>
    public static bool HasNewerSecurityVersion(PackageUpgrade upgrade, IEnumerable<MadisonEntry> entries)
    {
        ArgumentNullException.ThrowIfNull(upgrade);
        ArgumentNullException.ThrowIfNull(entries);
        return entries.Any(e => e.Name == upgrade.Name &&
                                e.Suite.EndsWith("-security", StringComparison.Ordinal) &&
                                (upgrade.Architecture == "all" || e.Architecture == upgrade.Architecture) &&
                                (upgrade.InstalledVersion is null || DebianVersion.Compare(e.Version, upgrade.InstalledVersion) > 0) &&
                                DebianVersion.Compare(e.Version, upgrade.Version) <= 0);
    }

    /// <summary>Parses <c>dpkg-query -W -f='${Package}\t${Architecture}\t${Version}\t${db:Status-Abbrev}\n'</c>; only
    /// fully installed packages ("ii").</summary>
    public static IReadOnlyDictionary<string, string> ParseInstalled(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            var parts = raw.TrimEnd('\r').Split('\t');
            if (parts.Length >= 4 && parts[3].StartsWith("ii", StringComparison.Ordinal))
            {
                map[parts[0] + ":" + parts[1]] = parts[2];
            }
        }

        return map;
    }
}

/// <summary>Parsers for dnf 4 / rpm output (run with LC_ALL=C).</summary>
public static partial class DnfParsers
{
    [GeneratedRegex(@"^(?:\d+:)?[A-Za-z0-9._+~^]+-[A-Za-z0-9._+~^]+$", RegexOptions.CultureInvariant)]
    private static partial Regex EvrRegex();

    /// <summary>Parses <c>dnf check-update</c>: "name.arch  [epoch:]version-release  repo" rows (dnf wraps long rows onto
    /// two lines). The "Obsoleting Packages" section is ignored.</summary>
    public static IReadOnlyList<PackageUpgrade> ParseCheckUpdate(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var tokens = new List<string>();
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.StartsWith("Obsoleting Packages", StringComparison.Ordinal))
            {
                break;
            }

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0 || parts[0].EndsWith(':'))
            {
                continue; // blank, or "Security: ..." / "Last metadata expiration check: ..." notes
            }

            tokens.AddRange(parts);
        }

        var list = new List<PackageUpgrade>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i + 2 < tokens.Count;)
        {
            var nameArch = tokens[i];
            var evr = tokens[i + 1];
            var dot = nameArch.LastIndexOf('.');
            if (dot <= 0 || !EvrRegex().IsMatch(evr))
            {
                i++;
                continue;
            }

            var name = nameArch[..dot];
            var architecture = nameArch[(dot + 1)..];
            if (PackageNames.IsRpmName(name) && PackageNames.IsArchitecture(architecture) && PackageNames.IsVersion(evr) &&
                seen.Add(name + ":" + architecture))
            {
                list.Add(new PackageUpgrade(name, architecture, null, NormalizeEvr(evr), [tokens[i + 2]]));
            }

            i += 3;
        }

        return list;
    }

    /// <summary>One advisory line of <c>dnf updateinfo list</c>.</summary>
    public sealed record Advisory(string Id, string Type, string? Severity, string Name, string Architecture, string Version)
    {
        public bool IsSecurity => Type == "security";
    }

    /// <summary>Parses <c>dnf updateinfo list</c>: "RLSA-2026:55439 Important/Sec.  curl-minimal-7.76.1-40.el9_8.5.x86_64".</summary>
    public static IReadOnlyList<Advisory> ParseUpdateInfo(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var list = new List<Advisory>();
        foreach (var raw in output.Split('\n'))
        {
            var parts = raw.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 3 || ParseNevra(parts[2]) is not { } nevra)
            {
                continue;
            }

            var kind = parts[1];
            string type;
            string? severity = null;
            if (kind.EndsWith("/Sec.", StringComparison.Ordinal))
            {
                type = "security";
                severity = NormalizeSeverity(kind[..^"/Sec.".Length]);
            }
            else
            {
                type = kind.ToLowerInvariant() switch
                {
                    "security" or "sec." => "security",
                    "bugfix" => "bugfix",
                    "enhancement" => "enhancement",
                    var other => other,
                };
            }

            list.Add(new Advisory(parts[0], type, severity, nevra.Name, nevra.Architecture, nevra.Version));
        }

        return list;
    }

    /// <summary>Parses dnf5 <c>advisory list --updates --json</c>: an array of objects with <c>name</c>, <c>type</c>,
    /// <c>severity</c> and <c>nevra</c> (dnf5 no longer prints the dnf4 "Important/Sec." column). Entries with a missing or
    /// malformed field are skipped; a document that is not a JSON array throws <see cref="JsonException"/>.</summary>
    /// <summary>CVE IDs in a text (an advisory reference ID or title such as "CVE-2026-1234 pcre2: …").</summary>
    public static IEnumerable<string> FindCves(string? text) =>
        text is null ? [] : CveRegex().Matches(text).Select(m => m.Value.ToUpperInvariant());

    public static bool IsCve(string value) => CveExactRegex().IsMatch(value);

    [GeneratedRegex(@"\bCVE-\d{4}-\d{4,7}\b", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex CveRegex();

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,7}$", RegexOptions.CultureInvariant)]
    private static partial Regex CveExactRegex();

    /// <summary>Parses <c>dnf5 advisory info --json</c>: advisory name → CVE IDs from its references (RHEL lists them as
    /// references of type "cve"; Fedora names them in Bugzilla titles).</summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> ParseAdvisoryCves(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var result = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(output))
        {
            return result;
        }

        using var document = JsonDocument.Parse(output);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("Expected a JSON array of advisories.");
        }

        foreach (var item in document.RootElement.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object || AnyCaseText(item, "name") is not { } name)
            {
                continue;
            }

            var cves = new SortedSet<string>(StringComparer.Ordinal);
            if (AnyCase(item, "references") is { ValueKind: JsonValueKind.Array } references)
            {
                foreach (var reference in references.EnumerateArray())
                {
                    if (reference.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    cves.UnionWith(FindCves(AnyCaseText(reference, "id")));
                    cves.UnionWith(FindCves(AnyCaseText(reference, "title")));
                }
            }

            if (cves.Count > 0)
            {
                result[name] = cves.ToList();
            }
        }

        return result;
    }

    /// <summary>dnf5 writes some JSON keys capitalized ("Name") and others not ("references").</summary>
    private static JsonElement? AnyCase(JsonElement item, string property)
    {
        foreach (var p in item.EnumerateObject())
        {
            if (string.Equals(p.Name, property, StringComparison.OrdinalIgnoreCase))
            {
                return p.Value;
            }
        }

        return null;
    }

    private static string? AnyCaseText(JsonElement item, string property) =>
        AnyCase(item, property) is { ValueKind: JsonValueKind.String } value && value.GetString() is { Length: > 0 } s ? s : null;

    public static IReadOnlyList<Advisory> ParseAdvisoryJson(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var list = new List<Advisory>();
        if (string.IsNullOrWhiteSpace(output))
        {
            return list;
        }

        using var document = JsonDocument.Parse(output);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("Expected a JSON array of advisories.");
        }

        foreach (var item in document.RootElement.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object ||
                Text(item, "name") is not { } id ||
                Text(item, "type") is not { } kind ||
                Text(item, "nevra") is not { } text ||
                ParseNevra(text) is not { } nevra)
            {
                continue;
            }

            var type = kind.ToLowerInvariant();
            list.Add(new Advisory(id, type, type == "security" ? NormalizeSeverity(Text(item, "severity")) : null, nevra.Name, nevra.Architecture,
                nevra.Version));
        }

        return list;

        static string? Text(JsonElement item, string property) =>
            item.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String && value.GetString() is { Length: > 0 } s ? s : null;
    }

    /// <summary>The package a dnf transaction line starts working on, or null. dnf4 prints
    /// "  Upgrading        : curl-8.12.1-4.el10.x86_64      3/8"; dnf5 prints "[3/8] Upgrading curl-0:8.21.0-9.fc45.x86_64 100% | …"
    /// and cuts long package specifications to the column width, so only the name (always followed by "-epoch:") is used.</summary>
    public static string? ParseProgressPackage(string line)
    {
        ArgumentNullException.ThrowIfNull(line);
        var dnf4 = Dnf4StepRegex().Match(line);
        if (dnf4.Success)
        {
            return ParseNevra(dnf4.Groups["nevra"].Value)?.Name;
        }

        var dnf5 = Dnf5StepRegex().Match(line);
        return dnf5.Success ? dnf5.Groups["name"].Value : null;
    }

    [GeneratedRegex(@"^\s+(?:Upgrading|Installing)\s+:\s+(?<nevra>\S+)\s+\d+/\d+", RegexOptions.CultureInvariant)]
    private static partial Regex Dnf4StepRegex();

    [GeneratedRegex(@"^\[\s*\d+/\d+\]\s+(?:Upgrading|Installing)\s+(?<name>[^\s:]+?)-\d+:", RegexOptions.CultureInvariant)]
    private static partial Regex Dnf5StepRegex();

    /// <summary>Splits <c>name-[epoch:]version-release.arch</c>.</summary>
    public static (string Name, string Version, string Architecture)? ParseNevra(string nevra)
    {
        ArgumentNullException.ThrowIfNull(nevra);
        var dot = nevra.LastIndexOf('.');
        if (dot <= 0)
        {
            return null;
        }

        var architecture = nevra[(dot + 1)..];
        var nevr = nevra[..dot];
        var releaseDash = nevr.LastIndexOf('-');
        if (releaseDash <= 0)
        {
            return null;
        }

        var versionDash = nevr.LastIndexOf('-', releaseDash - 1);
        if (versionDash <= 0)
        {
            return null;
        }

        var name = nevr[..versionDash];
        var evr = nevr[(versionDash + 1)..];
        return PackageNames.IsRpmName(name) && PackageNames.IsArchitecture(architecture) ? (name, NormalizeEvr(evr), architecture) : null;
    }

    /// <summary>Parses <c>rpm -q --qf '%{NAME}\t%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'</c>. Install-only packages
    /// (kernels) are installed in several versions: the newest is kept.</summary>
    public static IReadOnlyDictionary<string, string> ParseInstalled(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in output.Split('\n'))
        {
            var parts = raw.TrimEnd('\r').Split('\t');
            if (parts.Length != 3 || parts[0].Contains(' ', StringComparison.Ordinal))
            {
                continue; // "package x is not installed"
            }

            var key = parts[0] + ":" + parts[1];
            var version = NormalizeEvr(parts[2]);
            if (!map.TryGetValue(key, out var existing) || RpmVersion.Compare(version, existing) > 0)
            {
                map[key] = version;
            }
        }

        return map;
    }

    /// <summary>Drops a zero epoch ("0:1.2-3" → "1.2-3") so versions compare and display the same everywhere.</summary>
    public static string NormalizeEvr(string evr) => evr.StartsWith("0:", StringComparison.Ordinal) ? evr[2..] : evr;

    public static string? NormalizeSeverity(string? severity) => severity?.Trim() switch
    {
        null or "" or "None" or "Unknown" => null,
        var s when s.Equals("critical", StringComparison.OrdinalIgnoreCase) => "Critical",
        var s when s.Equals("important", StringComparison.OrdinalIgnoreCase) => "Important",
        var s when s.Equals("moderate", StringComparison.OrdinalIgnoreCase) => "Moderate",
        var s when s.Equals("low", StringComparison.OrdinalIgnoreCase) => "Low",
        _ => null,
    };

    public static int SeverityRank(string? severity) => severity switch
    {
        "Critical" => 4,
        "Important" => 3,
        "Moderate" => 2,
        "Low" => 1,
        _ => 0,
    };
}
