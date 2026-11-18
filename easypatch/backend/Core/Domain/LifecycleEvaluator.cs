using EasyPatch.Core.Entities;

namespace EasyPatch.Core.Domain;

public sealed record LifecycleResult(OsSupportStatus Status, DateOnly? EndOfServicing, string? Product, string? EditionGroup, OsLifecycleEntry? Entry);

/// <summary>
/// Determines OS support status from an editable lifecycle table. Windows 10 22H2 is NOT treated as receiving
/// free security updates after 2025-10-14; it is "ExtendedSecurityUpdates" only when an ESU license is detected
/// (or an administrator marks the endpoint as enrolled) and the ESU program has not ended.
/// </summary>
public static class LifecycleEvaluator
{
    public static string? ProductFamily(int? buildNumber, string? productType)
    {
        if (buildNumber is not { } build)
        {
            return null;
        }

        if (productType is not null && !productType.Equals("Workstation", StringComparison.OrdinalIgnoreCase))
        {
            return "Windows Server";
        }

        return build >= 22000 ? "Windows 11" : build >= 10240 ? "Windows 10" : null;
    }

    public static string EditionGroup(string? editionId, string? productType)
    {
        if (productType is not null && !productType.Equals("Workstation", StringComparison.OrdinalIgnoreCase))
        {
            return "Server";
        }

        var e = editionId ?? string.Empty;
        if (e.StartsWith("IoTEnterpriseS", StringComparison.OrdinalIgnoreCase))
        {
            return "IoTLTSC";
        }

        if (e.StartsWith("EnterpriseS", StringComparison.OrdinalIgnoreCase))
        {
            return "LTSC";
        }

        if (e.StartsWith("Enterprise", StringComparison.OrdinalIgnoreCase) ||
            e.StartsWith("Education", StringComparison.OrdinalIgnoreCase) ||
            e.StartsWith("IoTEnterprise", StringComparison.OrdinalIgnoreCase) ||
            e.StartsWith("ServerRdsh", StringComparison.OrdinalIgnoreCase))
        {
            return "EnterpriseEducation";
        }

        return "HomePro";
    }

    public static LifecycleResult Evaluate(
        IReadOnlyList<OsLifecycleEntry> table, int? buildNumber, string? editionId, string? productType,
        bool esuLicenseDetected, EsuOverride esuOverride, DateOnly today)
    {
        ArgumentNullException.ThrowIfNull(table);
        var product = ProductFamily(buildNumber, productType);
        var group = EditionGroup(editionId, productType);
        if (product is null)
        {
            return new LifecycleResult(OsSupportStatus.Unknown, null, null, group, null);
        }

        var entry = table.FirstOrDefault(e =>
                        e.Product == product && e.BuildNumber == buildNumber && e.EditionGroup == group)
                    ?? table.FirstOrDefault(e =>
                        e.Product == product && e.BuildNumber == buildNumber && e.EditionGroup == "Any");
        if (entry is null)
        {
            return new LifecycleResult(OsSupportStatus.Unknown, null, product, group, null);
        }

        return FromEntry(entry, product, group, esuLicenseDetected, esuOverride, today);
    }

    /// <summary>Lifecycle product name for a Linux os-release ID (null for distributions without a lifecycle entry).</summary>
    public static string? LinuxProduct(string? osId) => osId?.ToLowerInvariant() switch
    {
        "debian" => "Debian",
        "ubuntu" => "Ubuntu",
        "rhel" => "Red Hat Enterprise Linux",
        "rocky" => "Rocky Linux",
        "almalinux" => "AlmaLinux",
        "ol" => "Oracle Linux",
        "fedora" => "Fedora",
        "centos" => "CentOS Stream",
        _ => null,
    };

    /// <summary>Lifecycle "build number" of a Linux release: YYMM for Ubuntu (24.04 → 2404), the major version otherwise
    /// (Debian 12.8 → 12, RHEL 9.4 → 9).</summary>
    public static int? LinuxReleaseKey(string? osId, string? osVersion)
    {
        if (string.IsNullOrWhiteSpace(osVersion))
        {
            return null;
        }

        var match = System.Text.RegularExpressions.Regex.Match(osVersion, @"^\s*(\d{1,4})(?:\.(\d{1,2}))?");
        if (!match.Success)
        {
            return null;
        }

        var major = int.Parse(match.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture);
        if (string.Equals(osId, "ubuntu", StringComparison.OrdinalIgnoreCase))
        {
            return match.Groups[2].Success ? major * 100 + int.Parse(match.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture) : null;
        }

        return major;
    }

    /// <summary>Support status of a Linux distribution release. "Extended security updates" means Ubuntu Pro (ESM)
    /// after standard support ends; Debian LTS is included in the Debian end dates because it needs no subscription.</summary>
    public static LifecycleResult EvaluateLinux(
        IReadOnlyList<OsLifecycleEntry> table, string? osId, string? osVersion, bool esuLicenseDetected, EsuOverride esuOverride, DateOnly today)
    {
        ArgumentNullException.ThrowIfNull(table);
        var release = LinuxReleaseKey(osId, osVersion);
        // os-release ID "centos" is CentOS Linux up to 8 and CentOS Stream from 9 on (there was no CentOS Linux 9).
        var product = string.Equals(osId, "centos", StringComparison.OrdinalIgnoreCase) && release < 9 ? null : LinuxProduct(osId);
        if (product is null || release is null)
        {
            return new LifecycleResult(OsSupportStatus.Unknown, null, product, "Any", null);
        }

        var entry = table.FirstOrDefault(e => e.Product == product && e.BuildNumber == release);
        return entry is null
            ? new LifecycleResult(OsSupportStatus.Unknown, null, product, "Any", null)
            : FromEntry(entry, product, entry.EditionGroup, esuLicenseDetected, esuOverride, today);
    }

    private static LifecycleResult FromEntry(
        OsLifecycleEntry entry, string product, string group, bool esuLicenseDetected, EsuOverride esuOverride, DateOnly today)
    {
        if (today <= entry.EndOfServicing)
        {
            return new LifecycleResult(OsSupportStatus.Supported, entry.EndOfServicing, product, group, entry);
        }

        var esu = esuOverride switch
        {
            EsuOverride.Enrolled => true,
            EsuOverride.NotEnrolled => false,
            _ => esuLicenseDetected,
        };
        if (esu && entry.EsuEndDate is { } esuEnd && today <= esuEnd)
        {
            return new LifecycleResult(OsSupportStatus.ExtendedSecurityUpdates, esuEnd, product, group, entry);
        }

        return new LifecycleResult(OsSupportStatus.Unsupported, entry.EndOfServicing, product, group, entry);
    }

    /// <summary>Seed table (verify against https://learn.microsoft.com/lifecycle; editable in Settings → OS lifecycle).</summary>
    public static IReadOnlyList<OsLifecycleEntry> SeedEntries()
    {
        var list = new List<OsLifecycleEntry>();
        void Add(string product, string group, int build, string label, string eos, string? esu = null, string? notes = null) =>
            list.Add(new OsLifecycleEntry
            {
                Id = DeterministicGuid($"{product}|{group}|{build}"),
                Product = product,
                EditionGroup = group,
                BuildNumber = build,
                VersionLabel = label,
                EndOfServicing = DateOnly.Parse(eos, System.Globalization.CultureInfo.InvariantCulture),
                EsuEndDate = esu is null ? null : DateOnly.Parse(esu, System.Globalization.CultureInfo.InvariantCulture),
                Notes = notes,
            });

        // Windows 10
        Add("Windows 10", "HomePro", 19045, "22H2", "2025-10-14", "2028-10-10", "ESU: consumer program ended 2026-10-13; commercial ESU through 2028-10-10.");
        Add("Windows 10", "EnterpriseEducation", 19045, "22H2", "2025-10-14", "2028-10-10", "Commercial ESU through 2028-10-10.");
        Add("Windows 10", "HomePro", 19044, "21H2", "2023-06-13");
        Add("Windows 10", "EnterpriseEducation", 19044, "21H2", "2024-06-11");
        Add("Windows 10", "LTSC", 19044, "LTSC 2021", "2027-01-12");
        Add("Windows 10", "IoTLTSC", 19044, "IoT LTSC 2021", "2032-01-13");
        Add("Windows 10", "HomePro", 19043, "21H1", "2022-12-13");
        Add("Windows 10", "EnterpriseEducation", 19043, "21H1", "2022-12-13");
        Add("Windows 10", "LTSC", 17763, "LTSC 2019", "2029-01-09");
        Add("Windows 10", "IoTLTSC", 17763, "IoT LTSC 2019", "2029-01-09");
        Add("Windows 10", "LTSC", 14393, "LTSB 2016", "2026-10-13");
        Add("Windows 10", "IoTLTSC", 14393, "IoT LTSB 2016", "2026-10-13");
        Add("Windows 10", "LTSC", 10240, "LTSB 2015", "2025-10-14");
        // Windows 11
        Add("Windows 11", "HomePro", 22000, "21H2", "2023-10-10");
        Add("Windows 11", "EnterpriseEducation", 22000, "21H2", "2024-10-08");
        Add("Windows 11", "HomePro", 22621, "22H2", "2024-10-08");
        Add("Windows 11", "EnterpriseEducation", 22621, "22H2", "2025-10-14");
        Add("Windows 11", "HomePro", 22631, "23H2", "2025-11-11");
        Add("Windows 11", "EnterpriseEducation", 22631, "23H2", "2026-11-10");
        Add("Windows 11", "HomePro", 26100, "24H2", "2026-10-13");
        Add("Windows 11", "EnterpriseEducation", 26100, "24H2", "2027-10-12");
        Add("Windows 11", "LTSC", 26100, "LTSC 2024", "2029-10-09");
        Add("Windows 11", "IoTLTSC", 26100, "IoT LTSC 2024", "2034-10-10");
        Add("Windows 11", "HomePro", 26200, "25H2", "2027-10-12");
        Add("Windows 11", "EnterpriseEducation", 26200, "25H2", "2028-10-10");
        // Windows Server
        Add("Windows Server", "Server", 9200, "2012", "2023-10-10", "2026-10-13");
        Add("Windows Server", "Server", 9600, "2012 R2", "2023-10-10", "2026-10-13");
        Add("Windows Server", "Server", 14393, "2016", "2027-01-12");
        Add("Windows Server", "Server", 17763, "2019", "2029-01-09");
        Add("Windows Server", "Server", 20348, "2022", "2031-10-14");
        Add("Windows Server", "Server", 26100, "2025", "2034-10-10");
        // Linux (https://wiki.debian.org/LTS, https://ubuntu.com/about/release-cycle, https://access.redhat.com/support/policy/updates/errata).
        // Debian dates include Debian LTS (free, same security repository). Ubuntu ESU = Ubuntu Pro ESM.
        Add("Debian", "Any", 11, "11 (bullseye)", "2026-08-31", null, "Regular security support ended 2024-08-14; Debian LTS until 2026-08-31.");
        Add("Debian", "Any", 12, "12 (bookworm)", "2028-06-30", null, "Regular security support until 2026-06-10; Debian LTS until 2028-06-30.");
        Add("Debian", "Any", 13, "13 (trixie)", "2030-06-30", null, "Regular security support until about 2028-08; Debian LTS until 2030-06-30.");
        Add("Ubuntu", "LTS", 2004, "20.04 LTS", "2025-05-31", "2030-04-30", "ESU: Ubuntu Pro (ESM) until 2030-04.");
        Add("Ubuntu", "LTS", 2204, "22.04 LTS", "2027-06-30", "2032-04-30", "ESU: Ubuntu Pro (ESM) until 2032-04.");
        Add("Ubuntu", "LTS", 2404, "24.04 LTS", "2029-05-31", "2034-04-30", "ESU: Ubuntu Pro (ESM) until 2034-04.");
        Add("Ubuntu", "LTS", 2604, "26.04 LTS", "2031-05-31", "2036-04-30", "ESU: Ubuntu Pro (ESM) until 2036-04.");
        Add("Red Hat Enterprise Linux", "Any", 8, "8", "2029-05-31", null, "End of maintenance support; Extended Life Cycle Support is sold separately.");
        Add("Red Hat Enterprise Linux", "Any", 9, "9", "2032-05-31", null, "End of maintenance support; Extended Life Cycle Support is sold separately.");
        Add("Red Hat Enterprise Linux", "Any", 10, "10", "2035-05-31", null, "End of maintenance support; Extended Life Cycle Support is sold separately.");
        Add("Rocky Linux", "Any", 8, "8", "2029-05-31");
        Add("Rocky Linux", "Any", 9, "9", "2032-05-31");
        Add("Rocky Linux", "Any", 10, "10", "2035-05-31");
        Add("AlmaLinux", "Any", 8, "8", "2029-03-01");
        Add("AlmaLinux", "Any", 9, "9", "2032-05-31");
        Add("AlmaLinux", "Any", 10, "10", "2035-05-31");
        Add("Oracle Linux", "Any", 8, "8", "2029-07-31", null, "End of Premier Support.");
        Add("Oracle Linux", "Any", 9, "9", "2032-06-30", null, "End of Premier Support.");
        Add("Oracle Linux", "Any", 10, "10", "2035-06-30", null, "End of Premier Support (Oracle Lifetime Support Policy: June 2035).");
        // https://www.centos.org/download/: each CentOS Stream release ends with the full support phase of its RHEL release.
        Add("CentOS Stream", "Any", 9, "9", "2027-05-31");
        Add("CentOS Stream", "Any", 10, "10", "2030-05-31");
        // SUPPORT_END in each release's /etc/os-release. A new Fedora release comes out every six months: add it in Settings → OS lifecycle.
        Add("Fedora", "Any", 44, "44", "2027-05-19");
        Add("Fedora", "Any", 45, "45", "2027-12-08");
        return list;
    }

    private static Guid DeterministicGuid(string value)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("easypatch-lifecycle|" + value));
        return new Guid(hash.AsSpan(0, 16));
    }
}
