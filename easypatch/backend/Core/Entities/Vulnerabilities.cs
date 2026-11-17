namespace EasyPatch.Core.Entities;

/// <summary>What EasyPatch knows about a CVE, merged from the Microsoft Security Response Center (MSRC) and the CISA
/// Known Exploited Vulnerabilities (KEV) catalog. Rows exist for every CVE named by a feed.</summary>
public sealed class Vulnerability
{
    public required string CveId { get; set; }
    public string? Title { get; set; }

    /// <summary>MSRC severity: Critical, Important, Moderate or Low.</summary>
    public string? Severity { get; set; }

    /// <summary>Highest CVSS base score MSRC publishes for the CVE.</summary>
    public decimal? CvssBase { get; set; }

    /// <summary>MSRC says "Exploited: Yes".</summary>
    public bool MsrcExploited { get; set; }

    /// <summary>In the CISA KEV catalog: known to be exploited in the wild.</summary>
    public bool Kev { get; set; }
    public DateOnly? KevDateAdded { get; set; }

    /// <summary>The remediation due date CISA sets for US federal agencies (a useful urgency signal for everyone).</summary>
    public DateOnly? KevDueDate { get; set; }
    public bool KevRansomware { get; set; }
    public string? KevName { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>MSRC: a KB article (security update) fixes a CVE.</summary>
public sealed class MsrcKbCve
{
    public required string Kb { get; set; }
    public required string CveId { get; set; }
}

/// <summary>MSRC: on Windows build <see cref="Build"/> (10.0.<i>Build</i>), the CVE is fixed from revision (UBR)
/// <see cref="FixedRevision"/>. Lets EasyPatch tell which CVEs a computer is exposed to from its build number, including
/// those fixed by earlier, superseded cumulative updates.</summary>
public sealed class MsrcBuildFix
{
    public int Build { get; set; }
    public required string CveId { get; set; }
    public int FixedRevision { get; set; }
}

/// <summary>Debian Security Tracker: in Debian release <see cref="Release"/> (codename), source package
/// <see cref="Source"/> fixes the CVE in <see cref="FixedVersion"/>. Only kept for source packages that managed
/// Debian computers have upgrades for.</summary>
public sealed class DebianFix
{
    public required string Release { get; set; }
    public required string Source { get; set; }
    public required string CveId { get; set; }
    public required string FixedVersion { get; set; }
}

/// <summary>Synchronization state of one vulnerability feed (msrc, kev, debian).</summary>
public sealed class VulnerabilityFeedState
{
    public required string Name { get; set; }
    public DateTimeOffset? LastAttemptAt { get; set; }
    public DateTimeOffset? LastSuccessAt { get; set; }
    public string? LastError { get; set; }

    /// <summary>Feed version (KEV catalog version, number of MSRC documents, Debian sources).</summary>
    public string? Version { get; set; }

    /// <summary>Feed-specific state (MSRC: document ID → CurrentReleaseDate of the version imported).</summary>
    public string? StateJson { get; set; }
    public int ItemCount { get; set; }
}

public static class VulnerabilityFeeds
{
    public const string Msrc = "msrc";
    public const string Kev = "kev";
    public const string Debian = "debian";
}
