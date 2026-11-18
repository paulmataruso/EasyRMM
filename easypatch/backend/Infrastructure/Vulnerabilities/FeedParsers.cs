using System.Globalization;
using System.Text.Json;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Domain;

namespace EasyPatch.Infrastructure.Vulnerabilities;

/// <summary>One MSRC CVRF month document reduced to what EasyPatch uses.</summary>
public sealed record MsrcDocument(
    IReadOnlyList<MsrcCve> Cves, IReadOnlyList<(string Kb, string CveId)> KbCves, IReadOnlyList<(int Build, string CveId, int FixedRevision)> BuildFixes);

public sealed record MsrcCve(string CveId, string? Title, string? Severity, decimal? CvssBase, bool Exploited);

/// <summary>An entry of the MSRC update list (one CVRF document per month).</summary>
public sealed record MsrcDocumentRef(string Id, DateTimeOffset InitialReleaseDate, DateTimeOffset CurrentReleaseDate);

public sealed record KevCatalog(string Version, IReadOnlyList<KevEntry> Entries);

public sealed record KevEntry(string CveId, string? Name, DateOnly? DateAdded, DateOnly? DueDate, bool Ransomware);

public sealed record DebianFixRow(string Release, string Source, string CveId, string FixedVersion);

/// <summary>Parsers for the MSRC CVRF API, the CISA KEV catalog and the Debian Security Tracker. They read only the
/// fields EasyPatch uses and skip malformed entries.</summary>
public static class FeedParsers
{
    private static readonly string[] SeverityOrder = ["Low", "Moderate", "Important", "Critical"];

    /// <summary><c>GET /cvrf/v3.0/updates</c>: <c>{ "value": [ { "ID": "2026-Nov", "InitialReleaseDate", "CurrentReleaseDate" } ] }</c>.</summary>
    public static IReadOnlyList<MsrcDocumentRef> ParseMsrcUpdates(JsonDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var list = new List<MsrcDocumentRef>();
        if (!document.RootElement.TryGetProperty("value", out var value) || value.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("The MSRC update list has no \"value\" array.");
        }

        foreach (var item in value.EnumerateArray())
        {
            if (Str(item, "ID") is { } id && IsMsrcDocumentId(id) &&
                Date(item, "InitialReleaseDate") is { } initial && Date(item, "CurrentReleaseDate") is { } current)
            {
                list.Add(new MsrcDocumentRef(id, initial, current));
            }
        }

        return list;
    }

    /// <summary>Document IDs look like "2026-Nov"; they become part of a URL, so nothing else is accepted.</summary>
    public static bool IsMsrcDocumentId(string id) =>
        id.Length == 8 && id[4] == '-' && id[..4].All(char.IsAsciiDigit) && id[5..].All(char.IsAsciiLetter);

    /// <summary>One CVRF document (JSON). Vulnerability → CVE, title, severity (threat type 3), "Exploited:Yes" (threat
    /// type 1), highest CVSS base score, and from vendor fixes (remediation type 2) the KB number and the Windows fixed
    /// build "10.0.build.revision".</summary>
    public static MsrcDocument ParseMsrcDocument(JsonDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        if (!document.RootElement.TryGetProperty("Vulnerability", out var vulnerabilities) || vulnerabilities.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("The MSRC document has no \"Vulnerability\" array.");
        }

        var cves = new List<MsrcCve>();
        var kbCves = new HashSet<(string, string)>();
        var builds = new Dictionary<(int Build, string Cve), int>();
        foreach (var v in vulnerabilities.EnumerateArray())
        {
            if (Str(v, "CVE")?.Trim().ToUpperInvariant() is not { } cve || !VulnerabilityRules.IsCveId(cve))
            {
                continue;
            }

            var title = v.TryGetProperty("Title", out var t) ? Str(t, "Value") : null;
            string? severity = null;
            var exploited = false;
            if (v.TryGetProperty("Threats", out var threats) && threats.ValueKind == JsonValueKind.Array)
            {
                foreach (var threat in threats.EnumerateArray())
                {
                    var type = Int(threat, "Type");
                    var text = threat.TryGetProperty("Description", out var d) ? Str(d, "Value") : null;
                    if (text is null)
                    {
                        continue;
                    }

                    if (type == 3 && Array.IndexOf(SeverityOrder, text) is var rank and >= 0 &&
                        (severity is null || rank > Array.IndexOf(SeverityOrder, severity)))
                    {
                        severity = text;
                    }
                    else if (type == 1 && text.Contains("Exploited:Yes", StringComparison.OrdinalIgnoreCase))
                    {
                        exploited = true;
                    }
                }
            }

            decimal? cvss = null;
            if (v.TryGetProperty("CVSSScoreSets", out var scores) && scores.ValueKind == JsonValueKind.Array)
            {
                foreach (var score in scores.EnumerateArray())
                {
                    if (score.TryGetProperty("BaseScore", out var b) && b.ValueKind == JsonValueKind.Number && b.TryGetDecimal(out var value) &&
                        value is >= 0 and <= 10 && (cvss is null || value > cvss))
                    {
                        cvss = value;
                    }
                }
            }

            if (v.TryGetProperty("Remediations", out var remediations) && remediations.ValueKind == JsonValueKind.Array)
            {
                foreach (var r in remediations.EnumerateArray())
                {
                    if (Int(r, "Type") != 2)
                    {
                        continue;
                    }

                    if ((r.TryGetProperty("Description", out var d) ? Str(d, "Value") : null) is { } text && KbNumber.Normalize(text) is { } kb &&
                        text.Trim().All(char.IsAsciiDigit))
                    {
                        kbCves.Add((kb, cve));
                    }

                    if (VulnerabilityRules.TryParseWindowsBuild(Str(r, "FixedBuild"), out var build, out var revision) &&
                        (Str(r, "FixedBuild") ?? "").StartsWith("10.0.", StringComparison.Ordinal))
                    {
                        builds[(build, cve)] = builds.TryGetValue((build, cve), out var existing) ? Math.Min(existing, revision) : revision;
                    }
                }
            }

            cves.Add(new MsrcCve(cve, Clip(title, 500), severity, cvss, exploited));
        }

        return new MsrcDocument(
            cves.GroupBy(c => c.CveId).Select(g => g.First()).ToList(),
            kbCves.Select(k => (k.Item1, k.Item2)).ToList(),
            builds.Select(b => (b.Key.Build, b.Key.Cve, b.Value)).ToList());
    }

    /// <summary>CISA <c>known_exploited_vulnerabilities.json</c>.</summary>
    public static KevCatalog ParseKev(JsonDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var root = document.RootElement;
        if (!root.TryGetProperty("vulnerabilities", out var items) || items.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("The KEV catalog has no \"vulnerabilities\" array.");
        }

        var entries = new Dictionary<string, KevEntry>(StringComparer.Ordinal);
        foreach (var item in items.EnumerateArray())
        {
            if (Str(item, "cveID")?.Trim().ToUpperInvariant() is not { } cve || !VulnerabilityRules.IsCveId(cve))
            {
                continue;
            }

            entries[cve] = new KevEntry(cve, Clip(Str(item, "vulnerabilityName"), 500), DateOnlyOf(Str(item, "dateAdded")), DateOnlyOf(Str(item, "dueDate")),
                string.Equals(Str(item, "knownRansomwareCampaignUse"), "Known", StringComparison.OrdinalIgnoreCase));
        }

        if (entries.Count == 0)
        {
            throw new JsonException("The KEV catalog is empty.");
        }

        return new KevCatalog(Clip(Str(root, "catalogVersion"), 64) ?? "unknown", entries.Values.ToList());
    }

    /// <summary>
    /// Streams the Debian Security Tracker JSON (<c>{ source: { CVE: { "releases": { codename: { "status", "fixed_version" } } } } }</c>,
    /// about 90 MB) and returns the resolved fixes for the given source packages and releases. Fixed version "0" means
    /// the release was never affected and is skipped.
    /// </summary>
    public static async Task<List<DebianFixRow>> ParseDebianTrackerAsync(Stream stream, IReadOnlySet<string> sources, IReadOnlySet<string> releases,
        CancellationToken ct, int bufferSize = 1 << 16)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var walker = new DebianWalker(sources, releases);
        var buffer = new byte[Math.Max(16, bufferSize)];
        var filled = 0;
        var final = false;
        var state = new JsonReaderState(new JsonReaderOptions { MaxDepth = 64 });
        while (true)
        {
            if (!final && filled < buffer.Length)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(filled), ct);
                if (read == 0)
                {
                    final = true;
                }

                filled += read;
            }

            var consumed = walker.Process(buffer.AsSpan(0, filled), final, ref state);
            if (final && buffer.AsSpan(consumed, filled - consumed).Trim(" \t\r\n"u8).IsEmpty)
            {
                break;
            }

            if (consumed == 0 && filled == buffer.Length)
            {
                Array.Resize(ref buffer, buffer.Length * 2); // a token larger than the buffer (a long description)
            }
            else if (consumed > 0)
            {
                Buffer.BlockCopy(buffer, consumed, buffer, 0, filled - consumed);
                filled -= consumed;
            }
            else if (final)
            {
                throw new JsonException("The Debian Security Tracker data ends unexpectedly.");
            }
        }

        return walker.Result;
    }

    private sealed class DebianWalker(IReadOnlySet<string> sources, IReadOnlySet<string> releases)
    {
        private readonly string?[] names = new string?[8];
        private string? status;
        private string? fixedVersion;

        public List<DebianFixRow> Result { get; } = [];

        public int Process(ReadOnlySpan<byte> data, bool final, ref JsonReaderState state)
        {
            var reader = new Utf8JsonReader(data, final, state);
            while (reader.Read())
            {
                var depth = reader.CurrentDepth;
                switch (reader.TokenType)
                {
                    case JsonTokenType.PropertyName when depth < names.Length:
                        // Only names on the path source → CVE → "releases" → codename → field are needed.
                        names[depth] = depth switch
                        {
                            1 => reader.GetString(),
                            2 => Wanted(1) ? reader.GetString() : null,
                            3 => Wanted(1) && reader.ValueTextEquals("releases"u8) ? "releases" : null,
                            4 => Wanted(1) && names[3] is not null ? reader.GetString() : null,
                            5 => Wanted(1) && names[3] is not null && names[4] is not null ? reader.GetString() : null,
                            _ => null,
                        };
                        break;
                    case JsonTokenType.StartObject when depth == 4:
                        status = null;
                        fixedVersion = null;
                        break;
                    case JsonTokenType.String when depth == 5 && Wanted(1) && names[3] is not null && names[4] is not null:
                        if (names[5] == "status")
                        {
                            status = reader.GetString();
                        }
                        else if (names[5] == "fixed_version")
                        {
                            fixedVersion = reader.GetString();
                        }

                        break;
                    case JsonTokenType.EndObject when depth == 4:
                        if (Wanted(1) && names[3] is not null && names[4] is { } release && releases.Contains(release) && status == "resolved" &&
                            fixedVersion is { Length: > 0 and <= 200 } fixedAt && fixedAt != "0" && names[2] is { } cve && VulnerabilityRules.IsCveId(cve))
                        {
                            Result.Add(new DebianFixRow(release, names[1]!, cve, fixedAt));
                        }

                        break;
                }
            }

            state = reader.CurrentState;
            return (int)reader.BytesConsumed;
        }

        private bool Wanted(int depth) => names[depth] is { } source && sources.Contains(source);
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s
            ? s
            : null;

    private static int? Int(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i) ? i : null;

    private static DateTimeOffset? Date(JsonElement e, string name) =>
        Str(e, name) is { } s && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var d) ? d : null;

    private static DateOnly? DateOnlyOf(string? s) =>
        s is not null && DateOnly.TryParseExact(s, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;

    private static string? Clip(string? s, int max) => s is null ? null : s.Length > max ? s[..max] : s;
}
