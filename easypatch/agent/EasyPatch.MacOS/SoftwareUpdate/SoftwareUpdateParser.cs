using System.Globalization;
using System.Text.RegularExpressions;

namespace EasyPatch.MacOS.SoftwareUpdate;

/// <summary>An update listed by <c>softwareupdate --list</c>.</summary>
/// <param name="Label">The name <c>softwareupdate --install</c> takes, e.g. <c>macOS Sequoia 15.7.2-24G325</c>.</param>
/// <param name="RestartRequired"><c>Action: restart</c>: the update completes when the Mac restarts.</param>
public sealed record SoftwareUpdateItem(string Label, string Title, string Version, long? SizeBytes, bool Recommended, bool RestartRequired);

/// <summary>An entry of <c>softwareupdate --history</c>.</summary>
public sealed record SoftwareUpdateHistoryEntry(string Title, string Version, DateTimeOffset? Date);

/// <summary>Thrown when <c>softwareupdate</c> output cannot be understood. Nothing is reported from such output: an
/// unreadable list must never look like "no updates".</summary>
public sealed class SoftwareUpdateException : Exception
{
    public SoftwareUpdateException()
    {
    }

    public SoftwareUpdateException(string message)
        : base(message)
    {
    }

    public SoftwareUpdateException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public SoftwareUpdateException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    /// <summary>Short machine-readable error code.</summary>
    public string Code { get; } = "softwareupdate_failed";
}

/// <summary>Parses the output of <c>softwareupdate --list</c> and <c>softwareupdate --history</c> (macOS 12 and later).</summary>
public static partial class SoftwareUpdateParser
{
    private const string FoundMarker = "Software Update found the following new or updated software:";
    private const string NoneMarker = "No new software available.";

    private static readonly string[] Keys = ["Title", "Version", "Size", "Recommended", "Action", "Deferred"];

    /// <summary>
    /// The updates in <c>softwareupdate --list</c> output (standard output and standard error together). The output must say
    /// either that updates were found or that there are none; anything else (no network, a catalog error) is an exception.
    /// </summary>
    /// <exception cref="SoftwareUpdateException">The output is not a successful listing.</exception>
    public static IReadOnlyList<SoftwareUpdateItem> ParseList(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var lines = output.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n');
        var found = lines.Any(l => l.Trim() == FoundMarker);
        if (!found)
        {
            if (lines.Any(l => l.Trim() == NoneMarker))
            {
                return [];
            }

            throw new SoftwareUpdateException("softwareupdate_failed",
                "softwareupdate did not list the available updates: " + Summarize(output));
        }

        var items = new List<SoftwareUpdateItem>();
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();
            if (!line.StartsWith("* Label: ", StringComparison.Ordinal))
            {
                continue;
            }

            var label = line["* Label: ".Length..].Trim();
            var details = i + 1 < lines.Length ? lines[i + 1].Trim() : string.Empty;
            if (label.Length == 0 || !details.StartsWith("Title: ", StringComparison.Ordinal))
            {
                throw new SoftwareUpdateException("softwareupdate_unexpected_output",
                    $"softwareupdate listed '{label}' without the expected details: " + Summarize(details));
            }

            var fields = ParseFields(details);
            var title = fields.GetValueOrDefault("Title") ?? label;
            var version = fields.GetValueOrDefault("Version") ?? string.Empty;
            items.Add(new SoftwareUpdateItem(
                label,
                title,
                version,
                ParseSize(fields.GetValueOrDefault("Size")),
                string.Equals(fields.GetValueOrDefault("Recommended"), "YES", StringComparison.OrdinalIgnoreCase),
                string.Equals(fields.GetValueOrDefault("Action"), "restart", StringComparison.OrdinalIgnoreCase)));
        }

        if (items.Count == 0)
        {
            throw new SoftwareUpdateException("softwareupdate_unexpected_output",
                "softwareupdate reported updates but none could be read: " + Summarize(output));
        }

        return items;
    }

    /// <summary>"Title: X, Version: 1.2, Size: 123KiB, Recommended: YES, Action: restart," split on the known keys only, so a
    /// title containing a comma stays whole.</summary>
    internal static Dictionary<string, string> ParseFields(string details)
    {
        var positions = new List<(int Index, string Key)>();
        foreach (var key in Keys)
        {
            var marker = key == "Title" ? "Title: " : ", " + key + ": ";
            var index = key == "Title" ? (details.StartsWith(marker, StringComparison.Ordinal) ? 0 : -1) : details.IndexOf(marker, StringComparison.Ordinal);
            if (index >= 0)
            {
                positions.Add((index, key));
            }
        }

        positions.Sort((a, b) => a.Index.CompareTo(b.Index));
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var p = 0; p < positions.Count; p++)
        {
            var (index, key) = positions[p];
            var start = index + (key == "Title" ? "Title: ".Length : 2 + key.Length + 2);
            var end = p + 1 < positions.Count ? positions[p + 1].Index : details.Length;
            fields[key] = details[start..Math.Max(start, end)].Trim().TrimEnd(',').Trim();
        }

        return fields;
    }

    /// <summary>"6887516KiB" or "6887516K" (kibibytes), as bytes.</summary>
    internal static long? ParseSize(string? text)
    {
        var match = SizeRegex().Match(text ?? string.Empty);
        return match.Success && long.TryParse(match.Groups["value"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var kib)
            ? kib * 1024
            : null;
    }

    /// <summary>
    /// Entries of <c>softwareupdate --history</c>: a header ("Display Name  Version  Date"), a dashed line, then one line per
    /// installation in fixed-width columns (a ten-character version such as <c>13.4.1 (a)</c> leaves one space before the date).
    /// Lines that do not fit are skipped.
    /// </summary>
    public static IReadOnlyList<SoftwareUpdateHistoryEntry> ParseHistory(string output)
    {
        ArgumentNullException.ThrowIfNull(output);
        var entries = new List<SoftwareUpdateHistoryEntry>();
        var inTable = false;
        foreach (var raw in output.Replace("\r", string.Empty, StringComparison.Ordinal).Split('\n'))
        {
            var line = raw.TrimEnd();
            if (!inTable)
            {
                inTable = line.TrimStart().StartsWith("---", StringComparison.Ordinal);
                continue;
            }

            var match = HistoryLineRegex().Match(line);
            if (!match.Success)
            {
                continue;
            }

            entries.Add(new SoftwareUpdateHistoryEntry(match.Groups["name"].Value.Trim(), match.Groups["version"].Value.Trim(),
                ParseHistoryDate(match.Groups["date"].Value.Trim())));
        }

        return entries;
    }

    private static readonly string[] HistoryDateFormats = ["MM/dd/yyyy, HH:mm:ss", "M/d/yyyy, H:mm:ss", "MM/dd/yyyy HH:mm:ss", "yyyy-MM-dd HH:mm:ss"];

    /// <summary>History dates are the Mac's local time.</summary>
    internal static DateTimeOffset? ParseHistoryDate(string text) =>
        DateTime.TryParseExact(text, HistoryDateFormats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var date)
            ? new DateTimeOffset(date)
            : null;

    /// <summary>Compares dotted versions numerically (<c>15.10</c> &gt; <c>15.9</c>), falling back to ordinal comparison.</summary>
    public static int CompareVersions(string? left, string? right)
    {
        var a = (left ?? string.Empty).Split(['.', ' ', '-'], StringSplitOptions.RemoveEmptyEntries);
        var b = (right ?? string.Empty).Split(['.', ' ', '-'], StringSplitOptions.RemoveEmptyEntries);
        for (var i = 0; i < Math.Max(a.Length, b.Length); i++)
        {
            var x = i < a.Length ? a[i] : "0";
            var y = i < b.Length ? b[i] : "0";
            var result = long.TryParse(x, NumberStyles.None, CultureInfo.InvariantCulture, out var nx) &&
                         long.TryParse(y, NumberStyles.None, CultureInfo.InvariantCulture, out var ny)
                ? nx.CompareTo(ny)
                : string.CompareOrdinal(x, y);
            if (result != 0)
            {
                return result;
            }
        }

        return 0;
    }

    internal static string Summarize(string? text)
    {
        var summary = OutputRedactor.Summarize(text, 600);
        return summary.Length == 0 ? "(no output)" : summary;
    }

    [GeneratedRegex(@"^(?<value>\d+)\s*K(?:iB)?$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex SizeRegex();

    [GeneratedRegex(@"^(?<name>\S.*?)\s{2,}(?<version>\S+(?: \(\w\))?)\s+(?<date>\d{1,2}/\d{1,2}/\d{4}.*|\d{4}-\d{2}-\d{2}.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex HistoryLineRegex();
}
