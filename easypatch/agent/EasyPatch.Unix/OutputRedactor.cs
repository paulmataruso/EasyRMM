using System.Text.RegularExpressions;

namespace EasyPatch.Unix;

/// <summary>Removes credentials from package-manager output before it is logged or sent to the server: repository URLs
/// may carry a user name and password or token (<c>https://user:secret@host/…</c>).</summary>
public static partial class OutputRedactor
{
    [GeneratedRegex(@"(?<scheme>[A-Za-z][A-Za-z0-9+.\-]*://)[^/@\s]+@", RegexOptions.CultureInvariant)]
    private static partial Regex UserInfoRegex();

    [GeneratedRegex(@"(?<key>[?&](?:token|access_token|auth|key|password|passwd|secret|signature|sig)=)[^&\s]+",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex QueryRegex();

    public static string Redact(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        text = UserInfoRegex().Replace(text, "${scheme}***@");
        return QueryRegex().Replace(text, "${key}***");
    }

    /// <summary>The most useful part of a failed command's output for a job item: its error lines when there are any,
    /// otherwise its last lines, redacted and at most <paramref name="maxLength"/> characters.</summary>
    public static string Summarize(string? output, int maxLength = 1000)
    {
        var lines = Redact(output).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var errors = lines.Where(l => l.StartsWith("E:", StringComparison.Ordinal) || l.StartsWith("Error", StringComparison.Ordinal) ||
                                      l.StartsWith("dpkg: error", StringComparison.Ordinal) || l.Contains("error:", StringComparison.Ordinal) ||
                                      l.StartsWith("Problem", StringComparison.Ordinal) || l.StartsWith("- ", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal).ToList();
        var chosen = errors.Count > 0 ? errors : lines.TakeLast(8).ToList();
        var text = string.Join(" ", chosen);
        return text.Length <= maxLength ? text : text[..(maxLength - 1)] + "…";
    }
}
