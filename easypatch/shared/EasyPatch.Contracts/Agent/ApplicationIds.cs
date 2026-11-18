using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace EasyPatch.Contracts.Agent;

/// <summary>Rules for winget package IDs and versions. Both ends validate with these before an ID or version is stored,
/// sent or put on a winget command line.</summary>
public static partial class ApplicationIds
{
    /// <summary>The only winget source EasyPatch uses (the community repository).</summary>
    public const string Source = "winget";

    public const int MaxIdLength = 128;
    public const int MaxVersionLength = 64;

    /// <summary>Approved applications per policy layer.</summary>
    public const int MaxApproved = 100;

    /// <summary>A winget package ID: <c>Publisher.Package</c> segments of letters, digits, <c>-</c>, <c>_</c> and <c>+</c>,
    /// e.g. <c>Mozilla.Firefox</c>, <c>7zip.7zip</c>, <c>Notepad++.Notepad++</c>.</summary>
    public static bool IsValid(string? id) => id is { Length: > 2 and <= MaxIdLength } && IdPattern().IsMatch(id);

    /// <summary>A concrete version (digits, letters, <c>.</c>, <c>-</c>, <c>_</c>, <c>+</c>); ranges such as <c>&lt; 1.2</c> and
    /// <c>Unknown</c> are not concrete.</summary>
    public static bool IsValidVersion(string? version) =>
        version is { Length: > 0 and <= MaxVersionLength } && VersionPattern().IsMatch(version) &&
        !string.Equals(version, "Unknown", StringComparison.OrdinalIgnoreCase);

    /// <summary>The same version of the same package is the same update on every computer.</summary>
    public static Guid UpdateGuidFor(string id, string version)
    {
        ArgumentNullException.ThrowIfNull(id);
        ArgumentNullException.ThrowIfNull(version);
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes($"easypatch-winget|{id.ToLowerInvariant()}|{version}"), hash);
        var bytes = hash[..16];
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x80);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);
        return new Guid(bytes, bigEndian: true);
    }

    /// <summary>Trimmed, valid and distinct (ignoring case) IDs, in the given order; null when one is invalid.</summary>
    public static IReadOnlyList<string>? Normalize(IEnumerable<string>? ids)
    {
        var result = new List<string>();
        foreach (var raw in ids ?? [])
        {
            var id = raw?.Trim() ?? "";
            if (id.Length == 0)
            {
                continue;
            }

            if (!IsValid(id))
            {
                return null;
            }

            if (!result.Contains(id, StringComparer.OrdinalIgnoreCase))
            {
                result.Add(id);
            }
        }

        return result;
    }

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_+\-]*(\.[A-Za-z0-9_+\-]+)+$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex IdPattern();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._+\-]*$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex VersionPattern();
}
