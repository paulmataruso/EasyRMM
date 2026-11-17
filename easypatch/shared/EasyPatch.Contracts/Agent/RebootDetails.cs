using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace EasyPatch.Contracts.Agent;

/// <summary>
/// What Windows has queued for the next restart, behind the restart reasons (Windows agent 1.5.3 and later). Sent with
/// check-ins and scans only while a restart is pending. Both sides cap and clean it with <see cref="Sanitized"/>.
/// </summary>
public sealed partial record RebootDetails
{
    public const int MaxUpdates = 50;
    public const int MaxPackages = 50;
    public const int MaxFileOperations = 25;
    public const int MaxPathLength = 260;

    /// <summary>Windows Update IDs listed under <c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired</c>.</summary>
    public IReadOnlyList<Guid> WindowsUpdateIds { get; init; } = [];

    /// <summary>Servicing packages waiting for the restart (Component Based Servicing <c>PackagesPending</c> and
    /// <c>RebootPending</c>), for example <c>Package_for_KB5044284~31bf3856ad364e35~amd64~~26100.2033.1.4</c>.</summary>
    public IReadOnlyList<string> ServicingPackages { get; init; } = [];

    /// <summary>Files Windows will replace or delete during the restart (<c>PendingFileRenameOperations</c>), with user
    /// names in profile paths replaced by <c>*</c>.</summary>
    public IReadOnlyList<PendingFileOperation> FileOperations { get; init; } = [];

    /// <summary>The number of file operations before <see cref="FileOperations"/> was capped.</summary>
    public int FileOperationCount { get; init; }

    [JsonIgnore]
    public bool IsEmpty => WindowsUpdateIds.Count == 0 && ServicingPackages.Count == 0 && FileOperations.Count == 0;

    /// <summary>Whether a servicing package name contains a KB number.</summary>
    public static bool NamesKb(string package) => KbPattern().IsMatch(package);

    /// <summary>KB numbers named by the servicing packages (<c>Package_for_KB5044284~…</c> → <c>KB5044284</c>).</summary>
    public IReadOnlyList<string> ServicingKbNumbers() =>
        ServicingPackages.Select(p => KbPattern().Match(p)).Where(m => m.Success).Select(m => "KB" + m.Groups[1].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>Caps the lists, drops empty and duplicate entries, removes control characters and shortens long values.</summary>
    public RebootDetails Sanitized()
    {
        var operations = FileOperations
            .Where(o => o is not null && !string.IsNullOrWhiteSpace(o.Path))
            .Select(o => new PendingFileOperation
            {
                Action = o.Action == PendingFileOperation.Delete ? PendingFileOperation.Delete : PendingFileOperation.Replace,
                Path = Clean(CleanPath(o.Path), MaxPathLength),
            })
            .Distinct()
            .ToList();
        return new RebootDetails
        {
            WindowsUpdateIds = WindowsUpdateIds.Where(g => g != Guid.Empty).Distinct().Take(MaxUpdates).ToList(),
            ServicingPackages = ServicingPackages.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => Clean(p, 200))
                .Distinct(StringComparer.OrdinalIgnoreCase).Take(MaxPackages).ToList(),
            FileOperations = operations.Take(MaxFileOperations).ToList(),
            FileOperationCount = Math.Max(Math.Max(FileOperationCount, operations.Count), 0),
        };
    }

    /// <summary>
    /// A path as Windows queues it (<c>\??\C:\…</c>, with optional <c>!</c> or <c>*1</c> markers in front) as a plain path, with the
    /// user name of profile paths replaced by <c>*</c> (<c>C:\Users\alice\AppData\…</c> → <c>C:\Users\*\AppData\…</c>). Applied by
    /// the agent and again by the server, so user names are never stored.
    /// </summary>
    public static string CleanPath(string? raw)
    {
        var path = PathMarkers().Replace(raw?.Trim() ?? string.Empty, string.Empty);
        if (path.StartsWith(@"UNC\", StringComparison.OrdinalIgnoreCase))
        {
            path = @"\\" + path[4..];
        }

        return UserProfile().Replace(path, "${prefix}*");
    }

    private static string Clean(string value, int maxLength)
    {
        var text = new string(value.Trim().Where(c => !char.IsControl(c)).ToArray());
        return text.Length <= maxLength ? text : text[..(maxLength - 1)] + "…";
    }

    // Leading "!" (replace existing), "*1"/"*2" and "@" markers, then the NT prefix "\??\" or "\\?\".
    [GeneratedRegex(@"^(?:[!@]|\*\d*)*(?:\\\?\?\\|\\\\\?\\)?", RegexOptions.CultureInvariant)]
    private static partial Regex PathMarkers();

    [GeneratedRegex(@"(?<prefix>(?:^|\\)(?:Users|Documents and Settings)\\)[^\\]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UserProfile();

    [GeneratedRegex(@"(?:^|[_~])KB(\d{6,8})(?=[~_.]|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex KbPattern();
}

/// <summary>A file Windows changes during the next restart.</summary>
public sealed record PendingFileOperation
{
    public const string Delete = "Delete";
    public const string Replace = "Replace";

    /// <summary><see cref="Delete"/> or <see cref="Replace"/> (the file at <see cref="Path"/> is replaced or renamed).</summary>
    public required string Action { get; init; }

    /// <summary>The file that is deleted or replaced.</summary>
    public required string Path { get; init; }
}
