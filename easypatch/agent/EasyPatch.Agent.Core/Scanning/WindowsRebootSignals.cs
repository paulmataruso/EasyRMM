using EasyPatch.Contracts.Agent;

namespace EasyPatch.Agent.Core.Scanning;

/// <summary>
/// Turns the registry entries Windows uses for a pending restart into <see cref="RebootDetails"/>: which updates, servicing
/// packages and files are waiting for it. Pure functions; the Windows detector reads the registry.
/// </summary>
public static class WindowsRebootSignals
{
    /// <summary>Value or subkey names under <c>WindowsUpdate\Auto Update\RebootRequired</c> that are update IDs.</summary>
    public static IReadOnlyList<Guid> UpdateIds(IEnumerable<string> names) =>
        names.Select(n => Guid.TryParse(n.Trim().Trim('{', '}'), out var id) ? id : Guid.Empty)
            .Where(id => id != Guid.Empty).Distinct().ToList();

    /// <summary>Value or subkey names under Component Based Servicing <c>PackagesPending</c> / <c>RebootPending</c> that name
    /// servicing packages (<c>Package_for_KB5044284~31bf3856ad364e35~amd64~~26100.2033.1.4</c>).</summary>
    public static IReadOnlyList<string> Packages(IEnumerable<string> names) =>
        names.Select(n => n.Trim())
            .Where(n => n.StartsWith("Package_", StringComparison.OrdinalIgnoreCase) || n.Count(c => c == '~') >= 3)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// <summary>
    /// <c>Session Manager\PendingFileRenameOperations</c>: pairs of source and destination. An empty destination deletes the
    /// source; otherwise the destination is replaced (or created) by the source.
    /// </summary>
    public static IReadOnlyList<PendingFileOperation> FileOperations(IReadOnlyList<string>? values)
    {
        var operations = new List<PendingFileOperation>();
        if (values is null)
        {
            return operations;
        }

        for (var i = 0; i < values.Count; i += 2)
        {
            var source = CleanPath(values[i]);
            if (source.Length == 0)
            {
                continue;
            }

            var destination = i + 1 < values.Count ? CleanPath(values[i + 1]) : string.Empty;
            operations.Add(destination.Length == 0
                ? new PendingFileOperation { Action = PendingFileOperation.Delete, Path = source }
                : new PendingFileOperation { Action = PendingFileOperation.Replace, Path = destination });
        }

        return operations.Distinct().ToList();
    }

    /// <summary>
    /// Whether the queued file operations need a restart: only replacements do (a file in use waits for the restart to be
    /// updated). Deletions are cleanup that Windows does at the next start, for example temporary files left by
    /// installers, so they alone do not make a restart necessary.
    /// </summary>
    public static bool NeedRestart(IReadOnlyList<PendingFileOperation> operations) =>
        operations.Any(o => o.Action != PendingFileOperation.Delete);

    /// <summary>See <see cref="RebootDetails.CleanPath"/>: a plain path without user names.</summary>
    public static string CleanPath(string? raw) => RebootDetails.CleanPath(raw);
}
