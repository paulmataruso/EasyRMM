using System.Globalization;
using System.Text;

namespace EasyPatch.Agent.Core.Applications;

/// <summary>One installed application in <c>winget list</c> output.</summary>
/// <param name="Id">The package ID as winget printed it (or as configured when winget shortened it).</param>
/// <param name="Name">The display name, possibly shortened by winget (empty when unknown).</param>
/// <param name="AvailableVersion">A newer version in the winget source, or null.</param>
public sealed record WingetListRow(string Id, string Name, string InstalledVersion, string? AvailableVersion);

/// <summary>
/// Reads winget's console output. winget has no machine-readable "list" output, so the row is located by the package ID
/// (which EasyPatch knows exactly) rather than by column headers, which are translated; the columns after the ID are the
/// installed version, the available version (only when there is one) and the source.
/// </summary>
public static class WingetOutput
{
    private const char Ellipsis = '…';

    /// <summary>winget rewrites progress lines with carriage returns; only the final text of each line counts. Control
    /// characters are removed.</summary>
    public static IReadOnlyList<string> Lines(string? output)
    {
        var lines = new List<string>();
        foreach (var raw in (output ?? string.Empty).Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var lastReturn = line.LastIndexOf('\r');
            if (lastReturn >= 0)
            {
                line = line[(lastReturn + 1)..];
            }

            var clean = new StringBuilder(line.Length);
            foreach (var c in line)
            {
                if (!char.IsControl(c))
                {
                    clean.Append(c);
                }
                else if (c == '\t')
                {
                    clean.Append(' ');
                }
            }

            if (clean.Length > 0)
            {
                lines.Add(clean.ToString());
            }
        }

        return lines;
    }

    /// <summary>The row of <paramref name="id"/>, or null when winget did not list it.</summary>
    public static WingetListRow? FindRow(string? output, string id)
    {
        ArgumentNullException.ThrowIfNull(id);
        foreach (var line in Lines(output))
        {
            var tokens = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var index = -1;
            for (var i = tokens.Length - 1; i >= 0; i--)
            {
                if (MatchesId(tokens[i], id))
                {
                    index = i;
                    break;
                }
            }

            if (index < 0)
            {
                continue;
            }

            var rest = tokens[(index + 1)..].ToList();
            if (rest.Count > 0 && string.Equals(rest[^1], Contracts.Agent.ApplicationIds.Source, StringComparison.OrdinalIgnoreCase))
            {
                rest.RemoveAt(rest.Count - 1);
            }

            if (rest.Count == 0)
            {
                continue;
            }

            // "< 1.2.3" / "> 1.2.3": winget could not determine the exact installed version.
            var installed = rest[0] is "<" or ">" && rest.Count > 1 ? rest[0] + " " + rest[1] : rest[0];
            var consumed = installed.Contains(' ', StringComparison.Ordinal) ? 2 : 1;
            var available = rest.Count > consumed ? rest[consumed] : null;
            var printedId = tokens[index].EndsWith(Ellipsis) ? id : tokens[index];
            var name = string.Join(' ', tokens[..index]).TrimEnd(Ellipsis).Trim();
            return new WingetListRow(printedId, name, installed, available);
        }

        return null;
    }

    /// <summary>"v1.9.25200" → 1.9.25200 (null when the output has no version).</summary>
    public static Version? ParseWingetVersion(string? output)
    {
        foreach (var line in Lines(output))
        {
            var text = line.Trim().TrimStart('v', 'V');
            var end = 0;
            while (end < text.Length && (char.IsAsciiDigit(text[end]) || text[end] == '.'))
            {
                end++;
            }

            if (end > 0 && Version.TryParse(text[..end].TrimEnd('.'), out var version))
            {
                return version;
            }
        }

        return null;
    }

    /// <summary>The last lines of the output for an error message (without progress bars).</summary>
    public static string Tail(string? output, int maxChars = 600)
    {
        var lines = Lines(output)
            .Select(l => l.Trim())
            .Where(l => l.Length > 1 && !l.All(c => c is '█' or '▒' or '-' or '\\' or '|' or '/' or ' '))
            .ToList();
        var text = string.Join(" ", lines.TakeLast(6));
        return text.Length <= maxChars ? text : "…" + text[^maxChars..];
    }

    /// <summary>winget exit codes are HRESULTs; shown as 0x8A15xxxx.</summary>
    public static string FormatExitCode(int exitCode) =>
        exitCode is >= 0 and < 0x10000 ? exitCode.ToString(CultureInfo.InvariantCulture) : "0x" + ((uint)exitCode).ToString("X8", CultureInfo.InvariantCulture);

    private static bool MatchesId(string token, string id)
    {
        if (string.Equals(token, id, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // winget shortens long values to fit the console width: "Microsoft.VisualStudioCo…".
        return token.Length >= 9 && token[^1] == Ellipsis && id.StartsWith(token[..^1], StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>winget exit codes EasyPatch distinguishes (APPINSTALLER_CLI_ERROR_*).</summary>
public static class WingetExitCodes
{
    public const int NoApplicationsFound = unchecked((int)0x8A150014);
    public const int UpdateNotApplicable = unchecked((int)0x8A15002B);
    public const int PackageInUse = unchecked((int)0x8A150101);
    public const int InstallInProgress = unchecked((int)0x8A150102);
    public const int FileInUse = unchecked((int)0x8A150103);
    public const int MissingDependency = unchecked((int)0x8A150104);
    public const int DiskFull = unchecked((int)0x8A150105);
    public const int InsufficientMemory = unchecked((int)0x8A150106);
    public const int NoNetwork = unchecked((int)0x8A150107);
    public const int ContactSupport = unchecked((int)0x8A150108);
    public const int RebootRequiredToFinish = unchecked((int)0x8A150109);
    public const int RebootRequiredToInstall = unchecked((int)0x8A15010A);
    public const int RebootInitiated = unchecked((int)0x8A15010B);
    public const int CancelledByUser = unchecked((int)0x8A15010C);
    public const int AlreadyInstalled = unchecked((int)0x8A15010D);
    public const int Downgrade = unchecked((int)0x8A15010E);
    public const int BlockedByPolicy = unchecked((int)0x8A15010F);

    public static bool IsRebootRequired(int exitCode) => exitCode is RebootRequiredToFinish or RebootRequiredToInstall or RebootInitiated;

    public static string? Describe(int exitCode) => exitCode switch
    {
        0 => null,
        NoApplicationsFound => "The application is not installed.",
        UpdateNotApplicable => "winget has no applicable upgrade for the application.",
        PackageInUse => "The application is running; close it and try again.",
        InstallInProgress => "Another installation is in progress.",
        FileInUse => "A file of the application is in use.",
        MissingDependency => "A dependency of the installer is missing.",
        DiskFull => "The disk is full.",
        InsufficientMemory => "There is not enough memory.",
        NoNetwork => "The installer could not reach the network.",
        ContactSupport => "The installer failed; contact the application's vendor.",
        RebootRequiredToFinish => "A restart is needed to finish the upgrade.",
        RebootRequiredToInstall => "A restart is needed before the upgrade can be installed.",
        RebootInitiated => "The installer started a restart.",
        CancelledByUser => "The installation was cancelled.",
        AlreadyInstalled => "Another version of the application is already installed.",
        Downgrade => "A newer version of the application is already installed.",
        BlockedByPolicy => "The installation is blocked by policy.",
        _ => null,
    };
}
