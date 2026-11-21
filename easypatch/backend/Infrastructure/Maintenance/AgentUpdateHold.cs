using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using EasyPatch.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EasyPatch.Infrastructure.Maintenance;

/// <summary>
/// The host updater's hold on automatic agent updates (EasyRMM's ADR-0052). After an upgrade the updater writes
/// <see cref="FileName"/>, one RFC 3339 time, into its status directory (<see cref="EasyPatchOptions.UpdaterStatusPath"/>,
/// mounted read-only into the worker). Until that time <see cref="AgentUpdateTask"/> starts no agent update, so that a
/// rollback in that time never finds agents ahead of the engine it restores. Updates an operator asks for are not held.
/// Without the file, or the directory, or once the time has passed, nothing is held. A file that cannot be read or does not
/// hold exactly one time holds updates, and is logged as an error at every check: a mistake must never move agents early.
/// </summary>
public sealed partial class AgentUpdateHold(IOptions<EasyPatchOptions> options, ILogger<AgentUpdateHold> logger)
{
    public const string FileName = "agent-updates-held-until";

    /// <summary>The file is one time and a line end; anything longer is not what the updater writes.</summary>
    public const int MaxFileBytes = 256;

    private static readonly string[] Formats = ["yyyy-MM-dd'T'HH:mm:ssK", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK"];

    private readonly Lock gate = new();
    private DateTimeOffset? announced;

    /// <summary>An RFC 3339 date-time with its offset (<c>Z</c> or <c>±hh:mm</c>), fractional seconds optional.</summary>
    [GeneratedRegex(@"^(?<seconds>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.(?<fraction>[0-9]{1,9}))?(?<offset>Z|[+-][0-9]{2}:[0-9]{2})\z",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex Rfc3339();

    public string FilePath => Path.Combine(options.Value.UpdaterStatusPath, FileName);

    /// <summary>Whether automatic agent updates are held at <paramref name="now"/>. Logs when a hold begins, changes or ends,
    /// and every time the file cannot be used.</summary>
    public bool IsHeld(DateTimeOffset now)
    {
        var path = FilePath;
        DateTimeOffset? until;
        try
        {
            until = ReadUntil(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException)
        {
            logger.LogError("Automatic agent updates are held: the host updater's {File} cannot be used ({Reason}); they stay held until it is corrected or removed",
                path, ex.Message);
            return true;
        }

        var held = until > now ? until : null;
        lock (gate)
        {
            if (held != announced)
            {
                if (held is { } time)
                {
                    logger.LogInformation("Automatic agent updates are held by the host updater until {Until} ({File})",
                        time.UtcDateTime.ToString("u", CultureInfo.InvariantCulture), path);
                }
                else
                {
                    logger.LogInformation("Automatic agent updates are no longer held by the host updater");
                }

                announced = held;
            }
        }

        return held is not null;
    }

    /// <summary>The time in the hold file at <paramref name="path"/>, or null when there is no such file or directory. Throws
    /// <see cref="IOException"/> or <see cref="UnauthorizedAccessException"/> when the file cannot be read, and
    /// <see cref="FormatException"/> when it holds anything but one RFC 3339 time (surrounding white space aside).</summary>
    public static DateTimeOffset? ReadUntil(string path)
    {
        var buffer = new byte[MaxFileBytes + 1];
        int length;
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, bufferSize: 1);
            length = file.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }

        if (length > MaxFileBytes)
        {
            throw new FormatException($"it is longer than {MaxFileBytes} bytes");
        }

        return Parse(Encoding.UTF8.GetString(buffer, 0, length).Trim());
    }

    /// <summary>Parses one RFC 3339 date-time. Fractions beyond the 100 ns that <see cref="DateTimeOffset"/> keeps are dropped.</summary>
    public static DateTimeOffset Parse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (Rfc3339().Match(text) is { Success: true } match &&
            DateTimeOffset.TryParseExact(Normalize(match), Formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var time))
        {
            return time;
        }

        throw new FormatException("it does not hold one RFC 3339 time, such as 2026-11-22T07:00:00Z");
    }

    /// <summary>Upper-case <c>T</c> and <c>Z</c>, and at most the seven fractional digits <see cref="DateTimeOffset"/> keeps.</summary>
    private static string Normalize(Match match)
    {
        var fraction = match.Groups["fraction"].Value;
        return (match.Groups["seconds"].Value + (fraction.Length > 0 ? "." + fraction[..Math.Min(fraction.Length, 7)] : "") +
                match.Groups["offset"].Value).ToUpperInvariant();
    }
}
