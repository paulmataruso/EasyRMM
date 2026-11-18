using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using EasyPatch.Agent.Core.Abstractions;

namespace EasyPatch.Agent.Core.Logging;

/// <summary>
/// Reads the newest entries of the agent's log files (written by <see cref="RollingFileLoggerProvider"/>) for the
/// status window. Only the first line of each information, warning or error entry is returned: exception details,
/// debug and trace entries stay in the file. Every message passes through <see cref="LogRedactor"/> again.
/// </summary>
public static partial class AgentLogTail
{
    public const int DefaultMaxEntries = 200;
    public const int MaxMessageLength = 300;

    /// <summary>Bytes read from the end of each file; plenty for <see cref="DefaultMaxEntries"/> entries.</summary>
    private const int MaxBytesPerFile = 256 * 1024;

    /// <summary>The newest entries, oldest first. Missing or unreadable files give no entries.</summary>
    /// <param name="directory">The log directory.</param>
    /// <param name="fileName">The active file (rotated files are <c>stem.1.ext</c>, <c>stem.2.ext</c>, ...).</param>
    public static IReadOnlyList<TrayLogEntry> Read(string directory, string fileName = "agent.log", int maxEntries = DefaultMaxEntries)
    {
        ArgumentException.ThrowIfNullOrEmpty(directory);
        ArgumentException.ThrowIfNullOrEmpty(fileName);
        var entries = Parse(ReadTail(Path.Combine(directory, fileName)));
        if (entries.Count < maxEntries)
        {
            // The active file was rotated recently: the rest comes from the previous file.
            var rotated = Path.Combine(directory, $"{Path.GetFileNameWithoutExtension(fileName)}.1{Path.GetExtension(fileName)}");
            entries.InsertRange(0, Parse(ReadTail(rotated)));
        }

        return entries.Count > maxEntries ? entries.GetRange(entries.Count - maxEntries, maxEntries) : entries;
    }

    /// <summary>Parses log text into entries, oldest first.</summary>
    public static List<TrayLogEntry> Parse(string text)
    {
        var entries = new List<TrayLogEntry>();
        foreach (var raw in text.Split('\n'))
        {
            var match = EntryLine().Match(raw.TrimEnd('\r'));
            if (!match.Success)
            {
                continue; // exception details and other continuation lines
            }

            var level = match.Groups["level"].Value switch
            {
                "INF" => TrayLogLevel.Information,
                "WRN" => TrayLogLevel.Warning,
                "ERR" or "CRT" => TrayLogLevel.Error,
                _ => (TrayLogLevel?)null, // DBG, TRC
            };
            if (level is null || !DateTimeOffset.TryParseExact(match.Groups["at"].Value, "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at))
            {
                continue;
            }

            var message = LogRedactor.Redact(match.Groups["message"].Value).Trim();
            if (message.Length > MaxMessageLength)
            {
                message = message[..(MaxMessageLength - 1)] + "…";
            }

            entries.Add(new TrayLogEntry(at, level.Value, message));
        }

        return entries;
    }

    private static string ReadTail(string path)
    {
        try
        {
            // The logger appends with FileShare.ReadWrite | FileShare.Delete; reading must allow both.
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var start = Math.Max(0, stream.Length - MaxBytesPerFile);
            stream.Seek(start, SeekOrigin.Begin);
            var buffer = new byte[stream.Length - start];
            var read = stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
            var text = Encoding.UTF8.GetString(buffer, 0, read);
            if (start > 0)
            {
                // Started mid-line (or mid-character): drop the partial first line.
                var newline = text.IndexOf('\n', StringComparison.Ordinal);
                text = newline < 0 ? string.Empty : text[(newline + 1)..];
            }

            return text;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

    // "2026-11-14T23:49:13.123Z INF EasyPatch.Agent.Core.Runtime.AgentRuntime: message"
    [GeneratedRegex(@"^(?<at>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z) (?<level>[A-Z]{3}) [^:\s]+: (?<message>.*)$")]
    private static partial Regex EntryLine();
}
