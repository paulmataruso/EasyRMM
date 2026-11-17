using System.Text;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Logging;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>The recent log shown in the tray's status window.</summary>
public sealed class AgentLogTailTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "easypatch-logtail-" + Guid.NewGuid().ToString("N"));

    public AgentLogTailTests() => Directory.CreateDirectory(_dir);

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    [Fact]
    public void Only_first_lines_of_information_warning_and_error_entries_are_shown_redacted()
    {
        File.WriteAllText(Path.Combine(_dir, "agent.log"), string.Join("\n",
            "2026-11-14T10:00:00.000Z INF EasyPatch.Agent.Core.Runtime.AgentRuntime: EasyPatch agent 1.5.0 starting.",
            "2026-11-14T10:00:01.000Z DBG EasyPatch.Agent.Core.Ipc.TrayBroker: Tray connected in session 2.",
            "2026-11-14T10:00:02.250Z WRN EasyPatch.Agent.Core.Runtime.AgentRuntime: Server unreachable; retrying in 00:01:00.",
            "System.Net.Http.HttpRequestException: Connection refused",
            "   at Something.Secret(String path)",
            "2026-11-14T10:00:03.000Z ERR EasyPatch.Agent.Core.Scanning.ScanService: Windows Update scan failed (0x8024402C).",
            "2026-11-14T10:00:04.000Z CRT EasyPatch.Agent.Core.Runtime.AgentRuntime: Enrollment token=ept_abcdefghijklmnop was refused.",
            "2026-11-14T10:00:05.000Z INF EasyPatch.Agent.Core.Runtime.AgentRuntime: " + new string('z', 1000),
            "not a log line",
            "") + "\r\n");

        var entries = AgentLogTail.Read(_dir);

        Assert.Equal(5, entries.Count);
        Assert.Equal(new TrayLogEntry(new DateTimeOffset(2026, 11, 14, 10, 0, 0, TimeSpan.Zero), TrayLogLevel.Information, "EasyPatch agent 1.5.0 starting."), entries[0]);
        Assert.Equal(TrayLogLevel.Warning, entries[1].Level);
        Assert.Equal(new DateTimeOffset(2026, 11, 14, 10, 0, 2, 250, TimeSpan.Zero), entries[1].At);
        Assert.Equal("Server unreachable; retrying in 00:01:00.", entries[1].Message);
        Assert.Equal(TrayLogLevel.Error, entries[2].Level);
        Assert.Equal(TrayLogLevel.Error, entries[3].Level);
        Assert.DoesNotContain("ept_abcdefghijklmnop", entries[3].Message, StringComparison.Ordinal);
        Assert.Equal(AgentLogTail.MaxMessageLength, entries[4].Message.Length);
        Assert.EndsWith("…", entries[4].Message, StringComparison.Ordinal);
        Assert.DoesNotContain(entries, e => e.Message.Contains("Secret", StringComparison.Ordinal) || e.Message.Contains("session 2", StringComparison.Ordinal));
    }

    [Fact]
    public void The_newest_entries_come_from_the_active_file_then_the_rotated_one()
    {
        File.WriteAllText(Path.Combine(_dir, "agent.1.log"), Lines(0, 5));
        File.WriteAllText(Path.Combine(_dir, "agent.log"), Lines(5, 3));

        var entries = AgentLogTail.Read(_dir, maxEntries: 6);
        Assert.Equal(["entry 2", "entry 3", "entry 4", "entry 5", "entry 6", "entry 7"], entries.Select(e => e.Message));

        // Enough in the active file: the rotated file is not needed.
        Assert.Equal(["entry 6", "entry 7"], AgentLogTail.Read(_dir, maxEntries: 2).Select(e => e.Message));
    }

    [Fact]
    public void A_large_file_is_read_from_its_end_and_the_partial_first_line_is_dropped()
    {
        // About 1 MB: only the end is read, starting mid-line.
        File.WriteAllText(Path.Combine(_dir, "agent.log"), Lines(0, 12_000, padding: 70), new UTF8Encoding(false));

        var entries = AgentLogTail.Read(_dir);

        Assert.Equal(AgentLogTail.DefaultMaxEntries, entries.Count);
        Assert.StartsWith("entry 11999 ", entries[^1].Message, StringComparison.Ordinal);
        Assert.All(entries, e => Assert.Matches(@"^entry \d+ x+$", e.Message));
    }

    [Fact]
    public void Missing_files_give_no_entries()
    {
        Assert.Empty(AgentLogTail.Read(_dir));
        Assert.Empty(AgentLogTail.Read(Path.Combine(_dir, "nope")));
    }

    private static string Lines(int first, int count, int padding = 0)
    {
        var text = new StringBuilder();
        var start = new DateTimeOffset(2026, 11, 14, 0, 0, 0, TimeSpan.Zero);
        for (var i = first; i < first + count; i++)
        {
            var at = start.AddSeconds(i).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture);
            text.Append(at).Append(" INF EasyPatch.Agent.Test: entry ").Append(i);
            if (padding > 0)
            {
                text.Append(' ').Append('x', padding);
            }

            text.Append('\n');
        }

        return text.ToString();
    }
}
