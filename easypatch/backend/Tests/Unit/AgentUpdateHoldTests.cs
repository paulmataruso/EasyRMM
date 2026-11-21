using EasyPatch.Infrastructure.Maintenance;
using EasyPatch.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace EasyPatch.Tests.Unit;

/// <summary>The host updater's hold on automatic agent updates, read from a real status directory (EasyRMM's ADR-0052).</summary>
public sealed class AgentUpdateHoldTests : IDisposable
{
    private static readonly DateTimeOffset Now = new(2026, 11, 21, 7, 0, 0, TimeSpan.Zero);

    private readonly string directory = Directory.CreateTempSubdirectory("easypatch-updater-").FullName;
    private readonly CapturedLog<AgentUpdateHold> log = new();

    public void Dispose() => Directory.Delete(directory, recursive: true);

    private string HoldFile => Path.Combine(directory, AgentUpdateHold.FileName);

    private AgentUpdateHold Hold(string? statusPath = null) =>
        new(Options.Create(new EasyPatchOptions { UpdaterStatusPath = statusPath ?? directory }), log);

    [Fact]
    public void Without_the_file_or_its_directory_nothing_is_held()
    {
        Assert.False(Hold().IsHeld(Now));
        Assert.False(Hold(Path.Combine(directory, "missing")).IsHeld(Now));
        Assert.Empty(log.Entries);
    }

    [Fact]
    public void A_time_still_ahead_holds_updates_and_the_hold_is_logged_when_it_begins_changes_and_ends()
    {
        var hold = Hold();
        File.WriteAllText(HoldFile, "2026-11-22T07:00:00Z\n");

        Assert.True(hold.IsHeld(Now));
        Assert.True(hold.IsHeld(Now.AddHours(1)));
        var (level, message) = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Information, level);
        Assert.Equal($"Automatic agent updates are held by the host updater until 2026-11-22 07:00:00Z ({HoldFile})", message);

        File.WriteAllText(HoldFile, "2026-11-22T09:30:00Z");
        Assert.True(hold.IsHeld(Now.AddHours(2)));
        Assert.Equal(2, log.Entries.Count);
        Assert.Contains("until 2026-11-22 09:30:00Z", log.Entries[1].Message, StringComparison.Ordinal);

        // Held while now is before the time, and no longer at it.
        Assert.True(hold.IsHeld(new DateTimeOffset(2026, 11, 22, 9, 29, 59, TimeSpan.Zero)));
        Assert.False(hold.IsHeld(new DateTimeOffset(2026, 11, 22, 9, 30, 0, TimeSpan.Zero)));
        Assert.False(hold.IsHeld(new DateTimeOffset(2026, 11, 22, 10, 0, 0, TimeSpan.Zero)));
        Assert.Equal(3, log.Entries.Count);
        Assert.Equal((LogLevel.Information, "Automatic agent updates are no longer held by the host updater"), log.Entries[2]);
    }

    [Fact]
    public void A_time_that_has_passed_holds_nothing()
    {
        File.WriteAllText(HoldFile, "2026-11-20T07:00:00Z\n");
        Assert.False(Hold().IsHeld(Now));
        Assert.Empty(log.Entries);
    }

    [Theory]
    [InlineData("")]
    [InlineData("\n")]
    [InlineData("tomorrow")]
    [InlineData("2026-11-22T07:00:00")] // no offset
    [InlineData("2026-11-22")]
    [InlineData("2026-11-22T07:00:00.Z")]
    [InlineData("2026-02-30T07:00:00Z")]
    [InlineData("1763794800")]
    [InlineData("2026-11-22T07:00:00Z\n2026-11-23T07:00:00Z")]
    [InlineData("\"2026-11-22T07:00:00Z\"")]
    public void A_file_without_one_time_holds_updates_and_is_logged_as_an_error_at_every_check(string content)
    {
        var hold = Hold();
        File.WriteAllText(HoldFile, content);

        Assert.True(hold.IsHeld(Now));
        Assert.True(hold.IsHeld(Now.AddMinutes(2)));
        Assert.Equal(2, log.Entries.Count);
        Assert.All(log.Entries, e =>
        {
            Assert.Equal(LogLevel.Error, e.Level);
            Assert.StartsWith($"Automatic agent updates are held: the host updater's {HoldFile} cannot be used (it does not hold one RFC 3339 time",
                e.Message, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void A_file_longer_than_a_time_holds_updates()
    {
        File.WriteAllText(HoldFile, new string(' ', AgentUpdateHold.MaxFileBytes) + "2026-11-22T07:00:00Z");
        Assert.True(Hold().IsHeld(Now));
        var (level, message) = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Error, level);
        Assert.Contains($"{HoldFile} cannot be used (it is longer than {AgentUpdateHold.MaxFileBytes} bytes)", message, StringComparison.Ordinal);
    }

    [Fact]
    public void A_hold_that_cannot_be_read_holds_updates()
    {
        // Something is there under the file's name, but it cannot be read as a file.
        Directory.CreateDirectory(HoldFile);
        var hold = Hold();

        Assert.True(hold.IsHeld(Now));
        Assert.True(hold.IsHeld(Now.AddDays(30)));
        Assert.Equal(2, log.Entries.Count);
        Assert.All(log.Entries, e =>
        {
            Assert.Equal(LogLevel.Error, e.Level);
            Assert.StartsWith($"Automatic agent updates are held: the host updater's {HoldFile} cannot be used (", e.Message, StringComparison.Ordinal);
        });
    }

    [Fact]
    public void A_broken_file_followed_by_a_good_one_is_announced()
    {
        var hold = Hold();
        File.WriteAllText(HoldFile, "2026-11-22T07:00");
        Assert.True(hold.IsHeld(Now));

        File.WriteAllText(HoldFile, "2026-11-22T07:00:00Z");
        Assert.True(hold.IsHeld(Now));
        File.Delete(HoldFile);
        Assert.False(hold.IsHeld(Now));

        Assert.Equal([LogLevel.Error, LogLevel.Information, LogLevel.Information], log.Entries.Select(e => e.Level));
    }

    [Theory]
    [InlineData("2026-11-22T07:00:00Z", "2026-11-22T07:00:00.0000000+00:00")]
    [InlineData("2026-11-22t07:00:00z", "2026-11-22T07:00:00.0000000+00:00")]
    [InlineData("2026-11-22T07:00:00.5Z", "2026-11-22T07:00:00.5000000+00:00")]
    [InlineData("2026-11-22T07:00:00.123456789Z", "2026-11-22T07:00:00.1234567+00:00")] // Go's RFC3339Nano
    [InlineData("2026-11-22T09:00:00+02:00", "2026-11-22T09:00:00.0000000+02:00")]
    [InlineData("2026-11-22T07:00:00-00:00", "2026-11-22T07:00:00.0000000+00:00")]
    public void Rfc3339_times_are_read_as_written(string text, string expected)
    {
        var time = AgentUpdateHold.Parse(text);
        Assert.Equal(expected, time.ToString("o", System.Globalization.CultureInfo.InvariantCulture));
    }
}

/// <summary>Keeps what a component logs, as the text a log would show.</summary>
internal sealed class CapturedLog<T> : ILogger<T>
{
    private readonly Lock gate = new();
    private readonly List<(LogLevel Level, string Message)> entries = [];

    public IReadOnlyList<(LogLevel Level, string Message)> Entries
    {
        get
        {
            lock (gate)
            {
                return entries.ToList();
            }
        }
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        ArgumentNullException.ThrowIfNull(formatter);
        lock (gate)
        {
            entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
