using System.Globalization;
using System.Security;
using System.Text;

namespace EasyPatch.MacOS.Platform;

/// <summary>Whether a one-shot launchd job is loaded and running.</summary>
public sealed record LaunchdJobStatus(bool IsLoaded, bool IsRunning);

/// <summary>
/// Runs a fixed program as a one-shot job in launchd's system domain, so it keeps running when the agent daemon is stopped
/// (an agent update or removal stops it). The job's plist lives in the agent's root-only data directory; the job writes its
/// exit code to <c>&lt;log&gt;.exit</c>. Callers pass only fixed programs and validated paths.
/// </summary>
public sealed class LaunchdJobRunner
{
    private const string Launchctl = "/bin/launchctl";
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

    private readonly ICommandRunner _commands;
    private readonly string _jobDirectory;
    private readonly TimeProvider _time;

    public LaunchdJobRunner(ICommandRunner commands, string jobDirectory, TimeProvider? time = null)
    {
        _commands = commands;
        _jobDirectory = jobDirectory;
        _time = time ?? TimeProvider.System;
    }

    public static string ExitFileOf(string logPath) => logPath + ".exit";

    /// <summary>The launchd property list of a one-shot job (exposed for tests).</summary>
    public static string PropertyList(string label, IReadOnlyList<string> programArguments)
    {
        ArgumentNullException.ThrowIfNull(programArguments);
        var xml = new StringBuilder()
            .Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
            .Append("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
            .Append("<plist version=\"1.0\">\n<dict>\n")
            .Append("  <key>Label</key>\n  <string>").Append(SecurityElement.Escape(label)).Append("</string>\n")
            .Append("  <key>ProgramArguments</key>\n  <array>\n");
        foreach (var argument in programArguments)
        {
            xml.Append("    <string>").Append(SecurityElement.Escape(argument)).Append("</string>\n");
        }

        return xml.Append("  </array>\n")
            .Append("  <key>RunAtLoad</key>\n  <true/>\n")
            .Append("  <key>LaunchOnlyOnce</key>\n  <true/>\n")
            .Append("  <key>KeepAlive</key>\n  <false/>\n")
            .Append("  <key>WorkingDirectory</key>\n  <string>/</string>\n")
            .Append("</dict>\n</plist>\n")
            .ToString();
    }

    /// <summary>Replaces a finished job of the same label and starts the new one.</summary>
    public async Task StartAsync(string label, IReadOnlyList<string> programArguments, string logPath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(label);
        ArgumentException.ThrowIfNullOrEmpty(logPath);
        await RemoveAsync(label, cancellationToken);
        File.Delete(ExitFileOf(logPath));
        Directory.CreateDirectory(_jobDirectory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var plist = Path.Combine(_jobDirectory, label + ".plist");
        await File.WriteAllTextAsync(plist, PropertyList(label, programArguments), cancellationToken);
        File.SetUnixFileMode(plist, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        var result = await _commands.RunAsync(Launchctl, ["bootstrap", "system", plist], CommandTimeout, cancellationToken);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException($"launchctl bootstrap {label} failed (exit code {result.ExitCode}): {result.Combined.Trim()}");
        }
    }

    /// <summary>Unloads a job (one that has finished, normally). Not loaded is fine.</summary>
    public async Task RemoveAsync(string label, CancellationToken cancellationToken)
    {
        try
        {
            await _commands.RunAsync(Launchctl, ["bootout", "system/" + label], CommandTimeout, cancellationToken);
        }
        catch (CommandException)
        {
            // Not loaded, or launchctl missing: StartAsync reports the real problem.
        }
    }

    public async Task<LaunchdJobStatus> GetStatusAsync(string label, CancellationToken cancellationToken)
    {
        try
        {
            var result = await _commands.RunAsync(Launchctl, ["print", "system/" + label], CommandTimeout, cancellationToken);
            return result.Succeeded
                ? new LaunchdJobStatus(true, result.StandardOutput.Split('\n').Any(l => l.Trim() == "state = running"))
                : new LaunchdJobStatus(false, false);
        }
        catch (CommandException)
        {
            return new LaunchdJobStatus(false, false);
        }
    }

    /// <summary>The exit code the job wrote, or null while there is none.</summary>
    public static int? ReadExitCode(string logPath)
    {
        try
        {
            var text = File.ReadAllText(ExitFileOf(logPath)).Trim();
            return int.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var code) ? code : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Waits for the job's exit code. Returns -1 when the job stopped without writing one or did not finish in time.</summary>
    public async Task<int> WaitAsync(string label, string logPath, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = _time.GetUtcNow() + timeout;
        var stoppedChecks = 0;
        while (_time.GetUtcNow() < deadline)
        {
            if (ReadExitCode(logPath) is { } code)
            {
                return code;
            }

            var status = await GetStatusAsync(label, cancellationToken);
            if (!status.IsRunning && ++stoppedChecks >= 3)
            {
                return ReadExitCode(logPath) ?? -1;
            }

            await Task.Delay(PollInterval, _time, cancellationToken);
        }

        return -1;
    }
}
