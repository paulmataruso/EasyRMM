using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Linux.Processes;

/// <summary>State of a transient unit as systemd reports it.</summary>
public sealed record UnitStatus(string ActiveState, string SubState, string Result, int? ExitStatus)
{
    /// <summary>The unit is not loaded.</summary>
    public static UnitStatus Unknown { get; } = new("inactive", "dead", "success", null);

    /// <summary>systemctl could not report the state, for example while systemd re-executes itself after a glibc or systemd
    /// upgrade (which happens in the middle of such a transaction). Counted as running, so nothing concludes that a
    /// transaction has finished, or starts another one, while its state is unknown.</summary>
    public static UnitStatus Unavailable { get; } = new("unavailable", "unavailable", "unavailable", null);

    public bool IsUnavailable => ActiveState == "unavailable";

    /// <summary>The command is still running (or its state cannot be read at the moment).</summary>
    public bool IsRunning => IsUnavailable || ActiveState is "activating" or "deactivating" or "reloading" ||
                             (ActiveState == "active" && SubState is "running" or "start" or "start-pre" or "start-post");

    /// <summary>The unit ran and finished (it stays loaded because it is started with RemainAfterExit=yes).</summary>
    public bool HasFinished => !IsRunning && (ActiveState == "failed" || (ActiveState == "active" && SubState == "exited"));
}

/// <summary>
/// Runs package-manager commands as transient systemd services (<c>systemd-run</c>) instead of child processes of the
/// agent. Stopping or restarting the agent service (needrestart after a library upgrade, or the agent's own upgrade)
/// would otherwise kill apt or dpkg halfway through and leave packages half-configured. A unit keeps running when the
/// agent stops; the next agent process waits for it before doing anything else.
/// </summary>
public sealed partial class TransientUnitRunner
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromMinutes(2);
    private readonly ICommandRunner _commands;
    private readonly ILogger _logger;

    public TransientUnitRunner(ICommandRunner commands, ILogger logger)
    {
        _commands = commands;
        _logger = logger;
    }

    /// <summary>How often a running unit is checked.</summary>
    public TimeSpan PollInterval { get; init; } = TimeSpan.FromSeconds(2);

    /// <summary>How long systemctl may fail to report a unit's state before waiting for it gives up.</summary>
    public TimeSpan UnavailableLimit { get; init; } = TimeSpan.FromMinutes(5);

    [GeneratedRegex("^[a-z][a-z0-9-]{1,60}$", RegexOptions.CultureInvariant)]
    private static partial Regex UnitNameRegex();

    public async Task<UnitStatus> GetStatusAsync(string unit, CancellationToken cancellationToken)
    {
        RequireName(unit);
        CommandResult result;
        try
        {
            result = await _commands.RunAsync("systemctl",
                ["show", unit + ".service", "--property=ActiveState,SubState,Result,ExecMainStatus,LoadState"], CommandTimeout, cancellationToken);
        }
        catch (CommandException ex)
        {
            _logger.LogDebug("systemctl show {Unit} failed: {Message}", unit, ex.Message);
            return UnitStatus.Unavailable;
        }

        if (!result.Succeeded)
        {
            _logger.LogDebug("systemctl show {Unit} exited with {ExitCode}: {Output}", unit, result.ExitCode, result.Combined.Trim());
            return UnitStatus.Unavailable;
        }

        var values = result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(l => l.Split('=', 2)).Where(p => p.Length == 2).ToDictionary(p => p[0], p => p[1], StringComparer.Ordinal);
        if (values.GetValueOrDefault("LoadState") == "not-found")
        {
            return UnitStatus.Unknown;
        }

        if (!values.ContainsKey("ActiveState"))
        {
            return UnitStatus.Unavailable;
        }

        int? exit = int.TryParse(values.GetValueOrDefault("ExecMainStatus"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var code) ? code : null;
        return new UnitStatus(values.GetValueOrDefault("ActiveState", "inactive"), values.GetValueOrDefault("SubState", "dead"),
            values.GetValueOrDefault("Result", "success"), exit);
    }

    /// <summary>Waits while a unit with this name (for example one started by the previous agent process) is running.</summary>
    /// <returns>True when a unit was running and has now finished.</returns>
    public async Task<bool> WaitWhileRunningAsync(string unit, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;
        var waited = false;
        var unavailable = new UnavailableTracker(this, unit);
        UnitStatus status;
        while ((status = await GetStatusAsync(unit, cancellationToken)).IsRunning)
        {
            unavailable.Check(status, null);
            if (!waited && !status.IsUnavailable)
            {
                _logger.LogInformation("Waiting for {Unit} (started earlier) to finish.", unit);
                waited = true;
            }

            if (DateTime.UtcNow > deadline)
            {
                throw new CommandException($"{unit} was still running after {timeout.TotalMinutes:0} minutes.");
            }

            await Task.Delay(PollInterval, cancellationToken);
        }

        return waited;
    }

    /// <summary>Starts <paramref name="program"/> in the transient unit <paramref name="unit"/>, writing its output to
    /// <paramref name="logPath"/>. Returns as soon as the unit has started.</summary>
    public async Task StartAsync(string unit, string program, IReadOnlyList<string> arguments, IReadOnlyDictionary<string, string> environment,
        string logPath, string description, CancellationToken cancellationToken)
    {
        RequireName(unit);
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(environment);
        var executable = _commands.Find(program) ?? throw new CommandException($"{program} is not installed.");
        if (logPath.Contains('\n', StringComparison.Ordinal) || logPath.Contains(' ', StringComparison.Ordinal) || !Path.IsPathRooted(logPath))
        {
            throw new ArgumentException("The log path must be an absolute path without spaces.", nameof(logPath));
        }

        await ResetAsync(unit, cancellationToken);
        Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
        File.Delete(logPath);

        var args = new List<string>
        {
            "--unit=" + unit,
            "--description=" + description,
            "--quiet",
            "--property=RemainAfterExit=yes",
            "--property=StandardOutput=file:" + logPath,
            "--property=StandardError=inherit",
            "--property=StandardInput=null",
            "--setenv=LC_ALL=C",
            "--setenv=LANG=C",
            "--setenv=LANGUAGE=C",
        };
        foreach (var (key, value) in environment)
        {
            args.Add($"--setenv={key}={value}");
        }

        args.Add("--");
        args.Add(executable);
        args.AddRange(arguments);
        var result = await _commands.RunAsync("systemd-run", args, CommandTimeout, cancellationToken);
        if (!result.Succeeded)
        {
            throw new CommandException($"systemd-run could not start {Path.GetFileName(executable)}: {result.Combined.Trim()}");
        }

        _logger.LogInformation("Started {Unit}: {Program} {Arguments}", unit, executable, string.Join(' ', arguments));
    }

    /// <summary>Waits for a started unit to finish and returns the command's exit code (-1 when it was killed). Lines
    /// appended to the log are passed to <paramref name="onOutput"/> while waiting. Cancellation stops waiting, not the
    /// command.</summary>
    public async Task<int> WaitAsync(string unit, string logPath, TimeSpan timeout, Action<string>? onOutput, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + timeout;
        long offset = 0;
        var partial = new StringBuilder();
        var unavailable = new UnavailableTracker(this, unit);
        while (true)
        {
            var status = await GetStatusAsync(unit, cancellationToken);
            offset = Tail(logPath, offset, partial, onOutput);
            unavailable.Check(status, logPath);
            if (!status.IsRunning)
            {
                offset = Tail(logPath, offset, partial, onOutput);
                if (partial.Length > 0)
                {
                    onOutput?.Invoke(partial.ToString());
                }

                await ResetAsync(unit, cancellationToken);
                return status.HasFinished && status.Result is "success" or "exit-code" ? status.ExitStatus ?? -1 : -1;
            }

            if (DateTime.UtcNow > deadline)
            {
                throw new CommandException(
                    $"{unit} was still running after {timeout.TotalMinutes:0} minutes. It was left running; check {logPath}.");
            }

            await Task.Delay(PollInterval, cancellationToken);
        }
    }

    /// <summary>Starts a unit and waits for it.</summary>
    public async Task<int> RunAsync(string unit, string program, IReadOnlyList<string> arguments, IReadOnlyDictionary<string, string> environment,
        string logPath, string description, TimeSpan timeout, Action<string>? onOutput, CancellationToken cancellationToken)
    {
        await StartAsync(unit, program, arguments, environment, logPath, description, cancellationToken);
        return await WaitAsync(unit, logPath, timeout, onOutput, cancellationToken);
    }

    /// <summary>Tolerates systemctl failing to report a unit's state for up to <see cref="UnavailableLimit"/>.</summary>
    private sealed class UnavailableTracker(TransientUnitRunner runner, string unit)
    {
        private DateTime? _since;

        public void Check(UnitStatus status, string? logPath)
        {
            if (!status.IsUnavailable)
            {
                if (_since is not null)
                {
                    runner._logger.LogInformation("systemd reports the state of {Unit} again.", unit);
                }

                _since = null;
                return;
            }

            if (_since is null)
            {
                _since = DateTime.UtcNow;
                runner._logger.LogInformation(
                    "systemd did not report the state of {Unit} (it may be re-executing after an upgrade); still waiting for it.", unit);
            }
            else if (DateTime.UtcNow - _since > runner.UnavailableLimit)
            {
                throw new CommandException($"systemd did not report the state of {unit} for {runner.UnavailableLimit.TotalMinutes:0} minutes" +
                    (logPath is null ? "." : $"; it may still be running, check {logPath}."));
            }
        }
    }

    /// <summary>Unloads a finished unit so its name can be used again.</summary>
    public async Task ResetAsync(string unit, CancellationToken cancellationToken)
    {
        var status = await GetStatusAsync(unit, cancellationToken);
        if (status.IsRunning)
        {
            throw new CommandException(status.IsUnavailable ? $"systemd did not report the state of {unit}." : $"{unit} is still running.");
        }

        if (status.ActiveState == "active")
        {
            await _commands.RunAsync("systemctl", ["stop", unit + ".service"], CommandTimeout, cancellationToken);
        }

        await _commands.RunAsync("systemctl", ["reset-failed", unit + ".service"], CommandTimeout, cancellationToken);
    }

    private static long Tail(string path, long offset, StringBuilder partial, Action<string>? onOutput)
    {
        if (onOutput is null)
        {
            return offset;
        }

        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length <= offset)
            {
                return offset;
            }

            stream.Seek(offset, SeekOrigin.Begin);
            var buffer = new byte[Math.Min(stream.Length - offset, 4 * 1024 * 1024)];
            var read = stream.Read(buffer, 0, buffer.Length);
            partial.Append(Encoding.UTF8.GetString(buffer, 0, read));
            var text = partial.ToString();
            var lastNewline = text.LastIndexOf('\n');
            if (lastNewline >= 0)
            {
                foreach (var line in text[..lastNewline].Split('\n'))
                {
                    onOutput(line.TrimEnd('\r'));
                }

                partial.Clear().Append(text[(lastNewline + 1)..]);
            }

            return offset + read;
        }
        catch (FileNotFoundException)
        {
            return offset;
        }
        catch (IOException)
        {
            return offset;
        }
    }

    private static void RequireName(string unit)
    {
        if (!UnitNameRegex().IsMatch(unit))
        {
            throw new ArgumentException($"Invalid unit name '{unit}'.", nameof(unit));
        }
    }
}
