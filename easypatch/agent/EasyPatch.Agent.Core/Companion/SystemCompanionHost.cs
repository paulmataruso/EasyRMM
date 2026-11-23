using System.Globalization;

namespace EasyPatch.Agent.Core.Companion;

/// <summary>
/// The Windows and Linux halves of a repair: service control by <c>sc.exe</c> or <c>systemctl</c>, the journal, the recovery copy's trust
/// check and running it. Programs are named by absolute path, arguments are fixed templates and the service names come from
/// <see cref="CompanionLayout"/>, never from a job.
/// </summary>
public sealed class SystemCompanionHost : ICompanionHost
{
    private static readonly TimeSpan Short = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan Long = TimeSpan.FromSeconds(90);

    private readonly IProgramRunner _runner;
    private readonly bool _windows;
    private readonly int _trustedUid;

    /// <param name="trustedUid">The user that must own the recovery copy and the directories above it on Linux: root. Tests pass the
    /// user they create files as.</param>
    public SystemCompanionHost(IProgramRunner runner, bool? windows = null, int trustedUid = 0)
    {
        _runner = runner;
        _windows = windows ?? OperatingSystem.IsWindows();
        _trustedUid = trustedUid;
    }

    private static string Sc => Path.Combine(Environment.SystemDirectory, "sc.exe");

    private static string? Unix(string name) =>
        new[] { "/usr/bin", "/bin", "/usr/sbin", "/sbin" }.Select(d => Path.Combine(d, name)).FirstOrDefault(File.Exists);

    public async Task<string> ServiceStateAsync(string service, CancellationToken cancellationToken)
    {
        if (_windows)
        {
            var result = await _runner.RunAsync(Sc, ["query", service], Short, cancellationToken);
            if (result.Output.Contains("1060", StringComparison.Ordinal))
            {
                return "missing";
            }

            return result.Output.Contains("RUNNING", StringComparison.Ordinal) ? "running"
                : result.Output.Contains("STOPPED", StringComparison.Ordinal) ? "stopped" : "unknown";
        }

        var systemctl = Unix("systemctl");
        if (systemctl is null)
        {
            return "unknown";
        }

        var load = await _runner.RunAsync(systemctl, ["show", "--property=LoadState", "--value", service], Short, cancellationToken);
        if (load.Output.Trim() == "not-found")
        {
            return "missing";
        }

        var active = await _runner.RunAsync(systemctl, ["is-active", service], Short, cancellationToken);
        return active.Output.Trim() == "active" ? "running" : active.Output.Trim() is "inactive" or "failed" ? "stopped" : "unknown";
    }

    public async Task<string?> RestartServiceAsync(string service, CancellationToken cancellationToken)
    {
        if (_windows)
        {
            if (await ServiceStateAsync(service, cancellationToken) == "running")
            {
                var stop = await _runner.RunAsync(Sc, ["stop", service], Short, cancellationToken);
                if (!stop.Succeeded && !stop.Output.Contains("1062", StringComparison.Ordinal))
                {
                    return "sc stop: " + Brief(stop.Output);
                }

                for (var i = 0; i < 30 && await ServiceStateAsync(service, cancellationToken) != "stopped"; i++)
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
                }
            }

            var start = await _runner.RunAsync(Sc, ["start", service], Short, cancellationToken);
            // 1056: the service is running already.
            return start.Succeeded || start.Output.Contains("1056", StringComparison.Ordinal) ? null : "sc start: " + Brief(start.Output);
        }

        var systemctl = Unix("systemctl");
        if (systemctl is null)
        {
            return "systemctl is not installed.";
        }

        var restart = await _runner.RunAsync(systemctl, ["restart", service], Long, cancellationToken);
        return restart.Succeeded ? null : "systemctl restart: " + Brief(restart.Output);
    }

    public async Task<string?> ReadJournalAsync(string service, int lines, CancellationToken cancellationToken)
    {
        if (_windows || Unix("journalctl") is not { } journalctl)
        {
            return null;
        }

        var result = await _runner.RunAsync(journalctl, ["--unit", service, "--lines", lines.ToString(CultureInfo.InvariantCulture), "--no-pager", "--output", "short-iso"], Short,
            cancellationToken);
        return result.Succeeded ? result.Output : null;
    }

    public async Task<string?> CheckTrustAsync(string path, string? stopAt, CancellationToken cancellationToken)
    {
        if (_windows)
        {
            return OperatingSystem.IsWindows() ? FileTrust.CheckWindows(path, stopAt) : "This is not a Windows computer.";
        }

        var stat = Unix("stat");
        if (stat is null)
        {
            return "stat is not installed, so the copy cannot be checked.";
        }

        var chain = FileTrust.UnixChain(Path.GetFullPath(path));
        if (stopAt is not null)
        {
            // Tests only: the directories above stopAt are not walked.
            var top = chain.IndexOf(Path.TrimEndingDirectorySeparator(Path.GetFullPath(stopAt)));
            if (top > 0)
            {
                chain = chain.GetRange(top, chain.Count - top);
            }
        }

        // No `-L`: a link is reported as a link, not followed.
        var result = await _runner.RunAsync(stat, ["-c", "%u %a %h %F", "--", .. chain], Short, cancellationToken);
        if (!result.Succeeded)
        {
            return "stat could not read the copy or a directory above it: " + Brief(result.Output);
        }

        var entries = FileTrust.ParseStat(chain, result.Output);
        return entries is null ? "stat's answer was not understood." : FileTrust.EvaluateUnix(entries, _trustedUid);
    }

    public Task<ProgramResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken) =>
        _runner.RunAsync(program, arguments, timeout, cancellationToken);

    private static string Brief(string output)
    {
        var text = output.Trim().ReplaceLineEndings(" ");
        return text.Length <= 300 ? text : text[..300];
    }
}
