using System.Globalization;
using System.Text.RegularExpressions;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.Linux.Packages;
using EasyPatch.Linux.Processes;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Linux.Platform;

/// <summary>
/// Pending-restart detection: the Debian/Ubuntu <c>/run/reboot-required</c> flag, <c>dnf needs-restarting -r</c> on
/// Enterprise Linux, and a newer installed kernel than the running one. Never changes anything.
/// </summary>
public sealed partial class LinuxRebootDetector : IRebootDetector
{
    private const string RebootRequiredFile = "/run/reboot-required";
    private const string RebootRequiredPackagesFile = "/run/reboot-required.pkgs";
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(2);

    private readonly ICommandRunner _commands;
    private readonly PackageFamily _family;
    private readonly ILogger _logger;
    private bool? _container;

    public LinuxRebootDetector(ICommandRunner commands, PackageFamily family, ILogger<LinuxRebootDetector> logger)
    {
        _commands = commands;
        _family = family;
        _logger = logger;
    }

    public async Task<RebootStatus> DetectAsync(CancellationToken cancellationToken)
    {
        var reasons = new List<string>();
        if (File.Exists(RebootRequiredFile))
        {
            var packages = ReadRebootRequiredPackages();
            reasons.Add(packages.Count == 0
                ? "A package update requested a restart (/run/reboot-required)."
                : $"Package updates requested a restart: {string.Join(", ", packages.Order(StringComparer.Ordinal).Take(10))}{(packages.Count > 10 ? ", …" : string.Empty)}.");
        }

        if (_family == PackageFamily.RedHat && _commands.Find("dnf") is not null)
        {
            try
            {
                var result = await _commands.RunAsync("dnf", ["-q", "-C", "needs-restarting", "-r"], Timeout, cancellationToken);
                if (result.Combined.Contains("Reboot is required", StringComparison.Ordinal))
                {
                    reasons.Add("Core libraries or the kernel were updated since the last boot (dnf needs-restarting).");
                }
            }
            catch (CommandException ex)
            {
                _logger.LogDebug("dnf needs-restarting failed: {Message}", ex.Message);
            }
        }

        if (!await IsContainerAsync(cancellationToken) && NewerKernel(_family) is { } kernel)
        {
            reasons.Add($"Kernel {kernel.Newest} is installed, but {kernel.Running} is running.");
        }

        return reasons.Count == 0 ? RebootStatus.None : new RebootStatus(true, reasons);
    }

    /// <summary>Package names listed in <c>/run/reboot-required.pkgs</c> (Debian, Ubuntu).</summary>
    public static HashSet<string> ReadRebootRequiredPackages()
    {
        try
        {
            return File.Exists(RebootRequiredPackagesFile)
                ? File.ReadAllLines(RebootRequiredPackagesFile).Select(l => l.Trim()).Where(PackageNames.IsDebianName).ToHashSet(StringComparer.Ordinal)
                : [];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }
    }

    private async Task<bool> IsContainerAsync(CancellationToken cancellationToken)
    {
        if (_container is null)
        {
            try
            {
                var result = await _commands.RunAsync("systemd-detect-virt", ["--container", "--quiet"], Timeout, cancellationToken);
                _container = result.ExitCode == 0;
            }
            catch (CommandException)
            {
                _container = false;
            }
        }

        return _container.Value;
    }

    /// <summary>The newest installed kernel of the running kernel's flavour, when it is newer than the running one.</summary>
    internal static (string Running, string Newest)? NewerKernel(PackageFamily family, string modulesDirectory = "/lib/modules", string bootDirectory = "/boot",
        string? running = null)
    {
        try
        {
            running ??= File.ReadAllText("/proc/sys/kernel/osrelease").Trim();
            if (!Directory.Exists(modulesDirectory))
            {
                return null;
            }

            var flavour = Flavour(running, family);
            var newest = Directory.EnumerateDirectories(modulesDirectory)
                .Select(Path.GetFileName)
                .OfType<string>()
                .Where(k => Flavour(k, family) == flavour &&
                            (File.Exists(Path.Combine(bootDirectory, "vmlinuz-" + k)) || File.Exists(Path.Combine(modulesDirectory, k, "vmlinuz"))))
                .OrderByDescending(k => k, Comparer<string>.Create(RpmVersion.VerCmp))
                .FirstOrDefault();
            return newest is not null && RpmVersion.VerCmp(newest, running) > 0 ? (running, newest) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>"-amd64", "-cloud-amd64", "-generic" (Debian, Ubuntu); "x86_64", "x86_64+debug" (Enterprise Linux).</summary>
    internal static string Flavour(string release, PackageFamily family)
    {
        if (family == PackageFamily.Debian)
        {
            var match = DebianFlavourRegex().Match(release);
            return match.Success ? match.Groups["flavour"].Value : release;
        }

        var dot = release.LastIndexOf('.');
        return dot >= 0 ? release[(dot + 1)..] : string.Empty;
    }

    [GeneratedRegex(@"^\d+\.\d+(?:\.\d+)?-\d+(?:\.\d+)*(?<flavour>(?:-[a-z0-9]+)*)$", RegexOptions.CultureInvariant)]
    private static partial Regex DebianFlavourRegex();
}

/// <summary>Restarts with <c>shutdown -r</c>, which warns signed-in users (wall messages) during the grace period and can
/// be cancelled with <c>shutdown -c</c>. Only ever called for an administrator's restart job.</summary>
public sealed class LinuxSystemRestart : ISystemRestart
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);
    private readonly ICommandRunner _commands;

    public LinuxSystemRestart(ICommandRunner commands)
    {
        _commands = commands;
    }

    public void Restart(TimeSpan gracePeriod, string message)
    {
        var when = gracePeriod <= TimeSpan.Zero ? "now" : "+" + Math.Max(1, (int)Math.Ceiling(gracePeriod.TotalMinutes)).ToString(CultureInfo.InvariantCulture);
        var text = new string((message ?? string.Empty).Where(c => !char.IsControl(c)).Take(200).ToArray());
        var result = _commands.RunAsync("shutdown", ["-r", when, text], Timeout, CancellationToken.None).GetAwaiter().GetResult();
        if (!result.Succeeded)
        {
            throw new InvalidOperationException($"shutdown -r {when} failed (exit code {result.ExitCode}): {result.Combined.Trim()}");
        }
    }

    public bool TryAbort()
    {
        try
        {
            return _commands.RunAsync("shutdown", ["-c"], Timeout, CancellationToken.None).GetAwaiter().GetResult().Succeeded;
        }
        catch (CommandException)
        {
            return false;
        }
    }
}

/// <summary>Counts signed-in users (<c>who</c>: local and SSH sessions).</summary>
public sealed class LinuxUserSessions : IUserSessionCounter
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    private readonly ICommandRunner _commands;

    public LinuxUserSessions(ICommandRunner commands)
    {
        _commands = commands;
    }

    public UserSessionInfo GetSessions()
    {
        try
        {
            var result = _commands.RunAsync("who", [], Timeout, CancellationToken.None).GetAwaiter().GetResult();
            var users = result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Split(' ', 2)[0])
                .Where(u => u.Length > 0)
                .Distinct(StringComparer.Ordinal)
                .Count();
            return new UserSessionInfo { SignedInUsers = users };
        }
        catch (CommandException)
        {
            return new UserSessionInfo();
        }
    }
}

/// <summary>
/// Boot time from <c>/proc/stat</c> (btime) plus the start time of PID 1, so a restarted container counts as a restart
/// too. Unlike the tick counter it does not drift while the machine is suspended.
/// </summary>
public sealed class LinuxBootTimeProvider : IBootTimeProvider
{
    private const double ClockTicksPerSecond = 100; // USER_HZ, 100 on every supported architecture

    public DateTimeOffset GetLastBootTime()
    {
        try
        {
            var btime = File.ReadLines("/proc/stat").First(l => l.StartsWith("btime ", StringComparison.Ordinal));
            var seconds = long.Parse(btime.AsSpan(6).Trim(), NumberStyles.None, CultureInfo.InvariantCulture);
            var stat = File.ReadAllText("/proc/1/stat");
            var fields = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
            var start = long.Parse(fields[19], NumberStyles.None, CultureInfo.InvariantCulture); // field 22: starttime
            return DateTimeOffset.FromUnixTimeSeconds(seconds + (long)Math.Floor(start / ClockTicksPerSecond));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or InvalidOperationException or IndexOutOfRangeException or ArgumentException)
        {
            return new TickCountBootTimeProvider().GetLastBootTime();
        }
    }
}
