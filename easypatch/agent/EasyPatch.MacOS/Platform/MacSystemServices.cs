using System.Globalization;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.MacOS.SoftwareUpdate;

namespace EasyPatch.MacOS.Platform;

/// <summary>
/// Pending restart: updates EasyPatch installed since the last boot that complete at the next restart. macOS has no
/// system-wide "restart required" flag EasyPatch can read, so a restart an update started elsewhere (System Settings, MDM)
/// is not detected. Never changes anything.
/// </summary>
public sealed class MacRebootDetector(SoftwareUpdateService updates) : IRebootDetector
{
    public Task<RebootStatus> DetectAsync(CancellationToken cancellationToken)
    {
        var pending = updates.PendingRestarts();
        if (pending.Count == 0)
        {
            return Task.FromResult(RebootStatus.None);
        }

        var titles = pending.Select(p => p.Title).Order(StringComparer.Ordinal).ToList();
        return Task.FromResult(new RebootStatus(true,
            [$"EasyPatch installed {string.Join(", ", titles.Take(5))}{(titles.Count > 5 ? ", …" : string.Empty)}, which completes when the Mac restarts."]));
    }
}

/// <summary>Restarts with <c>shutdown -r</c> for an administrator's restart job. macOS shows signed-in users no warning during
/// the grace period. A restart still in its grace period is cancelled by stopping the waiting <c>shutdown</c> process.</summary>
public sealed class MacSystemRestart(ICommandRunner commands) : ISystemRestart
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    /// <summary>The <c>shutdown</c> arguments for a grace period (exposed for tests).</summary>
    public static IReadOnlyList<string> Arguments(TimeSpan gracePeriod, string? message)
    {
        var when = gracePeriod <= TimeSpan.Zero ? "now" : "+" + Math.Max(1, (int)Math.Ceiling(gracePeriod.TotalMinutes)).ToString(CultureInfo.InvariantCulture);
        var text = new string((message ?? string.Empty).Where(c => !char.IsControl(c)).Take(200).ToArray());
        return text.Length == 0 ? ["-r", when] : ["-r", when, text];
    }

    public void Restart(TimeSpan gracePeriod, string message)
    {
        var arguments = Arguments(gracePeriod, message);
        var result = commands.RunAsync("/sbin/shutdown", arguments, Timeout, CancellationToken.None).GetAwaiter().GetResult();
        if (!result.Succeeded)
        {
            throw new InvalidOperationException($"shutdown -r {arguments[1]} failed (exit code {result.ExitCode}): {result.Combined.Trim()}");
        }
    }

    public bool TryAbort()
    {
        try
        {
            return commands.RunAsync("/usr/bin/pkill", ["-x", "shutdown"], Timeout, CancellationToken.None).GetAwaiter().GetResult().Succeeded;
        }
        catch (CommandException)
        {
            return false;
        }
    }
}

/// <summary>Counts signed-in users (<c>who</c>: the console user and terminal sessions).</summary>
public sealed class MacUserSessions(ICommandRunner commands) : IUserSessionCounter
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public UserSessionInfo GetSessions()
    {
        try
        {
            var result = commands.RunAsync("/usr/bin/who", [], Timeout, CancellationToken.None).GetAwaiter().GetResult();
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

/// <summary>Boot time from <c>sysctl kern.boottime</c>, read once (it cannot change while the agent runs).</summary>
public sealed class MacBootTimeProvider : IBootTimeProvider
{
    private readonly Lazy<DateTimeOffset> _bootTime;

    public MacBootTimeProvider(ICommandRunner commands)
    {
        _bootTime = new Lazy<DateTimeOffset>(() =>
            MacSystemInfo.ParseBootTime(MacSystemInfo.Run(commands, "/usr/sbin/sysctl", ["-n", "kern.boottime"])) ??
            new TickCountBootTimeProvider().GetLastBootTime());
    }

    public DateTimeOffset GetLastBootTime() => _bootTime.Value;
}

/// <summary>Apple's software update service; reports whether the Mac is enrolled in MDM (<c>profiles status</c>). Never
/// changes configuration.</summary>
public sealed class MacUpdateSourceDetector(ICommandRunner commands) : IUpdateSourceDetector
{
    public UpdateSourceInfo Detect()
    {
        var enrollment = MacSystemInfo.Run(commands, "/usr/bin/profiles", ["status", "-type", "enrollment"]);
        return new UpdateSourceInfo
        {
            Type = UpdateSourceType.AppleSoftwareUpdate,
            ManagedByMdm = IsMdmEnrolled(enrollment),
        };
    }

    /// <summary>"MDM enrollment: Yes" or "MDM enrollment: Yes (User Approved)".</summary>
    public static bool IsMdmEnrolled(string? profilesOutput) =>
        (profilesOutput ?? string.Empty).Split('\n').Any(l => l.Trim().StartsWith("MDM enrollment: Yes", StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// The agent's private key relies on file permissions: the data directory is root-only (0700) and the key file 0600. The
/// System keychain is not used yet. Inventory reports <c>file-permissions</c>. The format matches the Linux agent's
/// file-permissions blobs.
/// </summary>
public sealed class FilePermissionSecretProtector : ISecretProtector
{
    public const string FilePermissionsKind = "file-permissions";

    private static readonly byte[] FileMagic = "EPF1"u8.ToArray();

    public string Kind => FilePermissionsKind;

    public byte[] Protect(byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        return [.. FileMagic, .. plaintext];
    }

    public byte[] Unprotect(byte[] protectedData)
    {
        ArgumentNullException.ThrowIfNull(protectedData);
        return protectedData.AsSpan().StartsWith(FileMagic)
            ? protectedData[FileMagic.Length..]
            : throw new System.Security.Cryptography.CryptographicException("The agent key file has an unknown format.");
    }
}
