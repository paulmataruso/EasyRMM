using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Linux.Packages;
using EasyPatch.Linux.Processes;

namespace EasyPatch.Linux.Platform;

/// <summary>
/// Removes the easypatch-agent package (<c>apt-get remove</c> on Debian and Ubuntu, <c>rpm -e</c> on Enterprise Linux, so no
/// other package is removed) in the transient unit <c>easypatch-agent-uninstall</c>, which keeps running when the package's
/// removal script stops this service. The removal script unenrolls the agent. The package name is fixed; the log path is the
/// only caller-supplied argument.
/// </summary>
public sealed class LinuxAgentUninstaller : IAgentUninstaller
{
    public const string UninstallUnit = "easypatch-agent-uninstall";
    public const string PackageName = "easypatch-agent";

    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(30);

    private static readonly IReadOnlyDictionary<string, string> AptEnvironment = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["DEBIAN_FRONTEND"] = "noninteractive",
        ["DEBCONF_NONINTERACTIVE_SEEN"] = "true",
        ["APT_LISTCHANGES_FRONTEND"] = "none",
    };

    private readonly TransientUnitRunner _units;
    private readonly PackageFamily _family;

    public LinuxAgentUninstaller(TransientUnitRunner units, PackageFamily family)
    {
        if (family == PackageFamily.Unsupported)
        {
            throw new ArgumentException("Unsupported distribution.", nameof(family));
        }

        _units = units;
        _family = family;
    }

    public string DisplayName => _family == PackageFamily.Debian ? "apt" : "rpm";

    /// <summary>The agent is only distributed as the easypatch-agent package.</summary>
    public bool IsAvailable => true;

    /// <summary>The command that removes the agent package (exposed for tests).</summary>
    public static (string Program, IReadOnlyList<string> Arguments) Command(PackageFamily family) => family == PackageFamily.Debian
        ? ("apt-get", ["remove", "-y", "-q", "-o", "DPkg::Lock::Timeout=1800", PackageName])
        : ("rpm", ["-e", PackageName]);

    public IInstallerProcess Start(string logPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(logPath);
        var (program, arguments) = Command(_family);
        var log = Path.GetFullPath(logPath);
        _units.WaitWhileRunningAsync(PackageBackend.PackagesUnit, PackageBackend.TransactionTimeout, CancellationToken.None).GetAwaiter().GetResult();
        _units.StartAsync(UninstallUnit, program, arguments, _family == PackageFamily.Debian ? AptEnvironment : new Dictionary<string, string>(),
            log, "EasyPatch agent removal", CancellationToken.None).GetAwaiter().GetResult();
        return new UnitProcess(_units, log);
    }

    public bool IsInstallerBusy() =>
        _units.GetStatusAsync(UninstallUnit, CancellationToken.None).GetAwaiter().GetResult().IsRunning ||
        _units.GetStatusAsync(LinuxAgentInstaller.UpdateUnit, CancellationToken.None).GetAwaiter().GetResult().IsRunning ||
        _units.GetStatusAsync(PackageBackend.PackagesUnit, CancellationToken.None).GetAwaiter().GetResult().IsRunning;

    public int? ReadResult(string logPath)
    {
        var status = _units.GetStatusAsync(UninstallUnit, CancellationToken.None).GetAwaiter().GetResult();
        return status.HasFinished ? status.ExitStatus ?? -1 : null;
    }

    public string DescribeResult(int code) => code switch
    {
        -1 => " (the removal was stopped)",
        100 when _family == PackageFamily.Debian => " (apt-get could not remove the package)",
        1 when _family == PackageFamily.RedHat => " (rpm could not remove the package)",
        _ => string.Empty,
    };

    private sealed class UnitProcess(TransientUnitRunner units, string logPath) : IInstallerProcess
    {
        public Task<int> WaitForExitAsync(CancellationToken cancellationToken) => units.WaitAsync(UninstallUnit, logPath, Timeout, null, cancellationToken);

        public void Dispose()
        {
        }
    }
}
