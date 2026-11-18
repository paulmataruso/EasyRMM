using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Agent;
using EasyPatch.Linux.Packages;
using EasyPatch.Linux.Processes;

namespace EasyPatch.Linux.Platform;

/// <summary>
/// Installs a verified agent package (.deb with apt-get, .rpm with dnf) in the transient unit
/// <c>easypatch-agent-update</c>, which keeps running when the package's maintainer script restarts this service.
/// The package path and the log path are the only caller-supplied arguments.
/// </summary>
public sealed class LinuxAgentInstaller : IAgentInstaller
{
    public const string UpdateUnit = "easypatch-agent-update";

    private static readonly IReadOnlyDictionary<string, string> AptEnvironment = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["DEBIAN_FRONTEND"] = "noninteractive",
        ["DEBCONF_NONINTERACTIVE_SEEN"] = "true",
        ["APT_LISTCHANGES_FRONTEND"] = "none",
    };

    private readonly TransientUnitRunner _units;
    private readonly PackageFamily _family;

    public LinuxAgentInstaller(TransientUnitRunner units, PackageFamily family)
    {
        if (family == PackageFamily.Unsupported)
        {
            throw new ArgumentException("Unsupported distribution.", nameof(family));
        }

        _units = units;
        _family = family;
    }

    public string PackageFormat => _family == PackageFamily.Debian ? AgentRelease.FormatDeb : AgentRelease.FormatRpm;

    public string DisplayName => _family == PackageFamily.Debian ? "apt" : "dnf";

    public IInstallerProcess Start(string packagePath, string logPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(packagePath);
        ArgumentException.ThrowIfNullOrEmpty(logPath);
        var package = Path.GetFullPath(packagePath);
        if (AgentRelease.FormatOf(Path.GetFileName(package)) != PackageFormat || package.Contains(' ', StringComparison.Ordinal))
        {
            throw new ArgumentException($"{Path.GetFileName(package)} is not a {PackageFormat} agent package.", nameof(packagePath));
        }

        // Upgrade in place: the configuration in /etc/easypatch and the identity in /var/lib/easypatch are kept.
        IReadOnlyList<string> arguments = _family == PackageFamily.Debian
            ? ["install", "-y", "-q", "--no-remove", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
               "-o", "DPkg::Lock::Timeout=1800", package]
            : ["-y", "--disablerepo=*", "install", package];
        var program = _family == PackageFamily.Debian ? "apt-get" : "dnf";
        _units.WaitWhileRunningAsync(PackageBackend.PackagesUnit, PackageBackend.TransactionTimeout, CancellationToken.None).GetAwaiter().GetResult();
        _units.StartAsync(UpdateUnit, program, arguments, _family == PackageFamily.Debian ? AptEnvironment : new Dictionary<string, string>(),
            Path.GetFullPath(logPath), "EasyPatch agent update", CancellationToken.None).GetAwaiter().GetResult();
        return new UnitProcess(_units, Path.GetFullPath(logPath));
    }

    public bool IsInstallerBusy() =>
        _units.GetStatusAsync(UpdateUnit, CancellationToken.None).GetAwaiter().GetResult().IsRunning ||
        _units.GetStatusAsync(PackageBackend.PackagesUnit, CancellationToken.None).GetAwaiter().GetResult().IsRunning;

    /// <summary>The exit code of the update unit started by the previous agent process (it stays loaded until the next
    /// update), or null when unknown.</summary>
    public int? ReadResult(string logPath)
    {
        var status = _units.GetStatusAsync(UpdateUnit, CancellationToken.None).GetAwaiter().GetResult();
        return status.HasFinished ? status.ExitStatus ?? -1 : null;
    }

    public string DescribeResult(int code) => code switch
    {
        -1 => " (the installation was stopped)",
        100 when _family == PackageFamily.Debian => " (apt-get could not install the package)",
        1 when _family == PackageFamily.RedHat => " (dnf could not install the package)",
        _ => string.Empty,
    };

    public bool IsSuccess(int code) => code == 0;

    private sealed class UnitProcess(TransientUnitRunner units, string logPath) : IInstallerProcess
    {
        public Task<int> WaitForExitAsync(CancellationToken cancellationToken) =>
            units.WaitAsync(UpdateUnit, logPath, AgentUpdateTimeout, null, cancellationToken);

        public void Dispose()
        {
        }
    }

    private static readonly TimeSpan AgentUpdateTimeout = TimeSpan.FromMinutes(30);
}
