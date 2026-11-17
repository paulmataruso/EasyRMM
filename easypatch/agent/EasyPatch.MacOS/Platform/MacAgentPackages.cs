using System.Text.RegularExpressions;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts.Agent;

namespace EasyPatch.MacOS.Platform;

/// <summary>
/// Installs a verified agent package with <c>installer -pkg &lt;package&gt; -target /</c> in the one-shot launchd job
/// <see cref="MacPaths.UpdateJobLabel"/>, which keeps running when the package's postinstall script restarts the agent
/// daemon. The package path and the log path are the only caller-supplied arguments, and both are checked.
/// </summary>
public sealed partial class MacAgentInstaller(LaunchdJobRunner jobs, ICommandRunner commands) : IAgentInstaller
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(30);

    /// <summary>installer's output is appended to the log; the exit code goes to the log's <c>.exit</c> file.</summary>
    internal const string InstallScript = "/usr/sbin/installer -pkg \"$0\" -target / >>\"$1\" 2>&1; echo $? >\"$1.exit\"";

    public string PackageFormat => AgentRelease.FormatPkg;

    public string DisplayName => "the macOS installer";

    public IInstallerProcess Start(string packagePath, string logPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(packagePath);
        ArgumentException.ThrowIfNullOrEmpty(logPath);
        var package = Path.GetFullPath(packagePath);
        var log = Path.GetFullPath(logPath);
        if (AgentRelease.FormatOf(Path.GetFileName(package)) != PackageFormat || !SafePath(package))
        {
            throw new ArgumentException($"{Path.GetFileName(package)} is not a pkg agent package.", nameof(packagePath));
        }

        if (!SafePath(log))
        {
            throw new ArgumentException("Unsupported log path.", nameof(logPath));
        }

        jobs.StartAsync(MacPaths.UpdateJobLabel, ["/bin/sh", "-c", InstallScript, package, log], log, CancellationToken.None).GetAwaiter().GetResult();
        return new JobProcess(jobs, MacPaths.UpdateJobLabel, log, Timeout);
    }

    public bool IsInstallerBusy() =>
        IsRunning(jobs, MacPaths.UpdateJobLabel) || IsRunning(jobs, MacPaths.UninstallJobLabel) || InstallerProcessRunning(commands);

    public int? ReadResult(string logPath) => LaunchdJobRunner.ReadExitCode(logPath);

    public string DescribeResult(int code) => code switch
    {
        -1 => " (the installation was stopped)",
        1 => " (installer could not install the package)",
        _ => string.Empty,
    };

    public bool IsSuccess(int code) => code == 0;

    /// <summary>Absolute paths of letters, digits and <c>/._-</c> only (the data directory and agent package names).</summary>
    internal static bool SafePath(string path) => SafePathRegex().IsMatch(path);

    internal static bool IsRunning(LaunchdJobRunner jobs, string label) => jobs.GetStatusAsync(label, CancellationToken.None).GetAwaiter().GetResult().IsRunning;

    /// <summary>Another package installation (an administrator's, or the agent's own).</summary>
    internal static bool InstallerProcessRunning(ICommandRunner commands)
    {
        try
        {
            return commands.RunAsync("/usr/bin/pgrep", ["-x", "installer"], TimeSpan.FromSeconds(30), CancellationToken.None).GetAwaiter().GetResult().ExitCode == 0;
        }
        catch (CommandException)
        {
            return false;
        }
    }

    [GeneratedRegex(@"^/[A-Za-z0-9._/-]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SafePathRegex();
}

/// <summary>
/// Removes the agent for an administrator's uninstall job: runs the package's <c>/Library/EasyPatch/uninstall.sh</c> in the
/// one-shot launchd job <see cref="MacPaths.UninstallJobLabel"/>. The script stops the daemon, unenrolls the agent and
/// deletes its files. Nothing else is ever run; the log path is the only caller-supplied argument.
/// </summary>
public sealed class MacAgentUninstaller(LaunchdJobRunner jobs, ICommandRunner commands, string uninstallScript = MacPaths.UninstallScript) : IAgentUninstaller
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(30);

    internal const string RunScript = "/bin/sh \"$0\" >>\"$1\" 2>&1; echo $? >\"$1.exit\"";

    public string DisplayName => "the EasyPatch uninstall script";

    /// <summary>The agent was installed from the package (which brings the uninstall script).</summary>
    public bool IsAvailable => File.Exists(uninstallScript);

    public IInstallerProcess Start(string logPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(logPath);
        var log = Path.GetFullPath(logPath);
        if (!MacAgentInstaller.SafePath(log))
        {
            throw new ArgumentException("Unsupported log path.", nameof(logPath));
        }

        jobs.StartAsync(MacPaths.UninstallJobLabel, ["/bin/sh", "-c", RunScript, uninstallScript, log], log, CancellationToken.None)
            .GetAwaiter().GetResult();
        return new JobProcess(jobs, MacPaths.UninstallJobLabel, log, Timeout);
    }

    public bool IsInstallerBusy() =>
        MacAgentInstaller.IsRunning(jobs, MacPaths.UninstallJobLabel) || MacAgentInstaller.IsRunning(jobs, MacPaths.UpdateJobLabel) ||
        MacAgentInstaller.InstallerProcessRunning(commands);

    public int? ReadResult(string logPath) => LaunchdJobRunner.ReadExitCode(logPath);

    public string DescribeResult(int code) => code == -1 ? " (the removal was stopped)" : string.Empty;
}

internal sealed class JobProcess(LaunchdJobRunner jobs, string label, string logPath, TimeSpan timeout) : IInstallerProcess
{
    public Task<int> WaitForExitAsync(CancellationToken cancellationToken) => jobs.WaitAsync(label, logPath, timeout, cancellationToken);

    public void Dispose()
    {
    }
}
