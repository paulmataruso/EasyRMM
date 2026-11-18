using System.Diagnostics;
using EasyPatch.Agent.Core.Abstractions;

namespace EasyPatch.Agent.Platform;

/// <summary>Runs <c>%SystemRoot%\System32\msiexec.exe</c> for a verified agent package. Nothing else is ever executed, and
/// the package path and log path are the only caller-supplied arguments.</summary>
internal sealed class WindowsAgentInstaller : IAgentInstaller
{
    private const string ExecuteMutex = @"Global\_MSIExecute";

    public IInstallerProcess Start(string packagePath, string logPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(packagePath);
        ArgumentException.ThrowIfNullOrEmpty(logPath);
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Environment.SystemDirectory,
        };

        // Upgrade in place: no properties, so the installed server URL and proxy are kept and nothing is re-enrolled.
        foreach (var argument in (string[])["/i", Path.GetFullPath(packagePath), "/qn", "/norestart", "/l*v", Path.GetFullPath(logPath)])
        {
            info.ArgumentList.Add(argument);
        }

        var process = Process.Start(info) ?? throw new InvalidOperationException("msiexec did not start.");
        return new InstallerProcess(process);
    }

    public bool IsInstallerBusy() => IsWindowsInstallerBusy();

    /// <summary>True while a Windows Installer installation or removal is running (the <c>_MSIExecute</c> mutex exists).</summary>
    internal static bool IsWindowsInstallerBusy()
    {
        try
        {
            if (Mutex.TryOpenExisting(ExecuteMutex, out var mutex))
            {
                mutex.Dispose();
                return true;
            }

            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return true; // it exists
        }
    }

    private sealed class InstallerProcess(Process process) : IInstallerProcess
    {
        public async Task<int> WaitForExitAsync(CancellationToken cancellationToken)
        {
            await process.WaitForExitAsync(cancellationToken);
            return process.ExitCode;
        }

        /// <summary>Releases the handle only; msiexec keeps running (it is what stops and replaces this service).</summary>
        public void Dispose() => process.Dispose();
    }
}
