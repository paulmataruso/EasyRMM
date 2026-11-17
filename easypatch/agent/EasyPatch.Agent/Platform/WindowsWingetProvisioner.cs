using System.Globalization;
using System.Runtime.InteropServices;
using EasyPatch.Agent.Core.Applications;
using EasyPatch.Agent.Core.Removal;
using EasyPatch.Contracts.Agent;

namespace EasyPatch.Agent.Platform;

/// <summary>
/// Provisions App Installer (winget) for all users with Windows' own DISM
/// (<c>dism.exe /Online /Add-ProvisionedAppxPackage</c>), the documented way to add it to Windows Server and other
/// editions without the Microsoft Store. The package files were verified against the pinned SHA-256 values before this
/// runs, and Windows checks Microsoft's package signatures as it installs them. Arguments are passed as a vector (see
/// <see cref="WindowsDismRunner"/>), with <c>/NoRestart</c> so DISM never restarts the computer.
/// </summary>
internal sealed class WindowsWingetProvisioner(IDismRunner dism) : IWingetProvisioner
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(30);

    public string Architecture => RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64 ? "arm64" : "x64";

    public string? UnsupportedReason
    {
        get
        {
            var build = Environment.OSVersion.Version.Build;
            if (build < WingetDistribution.MinimumWindowsBuild)
            {
                return $"winget needs Windows 10 version 1809 or Windows Server 2019 or later; this computer runs build {build}.";
            }

            return RuntimeInformation.OSArchitecture is System.Runtime.InteropServices.Architecture.X64 or System.Runtime.InteropServices.Architecture.Arm64
                ? null
                : "winget is installed only on x64 and Arm64 Windows.";
        }
    }

    public async Task ProvisionAsync(string bundlePath, IReadOnlyList<string> dependencyPaths, string licensePath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(bundlePath);
        ArgumentNullException.ThrowIfNull(dependencyPaths);
        ArgumentException.ThrowIfNullOrEmpty(licensePath);
        var arguments = new List<string> { "/Online", "/Add-ProvisionedAppxPackage", "/PackagePath:" + Path.GetFullPath(bundlePath) };
        foreach (var dependency in dependencyPaths)
        {
            arguments.Add("/DependencyPackagePath:" + Path.GetFullPath(dependency));
        }

        arguments.Add("/LicensePath:" + Path.GetFullPath(licensePath));
        arguments.Add("/NoRestart"); // never prompt for or start a restart
        arguments.Add("/English");
        arguments.Add("/LogPath:" + dism.LogPath);

        DismResult result;
        try
        {
            result = await dism.RunAsync(arguments, Timeout, cancellationToken);
        }
        catch (DismException ex)
        {
            throw new WingetException(ex.Message, ex);
        }

        if (result.ExitCode is 0 or DismPackages.RestartRequired)
        {
            return;
        }

        throw new WingetException(
            $"DISM could not install App Installer (exit code {FormatExitCode(result.ExitCode)}): {DismPackages.Summarize(result.Output)} See {dism.LogPath}.");
    }

    private static string FormatExitCode(int code) =>
        code < 0 ? "0x" + code.ToString("X8", CultureInfo.InvariantCulture) : code.ToString(CultureInfo.InvariantCulture);
}
