using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using EasyPatch.Agent.Core.Applications;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Platform;

/// <summary>
/// Runs the machine-wide winget.exe of App Installer. The service runs as LocalSystem, which has no <c>winget</c> command
/// alias, so the executable is located in <c>%ProgramFiles%\WindowsApps</c> (the newest installed App Installer for this
/// architecture), with the matching VC++ runtime package on PATH. Arguments are passed as a vector, never through a shell;
/// <see cref="WingetApplicationUpdateService"/> builds them from fixed templates and validated IDs and versions.
/// </summary>
internal sealed class WingetProcessRunner(ILogger<WingetProcessRunner> logger) : IWingetRunner
{
    private const string Publisher = "8wekyb3d8bbwe";

    /// <summary>Output beyond this is discarded.</summary>
    private const int MaxOutputChars = 4 * 1024 * 1024;

    public string? Locate() => Find("Microsoft.DesktopAppInstaller", "winget.exe") is { } directory ? Path.Combine(directory, "winget.exe") : null;

    public async Task<WingetRunResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var winget = Locate() ?? throw new WingetException("winget (App Installer) is not installed for all users on this computer.");
        var info = new ProcessStartInfo(winget)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            WorkingDirectory = Path.GetTempPath(),
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        var path = new List<string> { Path.GetDirectoryName(winget)! };
        if (Find("Microsoft.VCLibs.140.00.UWPDesktop", null) is { } vclibs)
        {
            path.Add(vclibs);
        }

        path.Add(Environment.GetEnvironmentVariable("PATH") ?? "");
        info.Environment["PATH"] = string.Join(';', path);

        using var process = new Process { StartInfo = info };
        var output = new StringBuilder();
        void Append(string? line)
        {
            if (line is null)
            {
                return;
            }

            lock (output)
            {
                if (output.Length < MaxOutputChars)
                {
                    output.Append(line).Append('\n');
                }
            }
        }

        process.OutputDataReceived += (_, e) => Append(e.Data);
        process.ErrorDataReceived += (_, e) => Append(e.Data);
        try
        {
            process.Start();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            throw new WingetException($"winget could not be started ({ex.GetType().Name}).", ex);
        }

        process.StandardInput.Close();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
        }
        catch (OperationCanceledException)
        {
            Kill(process);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            throw new WingetException($"winget did not finish within {timeout.TotalMinutes.ToString("0", CultureInfo.InvariantCulture)} minutes.");
        }

        process.WaitForExit(); // flushes the asynchronous output readers
        logger.LogDebug("winget {Command} exited with {ExitCode}.", arguments.Count > 0 ? arguments[0] : "", process.ExitCode);
        lock (output)
        {
            return new WingetRunResult(process.ExitCode, output.ToString());
        }
    }

    private void Kill(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            logger.LogDebug(ex, "winget had already exited.");
        }
    }

    /// <summary>The newest <c>{name}_{version}_{arch}__8wekyb3d8bbwe</c> package directory (containing <paramref name="file"/>).</summary>
    private static string? Find(string name, string? file)
    {
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");
        var arch = RuntimeInformation.OSArchitecture == Architecture.Arm64 ? "arm64" : "x64";
        try
        {
            return Directory.EnumerateDirectories(root, $"{name}_*_{arch}__{Publisher}")
                .Select(d => (Directory: d, Version: VersionOf(Path.GetFileName(d))))
                .Where(d => d.Version is not null && (file is null || File.Exists(Path.Combine(d.Directory, file))))
                .OrderByDescending(d => d.Version)
                .Select(d => d.Directory)
                .FirstOrDefault();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null; // not running as LocalSystem, or App Installer is not provisioned
        }
    }

    private static Version? VersionOf(string directoryName)
    {
        var parts = directoryName.Split('_');
        return parts.Length >= 2 && Version.TryParse(parts[1], out var version) ? version : null;
    }
}
