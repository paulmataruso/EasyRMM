using System.Diagnostics;
using System.Globalization;
using System.Text;
using EasyPatch.Agent.Core.Removal;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Platform;

/// <summary>
/// Runs <c>%SystemRoot%\System32\dism.exe</c> with an argument vector (no shell, no command string), with standard input closed so
/// DISM can never wait for an answer. Callers always pass <c>/NoRestart</c> to commands that could restart the computer.
/// </summary>
internal sealed class WindowsDismRunner(string logPath, ILogger<WindowsDismRunner> logger) : IDismRunner
{
    /// <summary>More than enough for <c>/Get-Packages</c> on a server with many features and language packs.</summary>
    private const int MaxOutputChars = 4 * 1024 * 1024;

    public string LogPath { get; } = logPath;

    public async Task<DismResult> RunAsync(IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
        var info = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "dism.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Environment.SystemDirectory,
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = info };
        var output = new StringBuilder();
        void Append(string? line)
        {
            if (line is not null)
            {
                lock (output)
                {
                    if (output.Length < MaxOutputChars)
                    {
                        output.Append(line).Append('\n');
                    }
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
            throw new DismException($"DISM could not be started ({ex.Message}).", ex);
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
            if (cancellationToken.IsCancellationRequested)
            {
                throw; // the service is stopping; DISM finishes on its own
            }

            // Not killed: stopping DISM part-way through a servicing operation could leave Windows' component store inconsistent.
            throw new DismException(
                $"DISM did not finish within {timeout.TotalMinutes.ToString("0", CultureInfo.InvariantCulture)} minutes; it was left to finish on its own. See {LogPath}.");
        }

        process.WaitForExit();
        logger.LogDebug("DISM {Command} exited with {ExitCode}.", arguments.Count > 1 ? arguments[1] : "", process.ExitCode);
        lock (output)
        {
            return new DismResult(process.ExitCode, output.ToString());
        }
    }
}
