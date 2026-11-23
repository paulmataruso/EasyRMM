using System.Diagnostics;
using System.Text;

namespace EasyPatch.Agent.Core.Companion;

/// <summary>Runs a program by absolute path with an argument vector, never through a shell, with a time limit and a cap on what it
/// may print. The locale is forced to C so that output can be read.</summary>
public sealed class ProcessProgramRunner : IProgramRunner
{
    private const int MaxOutputChars = 256 * 1024;

    public async Task<ProgramResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(program);
        ArgumentNullException.ThrowIfNull(arguments);
        if (!Path.IsPathRooted(program))
        {
            throw new ArgumentException("A program is run by absolute path.", nameof(program));
        }

        var info = new ProcessStartInfo(program)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }

        info.Environment["LC_ALL"] = "C";
        using var process = Process.Start(info) ?? throw new InvalidOperationException($"{program} did not start.");
        process.StandardInput.Close();
        var output = new StringBuilder();
        var gate = new Lock();
        void Append(string? line)
        {
            if (line is null)
            {
                return;
            }

            lock (gate)
            {
                if (output.Length < MaxOutputChars)
                {
                    output.Append(line).Append('\n');
                }
            }
        }

        var stdout = Task.Run(async () =>
        {
            while (await process.StandardOutput.ReadLineAsync(CancellationToken.None) is { } line)
            {
                Append(line);
            }
        }, CancellationToken.None);
        var stderr = Task.Run(async () =>
        {
            while (await process.StandardError.ReadLineAsync(CancellationToken.None) is { } line)
            {
                Append(line);
            }
        }, CancellationToken.None);

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutSource.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None);
            await Task.WhenAll(stdout, stderr);
            return new ProgramResult(-1, output.ToString(), TimedOut: true);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }

        await Task.WhenAll(stdout, stderr);
        return new ProgramResult(process.ExitCode, output.ToString(), TimedOut: false);
    }
}
