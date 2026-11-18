using System.Diagnostics;
using System.Text;

namespace EasyPatch.Unix.Processes;

/// <summary>Output of a finished command.</summary>
public sealed record CommandResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Succeeded => ExitCode == 0;

    /// <summary>Standard output followed by standard error (for error messages).</summary>
    public string Combined => string.IsNullOrEmpty(StandardError) ? StandardOutput : StandardOutput + "\n" + StandardError;
}

/// <summary>A command that could not be run (missing program, timeout).</summary>
public sealed class CommandException : Exception
{
    public CommandException()
    {
    }

    public CommandException(string message)
        : base(message)
    {
    }

    public CommandException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Runs operating-system programs. Programs are named by absolute path or resolved from the standard system directories
/// only (never from PATH), arguments are passed as an argument vector (never through a shell) and the C locale is forced
/// so output can be parsed. Nothing an administrator sends is ever turned into a command: callers build every argument
/// from fixed templates and validated package names.
/// </summary>
public interface ICommandRunner
{
    /// <summary>Absolute path of a system program, or null when it is not installed.</summary>
    string? Find(string program);

    Task<CommandResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? environment = null, byte[]? standardInput = null);

    /// <summary>Like <see cref="RunAsync"/> but returns standard output as bytes (binary-safe).</summary>
    Task<(int ExitCode, byte[] Output, string Error)> RunBinaryAsync(string program, IReadOnlyList<string> arguments, byte[] standardInput,
        TimeSpan timeout, CancellationToken cancellationToken);
}

public sealed class ProcessCommandRunner : ICommandRunner
{
    /// <summary>Output beyond this size is discarded (a runaway program cannot exhaust the agent's memory).</summary>
    public const int MaxOutputBytes = 32 * 1024 * 1024;

    private static readonly string[] SystemDirectories = ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"];

    public string? Find(string program)
    {
        ArgumentException.ThrowIfNullOrEmpty(program);
        if (Path.IsPathRooted(program))
        {
            return File.Exists(program) ? program : null;
        }

        foreach (var directory in SystemDirectories)
        {
            var candidate = Path.Combine(directory, program);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    public async Task<CommandResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken,
        IReadOnlyDictionary<string, string>? environment = null, byte[]? standardInput = null)
    {
        var (exitCode, output, error) = await RunCoreAsync(program, arguments, timeout, environment, standardInput, cancellationToken);
        return new CommandResult(exitCode, Decode(output), error);
    }

    public Task<(int ExitCode, byte[] Output, string Error)> RunBinaryAsync(string program, IReadOnlyList<string> arguments, byte[] standardInput,
        TimeSpan timeout, CancellationToken cancellationToken) =>
        RunCoreAsync(program, arguments, timeout, null, standardInput, cancellationToken);

    private async Task<(int ExitCode, byte[] Output, string Error)> RunCoreAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout,
        IReadOnlyDictionary<string, string>? environment, byte[]? standardInput, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var path = Find(program) ?? throw new CommandException($"{program} is not installed.");
        var start = new ProcessStartInfo(path)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            WorkingDirectory = "/",
        };
        foreach (var argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        // systemd's service variables belong to the agent process only (a child that inherits NOTIFY_SOCKET could
        // send notifications for the agent's service).
        foreach (var variable in (string[])["NOTIFY_SOCKET", "WATCHDOG_PID", "WATCHDOG_USEC", "LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES"])
        {
            start.Environment.Remove(variable);
        }

        start.Environment["LC_ALL"] = "C";
        start.Environment["LANG"] = "C";
        start.Environment["LANGUAGE"] = "C";
        start.Environment["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
        if (environment is not null)
        {
            foreach (var (key, value) in environment)
            {
                start.Environment[key] = value;
            }
        }

        using var process = new Process { StartInfo = start };
        try
        {
            process.Start();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            throw new CommandException($"Could not start {path}: {ex.Message}", ex);
        }

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        var outputTask = ReadLimitedAsync(process.StandardOutput.BaseStream, timeoutSource.Token);
        var errorTask = ReadLimitedAsync(process.StandardError.BaseStream, timeoutSource.Token);
        try
        {
            if (standardInput is not null)
            {
                await process.StandardInput.BaseStream.WriteAsync(standardInput, timeoutSource.Token);
            }

            process.StandardInput.Close();
            await process.WaitForExitAsync(timeoutSource.Token);
            var output = await outputTask;
            var error = await errorTask;
            return (process.ExitCode, output, Decode(error));
        }
        catch (OperationCanceledException)
        {
            Kill(process);
            if (cancellationToken.IsCancellationRequested)
            {
                throw;
            }

            throw new CommandException($"{Path.GetFileName(path)} did not finish within {timeout.TotalMinutes:0.#} minutes and was stopped.");
        }
        catch (IOException ex)
        {
            Kill(process);
            throw new CommandException($"{Path.GetFileName(path)} failed: {ex.Message}", ex);
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[64 * 1024];
        int read;
        while ((read = await stream.ReadAsync(chunk, cancellationToken)) > 0)
        {
            if (buffer.Length + read <= MaxOutputBytes)
            {
                buffer.Write(chunk, 0, read);
            }
        }

        return buffer.ToArray();
    }

    private static void Kill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Already gone.
        }
    }

    private static string Decode(byte[] bytes) => Encoding.UTF8.GetString(bytes);
}
