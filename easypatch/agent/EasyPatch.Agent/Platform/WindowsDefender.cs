using System.Diagnostics;
using System.Security.Principal;
using EasyPatch.Agent.Core.Companion;
using EasyPatch.Agent.Core.Defender;

namespace EasyPatch.Agent.Platform;

/// <summary>Drives Microsoft Defender through its PowerShell module, run from the fixed Windows PowerShell with fixed scripts; a call that
/// fails for a reason other than Defender's own refusal is tried once more by the <c>MSFT_MpPreference</c> class (ADR-0070, section 4).</summary>
internal sealed class WindowsDefenderBackend(string dataDirectory) : IDefenderBackend
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(2);

    public string Method { get; private set; } = "";

    public async Task<DefenderPrefs> ReadAsync(CancellationToken cancellationToken)
    {
        Method = "powershell";
        var (code, output) = await RunAsync(DefenderScripts.ReadScript, null, cancellationToken);
        return code == 0
            ? DefenderScripts.ParsePrefs(output)
            : throw new InvalidOperationException($"Defender's settings could not be read: {Tail(output)}");
    }

    public Task AddAsync(string kind, string path, CancellationToken cancellationToken) => ChangeAsync("Add", kind, path, cancellationToken);

    public Task RemoveAsync(string kind, string path, CancellationToken cancellationToken) => ChangeAsync("Remove", kind, path, cancellationToken);

    private async Task ChangeAsync(string verb, string kind, string path, CancellationToken cancellationToken)
    {
        var script = DefenderScripts.ChangeScript(verb, kind) ?? throw new ArgumentException($"Unknown exclusion kind '{kind}'.", nameof(kind));
        var (code, output) = await RunAsync(script, path, cancellationToken);
        if (code == 0)
        {
            Method = "powershell";
            return;
        }

        if (DefenderScripts.IsRefusal(output))
        {
            Method = "powershell";
            throw new DefenderRefusedException(Tail(output));
        }

        // Once, for this one call: never both for an entry that worked.
        var (code2, output2) = await RunAsync(DefenderScripts.WmiScript(verb, kind)!, path, cancellationToken);
        Method = "wmi";
        if (code2 == 0)
        {
            return;
        }

        throw DefenderScripts.IsRefusal(output2)
            ? new DefenderRefusedException(Tail(output2))
            : new InvalidOperationException($"Defender could not be changed by PowerShell ({Tail(output)}) or by WMI ({Tail(output2)}).");
    }

    private async Task<(int Code, string Output)> RunAsync(string script, string? path, CancellationToken cancellationToken)
    {
        var exe = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var info = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            WorkingDirectory = Environment.SystemDirectory,
        };
        foreach (var argument in (string[])["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script])
        {
            info.ArgumentList.Add(argument);
        }

        if (path is not null)
        {
            info.Environment[DefenderScripts.PathVariable] = path;
        }

        AgentFolders.UseWorkAsTemp(info, dataDirectory);
        using var process = Process.Start(info) ?? throw new InvalidOperationException("PowerShell did not start.");
        process.StandardInput.Close();
        var output = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var error = process.StandardError.ReadToEndAsync(cancellationToken);
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        limit.CancelAfter(Timeout);
        try
        {
            await process.WaitForExitAsync(limit.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            throw;
        }

        return (process.ExitCode, await output + await error);
    }

    private static string Tail(string text)
    {
        var s = string.Join(' ', text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return s.Length > 200 ? s[^200..] : s;
    }
}

/// <summary>Locks the folders down and verifies them with the rules of <see cref="FileTrust"/> (ADR-0070, section 2).</summary>
internal sealed class WindowsFolderGuard(string dataDirectory, string installDirectory) : IFolderGuard
{
    private static readonly string? Agent = WindowsIdentity.GetCurrent().User?.Value;

    public string? Secure(string folder)
    {
        try
        {
            if (Same(folder, dataDirectory))
            {
                SecureStorage.SecureDataDirectory(folder);
            }
            else if (Same(folder, installDirectory))
            {
                SecureStorage.SecureInstallDirectory(folder);
            }
            else
            {
                return $"{folder} is not a folder of this agent.";
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {
            return ex.Message;
        }

        return Check(folder);
    }

    public string? Check(string folder)
    {
        try
        {
            return FileTrust.CheckFolderWindows(folder, Agent);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            return $"{folder} cannot be verified: {ex.Message}";
        }
    }

    private static bool Same(string a, string b) =>
        string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(a)), Path.TrimEndingDirectorySeparator(Path.GetFullPath(b)), StringComparison.OrdinalIgnoreCase);
}
