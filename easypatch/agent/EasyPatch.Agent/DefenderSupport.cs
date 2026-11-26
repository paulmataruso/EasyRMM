using System.Text.Json;
using EasyPatch.Agent.Core.Defender;
using EasyPatch.Agent.Platform;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent;

/// <summary>Wires the Defender exclusions (ADR-0070, slice B) to this agent's fixed folders and program, and runs them at service start
/// and for the <c>defender</c> command. A Defender failure is logged and reported; it never stops the agent, an install or an uninstall.</summary>
internal static class DefenderSupport
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    /// <summary>The fixed install folder: <c>%ProgramFiles%\EasyPatch Agent</c>, never read from the command line or the installer's properties.</summary>
    public static string InstallDirectory => AgentFolders.InstallDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));

    public static DefenderExclusions Create(ILogger logger)
    {
        var data = AgentComposition.DataDirectory;
        var install = InstallDirectory;
        return new DefenderExclusions(
            new DefenderExclusionsOptions
            {
                Folders = [install, data],
                Programs = [Path.Combine(install, AgentFolders.ProgramName)],
                RecordFile = AgentFolders.RecordFile(data),
                AgentVersion = AgentComposition.AgentVersion,
            },
            new WindowsDefenderBackend(data),
            new WindowsFolderGuard(data, install),
            logger);
    }

    /// <summary>At each service start, beside <c>SecureDataDirectory</c>: locks down, verifies, and excludes what qualifies. Runs after
    /// the service is up so it never delays the service control manager.</summary>
    public static void ReconcileInBackground(ILogger logger) =>
        _ = Task.Run(async () =>
        {
            try
            {
                var report = await Create(logger).ReconcileAsync(CancellationToken.None);
                logger.LogInformation("Defender exclusions: {State}{Reason}", report.State, report.Reason is null ? "" : $" ({report.Reason})");
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Defender exclusions could not be reconciled.");
            }
        });

    /// <summary><c>defender add|remove|status</c>: the installer runs <c>add</c> after the files are laid down and <c>remove</c> on
    /// uninstall, before the identity is deleted. <c>status</c> changes nothing.</summary>
    public static async Task<int> RunAsync(string[] args, ILoggerFactory loggers)
    {
        var action = args.Length > 0 ? args[0].ToLowerInvariant() : "";
        if (action is not ("add" or "remove" or "status") || args.Length > 1)
        {
            throw new CliUsageException("Usage: defender add|remove|status");
        }

        if (!SecureStorage.IsElevated())
        {
            return Cli.StartupFailure("The defender command must run elevated.", Cli.ExitNotElevated);
        }

        var exclusions = Create(loggers.CreateLogger("EasyPatch.Defender"));
        try
        {
            switch (action)
            {
                case "add":
                    Console.WriteLine(JsonSerializer.Serialize(await exclusions.ReconcileAsync(CancellationToken.None), Indented));
                    break;
                case "status":
                    Console.WriteLine(JsonSerializer.Serialize(await exclusions.StatusAsync(CancellationToken.None), Indented));
                    break;
                default:
                    var result = await exclusions.RemoveAsync(CancellationToken.None);
                    Console.WriteLine(JsonSerializer.Serialize(result, Indented));
                    break;
            }

            return Cli.ExitSuccess;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return Cli.ExitFailure;
        }
    }
}
