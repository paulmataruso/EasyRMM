using System.Security.Cryptography;
using System.Text;
using EasyPatch.Agent.Core.Logging;
using EasyPatch.Contracts.Agent;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Agent.Core.Companion;

/// <summary>
/// The steps of ADR-0069's RepairCompanion and CollectLogs jobs. A step is chosen by target and name from fixed lists and maps to code
/// shipped here: it restarts a service, runs the EasyRMM agent's own <c>repair-install</c> from its recovery copy once the four
/// checks pass, or reads logs. This side builds no service definition; the EasyRMM agent puts itself back.
/// </summary>
public sealed class CompanionRepairService : ICompanionRepair
{
    /// <summary>How many lines of each log a repair or a collection returns.</summary>
    public const int LogLines = 500;

    private const long MaxBytesPerLog = 1024 * 1024;
    private const int MaxLineLength = 4000;
    private static readonly TimeSpan RepairTimeout = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RunningWait = TimeSpan.FromSeconds(30);

    private readonly CompanionLayout _layout;
    private readonly ICompanionHost _host;
    private readonly ILogger _logger;
    private readonly TimeSpan _poll;

    public CompanionRepairService(CompanionLayout layout, ICompanionHost host, ILogger<CompanionRepairService> logger, TimeSpan? pollInterval = null)
    {
        _layout = layout;
        _host = host;
        _logger = logger;
        _poll = pollInterval ?? TimeSpan.FromSeconds(1);
    }

    public async Task<CompanionOutcome> RestartAsync(string target, CancellationToken cancellationToken)
    {
        var (name, service) = target switch
        {
            CompanionTargets.EasyRmmAgent => ("EasyRMM agent", _layout.EasyRmmService),
            CompanionTargets.MeshAgent => ("MeshAgent", _layout.MeshService),
            _ => throw new ArgumentOutOfRangeException(nameof(target), target, "Not a repair target."),
        };

        if (await _host.ServiceStateAsync(service, cancellationToken) == "missing")
        {
            var hint = target == CompanionTargets.MeshAgent
                ? " MeshAgent runs as a child of the EasyRMM agent on this computer, so restart the EasyRMM agent instead."
                : " Repair it from the recovery copy instead.";
            return await FailedAsync(target, CompanionErrors.ServiceMissing, $"The {name}'s service ({service}) is not installed.{hint}", null, cancellationToken);
        }

        var why = await _host.RestartServiceAsync(service, cancellationToken);
        if (why is not null)
        {
            return await FailedAsync(target, CompanionErrors.RestartFailed, $"The {name} could not be restarted: {why}", why, cancellationToken);
        }

        if (!await WaitRunningAsync(service, cancellationToken))
        {
            return await FailedAsync(target, CompanionErrors.RestartFailed, $"The {name}'s service was restarted but is not running {RunningWait.TotalSeconds:0} seconds later.", null,
                cancellationToken);
        }

        _logger.LogWarning("Restarted {Target}'s service {Service} for EasyRMM.", target, service);
        return new CompanionOutcome(true, $"Restarted the {name}'s service ({service}); it is running.", Diagnostics: await TargetDiagnosticsAsync(target, null, cancellationToken));
    }

    public async Task<CompanionOutcome> RepairEasyRmmAgentAsync(string expectedSha256, CancellationToken cancellationToken)
    {
        const string target = CompanionTargets.EasyRmmAgent;

        // 1. An update is in progress, or its probation is open: the agent is not broken, and repairing it would undo the update.
        if (Path.Exists(_layout.UpdateMarker))
        {
            return await FailedAsync(target, CompanionErrors.UpdateInProgress,
                "The EasyRMM agent is updating itself or in the probation after an update (update.json is present), so it was not repaired.", null, cancellationToken);
        }

        var copy = _layout.RecoveryCopy;
        if (!Path.Exists(copy) && new FileInfo(copy).LinkTarget is null)
        {
            return await FailedAsync(target, CompanionErrors.CopyMissing, "There is no recovery copy of the EasyRMM agent on this computer.", null, cancellationToken);
        }

        // 2. No links or reparse points; the system owns the copy; only the system, administrators or root may change it or the
        // directories above it.
        var refusal = await _host.CheckTrustAsync(copy, _layout.TrustStopAt, cancellationToken);
        if (refusal is not null)
        {
            _logger.LogError("Refused to repair the EasyRMM agent from {Copy}: {Reason}", copy, refusal);
            return await FailedAsync(target, CompanionErrors.CopyNotTrusted, "The recovery copy was refused: " + refusal, null, cancellationToken);
        }

        // 3. Its SHA-256 is the one EasyRMM recorded for the build the device runs.
        string actual;
        try
        {
            actual = await HashAsync(copy, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return await FailedAsync(target, CompanionErrors.CopyNotTrusted, "The recovery copy could not be read: " + ex.Message, null, cancellationToken);
        }

        if (!string.Equals(actual, expectedSha256, StringComparison.Ordinal))
        {
            _logger.LogError("Refused to repair the EasyRMM agent: the recovery copy's SHA-256 is {Actual}, the job says {Expected}.", actual, expectedSha256);
            return await FailedAsync(target, CompanionErrors.HashMismatch,
                $"The recovery copy was refused: its SHA-256 ({actual[..12]}...) is not the one EasyRMM recorded for this device's build ({expectedSha256[..12]}...).", null,
                cancellationToken);
        }

        // 4. The copy's own repair-install puts the agent back and starts it.
        ProgramResult result;
        try
        {
            result = await _host.RunAsync(copy, ["repair-install"], RepairTimeout, cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return await FailedAsync(target, CompanionErrors.RepairFailed, "The recovery copy could not be run: " + ex.Message, null, cancellationToken);
        }

        var output = LogRedactor.Redact(result.Output).Trim();
        if (!result.Succeeded)
        {
            var why = result.TimedOut ? "it did not finish in " + RepairTimeout.TotalMinutes.ToString("0", System.Globalization.CultureInfo.InvariantCulture) + " minutes" : $"it exited with code {result.ExitCode}";
            return await FailedAsync(target, CompanionErrors.RepairFailed, $"The recovery copy's repair-install failed: {why}. {Last(output)}".Trim(), output, cancellationToken);
        }

        if (!await WaitRunningAsync(_layout.EasyRmmService, cancellationToken))
        {
            return await FailedAsync(target, CompanionErrors.RepairFailed,
                $"repair-install finished but the EasyRMM agent's service is not running {RunningWait.TotalSeconds:0} seconds later. {Last(output)}".Trim(), output, cancellationToken);
        }

        _logger.LogWarning("Repaired the EasyRMM agent from its recovery copy for EasyRMM.");
        return new CompanionOutcome(true, "Repaired the EasyRMM agent from its recovery copy; its service is running. " + Last(output),
            Diagnostics: await TargetDiagnosticsAsync(target, output, cancellationToken));
    }

    public async Task<CompanionOutcome> CollectLogsAsync(CancellationToken cancellationToken)
    {
        var sections = new List<(string Title, string Text)>();
        foreach (var target in new[] { "easyrmm-agent", "meshagent", "easypatch-agent" })
        {
            sections.Add((target, await ReadLogAsync(target, cancellationToken)));
        }

        return new CompanionOutcome(true, $"Collected the newest {LogLines} lines of each agent's log.", Diagnostics: Combine(sections));
    }

    // ---------------------------------------------------------------------------------------------------------------------------

    private async Task<CompanionOutcome> FailedAsync(string target, string code, string message, string? detail, CancellationToken cancellationToken) =>
        new(false, Truncate(message), code, await TargetDiagnosticsAsync(target, detail, cancellationToken));

    private async Task<string> TargetDiagnosticsAsync(string target, string? detail, CancellationToken cancellationToken)
    {
        var sections = new List<(string, string)>();
        if (!string.IsNullOrWhiteSpace(detail))
        {
            sections.Add(("output", LogRedactor.Redact(detail).Trim()));
        }

        sections.Add((target, await ReadLogAsync(target, cancellationToken)));
        return Combine(sections);
    }

    private async Task<string> ReadLogAsync(string target, CancellationToken cancellationToken)
    {
        var (file, previous, service) = target switch
        {
            CompanionTargets.EasyRmmAgent => (_layout.EasyRmmLogFile, _layout.EasyRmmLogFile + ".1", _layout.EasyRmmService),
            CompanionTargets.MeshAgent => (_layout.MeshLogFile, null, _layout.MeshService),
            _ => (_layout.EasyPatchLogFile, Path.Combine(Path.GetDirectoryName(_layout.EasyPatchLogFile) ?? "", Path.GetFileNameWithoutExtension(_layout.EasyPatchLogFile) + ".1" + Path.GetExtension(_layout.EasyPatchLogFile)), null),
        };

        var lines = new List<string>();
        try
        {
            lines = ReadLastLines(file, previous, LogLines);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            lines.Add($"(the log {Path.GetFileName(file)} could not be read: {ex.Message})");
        }

        if (lines.Count == 0 && service is not null)
        {
            // Where the program writes to the journal and not to a file (the EasyRMM agent on Linux).
            var journal = await _host.ReadJournalAsync(service, LogLines, cancellationToken);
            if (!string.IsNullOrWhiteSpace(journal))
            {
                lines = journal.Split('\n').TakeLast(LogLines).ToList();
            }
        }

        // A line of an agent's log is short; one that is not is cut, so that redacting it is bounded.
        lines = lines.Select(l => l.Length > MaxLineLength ? l[..MaxLineLength] + " [line cut]" : l).ToList();
        return lines.Count == 0 ? "(no log lines found)" : LogRedactor.Redact(string.Join('\n', lines));
    }

    /// <summary>The last <paramref name="count"/> lines of a log, reaching into its previous file when the newest one is short.</summary>
    internal static List<string> ReadLastLines(string file, string? previous, int count)
    {
        var lines = TailLines(file, count);
        if (lines.Count < count && previous is not null)
        {
            lines.InsertRange(0, TailLines(previous, count - lines.Count));
        }

        return lines;
    }

    private static List<string> TailLines(string path, int count)
    {
        if (!File.Exists(path))
        {
            return [];
        }

        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        var start = Math.Max(0, stream.Length - MaxBytesPerLog);
        stream.Seek(start, SeekOrigin.Begin);
        using var reader = new StreamReader(stream, new UTF8Encoding(false), true);
        var text = reader.ReadToEnd();
        var lines = text.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n').ToList();
        if (start > 0 && lines.Count > 0)
        {
            lines.RemoveAt(0); // a line cut in the middle
        }

        while (lines.Count > 0 && lines[^1].Length == 0)
        {
            lines.RemoveAt(lines.Count - 1);
        }

        return lines.Count > count ? lines.GetRange(lines.Count - count, count) : lines;
    }

    /// <summary>Titled sections, newest lines kept, within <see cref="JobDiagnostics.MaxBytes"/>: each section gets an equal share.</summary>
    internal static string Combine(IReadOnlyList<(string Title, string Text)> sections)
    {
        var share = (JobDiagnostics.MaxBytes - (sections.Count * 128)) / Math.Max(1, sections.Count);
        var builder = new StringBuilder();
        foreach (var (title, text) in sections)
        {
            builder.Append("==== ").Append(title).Append(" ====\n").Append(KeepEnd(text, share)).Append("\n\n");
        }

        return KeepEnd(builder.ToString(), JobDiagnostics.MaxBytes);
    }

    /// <summary>The end of <paramref name="text"/>, at most <paramref name="maxBytes"/> bytes (UTF-8), cut at a line.</summary>
    internal static string KeepEnd(string text, int maxBytes)
    {
        if (Encoding.UTF8.GetByteCount(text) <= maxBytes)
        {
            return text;
        }

        const string Marker = "[earlier lines dropped]\n";
        var budget = maxBytes - Encoding.UTF8.GetByteCount(Marker);
        var bytes = Encoding.UTF8.GetBytes(text);
        var start = bytes.Length - budget;
        // Not in the middle of a character, and at the start of a line where there is one close.
        while (start < bytes.Length && (bytes[start] & 0xC0) == 0x80)
        {
            start++;
        }

        var newline = Array.IndexOf(bytes, (byte)'\n', start);
        if (newline >= 0 && newline + 1 < bytes.Length)
        {
            start = newline + 1;
        }

        return Marker + Encoding.UTF8.GetString(bytes, start, bytes.Length - start);
    }

    private async Task<bool> WaitRunningAsync(string service, CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + RunningWait;
        while (true)
        {
            if (await _host.ServiceStateAsync(service, cancellationToken) == "running")
            {
                return true;
            }

            if (DateTime.UtcNow >= deadline)
            {
                return false;
            }

            await Task.Delay(_poll, cancellationToken);
        }
    }

    private static async Task<string> HashAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken));
    }

    private static string Last(string output)
    {
        var line = output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault() ?? "";
        return line.Length > 300 ? line[..300] : line;
    }

    private static string Truncate(string message) =>
        message.Length <= JobDiagnostics.MaxMessageLength ? message : message[..(JobDiagnostics.MaxMessageLength - 3)] + "...";
}
