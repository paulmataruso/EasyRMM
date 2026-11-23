using EasyPatch.Contracts.Agent;

namespace EasyPatch.Agent.Core.Companion;

/// <summary>How a repair or log collection ended, as the job reports it (ADR-0069).</summary>
/// <param name="Message">What happened, in a sentence or two (at most <see cref="JobDiagnostics.MaxMessageLength"/> characters).</param>
/// <param name="ErrorCode">Why it failed (<see cref="CompanionErrors"/>), null on success.</param>
/// <param name="Diagnostics">Redacted log lines and facts, at most <see cref="JobDiagnostics.MaxBytes"/> bytes.</param>
public sealed record CompanionOutcome(bool Succeeded, string Message, string? ErrorCode = null, string? Diagnostics = null);

/// <summary>The error codes of a refused or failed repair step.</summary>
public static class CompanionErrors
{
    public const string UpdateInProgress = "update_in_progress";
    public const string CopyMissing = "recovery_copy_missing";
    public const string CopyNotTrusted = "recovery_copy_not_trusted";
    public const string HashMismatch = "recovery_copy_hash_mismatch";
    public const string RepairFailed = "repair_failed";
    public const string ServiceMissing = "service_missing";
    public const string RestartFailed = "restart_failed";
    public const string NotSupported = "not_supported";
}

/// <summary>What a RepairCompanion or CollectLogs job does on this computer. Every step is code the agent ships with; nothing in a
/// job is run as a command.</summary>
public interface ICompanionRepair
{
    /// <summary>Restarts the service of <see cref="CompanionTargets.EasyRmmAgent"/> or <see cref="CompanionTargets.MeshAgent"/>.</summary>
    Task<CompanionOutcome> RestartAsync(string target, CancellationToken cancellationToken);

    /// <summary>Repairs the EasyRMM agent from its recovery copy: refuses while its update marker is present, refuses a copy that is
    /// linked or that anyone but the system may change, refuses a copy whose SHA-256 is not <paramref name="expectedSha256"/>, then
    /// runs the copy's own <c>repair-install</c>.</summary>
    Task<CompanionOutcome> RepairEasyRmmAgentAsync(string expectedSha256, CancellationToken cancellationToken);

    /// <summary>The newest lines of each agent's log, redacted.</summary>
    Task<CompanionOutcome> CollectLogsAsync(CancellationToken cancellationToken);
}

/// <summary>The output of a program that was run.</summary>
public sealed record ProgramResult(int ExitCode, string Output, bool TimedOut)
{
    public bool Succeeded => ExitCode == 0 && !TimedOut;
}

/// <summary>Runs a program by absolute path with an argument vector, never through a shell.</summary>
public interface IProgramRunner
{
    Task<ProgramResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>The parts of a repair that differ between Windows and Linux.</summary>
public interface ICompanionHost
{
    /// <summary>"running", "stopped", "missing" (there is no such service) or "unknown".</summary>
    Task<string> ServiceStateAsync(string service, CancellationToken cancellationToken);

    /// <summary>Stops the service, if it runs, and starts it. Returns why it could not, null when the restart was done.</summary>
    Task<string?> RestartServiceAsync(string service, CancellationToken cancellationToken);

    /// <summary>The newest lines the service wrote to the system journal, where there is one; null otherwise.</summary>
    Task<string?> ReadJournalAsync(string service, int lines, CancellationToken cancellationToken);

    /// <summary>Why the recovery copy cannot be trusted (ADR-0069, step 2): linked, a reparse point, owned by anyone but the system, or
    /// changeable by anyone but the system, an administrator or root, in itself or in a directory above it. Null when it can.
    /// <paramref name="stopAt"/> ends the walk up the directories at that one (tests only).</summary>
    Task<string?> CheckTrustAsync(string path, string? stopAt, CancellationToken cancellationToken);

    /// <summary>Runs the recovery copy.</summary>
    Task<ProgramResult> RunAsync(string program, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Where the EasyRMM agent, MeshAgent and this agent keep what a repair touches.</summary>
public sealed record CompanionLayout
{
    /// <summary>The EasyRMM agent's state directory.</summary>
    public required string StateDirectory { get; init; }

    /// <summary>The EasyRMM agent's recovery copy of its own program.</summary>
    public required string RecoveryCopy { get; init; }

    /// <summary>The EasyRMM agent's service: a Windows service name or a systemd unit.</summary>
    public required string EasyRmmService { get; init; }

    /// <summary>MeshAgent's service, where it runs as one.</summary>
    public required string MeshService { get; init; }

    public required string EasyRmmLogFile { get; init; }
    public required string MeshLogFile { get; init; }
    public required string EasyPatchLogFile { get; init; }

    /// <summary>The self-update marker (<c>update.json</c>) in the EasyRMM agent's state directory: present while an update is in
    /// progress or its probation is open (ADR-0027).</summary>
    public string UpdateMarker => Path.Combine(StateDirectory, "update.json");

    /// <summary>Set by tests: the directory the walk up from the recovery copy ends at.</summary>
    public string? TrustStopAt { get; init; }

    public static CompanionLayout ForWindows()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData, Environment.SpecialFolderOption.DoNotVerify);
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolderOption.DoNotVerify);
        var state = Path.Combine(programData, "EasyRMM", "Agent");
        return new CompanionLayout
        {
            StateDirectory = state,
            RecoveryCopy = Path.Combine(state, "recovery", "easyrmm-agent.exe"),
            EasyRmmService = "EasyRMMAgent",
            MeshService = "EasyRMMMeshAgent",
            EasyRmmLogFile = Path.Combine(state, "logs", "agent.log"),
            MeshLogFile = Path.Combine(programFiles, "EasyRMM", "MeshAgent", "meshagent.log"),
            EasyPatchLogFile = Path.Combine(programData, "EasyPatch", "logs", "agent.log"),
        };
    }

    public static CompanionLayout ForLinux()
    {
        const string state = "/var/lib/easyrmm-agent";
        return new CompanionLayout
        {
            StateDirectory = state,
            RecoveryCopy = state + "/recovery/easyrmm-agent",
            EasyRmmService = "easyrmm-agent.service",
            MeshService = "easyrmm-meshagent.service",
            EasyRmmLogFile = state + "/logs/agent.log",
            MeshLogFile = "/usr/local/lib/easyrmm-agent/meshagent/meshagent.log",
            EasyPatchLogFile = "/var/lib/easypatch/logs/agent.log",
        };
    }
}
