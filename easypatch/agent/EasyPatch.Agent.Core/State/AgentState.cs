using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Policy;

namespace EasyPatch.Agent.Core.State;

public enum AgentEnrollmentStatus
{
    NotEnrolled,
    PendingApproval,
    Active,
    Rejected,

    /// <summary>The server revoked or no longer recognizes this agent's credential.</summary>
    Revoked,
}

public enum JobRunState
{
    /// <summary>Persisted locally, acknowledgement not yet confirmed by the server.</summary>
    Received,
    Acknowledged,
    Running,

    /// <summary>Parked until the computer restarts (Windows requires a reboot before installing, or a restart job
    /// has started the restart).</summary>
    WaitingForReboot,

    /// <summary>A restart job waiting for a signed-in user, a postponement, a countdown or a deadline.</summary>
    WaitingForUser,
}

/// <summary>Durable agent state, persisted as JSON under &lt;data&gt;/state/agent-state.json.</summary>
public sealed class AgentState
{
    public int SchemaVersion { get; set; } = 1;

    public string? ServerUrl { get; set; }

    public AgentEnrollmentStatus Status { get; set; } = AgentEnrollmentStatus.NotEnrolled;

    public Guid? EndpointId { get; set; }

    public Guid? OrganizationId { get; set; }

    /// <summary>Active credential (c_…).</summary>
    public string? CredentialId { get; set; }

    public DateTimeOffset? CredentialExpiresAt { get; set; }

    /// <summary>Pending enrollment request (r_…) while waiting for administrator approval.</summary>
    public string? PendingEnrollmentRequestId { get; set; }

    /// <summary>Fingerprint of the key the current credential belongs to.</summary>
    public string? KeyFingerprint { get; set; }

    public DateTimeOffset? EnrolledAt { get; set; }

    public DateTimeOffset? FirstStartedAt { get; set; }

    public DateTimeOffset? LastCheckInAt { get; set; }

    /// <summary>Last successful scan.</summary>
    public DateTimeOffset? LastScanAt { get; set; }

    public DateTimeOffset? LastScanAttemptAt { get; set; }

    /// <summary>Applicable updates not installed, found by the last successful scan.</summary>
    public int? LastScanMissingCount { get; set; }

    /// <summary>Why the most recent scan failed; null when it succeeded.</summary>
    public string? LastScanError { get; set; }

    /// <summary>The most recent installation job that installed at least one update, and how many it installed.</summary>
    public DateTimeOffset? LastInstallAt { get; set; }

    public int? LastInstallCount { get; set; }

    public DateTimeOffset? LastInventoryAt { get; set; }

    public DateTimeOffset? LastHistorySyncAt { get; set; }

    /// <summary>Newest Windows Update history entry already sent to the server.</summary>
    public DateTimeOffset? LastHistoryEntryDate { get; set; }

    /// <summary>Boot time observed on the previous run; a change triggers a post-reboot scan.</summary>
    public DateTimeOffset? LastBootAt { get; set; }

    public AgentConfig Config { get; set; } = new();

    public double ServerClockOffsetSeconds { get; set; }

    public string? LastAuthFailureCode { get; set; }

    public DateTimeOffset? LastAuthFailureAt { get; set; }

    /// <summary>Jobs held by the agent, in delivery order. At most one is executing at a time.</summary>
    public List<JobRecord> Jobs { get; set; } = [];

    /// <summary>Windows Update policy values EasyPatch manages, with the original values to restore.</summary>
    public WindowsUpdatePolicyEnforcement WindowsUpdatePolicy { get; set; } = new();

    /// <summary>The machine-wide winget as last checked, and the agent's attempts to install it (Windows).</summary>
    public WingetSetupState Winget { get; set; } = new();

    public JobRecord? FindJob(Guid jobId) => Jobs.Find(j => j.Job.JobId == jobId);
}

/// <summary>A job the agent has accepted, with everything needed to resume after a crash or restart.</summary>
public sealed class JobRecord
{
    public required AgentJob Job { get; set; }

    public JobRunState RunState { get; set; } = JobRunState.Received;

    public DateTimeOffset ReceivedAt { get; set; }

    public DateTimeOffset? StartedAt { get; set; }

    public string? Phase { get; set; }

    /// <summary>Next status-report sequence number (monotonic, persisted before each report).</summary>
    public long NextSequence { get; set; } = 1;

    /// <summary>Number of times execution has started; protects against crash loops.</summary>
    public int Attempts { get; set; }

    public bool CancelRequested { get; set; }

    /// <summary>Boot time when the job entered <see cref="JobRunState.WaitingForReboot"/>.</summary>
    public DateTimeOffset? WaitingBootTime { get; set; }

    public DateTimeOffset? WaitingSince { get; set; }

    /// <summary>Latest known per-update progress (used to keep earlier results across a resume).</summary>
    public List<JobItemReport> Items { get; set; } = [];

    /// <summary>Signed-in users were told that updates are installing (install jobs; avoids repeats after a crash).</summary>
    public bool UsersNotified { get; set; }

    /// <summary>Progress of a restart job.</summary>
    public RestartProgress? Restart { get; set; }

    /// <summary>Set when Windows Installer was started for an agent update job.</summary>
    public AgentUpdateProgress? AgentUpdate { get; set; }

    /// <summary>Set when the removal of the agent was started for an uninstall job.</summary>
    public UninstallProgress? Uninstall { get; set; }
}

public sealed class WingetSetupState
{
    /// <summary>Version of the machine-wide winget found at the last check; null when there was none.</summary>
    public string? Version { get; set; }

    public bool InstalledByAgent { get; set; }

    /// <summary>Why the last installation attempt failed; null when winget is ready.</summary>
    public string? Error { get; set; }

    public DateTimeOffset? CheckedAt { get; set; }

    public DateTimeOffset? LastAttemptAt { get; set; }

    /// <summary>Failed installation attempts in a row (spaces the retries out).</summary>
    public int Failures { get; set; }
}

public sealed class UninstallProgress
{
    public required string LogPath { get; set; }
    public DateTimeOffset LaunchedAt { get; set; }
}

public sealed class AgentUpdateProgress
{
    public required string FromVersion { get; set; }
    public required string TargetVersion { get; set; }
    public required string PackagePath { get; set; }
    public required string LogPath { get; set; }
    public DateTimeOffset LaunchedAt { get; set; }
}

public sealed class RestartProgress
{
    public DateTimeOffset StartedAt { get; set; }

    /// <summary>Boot time when the job started; a restart by anyone afterwards completes the job.</summary>
    public DateTimeOffset BootTimeAtStart { get; set; }

    public DateTimeOffset? Deadline { get; set; }

    /// <summary>The restart starts at this time (countdown).</summary>
    public DateTimeOffset? RestartAt { get; set; }

    public DateTimeOffset? PostponedUntil { get; set; }

    public int Postponements { get; set; }

    /// <summary>When the restart was requested from Windows.</summary>
    public DateTimeOffset? IssuedAt { get; set; }

    public TimeSpan GracePeriod { get; set; }

    public DateTimeOffset? LastHeartbeatAt { get; set; }
}

/// <summary>Per-group enforcement state of Windows Update policy overrides.</summary>
public sealed class WindowsUpdatePolicyEnforcement
{
    public Dictionary<WindowsUpdatePolicyGroup, ManagedPolicyGroup> Groups { get; set; } = [];

    /// <summary>Hash of the last status report the server accepted, and when.</summary>
    public string? LastReportedHash { get; set; }

    public DateTimeOffset? LastReportedAt { get; set; }
}

public sealed class ManagedPolicyGroup
{
    /// <summary>Values before EasyPatch first changed them; restored when the group is no longer managed.</summary>
    public List<PolicyRegistryValue> Original { get; set; } = [];

    /// <summary>Values EasyPatch wrote (the desired state the last time it applied the group).</summary>
    public List<PolicyRegistryValue> Applied { get; set; } = [];

    public WindowsUpdatePolicyState State { get; set; } = WindowsUpdatePolicyState.Applied;

    public string? Message { get; set; }

    public DateTimeOffset? AppliedAt { get; set; }

    public List<string> ConflictingValues { get; set; } = [];
}
