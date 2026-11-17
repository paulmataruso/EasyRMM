using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Policy;

namespace EasyPatch.Agent.Core.Abstractions;

/// <summary>A preset message shown in the EasyPatch tray of every signed-in user.</summary>
public sealed record UserNotice
{
    public required UserMessagePreset Preset { get; init; }

    /// <summary>Restart time for <see cref="UserMessagePreset.RestartScheduled"/>; the tray shows it in local time.</summary>
    public DateTimeOffset? ScheduledAt { get; init; }
}

public enum RestartPromptKind
{
    /// <summary>The user is asked to restart and may postpone (within the deadline, if there is one).</summary>
    Prompt,

    /// <summary>The restart happens at <see cref="RestartPrompt.RestartAt"/>; the user can only restart sooner.</summary>
    Countdown,

    /// <summary>A user postponed the restart; the prompt returns at <see cref="RestartPrompt.PostponedUntil"/>.</summary>
    Postponed,
}

/// <summary>The restart request currently shown to users (published to every tray).</summary>
public sealed record RestartPrompt
{
    public required Guid JobId { get; init; }
    public required RestartPromptKind Kind { get; init; }

    /// <summary>When the computer restarts automatically (a deadline), if it does.</summary>
    public DateTimeOffset? Deadline { get; init; }

    /// <summary>For <see cref="RestartPromptKind.Countdown"/>: when the restart starts.</summary>
    public DateTimeOffset? RestartAt { get; init; }

    public DateTimeOffset? PostponedUntil { get; init; }

    /// <summary>Postpone choices in minutes (empty when the user cannot postpone).</summary>
    public IReadOnlyList<int> PostponeOptions { get; init; } = [];
}

/// <summary>A signed-in user's answer to a <see cref="RestartPrompt"/>.</summary>
public sealed record RestartPromptResponse(Guid JobId, bool RestartNow, int? PostponeMinutes, int SessionId);

/// <summary>The agent's connection to its server, as shown in the status window.</summary>
public enum TrayConnection
{
    Connected,

    /// <summary>The last check-in attempt failed (see <see cref="TrayStatus.UnreachableSince"/>).</summary>
    Unreachable,

    NotEnrolled,
    PendingApproval,

    /// <summary>The server rejected or revoked this computer's enrollment.</summary>
    Revoked,
}

/// <summary>Summary shown in the tray menu, its tooltip and the status window. Scalar values only, so two statuses
/// compare by value and an unchanged status is not sent again.</summary>
public sealed record TrayStatus
{
    public string Activity { get; init; } = "Idle";
    public DateTimeOffset? LastContactAt { get; init; }
    public bool RebootPending { get; init; }
    public string? AgentVersion { get; init; }

    /// <summary>When false the icon is hidden except while a message or restart request is shown.</summary>
    public bool ShowIcon { get; init; } = true;

    public TrayConnection Connection { get; init; } = TrayConnection.Connected;

    /// <summary>First failed check-in attempt since the last successful one.</summary>
    public DateTimeOffset? UnreachableSince { get; init; }

    /// <summary>Host name of the EasyPatch server (shown as "Managed by").</summary>
    public string? ServerHost { get; init; }

    /// <summary>Last successful update scan, and the number of applicable updates it found not installed.</summary>
    public DateTimeOffset? LastScanAt { get; init; }

    public int? UpdatesAvailable { get; init; }

    /// <summary>Set when the most recent scan failed (the reason, for example "Windows Update error 0x8024402C").</summary>
    public string? LastScanError { get; init; }

    /// <summary>The most recent installation job that installed at least one update, and how many it installed.</summary>
    public DateTimeOffset? LastInstallAt { get; init; }

    public int? LastInstallCount { get; init; }

    /// <summary>A user's check-in or update check is waiting to run (the status window disables the button meanwhile).</summary>
    public bool CheckInRequested { get; init; }

    public bool UpdateCheckRequested { get; init; }
}

/// <summary>What a signed-in user can ask for from the status window. Neither request carries any input.</summary>
public enum UserRequestKind
{
    /// <summary>Check in with the server now (also delivers queued reports and picks up waiting jobs).</summary>
    CheckIn,

    /// <summary>Scan for missing updates now. Never installs anything.</summary>
    CheckForUpdates,
}

/// <summary>The answer shown to the user in the status window.</summary>
public sealed record UserRequestResult(bool Accepted, string Message);

/// <summary>Runs the requests users make from the status window, rate-limited for the whole computer.</summary>
public interface IUserRequestHandler
{
    /// <param name="sessionId">The requesting user's session, from Windows (for the log only).</param>
    UserRequestResult Handle(UserRequestKind kind, int sessionId);
}

public enum TrayLogLevel
{
    Information,
    Warning,
    Error,
}

/// <summary>One entry of the agent log as shown in the status window: the first line of the message only.</summary>
public sealed record TrayLogEntry(DateTimeOffset At, TrayLogLevel Level, string Message);

/// <summary>
/// Talks to the signed-in users through the EasyPatch tray. Implementations never execute anything on behalf of a
/// user: the only input accepted from a tray is a restart-now or postpone answer to the current restart request,
/// and the fixed, parameterless requests of <see cref="UserRequestKind"/> (handled by <see cref="IUserRequestHandler"/>).
/// </summary>
public interface IUserInteraction
{
    UserSessionInfo GetSessions();

    /// <summary>Shows a preset message in every connected tray. Returns the number of sessions it reached.</summary>
    int Notify(UserNotice notice);

    /// <summary>Publishes the current restart request (null removes it).</summary>
    void SetRestartPrompt(RestartPrompt? prompt);

    /// <summary>Returns and clears the answers received since the last call.</summary>
    IReadOnlyList<RestartPromptResponse> TakeResponses();

    void SetStatus(TrayStatus status);

    /// <summary>Asks every tray to exit and, while <paramref name="suspended"/> is true, keeps trays from starting again.
    /// An agent update needs this: the trays run from the executable Windows Installer replaces.</summary>
    void SuspendTrays(bool suspended);
}

/// <summary>Used where no interactive users can exist (tests, or platforms without a tray).</summary>
public sealed class NoUserInteraction : IUserInteraction
{
    public static NoUserInteraction Instance { get; } = new();

    public UserSessionInfo GetSessions() => new();

    public int Notify(UserNotice notice) => 0;

    public void SetRestartPrompt(RestartPrompt? prompt)
    {
    }

    public IReadOnlyList<RestartPromptResponse> TakeResponses() => [];

    public void SetStatus(TrayStatus status)
    {
    }

    public void SuspendTrays(bool suspended)
    {
    }
}

/// <summary>Restarts the operating system. Only ever called for an administrator's restart job.</summary>
public interface ISystemRestart
{
    /// <summary>Restarts Windows. Signed-in sessions are signed out and their applications closed, so users are
    /// always warned first (tray countdown, or Windows' own warning during <paramref name="gracePeriod"/>).</summary>
    /// <param name="gracePeriod">Zero restarts at once; otherwise Windows warns signed-in users and waits this long.</param>
    /// <param name="message">Shown by Windows during the grace period.</param>
    void Restart(TimeSpan gracePeriod, string message);

    /// <summary>Cancels a restart that is still in its grace period. Returns false when it is too late.</summary>
    bool TryAbort();
}

/// <summary>Reads and writes the Windows Update policy values EasyPatch manages (HKLM, the two keys in
/// <see cref="WindowsUpdatePolicyRegistry"/> only).</summary>
public interface IPolicyRegistry
{
    /// <summary>Current value; absent (both null) when it does not exist. Values of other registry types are
    /// returned as text describing the type, so they never compare equal to a value EasyPatch writes.</summary>
    PolicyRegistryValue Read(PolicyRegistryKey key, string name);

    /// <summary>Writes a DWORD or string value, or deletes it when <see cref="PolicyRegistryValue.IsAbsent"/>.</summary>
    void Write(PolicyRegistryValue value);

    /// <summary>True when MDM (e.g. Intune) Update policies are present on the device.</summary>
    bool MdmUpdatePoliciesPresent();
}
