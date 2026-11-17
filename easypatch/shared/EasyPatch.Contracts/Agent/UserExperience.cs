namespace EasyPatch.Contracts.Agent;

/// <summary>Optional features an agent declares in every check-in. The server only delivers jobs an agent can run.</summary>
public static class AgentCapabilities
{
    public const string Restart = "restart";
    public const string NotifyUser = "notify-user";
    public const string WindowsUpdatePolicy = "windows-update-policy";
    public const string Tray = "tray";

    /// <summary>The agent can install signed agent updates (it was built with at least one release key).</summary>
    public const string SelfUpdate = "self-update";

    /// <summary>The agent can check and install third-party application updates (winget; Windows agent 1.4.0 and later).</summary>
    public const string ApplicationUpdates = "app-updates";

    /// <summary>The agent can remove itself for an administrator's uninstall job (agent 1.6.0 and later, installed from its package).</summary>
    public const string Uninstall = "uninstall";

    /// <summary>The agent can remove an installed Windows update (Windows agent 1.8.0 and later).</summary>
    public const string UninstallUpdates = "uninstall-updates";

    /// <summary>The agent can download Windows updates without installing them (Windows agent 1.8.0 and later).</summary>
    public const string DownloadUpdates = "download-updates";

    public static IReadOnlyList<string> All { get; } =
        [Restart, NotifyUser, WindowsUpdatePolicy, Tray, SelfUpdate, ApplicationUpdates, Uninstall, UninstallUpdates, DownloadUpdates];

    /// <summary>The capability a job type needs, or null when every agent supports it.</summary>
    public static string? RequiredFor(JobType type) => type switch
    {
        JobType.Restart => Restart,
        JobType.NotifyUser => NotifyUser,
        JobType.AgentUpdate => SelfUpdate,
        JobType.UninstallAgent => Uninstall,
        JobType.UninstallUpdate => UninstallUpdates,
        JobType.DownloadUpdates => DownloadUpdates,
        _ => null,
    };
}

public sealed record RestartPayload
{
    public const int MinCountdownMinutes = 1;
    public const int MaxCountdownMinutes = 60;
    public const int MinDeadlineMinutes = 15;
    public const int MaxDeadlineMinutes = 7 * 24 * 60;

    /// <summary>Length of the final countdown when a <see cref="RestartMode.PromptWithDeadline"/> deadline is reached.</summary>
    public const int FinalCountdownMinutes = 5;

    public RestartMode Mode { get; init; }
    public RestartCondition Condition { get; init; }

    /// <summary>For <see cref="RestartMode.Countdown"/>.</summary>
    public int CountdownMinutes { get; init; } = 5;

    /// <summary>For <see cref="RestartMode.PromptWithDeadline"/>: measured from when the user is first asked.</summary>
    public int DeadlineMinutes { get; init; } = 240;

    public static IReadOnlyList<string> Validate(RestartPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var errors = new List<string>();
        if (!Enum.IsDefined(payload.Mode))
        {
            errors.Add("Unknown restart mode.");
        }

        if (!Enum.IsDefined(payload.Condition))
        {
            errors.Add("Unknown restart condition.");
        }

        if (payload.Mode == RestartMode.Countdown && payload.CountdownMinutes is < MinCountdownMinutes or > MaxCountdownMinutes)
        {
            errors.Add($"The countdown must be between {MinCountdownMinutes} and {MaxCountdownMinutes} minutes.");
        }

        if (payload.Mode == RestartMode.PromptWithDeadline && payload.DeadlineMinutes is < MinDeadlineMinutes or > MaxDeadlineMinutes)
        {
            errors.Add($"The deadline must be between {MinDeadlineMinutes} minutes and {MaxDeadlineMinutes / 1440} days.");
        }

        return errors;
    }

    /// <summary>Postpone choices offered to the user (minutes), limited by the time left before the deadline.</summary>
    public static IReadOnlyList<int> PostponeOptions(TimeSpan? timeLeft)
    {
        int[] all = [60, 4 * 60, 24 * 60];
        return timeLeft is { } left ? all.Where(m => TimeSpan.FromMinutes(m) < left).ToList() : all;
    }
}

public sealed record NotifyUserPayload
{
    public required UserMessagePreset Preset { get; init; }

    /// <summary>Restart time for <see cref="UserMessagePreset.RestartScheduled"/>; shown in the user's local time.</summary>
    public DateTimeOffset? ScheduledAt { get; init; }
}

/// <summary>Per-endpoint user-facing settings delivered in <see cref="AgentConfig"/>.</summary>
public sealed record UserExperienceConfig
{
    /// <summary>Show the EasyPatch icon in the notification area for every signed-in user.</summary>
    public bool TrayIcon { get; init; } = true;

    /// <summary>Tell signed-in users when updates start installing and when they finish.</summary>
    public bool InstallNotifications { get; init; } = true;
}

/// <summary>Signed-in interactive users, reported in check-ins. Counts only: no user names leave the computer.</summary>
public sealed record UserSessionInfo
{
    public int SignedInUsers { get; init; }

    /// <summary>Sessions whose EasyPatch tray is connected to the agent service.</summary>
    public int TrayConnected { get; init; }
}

/// <summary>Texts of the preset messages. Shared so the console preview and the tray show exactly the same words.</summary>
public static class UserMessages
{
    public static string Title(UserMessagePreset preset) => preset switch
    {
        UserMessagePreset.UpdatesInstalling => "Updates are installing",
        UserMessagePreset.UpdatesInstalled => "Updates installed",
        UserMessagePreset.RestartRequired => "Restart required",
        UserMessagePreset.SaveYourWork => "Please save your work",
        UserMessagePreset.MaintenanceTonight => "Maintenance tonight",
        UserMessagePreset.RestartScheduled => "Restart scheduled",
        _ => "Message from your IT team",
    };

    /// <param name="scheduledAt">Formatted restart time for <see cref="UserMessagePreset.RestartScheduled"/>.</param>
    public static string Body(UserMessagePreset preset, string? scheduledAt = null) => preset switch
    {
        UserMessagePreset.UpdatesInstalling =>
            "Windows updates are being installed on this computer. You can keep working, but it may be slower for a while.",
        UserMessagePreset.UpdatesInstalled =>
            "Windows updates were installed on this computer. No restart is needed.",
        UserMessagePreset.RestartRequired =>
            "Windows updates were installed and this computer needs to restart to finish. Please save your work and restart when you can.",
        UserMessagePreset.SaveYourWork =>
            "Your IT team is about to carry out maintenance on this computer. Please save your work and close your applications.",
        UserMessagePreset.MaintenanceTonight =>
            "Maintenance is scheduled for this computer tonight. Please save your work and leave the computer switched on when you finish for the day.",
        UserMessagePreset.RestartScheduled => scheduledAt is null
            ? "This computer will restart soon. Please save your work."
            : $"This computer will restart at {scheduledAt}. Please save your work before then.",
        _ => "",
    };
}
