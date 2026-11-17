namespace EasyPatch.Contracts;

/// <summary>Normalized update category. Cumulative, ServicingStack and DotNet are derived from titles/products;
/// the others map to Microsoft update classifications.</summary>
public enum UpdateCategory
{
    Security,
    Critical,
    Cumulative,
    Definition,
    ServicingStack,
    DotNet,
    Feature,
    Driver,
    Other,

    /// <summary>A newer version of a third-party application (winget, agent 1.4.0 and later). Never part of
    /// <see cref="Agent.InstallFilterOptions.Categories"/>: application updates are governed by the approved application list.</summary>
    Application,
}

public enum JobType
{
    UpdateScan,
    InstallUpdates,
    InventoryRefresh,
    /// <summary>Restart the computer (always an explicit administrator action or administrator-configured schedule).</summary>
    Restart,
    /// <summary>Show a preset message to the signed-in users. Never executes anything.</summary>
    NotifyUser,

    /// <summary>Install a newer EasyPatch agent MSI. The agent installs it only when its release signature verifies
    /// against a release key built into the agent.</summary>
    AgentUpdate,

    /// <summary>Remove the EasyPatch agent from the endpoint (Windows Installer, apt or rpm removal of the agent package only).
    /// The agent unenrolls as part of the removal; the server completes the job when that unenrollment arrives.</summary>
    UninstallAgent,

    /// <summary>Remove one installed Windows update (Windows agent 1.8.0 and later): Windows Update's own uninstall when the
    /// update supports it, otherwise DISM's <c>/Remove-Package</c> for the update's servicing package. Never runs anything
    /// else and never restarts the computer.</summary>
    UninstallUpdate,

    /// <summary>Download updates ahead of a maintenance window without installing them (Windows agent 1.8.0 and later), so the
    /// installation inside the window starts with the downloads done. Uses the install payload; <c>NotAfter</c> is the start of
    /// the window.</summary>
    DownloadUpdates,
}

/// <summary>How a <see cref="JobType.Restart"/> job treats signed-in users. With nobody signed in, every mode restarts at once.</summary>
public enum RestartMode
{
    /// <summary>Restart straight away.</summary>
    Immediate,
    /// <summary>Show a countdown, then restart. Users can restart sooner but cannot postpone.</summary>
    Countdown,
    /// <summary>Ask the user, who may postpone until a deadline; then a short final countdown and restart.</summary>
    PromptWithDeadline,
    /// <summary>Ask the user and keep reminding; while someone is signed in, restart only when a user accepts.</summary>
    PromptNoDeadline,
}

public enum RestartCondition
{
    Always,
    /// <summary>Only restart when Windows reports a pending restart when the job runs.</summary>
    OnlyIfPending,
}

/// <summary>The only messages EasyPatch can show to users. There is deliberately no free-text message.</summary>
public enum UserMessagePreset
{
    UpdatesInstalling,
    UpdatesInstalled,
    RestartRequired,
    SaveYourWork,
    MaintenanceTonight,
    RestartScheduled,
}

public enum JobStatus
{
    Queued,
    Delivered,
    Acknowledged,
    Running,
    Completed,
    Failed,
    Cancelled,
    Expired,
    WaitingForReboot,
}

public enum JobTrigger
{
    /// <summary>Requested by an administrator.</summary>
    Manual,
    /// <summary>Created by a policy maintenance window.</summary>
    Scheduled,
    /// <summary>Created by the platform itself (e.g. retry).</summary>
    System,
}

public enum JobItemStatus
{
    Pending,
    Downloading,
    Downloaded,
    Installing,
    Succeeded,
    Failed,
    Skipped,
    Cancelled,
}

public enum InstallMode
{
    /// <summary>Install every update the policy filter allows.</summary>
    AllEligible,
    /// <summary>Install only the explicitly selected update GUIDs.</summary>
    Selected,
}

public enum ScanTrigger
{
    Scheduled,
    Startup,
    Job,
    PostInstall,
    PostReboot,

    /// <summary>A signed-in user chose <i>Check for updates</i> in the EasyPatch status window (Windows agent 1.5.0 and later).</summary>
    User,
}

public enum UpdateSourceType
{
    Unknown,
    WindowsUpdate,
    MicrosoftUpdate,
    Wsus,

    /// <summary>Linux: the repositories configured for apt or dnf.</summary>
    PackageRepositories,

    /// <summary>macOS: Apple's software update service, through <c>softwareupdate</c> (experimental macOS agent).</summary>
    AppleSoftwareUpdate,
}

public enum EnrollmentState
{
    Active,
    PendingApproval,
    Rejected,
    Expired,
}

public static class JobStatusExtensions
{
    public static bool IsTerminal(this JobStatus status) =>
        status is JobStatus.Completed or JobStatus.Failed or JobStatus.Cancelled or JobStatus.Expired;

    /// <summary>Statuses in which the job is held by (or on its way to) the agent.</summary>
    public static bool IsInFlight(this JobStatus status) =>
        status is JobStatus.Delivered or JobStatus.Acknowledged or JobStatus.Running or JobStatus.WaitingForReboot;
}
