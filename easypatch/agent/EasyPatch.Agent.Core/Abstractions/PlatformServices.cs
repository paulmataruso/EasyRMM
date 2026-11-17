using EasyPatch.Agent.Core.Applications;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;

namespace EasyPatch.Agent.Core.Abstractions;

// Platform abstractions. Production implementations live in EasyPatch.WindowsUpdate, EasyPatch.Inventory and
// EasyPatch.Agent (Windows), in EasyPatch.Linux and in EasyPatch.MacOS. Test doubles live exclusively in test projects.

/// <summary>Opaque reference to an update (a WUA update object, or a Linux package upgrade), valid until disposed.</summary>
public interface IUpdateHandle : IDisposable
{
}

/// <summary>A missing update returned by a scan, plus the handle needed to download/install it.</summary>
public sealed class UpdateCandidate
{
    public UpdateCandidate(ReportedUpdate update, IUpdateHandle handle)
    {
        ArgumentNullException.ThrowIfNull(update);
        ArgumentNullException.ThrowIfNull(handle);
        Update = update;
        Handle = handle;
    }

    public ReportedUpdate Update { get; }

    public IUpdateHandle Handle { get; }
}

/// <summary>Result of an update search. Disposing releases the underlying objects (COM objects on Windows).</summary>
public sealed class UpdateScanResult : IDisposable
{
    public UpdateScanResult(
        IReadOnlyList<UpdateCandidate> missing,
        IReadOnlyList<ReportedUpdate> installed,
        bool microsoftUpdateRegistered)
    {
        Missing = missing ?? throw new ArgumentNullException(nameof(missing));
        Installed = installed ?? throw new ArgumentNullException(nameof(installed));
        MicrosoftUpdateRegistered = microsoftUpdateRegistered;
    }

    /// <summary>"IsInstalled=0 and IsHidden=0" (includes installed-pending-reboot updates flagged RebootRequired).</summary>
    public IReadOnlyList<UpdateCandidate> Missing { get; }

    /// <summary>"IsInstalled=1" (empty when the caller did not request installed updates).</summary>
    public IReadOnlyList<ReportedUpdate> Installed { get; }

    public bool MicrosoftUpdateRegistered { get; }

    /// <summary>Outcome of the application (winget) part; null when application updates are off.</summary>
    public ApplicationScanReport? Applications { get; init; }

    public void Dispose()
    {
        foreach (var candidate in Missing)
        {
            candidate.Handle.Dispose();
        }
    }
}

/// <summary>Outcome of a single download or install.</summary>
/// <param name="ResultCode">WUA OperationResultCode (2 Succeeded, 3 SucceededWithErrors, 4 Failed, 5 Aborted); Linux uses the same values.</param>
/// <param name="HResult">HRESULT reported by WUA (0 on success; 0 on Linux).</param>
/// <param name="RebootRequired">True when the update needs a restart to complete.</param>
public sealed record UpdateOperationResult(int ResultCode, int HResult, bool RebootRequired)
{
    /// <summary>Short machine-readable error (Linux, e.g. <c>apt_failed</c>); null means "format <see cref="HResult"/>".</summary>
    public string? ErrorCode { get; init; }

    /// <summary>Human-readable explanation of a failure (Linux: the package manager's error output).</summary>
    public string? Message { get; init; }

    public const int NotStarted = 0;
    public const int InProgress = 1;
    public const int Succeeded = 2;
    public const int SucceededWithErrors = 3;
    public const int Failed = 4;
    public const int Aborted = 5;

    public bool IsSuccess => ResultCode is Succeeded or SucceededWithErrors;
}

/// <summary>Failure raised by the Windows Update integration, carrying the WUA/COM HRESULT.</summary>
public sealed class WindowsUpdateException : Exception
{
    public WindowsUpdateException()
    {
    }

    public WindowsUpdateException(string message)
        : base(message)
    {
    }

    public WindowsUpdateException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public WindowsUpdateException(string message, int hresult, Exception? innerException = null)
        : base(message, innerException)
    {
        HResult = hresult;
    }
}

/// <summary>The operating system's update mechanism (Windows Update; apt or dnf on Linux; softwareupdate on macOS). Implementations must never report
/// success they did not observe.</summary>
public interface IUpdateService
{
    /// <summary>Name used in messages, e.g. "Windows Update", "apt", "dnf", "softwareupdate".</summary>
    string Name => "Windows Update";

    /// <summary>Updates can be downloaded ahead of a maintenance window and kept for the installation (Windows Update). Only
    /// then does the agent advertise <see cref="AgentCapabilities.DownloadUpdates"/>.</summary>
    bool KeepsDownloads => true;

    /// <summary>Error code and message for a failed scan.</summary>
    (string Code, string Message) DescribeFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return (WindowsUpdateErrors.Format(exception.HResult), $"{WindowsUpdateErrors.Describe(exception.HResult)} {exception.Message}".Trim());
    }

    /// <summary>Searches for applicable, non-hidden, non-installed updates (and installed updates when requested).</summary>
    Task<UpdateScanResult> ScanAsync(bool includeInstalled, CancellationToken cancellationToken);

    /// <summary>True when Windows refuses further installs until the computer restarts.</summary>
    Task<bool> IsRebootRequiredBeforeInstallationAsync(CancellationToken cancellationToken);

    /// <param name="progress">Receives the percentage downloaded (0-100) when the update source reports one.</param>
    Task<UpdateOperationResult> DownloadAsync(IUpdateHandle update, IProgress<int>? progress, CancellationToken cancellationToken);

    /// <param name="acceptEula">Accept the update's license agreement if it has not been accepted yet.</param>
    /// <param name="progress">Receives the percentage installed (0-100) when the update source reports one.</param>
    Task<UpdateOperationResult> InstallAsync(IUpdateHandle update, bool acceptEula, IProgress<int>? progress, CancellationToken cancellationToken);

    /// <summary>Windows Update history newer than <paramref name="since"/> (newest first), at most <paramref name="maxEntries"/>.</summary>
    Task<IReadOnlyList<HistoryEntryReport>> GetHistoryAsync(DateTimeOffset? since, int maxEntries, CancellationToken cancellationToken);
}

/// <summary>An application update found by <see cref="IApplicationUpdateService"/>.</summary>
public sealed class ApplicationUpdateHandle(string id, string version, string? installedVersion) : IUpdateHandle
{
    public string Id { get; } = id;

    public string Version { get; } = version;

    public string? InstalledVersion { get; } = installedVersion;

    public void Dispose()
    {
    }
}

/// <summary>Result of an application update check.</summary>
public sealed record ApplicationScanResult(IReadOnlyList<UpdateCandidate> Missing, IReadOnlyList<ReportedUpdate> Installed, ApplicationScanReport Report);

/// <summary>Third-party application updates (winget). Implementations upgrade applications that are already installed, to the
/// version a scan found, and report success only when a new check shows that version installed.</summary>
public interface IApplicationUpdateService
{
    /// <summary>Checks the approved applications (winget package IDs, already validated) for newer versions.</summary>
    Task<ApplicationScanResult> ScanAsync(IReadOnlyList<string> approvedIds, CancellationToken cancellationToken);

    Task<UpdateOperationResult> InstallAsync(ApplicationUpdateHandle update, CancellationToken cancellationToken);
}

/// <summary>Progress of a batch installation: how many of the updates the package manager has finished.</summary>
public sealed record BatchInstallProgress(int Completed, int Total, string? Current);

/// <summary>
/// Implemented by update services whose package manager installs a set of updates in one transaction (apt, dnf), which is
/// faster and resolves dependencies between the updates. Results are per update, in the order given, and success means
/// the new version was confirmed installed afterwards.
/// </summary>
public interface IBatchUpdateService
{
    Task<IReadOnlyList<UpdateOperationResult>> DownloadAsync(IReadOnlyList<IUpdateHandle> updates, CancellationToken cancellationToken);

    Task<IReadOnlyList<UpdateOperationResult>> InstallAsync(
        IReadOnlyList<IUpdateHandle> updates, IProgress<BatchInstallProgress>? progress, CancellationToken cancellationToken);
}

/// <summary>Counts signed-in users where there is no tray to talk to them (Linux): restarts then warn through the
/// operating system's own shutdown messages instead of restarting at once.</summary>
public interface IUserSessionCounter
{
    UserSessionInfo GetSessions();
}

/// <summary>Context passed to the inventory collector.</summary>
public sealed record InventoryContext(string AgentVersion, DateTimeOffset? AgentInstalledAt);

public interface IInventoryCollector
{
    Task<InventoryReport> CollectAsync(InventoryContext context, CancellationToken cancellationToken);
}

/// <param name="Details">What Windows has queued for the restart, when the detector can tell (registry detector).</param>
public sealed record RebootStatus(bool Pending, IReadOnlyList<string> Reasons, RebootDetails? Details = null)
{
    public static RebootStatus None { get; } = new(false, []);
}

public interface IRebootDetector
{
    Task<RebootStatus> DetectAsync(CancellationToken cancellationToken);
}

public interface IUpdateSourceDetector
{
    /// <summary>Reports the configured update source and policies. Never modifies configuration.</summary>
    UpdateSourceInfo Detect();
}

/// <summary>Protects secrets at rest (DPAPI LocalMachine on Windows).</summary>
public interface ISecretProtector
{
    /// <summary>Reported in inventory: <c>dpapi</c>, <c>systemd-creds-host</c> or <c>file-permissions</c>.</summary>
    string Kind => "dpapi";

    byte[] Protect(byte[] plaintext);

    byte[] Unprotect(byte[] protectedData);
}

/// <summary>Installer-provided bootstrap values (HKLM\SOFTWARE\EasyPatch\Agent on Windows, /etc/easypatch/agent.conf on Linux).</summary>
/// <param name="ServerCaCertificate">Optional certificate authority (base64 DER) trusted for the connection to the server
/// only; see <see cref="Security.ServerCertificateAuthority"/>.</param>
public sealed record BootstrapConfig(string? ServerUrl, string? EnrollmentToken, string? DeploymentCode, string? ProxyUrl,
    string? ServerCaCertificate = null)
{
    public static BootstrapConfig Empty { get; } = new(null, null, null, null);

    public bool HasEnrollmentCredential =>
        !string.IsNullOrWhiteSpace(EnrollmentToken) || !string.IsNullOrWhiteSpace(DeploymentCode);
}

public interface IBootstrapConfigSource
{
    BootstrapConfig Read();

    /// <summary>Removes the enrollment token and deployment code once they have been used.</summary>
    void ClearEnrollmentSecrets();

    /// <summary>How an administrator provides the settings (logged when they are missing).</summary>
    string SetupHint => "Reinstall with SERVERURL and ENROLLMENTTOKEN or DEPLOYMENTCODE, or run 'EasyPatch.Agent.exe enroll'.";
}

public interface IBootTimeProvider
{
    DateTimeOffset GetLastBootTime();
}

/// <summary>Boot time derived from the monotonic tick counter (cross-platform, no WMI required).</summary>
public sealed class TickCountBootTimeProvider : IBootTimeProvider
{
    private readonly TimeProvider _timeProvider;

    public TickCountBootTimeProvider(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public DateTimeOffset GetLastBootTime()
    {
        var boot = _timeProvider.GetUtcNow() - TimeSpan.FromMilliseconds(Environment.TickCount64);
        // Round to whole seconds so repeated calls produce a stable value.
        return new DateTimeOffset(boot.Ticks - (boot.Ticks % TimeSpan.TicksPerSecond), TimeSpan.Zero);
    }
}

/// <summary>Creates the HTTP client used to talk to the server (TLS validation, proxy and timeouts are its concern).</summary>
public interface IAgentHttpClientFactory
{
    HttpClient Create(Uri serverUrl);
}

/// <summary>Always returns the same pre-configured client (tests and integration scenarios).</summary>
public sealed class FixedHttpClientFactory : IAgentHttpClientFactory
{
    private readonly HttpClient _client;

    public FixedHttpClientFactory(HttpClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    public HttpClient Create(Uri serverUrl) => _client;
}

/// <summary>Bundle of the platform services an <see cref="Runtime.AgentRuntime"/> needs.</summary>
/// <remarks>The optional services enable the matching <see cref="AgentCapabilities"/>; without them the agent only
/// scans, installs and reports, exactly like an agent built before they existed.</remarks>
public sealed record AgentPlatform(
    IUpdateService Updates,
    IInventoryCollector Inventory,
    IRebootDetector RebootDetector,
    IUpdateSourceDetector UpdateSource,
    ISecretProtector SecretProtector,
    IBootstrapConfigSource Bootstrap,
    IBootTimeProvider BootTime)
{
    /// <summary>The EasyPatch tray in each signed-in session (messages and restart prompts).</summary>
    public IUserInteraction? UserInteraction { get; init; }

    /// <summary>Restarts for administrator restart jobs.</summary>
    public ISystemRestart? SystemRestart { get; init; }

    /// <summary>Windows Update policy overrides.</summary>
    public IPolicyRegistry? PolicyRegistry { get; init; }

    /// <summary>Installs agent updates (the self-update capability also needs a release key; see
    /// <see cref="AgentRuntimeOptions.ReleasePublicKeys"/>).</summary>
    public IAgentInstaller? AgentInstaller { get; init; }

    /// <summary>Removes the agent for an administrator's uninstall job.</summary>
    public IAgentUninstaller? AgentUninstaller { get; init; }

    /// <summary>Signed-in users on a platform without a tray (Linux). Ignored when <see cref="UserInteraction"/> is set.</summary>
    public IUserSessionCounter? SessionCounter { get; init; }

    /// <summary>Third-party application updates (winget on Windows). Used only while the server's policy enables them.</summary>
    public IApplicationUpdateService? ApplicationUpdates { get; init; }

    /// <summary>Installs winget for all users when the computer has none (Windows); needs <see cref="WingetRunner"/>.</summary>
    public IWingetProvisioner? WingetProvisioner { get; init; }

    /// <summary>Finds and runs the machine-wide winget.</summary>
    public IWingetRunner? WingetRunner { get; init; }

    /// <summary>Removes installed updates for administrators' uninstall-update jobs (Windows).</summary>
    public Removal.IUpdateRemover? UpdateRemover { get; init; }

    public IUserInteraction Users => UserInteraction ?? (SessionCounter is { } counter ? new SessionsOnlyInteraction(counter) : NoUserInteraction.Instance);

    /// <summary>The update service downloads updates one by one without installing them (Windows Update keeps the downloads for
    /// the installation); apt and dnf work in transactions and do not.</summary>
    public bool SupportsDownloadOnly => Updates is not IBatchUpdateService && Updates.KeepsDownloads;

    public IReadOnlyList<string> Capabilities
    {
        get
        {
            var list = new List<string>();
            if (SystemRestart is not null)
            {
                list.Add(AgentCapabilities.Restart);
            }

            if (UserInteraction is not null)
            {
                list.Add(AgentCapabilities.NotifyUser);
                list.Add(AgentCapabilities.Tray);
            }

            if (PolicyRegistry is not null)
            {
                list.Add(AgentCapabilities.WindowsUpdatePolicy);
            }

            if (ApplicationUpdates is not null)
            {
                list.Add(AgentCapabilities.ApplicationUpdates);
            }

            if (AgentUninstaller?.IsAvailable == true)
            {
                list.Add(AgentCapabilities.Uninstall);
            }

            if (UpdateRemover is not null)
            {
                list.Add(AgentCapabilities.UninstallUpdates);
            }

            if (SupportsDownloadOnly)
            {
                list.Add(AgentCapabilities.DownloadUpdates);
            }

            return list;
        }
    }
}

/// <summary>No tray: reports the signed-in users (so restarts warn them through the operating system) and nothing else.</summary>
internal sealed class SessionsOnlyInteraction(IUserSessionCounter counter) : IUserInteraction
{
    public UserSessionInfo GetSessions() => counter.GetSessions() with { TrayConnected = 0 };

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
