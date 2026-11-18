using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Policy;
using EasyPatch.Contracts.Updates;

namespace EasyPatch.Agent.Tests.Infrastructure;

/// <summary>Deterministic, manually advanced clock.</summary>
public sealed class ManualTimeProvider(DateTimeOffset start) : TimeProvider
{
    private readonly Lock _lock = new();
    private DateTimeOffset _now = start;

    public override DateTimeOffset GetUtcNow()
    {
        lock (_lock)
        {
            return _now;
        }
    }

    public void Advance(TimeSpan by)
    {
        lock (_lock)
        {
            _now += by;
        }
    }
}

public sealed class FakeBootTime(DateTimeOffset boot) : IBootTimeProvider
{
    public DateTimeOffset Boot { get; set; } = boot;

    public DateTimeOffset GetLastBootTime() => Boot;
}

/// <summary>Reversible transform standing in for DPAPI, with a marker proving that stored keys went through it.</summary>
public sealed class TestSecretProtector : ISecretProtector
{
    public static readonly byte[] Marker = "TESTPROT"u8.ToArray();

    public int ProtectCalls { get; private set; }

    public byte[] Protect(byte[] plaintext)
    {
        ProtectCalls++;
        return [.. Marker, .. plaintext.Select(b => (byte)(b ^ 0x5A))];
    }

    public byte[] Unprotect(byte[] protectedData)
    {
        if (protectedData.Length < Marker.Length || !protectedData.AsSpan(0, Marker.Length).SequenceEqual(Marker))
        {
            throw new System.Security.Cryptography.CryptographicException("Not protected by TestSecretProtector.");
        }

        return protectedData.Skip(Marker.Length).Select(b => (byte)(b ^ 0x5A)).ToArray();
    }
}

public sealed class InMemoryBootstrap : IBootstrapConfigSource
{
    public string? ServerUrl { get; set; }
    public string? EnrollmentToken { get; set; }
    public string? DeploymentCode { get; set; }
    public int ClearCalls { get; private set; }

    public BootstrapConfig Read() => new(ServerUrl, EnrollmentToken, DeploymentCode, null);

    public void ClearEnrollmentSecrets()
    {
        ClearCalls++;
        EnrollmentToken = null;
        DeploymentCode = null;
    }
}

public sealed class FakeInventory : IInventoryCollector
{
    public int Calls { get; private set; }

    public Task<InventoryReport> CollectAsync(InventoryContext context, CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult(new InventoryReport
        {
            Hostname = "TEST-PC",
            DnsDomain = "corp.test",
            OsCaption = "Microsoft Windows 11 Pro",
            OsBuildNumber = 26100,
            OsUbr = 2605,
            SmbiosUuid = "4C4C4544-0000-0000-0000-000000000001",
            AgentVersion = context.AgentVersion,
        });
    }
}

public sealed class FakeRebootDetector : IRebootDetector
{
    public RebootStatus Status { get; set; } = RebootStatus.None;

    public Task<RebootStatus> DetectAsync(CancellationToken cancellationToken) => Task.FromResult(Status);
}

public sealed class FakeUpdateSource : IUpdateSourceDetector
{
    public UpdateSourceInfo Detect() => new() { Type = UpdateSourceType.WindowsUpdate, AutomaticUpdatesMode = "NotConfigured" };
}

/// <summary>One update known to <see cref="FakeWindowsUpdate"/>.</summary>
public sealed class FakeUpdate
{
    public required ReportedUpdate Metadata { get; init; }
    public bool Installed { get; set; }
    public bool PendingReboot { get; set; }
    public bool Downloaded { get; set; }
    public bool RequiresReboot { get; init; }
    public int? DownloadHResult { get; set; }
    public int? InstallHResult { get; set; }

    /// <summary>Percentages reported while the update downloads, as WUA's download job would.</summary>
    public IReadOnlyList<int> DownloadProgress { get; set; } = [];

    /// <summary>Percentages reported while the update installs.</summary>
    public IReadOnlyList<int> InstallProgress { get; set; } = [];

    public Guid Guid => Metadata.UpdateGuid;
}

/// <summary>
/// Test double for the Windows Update Agent with WUA's observable semantics: an installed update that needs a
/// restart keeps appearing in "IsInstalled=0" with RebootRequired=true until <see cref="SimulateReboot"/>.
/// </summary>
public sealed class FakeWindowsUpdate : IUpdateService
{
    private readonly Lock _lock = new();

    public List<FakeUpdate> Updates { get; } = [];

    public List<string> Operations { get; } = [];

    public List<HistoryEntryReport> History { get; } = [];

    public bool RebootRequiredBeforeInstallation { get; set; }

    public Exception? ScanException { get; set; }

    public int Scans { get; private set; }

    public int OpenHandles { get; private set; }

    /// <summary>Invoked before each install; may throw, cancel or change state.</summary>
    public Func<FakeUpdate, CancellationToken, Task>? BeforeInstall { get; set; }

    /// <summary>Invoked before each progress percentage is reported ("download" or "install"), e.g. to advance the clock.</summary>
    public Action<string, int>? BeforeProgress { get; set; }

    public FakeUpdate Add(string title, Guid? classification = null, string? kb = null, bool browseOnly = false, bool isDriver = false,
        bool requiresReboot = false, bool installed = false)
    {
        var update = new FakeUpdate
        {
            Metadata = new ReportedUpdate
            {
                UpdateGuid = Guid.NewGuid(),
                RevisionNumber = 200,
                Title = title,
                KbNumbers = kb is null ? [] : [kb],
                Categories = classification is { } id ? [new UpdateCategoryRef { Id = id, Name = MicrosoftClassifications.NameOf(id) ?? "x", Type = "UpdateClassification" }] : [],
                BrowseOnly = browseOnly,
                IsDriver = isDriver,
                RebootBehavior = requiresReboot ? 1 : 0,
            },
            RequiresReboot = requiresReboot,
            Installed = installed,
        };
        Updates.Add(update);
        return update;
    }

    public void SimulateReboot()
    {
        lock (_lock)
        {
            foreach (var update in Updates.Where(u => u.PendingReboot))
            {
                update.PendingReboot = false;
                update.Installed = true;
            }

            RebootRequiredBeforeInstallation = false;
        }
    }

    public int InstallCount(Guid guid) => Operations.Count(o => o == $"install:{guid}");

    public Task<UpdateScanResult> ScanAsync(bool includeInstalled, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_lock)
        {
            Scans++;
            if (ScanException is not null)
            {
                throw ScanException;
            }

            var missing = Updates.Where(u => !u.Installed)
                .Select(u => new UpdateCandidate(u.Metadata with { IsDownloaded = u.Downloaded, RebootRequired = u.PendingReboot }, new Handle(this, u)))
                .ToList();
            var installed = includeInstalled
                ? Updates.Where(u => u.Installed).Select(u => u.Metadata with { IsInstalled = true }).ToList()
                : [];
            return Task.FromResult(new UpdateScanResult(missing, installed, microsoftUpdateRegistered: false));
        }
    }

    public Task<bool> IsRebootRequiredBeforeInstallationAsync(CancellationToken cancellationToken) =>
        Task.FromResult(RebootRequiredBeforeInstallation);

    public Task<UpdateOperationResult> DownloadAsync(IUpdateHandle update, IProgress<int>? progress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var target = ((Handle)update).Update;
        Report("download", target.DownloadProgress, progress);
        lock (_lock)
        {
            Operations.Add($"download:{target.Guid}");
            if (target.DownloadHResult is { } hr)
            {
                return Task.FromResult(new UpdateOperationResult(UpdateOperationResult.Failed, hr, false));
            }

            target.Downloaded = true;
            return Task.FromResult(new UpdateOperationResult(UpdateOperationResult.Succeeded, 0, false));
        }
    }

    public async Task<UpdateOperationResult> InstallAsync(IUpdateHandle update, bool acceptEula, IProgress<int>? progress, CancellationToken cancellationToken)
    {
        var target = ((Handle)update).Update;
        if (BeforeInstall is not null)
        {
            await BeforeInstall(target, cancellationToken);
        }

        cancellationToken.ThrowIfCancellationRequested();
        Report("install", target.InstallProgress, progress);
        lock (_lock)
        {
            Operations.Add($"install:{target.Guid}");
            if (target.InstallHResult is { } hr)
            {
                History.Add(Entry(target, OperationResultCode: 4, hr));
                return new UpdateOperationResult(UpdateOperationResult.Failed, hr, false);
            }

            if (target.RequiresReboot)
            {
                target.PendingReboot = true;
            }
            else
            {
                target.Installed = true;
            }

            History.Add(Entry(target, OperationResultCode: 2, 0));
            return new UpdateOperationResult(UpdateOperationResult.Succeeded, 0, target.RequiresReboot);
        }
    }

    private void Report(string operation, IReadOnlyList<int> percentages, IProgress<int>? progress)
    {
        foreach (var percent in percentages)
        {
            BeforeProgress?.Invoke(operation, percent);
            progress?.Report(percent);
        }
    }

    public Task<IReadOnlyList<HistoryEntryReport>> GetHistoryAsync(DateTimeOffset? since, int maxEntries, CancellationToken cancellationToken)
    {
        lock (_lock)
        {
            IReadOnlyList<HistoryEntryReport> entries = History.Where(h => since is null || h.Date > since).Take(maxEntries).ToList();
            return Task.FromResult(entries);
        }
    }

    private static HistoryEntryReport Entry(FakeUpdate update, int OperationResultCode, int hresult) => new()
    {
        UpdateGuid = update.Guid,
        RevisionNumber = update.Metadata.RevisionNumber,
        Title = update.Metadata.Title,
        KbNumber = update.Metadata.KbNumbers.Count > 0 ? update.Metadata.KbNumbers[0] : null,
        Operation = "Installation",
        ResultCode = OperationResultCode,
        HResult = hresult == 0 ? null : WindowsUpdateErrors.Format(hresult),
        Date = DateTimeOffset.UtcNow,
        ClientApplicationId = "EasyPatch Agent",
    };

    private sealed class Handle : IUpdateHandle
    {
        private readonly FakeWindowsUpdate _owner;
        private bool _disposed;

        public Handle(FakeWindowsUpdate owner, FakeUpdate update)
        {
            _owner = owner;
            Update = update;
            _owner.OpenHandles++;
        }

        public FakeUpdate Update { get; }

        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                _owner.OpenHandles--;
            }
        }
    }
}

/// <summary>Signed-in users and their trays. Answers are queued with <see cref="Answer"/>.</summary>
public sealed class FakeUserInteraction : IUserInteraction
{
    private readonly List<RestartPromptResponse> _responses = [];

    public int SignedInUsers { get; set; } = 1;
    public int TrayConnected { get; set; } = 1;
    public List<UserNotice> Notices { get; } = [];

    /// <summary>Every prompt published, in order (null = removed).</summary>
    public List<RestartPrompt?> Prompts { get; } = [];

    public RestartPrompt? CurrentPrompt => Prompts.Count == 0 ? null : Prompts[^1];
    public TrayStatus? Status { get; private set; }

    public UserSessionInfo GetSessions() => new() { SignedInUsers = SignedInUsers, TrayConnected = TrayConnected };

    public int Notify(UserNotice notice)
    {
        if (TrayConnected > 0)
        {
            Notices.Add(notice);
        }

        return TrayConnected;
    }

    public void SetRestartPrompt(RestartPrompt? prompt) => Prompts.Add(prompt);

    public IReadOnlyList<RestartPromptResponse> TakeResponses()
    {
        var list = _responses.ToList();
        _responses.Clear();
        return list;
    }

    public void SetStatus(TrayStatus status) => Status = status;

    public bool TraysSuspended { get; private set; }

    /// <summary>How many trays were connected when they were asked to exit.</summary>
    public int ClosedTrays { get; private set; }

    public void SuspendTrays(bool suspended)
    {
        TraysSuspended = suspended;
        if (suspended)
        {
            ClosedTrays = TrayConnected;
            TrayConnected = 0;
        }
    }

    public void Answer(Guid jobId, bool restartNow, int? postponeMinutes = null) =>
        _responses.Add(new RestartPromptResponse(jobId, restartNow, postponeMinutes, SessionId: 1));
}

public sealed class FakeSystemRestart : ISystemRestart
{
    /// <summary>Grace period of every restart requested.</summary>
    public List<TimeSpan> Requests { get; } = [];
    public Exception? Failure { get; set; }
    public bool AbortSucceeds { get; set; } = true;
    public int Aborts { get; private set; }

    public void Restart(TimeSpan gracePeriod, string message)
    {
        if (Failure is not null)
        {
            throw Failure;
        }

        Requests.Add(gracePeriod);
    }

    public bool TryAbort()
    {
        Aborts++;
        return AbortSucceeds;
    }
}

/// <summary>The two Windows Update policy keys, in memory.</summary>
public sealed class FakePolicyRegistry : IPolicyRegistry
{
    private readonly Dictionary<(PolicyRegistryKey, string), PolicyRegistryValue> _values = [];

    public List<string> Writes { get; } = [];
    public Exception? Failure { get; set; }
    public bool Mdm { get; set; }

    public PolicyRegistryValue Read(PolicyRegistryKey key, string name)
    {
        if (Failure is not null)
        {
            throw Failure;
        }

        return _values.TryGetValue((key, name.ToUpperInvariant()), out var v) ? v : new PolicyRegistryValue(key, name);
    }

    public void Write(PolicyRegistryValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (Failure is not null)
        {
            throw Failure;
        }

        Writes.Add($"{value.Name}={value.Display}");
        Set(value);
    }

    public bool MdmUpdatePoliciesPresent() => Mdm;

    /// <summary>Changes a value behind EasyPatch's back (another policy source).</summary>
    public void Set(PolicyRegistryValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.IsAbsent)
        {
            _values.Remove((value.Key, value.Name.ToUpperInvariant()));
        }
        else
        {
            _values[(value.Key, value.Name.ToUpperInvariant())] = value;
        }
    }

    public int? DWord(PolicyRegistryKey key, string name) => Read(key, name).DWord;

    public int Count => _values.Count;
}

/// <summary>
/// Stands in for msiexec. By default it behaves like a real upgrade: starting it "stops the service" (cancels
/// <see cref="ServiceStopping"/>) and it never exits while the old agent is alive. Set <see cref="ExitCode"/> to make it
/// return while the old agent is still running instead.
/// </summary>
public sealed class FakeAgentInstaller : IAgentInstaller
{
    public List<(string PackagePath, string LogPath, byte[] Package)> Started { get; } = [];

    /// <summary>Cancelled when the installer starts, like Windows Installer stopping the agent service.</summary>
    public CancellationTokenSource? ServiceStopping { get; set; }

    /// <summary>When set, msiexec exits with this code without replacing the agent.</summary>
    public int? ExitCode { get; set; }

    /// <summary>Text written to the installer log when it starts.</summary>
    public string? LogText { get; set; }

    /// <summary>Number of <see cref="IsInstallerBusy"/> calls that return true before it reports idle.</summary>
    public int BusyChecks { get; set; }

    /// <summary>Called on every busy check (e.g. to advance the clock).</summary>
    public Action? OnBusyCheck { get; set; }

    public Exception? StartFailure { get; set; }

    public IInstallerProcess Start(string packagePath, string logPath)
    {
        if (StartFailure is not null)
        {
            throw StartFailure;
        }

        Started.Add((packagePath, logPath, File.ReadAllBytes(packagePath)));
        if (LogText is not null)
        {
            File.WriteAllText(logPath, LogText, System.Text.Encoding.Unicode);
        }

        if (ExitCode is null)
        {
            ServiceStopping?.Cancel();
        }

        return new Process(ExitCode);
    }

    public bool IsInstallerBusy()
    {
        OnBusyCheck?.Invoke();
        if (BusyChecks > 0)
        {
            BusyChecks--;
            return true;
        }

        return false;
    }

    private sealed class Process(int? exitCode) : IInstallerProcess
    {
        public async Task<int> WaitForExitAsync(CancellationToken cancellationToken)
        {
            if (exitCode is { } code)
            {
                return code;
            }

            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public void Dispose()
        {
        }
    }
}

/// <summary>
/// Stands in for <c>msiexec /x</c> (or apt-get remove). By default it behaves like a real removal: starting it "stops the
/// service" (cancels <see cref="ServiceStopping"/>) and it never exits while the agent is alive. Set <see cref="ExitCode"/>
/// to make it return while the agent is still running instead.
/// </summary>
public sealed class FakeAgentUninstaller : IAgentUninstaller
{
    public List<string> Started { get; } = [];

    public CancellationTokenSource? ServiceStopping { get; set; }

    public int? ExitCode { get; set; }

    /// <summary>What <see cref="ReadResult"/> returns (the result of a removal started by an earlier process).</summary>
    public int? Result { get; set; }

    public int BusyChecks { get; set; }

    /// <summary>False until the product is registered (Windows Installer starts the service before it registers the product).</summary>
    public bool IsAvailable { get; set; } = true;

    public string DisplayName => "Windows Installer";

    public IInstallerProcess Start(string logPath)
    {
        Started.Add(logPath);
        if (ExitCode is null)
        {
            ServiceStopping?.Cancel();
        }

        return new Process(ExitCode);
    }

    public bool IsInstallerBusy()
    {
        if (BusyChecks > 0)
        {
            BusyChecks--;
            return true;
        }

        return false;
    }

    public int? ReadResult(string logPath) => Result;

    public string DescribeResult(int code) => code == 1603 ? " (a fatal error occurred during installation)" : string.Empty;

    private sealed class Process(int? exitCode) : IInstallerProcess
    {
        public async Task<int> WaitForExitAsync(CancellationToken cancellationToken)
        {
            if (exitCode is { } code)
            {
                return code;
            }

            await Task.Delay(Timeout.Infinite, cancellationToken);
            return 0;
        }

        public void Dispose()
        {
        }
    }
}
