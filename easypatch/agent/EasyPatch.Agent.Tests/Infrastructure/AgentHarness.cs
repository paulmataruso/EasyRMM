using EasyPatch.Agent.Core;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using Xunit;

namespace EasyPatch.Agent.Tests.Infrastructure;

/// <summary>
/// A complete agent wired to fakes: in-memory server, Windows Update double, manual clock and a temporary data
/// directory. <see cref="Restart"/> simulates a service restart (new runtime instance, same data directory).
/// </summary>
public sealed class AgentHarness : IDisposable
{
    public const string Token = "ept_test_token_0123456789abcdef";
    public const string DeploymentCode = "EP-DEPLOY-7Q4K";

    private readonly HttpClient _http;

    /// <param name="installedFromPackage">False for an agent that cannot remove itself (no <see cref="IAgentUninstaller"/>).</param>
    /// <param name="configurePlatform">Adds or replaces platform services.</param>
    public AgentHarness(Func<AgentRuntimeOptions, AgentRuntimeOptions>? configure = null, bool installedFromPackage = true,
        Func<AgentPlatform, AgentPlatform>? configurePlatform = null)
    {
        DataDirectory = Path.Combine(Path.GetTempPath(), "easypatch-agent-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(DataDirectory);
        Time = new ManualTimeProvider(new DateTimeOffset(2026, 11, 10, 2, 0, 0, TimeSpan.Zero));
        BootTime = new FakeBootTime(Time.GetUtcNow().AddHours(-3));
        Server = new FakeAgentServer(Time);
        Server.ValidTokens.Add(Token);
        Server.DeploymentCodes.Add(DeploymentCode);
        Bootstrap = new InMemoryBootstrap { ServerUrl = "https://easypatch.test" };
        _http = new HttpClient(Server, disposeHandler: false) { BaseAddress = FakeAgentServer.BaseAddress };

        var options = new AgentRuntimeOptions { DataDirectory = DataDirectory, AgentVersion = "1.0.0" };
        Options = configure?.Invoke(options) ?? options;
        Platform = new AgentPlatform(WindowsUpdate, Inventory, RebootDetector, new FakeUpdateSource(), Protector, Bootstrap, BootTime)
        {
            UserInteraction = Users,
            SystemRestart = SystemRestart,
            PolicyRegistry = PolicyRegistry,
            AgentInstaller = Installer,
            AgentUninstaller = installedFromPackage ? Uninstaller : null,
        };
        Platform = configurePlatform?.Invoke(Platform) ?? Platform;
        Runtime = CreateRuntime();
    }

    public string DataDirectory { get; }
    public ManualTimeProvider Time { get; }
    public FakeBootTime BootTime { get; }
    public FakeAgentServer Server { get; }
    public InMemoryBootstrap Bootstrap { get; }
    public FakeWindowsUpdate WindowsUpdate { get; } = new();
    public FakeInventory Inventory { get; } = new();
    public FakeRebootDetector RebootDetector { get; } = new();
    public TestSecretProtector Protector { get; } = new();
    public FakeUserInteraction Users { get; } = new();
    public FakeSystemRestart SystemRestart { get; } = new();
    public FakePolicyRegistry PolicyRegistry { get; } = new();
    public FakeAgentInstaller Installer { get; } = new();
    public FakeAgentUninstaller Uninstaller { get; } = new();
    public AgentRuntimeOptions Options { get; private set; }
    public AgentPlatform Platform { get; }
    public AgentRuntime Runtime { get; private set; }

    /// <summary>Simulates a service restart: the old runtime is disposed and a new one loads the persisted state.</summary>
    public AgentRuntime Restart()
    {
        Runtime.Dispose();
        Runtime = CreateRuntime();
        return Runtime;
    }

    /// <summary>Simulates Windows Installer replacing the service with <paramref name="agentVersion"/> (or putting the
    /// same version back) and starting it.</summary>
    public AgentRuntime RestartAs(string agentVersion)
    {
        Options = Options with { AgentVersion = agentVersion };
        return Restart();
    }

    /// <summary>Simulates a computer restart: boot time changes and pending-reboot updates complete.</summary>
    public AgentRuntime Reboot()
    {
        Time.Advance(TimeSpan.FromMinutes(10));
        BootTime.Boot = Time.GetUtcNow().AddMinutes(-2);
        WindowsUpdate.SimulateReboot();
        return Restart();
    }

    public async Task EnrollWithTokenAsync()
    {
        Bootstrap.EnrollmentToken = Token;
        var outcome = await Runtime.EnsureEnrolledAsync(TestContext.Current.CancellationToken);
        Assert.Equal(EnrollmentOutcome.Active, outcome);
    }

    /// <summary>Delivers a job through a real check-in (persist + acknowledge).</summary>
    public async Task DeliverAsync(AgentJob job)
    {
        Server.EnqueueJob(job);
        await Runtime.CheckInOnceAsync(TestContext.Current.CancellationToken);
        Assert.Contains(job.JobId, Server.Acks);
    }

    /// <summary>Executes every runnable job, then delivers all queued reports.</summary>
    public async Task RunJobsAndFlushAsync()
    {
        var ct = TestContext.Current.CancellationToken;
        while (await Runtime.ProcessNextJobAsync(ct))
        {
        }

        Assert.True(await Runtime.FlushOutboxAsync(ct));
    }

    public static AgentJob InstallJob(InstallFilterOptions? filter = null, InstallMode mode = InstallMode.AllEligible,
        IReadOnlyList<Guid>? selected = null, DateTimeOffset? notAfter = null, DateTimeOffset? expiresAt = null) => new()
    {
        JobId = Guid.NewGuid(),
        Type = JobType.InstallUpdates,
        Trigger = JobTrigger.Manual,
        CreatedAt = DateTimeOffset.UtcNow,
        ExpiresAt = expiresAt ?? new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
        Install = new InstallUpdatesPayload
        {
            Mode = mode,
            SelectedUpdateGuids = selected ?? [],
            NotAfter = notAfter,
            Filter = filter ?? DefaultFilter,
        },
    };

    public static InstallFilterOptions DefaultFilter { get; } = new()
    {
        Categories = [UpdateCategory.Security, UpdateCategory.Critical, UpdateCategory.Cumulative, UpdateCategory.ServicingStack, UpdateCategory.DotNet, UpdateCategory.Definition],
    };

    public static AgentJob RestartJob(RestartMode mode, int deadlineMinutes = 240, int countdownMinutes = 5,
        RestartCondition condition = RestartCondition.Always) => new()
    {
        JobId = Guid.NewGuid(),
        Type = JobType.Restart,
        Trigger = JobTrigger.Manual,
        ExpiresAt = new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
        Restart = new RestartPayload { Mode = mode, Condition = condition, DeadlineMinutes = deadlineMinutes, CountdownMinutes = countdownMinutes },
    };

    public static AgentJob MessageJob(UserMessagePreset preset, DateTimeOffset? scheduledAt = null, DateTimeOffset? expiresAt = null) => new()
    {
        JobId = Guid.NewGuid(),
        Type = JobType.NotifyUser,
        Trigger = JobTrigger.Manual,
        ExpiresAt = expiresAt ?? new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
        Notify = new NotifyUserPayload { Preset = preset, ScheduledAt = scheduledAt },
    };

    /// <summary>Advances the clock and runs one pass of the job loop (restart ticks, messages, runnable jobs), then flushes.</summary>
    public async Task TickAsync(TimeSpan? advance = null)
    {
        if (advance is { } by)
        {
            Time.Advance(by);
        }

        await RunJobsAndFlushAsync();
    }

    public static AgentJob SimpleJob(JobType type) => new()
    {
        JobId = Guid.NewGuid(),
        Type = type,
        Trigger = JobTrigger.Manual,
        ExpiresAt = new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
    };

    public FakeUpdate AddSecurityUpdate(string kb, bool requiresReboot = false) =>
        WindowsUpdate.Add($"Security Update for Microsoft Edge ({kb})", MicrosoftClassifications.SecurityUpdates, kb, requiresReboot: requiresReboot);

    public FakeUpdate AddCumulativeUpdate(string kb) =>
        WindowsUpdate.Add($"2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems ({kb})", MicrosoftClassifications.SecurityUpdates, kb, requiresReboot: true);

    public FakeUpdate AddServicingStackUpdate(string kb) =>
        WindowsUpdate.Add($"2026-11 Servicing Stack Update for Windows 11 ({kb})", MicrosoftClassifications.SecurityUpdates, kb);

    public void Dispose()
    {
        Runtime.Dispose();
        _http.Dispose();
        Server.Dispose();
        try
        {
            Directory.Delete(DataDirectory, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private AgentRuntime CreateRuntime() => new(Options, Platform, _http, loggerFactory: null, timeProvider: Time);
}
