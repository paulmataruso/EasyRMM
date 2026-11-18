using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Policy;
using Xunit;

namespace EasyPatch.Agent.Tests;

/// <summary>Windows Update policy overrides: apply, report, conflicts with other policy sources, and restore.</summary>
public sealed class WindowsUpdatePolicyTests
{
    private const PolicyRegistryKey Au = PolicyRegistryKey.AutomaticUpdates;
    private const PolicyRegistryKey Wu = PolicyRegistryKey.WindowsUpdate;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static AgentConfig Config(WindowsUpdatePolicySettings? settings) => new() { WindowsUpdate = settings };

    private static WindowsUpdatePolicySettings ScheduledInstall { get; } = new()
    {
        AutomaticUpdates = new AutomaticUpdatesSettings { Mode = AutoUpdateMode.AutoDownloadScheduleInstall, ScheduledInstallDay = 0, ScheduledInstallHour = 3 },
    };

    private static WindowsUpdatePolicySettings DeferQuality(int days) => new()
    {
        QualityUpdates = new QualityUpdateSettings { DeferDays = days, DisablePause = true },
    };

    private static WindowsUpdatePolicyGroupStatus Group(CheckInRequest checkIn, WindowsUpdatePolicyGroup group) =>
        checkIn.WindowsUpdatePolicy!.Groups.Single(g => g.Group == group);

    [Fact]
    public async Task Nothing_is_written_until_an_administrator_configures_a_group()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.PolicyRegistry.Set(new PolicyRegistryValue(Au, "AUOptions", 2));

        await h.Runtime.CheckInOnceAsync(Ct);
        await h.Runtime.CheckInOnceAsync(Ct);

        Assert.Empty(h.PolicyRegistry.Writes);
        var report = h.Server.CheckIns[0].WindowsUpdatePolicy!;
        Assert.All(report.Groups, g => Assert.Equal(WindowsUpdatePolicyState.NotManaged, g.State));
        Assert.Null(h.Server.CheckIns[1].WindowsUpdatePolicy); // unchanged reports are not re-sent
    }

    [Fact]
    public async Task Settings_are_applied_reported_and_the_original_values_restored_when_no_longer_managed()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.PolicyRegistry.Set(new PolicyRegistryValue(Au, "AUOptions", 2));
        h.PolicyRegistry.Set(new PolicyRegistryValue(Au, "ScheduledInstallTime", 22));
        h.PolicyRegistry.Set(new PolicyRegistryValue(Wu, "WUServer", Text: "https://wsus.example.test:8531"));
        h.PolicyRegistry.Set(new PolicyRegistryValue(Au, "UseWUServer", 1));

        h.Server.Config = Config(ScheduledInstall);
        await h.Runtime.CheckInOnceAsync(Ct);

        Assert.Equal(0, h.PolicyRegistry.DWord(Au, "NoAutoUpdate"));
        Assert.Equal(4, h.PolicyRegistry.DWord(Au, "AUOptions"));
        Assert.Equal(0, h.PolicyRegistry.DWord(Au, "ScheduledInstallDay"));
        Assert.Equal(3, h.PolicyRegistry.DWord(Au, "ScheduledInstallTime"));
        Assert.Null(h.PolicyRegistry.DWord(Wu, "DeferQualityUpdates")); // other groups untouched

        await h.Runtime.CheckInOnceAsync(Ct);
        var applied = Group(h.Server.CheckIns[^1], WindowsUpdatePolicyGroup.AutomaticUpdates);
        Assert.Equal(WindowsUpdatePolicyState.Applied, applied.State);
        Assert.Equal(h.Time.GetUtcNow(), applied.AppliedAt);
        Assert.Equal(WindowsUpdatePolicyState.NotManaged, Group(h.Server.CheckIns[^1], WindowsUpdatePolicyGroup.QualityUpdates).State);

        var writes = h.PolicyRegistry.Writes.Count;
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Equal(writes, h.PolicyRegistry.Writes.Count); // nothing rewritten while it holds

        h.Server.Config = Config(null);
        await h.Runtime.CheckInOnceAsync(Ct);

        Assert.Equal(2, h.PolicyRegistry.DWord(Au, "AUOptions"));
        Assert.Equal(22, h.PolicyRegistry.DWord(Au, "ScheduledInstallTime"));
        Assert.Null(h.PolicyRegistry.DWord(Au, "NoAutoUpdate"));
        Assert.Null(h.PolicyRegistry.DWord(Au, "ScheduledInstallDay"));
        Assert.Equal("https://wsus.example.test:8531", h.PolicyRegistry.Read(Wu, "WUServer").Text);
        Assert.Equal(1, h.PolicyRegistry.DWord(Au, "UseWUServer"));
        Assert.DoesNotContain(h.PolicyRegistry.Writes, w => w.StartsWith("WUServer", StringComparison.Ordinal) || w.StartsWith("UseWUServer", StringComparison.Ordinal));
        Assert.Empty(h.Runtime.State.Read(s => s.WindowsUpdatePolicy.Groups));
    }

    [Fact]
    public async Task A_value_changed_by_another_policy_source_is_reported_once_and_not_fought_over()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Server.Config = Config(DeferQuality(7));
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Equal(7, h.PolicyRegistry.DWord(Wu, "DeferQualityUpdatesPeriodInDays"));

        // Domain Group Policy sets a different value.
        h.PolicyRegistry.Set(new PolicyRegistryValue(Wu, "DeferQualityUpdatesPeriodInDays", 14));
        var writes = h.PolicyRegistry.Writes.Count;
        await h.Runtime.CheckInOnceAsync(Ct); // detects the drift
        await h.Runtime.CheckInOnceAsync(Ct); // reports it
        await h.Runtime.CheckInOnceAsync(Ct);

        Assert.Equal(14, h.PolicyRegistry.DWord(Wu, "DeferQualityUpdatesPeriodInDays"));
        Assert.Equal(writes, h.PolicyRegistry.Writes.Count);
        var conflict = Group(h.Server.CheckIns[^2], WindowsUpdatePolicyGroup.QualityUpdates);
        Assert.Equal(WindowsUpdatePolicyState.Conflict, conflict.State);
        Assert.Equal(["DeferQualityUpdatesPeriodInDays = 14 (EasyPatch: 7)"], conflict.ConflictingValues);
        Assert.Null(h.Server.CheckIns[^1].WindowsUpdatePolicy);

        // Changing the EasyPatch settings is an explicit decision: they are applied again.
        h.Server.Config = Config(DeferQuality(10));
        await h.Runtime.CheckInOnceAsync(Ct);
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Equal(10, h.PolicyRegistry.DWord(Wu, "DeferQualityUpdatesPeriodInDays"));
        Assert.Equal(WindowsUpdatePolicyState.Applied, Group(h.Server.CheckIns[^1], WindowsUpdatePolicyGroup.QualityUpdates).State);

        // On restore, a value another source changed since is left alone; the rest is put back.
        h.PolicyRegistry.Set(new PolicyRegistryValue(Wu, "DeferQualityUpdatesPeriodInDays", 21));
        h.Server.Config = Config(null);
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Equal(21, h.PolicyRegistry.DWord(Wu, "DeferQualityUpdatesPeriodInDays"));
        Assert.Null(h.PolicyRegistry.DWord(Wu, "DeferQualityUpdates"));
        Assert.Null(h.PolicyRegistry.DWord(Wu, "SetDisablePauseUXAccess"));
    }

    [Fact]
    public async Task Registry_errors_are_reported_and_the_settings_applied_once_possible()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.PolicyRegistry.Failure = new UnauthorizedAccessException("Access to the registry key is denied.");
        h.Server.Config = Config(DeferQuality(7));

        await h.Runtime.CheckInOnceAsync(Ct);
        await h.Runtime.CheckInOnceAsync(Ct);
        var error = Group(h.Server.CheckIns[^1], WindowsUpdatePolicyGroup.QualityUpdates);
        Assert.Equal(WindowsUpdatePolicyState.Error, error.State);
        Assert.Contains("denied", error.Message, StringComparison.Ordinal);

        h.PolicyRegistry.Failure = null;
        await h.Runtime.CheckInOnceAsync(Ct);
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Equal(7, h.PolicyRegistry.DWord(Wu, "DeferQualityUpdatesPeriodInDays"));
        Assert.Equal(WindowsUpdatePolicyState.Applied, Group(h.Server.CheckIns[^1], WindowsUpdatePolicyGroup.QualityUpdates).State);
    }

    [Fact]
    public async Task Unchanged_reports_are_refreshed_daily_and_mdm_policies_are_reported()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.PolicyRegistry.Mdm = true;
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.True(h.Server.CheckIns[^1].WindowsUpdatePolicy!.MdmUpdatePoliciesPresent);

        h.Time.Advance(TimeSpan.FromHours(23));
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Null(h.Server.CheckIns[^1].WindowsUpdatePolicy);

        h.Time.Advance(TimeSpan.FromHours(1));
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.NotNull(h.Server.CheckIns[^1].WindowsUpdatePolicy);
    }

    [Fact]
    public async Task Uninstalling_restores_the_original_settings()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.PolicyRegistry.Set(new PolicyRegistryValue(Au, "AUOptions", 2));
        h.Server.Config = Config(ScheduledInstall);
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Equal(4, h.PolicyRegistry.DWord(Au, "AUOptions"));

        await h.Runtime.UnenrollAsync("uninstall", Ct);

        Assert.Equal(2, h.PolicyRegistry.DWord(Au, "AUOptions"));
        Assert.Equal(1, h.PolicyRegistry.Count);
    }

    [Fact]
    public async Task A_revoked_credential_restores_the_original_settings()
    {
        using var h = new AgentHarness();
        await h.EnrollWithTokenAsync();
        h.Server.Config = Config(DeferQuality(7));
        await h.Runtime.CheckInOnceAsync(Ct);
        Assert.Equal(7, h.PolicyRegistry.DWord(Wu, "DeferQualityUpdatesPeriodInDays"));

        h.Server.Revoke(h.Runtime.State.Read(s => s.CredentialId)!);
        await Assert.ThrowsAsync<EasyPatch.Communication.AgentAuthException>(() => h.Runtime.CheckInOnceAsync(Ct));

        Assert.Equal(0, h.PolicyRegistry.Count);
    }
}
