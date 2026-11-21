using System.Globalization;
using EasyPatch.Contracts;
using EasyPatch.Infrastructure.Maintenance;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>After an upgrade the host updater holds automatic agent updates (EasyRMM's ADR-0052); an operator's are not held.</summary>
public sealed class AgentUpdateHoldTests(PostgresFixture postgres) : AgentUpdateTestBase(postgres)
{
    private string HoldFile => Path.Combine(Factory.UpdaterStatusPath, AgentUpdateHold.FileName);

    private void HoldUntil(DateTimeOffset until) =>
        File.WriteAllText(HoldFile, until.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture) + "\n");

    [Fact]
    public async Task Automatic_updates_wait_for_the_end_of_the_hold_and_an_operators_do_not()
    {
        var automatic = await UpdatableAgentAsync("PC-AUTO");
        var manual = await UpdatableAgentAsync("PC-MANUAL");
        Publish("1.3.0");
        var until = Clock.GetUtcNow().AddHours(24);
        HoldUntil(until);

        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Empty(await AgentUpdateJobsAsync());

        var asked = await UpdateAgentQueuedAsync(manual.EndpointId);
        Assert.Equal(asked, Assert.Single(await AgentUpdateJobsAsync()).Id);

        Clock.Advance(until - Clock.GetUtcNow() - TimeSpan.FromSeconds(1));
        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Single(await AgentUpdateJobsAsync());

        Clock.Advance(TimeSpan.FromSeconds(1));
        await RunMaintenanceAsync<AgentUpdateTask>();
        var jobs = await AgentUpdateJobsAsync();
        Assert.Equal(2, jobs.Count);
        var queued = jobs.Single(j => j.Id != asked);
        Assert.Equal((automatic.EndpointId, JobTrigger.System), (queued.EndpointId, queued.Trigger));
    }

    [Fact]
    public async Task A_time_that_has_passed_holds_nothing()
    {
        var agent = await UpdatableAgentAsync("PC-PAST");
        Publish("1.3.0");
        HoldUntil(Clock.GetUtcNow().AddMinutes(-1));

        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Equal(agent.EndpointId, Assert.Single(await AgentUpdateJobsAsync()).EndpointId);
    }

    [Fact]
    public async Task Without_the_updaters_status_directory_nothing_is_held()
    {
        var agent = await UpdatableAgentAsync("PC-NO-UPDATER");
        Publish("1.3.0");
        Directory.Delete(Factory.UpdaterStatusPath);

        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Equal(agent.EndpointId, Assert.Single(await AgentUpdateJobsAsync()).EndpointId);
    }

    [Fact]
    public async Task A_hold_file_that_cannot_be_used_holds_updates_until_it_is_removed()
    {
        var agent = await UpdatableAgentAsync("PC-MALFORMED");
        Publish("1.3.0");
        await File.WriteAllTextAsync(HoldFile, "22 November 2026", TestContext.Current.CancellationToken);

        await RunMaintenanceAsync<AgentUpdateTask>();
        Clock.Advance(TimeSpan.FromDays(7));
        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Empty(await AgentUpdateJobsAsync());

        File.Delete(HoldFile);
        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Equal(agent.EndpointId, Assert.Single(await AgentUpdateJobsAsync()).EndpointId);
    }
}
