using EasyPatch.Api.Contracts;
using EasyPatch.Infrastructure.Maintenance;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>
/// The presence monitor after a restart or an upgrade (EasyRMM's ADR-0052): an endpoint counts as seen no earlier than the worker's
/// start plus <see cref="PresenceMonitorTask.ReconnectGrace"/>. The worker starts with each test's host, at the clock's first time.
/// </summary>
public sealed class PresenceTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    /// <summary>The default <c>OfflineThresholdMinutes</c>.</summary>
    private static readonly TimeSpan Threshold = TimeSpan.FromMinutes(10);

    private AdminClient root = null!;
    private OrganizationDto org = null!;
    private SiteDto site = null!;
    private DateTimeOffset started;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        started = Clock.GetUtcNow();
        root = SuperAdmin();
        (org, site) = await CreateOrgAsync(root);
    }

    private async Task<SignedAgent> OnlineAgentAsync(string hostname)
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, hostname);
        await agent.CheckInAsync();
        await FlushPresenceAsync();
        return agent;
    }

    /// <summary>The engine was down: the endpoint's last check-in reached it <paramref name="before"/> the worker started.</summary>
    private Task LastSeenBeforeStartAsync(SignedAgent agent, TimeSpan before) =>
        WithDbAsync(db => db.Endpoints.Where(e => e.Id == agent.EndpointId)
            .ExecuteUpdateAsync(s => s.SetProperty(e => e.LastCheckInAt, started - before)));

    private Task<bool> IsOnlineAsync(SignedAgent agent) =>
        WithDbAsync(db => db.Endpoints.Where(e => e.Id == agent.EndpointId).Select(e => e.IsOnline).SingleAsync());

    private Task<List<string>> PresenceEventsAsync(SignedAgent agent) =>
        WithDbAsync(db => db.EndpointEvents.AsNoTracking()
            .Where(e => e.EndpointId == agent.EndpointId && (e.Type == "Offline" || e.Type == "Online"))
            .OrderBy(e => e.Id).Select(e => e.Type).ToListAsync());

    private async Task AtAsync(TimeSpan sinceStart)
    {
        Clock.Advance(started + sinceStart - Clock.GetUtcNow());
        await RunMaintenanceAsync<PresenceMonitorTask>();
    }

    [Fact]
    public async Task After_a_restart_no_endpoint_goes_offline_whose_agent_is_back_within_its_backoff()
    {
        var back = await OnlineAgentAsync("PC-BACK");
        var gone = await OnlineAgentAsync("PC-GONE");
        await LastSeenBeforeStartAsync(back, TimeSpan.FromMinutes(20));
        await LastSeenBeforeStartAsync(gone, TimeSpan.FromMinutes(20));

        // Silent for longer than the threshold, but the worker has just started.
        await AtAsync(TimeSpan.Zero);
        Assert.True(await IsOnlineAsync(back));
        Assert.True(await IsOnlineAsync(gone));

        // One agent gets through after waiting nearly its longest backoff; the other's computer stays off.
        Clock.Advance(PresenceMonitorTask.ReconnectGrace - TimeSpan.FromSeconds(30));
        await back.CheckInAsync();
        await FlushPresenceAsync();

        // Counted as seen at the start plus the grace: neither is offline before the threshold has passed since then.
        await AtAsync(PresenceMonitorTask.ReconnectGrace + Threshold);
        Assert.True(await IsOnlineAsync(back));
        Assert.True(await IsOnlineAsync(gone));

        await back.CheckInAsync();
        await FlushPresenceAsync();
        await AtAsync(PresenceMonitorTask.ReconnectGrace + Threshold + TimeSpan.FromMinutes(1));
        Assert.True(await IsOnlineAsync(back));
        Assert.False(await IsOnlineAsync(gone));

        Assert.Equal(["Online"], await PresenceEventsAsync(back)); // its first check-in
        Assert.Equal(["Online", "Offline"], await PresenceEventsAsync(gone));
    }

    [Fact]
    public async Task After_the_grace_an_endpoint_goes_offline_after_the_usual_threshold()
    {
        var agent = await OnlineAgentAsync("PC-LATER");
        Clock.Advance(PresenceMonitorTask.ReconnectGrace + TimeSpan.FromMinutes(5));
        await agent.CheckInAsync();
        await FlushPresenceAsync();
        var lastSeen = Clock.GetUtcNow() - started;

        await AtAsync(lastSeen + Threshold);
        Assert.True(await IsOnlineAsync(agent));

        await AtAsync(lastSeen + Threshold + TimeSpan.FromMinutes(1));
        Assert.False(await IsOnlineAsync(agent));
        Assert.Equal(["Online", "Offline"], await PresenceEventsAsync(agent));
    }

    [Fact]
    public async Task An_endpoint_offline_before_the_restart_stays_offline_until_its_agent_checks_in()
    {
        var agent = await OnlineAgentAsync("PC-OFF");
        await WithDbAsync(db => db.Endpoints.Where(e => e.Id == agent.EndpointId)
            .ExecuteUpdateAsync(s => s.SetProperty(e => e.IsOnline, false).SetProperty(e => e.LastCheckInAt, started - TimeSpan.FromHours(2))));

        await AtAsync(TimeSpan.Zero);
        await AtAsync(TimeSpan.FromMinutes(1));
        Assert.False(await IsOnlineAsync(agent));

        await agent.CheckInAsync();
        Assert.True(await IsOnlineAsync(agent));
        Assert.Equal(["Online", "Online"], await PresenceEventsAsync(agent)); // its first check-in, and this one
    }
}
