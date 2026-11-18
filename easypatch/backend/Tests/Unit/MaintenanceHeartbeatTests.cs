using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Infrastructure.Maintenance;
using Xunit;

namespace EasyPatch.Tests.Unit;

public sealed class MaintenanceHeartbeatTests
{
    [Fact]
    public void A_loop_is_stalled_only_after_three_missed_intervals_plus_slack()
    {
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 11, 13, 12, 0, 0, TimeSpan.Zero));
        var heartbeat = new MaintenanceHeartbeat(clock);
        heartbeat.Register("jobs", TimeSpan.FromSeconds(30));
        heartbeat.Register("retention", TimeSpan.FromHours(6));

        clock.Advance(TimeSpan.FromMinutes(3)); // 3 × 30 s + 2 min = 3.5 min
        Assert.Empty(heartbeat.Stalled());
        clock.Advance(TimeSpan.FromMinutes(1));
        Assert.Equal(["jobs"], heartbeat.Stalled());

        heartbeat.Beat("jobs", TimeSpan.FromSeconds(30));
        Assert.Empty(heartbeat.Stalled());
        Assert.NotNull(heartbeat.Snapshot()["jobs"]);
        Assert.Null(heartbeat.Snapshot()["retention"]);
    }
}
