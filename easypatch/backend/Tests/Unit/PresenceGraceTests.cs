using EasyPatch.Agent.Core;
using EasyPatch.Infrastructure.Maintenance;
using Xunit;

namespace EasyPatch.Tests.Unit;

public sealed class PresenceGraceTests
{
    /// <summary>After a restart the presence monitor waits for agents as long as an agent can wait between two attempts.</summary>
    [Fact]
    public void The_grace_after_the_workers_start_covers_the_agents_longest_backoff()
    {
        var agent = new AgentRuntimeOptions { DataDirectory = Path.GetTempPath(), AgentVersion = "1.0.0" };
        Assert.True(PresenceMonitorTask.ReconnectGrace >= agent.BackoffMax);
    }
}
