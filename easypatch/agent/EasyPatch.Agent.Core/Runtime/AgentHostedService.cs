using Microsoft.Extensions.Hosting;

namespace EasyPatch.Agent.Core.Runtime;

/// <summary>Hosts <see cref="AgentRuntime.RunAsync"/> as a background service (Windows service on endpoints).</summary>
public sealed class AgentHostedService : BackgroundService
{
    private readonly AgentRuntime _runtime;

    public AgentHostedService(AgentRuntime runtime)
    {
        _runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) => _runtime.RunAsync(stoppingToken);
}
