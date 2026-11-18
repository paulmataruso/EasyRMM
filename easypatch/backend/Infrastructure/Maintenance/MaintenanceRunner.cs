using EasyPatch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Infrastructure.Maintenance;

/// <summary>Executes one maintenance task while holding a PostgreSQL session-level advisory lock, so that replicas
/// never run the same task at the same time. Returns false when another instance holds the lock.</summary>
public static class MaintenanceExecutor
{
    public static async Task<bool> RunExclusiveAsync<TTask>(IServiceProvider services, CancellationToken ct)
        where TTask : IMaintenanceTask
    {
        await using var scope = services.CreateAsyncScope();
        var task = scope.ServiceProvider.GetRequiredService<TTask>();
        var db = scope.ServiceProvider.GetRequiredService<EasyPatchDbContext>();
        await db.Database.OpenConnectionAsync(ct);
        try
        {
            var acquired = await db.Database.SqlQuery<bool>($"SELECT pg_try_advisory_lock({task.LockKey}) AS \"Value\"").SingleAsync(ct);
            if (!acquired)
            {
                return false;
            }

            try
            {
                await task.RunOnceAsync(ct);
                return true;
            }
            finally
            {
                await db.Database.SqlQuery<bool>($"SELECT pg_advisory_unlock({task.LockKey}) AS \"Value\"").SingleAsync(CancellationToken.None);
            }
        }
        finally
        {
            await db.Database.CloseConnectionAsync();
        }
    }
}

/// <summary>Records when each maintenance loop last completed an iteration (ran, or skipped because another worker
/// holds the lock). The worker's health endpoint reports unhealthy when a loop stops making progress.</summary>
public sealed class MaintenanceHeartbeat(TimeProvider clock)
{
    private readonly DateTimeOffset startedAt = clock.GetUtcNow();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (TimeSpan Interval, DateTimeOffset? LastBeat)> loops = new();

    public void Register(string name, TimeSpan interval) => loops.TryAdd(name, (interval, null));

    public void Beat(string name, TimeSpan interval) => loops[name] = (interval, clock.GetUtcNow());

    /// <summary>Loops whose last successful iteration is older than three intervals plus two minutes of slack.</summary>
    public IReadOnlyList<string> Stalled()
    {
        var now = clock.GetUtcNow();
        return loops.Where(l => now - (l.Value.LastBeat ?? startedAt) > l.Value.Interval * 3 + TimeSpan.FromMinutes(2))
            .Select(l => l.Key).Order(StringComparer.Ordinal).ToList();
    }

    public IReadOnlyDictionary<string, DateTimeOffset?> Snapshot() => loops.ToDictionary(l => l.Key, l => l.Value.LastBeat);
}

/// <summary>Hosted loop for one maintenance task type.</summary>
public sealed class MaintenanceLoop<TTask>(IServiceProvider services, TimeProvider clock, MaintenanceHeartbeat heartbeat, ILogger<MaintenanceLoop<TTask>> logger)
    : BackgroundService
    where TTask : class, IMaintenanceTask
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        TimeSpan interval;
        string name;
        await using (var scope = services.CreateAsyncScope())
        {
            var task = scope.ServiceProvider.GetRequiredService<TTask>();
            interval = task.Interval;
            name = task.Name;
        }

        heartbeat.Register(name, interval);

        // Stagger start-up so tasks do not all hit the database at once.
        await Task.Delay(TimeSpan.FromSeconds(Random.Shared.Next(2, 15)), clock, stoppingToken).ConfigureAwait(false);
        while (!stoppingToken.IsCancellationRequested)
        {
            var started = clock.GetTimestamp();
            try
            {
                var ran = await MaintenanceExecutor.RunExclusiveAsync<TTask>(services, stoppingToken);
                heartbeat.Beat(name, interval);
                if (!ran)
                {
                    logger.LogDebug("Maintenance task {Task} skipped: another instance holds the lock", name);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Maintenance task {Task} failed", name);
            }

            var elapsed = clock.GetElapsedTime(started);
            var delay = interval - elapsed;
            try
            {
                await Task.Delay(delay > TimeSpan.Zero ? delay : TimeSpan.FromSeconds(1), clock, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
