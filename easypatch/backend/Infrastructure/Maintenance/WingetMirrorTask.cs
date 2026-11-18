using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Infrastructure.Maintenance;

/// <summary>
/// Downloads the pinned winget release from GitHub once an agent has asked the server for it (an agent that could not
/// reach GitHub itself). Failed downloads are retried after 15 minutes, 1 hour, 6 hours, then daily.
/// </summary>
public sealed class WingetMirrorTask(EasyPatchDbContext db, WingetMirrorService mirror, TimeProvider clock, ILogger<WingetMirrorTask> logger)
    : IMaintenanceTask
{
    private static readonly TimeSpan[] RetryDelays = [TimeSpan.FromMinutes(15), TimeSpan.FromHours(1), TimeSpan.FromHours(6), TimeSpan.FromHours(24)];

    public string Name => "winget-mirror";
    public long LockKey => 0x4550_000D;
    public TimeSpan Interval => TimeSpan.FromMinutes(5);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var state = await db.MirrorStates.FirstOrDefaultAsync(m => m.Name == Mirrors.Winget, ct);
        if (state?.RequestedAt is null)
        {
            return; // no agent has needed the server's copy
        }

        var now = clock.GetUtcNow();
        if (mirror.IsComplete())
        {
            if (state.LastError is not null || state.LastSuccessAt is null)
            {
                state.LastSuccessAt ??= now;
                state.LastError = null;
                state.Failures = 0;
                await db.SaveChangesAsync(ct);
            }

            return;
        }

        if (state.Failures > 0 && state.LastAttemptAt is { } last && now - last < RetryDelays[Math.Min(state.Failures, RetryDelays.Length) - 1])
        {
            return;
        }

        state.LastAttemptAt = now;
        await db.SaveChangesAsync(ct);
        try
        {
            await mirror.MirrorAsync(ct);
            state.LastSuccessAt = clock.GetUtcNow();
            state.LastError = null;
            state.Failures = 0;
            logger.LogInformation("The server's copy of winget is ready for agents.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            state.LastError = ScanIngestionService.Truncate(ex.Message, 2000);
            state.Failures++;
            logger.LogWarning("Could not download winget for agents: {Error}", ex.Message);
        }

        await db.SaveChangesAsync(CancellationToken.None);
    }
}
