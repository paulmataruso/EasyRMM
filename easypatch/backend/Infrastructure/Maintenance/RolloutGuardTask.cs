using System.Globalization;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace EasyPatch.Infrastructure.Maintenance;

/// <summary>
/// The rollout guard: holds a Windows update for every organization when its latest installation failed on too many of the
/// endpoints that installed it recently (server settings), so scheduled installs and "install all" stop spreading it. With a pilot
/// ring that installs before the others (a shorter rollout delay), failures in the pilot stop the update before the other rings
/// are due. Failures from before an administrator released a hold for every organization are not counted again.
/// </summary>
public sealed class RolloutGuardTask(EasyPatchDbContext db, SettingsService settingsService, AuditService audit, TimeProvider clock,
    ILogger<RolloutGuardTask> logger) : IMaintenanceTask
{
    public string Name => "rollout-guard";
    public long LockKey => 0x4550_000E;
    public TimeSpan Interval => TimeSpan.FromMinutes(5);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var settings = await settingsService.GetAsync(ct);
        if (!settings.RolloutGuardEnabled)
        {
            return;
        }

        var now = clock.GetUtcNow();
        var since = now.AddDays(-settings.RolloutGuardWindowDays);
        var outcomes =
            from i in db.JobUpdates.AsNoTracking()
            join j in db.Jobs.AsNoTracking() on i.JobId equals j.Id
            join e in db.Endpoints.AsNoTracking() on j.EndpointId equals e.Id
            where j.Type == JobType.InstallUpdates && e.Platform == AgentPlatforms.Windows && i.Category != UpdateCategory.Application &&
                  (i.Status == JobItemStatus.Succeeded || i.Status == JobItemStatus.Failed) && (i.CompletedAt ?? i.UpdatedAt) >= since
            select new { i.UpdateGuid, j.EndpointId, i.Status, At = i.CompletedAt ?? i.UpdatedAt };

        // Only updates that failed on enough endpoints are looked at in detail.
        var min = settings.RolloutGuardMinFailedEndpoints;
        var suspects = await outcomes.Where(o => o.Status == JobItemStatus.Failed)
            .GroupBy(o => o.UpdateGuid)
            .Where(g => g.Select(o => o.EndpointId).Distinct().Count() >= min)
            .Select(g => g.Key)
            .ToListAsync(ct);
        if (suspects.Count == 0)
        {
            return;
        }

        var holds = await db.UpdateHolds.AsNoTracking().Where(h => suspects.Contains(h.UpdateGuid) && h.OrganizationId == null).ToListAsync(ct);
        var rows = await outcomes.Where(o => suspects.Contains(o.UpdateGuid)).ToListAsync(ct);
        var created = 0;
        foreach (var update in rows.GroupBy(r => r.UpdateGuid))
        {
            var mine = holds.Where(h => h.UpdateGuid == update.Key).ToList();
            if (mine.Exists(h => h.ReleasedAt is null))
            {
                continue; // already held for everyone
            }

            var releasedAt = mine.Max(h => h.ReleasedAt);
            var latest = update.Where(r => releasedAt is null || r.At > releasedAt)
                .GroupBy(r => r.EndpointId)
                .Select(g => g.MaxBy(r => r.At)!.Status)
                .ToList();
            var failed = latest.Count(s => s == JobItemStatus.Failed);
            if (failed < min || failed * 100 < settings.RolloutGuardFailurePercent * latest.Count)
            {
                continue;
            }

            var percent = (int)Math.Round(100.0 * failed / latest.Count);
            var hold = new UpdateHold
            {
                Id = Guid.CreateVersion7(now),
                UpdateGuid = update.Key,
                OrganizationId = null,
                Source = UpdateHoldSource.Automatic,
                Reason = string.Create(CultureInfo.InvariantCulture,
                    $"Installation failed on {failed} of {latest.Count} endpoints ({percent}%) in the last {settings.RolloutGuardWindowDays} days."),
                FailedEndpoints = failed,
                AttemptedEndpoints = latest.Count,
                CreatedAt = now,
                CreatedBy = UpdateHoldService.GuardName,
            };
            db.UpdateHolds.Add(hold);
            audit.Record("update.hold", "Update", update.Key.ToString(), null, null,
                new { updateGuid = update.Key, source = hold.Source, hold.Reason, failed, attempted = latest.Count });
            var title = await db.Updates.AsNoTracking().Where(u => u.UpdateGuid == update.Key).OrderByDescending(u => u.RevisionNumber)
                .Select(u => u.Title).FirstOrDefaultAsync(ct);
            logger.LogWarning("Rollout guard: holding {Update} ({UpdateGuid}) for every organization. {Reason}", title, update.Key, hold.Reason);
            created++;
        }

        if (created > 0)
        {
            await db.SaveChangesAsync(ct);
        }
    }
}
