using EasyPatch.Contracts;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Infrastructure.Services;

/// <summary>
/// Rolls back an installed Windows update on one endpoint: queues an uninstall-update job (the agent removes only that update,
/// with Windows Update or DISM, and never restarts) and, when asked, excludes the update on the endpoint so EasyPatch does not
/// install it again.
/// </summary>
public sealed class UpdateRemovalService(
    EasyPatchDbContext db,
    JobService jobs,
    AuditService audit,
    ComplianceService compliance,
    IActorContext actor,
    TimeProvider clock)
{
    public const string DefaultBlockReason = "Removed with EasyPatch";

    public async Task<Job> RemoveAsync(Guid endpointId, Guid updateGuid, bool block, string? reason, CancellationToken ct = default)
    {
        var job = await jobs.CreateAsync(new CreateJobRequest(endpointId, JobType.UninstallUpdate, UpdateGuids: [updateGuid]), ct);
        var blocked = false;
        if (block && !await db.UpdateExclusions.AnyAsync(x => x.EndpointId == endpointId && x.UpdateGuid == updateGuid, ct))
        {
            db.UpdateExclusions.Add(new UpdateExclusion
            {
                Id = Guid.CreateVersion7(),
                EndpointId = endpointId,
                UpdateGuid = updateGuid,
                Reason = reason ?? DefaultBlockReason,
                CreatedAt = clock.GetUtcNow(),
                CreatedByUserId = actor.UserId,
            });
            audit.Record("endpoint.update_excluded", "Endpoint", endpointId.ToString(), job.OrganizationId, endpointId,
                new { UpdateGuid = updateGuid, Reason = reason ?? DefaultBlockReason });
            blocked = true;
        }

        audit.Record("endpoint.update_removal", "Job", job.Id.ToString(), job.OrganizationId, endpointId, new { updateGuid, block, reason });
        await db.SaveChangesAsync(ct);
        if (blocked)
        {
            await compliance.RecomputeAsync([endpointId], ct);
        }

        return job;
    }
}
