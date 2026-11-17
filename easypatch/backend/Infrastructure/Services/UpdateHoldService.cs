using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace EasyPatch.Infrastructure.Services;

/// <summary>Update holds: which updates are held for an organization, and holding and releasing them. Callers check that the
/// administrator may act on the hold's scope (an organization, or every organization for super administrators).</summary>
public sealed class UpdateHoldService(EasyPatchDbContext db, AuditService audit, IActorContext actor, TimeProvider clock)
{
    public const string GuardName = "Rollout guard";

    /// <summary>Active holds that apply to endpoints of the organization (its own and those for every organization), by update.
    /// An organization's own hold is preferred when both exist.</summary>
    public async Task<Dictionary<Guid, UpdateHold>> ActiveForAsync(Guid organizationId, CancellationToken ct = default)
    {
        var holds = await db.UpdateHolds.AsNoTracking()
            .Where(h => h.ReleasedAt == null && (h.OrganizationId == null || h.OrganizationId == organizationId))
            .ToListAsync(ct);
        return holds.GroupBy(h => h.UpdateGuid).ToDictionary(g => g.Key, g => g.OrderBy(h => h.OrganizationId is null).First());
    }

    public async Task<UpdateHold> HoldAsync(Guid updateGuid, Guid? organizationId, string reason, CancellationToken ct = default)
    {
        if (!await db.Updates.AnyAsync(u => u.UpdateGuid == updateGuid, ct))
        {
            throw AppException.NotFound("Update");
        }

        if (await IsHeldAsync(updateGuid, organizationId, ct))
        {
            throw AlreadyHeld();
        }

        var hold = new UpdateHold
        {
            Id = Guid.CreateVersion7(),
            UpdateGuid = updateGuid,
            OrganizationId = organizationId,
            Source = UpdateHoldSource.Manual,
            Reason = reason,
            CreatedAt = clock.GetUtcNow(),
            CreatedByUserId = actor.UserId,
            CreatedBy = Truncate(actor.Username ?? "unknown"),
        };
        db.UpdateHolds.Add(hold);
        audit.Record("update.hold", "Update", updateGuid.ToString(), organizationId, null, new { updateGuid, organizationId, reason });
        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            db.ChangeTracker.Clear();
            throw AlreadyHeld();
        }

        return hold;
    }

    public async Task ReleaseAsync(UpdateHold hold, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(hold);
        if (hold.ReleasedAt is not null)
        {
            return;
        }

        hold.ReleasedAt = clock.GetUtcNow();
        hold.ReleasedByUserId = actor.UserId;
        hold.ReleasedBy = Truncate(actor.Username ?? "unknown");
        audit.Record("update.hold_released", "Update", hold.UpdateGuid.ToString(), hold.OrganizationId, null,
            new { hold.UpdateGuid, hold.OrganizationId, hold.Source, hold.Reason });
        await db.SaveChangesAsync(ct);
    }

    public Task<bool> IsHeldAsync(Guid updateGuid, Guid? organizationId, CancellationToken ct = default) =>
        db.UpdateHolds.AnyAsync(h => h.UpdateGuid == updateGuid && h.OrganizationId == organizationId && h.ReleasedAt == null, ct);

    private static AppException AlreadyHeld() => AppException.Conflict("This update is already on hold.", "already_held");

    private static string Truncate(string value) => value.Length > 100 ? value[..100] : value;
}
