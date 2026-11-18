using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Infrastructure.Data;

/// <summary>Idempotent seed data that cannot be expressed with HasData (the global policy has list-valued columns).</summary>
public static class DatabaseSeeder
{
    public static async Task EnsureSeedDataAsync(EasyPatchDbContext db, TimeProvider clock, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(clock);
        if (!await db.Policies.AnyAsync(p => p.Scope == PolicyScope.Global, ct))
        {
            db.Policies.Add(PolicyDefaults.CreateGlobal(clock.GetUtcNow()));
            await db.SaveChangesAsync(ct);
        }
    }

    /// <summary>Applies migrations and seed data.</summary>
    public static async Task<IReadOnlyList<string>> MigrateAsync(EasyPatchDbContext db, TimeProvider clock, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        var pending = (await db.Database.GetPendingMigrationsAsync(ct)).ToList();
        await db.Database.MigrateAsync(ct);
        await EnsureSeedDataAsync(db, clock, ct);
        return pending;
    }
}
