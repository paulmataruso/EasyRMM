using EasyPatch.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Infrastructure.Data;

/// <summary>What <see cref="ImportPreparation.PrepareAsync"/> found and did.</summary>
public sealed record ImportPreparationResult(
    string LastMigrationBefore,
    string? ReleaseBefore,
    IReadOnlyList<string> Applied,
    int EmailsRenamed,
    int AccountsDisabled,
    int Organizations,
    int ArchivedOrganizations,
    int Sites,
    int ActiveEndpoints);

/// <summary>
/// Prepares a standalone EasyPatch's database, restored from its backup, to become the database of the patching engine in
/// an EasyRMM deployment (EasyRMM's one-product plan, phase S). It checks that this engine knows every migration the database
/// has, brings the database to this engine's schema, and disables the standalone server's own accounts: in EasyRMM people
/// sign in to EasyRMM, with EasyRMM's accounts and roles, and the engine's console is not served.
/// </summary>
public static class ImportPreparation
{
    /// <summary>The last migration of each EasyPatch release it can come from, to name the release in messages.</summary>
    public static readonly IReadOnlyDictionary<string, string> Releases = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["20261114215818_SmtpSkipCertificateValidation"] = "1.4.0",
        ["20261115051106_WingetSetup"] = "1.7",
        ["20261115230915_ReofferedMissingRows"] = "1.8.0 or 1.9.0",
        ["20261117021235_SingleSignOn"] = "1.10.0",
    };

    /// <summary>
    /// The migration that made email addresses unique ignoring case. It refuses to run while two accounts share an address in
    /// another case, which older releases allowed.
    /// </summary>
    public const string EmailSignInMigration = "20261117005722_EmailSignIn";

    /// <summary>The value an imported account's password hash is replaced with: no password matches it.</summary>
    public const string DisabledPasswordHash = "disabled:imported-into-easyrmm";

    public static async Task<ImportPreparationResult> PrepareAsync(EasyPatchDbContext db, TimeProvider clock, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(clock);

        var hasHistory = await db.Database
            .SqlQueryRaw<bool>("""SELECT to_regclass('public."__EFMigrationsHistory"') IS NOT NULL AS "Value" """)
            .SingleAsync(ct);
        var applied = hasHistory ? (await db.Database.GetAppliedMigrationsAsync(ct)).ToList() : [];
        if (applied.Count == 0)
        {
            throw new ImportRefusedException("The database is not an EasyPatch database: it has no EasyPatch migrations.");
        }

        var known = db.Database.GetMigrations().ToHashSet(StringComparer.Ordinal);
        var unknown = applied.Where(m => !known.Contains(m)).Order(StringComparer.Ordinal).ToList();
        if (unknown.Count > 0)
        {
            throw new ImportRefusedException(
                $"The database comes from a newer EasyPatch than this patching engine (it has {unknown.Count} migration(s) this engine does not know, " +
                $"the newest {unknown[^1]}). Upgrade EasyRMM first.");
        }

        var last = applied.Order(StringComparer.Ordinal).Last();
        var emailsRenamed = 0;
        if (!applied.Contains(EmailSignInMigration, StringComparer.Ordinal))
        {
            // Accounts are not imported, so an address in another case only has to stop blocking the migration. The first account
            // with an address keeps it; the others get one that cannot receive mail (.invalid is reserved, RFC 2606).
            emailsRenamed = await db.Database.ExecuteSqlRawAsync(
                """
                UPDATE users u SET email = u.id::text || '@duplicate.invalid'
                FROM (SELECT id, row_number() OVER (PARTITION BY lower(email) ORDER BY created_at, id) AS n FROM users) d
                WHERE d.id = u.id AND d.n > 1
                """, ct);
        }

        var pending = await DatabaseSeeder.MigrateAsync(db, clock, ct);

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var disabled = await db.Users.ExecuteUpdateAsync(s => s
            .SetProperty(u => u.IsActive, false)
            .SetProperty(u => u.PasswordHash, DisabledPasswordHash)
            .SetProperty(u => u.MfaEnabled, false)
            .SetProperty(u => u.MfaSecretProtected, (string?)null)
            .SetProperty(u => u.MfaPendingSecretProtected, (string?)null)
            .SetProperty(u => u.RecoveryCodeHashes, new List<string>())
            .SetProperty(u => u.MustChangePassword, false), ct);
        await db.UserSessions.ExecuteDeleteAsync(ct);
        await db.PasswordResetTokens.ExecuteDeleteAsync(ct);
        await db.ApiTokens.ExecuteDeleteAsync(ct);
        await db.WebAuthnCredentials.ExecuteDeleteAsync(ct);
        await db.WebAuthnChallenges.ExecuteDeleteAsync(ct);
        await db.ExternalLogins.ExecuteDeleteAsync(ct);
        await db.OidcLoginStates.ExecuteDeleteAsync(ct);
        await db.OidcProviders.ExecuteDeleteAsync(ct);
        db.AuditLogs.Add(new AuditLog
        {
            Username = "easyrmm-import",
            Action = "import.prepare",
            TargetType = "System",
            Details = System.Text.Json.JsonSerializer.Serialize(new
            {
                from = Releases.GetValueOrDefault(last) ?? last,
                applied = pending.Count,
                accountsDisabled = disabled,
                emailsRenamed,
            }),
            CreatedAt = clock.GetUtcNow(),
        });
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);

        return new ImportPreparationResult(
            last,
            Releases.GetValueOrDefault(last),
            pending,
            emailsRenamed,
            disabled,
            await db.Organizations.CountAsync(o => o.ArchivedAt == null, ct),
            await db.Organizations.CountAsync(o => o.ArchivedAt != null, ct),
            await db.Sites.CountAsync(s => s.ArchivedAt == null, ct),
            await db.Endpoints.CountAsync(e => e.Status == EndpointStatus.Active, ct));
    }
}

/// <summary>The database cannot be imported; the message says why.</summary>
public sealed class ImportRefusedException(string message) : Exception(message);
