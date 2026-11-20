using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>
/// A standalone EasyPatch's database, prepared to become the patching engine's in an EasyRMM deployment (EasyRMM's
/// one-product plan, phase S): brought to this engine's schema from an older release, refused when it is newer or not
/// EasyPatch's, and without usable accounts afterwards.
/// </summary>
public sealed class ImportPreparationTests(PostgresFixture postgres)
{
    private static EasyPatchDbContext Open(string connectionString) =>
        new(new DbContextOptionsBuilder<EasyPatchDbContext>().UseNpgsql(connectionString).Options);

    [Fact]
    public async Task A_1_4_database_is_brought_to_this_engine_and_its_accounts_disabled()
    {
        var cs = await postgres.CreateEmptyDatabaseAsync();
        await using (var db = Open(cs))
        {
            // EasyPatch 1.4.0's schema, with data as it allowed: two accounts whose addresses differ only in case.
            await db.GetService<IMigrator>().MigrateAsync("20261114215818_SmtpSkipCertificateValidation");
            await db.Database.ExecuteSqlRawAsync(
                """
                INSERT INTO users (id, username, email, password_hash, role, is_active, mfa_enabled, mfa_secret_protected, recovery_code_hashes,
                    created_at, failed_login_count, lockout_count, password_changed_at, must_change_password)
                VALUES ('00000000-0000-0000-0000-000000000001', 'admin', 'Admin@Example.com', '$argon2id$x', 'SuperAdmin', true, true, 'secret',
                        ARRAY['a','b'], now() - interval '2 days', 0, 0, now(), false),
                       ('00000000-0000-0000-0000-000000000002', 'admin2', 'admin@example.com', '$argon2id$y', 'Admin', true, false, null,
                        ARRAY[]::text[], now() - interval '1 day', 0, 0, now(), false)
                """);
            await db.Database.ExecuteSqlRawAsync(
                """
                INSERT INTO organizations (id, name, time_zone, is_active, created_at, updated_at)
                VALUES ('00000000-0000-0000-0000-00000000000a', 'Fabrikam', 'Europe/Oslo', true, now(), now()),
                       ('00000000-0000-0000-0000-00000000000b', 'fabrikam', 'UTC', true, now(), now()),
                       ('00000000-0000-0000-0000-00000000000c', 'Old', 'UTC', false, now(), now())
                """);
            await db.Database.ExecuteSqlRawAsync(
                "UPDATE organizations SET archived_at = now() WHERE id = '00000000-0000-0000-0000-00000000000c'");
        }

        ImportPreparationResult result;
        await using (var db = Open(cs))
        {
            result = await ImportPreparation.PrepareAsync(db, TimeProvider.System, TestContext.Current.CancellationToken);
        }

        Assert.Equal(("20261114215818_SmtpSkipCertificateValidation", "1.4.0"), (result.LastMigrationBefore, result.ReleaseBefore));
        Assert.Equal((1, 2, 2, 1, 0), (result.EmailsRenamed, result.AccountsDisabled, result.Organizations, result.ArchivedOrganizations,
            result.ActiveEndpoints));
        await using (var db = Open(cs))
        {
            Assert.Empty(await db.Database.GetPendingMigrationsAsync(TestContext.Current.CancellationToken));
            Assert.Equal(db.Database.GetMigrations().Where(m => string.CompareOrdinal(m, "20261114215818_SmtpSkipCertificateValidation") > 0),
                result.Applied);
            var users = await db.Users.AsNoTracking().OrderBy(u => u.CreatedAt).ToListAsync(TestContext.Current.CancellationToken);
            // The first keeps its address (which the migration stores in lower case); the second no longer blocks it.
            Assert.Equal(["admin@example.com", "00000000-0000-0000-0000-000000000002@duplicate.invalid"], users.Select(u => u.Email));
            Assert.All(users, u => Assert.Equal((false, ImportPreparation.DisabledPasswordHash, false, null, 0), (u.IsActive, u.PasswordHash,
                u.MfaEnabled, u.MfaSecretProtected, u.RecoveryCodeHashes.Count)));
            // The global policy a migrated database is seeded with.
            Assert.True(await db.Policies.AnyAsync(p => p.Scope == PolicyScope.Global, TestContext.Current.CancellationToken));
            var audit = await db.AuditLogs.AsNoTracking().SingleAsync(a => a.Action == "import.prepare", TestContext.Current.CancellationToken);
            using var details = System.Text.Json.JsonDocument.Parse(audit.Details!);
            Assert.Equal(("1.4.0", 2), (details.RootElement.GetProperty("from").GetString(), details.RootElement.GetProperty("accountsDisabled").GetInt32()));
        }
    }

    [Fact]
    public async Task Sessions_tokens_and_second_factors_go()
    {
        var cs = await postgres.CreateDatabaseAsync();
        var userId = Guid.NewGuid();
        await using (var db = Open(cs))
        {
            var now = DateTimeOffset.UtcNow;
            db.Users.Add(new User
            {
                Id = userId, Username = "ops", Email = "ops@example.com", PasswordHash = "$argon2id$z", Role = UserRole.SuperAdmin,
                MfaEnabled = true, MfaSecretProtected = "protected", CreatedAt = now, PasswordChangedAt = now,
            });
            db.UserSessions.Add(new UserSession { UserId = userId, TokenHash = new string('a', 64), CreatedAt = now, LastSeenAt = now, ExpiresAt = now.AddHours(1) });
            db.ApiTokens.Add(new ApiToken
            {
                Name = "integration", Prefix = "ept_abcdefgh", TokenHash = new string('b', 64), Role = UserRole.Admin, AllOrganizations = true,
                CreatedAt = now, ExpiresAt = now.AddDays(30),
            });
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        await using (var db = Open(cs))
        {
            var result = await ImportPreparation.PrepareAsync(db, TimeProvider.System, TestContext.Current.CancellationToken);
            Assert.Equal((0, 1, 0), (result.Applied.Count, result.AccountsDisabled, result.EmailsRenamed));
            Assert.Equal(db.Database.GetMigrations().Last(), result.LastMigrationBefore);
        }

        await using (var check = Open(cs))
        {
            Assert.False(await check.UserSessions.AnyAsync(TestContext.Current.CancellationToken));
            Assert.False(await check.ApiTokens.AnyAsync(TestContext.Current.CancellationToken));
            var user = await check.Users.AsNoTracking().SingleAsync(TestContext.Current.CancellationToken);
            Assert.Equal((false, false, null), (user.IsActive, user.MfaEnabled, user.MfaSecretProtected));
        }
    }

    [Fact]
    public async Task A_newer_database_is_refused_and_left_as_it_was()
    {
        var cs = await postgres.CreateDatabaseAsync();
        await using (var db = Open(cs))
        {
            await db.Database.ExecuteSqlRawAsync(
                """INSERT INTO "__EFMigrationsHistory" ("MigrationId", "ProductVersion") VALUES ('29991231000000_FromTheFuture', '10.0.0')""");
        }

        await using (var db = Open(cs))
        {
            var e = await Assert.ThrowsAsync<ImportRefusedException>(() => ImportPreparation.PrepareAsync(db, TimeProvider.System,
                TestContext.Current.CancellationToken));
            Assert.Contains("newer EasyPatch than this patching engine", e.Message, StringComparison.Ordinal);
            Assert.Contains("29991231000000_FromTheFuture", e.Message, StringComparison.Ordinal);
        }

        await using (var check = Open(cs))
        {
            Assert.False(await check.AuditLogs.AnyAsync(a => a.Action == "import.prepare", TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task A_database_that_is_not_easypatch_is_refused()
    {
        var cs = await postgres.CreateEmptyDatabaseAsync();
        await using var db = Open(cs);
        var e = await Assert.ThrowsAsync<ImportRefusedException>(() => ImportPreparation.PrepareAsync(db, TimeProvider.System,
            TestContext.Current.CancellationToken));
        Assert.Contains("not an EasyPatch database", e.Message, StringComparison.Ordinal);
    }
}
