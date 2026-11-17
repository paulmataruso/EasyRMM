using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Infrastructure.Services;

/// <summary>
/// API tokens for scripts and integrations. The secret is a 256-bit random value shown once at creation; only its SHA-256 hash is
/// stored, and the secret is never written to logs or audit records. Callers (super administrators) are authorized by the endpoint.
/// </summary>
public sealed class ApiTokenService(EasyPatchDbContext db, AuditService audit, IActorContext actor, TimeProvider clock)
{
    public const string SecretPrefix = "ept_";
    public const int MaxNameLength = 50;
    public const int MaxLifetimeDays = 365;

    /// <summary>Characters of the secret kept in clear to recognize a token (the <c>ept_</c> prefix and 8 random characters).</summary>
    private const int DisplayPrefixLength = 12;

    /// <summary>The token for a secret, when it is active (not revoked or expired). Records when and from where it was last used.</summary>
    public async Task<ApiToken?> ValidateAsync(string? secret, string? ipAddress, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(secret) || !secret.StartsWith(SecretPrefix, StringComparison.Ordinal) || secret.Length > 100)
        {
            return null;
        }

        var hash = SecureTokens.Hash(secret);
        var token = await db.ApiTokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == hash, ct);
        var now = clock.GetUtcNow();
        if (token is null || token.RevokedAt is not null || token.ExpiresAt <= now)
        {
            return null;
        }

        var ip = ipAddress is { Length: > 64 } ? ipAddress[..64] : ipAddress;
        if (token.LastUsedAt is null || now - token.LastUsedAt > TimeSpan.FromMinutes(1) || token.LastUsedIp != ip)
        {
            await db.ApiTokens.Where(t => t.Id == token.Id)
                .ExecuteUpdateAsync(s => s.SetProperty(t => t.LastUsedAt, now).SetProperty(t => t.LastUsedIp, ip), ct);
        }

        return token;
    }

    /// <summary>Creates a token and returns it with its secret, which cannot be retrieved again.</summary>
    public async Task<(ApiToken Token, string Secret)> CreateAsync(string name, UserRole role, IReadOnlyCollection<Guid> organizationIds,
        int expiresInDays, CancellationToken ct = default)
    {
        if (role is not (UserRole.ReadOnly or UserRole.Admin))
        {
            throw AppException.BadRequest("An API token can be read-only or an operator (Admin), not a super administrator.", "invalid_role");
        }

        if (await NameTakenAsync(name, ct))
        {
            throw AppException.Conflict($"An active API token is already named \"{name}\". Choose another name or revoke that token.", "name_taken");
        }

        var orgs = organizationIds.Distinct().ToList();
        var found = await db.Organizations.CountAsync(o => orgs.Contains(o.Id), ct);
        if (found != orgs.Count)
        {
            throw AppException.NotFound("Organization");
        }

        var secret = SecureTokens.Create(SecretPrefix);
        var now = clock.GetUtcNow();
        var token = new ApiToken
        {
            Id = Guid.CreateVersion7(),
            Name = name,
            Prefix = secret[..DisplayPrefixLength],
            TokenHash = SecureTokens.Hash(secret),
            Role = role,
            AllOrganizations = orgs.Count == 0,
            OrganizationIds = orgs,
            CreatedAt = now,
            CreatedByUserId = actor.UserId,
            CreatedBy = actor.Username,
            ExpiresAt = now.AddDays(expiresInDays),
        };
        db.ApiTokens.Add(token);
        audit.Record("api_token.create", "ApiToken", token.Id.ToString(), details: new
        {
            token.Name, token.Prefix, Role = role.ToString(), token.AllOrganizations, token.OrganizationIds, token.ExpiresAt,
        });
        await db.SaveChangesAsync(ct);
        return (token, secret);
    }

    public async Task<ApiToken> RevokeAsync(Guid id, CancellationToken ct = default)
    {
        var token = await db.ApiTokens.FirstOrDefaultAsync(t => t.Id == id, ct) ?? throw AppException.NotFound("API token");
        if (token.RevokedAt is null)
        {
            token.RevokedAt = clock.GetUtcNow();
            token.RevokedBy = actor.Username;
            audit.Record("api_token.revoke", "ApiToken", token.Id.ToString(), details: new { token.Name, token.Prefix });
            await db.SaveChangesAsync(ct);
        }

        return token;
    }

    private Task<bool> NameTakenAsync(string name, CancellationToken ct)
    {
        var pattern = name.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal)
            .Replace("_", "\\_", StringComparison.Ordinal);
        return db.ApiTokens.AnyAsync(t => t.RevokedAt == null && EF.Functions.ILike(t.Name, pattern), ct);
    }
}
