using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

/// <summary>API tokens for scripts and integrations, managed by super administrators signed in to the console.</summary>
public static class ApiTokenEndpoints
{
    public static void MapApiTokenEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/api-tokens").WithTags("API tokens").RequireAuthorization(Policies.SuperAdmin);

        g.MapGet("/", async (EasyPatchDbContext db, TimeProvider clock, CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            var tokens = await db.ApiTokens.AsNoTracking().OrderBy(t => t.RevokedAt != null).ThenBy(t => t.Name).ToListAsync(ct);
            return TypedResults.Ok(tokens.Select(t => ToDto(t, now)).ToList());
        });

        g.MapPost("/", async (CreateApiTokenRequest request, ApiTokenService tokens, TimeProvider clock, CancellationToken ct) =>
        {
            var name = Validator.Clean(request.Name);
            new Validator()
                .Required("name", name, ApiTokenService.MaxNameLength)
                .Check(name is null || !name.Any(char.IsControl), "name", "Must not contain control characters.")
                .Check(request.Role is UserRole.ReadOnly or UserRole.Admin, "role", "Must be ReadOnly or Admin.")
                .Range("expiresInDays", request.ExpiresInDays, 1, ApiTokenService.MaxLifetimeDays)
                .Check(request.OrganizationIds is null || request.OrganizationIds.Count <= 500, "organizationIds", "At most 500 organizations.")
                .ThrowIfInvalid();
            var (token, secret) = await tokens.CreateAsync(name!, request.Role, request.OrganizationIds ?? [], request.ExpiresInDays, ct);
            return TypedResults.Created($"/api/v1/api-tokens/{token.Id}", new CreateApiTokenResponse(ToDto(token, clock.GetUtcNow()), secret));
        });

        g.MapPost("/{id:guid}/revoke", async (Guid id, ApiTokenService tokens, TimeProvider clock, CancellationToken ct) =>
            TypedResults.Ok(ToDto(await tokens.RevokeAsync(id, ct), clock.GetUtcNow())));
    }

    private static ApiTokenDto ToDto(ApiToken t, DateTimeOffset now) => new(
        t.Id, t.Name, t.Prefix, t.Role, t.AllOrganizations, t.AllOrganizations ? [] : t.OrganizationIds, t.CreatedAt, t.CreatedBy, t.ExpiresAt,
        t.LastUsedAt, t.LastUsedIp, t.RevokedAt, t.RevokedBy,
        t.RevokedAt is not null ? "Revoked" : t.ExpiresAt <= now ? "Expired" : "Active");
}
