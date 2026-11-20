using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

public static class AgentManagementEndpoints
{
    public static void MapAgentManagementEndpoints(this IEndpointRouteBuilder app)
    {
        // ---------------------------------------------------------------- enrollment tokens
        var tokens = app.MapGroup("/api/v1/enrollment-tokens").WithTags("Agent management").RequireAuthorization(Policies.Operator);

        tokens.MapGet("/", async (Guid? organizationId, bool? includeInactive, EasyPatchDbContext db, ITenantContext tenant, TimeProvider clock,
            CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            var query = db.EnrollmentTokens.AsNoTracking().ForTenant(tenant, t => t.OrganizationId);
            if (organizationId is { } orgId)
            {
                query = query.Where(t => t.OrganizationId == orgId);
            }

            if (includeInactive != true)
            {
                query = query.Where(t => t.RevokedAt == null && t.ExpiresAt > now && t.UseCount < t.MaxUses);
            }

            var rows = await TokenQuery(db, query.OrderByDescending(t => t.CreatedAt).Take(1000)).ToListAsync(ct);
            return TypedResults.Ok(rows.OrderByDescending(r => r.CreatedAt).Select(r => r with { State = TokenState(r, now) }).ToList());
        });

        tokens.MapPost("/", async (CreateTokensRequest request, EnrollmentService enrollment, EasyPatchDbContext db, ITenantContext tenant,
            TimeProvider clock, CancellationToken ct) =>
        {
            tenant.EnsureAccess(request.OrganizationId);
            new Validator().Optional("description", request.Description, 500).ThrowIfInvalid();
            var created = await enrollment.CreateTokensAsync(request.OrganizationId, request.SiteId, Validator.Clean(request.Description),
                request.ExpiresInHours, request.MaxUses, request.Count, ct);
            var ids = created.Select(c => c.Token.Id).ToList();
            var now = clock.GetUtcNow();
            var dtos = await TokenQuery(db, db.EnrollmentTokens.AsNoTracking().Where(t => ids.Contains(t.Id))).ToDictionaryAsync(t => t.Id, ct);
            return TypedResults.Ok(created.Select(c => new CreatedTokenDto(dtos[c.Token.Id] with { State = TokenState(dtos[c.Token.Id], now) },
                c.PlaintextToken)).ToList());
        });

        tokens.MapPost("/{id:guid}/revoke", async (Guid id, EnrollmentService enrollment, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var orgId = await db.EnrollmentTokens.Where(t => t.Id == id).Select(t => (Guid?)t.OrganizationId).FirstOrDefaultAsync(ct)
                        ?? throw AppException.NotFound("Enrollment token");
            tenant.EnsureAccess(orgId);
            await enrollment.RevokeTokenAsync(id, ct);
            return TypedResults.NoContent();
        });

        // ---------------------------------------------------------------- packages
        app.MapGet("/api/v1/agent-packages", (AgentPackageService packages) =>
        {
            var list = packages.List();
            var latest = list.GroupBy(p => (p.Architecture, p.Format))
                .Select(g => g.OrderByDescending(p => Mapping.ParseVersion(p.Version)).First().FileName).ToHashSet();
            return TypedResults.Ok(list.OrderByDescending(p => Mapping.ParseVersion(p.Version)).ThenBy(p => p.Format).ThenBy(p => p.Architecture)
                .Select(p => new AgentPackageDto(p.FileName, p.Version, p.Architecture, p.SizeBytes, p.Sha256, p.ModifiedAt,
                    "/downloads/agent/" + Uri.EscapeDataString(p.FileName), latest.Contains(p.FileName), p.Release?.KeyId, p.SignatureProblem,
                    p.Format)).ToList());
        }).WithTags("Agent management").RequireAuthorization(Policies.Viewer);
    }

    private static IQueryable<EnrollmentTokenDto> TokenQuery(EasyPatchDbContext db, IQueryable<EnrollmentToken> query) =>
        query.Join(db.Organizations, t => t.OrganizationId, o => o.Id, (t, o) => new { t, OrgName = o.Name })
            .Select(x => new EnrollmentTokenDto(x.t.Id, x.t.OrganizationId, x.OrgName, x.t.SiteId,
                db.Sites.Where(s => s.Id == x.t.SiteId).Select(s => s.Name).FirstOrDefault(),
                x.t.TokenPrefix, x.t.Description, x.t.MaxUses, x.t.UseCount, x.t.CreatedAt, x.t.ExpiresAt, x.t.LastUsedAt, x.t.RevokedAt, string.Empty));

    private static string TokenState(EnrollmentTokenDto t, DateTimeOffset now) =>
        t.RevokedAt is not null ? "Revoked" : t.ExpiresAt <= now ? "Expired" : t.UseCount >= t.MaxUses ? "Exhausted" : "Active";
}

/// <summary>Anonymous downloads for agents: agent packages and the pinned winget release.</summary>
public static class DownloadEndpoints
{
    public static void MapDownloadEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/downloads").WithTags("Downloads").AllowAnonymous().RequireRateLimiting(RateLimits.Downloads);

        g.MapGet("/agent/{fileName}", (string fileName, AgentPackageService packages) =>
        {
            var path = packages.GetPath(fileName);
            var contentType = AgentRelease.FormatOf(path is null ? null : Path.GetFileName(path)) switch
            {
                AgentRelease.FormatDeb => "application/vnd.debian.binary-package",
                AgentRelease.FormatRpm => "application/x-rpm",
                AgentRelease.FormatPkg => "application/octet-stream",
                _ => "application/x-msi",
            };
            return path is null
                ? Results.NotFound()
                : Results.File(path, contentType, Path.GetFileName(path), enableRangeProcessing: true);
        });

        // The pinned winget release, for Windows agents that cannot reach GitHub (they verify the SHA-256 themselves too).
        // A file the server does not have yet is requested from the worker, which downloads the release from GitHub.
        g.MapGet("/winget/{fileName}", async (string fileName, WingetMirrorService mirror, EasyPatchDbContext db, TimeProvider clock,
            HttpContext http, CancellationToken ct) =>
        {
            if (mirror.Find(fileName) is not { } file)
            {
                return Results.NotFound();
            }

            if (mirror.GetPath(file) is { } path)
            {
                var contentType = file.Name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ? "application/xml" : "application/octet-stream";
                return Results.File(path, contentType, file.Name, enableRangeProcessing: true);
            }

            await WingetMirrorService.RequestAsync(db, clock.GetUtcNow(), ct);
            http.Response.Headers.RetryAfter = "900";
            return Results.Problem(statusCode: StatusCodes.Status503ServiceUnavailable, title: "winget is not available yet",
                detail: "The server is downloading winget from GitHub. Try again later.",
                extensions: new Dictionary<string, object?> { ["code"] = "winget_not_ready" });
        });
    }
}
