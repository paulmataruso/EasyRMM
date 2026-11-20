using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using EndpointEntity = EasyPatch.Core.Entities.Endpoint;

namespace EasyPatch.Api.Endpoints;

/// <summary>"Restart all that need it" for an organization or one of its sites: the endpoints whose operating system reports a
/// pending restart. EasyRMM lists them first, then restarts the ones the administrator confirms through <c>bulk/restart</c>, on
/// condition that a restart is still pending when the agent gets the job. Each restart is the explicit administrator action that
/// EasyPatch requires; nothing restarts on its own.</summary>
public static class RestartPendingEndpoints
{
    public const int MaxEndpoints = 1000;

    public static void MapRestartPendingEndpoints(this IEndpointRouteBuilder app)
    {
        var orgs = app.MapGroup("/api/v1/organizations").WithTags("Organizations").RequireAuthorization(Policies.Viewer);

        orgs.MapGet("/{id:guid}/restart-pending", async (Guid id, Guid? siteId, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            await EnsureScopeAsync(db, tenant, id, siteId, ct);
            var query = Pending(db, id, siteId);
            var total = await query.CountAsync(ct);
            var endpoints = await query.OrderBy(e => e.Hostname).Take(MaxEndpoints)
                .Select(e => new
                {
                    e.Id, e.Hostname, e.SiteId, SiteName = e.Site != null ? e.Site.Name : null, e.Platform, e.OperatingSystem, e.OsProductType,
                    e.IsOnline, e.RebootPendingSince, e.AgentCapabilities,
                })
                .ToListAsync(ct);
            return TypedResults.Ok(new RestartPendingDto(total, endpoints
                .Select(e => new RestartPendingEndpointDto(e.Id, e.Hostname, e.SiteId, e.SiteName, e.Platform, e.OperatingSystem,
                    e.OsProductType is "Server" or "DomainController", e.IsOnline, e.RebootPendingSince,
                    e.AgentCapabilities.Contains(AgentCapabilities.Restart)))
                .ToList()));
        });

    }

    private static IQueryable<EndpointEntity> Pending(EasyPatchDbContext db, Guid organizationId, Guid? siteId)
    {
        var query = db.Endpoints.AsNoTracking()
            .Where(e => e.OrganizationId == organizationId && e.Status == EndpointStatus.Active && e.RebootPending);
        return siteId is { } site ? query.Where(e => e.SiteId == site) : query;
    }

    private static async Task EnsureScopeAsync(EasyPatchDbContext db, ITenantContext tenant, Guid organizationId, Guid? siteId, CancellationToken ct)
    {
        tenant.EnsureAccess(organizationId);
        if (!await db.Organizations.AnyAsync(o => o.Id == organizationId, ct))
        {
            throw AppException.NotFound("Organization");
        }

        if (siteId is { } site && !await db.Sites.AnyAsync(s => s.Id == site && s.OrganizationId == organizationId, ct))
        {
            throw AppException.NotFound("Site");
        }
    }
}
