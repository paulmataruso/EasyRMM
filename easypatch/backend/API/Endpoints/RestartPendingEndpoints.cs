using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using EndpointEntity = EasyPatch.Core.Entities.Endpoint;

namespace EasyPatch.Api.Endpoints;

/// <summary>"Restart all that need it" for an organization or one of its sites: the endpoints whose operating system reports a
/// pending restart. The console lists them first; the administrator's confirmation restarts exactly that list, and only the
/// endpoints that are still in the scope and still report a pending restart. Each restart is the explicit administrator action
/// that EasyPatch requires; nothing restarts on its own.</summary>
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

        orgs.MapPost("/{id:guid}/restart-pending", async (Guid id, RestartPendingRequest request, EasyPatchDbContext db, ITenantContext tenant,
            JobService jobs, TimeProvider clock, CancellationToken ct) =>
        {
            await EnsureScopeAsync(db, tenant, id, request.SiteId, ct);
            var ids = (request.EndpointIds ?? []).Distinct().ToList();
            if (ids.Count is 0 or > MaxEndpoints)
            {
                throw AppException.BadRequest($"Select between 1 and {MaxEndpoints} endpoints.", "validation_failed");
            }

            ArgumentNullException.ThrowIfNull(request.Restart);
            // The agent checks again when the job arrives and completes without restarting if nothing is pending any more.
            var restart = request.Restart with { Condition = RestartCondition.OnlyIfPending };
            var now = clock.GetUtcNow();
            var endpoints = await db.Endpoints.AsNoTracking().Where(e => ids.Contains(e.Id))
                .Select(e => new { e.Id, e.Hostname, e.OrganizationId, e.SiteId, e.Status, e.RebootPending })
                .ToDictionaryAsync(e => e.Id, ct);
            var results = new List<BulkItemResult>();
            foreach (var endpointId in ids)
            {
                if (!endpoints.TryGetValue(endpointId, out var e) || e.OrganizationId != id || (request.SiteId is { } site && e.SiteId != site) ||
                    e.Status != EndpointStatus.Active)
                {
                    results.Add(new BulkItemResult(endpointId, null, false, null, "out_of_scope",
                        request.SiteId is null ? "Not an active endpoint of this organization." : "Not an active endpoint of this site."));
                    continue;
                }

                if (!e.RebootPending)
                {
                    results.Add(new BulkItemResult(endpointId, e.Hostname, false, null, "no_restart_pending",
                        "No longer reports a pending restart, so it was not restarted."));
                    continue;
                }

                try
                {
                    var job = await jobs.CreateAsync(EndpointEndpoints.RestartJob(endpointId, restart, now), ct);
                    results.Add(new BulkItemResult(endpointId, e.Hostname, true, job.Id, null, null));
                }
                catch (AppException ex)
                {
                    db.ChangeTracker.Clear();
                    var existing = ex.Extensions.TryGetValue("existingJobId", out var value) ? value as Guid? : null;
                    results.Add(new BulkItemResult(endpointId, e.Hostname, false, existing, ex.Code, ex.Message));
                }
            }

            return TypedResults.Ok(new BulkResultDto(results.Count(r => r.Success), results.Count(r => !r.Success), results));
        }).RequireAuthorization(Policies.Operator);
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
