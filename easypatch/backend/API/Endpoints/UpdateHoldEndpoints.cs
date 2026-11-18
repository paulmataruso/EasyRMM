using System.Security.Claims;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

/// <summary>
/// Update holds: an update on hold is not installed automatically (scheduled installs and "install all"), for one
/// organization or for every organization. The rollout guard creates holds for every organization; administrators hold and
/// release updates for an organization they can access, and super administrators for every organization.
/// </summary>
public static class UpdateHoldEndpoints
{
    public static void MapUpdateHoldEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/update-holds").WithTags("Update management").RequireAuthorization(Policies.Viewer);

        g.MapGet("/", async (Guid? updateGuid, bool? active, EasyPatchDbContext db, ITenantContext tenant, ClaimsPrincipal user, CancellationToken ct) =>
        {
            var query = Visible(db, tenant);
            if (updateGuid is { } guid)
            {
                query = query.Where(h => h.UpdateGuid == guid);
            }

            query = active ?? true ? query.Where(h => h.ReleasedAt == null) : query;
            var holds = await query.OrderByDescending(h => h.CreatedAt).Take(500).ToListAsync(ct);
            return TypedResults.Ok(await ToDtosAsync(db, holds, user, tenant, ct));
        });

        g.MapPost("/{id:guid}/release", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, ClaimsPrincipal user, UpdateHoldService holds,
            CancellationToken ct) =>
        {
            var hold = await db.UpdateHolds.FirstOrDefaultAsync(h => h.Id == id, ct) ?? throw AppException.NotFound("Hold");
            if (hold.OrganizationId is { } org)
            {
                tenant.EnsureAccess(org);
            }
            else if (user.GetRole() != UserRole.SuperAdmin)
            {
                throw AppException.Forbidden("Only super administrators can release a hold that applies to every organization.");
            }

            await holds.ReleaseAsync(hold, ct);
            return TypedResults.Ok((await ToDtosAsync(db, [hold], user, tenant, ct))[0]);
        }).RequireAuthorization(Policies.Operator);

        app.MapPost("/api/v1/updates/{updateGuid:guid}/holds", async (Guid updateGuid, CreateUpdateHoldRequest request, EasyPatchDbContext db,
            ITenantContext tenant, ClaimsPrincipal user, UpdateHoldService holds, CancellationToken ct) =>
        {
            new Validator().Required("reason", request.Reason, 500).ThrowIfInvalid();
            await EnsureCanHoldAsync(db, tenant, user, request.OrganizationId, ct);
            var hold = await holds.HoldAsync(updateGuid, request.OrganizationId, Validator.Clean(request.Reason)!, ct);
            return TypedResults.Created($"/api/v1/update-holds/{hold.Id}", (await ToDtosAsync(db, [hold], user, tenant, ct))[0]);
        }).WithTags("Update management").RequireAuthorization(Policies.Operator);
    }

    /// <summary>Holding for every organization needs a super administrator; for one organization, access to it.</summary>
    public static async Task EnsureCanHoldAsync(EasyPatchDbContext db, ITenantContext tenant, ClaimsPrincipal user, Guid? organizationId, CancellationToken ct)
    {
        if (organizationId is { } org)
        {
            tenant.EnsureAccess(org);
            if (!await db.Organizations.AnyAsync(o => o.Id == org && o.IsActive, ct))
            {
                throw AppException.NotFound("Organization");
            }
        }
        else if (user.GetRole() != UserRole.SuperAdmin)
        {
            throw AppException.Forbidden("Only super administrators can hold an update for every organization. Choose an organization.");
        }
    }

    /// <summary>Holds for every organization and for organizations the administrator can access.</summary>
    public static IQueryable<UpdateHold> Visible(EasyPatchDbContext db, ITenantContext tenant)
    {
        var holds = db.UpdateHolds.AsNoTracking();
        if (tenant.IsUnrestricted)
        {
            return holds;
        }

        var allowed = tenant.AllowedOrganizationIds.ToList();
        return holds.Where(h => h.OrganizationId == null || allowed.Contains(h.OrganizationId.Value));
    }

    public static async Task<List<UpdateHoldDto>> ToDtosAsync(EasyPatchDbContext db, IReadOnlyList<UpdateHold> holds, ClaimsPrincipal user,
        ITenantContext tenant, CancellationToken ct)
    {
        var guids = holds.Select(h => h.UpdateGuid).Distinct().ToList();
        var titles = (await db.Updates.AsNoTracking().Where(u => guids.Contains(u.UpdateGuid))
                .Select(u => new { u.UpdateGuid, u.RevisionNumber, u.Title, u.KbNumbers }).ToListAsync(ct))
            .GroupBy(u => u.UpdateGuid).ToDictionary(g => g.Key, g => g.MaxBy(u => u.RevisionNumber)!);
        var orgIds = holds.Where(h => h.OrganizationId != null).Select(h => h.OrganizationId!.Value).Distinct().ToList();
        var orgs = await db.Organizations.AsNoTracking().Where(o => orgIds.Contains(o.Id)).ToDictionaryAsync(o => o.Id, o => o.Name, ct);
        var superAdmin = user.GetRole() == UserRole.SuperAdmin;
        var operatorRole = user.GetRole() is UserRole.Admin or UserRole.SuperAdmin;
        return holds.Select(h =>
        {
            var u = titles.GetValueOrDefault(h.UpdateGuid);
            var canRelease = h.ReleasedAt is null && operatorRole && (h.OrganizationId is { } org ? tenant.CanAccess(org) : superAdmin);
            return new UpdateHoldDto(h.Id, h.UpdateGuid, u?.Title, u?.KbNumbers.FirstOrDefault(), h.OrganizationId,
                h.OrganizationId is { } o ? orgs.GetValueOrDefault(o) : null, h.Source, h.Reason, h.FailedEndpoints, h.AttemptedEndpoints, h.CreatedAt,
                h.CreatedBy, h.ReleasedAt, h.ReleasedBy, canRelease);
        }).ToList();
    }
}
