using System.Security.Claims;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

/// <summary>
/// MSP-wide endpoint tags. Tags (and tag policies) are managed by SuperAdmins because a tag can span customers; assigning
/// tags requires an Admin without organization restrictions. Restricted users only see tags used on their endpoints.
/// </summary>
public static class TagEndpoints
{
    public const int MaxTagsPerEndpoint = 20;
    public const int MaxBulkEndpoints = 1000;

    public static void MapTagEndpoints(this IEndpointRouteBuilder app)
    {
        var tags = app.MapGroup("/api/v1/tags").WithTags("Tags").RequireAuthorization(Policies.Viewer);

        tags.MapGet("/", async (EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var query = db.Tags.AsNoTracking();
            if (!tenant.IsUnrestricted)
            {
                var allowed = tenant.AllowedOrganizationIds.ToList();
                query = query.Where(t =>
                    db.EndpointTags.Any(et => et.TagId == t.Id && db.Endpoints.Any(e => e.Id == et.EndpointId && allowed.Contains(e.OrganizationId))) ||
                    db.SiteTags.Any(st => st.TagId == t.Id && db.Sites.Any(s => s.Id == st.SiteId && allowed.Contains(s.OrganizationId))) ||
                    db.OrganizationTags.Any(ot => ot.TagId == t.Id && allowed.Contains(ot.OrganizationId)));
            }

            var rows = await query
                .OrderBy(t => t.Name)
                .Select(t => new
                {
                    Tag = t,
                    // Endpoints with the tag directly or through their site or organization.
                    Endpoints = db.Endpoints.Count(e =>
                        db.EndpointTags.Any(et => et.EndpointId == e.Id && et.TagId == t.Id) ||
                        db.SiteTags.Any(st => st.SiteId == e.SiteId && st.TagId == t.Id) ||
                        db.OrganizationTags.Any(ot => ot.OrganizationId == e.OrganizationId && ot.TagId == t.Id)),
                    Sites = db.SiteTags.Count(st => st.TagId == t.Id),
                    Organizations = db.OrganizationTags.Count(ot => ot.TagId == t.Id),
                    HasPolicy = db.Policies.Any(p => p.Scope == PolicyScope.Tag && p.TagId == t.Id),
                })
                .ToListAsync(ct);
            return TypedResults.Ok(rows.Select(r => tenant.IsUnrestricted
                ? ToDto(r.Tag, r.Endpoints, r.HasPolicy, r.Sites, r.Organizations)
                : ToDto(r.Tag, 0, r.HasPolicy)).ToList());
        });

        tags.MapPost("/", async (TagRequest request, EasyPatchDbContext db, AuditService audit, TimeProvider clock, CancellationToken ct) =>
        {
            var (name, color, description) = Validate(request);
            if (await NameTakenAsync(db, name, null, ct))
            {
                throw AppException.Conflict($"A tag named '{name}' already exists.", "tag_exists");
            }

            var now = clock.GetUtcNow();
            var tag = new Tag
            {
                Id = Guid.CreateVersion7(now),
                Name = name,
                Color = color,
                Description = description,
                Priority = request.Priority,
                CreatedAt = now,
                UpdatedAt = now,
            };
            db.Tags.Add(tag);
            audit.Record("tag.create", "Tag", tag.Id.ToString(), details: new { tag.Name, tag.Color, tag.Priority });
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok(ToDto(tag, 0, false));
        }).RequireAuthorization(Policies.SuperAdmin);

        tags.MapPut("/{id:guid}", async (Guid id, TagRequest request, EasyPatchDbContext db, AuditService audit, ComplianceService compliance,
            TimeProvider clock, CancellationToken ct) =>
        {
            var tag = await db.Tags.FirstOrDefaultAsync(t => t.Id == id, ct) ?? throw AppException.NotFound("Tag");
            var (name, color, description) = Validate(request);
            if (await NameTakenAsync(db, name, id, ct))
            {
                throw AppException.Conflict($"A tag named '{name}' already exists.", "tag_exists");
            }

            // Name and priority decide which tag policy wins on endpoints with several tags.
            var orderingChanged = tag.Priority != request.Priority || !string.Equals(tag.Name, name, StringComparison.Ordinal);
            tag.Name = name;
            tag.Color = color;
            tag.Description = description;
            tag.Priority = request.Priority;
            tag.UpdatedAt = clock.GetUtcNow();
            audit.Record("tag.update", "Tag", id.ToString(), details: new { tag.Name, tag.Color, tag.Priority });
            await db.SaveChangesAsync(ct);
            if (orderingChanged && await db.Policies.AnyAsync(p => p.Scope == PolicyScope.Tag && p.TagId == id, ct))
            {
                await compliance.RecomputeAsync(await TaggedEndpointsAsync(db, id, ct), ct);
            }

            var count = await db.Endpoints.WithTag(db, id).CountAsync(ct);
            var sites = await db.SiteTags.CountAsync(st => st.TagId == id, ct);
            var organizations = await db.OrganizationTags.CountAsync(ot => ot.TagId == id, ct);
            var hasPolicy = await db.Policies.AnyAsync(p => p.Scope == PolicyScope.Tag && p.TagId == id, ct);
            return TypedResults.Ok(ToDto(tag, count, hasPolicy, sites, organizations));
        }).RequireAuthorization(Policies.SuperAdmin);

        tags.MapDelete("/{id:guid}", async (Guid id, EasyPatchDbContext db, AuditService audit, ComplianceService compliance, CancellationToken ct) =>
        {
            var tag = await db.Tags.FirstOrDefaultAsync(t => t.Id == id, ct) ?? throw AppException.NotFound("Tag");
            var affected = await TaggedEndpointsAsync(db, id, ct);
            var hadPolicy = await db.Policies.AnyAsync(p => p.Scope == PolicyScope.Tag && p.TagId == id, ct);
            db.Tags.Remove(tag); // endpoint, site and organization tags and the tag policy cascade
            audit.Record("tag.delete", "Tag", id.ToString(), details: new { tag.Name, Endpoints = affected.Count });
            await db.SaveChangesAsync(ct);
            if (hadPolicy)
            {
                await compliance.RecomputeAsync(affected, ct);
            }

            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.SuperAdmin);

        tags.MapGet("/{id:guid}/policy", async (Guid id, EasyPatchDbContext db, PolicyService policies, CancellationToken ct) =>
        {
            _ = await db.Tags.AnyAsync(t => t.Id == id, ct) ? 0 : throw AppException.NotFound("Tag");
            var policy = await policies.GetTagPolicyAsync(id, ct);
            return TypedResults.Ok(policy is null
                ? OrganizationEndpoints.EmptyPolicy(PolicyScope.Tag, null, null, tagId: id)
                : OrganizationEndpoints.ToDto(policy));
        }).RequireAuthorization(Policies.SuperAdmin);

        tags.MapPut("/{id:guid}/policy", async (Guid id, PolicyRequest request, EasyPatchDbContext db, PolicyService policies, ComplianceService compliance,
            AuditService audit, ClaimsPrincipal user, CancellationToken ct) =>
        {
            _ = await db.Tags.AnyAsync(t => t.Id == id, ct) ? 0 : throw AppException.NotFound("Tag");
            var stored = await policies.UpsertTagPolicyAsync(id, OrganizationEndpoints.FromRequest(request), user.GetUserId(), ct);
            audit.Record("policy.update", "Policy", stored.Id.ToString(), details: new { TagId = id, Policy = request });
            await db.SaveChangesAsync(ct);
            await compliance.RecomputeAsync(await TaggedEndpointsAsync(db, id, ct), ct);
            return TypedResults.Ok(OrganizationEndpoints.ToDto(stored));
        }).RequireAuthorization(Policies.SuperAdmin);

        tags.MapDelete("/{id:guid}/policy", async (Guid id, EasyPatchDbContext db, PolicyService policies, ComplianceService compliance,
            AuditService audit, CancellationToken ct) =>
        {
            if (await policies.DeleteAsync(PolicyScope.Tag, id, ct))
            {
                audit.Record("policy.delete", "Policy", null, details: new { TagId = id });
                await db.SaveChangesAsync(ct);
                await compliance.RecomputeAsync(await TaggedEndpointsAsync(db, id, ct), ct);
            }

            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.SuperAdmin);

        // The tag policies that apply to one endpoint (read-only; used for the "inherited" hints of the endpoint policy editor).
        app.MapGet("/api/v1/endpoints/{id:guid}/tag-policies", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            await EndpointEndpoints.EnsureEndpointAccessAsync(db, tenant, id, ct);
            var tagIds = (await EffectiveTags.ForEndpointsAsync(db, [id], ct)).Select(t => t.TagId).ToList();
            var rows = await (from t in db.Tags.AsNoTracking()
                              join p in db.Policies.AsNoTracking() on t.Id equals p.TagId
                              where tagIds.Contains(t.Id) && p.Scope == PolicyScope.Tag
                              select new { Tag = t, Policy = p }).ToListAsync(ct);
            var byName = rows.ToDictionary(r => r.Tag.Name, StringComparer.OrdinalIgnoreCase);
            var ordered = PolicyResolver.OrderTags(rows.Select(r => new TagPolicyLayer(r.Tag.Name, r.Tag.Priority, r.Policy)))
                .Select(l => byName[l.TagName])
                .Select(r => new TagPolicyLayerDto(new TagRefDto(r.Tag.Id, r.Tag.Name, r.Tag.Color), r.Tag.Priority, OrganizationEndpoints.ToDto(r.Policy)))
                .ToList();
            return TypedResults.Ok(ordered);
        }).WithTags("Tags").RequireAuthorization(Policies.Viewer);

        // Tags on an organization or a site apply to every endpoint in it (for example a pilot customer or office).
        app.MapPut("/api/v1/organizations/{id:guid}/tags", async (Guid id, TagAssignmentRequest request, EasyPatchDbContext db, ITenantContext tenant,
            AuditService audit, ComplianceService compliance, TimeProvider clock, CancellationToken ct) =>
        {
            EnsureCanAssign(tenant);
            _ = await db.Organizations.AnyAsync(o => o.Id == id, ct) ? 0 : throw AppException.NotFound("Organization");
            var now = clock.GetUtcNow();
            var current = await db.OrganizationTags.Where(t => t.OrganizationId == id).ToListAsync(ct);
            var (added, removed) = await ReplaceAsync(db, db.OrganizationTags, current, l => l.TagId, request.TagIds,
                t => new OrganizationTag { OrganizationId = id, TagId = t, CreatedAt = now }, ct);
            if (added.Count == 0 && removed.Count == 0)
            {
                return TypedResults.NoContent();
            }

            audit.Record("organization.tags_update", "Organization", id.ToString(), id, details: new { Added = added, Removed = removed });
            await db.SaveChangesAsync(ct);
            await RecomputeIfPolicyTagsChangedAsync(db, compliance, db.Endpoints.Where(e => e.OrganizationId == id), [.. added, .. removed], ct);
            return TypedResults.NoContent();
        }).WithTags("Tags").RequireAuthorization(Policies.Operator);

        app.MapPut("/api/v1/sites/{id:guid}/tags", async (Guid id, TagAssignmentRequest request, EasyPatchDbContext db, ITenantContext tenant,
            AuditService audit, ComplianceService compliance, TimeProvider clock, CancellationToken ct) =>
        {
            EnsureCanAssign(tenant);
            var site = await db.Sites.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct) ?? throw AppException.NotFound("Site");
            var now = clock.GetUtcNow();
            var current = await db.SiteTags.Where(t => t.SiteId == id).ToListAsync(ct);
            var (added, removed) = await ReplaceAsync(db, db.SiteTags, current, l => l.TagId, request.TagIds,
                t => new SiteTag { SiteId = id, TagId = t, CreatedAt = now }, ct);
            if (added.Count == 0 && removed.Count == 0)
            {
                return TypedResults.NoContent();
            }

            audit.Record("site.tags_update", "Site", id.ToString(), site.OrganizationId, details: new { Added = added, Removed = removed });
            await db.SaveChangesAsync(ct);
            await RecomputeIfPolicyTagsChangedAsync(db, compliance, db.Endpoints.Where(e => e.SiteId == id), [.. added, .. removed], ct);
            return TypedResults.NoContent();
        }).WithTags("Tags").RequireAuthorization(Policies.Operator);

        var endpoints = app.MapGroup("/api/v1/endpoints").WithTags("Tags").RequireAuthorization(Policies.Operator);

        endpoints.MapPut("/{id:guid}/tags", async (Guid id, EndpointTagsRequest request, EasyPatchDbContext db, ITenantContext tenant,
            AuditService audit, ComplianceService compliance, TimeProvider clock, CancellationToken ct) =>
        {
            EnsureCanAssign(tenant);
            var endpoint = await db.Endpoints.AsNoTracking().FirstOrDefaultAsync(e => e.Id == id, ct) ?? throw AppException.NotFound("Endpoint");
            var wanted = (request.TagIds ?? []).Distinct().ToList();
            if (wanted.Count > MaxTagsPerEndpoint)
            {
                throw AppException.BadRequest($"An endpoint can have at most {MaxTagsPerEndpoint} tags.", "validation_failed");
            }

            await EnsureTagsExistAsync(db, wanted, ct);
            var current = await db.EndpointTags.Where(et => et.EndpointId == id).ToListAsync(ct);
            var removed = current.Where(et => !wanted.Contains(et.TagId)).ToList();
            var added = wanted.Where(t => current.All(et => et.TagId != t)).ToList();
            if (removed.Count == 0 && added.Count == 0)
            {
                return TypedResults.NoContent();
            }

            var now = clock.GetUtcNow();
            db.EndpointTags.RemoveRange(removed);
            db.EndpointTags.AddRange(added.Select(t => new EndpointTag { EndpointId = id, TagId = t, CreatedAt = now }));
            audit.Record("endpoint.tags_update", "Endpoint", id.ToString(), endpoint.OrganizationId, id,
                new { Added = added, Removed = removed.Select(r => r.TagId).ToList() });
            await db.SaveChangesAsync(ct);
            await compliance.RecomputeAsync([id], ct);
            return TypedResults.NoContent();
        });

        endpoints.MapPost("/tags/bulk", async (BulkEndpointTagsRequest request, EasyPatchDbContext db, ITenantContext tenant,
            AuditService audit, ComplianceService compliance, TimeProvider clock, CancellationToken ct) =>
        {
            EnsureCanAssign(tenant);
            var endpointIds = (request.EndpointIds ?? []).Distinct().ToList();
            var add = (request.AddTagIds ?? []).Distinct().ToList();
            var remove = (request.RemoveTagIds ?? []).Distinct().Where(t => !add.Contains(t)).ToList();
            if (endpointIds.Count == 0 || (add.Count == 0 && remove.Count == 0))
            {
                throw AppException.BadRequest("Select endpoints and at least one tag to add or remove.", "validation_failed");
            }

            if (endpointIds.Count > MaxBulkEndpoints)
            {
                throw AppException.BadRequest($"At most {MaxBulkEndpoints} endpoints can be changed at once.", "validation_failed");
            }

            await EnsureTagsExistAsync(db, add.Concat(remove).ToList(), ct);
            var existingEndpoints = await db.Endpoints.AsNoTracking().Where(e => endpointIds.Contains(e.Id)).Select(e => e.Id).ToListAsync(ct);
            var links = await db.EndpointTags.Where(et => existingEndpoints.Contains(et.EndpointId)).ToListAsync(ct);
            var linksByEndpoint = links.ToLookup(l => l.EndpointId);
            var now = clock.GetUtcNow();
            var changed = new List<Guid>();
            foreach (var endpointId in existingEndpoints)
            {
                var current = linksByEndpoint[endpointId].ToList();
                var toRemove = current.Where(l => remove.Contains(l.TagId)).ToList();
                var toAdd = add.Where(t => current.All(l => l.TagId != t)).ToList();
                if (current.Count - toRemove.Count + toAdd.Count > MaxTagsPerEndpoint)
                {
                    throw AppException.BadRequest($"An endpoint can have at most {MaxTagsPerEndpoint} tags.", "validation_failed");
                }

                if (toRemove.Count == 0 && toAdd.Count == 0)
                {
                    continue;
                }

                db.EndpointTags.RemoveRange(toRemove);
                db.EndpointTags.AddRange(toAdd.Select(t => new EndpointTag { EndpointId = endpointId, TagId = t, CreatedAt = now }));
                changed.Add(endpointId);
            }

            if (changed.Count > 0)
            {
                audit.Record("endpoint.tags_bulk_update", "Endpoint", null,
                    details: new { Endpoints = changed.Count, AddTagIds = add, RemoveTagIds = remove });
                await db.SaveChangesAsync(ct);
                await compliance.RecomputeAsync(changed, ct);
            }

            return TypedResults.Ok(new BulkEndpointTagsResult(changed.Count));
        });
    }

    internal static TagDto ToDto(Tag t, int endpointCount, bool hasPolicy, int siteCount = 0, int organizationCount = 0) =>
        new(t.Id, t.Name, t.Color, t.Description, t.Priority, endpointCount, hasPolicy, t.CreatedAt, siteCount, organizationCount);

    private static (string Name, string Color, string? Description) Validate(TagRequest request)
    {
        var name = request.Name?.Trim() ?? "";
        if (name.Length == 0 || name.Length > Tag.MaxNameLength)
        {
            throw AppException.BadRequest($"Tag name must be 1-{Tag.MaxNameLength} characters.", "validation_failed");
        }

        if (name.Any(char.IsControl))
        {
            throw AppException.BadRequest("Tag name contains invalid characters.", "validation_failed");
        }

        if (!TagColors.IsValid(request.Color))
        {
            throw AppException.BadRequest($"Color must be one of: {string.Join(", ", TagColors.All)}.", "validation_failed");
        }

        if (request.Priority is < 0 or > 1000)
        {
            throw AppException.BadRequest("Priority must be between 0 and 1000.", "validation_failed");
        }

        var description = string.IsNullOrWhiteSpace(request.Description) ? null : request.Description.Trim();
        if (description is { Length: > 500 })
        {
            throw AppException.BadRequest("Description must be at most 500 characters.", "validation_failed");
        }

        return (name, request.Color, description);
    }

    private static Task<bool> NameTakenAsync(EasyPatchDbContext db, string name, Guid? exceptId, CancellationToken ct)
    {
        var pattern = OrganizationEndpoints.EscapeLike(name);
        return db.Tags.AnyAsync(t => EF.Functions.ILike(t.Name, pattern) && t.Id != exceptId, ct);
    }

    private static async Task EnsureTagsExistAsync(EasyPatchDbContext db, IReadOnlyList<Guid> tagIds, CancellationToken ct)
    {
        if (tagIds.Count == 0)
        {
            return;
        }

        var found = await db.Tags.CountAsync(t => tagIds.Contains(t.Id), ct);
        if (found != tagIds.Count)
        {
            throw AppException.NotFound("Tag");
        }
    }

    /// <summary>Endpoints with the tag, directly or through their site or organization.</summary>
    private static Task<List<Guid>> TaggedEndpointsAsync(EasyPatchDbContext db, Guid tagId, CancellationToken ct) =>
        EffectiveTags.EndpointIdsAsync(db, tagId, ct);

    /// <summary>Replaces the tags of an organization or site. Returns the tags added and removed.</summary>
    private static async Task<(List<Guid> Added, List<Guid> Removed)> ReplaceAsync<TLink>(EasyPatchDbContext db, DbSet<TLink> set,
        List<TLink> current, Func<TLink, Guid> tagOf, IReadOnlyList<Guid>? requested, Func<Guid, TLink> create, CancellationToken ct)
        where TLink : class
    {
        var wanted = (requested ?? []).Distinct().ToList();
        if (wanted.Count > MaxTagsPerEndpoint)
        {
            throw AppException.BadRequest($"An organization or site can have at most {MaxTagsPerEndpoint} tags.", "validation_failed");
        }

        await EnsureTagsExistAsync(db, wanted, ct);
        var removed = current.Where(l => !wanted.Contains(tagOf(l))).ToList();
        var added = wanted.Where(t => current.All(l => tagOf(l) != t)).ToList();
        set.RemoveRange(removed);
        set.AddRange(added.Select(create));
        return (added, removed.Select(tagOf).ToList());
    }

    /// <summary>Recalculates compliance of the endpoints in an organization or site when a tag with a policy was added or removed.</summary>
    private static async Task RecomputeIfPolicyTagsChangedAsync(EasyPatchDbContext db, ComplianceService compliance, IQueryable<EasyPatch.Core.Entities.Endpoint> endpoints,
        List<Guid> changedTags, CancellationToken ct)
    {
        if (changedTags.Count > 0 && await db.Policies.AnyAsync(p => p.Scope == PolicyScope.Tag && p.TagId != null && changedTags.Contains(p.TagId.Value), ct))
        {
            await compliance.RecomputeAsync(await endpoints.Select(e => e.Id).ToListAsync(ct), ct);
        }
    }

    private static void EnsureCanAssign(ITenantContext tenant)
    {
        // Tags span customers and may carry SuperAdmin-defined policy; organization-restricted admins can only view them.
        if (!tenant.IsUnrestricted)
        {
            throw AppException.Forbidden("Only administrators without organization restrictions can assign tags.");
        }
    }
}
