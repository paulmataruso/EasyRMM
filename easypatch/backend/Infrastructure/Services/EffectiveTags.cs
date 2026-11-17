using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Infrastructure.Services;

/// <summary>A tag an endpoint has, and where it comes from (the endpoint itself, its site or its organization).</summary>
public sealed record EffectiveTag(Guid EndpointId, Guid TagId, TagSource Source);

/// <summary>
/// The tags of an endpoint are its own tags plus the tags of its site and of its organization. Everything that acts on tags
/// (tag policies, the endpoint tag filter, alert rule scopes, counts) goes through these helpers.
/// </summary>
public static class EffectiveTags
{
    /// <summary>Endpoints that have the tag, directly or through their site or organization.</summary>
    public static IQueryable<Endpoint> WithTag(this IQueryable<Endpoint> endpoints, EasyPatchDbContext db, Guid tagId)
    {
        ArgumentNullException.ThrowIfNull(db);
        return endpoints.Where(e =>
            db.EndpointTags.Any(et => et.EndpointId == e.Id && et.TagId == tagId) ||
            db.SiteTags.Any(st => st.SiteId == e.SiteId && st.TagId == tagId) ||
            db.OrganizationTags.Any(ot => ot.OrganizationId == e.OrganizationId && ot.TagId == tagId));
    }

    /// <summary>IDs of the endpoints that have the tag (for recalculating compliance after a tag or tag policy changed).</summary>
    public static Task<List<Guid>> EndpointIdsAsync(EasyPatchDbContext db, Guid tagId, CancellationToken ct) =>
        db.Endpoints.AsNoTracking().WithTag(db, tagId).Select(e => e.Id).ToListAsync(ct);

    /// <summary>The tags of the given endpoints. A tag an endpoint has in several ways is listed once, by the most specific
    /// source (endpoint, then site, then organization).</summary>
    public static async Task<List<EffectiveTag>> ForEndpointsAsync(EasyPatchDbContext db, IReadOnlyCollection<Guid> endpointIds, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(endpointIds);
        if (endpointIds.Count == 0)
        {
            return [];
        }

        var ids = endpointIds.Distinct().ToList();
        var endpoints = await db.Endpoints.AsNoTracking().Where(e => ids.Contains(e.Id))
            .Select(e => new EndpointPlacement(e.Id, e.OrganizationId, e.SiteId)).ToListAsync(ct);
        var direct = await db.EndpointTags.AsNoTracking().Where(et => ids.Contains(et.EndpointId)).ToListAsync(ct);
        var siteIds = endpoints.Where(e => e.SiteId != null).Select(e => e.SiteId!.Value).Distinct().ToList();
        var organizationIds = endpoints.Select(e => e.OrganizationId).Distinct().ToList();
        var siteTags = siteIds.Count == 0 ? new List<SiteTag>() : await db.SiteTags.AsNoTracking().Where(st => siteIds.Contains(st.SiteId)).ToListAsync(ct);
        var organizationTags = await db.OrganizationTags.AsNoTracking().Where(ot => organizationIds.Contains(ot.OrganizationId)).ToListAsync(ct);
        return Combine(endpoints, direct, siteTags, organizationTags);
    }

    /// <summary>Merges the three sources (exposed for the policy resolver, which loads them once for all endpoints).</summary>
    public static List<EffectiveTag> Combine(IEnumerable<EndpointPlacement> endpoints, IEnumerable<EndpointTag> direct, IEnumerable<SiteTag> siteTags,
        IEnumerable<OrganizationTag> organizationTags)
    {
        var bySite = siteTags.ToLookup(t => t.SiteId, t => t.TagId);
        var byOrganization = organizationTags.ToLookup(t => t.OrganizationId, t => t.TagId);
        var byEndpoint = direct.ToLookup(t => t.EndpointId, t => t.TagId);
        var result = new List<EffectiveTag>();
        foreach (var endpoint in endpoints)
        {
            var seen = new HashSet<Guid>();
            foreach (var tag in byEndpoint[endpoint.Id].Where(seen.Add))
            {
                result.Add(new EffectiveTag(endpoint.Id, tag, TagSource.Endpoint));
            }

            if (endpoint.SiteId is { } siteId)
            {
                foreach (var tag in bySite[siteId].Where(seen.Add))
                {
                    result.Add(new EffectiveTag(endpoint.Id, tag, TagSource.Site));
                }
            }

            foreach (var tag in byOrganization[endpoint.OrganizationId].Where(seen.Add))
            {
                result.Add(new EffectiveTag(endpoint.Id, tag, TagSource.Organization));
            }
        }

        return result;
    }
}

/// <summary>An endpoint's organization and site.</summary>
public sealed record EndpointPlacement(Guid Id, Guid OrganizationId, Guid? SiteId);
