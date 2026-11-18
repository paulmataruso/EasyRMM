using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Vulnerabilities;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Infrastructure.Services;

/// <summary>Recomputes per-update requirement flags, endpoint compliance counters and OS support status.</summary>
public sealed class ComplianceService(EasyPatchDbContext db, PolicyService policies, VulnerabilityMatcher vulnerabilities, TimeProvider clock)
{
    /// <summary>Recomputes and saves (per chunk) the given endpoints: CVE exposure and known-exploited flags, requirement
    /// flags, counters and OS support status. Callers save their own pending changes first.</summary>
    public async Task RecomputeAsync(IReadOnlyCollection<Guid> endpointIds, CancellationToken ct = default)
    {
        if (endpointIds.Count == 0)
        {
            return;
        }

        var resolver = await policies.CreateResolverAsync(ct);
        var lifecycle = await db.OsLifecycleEntries.AsNoTracking().ToListAsync(ct);
        var now = clock.GetUtcNow();
        var changedUpdates = new HashSet<Guid>();
        foreach (var chunk in endpointIds.Distinct().Chunk(200))
        {
            var endpoints = await db.Endpoints.Where(e => chunk.Contains(e.Id)).ToListAsync(ct);
            var updates = await db.EndpointUpdates.Include(u => u.Update)
                .Where(u => chunk.Contains(u.EndpointId)).ToListAsync(ct);
            var exclusions = await db.UpdateExclusions.AsNoTracking()
                .Where(x => chunk.Contains(x.EndpointId)).Select(x => new { x.EndpointId, x.UpdateGuid }).ToListAsync(ct);
            var updatesByEndpoint = updates.ToLookup(u => u.EndpointId);
            var exclusionsByEndpoint = exclusions.ToLookup(x => x.EndpointId, x => x.UpdateGuid);
            changedUpdates.UnionWith(await vulnerabilities.ApplyAsync(endpoints, updatesByEndpoint, ct));
            foreach (var endpoint in endpoints)
            {
                var policy = resolver(endpoint.OrganizationId, endpoint.SiteId, endpoint.Id);
                ApplyRequirementFlags(updatesByEndpoint[endpoint.Id], exclusionsByEndpoint[endpoint.Id].ToHashSet(), policy, now);
                ApplyCounts(endpoint, updatesByEndpoint[endpoint.Id], policy, now);
                ApplyLifecycle(endpoint, lifecycle, now);
            }

            await db.SaveChangesAsync(ct);
        }

        await vulnerabilities.RefreshUpdateSummariesAsync(changedUpdates, ct);
    }

    /// <summary>Recomputes all endpoints in an organization (or site) after a policy change.</summary>
    public async Task RecomputeScopeAsync(Guid? organizationId, Guid? siteId, CancellationToken ct = default)
    {
        var query = db.Endpoints.AsNoTracking().Where(e => e.Status == EndpointStatus.Active);
        if (siteId is { } s)
        {
            query = query.Where(e => e.SiteId == s);
        }
        else if (organizationId is { } o)
        {
            query = query.Where(e => e.OrganizationId == o);
        }

        var ids = await query.Select(e => e.Id).ToListAsync(ct);
        await RecomputeAsync(ids, ct);
    }

    public static void ApplyRequirementFlags(IEnumerable<EndpointUpdate> updates, IReadOnlySet<Guid> excludedGuids, EffectivePolicy policy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(policy);
        var filter = policy.ToFilter(excludedGuids);
        foreach (var u in updates)
        {
            if (u.Update is null)
            {
                continue;
            }

            var decision = UpdateRequirement.Evaluate(u.Update, u, policy, filter, now);
            u.IsExcluded = decision.Excluded;
            u.IsRequired = decision.Required;
            u.DeferredUntil = UpdateReconciler.IsOutstanding(u.State) ? decision.DeferredUntil : null;
            var next = u.State;
            if (decision.Excluded && u.State is EndpointUpdateState.Missing or EndpointUpdateState.Failed)
            {
                next = EndpointUpdateState.Excluded;
            }
            else if (!decision.Excluded && u.State == EndpointUpdateState.Excluded)
            {
                next = u.FailedAttempts > 0 ? EndpointUpdateState.Failed : EndpointUpdateState.Missing;
                u.DeferredUntil = decision.DeferredUntil;
            }

            if (next != u.State)
            {
                u.State = next;
                u.StateChangedAt = now;
            }
        }
    }

    public static void ApplyCounts(Endpoint endpoint, IEnumerable<EndpointUpdate> updates, EffectivePolicy policy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(policy);
        var counts = ComplianceCalculator.Count(updates);
        endpoint.MissingRequiredCount = counts.MissingRequired;
        endpoint.MissingTotalCount = counts.MissingTotal;
        endpoint.FailedCount = counts.Failed;
        endpoint.InstalledCount = counts.Installed;
        endpoint.PendingRebootUpdateCount = counts.PendingReboot;
        endpoint.MissingDeferredCount = counts.MissingDeferred;
        endpoint.KnownExploitedMissingCount = counts.KnownExploitedMissing;
        endpoint.ComplianceStatus = ComplianceCalculator.Evaluate(endpoint.LastScanAt, endpoint.RebootPending, counts, policy.ScanStaleAfterHours, now);
        endpoint.ComplianceEvaluatedAt = now;
    }

    /// <summary>Re-evaluates status from stored counters (for reboot-flag or staleness changes without a scan).</summary>
    public static void ReevaluateStatus(Endpoint endpoint, EffectivePolicy policy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(policy);
        var counts = new UpdateCounts(endpoint.MissingRequiredCount, endpoint.MissingTotalCount, endpoint.FailedCount,
            endpoint.InstalledCount, endpoint.PendingRebootUpdateCount, endpoint.MissingDeferredCount);
        endpoint.ComplianceStatus = ComplianceCalculator.Evaluate(endpoint.LastScanAt, endpoint.RebootPending, counts, policy.ScanStaleAfterHours, now);
        endpoint.ComplianceEvaluatedAt = now;
    }

    public static void ApplyLifecycle(Endpoint endpoint, IReadOnlyList<OsLifecycleEntry> lifecycle, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var today = DateOnly.FromDateTime(now.UtcDateTime);
        var result = endpoint.Platform switch
        {
            EasyPatch.Contracts.Agent.AgentPlatforms.Linux =>
                LifecycleEvaluator.EvaluateLinux(lifecycle, endpoint.OsId, endpoint.OsVersion, endpoint.EsuLicenseDetected, endpoint.EsuOverride, today),
            // Apple publishes no end-of-support dates for macOS releases, so their support status stays unknown.
            EasyPatch.Contracts.Agent.AgentPlatforms.MacOS => new LifecycleResult(OsSupportStatus.Unknown, null, "macOS", "Any", null),
            _ => LifecycleEvaluator.Evaluate(lifecycle, endpoint.OsBuildNumber, endpoint.OsEdition, endpoint.OsProductType,
                endpoint.EsuLicenseDetected, endpoint.EsuOverride, today),
        };
        endpoint.OsSupportStatus = result.Status;
        endpoint.OsEndOfServicing = result.EndOfServicing;
    }
}
