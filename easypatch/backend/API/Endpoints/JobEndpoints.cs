using System.Security.Claims;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

public sealed record JobListQuery(
    Guid? EndpointId, Guid? OrganizationId, JobStatus? Status, JobType? Type, JobTrigger? Trigger, bool? Active, DateTimeOffset? From, DateTimeOffset? To,
    int? Page, int? PageSize);

public static class JobEndpoints
{
    public static void MapJobEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/jobs").WithTags("Jobs").RequireAuthorization(Policies.Viewer);

        g.MapGet("/", async ([AsParameters] JobListQuery q, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var query = db.Jobs.AsNoTracking().ForTenant(tenant, j => j.OrganizationId);
            if (q.EndpointId is { } endpointId)
            {
                query = query.Where(j => j.EndpointId == endpointId);
            }

            if (q.OrganizationId is { } orgId)
            {
                query = query.Where(j => j.OrganizationId == orgId);
            }

            if (q.Status is { } status)
            {
                query = query.Where(j => j.Status == status);
            }

            if (q.Active == true)
            {
                query = query.Where(j => j.Status == JobStatus.Queued || j.Status == JobStatus.Delivered || j.Status == JobStatus.Acknowledged ||
                                         j.Status == JobStatus.Running || j.Status == JobStatus.WaitingForReboot);
            }

            if (q.Type is { } type)
            {
                query = query.Where(j => j.Type == type);
            }

            if (q.Trigger is { } trigger)
            {
                query = query.Where(j => j.Trigger == trigger);
            }

            if (q.From is { } from)
            {
                query = query.Where(j => j.CreatedAt >= from);
            }

            if (q.To is { } to)
            {
                query = query.Where(j => j.CreatedAt < to);
            }

            return TypedResults.Ok(await query.OrderByDescending(j => j.CreatedAt).Select(Mapping.JobSummary).ToPagedAsync(PageRequest.From(q.Page, q.PageSize), ct));
        });

        g.MapGet("/{id:guid}", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
            TypedResults.Ok(await LoadDetailAsync(db, tenant, id, ct)));

        g.MapDelete("/{id:guid}", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, CancellationToken ct) =>
        {
            await EnsureAccessAsync(db, tenant, id, ct);
            await jobs.CancelAsync(id, ct);
            return TypedResults.Ok(await LoadDetailAsync(db, tenant, id, ct));
        }).RequireAuthorization(Policies.Operator);

        g.MapPost("/{id:guid}/cancel", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, CancellationToken ct) =>
        {
            await EnsureAccessAsync(db, tenant, id, ct);
            await jobs.CancelAsync(id, ct);
            return TypedResults.Ok(await LoadDetailAsync(db, tenant, id, ct));
        }).RequireAuthorization(Policies.Operator);

        g.MapPost("/{id:guid}/retry", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, CancellationToken ct) =>
        {
            await EnsureAccessAsync(db, tenant, id, ct);
            var job = await jobs.RetryAsync(id, ct);
            return TypedResults.Accepted($"/api/v1/jobs/{job.Id}", await LoadSummaryAsync(db, job.Id, ct));
        }).RequireAuthorization(Policies.Operator);
    }

    internal static Task<JobSummaryDto> LoadSummaryAsync(EasyPatchDbContext db, Guid id, CancellationToken ct) =>
        db.Jobs.AsNoTracking().Where(j => j.Id == id).Select(Mapping.JobSummary).FirstAsync(ct);

    private static async Task EnsureAccessAsync(EasyPatchDbContext db, ITenantContext tenant, Guid id, CancellationToken ct)
    {
        var orgId = await db.Jobs.AsNoTracking().Where(j => j.Id == id).Select(j => (Guid?)j.OrganizationId).FirstOrDefaultAsync(ct)
                    ?? throw AppException.NotFound("Job");
        tenant.EnsureAccess(orgId);
    }

    private static async Task<JobDetailDto> LoadDetailAsync(EasyPatchDbContext db, ITenantContext tenant, Guid id, CancellationToken ct)
    {
        var job = await db.Jobs.AsNoTracking().Where(j => j.Id == id)
            .Select(j => new
            {
                Summary = new JobSummaryDto(j.Id, j.EndpointId, j.Endpoint!.Hostname, j.OrganizationId, j.Endpoint.Organization!.Name, j.Type, j.Status,
                    j.Trigger, j.RequestedBy, j.CreatedAt, j.StartedAt, j.CompletedAt, j.ExpiresAt, j.ProgressPercent, j.Phase, j.ProgressMessage,
                    j.ErrorCode, j.ErrorMessage, j.RebootRequired, j.TimedOut, j.CancelRequestedAt != null, j.Updates.Count,
                    j.Updates.Count(u => u.Status == JobItemStatus.Succeeded), j.Updates.Count(u => u.Status == JobItemStatus.Failed)),
                j.Payload, j.NotBefore, j.DeliveredAt, j.AcknowledgedAt, j.LastProgressAt, j.DeliveryCount, j.RetryOfJobId, j.CancelRequestedAt,
            }).FirstOrDefaultAsync(ct) ?? throw AppException.NotFound("Job");
        tenant.EnsureAccess(job.Summary.OrganizationId);
        var items = await db.Set<JobUpdate>().AsNoTracking().Where(u => u.JobId == id).OrderBy(u => u.StartedAt == null).ThenBy(u => u.StartedAt)
            .ThenBy(u => u.Title).Select(Mapping.JobItem).ToListAsync(ct);
        var events = await db.EndpointEvents.AsNoTracking().Where(e => e.JobId == id).OrderBy(e => e.Id).Select(Mapping.Event).ToListAsync(ct);
        InstallMode? mode = null;
        if (job.Summary.Type is JobType.InstallUpdates or JobType.DownloadUpdates && job.Payload is not null)
        {
            mode = JsonSerializer.Deserialize<InstallUpdatesPayload>(job.Payload, ContractJson.Options)?.Mode;
        }

        return new JobDetailDto(job.Summary, mode, job.NotBefore, job.DeliveredAt, job.AcknowledgedAt, job.LastProgressAt, job.DeliveryCount,
            job.RetryOfJobId, job.CancelRequestedAt, items, events);
    }
}

public sealed record FleetUpdateQuery(Guid? OrganizationId, Guid? SiteId, UpdateCategory? Category, EndpointUpdateState? State, string? Search, string? Sort,
    string? Dir, int? Page, int? PageSize, bool? KnownExploited = null);

public static class FleetUpdateEndpoints
{
    public static void MapFleetUpdateEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/updates").WithTags("Update management").RequireAuthorization(Policies.Viewer);

        g.MapGet("/", async ([AsParameters] FleetUpdateQuery q, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var rows = Scope(db, tenant, q.OrganizationId, q.SiteId);
            if (q.Category is { } category)
            {
                rows = rows.Where(u => u.Update!.Category == category);
            }

            if (Validator.Clean(q.Search) is { } search)
            {
                var pattern = "%" + OrganizationEndpoints.EscapeLike(search) + "%";
                rows = rows.Where(u => EF.Functions.ILike(u.Update!.Title, pattern) || u.Update.KbNumbers.Any(k => EF.Functions.ILike(k, pattern)));
            }

            var grouped = rows.GroupBy(u => u.UpdateGuid).Select(gr => new
            {
                UpdateGuid = gr.Key,
                Missing = gr.Count(u => u.State == EndpointUpdateState.Missing),
                Failed = gr.Count(u => u.State == EndpointUpdateState.Failed),
                Installed = gr.Count(u => u.State == EndpointUpdateState.Installed),
                PendingReboot = gr.Count(u => u.State == EndpointUpdateState.PendingReboot || u.State == EndpointUpdateState.PendingVerification),
                Excluded = gr.Count(u => u.State == EndpointUpdateState.Excluded || u.IsExcluded),
                KnownExploited = gr.Count(u => u.KnownExploited),
                Reoffered = gr.Count(u => u.State == EndpointUpdateState.Reoffered),
            });
            if (q.KnownExploited is { } exploited)
            {
                grouped = exploited ? grouped.Where(x => x.KnownExploited > 0) : grouped.Where(x => x.KnownExploited == 0);
            }

            grouped = q.State switch
            {
                EndpointUpdateState.Missing => grouped.Where(x => x.Missing > 0),
                EndpointUpdateState.Failed => grouped.Where(x => x.Failed > 0),
                EndpointUpdateState.Installed => grouped.Where(x => x.Installed > 0),
                EndpointUpdateState.PendingReboot or EndpointUpdateState.PendingVerification => grouped.Where(x => x.PendingReboot > 0),
                EndpointUpdateState.Excluded => grouped.Where(x => x.Excluded > 0),
                EndpointUpdateState.Reoffered => grouped.Where(x => x.Reoffered > 0),
                _ => grouped.Where(x => x.Missing > 0 || x.Failed > 0 || x.PendingReboot > 0 || x.Reoffered > 0),
            };
            var desc = q.Dir is null || PagingExtensions.IsDescending(q.Dir);
            grouped = (q.Sort?.ToLowerInvariant()) switch
            {
                "failed" => desc ? grouped.OrderByDescending(x => x.Failed) : grouped.OrderBy(x => x.Failed),
                "installed" => desc ? grouped.OrderByDescending(x => x.Installed) : grouped.OrderBy(x => x.Installed),
                "missing" => desc ? grouped.OrderByDescending(x => x.Missing + x.Failed) : grouped.OrderBy(x => x.Missing + x.Failed),
                // Default: updates fixing known-exploited vulnerabilities first, then by how many endpoints need them.
                _ => desc
                    ? grouped.OrderByDescending(x => x.KnownExploited > 0).ThenByDescending(x => x.Missing + x.Failed)
                    : grouped.OrderBy(x => x.KnownExploited > 0).ThenBy(x => x.Missing + x.Failed),
            };
            var page = PageRequest.From(q.Page, q.PageSize);
            var total = await grouped.CountAsync(ct);
            var pageRows = await grouped.Skip(page.Skip).Take(page.PageSize).ToListAsync(ct);
            var guids = pageRows.Select(r => r.UpdateGuid).ToList();
            var catalog = await LatestCatalogAsync(db, guids, ct);
            var held = await HeldAsync(db, tenant, q.OrganizationId, guids, ct);
            var items = pageRows.Where(r => catalog.ContainsKey(r.UpdateGuid)).Select(r =>
            {
                var u = catalog[r.UpdateGuid];
                return new FleetUpdateDto(r.UpdateGuid, u.Title, u.PrimaryKb, u.Category, u.MsrcSeverity, u.ReleaseDate, u.MaxDownloadSizeBytes, r.Missing,
                    r.Failed, r.Installed, r.PendingReboot, r.Excluded, Mapping.Package(u, null), u.CveIds.Count, r.KnownExploited > 0, r.Reoffered,
                    held.Contains(r.UpdateGuid));
            }).ToList();
            return TypedResults.Ok(new PagedResult<FleetUpdateDto>(items, page.Page, page.PageSize, total));
        });

        g.MapGet("/{updateGuid:guid}", async (Guid updateGuid, Guid? organizationId, Guid? siteId, EasyPatchDbContext db, ITenantContext tenant,
            ClaimsPrincipal user, CancellationToken ct) =>
        {
            var catalog = await LatestCatalogAsync(db, [updateGuid], ct);
            if (!catalog.TryGetValue(updateGuid, out var u))
            {
                throw AppException.NotFound("Update");
            }

            var states = await Scope(db, tenant, organizationId, siteId).Where(x => x.UpdateGuid == updateGuid)
                .GroupBy(x => 1).Select(gr => new
                {
                    Missing = gr.Count(x => x.State == EndpointUpdateState.Missing),
                    Failed = gr.Count(x => x.State == EndpointUpdateState.Failed),
                    Installed = gr.Count(x => x.State == EndpointUpdateState.Installed),
                    PendingReboot = gr.Count(x => x.State == EndpointUpdateState.PendingReboot || x.State == EndpointUpdateState.PendingVerification),
                    Excluded = gr.Count(x => x.State == EndpointUpdateState.Excluded || x.IsExcluded),
                    KnownExploited = gr.Count(x => x.KnownExploited),
                    Reoffered = gr.Count(x => x.State == EndpointUpdateState.Reoffered),
                }).FirstOrDefaultAsync(ct);

            // CVEs on the endpoints in scope (the catalog summary covers every organization).
            var cveLists = await Scope(db, tenant, organizationId, siteId).Where(x => x.UpdateGuid == updateGuid && x.CveIds.Count > 0)
                .Select(x => x.CveIds).Take(5000).ToListAsync(ct);
            var cves = VulnerabilityRules.Normalize(cveLists.SelectMany(c => c));
            var known = cves.Count == 0
                ? []
                : await db.Vulnerabilities.AsNoTracking().Where(v => cves.Contains(v.CveId)).ToDictionaryAsync(v => v.CveId, ct);
            var vulnerabilities = cves
                .Select(id => known.TryGetValue(id, out var v)
                    ? new VulnerabilityDto(id, v.Title, v.Severity, v.CvssBase, v.MsrcExploited, v.Kev, v.KevDateAdded, v.KevDueDate, v.KevRansomware, v.KevName)
                    : new VulnerabilityDto(id, null, null, null, false, false, null, null, false, null))
                .OrderByDescending(v => v.Kev).ThenByDescending(v => v.MsrcExploited).ThenByDescending(v => v.CvssBase ?? 0).ThenBy(v => v.CveId, StringComparer.Ordinal)
                .ToList();
            var holds = await UpdateHoldEndpoints.Visible(db, tenant).Where(h => h.UpdateGuid == updateGuid && h.ReleasedAt == null)
                .OrderBy(h => h.OrganizationId != null).ThenBy(h => h.CreatedAt).ToListAsync(ct);
            var holdDtos = await UpdateHoldEndpoints.ToDtosAsync(db, holds, user, tenant, ct);
            var onHold = holds.Exists(h => h.OrganizationId is null || organizationId is null || h.OrganizationId == organizationId);
            var summary = new FleetUpdateDto(updateGuid, u.Title, u.PrimaryKb, u.Category, u.MsrcSeverity, u.ReleaseDate, u.MaxDownloadSizeBytes,
                states?.Missing ?? 0, states?.Failed ?? 0, states?.Installed ?? 0, states?.PendingReboot ?? 0, states?.Excluded ?? 0,
                Mapping.Package(u, null), cves.Count, (states?.KnownExploited ?? 0) > 0, states?.Reoffered ?? 0, onHold);
            return TypedResults.Ok(new FleetUpdateDetailDto(summary, u.Description, u.SupportUrl, u.KbNumbers, u.Products, u.MsClassification,
                u.RebootBehavior is > 0, u.SupersededUpdateGuids, vulnerabilities, holdDtos));
        });

        g.MapGet("/{updateGuid:guid}/endpoints", async (Guid updateGuid, EndpointUpdateState? state, Guid? organizationId, Guid? siteId, int? page,
            int? pageSize, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var query = Scope(db, tenant, organizationId, siteId).Where(x => x.UpdateGuid == updateGuid);
            if (state is { } s)
            {
                query = query.Where(x => x.State == s);
            }

            return TypedResults.Ok(await query
                .Join(db.Endpoints, x => x.EndpointId, e => e.Id, (x, e) => new { x, e })
                .OrderBy(r => r.e.Hostname)
                .Select(r => new FleetUpdateEndpointDto(r.e.Id, r.e.Hostname, r.e.Organization!.Name, r.e.Site != null ? r.e.Site.Name : null, r.e.IsOnline,
                    r.x.State, r.x.IsRequired, r.x.IsExcluded, r.x.FailedAttempts, r.x.ErrorCode, r.x.ErrorMessage, r.x.StateChangedAt))
                .ToPagedAsync(PageRequest.From(page, pageSize), ct));
        });

        g.MapPost("/{updateGuid:guid}/install", async (Guid updateGuid, FleetInstallRequest request, EasyPatchDbContext db, ITenantContext tenant,
            JobService jobs, CancellationToken ct) =>
        {
            var query = Scope(db, tenant, request.OrganizationId, request.SiteId)
                .Where(x => x.UpdateGuid == updateGuid && (x.State == EndpointUpdateState.Missing || x.State == EndpointUpdateState.Failed) && !x.IsExcluded);
            if (request.EndpointIds is { Count: > 0 } ids)
            {
                query = query.Where(x => ids.Contains(x.EndpointId));
            }

            var targets = await query.Join(db.Endpoints, x => x.EndpointId, e => e.Id, (x, e) => new { e.Id, e.Hostname }).Distinct().OrderBy(t => t.Hostname).Take(1000).ToListAsync(ct);
            var results = new List<BulkItemResult>();
            foreach (var target in targets)
            {
                try
                {
                    var job = await jobs.CreateAsync(new CreateJobRequest(target.Id, JobType.InstallUpdates, InstallMode.Selected, [updateGuid]), ct);
                    results.Add(new BulkItemResult(target.Id, target.Hostname, true, job.Id, null, null));
                }
                catch (AppException ex)
                {
                    db.ChangeTracker.Clear();
                    results.Add(new BulkItemResult(target.Id, target.Hostname, false,
                        ex.Extensions.TryGetValue("existingJobId", out var existing) ? existing as Guid? : null, ex.Code, ex.Message));
                }
            }

            return TypedResults.Ok(new BulkResultDto(results.Count(r => r.Success), results.Count(r => !r.Success), results));
        }).RequireAuthorization(Policies.Operator);

        // Rolling back an update across endpoints: one uninstall-update job per endpoint that reports it installed.
        g.MapPost("/{updateGuid:guid}/uninstall", async (Guid updateGuid, FleetUninstallRequest request, EasyPatchDbContext db, ITenantContext tenant,
            ClaimsPrincipal user, UpdateRemovalService removals, UpdateHoldService holdService, CancellationToken ct) =>
        {
            new Validator().Optional("reason", request.Reason, 500).ThrowIfInvalid();
            if (request.Hold)
            {
                await UpdateHoldEndpoints.EnsureCanHoldAsync(db, tenant, user, request.OrganizationId, ct);
            }

            var query = Scope(db, tenant, request.OrganizationId, request.SiteId)
                .Where(x => x.UpdateGuid == updateGuid && (x.State == EndpointUpdateState.Installed || x.State == EndpointUpdateState.PendingReboot));
            if (request.EndpointIds is { Count: > 0 } ids)
            {
                query = query.Where(x => ids.Contains(x.EndpointId));
            }

            var targets = await query.Join(db.Endpoints, x => x.EndpointId, e => e.Id, (x, e) => new { e.Id, e.Hostname }).Distinct().OrderBy(t => t.Hostname).Take(1000).ToListAsync(ct);
            var reason = Validator.Clean(request.Reason);
            var results = new List<BulkItemResult>();
            foreach (var target in targets)
            {
                try
                {
                    var job = await removals.RemoveAsync(target.Id, updateGuid, request.Block, reason, ct);
                    results.Add(new BulkItemResult(target.Id, target.Hostname, true, job.Id, null, null));
                }
                catch (AppException ex)
                {
                    db.ChangeTracker.Clear();
                    results.Add(new BulkItemResult(target.Id, target.Hostname, false,
                        ex.Extensions.TryGetValue("existingJobId", out var existing) ? existing as Guid? : null, ex.Code, ex.Message));
                }
            }

            // Held even when no endpoint had it installed: the point is that the others do not install it.
            if (request.Hold && !await holdService.IsHeldAsync(updateGuid, request.OrganizationId, ct))
            {
                try
                {
                    await holdService.HoldAsync(updateGuid, request.OrganizationId, reason ?? "Removed with EasyPatch", ct);
                }
                catch (AppException ex) when (ex.Code == "already_held")
                {
                    // Held concurrently: nothing to do.
                }
            }

            return TypedResults.Ok(new BulkResultDto(results.Count(r => r.Success), results.Count(r => !r.Success), results));
        }).RequireAuthorization(Policies.Operator);
    }

    /// <summary>Updates with an active hold for every organization, or for the organization in scope (any organization the
    /// administrator can access when none is selected).</summary>
    private static async Task<HashSet<Guid>> HeldAsync(EasyPatchDbContext db, ITenantContext tenant, Guid? organizationId, IReadOnlyList<Guid> guids,
        CancellationToken ct)
    {
        var holds = UpdateHoldEndpoints.Visible(db, tenant).Where(h => h.ReleasedAt == null && guids.Contains(h.UpdateGuid));
        if (organizationId is { } org)
        {
            holds = holds.Where(h => h.OrganizationId == null || h.OrganizationId == org);
        }

        return (await holds.Select(h => h.UpdateGuid).Distinct().ToListAsync(ct)).ToHashSet();
    }

    private static IQueryable<EndpointUpdate> Scope(EasyPatchDbContext db, ITenantContext tenant, Guid? organizationId, Guid? siteId)
    {
        var endpoints = db.Endpoints.AsNoTracking().ForTenant(tenant, e => e.OrganizationId).Where(e => e.Status == EndpointStatus.Active);
        if (organizationId is { } orgId)
        {
            endpoints = endpoints.Where(e => e.OrganizationId == orgId);
        }

        if (siteId is { } site)
        {
            endpoints = endpoints.Where(e => e.SiteId == site);
        }

        var ids = endpoints.Select(e => e.Id);
        return db.EndpointUpdates.AsNoTracking().Where(u => ids.Contains(u.EndpointId));
    }

    private static async Task<Dictionary<Guid, Update>> LatestCatalogAsync(EasyPatchDbContext db, IReadOnlyCollection<Guid> guids, CancellationToken ct)
    {
        var rows = await db.Updates.AsNoTracking().Where(u => guids.Contains(u.UpdateGuid)).ToListAsync(ct);
        return rows.GroupBy(u => u.UpdateGuid).ToDictionary(g => g.Key, g =>
        {
            var latest = g.OrderByDescending(u => u.RevisionNumber).First();
            latest.CveIds = VulnerabilityRules.Normalize(g.SelectMany(u => u.CveIds)); // endpoints may still be on an older revision
            return latest;
        });
    }
}
