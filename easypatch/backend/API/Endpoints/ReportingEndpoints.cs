using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Contracts;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

public sealed record InstallationReportQuery(DateTimeOffset? From, DateTimeOffset? To, Guid? OrganizationId, Guid? SiteId, Guid? EndpointId,
    UpdateCategory? Category, JobItemStatus? Result, int? Page, int? PageSize);

public static class ReportingEndpoints
{
    public static void MapReportingEndpoints(this IEndpointRouteBuilder app)
    {
        var reports = app.MapGroup("/api/v1/reports").WithTags("Reports").RequireAuthorization(Policies.Viewer);

        reports.MapGet("/compliance/trend", async (Guid? organizationId, DateOnly? from, DateOnly? to, EasyPatchDbContext db, ITenantContext tenant,
            TimeProvider clock, CancellationToken ct) =>
        {
            var today = DateOnly.FromDateTime(clock.GetUtcNow().UtcDateTime);
            var start = from ?? today.AddDays(-30);
            var end = to ?? today;
            var query = db.ComplianceSnapshots.AsNoTracking().ForTenant(tenant, s => s.OrganizationId).Where(s => s.Date >= start && s.Date <= end);
            if (organizationId is { } orgId)
            {
                query = query.Where(s => s.OrganizationId == orgId);
            }

            var points = await query.GroupBy(s => s.Date).OrderBy(g => g.Key).Select(g => new
            {
                Date = g.Key,
                Total = g.Sum(s => s.TotalEndpoints),
                Compliant = g.Sum(s => s.Compliant),
                Missing = g.Sum(s => s.MissingUpdates),
                Failed = g.Sum(s => s.FailedUpdates),
                Reboot = g.Sum(s => s.RebootRequired),
                Stale = g.Sum(s => s.ScanStale),
                Never = g.Sum(s => s.NeverScanned),
                Offline = g.Sum(s => s.Offline),
                MissingUpdates = g.Sum(s => s.MissingRequiredUpdates),
            }).ToListAsync(ct);
            return TypedResults.Ok(points.Select(p => new ComplianceTrendPoint(p.Date, p.Total, p.Compliant, p.Missing, p.Failed, p.Reboot, p.Stale, p.Never,
                p.Offline, p.MissingUpdates, ComplianceCalculator.Percentage(p.Compliant, p.Total))).ToList());
        });

        reports.MapGet("/installations", async ([AsParameters] InstallationReportQuery q, EasyPatchDbContext db, ITenantContext tenant, TimeProvider clock,
            CancellationToken ct) =>
            TypedResults.Ok(await InstallationQuery(q, db, tenant, clock).ToPagedAsync(PageRequest.From(q.Page, q.PageSize), ct)));

        app.MapGet("/api/v1/audit-logs", async (Guid? userId, Guid? organizationId, string? action, DateTimeOffset? from, DateTimeOffset? to, int? page,
            int? pageSize, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var query = db.AuditLogs.AsNoTracking();
            if (!tenant.IsUnrestricted)
            {
                var allowed = tenant.AllowedOrganizationIds.ToList();
                query = query.Where(a => a.OrganizationId != null && allowed.Contains(a.OrganizationId.Value));
            }

            if (userId is { } uid)
            {
                query = query.Where(a => a.UserId == uid);
            }

            if (organizationId is { } orgId)
            {
                query = query.Where(a => a.OrganizationId == orgId);
            }

            if (Validator.Clean(action) is { } act)
            {
                query = query.Where(a => a.Action.StartsWith(act));
            }

            if (from is { } f)
            {
                query = query.Where(a => a.CreatedAt >= f);
            }

            if (to is { } t)
            {
                query = query.Where(a => a.CreatedAt < t);
            }

            return TypedResults.Ok(await query.OrderByDescending(a => a.Id)
                .Select(a => new AuditLogDto(a.Id, a.UserId, a.Username, a.OrganizationId, a.EndpointId, a.Action, a.TargetType, a.TargetId, a.Details,
                    a.IpAddress, a.CorrelationId, a.CreatedAt))
                .ToPagedAsync(PageRequest.From(page, pageSize), ct));
        }).WithTags("Audit").RequireAuthorization(Policies.Operator);
    }

    private static IQueryable<InstallationReportRow> InstallationQuery(InstallationReportQuery q, EasyPatchDbContext db, ITenantContext tenant, TimeProvider clock)
    {
        var from = q.From ?? clock.GetUtcNow().AddDays(-30);
        var jobs = db.Jobs.AsNoTracking().ForTenant(tenant, j => j.OrganizationId).Where(j => j.Type == JobType.InstallUpdates);
        if (q.OrganizationId is { } orgId)
        {
            jobs = jobs.Where(j => j.OrganizationId == orgId);
        }

        if (q.SiteId is { } siteId)
        {
            jobs = jobs.Where(j => j.SiteId == siteId);
        }

        if (q.EndpointId is { } endpointId)
        {
            jobs = jobs.Where(j => j.EndpointId == endpointId);
        }

        var items = db.Set<JobUpdate>().AsNoTracking().Where(u => u.CompletedAt != null && u.CompletedAt >= from);
        if (q.To is { } to)
        {
            items = items.Where(u => u.CompletedAt < to);
        }

        if (q.Category is { } category)
        {
            items = items.Where(u => u.Category == category);
        }

        if (q.Result is { } result)
        {
            items = items.Where(u => u.Status == result);
        }

        return items.Join(jobs, u => u.JobId, j => j.Id, (u, j) => new { u, j })
            .OrderByDescending(x => x.u.CompletedAt)
            .Select(x => new InstallationReportRow(x.j.Id, x.j.EndpointId, x.j.Endpoint!.Hostname, x.j.Endpoint.Organization!.Name,
                x.j.Endpoint.Site != null ? x.j.Endpoint.Site.Name : null, x.u.UpdateGuid, x.u.Title, x.u.KbNumber, x.u.Category, x.u.Status, x.u.SkipReason,
                x.u.ErrorCode, x.u.ErrorMessage, x.u.RebootRequired, x.j.RequestedBy, x.u.CompletedAt));
    }
}

public static class SettingsEndpoints
{
    public static void MapSettingsEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/settings", async (SettingsService settings, CancellationToken ct) => TypedResults.Ok(await settings.GetAsync(ct)))
            .WithTags("Settings").RequireAuthorization(Policies.Viewer);

        app.MapPut("/api/v1/settings", async (ServerSettings request, SettingsService settings, EasyPatchDbContext db, AuditService audit,
            IActorContext actor, CancellationToken ct) =>
        {
            var updated = await settings.UpdateAsync(request, actor.UserId, ct);
            audit.Record("settings.update", "ServerSettings", "1", details: request);
            await db.SaveChangesAsync(ct);
            settings.Invalidate();
            return TypedResults.Ok(updated);
        }).WithTags("Settings").RequireAuthorization(Policies.SuperAdmin);

        app.MapGet("/api/v1/server-info", (Microsoft.Extensions.Options.IOptions<EasyPatchOptions> options, TimeProvider clock) =>
            TypedResults.Ok(new ServerInfoDto(typeof(SettingsEndpoints).Assembly.GetName().Version?.ToString(3) ?? "0.0.0", options.Value.PublicUrl,
                clock.GetUtcNow()))).WithTags("Settings").RequireAuthorization(Policies.Viewer);

        // Feed status only: the worker downloads the feeds (the API has no outbound internet access).
        app.MapGet("/api/v1/vulnerability-feeds", async (EasyPatchDbContext db, CancellationToken ct) =>
            TypedResults.Ok(await db.VulnerabilityFeeds.AsNoTracking().OrderBy(f => f.Name)
                .Select(f => new VulnerabilityFeedDto(f.Name, f.LastAttemptAt, f.LastSuccessAt, f.LastError, f.Version, f.ItemCount))
                .ToListAsync(ct))).WithTags("Settings").RequireAuthorization(Policies.Viewer);

        var lifecycle = app.MapGroup("/api/v1/lifecycle").WithTags("OS lifecycle").RequireAuthorization(Policies.Viewer);
        lifecycle.MapGet("/", async (EasyPatchDbContext db, CancellationToken ct) =>
            TypedResults.Ok(await db.OsLifecycleEntries.AsNoTracking().OrderBy(e => e.Product).ThenByDescending(e => e.BuildNumber).ThenBy(e => e.EditionGroup)
                .Select(e => new OsLifecycleDto(e.Id, e.Product, e.EditionGroup, e.BuildNumber, e.VersionLabel, e.EndOfServicing, e.EsuEndDate, e.Notes))
                .ToListAsync(ct)));

        lifecycle.MapPost("/", async (OsLifecycleRequest request, EasyPatchDbContext db, AuditService audit, ComplianceService compliance,
            CancellationToken ct) =>
        {
            Validate(request);
            var entry = new OsLifecycleEntry
            {
                Id = Guid.CreateVersion7(), Product = request.Product.Trim(), EditionGroup = request.EditionGroup.Trim(), VersionLabel = request.VersionLabel.Trim(),
            };
            Apply(entry, request);
            db.OsLifecycleEntries.Add(entry);
            audit.Record("lifecycle.create", "OsLifecycleEntry", entry.Id.ToString(), details: request);
            await db.SaveChangesAsync(ct);
            await compliance.RecomputeScopeAsync(null, null, ct);
            return TypedResults.Created($"/api/v1/lifecycle/{entry.Id}", ToDto(entry));
        }).RequireAuthorization(Policies.SuperAdmin);

        lifecycle.MapPut("/{id:guid}", async (Guid id, OsLifecycleRequest request, EasyPatchDbContext db, AuditService audit, ComplianceService compliance,
            CancellationToken ct) =>
        {
            Validate(request);
            var entry = await db.OsLifecycleEntries.FirstOrDefaultAsync(e => e.Id == id, ct) ?? throw AppException.NotFound("Lifecycle entry");
            Apply(entry, request);
            audit.Record("lifecycle.update", "OsLifecycleEntry", id.ToString(), details: request);
            await db.SaveChangesAsync(ct);
            await compliance.RecomputeScopeAsync(null, null, ct);
            return TypedResults.Ok(ToDto(entry));
        }).RequireAuthorization(Policies.SuperAdmin);

        lifecycle.MapDelete("/{id:guid}", async (Guid id, EasyPatchDbContext db, AuditService audit, ComplianceService compliance, CancellationToken ct) =>
        {
            var entry = await db.OsLifecycleEntries.FirstOrDefaultAsync(e => e.Id == id, ct) ?? throw AppException.NotFound("Lifecycle entry");
            db.OsLifecycleEntries.Remove(entry);
            audit.Record("lifecycle.delete", "OsLifecycleEntry", id.ToString(), details: new { entry.Product, entry.BuildNumber, entry.EditionGroup });
            await db.SaveChangesAsync(ct);
            await compliance.RecomputeScopeAsync(null, null, ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.SuperAdmin);
    }

    private static void Validate(OsLifecycleRequest r) =>
        new Validator().Required("product", r.Product, 100).Required("editionGroup", r.EditionGroup, 50).Required("versionLabel", r.VersionLabel, 50)
            .Range("buildNumber", r.BuildNumber, 1, 1_000_000).Optional("notes", r.Notes, 1000)
            .Check(r.EsuEndDate is null || r.EsuEndDate >= r.EndOfServicing, "esuEndDate", "ESU end date must be on or after the end of servicing date.")
            .ThrowIfInvalid();

    private static void Apply(OsLifecycleEntry entry, OsLifecycleRequest r)
    {
        entry.Product = r.Product.Trim();
        entry.EditionGroup = r.EditionGroup.Trim();
        entry.BuildNumber = r.BuildNumber;
        entry.VersionLabel = r.VersionLabel.Trim();
        entry.EndOfServicing = r.EndOfServicing;
        entry.EsuEndDate = r.EsuEndDate;
        entry.Notes = Validator.Clean(r.Notes);
    }

    private static OsLifecycleDto ToDto(OsLifecycleEntry e) => new(e.Id, e.Product, e.EditionGroup, e.BuildNumber, e.VersionLabel, e.EndOfServicing,
        e.EsuEndDate, e.Notes);
}
