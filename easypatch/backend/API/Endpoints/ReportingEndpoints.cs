using System.Globalization;
using System.Text;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Contracts;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

public sealed record ComplianceReportQuery(Guid? OrganizationId, Guid? SiteId, Guid? EndpointId, string? Os, ComplianceStatus? Compliance);

public sealed record InstallationReportQuery(DateTimeOffset? From, DateTimeOffset? To, Guid? OrganizationId, Guid? SiteId, Guid? EndpointId,
    UpdateCategory? Category, JobItemStatus? Result, int? Page, int? PageSize);

public static class ReportingEndpoints
{
    public static void MapReportingEndpoints(this IEndpointRouteBuilder app)
    {
        var dashboard = app.MapGroup("/api/v1/dashboard").WithTags("Dashboard").RequireAuthorization(Policies.Viewer);

        dashboard.MapGet("/summary", async (EasyPatchDbContext db, ITenantContext tenant, AgentPackageService packages, TimeProvider clock,
            CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            var endpoints = db.Endpoints.AsNoTracking().ForTenant(tenant, e => e.OrganizationId).Where(e => e.Status == EndpointStatus.Active);
            var counts = await endpoints.GroupBy(e => 1).Select(g => new
            {
                Total = g.Count(),
                Online = g.Count(e => e.IsOnline),
                Compliant = g.Count(e => e.ComplianceStatus == ComplianceStatus.Compliant),
                Missing = g.Count(e => e.ComplianceStatus == ComplianceStatus.MissingUpdates),
                Failed = g.Count(e => e.ComplianceStatus == ComplianceStatus.FailedUpdates),
                Reboot = g.Count(e => e.ComplianceStatus == ComplianceStatus.RebootRequired),
                Stale = g.Count(e => e.ComplianceStatus == ComplianceStatus.ScanStale),
                Never = g.Count(e => e.ComplianceStatus == ComplianceStatus.NeverScanned),
                MissingUpdates = g.Sum(e => e.MissingRequiredCount),
                Unsupported = g.Count(e => e.OsSupportStatus == OsSupportStatus.Unsupported),
                KnownExploited = g.Count(e => e.KnownExploitedMissingCount > 0),
            }).FirstOrDefaultAsync(ct);
            var jobs = db.Jobs.AsNoTracking().ForTenant(tenant, j => j.OrganizationId);
            var queued = await jobs.CountAsync(j => j.Status == JobStatus.Queued || j.Status == JobStatus.Delivered, ct);
            var running = await jobs.CountAsync(j => j.Status == JobStatus.Acknowledged || j.Status == JobStatus.Running, ct);
            var dayAgo = now.AddDays(-1);
            var failed24 = await jobs.CountAsync(j => j.Status == JobStatus.Failed && j.CompletedAt >= dayAgo, ct);
            var pending = await db.EnrollmentRequests.AsNoTracking().ForTenant(tenant, r => r.OrganizationId)
                .CountAsync(r => r.Status == EnrollmentRequestStatus.Pending && r.ExpiresAt > now, ct);
            var latest = Mapping.LatestAgentVersions.From(packages);
            var outdated = 0;
            if (latest.Any)
            {
                var versions = await endpoints.GroupBy(e => new { e.AgentVersion, e.AgentPackageFormat })
                    .Select(g => new { g.Key.AgentVersion, g.Key.AgentPackageFormat, Count = g.Count() }).ToListAsync(ct);
                outdated = versions.Where(v => latest.IsOutdated(v.AgentVersion, v.AgentPackageFormat)).Sum(v => v.Count);
            }

            var orgs = await db.Organizations.AsNoTracking().ForTenant(tenant, o => o.Id).Where(o => o.IsActive).ToListAsync(ct);
            var stats = await OrganizationStats.LoadAsync(db, orgs.Select(o => o.Id).ToList(), ct);
            var leastCompliant = orgs.Select(o => OrganizationStats.ToSummary(o, stats)).Where(s => s.EndpointCount > 0)
                .OrderBy(s => s.CompliancePercent).ThenByDescending(s => s.MissingRequiredUpdates).Take(5).ToList();
            var c = counts ?? new { Total = 0, Online = 0, Compliant = 0, Missing = 0, Failed = 0, Reboot = 0, Stale = 0, Never = 0, MissingUpdates = 0, Unsupported = 0, KnownExploited = 0 };
            return TypedResults.Ok(new DashboardSummaryDto(orgs.Count, c.Total, c.Online, c.Total - c.Online, c.Compliant, c.Missing, c.Failed, c.Reboot,
                c.Stale, c.Never, ComplianceCalculator.Percentage(c.Compliant, c.Total), c.MissingUpdates, queued, running, failed24, pending,
                c.Unsupported, outdated, leastCompliant, c.KnownExploited));
        });

        dashboard.MapGet("/activity", async (int? limit, Guid? organizationId, EventSeverity? severity, EasyPatchDbContext db, ITenantContext tenant,
            CancellationToken ct) =>
        {
            var query = db.EndpointEvents.AsNoTracking().ForTenant(tenant, e => e.OrganizationId);
            if (organizationId is { } orgId)
            {
                query = query.Where(e => e.OrganizationId == orgId);
            }

            if (severity is { } sev)
            {
                query = query.Where(e => e.Severity >= sev);
            }

            var rows = await query.OrderByDescending(e => e.Id).Take(Math.Clamp(limit ?? 50, 1, 200))
                .Join(db.Endpoints, e => e.EndpointId, ep => ep.Id, (e, ep) => new EndpointEventDto(e.Id, e.EndpointId, ep.Hostname, e.Type, e.Severity,
                    e.Message, e.JobId, e.CreatedAt))
                .ToListAsync(ct);
            return TypedResults.Ok(rows.OrderByDescending(r => r.Id).ToList());
        });

        var reports = app.MapGroup("/api/v1/reports").WithTags("Reports").RequireAuthorization(Policies.Viewer);

        reports.MapGet("/compliance", async ([AsParameters] ComplianceReportQuery q, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var rows = await ComplianceRowsAsync(q, db, tenant, ct);
            var byStatus = Enum.GetValues<ComplianceStatus>().ToDictionary(s => s, s => rows.Count(r => r.ComplianceStatus == s));
            var compliant = byStatus[ComplianceStatus.Compliant];
            return TypedResults.Ok(new ComplianceReportDto(rows.Count, compliant, ComplianceCalculator.Percentage(compliant, rows.Count), byStatus, rows));
        });

        reports.MapGet("/compliance.csv", async ([AsParameters] ComplianceReportQuery q, EasyPatchDbContext db, ITenantContext tenant, TimeProvider clock,
            CancellationToken ct) =>
        {
            var rows = await ComplianceRowsAsync(q, db, tenant, ct);
            var csv = new CsvWriter("Hostname", "Organization", "Site", "Operating system", "Build", "Compliance", "Missing required", "Missing total",
                "Failed", "Reboot pending", "Online", "OS support", "Last scan (UTC)", "Last check-in (UTC)", "Platform");
            foreach (var r in rows)
            {
                csv.Row(r.Hostname, r.OrganizationName, r.SiteName, r.OperatingSystem, r.OsBuild, r.ComplianceStatus.ToString(), r.MissingRequiredCount,
                    r.MissingTotalCount, r.FailedCount, r.RebootPending, r.IsOnline, r.OsSupportStatus.ToString(), r.LastScanAt, r.LastCheckInAt, r.Platform);
            }

            return csv.ToResult($"easypatch-compliance-{clock.GetUtcNow():yyyyMMdd-HHmm}.csv");
        });

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

        reports.MapGet("/installations.csv", async ([AsParameters] InstallationReportQuery q, EasyPatchDbContext db, ITenantContext tenant,
            TimeProvider clock, CancellationToken ct) =>
        {
            var rows = await InstallationQuery(q, db, tenant, clock).Take(50_000).ToListAsync(ct);
            var csv = new CsvWriter("Completed (UTC)", "Hostname", "Organization", "Site", "KB", "Title", "Category", "Result", "Skip reason", "Error code",
                "Error message", "Reboot required", "Requested by", "Job ID");
            foreach (var r in rows)
            {
                csv.Row(r.CompletedAt, r.Hostname, r.OrganizationName, r.SiteName, r.KbNumber, r.Title, r.Category.ToString(), r.Status.ToString(), r.SkipReason,
                    r.ErrorCode, r.ErrorMessage, r.RebootRequired, r.RequestedBy, r.JobId.ToString());
            }

            return csv.ToResult($"easypatch-installations-{clock.GetUtcNow():yyyyMMdd-HHmm}.csv");
        });

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

    private static async Task<List<ComplianceReportRow>> ComplianceRowsAsync(ComplianceReportQuery q, EasyPatchDbContext db, ITenantContext tenant,
        CancellationToken ct)
    {
        var query = db.Endpoints.AsNoTracking().ForTenant(tenant, e => e.OrganizationId).Where(e => e.Status == EndpointStatus.Active);
        if (q.OrganizationId is { } orgId)
        {
            query = query.Where(e => e.OrganizationId == orgId);
        }

        if (q.SiteId is { } siteId)
        {
            query = query.Where(e => e.SiteId == siteId);
        }

        if (q.EndpointId is { } endpointId)
        {
            query = query.Where(e => e.Id == endpointId);
        }

        if (q.Compliance is { } status)
        {
            query = query.Where(e => e.ComplianceStatus == status);
        }

        if (Validator.Clean(q.Os) is { } os)
        {
            var pattern = "%" + OrganizationEndpoints.EscapeLike(os) + "%";
            query = query.Where(e => e.OperatingSystem != null && EF.Functions.ILike(e.OperatingSystem, pattern));
        }

        var rows = await query.OrderBy(e => e.Organization!.Name).ThenBy(e => e.Hostname).Take(50_000)
            .Select(e => new
            {
                e.Id, e.Hostname, Org = e.Organization!.Name, Site = e.Site != null ? e.Site.Name : null, e.OperatingSystem, e.OsBuildNumber, e.OsProductType,
                e.OsBuild, e.ComplianceStatus, e.MissingRequiredCount, e.MissingTotalCount, e.FailedCount, e.RebootPending, e.IsOnline, e.OsSupportStatus,
                e.LastScanAt, e.LastCheckInAt, e.Platform,
            }).ToListAsync(ct);
        return rows.Select(r => new ComplianceReportRow(r.Id, r.Hostname, r.Org, r.Site, OsNaming.Describe(r.OperatingSystem, r.OsBuildNumber, r.OsProductType),
            r.OsBuild, r.ComplianceStatus, r.MissingRequiredCount, r.MissingTotalCount, r.FailedCount, r.RebootPending, r.IsOnline, r.OsSupportStatus,
            r.LastScanAt, r.LastCheckInAt, r.Platform)).ToList();
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

/// <summary>RFC 4180 CSV with spreadsheet formula-injection protection (hostnames and titles come from endpoints).</summary>
public sealed class CsvWriter
{
    private readonly StringBuilder sb = new();

    public CsvWriter(params string[] headers) => Row(headers);

    public void Row(params object?[] values)
    {
        for (var i = 0; i < values.Length; i++)
        {
            if (i > 0)
            {
                sb.Append(',');
            }

            sb.Append(Escape(values[i]));
        }

        sb.Append("\r\n");
    }

    public IResult ToResult(string fileName) =>
        Results.File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv; charset=utf-8", fileName);

    public static string Escape(object? value)
    {
        var text = value switch
        {
            null => string.Empty,
            DateTimeOffset d => d.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            bool b => b ? "Yes" : "No",
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            _ => value.ToString() ?? string.Empty,
        };
        if (text.Length > 0 && text[0] is '=' or '+' or '-' or '@' or '\t' or '\r' && value is string)
        {
            text = "'" + text;
        }

        return text.IndexOfAny([',', '"', '\r', '\n']) >= 0 ? "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : text;
    }
}

public static class SettingsEndpoints
{
    public static void MapSettingsEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/v1/settings", async (SettingsService settings, CancellationToken ct) => TypedResults.Ok(await settings.GetAsync(ct)))
            .WithTags("Settings").RequireAuthorization(Policies.Viewer);

        app.MapPut("/api/v1/settings", async (ServerSettings request, SettingsService settings, EasyPatchDbContext db, AuditService audit,
            System.Security.Claims.ClaimsPrincipal user, CancellationToken ct) =>
        {
            var updated = await settings.UpdateAsync(request, user.GetUserId(), ct);
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
