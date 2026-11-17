using System.Globalization;
using System.Security.Claims;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Api.Endpoints;

public static class OrganizationEndpoints
{
    public static void MapOrganizationEndpoints(this IEndpointRouteBuilder app)
    {
        var orgs = app.MapGroup("/api/v1/organizations").WithTags("Organizations").RequireAuthorization(Policies.Viewer);

        orgs.MapGet("/", async (bool? includeArchived, string? search, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var query = db.Organizations.AsNoTracking().ForTenant(tenant, o => o.Id);
            if (includeArchived != true)
            {
                query = query.Where(o => o.IsActive);
            }

            if (Validator.Clean(search) is { } s)
            {
                query = query.Where(o => EF.Functions.ILike(o.Name, "%" + EscapeLike(s) + "%"));
            }

            var list = await query.OrderBy(o => o.Name).ToListAsync(ct);
            var stats = await OrganizationStats.LoadAsync(db, list.Select(o => o.Id).ToList(), ct);
            return TypedResults.Ok(list.Select(o => OrganizationStats.ToSummary(o, stats)).ToList());
        });

        orgs.MapPost("/", async (OrganizationRequest request, EasyPatchDbContext db, ITenantContext tenant, AuditService audit, TimeProvider clock,
            CancellationToken ct) =>
        {
            if (!tenant.IsUnrestricted)
            {
                throw AppException.Forbidden("Only administrators with access to all organizations can create organizations.");
            }

            ValidateOrganization(request);
            var now = clock.GetUtcNow();
            var org = new Organization { Id = Guid.CreateVersion7(now), Name = request.Name.Trim(), CreatedAt = now, UpdatedAt = now };
            Apply(org, request);
            db.Organizations.Add(org);
            audit.Record("organization.create", "Organization", org.Id.ToString(), org.Id, details: new { org.Name });
            await db.SaveChangesAsync(ct);
            return TypedResults.Created($"/api/v1/organizations/{org.Id}", await LoadOrganizationAsync(db, org.Id, ct));
        }).RequireAuthorization(Policies.Operator);

        orgs.MapGet("/{id:guid}", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            tenant.EnsureAccess(id);
            return TypedResults.Ok(await LoadOrganizationAsync(db, id, ct));
        });

        orgs.MapPut("/{id:guid}", async (Guid id, OrganizationRequest request, EasyPatchDbContext db, ITenantContext tenant, AuditService audit,
            TimeProvider clock, CancellationToken ct) =>
        {
            tenant.EnsureAccess(id);
            ValidateOrganization(request);
            var org = await db.Organizations.FirstOrDefaultAsync(o => o.Id == id, ct) ?? throw AppException.NotFound("Organization");
            org.Name = request.Name.Trim();
            Apply(org, request);
            org.UpdatedAt = clock.GetUtcNow();
            audit.Record("organization.update", "Organization", id.ToString(), id, details: request);
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok(await LoadOrganizationAsync(db, id, ct));
        }).RequireAuthorization(Policies.Operator);

        orgs.MapDelete("/{id:guid}", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, AuditService audit, CancellationToken ct) =>
        {
            tenant.EnsureAccess(id);
            var org = await db.Organizations.FirstOrDefaultAsync(o => o.Id == id, ct) ?? throw AppException.NotFound("Organization");
            if (await db.Endpoints.AnyAsync(e => e.OrganizationId == id, ct))
            {
                throw AppException.Conflict("Delete or move this organization's endpoints first, or archive the organization instead.", "has_endpoints");
            }

            await db.Jobs.Where(j => j.OrganizationId == id).ExecuteDeleteAsync(ct);
            db.Organizations.Remove(org);
            audit.Record("organization.delete", "Organization", id.ToString(), details: new { org.Name });
            await db.SaveChangesAsync(ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Operator);

        orgs.MapPost("/{id:guid}/archive", (Guid id, EasyPatchDbContext db, ITenantContext tenant, AuditService audit, TimeProvider clock, CancellationToken ct) =>
            SetOrganizationActiveAsync(id, false, db, tenant, audit, clock, ct)).RequireAuthorization(Policies.Operator);
        orgs.MapPost("/{id:guid}/restore", (Guid id, EasyPatchDbContext db, ITenantContext tenant, AuditService audit, TimeProvider clock, CancellationToken ct) =>
            SetOrganizationActiveAsync(id, true, db, tenant, audit, clock, ct)).RequireAuthorization(Policies.Operator);

        orgs.MapGet("/{id:guid}/sites", async (Guid id, bool? includeArchived, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            tenant.EnsureAccess(id);
            return TypedResults.Ok(await WithTagsAsync(db, await SiteQuery(db, s => s.OrganizationId == id && (includeArchived == true || s.IsActive)).ToListAsync(ct), ct));
        });

        orgs.MapPost("/{id:guid}/sites", async (Guid id, SiteRequest request, EasyPatchDbContext db, ITenantContext tenant, AuditService audit,
            TimeProvider clock, CancellationToken ct) =>
        {
            tenant.EnsureAccess(id);
            ValidateSite(request);
            var org = await db.Organizations.FirstOrDefaultAsync(o => o.Id == id, ct) ?? throw AppException.NotFound("Organization");
            var now = clock.GetUtcNow();
            var site = new Site
            {
                Id = Guid.CreateVersion7(now), OrganizationId = id, Name = request.Name.Trim(), Description = Validator.Clean(request.Description),
                Address = Validator.Clean(request.Address), TimeZone = Validator.Clean(request.TimeZone) ?? org.TimeZone, CreatedAt = now, UpdatedAt = now,
            };
            db.Sites.Add(site);
            audit.Record("site.create", "Site", site.Id.ToString(), id, details: new { site.Name });
            await db.SaveChangesAsync(ct);
            return TypedResults.Created($"/api/v1/sites/{site.Id}", await SiteQuery(db, s => s.Id == site.Id).FirstAsync(ct));
        }).RequireAuthorization(Policies.Operator);

        orgs.MapGet("/{id:guid}/policy", async (Guid id, PolicyService policies, ITenantContext tenant, CancellationToken ct) =>
        {
            tenant.EnsureAccess(id);
            var policy = await policies.GetOrganizationPolicyAsync(id, ct);
            return TypedResults.Ok(policy is null ? EmptyPolicy(PolicyScope.Organization, id, null) : ToDto(policy));
        });

        orgs.MapPut("/{id:guid}/policy", async (Guid id, PolicyRequest request, PolicyService policies, ComplianceService compliance, EasyPatchDbContext db,
            ITenantContext tenant, AuditService audit, ClaimsPrincipal user, CancellationToken ct) =>
        {
            tenant.EnsureAccess(id);
            _ = await db.Organizations.AnyAsync(o => o.Id == id, ct) ? 0 : throw AppException.NotFound("Organization");
            var stored = await policies.UpsertAsync(PolicyScope.Organization, id, null, FromRequest(request), user.FindUserId(), ct);
            audit.Record("policy.update", "Policy", stored.Id.ToString(), id, details: request);
            await db.SaveChangesAsync(ct);
            await compliance.RecomputeScopeAsync(id, null, ct);
            return TypedResults.Ok(ToDto(stored));
        }).RequireAuthorization(Policies.Operator);

        orgs.MapDelete("/{id:guid}/policy", async (Guid id, PolicyService policies, ComplianceService compliance, EasyPatchDbContext db,
            ITenantContext tenant, AuditService audit, CancellationToken ct) =>
        {
            tenant.EnsureAccess(id);
            if (await policies.DeleteAsync(PolicyScope.Organization, id, ct))
            {
                audit.Record("policy.delete", "Policy", null, id);
                await db.SaveChangesAsync(ct);
                await compliance.RecomputeScopeAsync(id, null, ct);
            }

            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Operator);

        var sites = app.MapGroup("/api/v1/sites").WithTags("Sites").RequireAuthorization(Policies.Viewer);

        sites.MapGet("/{id:guid}", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var site = (await WithTagsAsync(db, [await SiteQuery(db, s => s.Id == id).FirstOrDefaultAsync(ct) ?? throw AppException.NotFound("Site")], ct))[0];
            tenant.EnsureAccess(site.OrganizationId);
            return TypedResults.Ok(site);
        });

        sites.MapPut("/{id:guid}", async (Guid id, SiteRequest request, EasyPatchDbContext db, ITenantContext tenant, AuditService audit, TimeProvider clock,
            CancellationToken ct) =>
        {
            ValidateSite(request);
            var site = await db.Sites.FirstOrDefaultAsync(s => s.Id == id, ct) ?? throw AppException.NotFound("Site");
            tenant.EnsureAccess(site.OrganizationId);
            site.Name = request.Name.Trim();
            site.Description = Validator.Clean(request.Description);
            site.Address = Validator.Clean(request.Address);
            site.TimeZone = Validator.Clean(request.TimeZone) ?? site.TimeZone;
            site.UpdatedAt = clock.GetUtcNow();
            audit.Record("site.update", "Site", id.ToString(), site.OrganizationId, details: request);
            await db.SaveChangesAsync(ct);
            return TypedResults.Ok(await SiteQuery(db, s => s.Id == id).FirstAsync(ct));
        }).RequireAuthorization(Policies.Operator);

        sites.MapDelete("/{id:guid}", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, AuditService audit, CancellationToken ct) =>
        {
            var site = await db.Sites.FirstOrDefaultAsync(s => s.Id == id, ct) ?? throw AppException.NotFound("Site");
            tenant.EnsureAccess(site.OrganizationId);
            if (await db.Endpoints.AnyAsync(e => e.SiteId == id, ct))
            {
                throw AppException.Conflict("Move this site's endpoints to another site first, or archive the site instead.", "has_endpoints");
            }

            db.Sites.Remove(site);
            audit.Record("site.delete", "Site", id.ToString(), site.OrganizationId, details: new { site.Name });
            await db.SaveChangesAsync(ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Operator);

        sites.MapPost("/{id:guid}/archive", (Guid id, EasyPatchDbContext db, ITenantContext tenant, AuditService audit, TimeProvider clock, CancellationToken ct) =>
            SetSiteActiveAsync(id, false, db, tenant, audit, clock, ct)).RequireAuthorization(Policies.Operator);
        sites.MapPost("/{id:guid}/restore", (Guid id, EasyPatchDbContext db, ITenantContext tenant, AuditService audit, TimeProvider clock, CancellationToken ct) =>
            SetSiteActiveAsync(id, true, db, tenant, audit, clock, ct)).RequireAuthorization(Policies.Operator);

        sites.MapGet("/{id:guid}/policy", async (Guid id, EasyPatchDbContext db, PolicyService policies, ITenantContext tenant, CancellationToken ct) =>
        {
            var site = await db.Sites.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct) ?? throw AppException.NotFound("Site");
            tenant.EnsureAccess(site.OrganizationId);
            var policy = await policies.GetSitePolicyAsync(id, ct);
            return TypedResults.Ok(policy is null ? EmptyPolicy(PolicyScope.Site, site.OrganizationId, id) : ToDto(policy));
        });

        sites.MapPut("/{id:guid}/policy", async (Guid id, PolicyRequest request, PolicyService policies, ComplianceService compliance, EasyPatchDbContext db,
            ITenantContext tenant, AuditService audit, ClaimsPrincipal user, CancellationToken ct) =>
        {
            var site = await db.Sites.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct) ?? throw AppException.NotFound("Site");
            tenant.EnsureAccess(site.OrganizationId);
            var stored = await policies.UpsertAsync(PolicyScope.Site, site.OrganizationId, id, FromRequest(request), user.FindUserId(), ct);
            audit.Record("policy.update", "Policy", stored.Id.ToString(), site.OrganizationId, details: request);
            await db.SaveChangesAsync(ct);
            await compliance.RecomputeScopeAsync(site.OrganizationId, id, ct);
            return TypedResults.Ok(ToDto(stored));
        }).RequireAuthorization(Policies.Operator);

        sites.MapDelete("/{id:guid}/policy", async (Guid id, PolicyService policies, ComplianceService compliance, EasyPatchDbContext db,
            ITenantContext tenant, AuditService audit, CancellationToken ct) =>
        {
            var site = await db.Sites.AsNoTracking().FirstOrDefaultAsync(s => s.Id == id, ct) ?? throw AppException.NotFound("Site");
            tenant.EnsureAccess(site.OrganizationId);
            if (await policies.DeleteAsync(PolicyScope.Site, id, ct))
            {
                audit.Record("policy.delete", "Policy", null, site.OrganizationId, details: new { siteId = id });
                await db.SaveChangesAsync(ct);
                await compliance.RecomputeScopeAsync(site.OrganizationId, id, ct);
            }

            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Operator);

        var global = app.MapGroup("/api/v1/policies").WithTags("Policies");
        global.MapGet("/global", async (PolicyService policies, CancellationToken ct) => TypedResults.Ok(ToDto(await policies.GetGlobalAsync(ct))))
            .RequireAuthorization(Policies.Viewer);
        global.MapPut("/global", async (PolicyRequest request, PolicyService policies, ComplianceService compliance, EasyPatchDbContext db, AuditService audit,
            ClaimsPrincipal user, CancellationToken ct) =>
        {
            var stored = await policies.UpsertAsync(PolicyScope.Global, null, null, FromRequest(request), user.FindUserId(), ct);
            audit.Record("policy.update", "Policy", stored.Id.ToString(), details: request);
            await db.SaveChangesAsync(ct);
            await compliance.RecomputeScopeAsync(null, null, ct);
            return TypedResults.Ok(ToDto(stored));
        }).RequireAuthorization(Policies.SuperAdmin);
    }

    internal static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal);

    private static void ValidateOrganization(OrganizationRequest request)
    {
        new Validator()
            .Required("name", request.Name, 200)
            .Optional("description", request.Description, 2000)
            .Optional("contactName", request.ContactName, 200)
            .Optional("contactEmail", request.ContactEmail, 256)
            .Optional("notes", request.Notes, 4000)
            .Check(request.TimeZone is null || MaintenanceWindow.IsValidTimeZone(request.TimeZone), "timeZone", "Unknown time zone. Use an IANA name such as Europe/London.")
            .Check(string.IsNullOrWhiteSpace(request.ContactEmail) || request.ContactEmail.Contains('@', StringComparison.Ordinal), "contactEmail",
                "Enter a valid email address.")
            .ThrowIfInvalid();
    }

    private static void ValidateSite(SiteRequest request) =>
        new Validator()
            .Required("name", request.Name, 200)
            .Optional("description", request.Description, 2000)
            .Optional("address", request.Address, 1000)
            .Check(request.TimeZone is null || MaintenanceWindow.IsValidTimeZone(request.TimeZone), "timeZone", "Unknown time zone. Use an IANA name such as Europe/London.")
            .ThrowIfInvalid();

    private static void Apply(Organization org, OrganizationRequest request)
    {
        org.Description = Validator.Clean(request.Description);
        org.ContactName = Validator.Clean(request.ContactName);
        org.ContactEmail = Validator.Clean(request.ContactEmail);
        org.Notes = Validator.Clean(request.Notes);
        org.TimeZone = Validator.Clean(request.TimeZone) ?? org.TimeZone;
    }

    private static async Task<IResult> SetOrganizationActiveAsync(Guid id, bool active, EasyPatchDbContext db, ITenantContext tenant, AuditService audit,
        TimeProvider clock, CancellationToken ct)
    {
        tenant.EnsureAccess(id);
        var org = await db.Organizations.FirstOrDefaultAsync(o => o.Id == id, ct) ?? throw AppException.NotFound("Organization");
        var now = clock.GetUtcNow();
        org.IsActive = active;
        org.ArchivedAt = active ? null : now;
        org.UpdatedAt = now;
        audit.Record(active ? "organization.restore" : "organization.archive", "Organization", id.ToString(), id);
        await db.SaveChangesAsync(ct);
        return TypedResults.Ok(await LoadOrganizationAsync(db, id, ct));
    }

    private static async Task<IResult> SetSiteActiveAsync(Guid id, bool active, EasyPatchDbContext db, ITenantContext tenant, AuditService audit,
        TimeProvider clock, CancellationToken ct)
    {
        var site = await db.Sites.FirstOrDefaultAsync(s => s.Id == id, ct) ?? throw AppException.NotFound("Site");
        tenant.EnsureAccess(site.OrganizationId);
        var now = clock.GetUtcNow();
        site.IsActive = active;
        site.ArchivedAt = active ? null : now;
        site.UpdatedAt = now;
        audit.Record(active ? "site.restore" : "site.archive", "Site", id.ToString(), site.OrganizationId);
        await db.SaveChangesAsync(ct);
        return TypedResults.Ok(await SiteQuery(db, s => s.Id == id).FirstAsync(ct));
    }

    internal static IQueryable<SiteDto> SiteQuery(EasyPatchDbContext db, System.Linq.Expressions.Expression<Func<Site, bool>> filter) =>
        db.Sites.AsNoTracking().Where(filter).OrderBy(s => s.Name).Select(s => new SiteDto(
            s.Id, s.OrganizationId, s.Organization!.Name, s.Name, s.Description, s.Address, s.TimeZone, s.IsActive,
            db.Endpoints.Count(e => e.SiteId == s.Id && e.Status == EndpointStatus.Active),
            db.Endpoints.Count(e => e.SiteId == s.Id && e.Status == EndpointStatus.Active && e.RebootPending), s.CreatedAt, s.ArchivedAt));

    private static async Task<OrganizationDto> LoadOrganizationAsync(EasyPatchDbContext db, Guid id, CancellationToken ct)
    {
        var org = await db.Organizations.AsNoTracking().FirstOrDefaultAsync(o => o.Id == id, ct) ?? throw AppException.NotFound("Organization");
        var sites = await WithTagsAsync(db, await SiteQuery(db, s => s.OrganizationId == id).ToListAsync(ct), ct);
        var stats = await OrganizationStats.LoadAsync(db, [id], ct);
        var tags = await (from ot in db.OrganizationTags.AsNoTracking()
                          join t in db.Tags.AsNoTracking() on ot.TagId equals t.Id
                          where ot.OrganizationId == id
                          orderby t.Name
                          select t).ToListAsync(ct);
        return new OrganizationDto(org.Id, org.Name, org.Description, org.ContactName, org.ContactEmail, org.Notes, org.TimeZone, org.IsActive,
            org.CreatedAt, org.UpdatedAt, org.ArchivedAt, sites, OrganizationStats.ToSummary(org, stats), tags.Select(t => Mapping.ToRef(t)).ToList());
    }

    /// <summary>Adds each site's own tags (an organization's tags are on the organization).</summary>
    private static async Task<List<SiteDto>> WithTagsAsync(EasyPatchDbContext db, List<SiteDto> sites, CancellationToken ct)
    {
        var ids = sites.Select(s => s.Id).ToList();
        var rows = await (from st in db.SiteTags.AsNoTracking()
                          join t in db.Tags.AsNoTracking() on st.TagId equals t.Id
                          where ids.Contains(st.SiteId)
                          orderby t.Name
                          select new { st.SiteId, Tag = t }).ToListAsync(ct);
        var bySite = rows.ToLookup(r => r.SiteId, r => Mapping.ToRef(r.Tag));
        return sites.Select(s => s with { Tags = bySite[s.Id].ToList() }).ToList();
    }

    internal static PolicyDto ToDto(Policy p) => new(
        p.Id, p.Scope, p.OrganizationId, p.SiteId, p.CheckInIntervalSeconds, p.ScanIntervalMinutes, p.InventoryIntervalMinutes, p.JitterPercent,
        p.AllowedCategories, p.IncludeOptional, p.ExcludedKbs, p.AcceptEulas, p.AutoInstallEnabled, p.MaintenanceDays,
        p.MaintenanceStart?.ToString("HH:mm", CultureInfo.InvariantCulture), p.MaintenanceDurationMinutes, p.ScanStaleAfterHours,
        p.MaxConcurrentInstallsPerSite, p.UpdatedAt, p.EndpointId, p.TrayIconEnabled, p.InstallNotificationsEnabled,
        ToDto(p.RestartSchedule), p.WindowsUpdate, p.AgentAutoUpdateEnabled, p.InstallDelayDays, p.SecurityInstallDelayDays, p.TagId,
        p.KnownExploitedSkipsDelay, p.ApplicationUpdates, p.PreDownloadHours);

    internal static RestartScheduleDto? ToDto(RestartScheduleSettings? r) => r is null
        ? null
        : new RestartScheduleDto(r.Enabled, r.Days, r.Time.ToString("HH:mm", CultureInfo.InvariantCulture), r.Condition, r.Mode,
            r.CountdownMinutes, r.DeadlineMinutes, r.ExpiryMinutes);

    internal static PolicyDto EmptyPolicy(PolicyScope scope, Guid? organizationId, Guid? siteId, Guid? endpointId = null, Guid? tagId = null) => new(
        null, scope, organizationId, siteId, null, null, null, null, null, null, [], null, null, null, null, null, null, null, null, endpointId,
        TagId: tagId);

    internal static Policy FromRequest(PolicyRequest r)
    {
        TimeOnly? start = null;
        if (Validator.Clean(r.MaintenanceStart) is { } text)
        {
            start = TimeOnly.TryParseExact(text, ["HH:mm", "H:mm", "HH:mm:ss"], CultureInfo.InvariantCulture, DateTimeStyles.None, out var t)
                ? t
                : throw AppException.BadRequest("maintenanceStart must be a time in HH:mm format.", "validation_failed");
        }

        if (r.AllowedCategories is { } categories && categories.Any(c => !Enum.TryParse<EasyPatch.Contracts.UpdateCategory>(c, true, out _)))
        {
            throw AppException.BadRequest("allowedCategories contains an unknown category.", "validation_failed");
        }

        return new Policy
        {
            CheckInIntervalSeconds = r.CheckInIntervalSeconds,
            ScanIntervalMinutes = r.ScanIntervalMinutes,
            InventoryIntervalMinutes = r.InventoryIntervalMinutes,
            JitterPercent = r.JitterPercent,
            AllowedCategories = r.AllowedCategories?.Select(c => Enum.Parse<EasyPatch.Contracts.UpdateCategory>(c, true).ToString()).Distinct().ToList(),
            IncludeOptional = r.IncludeOptional,
            ExcludedKbs = r.ExcludedKbs?.ToList() ?? [],
            AcceptEulas = r.AcceptEulas,
            AutoInstallEnabled = r.AutoInstallEnabled,
            InstallDelayDays = r.InstallDelayDays,
            SecurityInstallDelayDays = r.SecurityInstallDelayDays,
            KnownExploitedSkipsDelay = r.KnownExploitedSkipsDelay,
            MaintenanceDays = r.MaintenanceDays?.Distinct().Order().ToList(),
            MaintenanceStart = start,
            MaintenanceDurationMinutes = r.MaintenanceDurationMinutes,
            PreDownloadHours = r.PreDownloadHours,
            ScanStaleAfterHours = r.ScanStaleAfterHours,
            MaxConcurrentInstallsPerSite = r.MaxConcurrentInstallsPerSite,
            TrayIconEnabled = r.TrayIconEnabled,
            InstallNotificationsEnabled = r.InstallNotificationsEnabled,
            AgentAutoUpdateEnabled = r.AgentAutoUpdateEnabled,
            RestartSchedule = FromRequest(r.RestartSchedule),
            WindowsUpdate = r.WindowsUpdate,
            ApplicationUpdates = r.ApplicationUpdates?.Normalized(),
        };
    }

    private static RestartScheduleSettings? FromRequest(RestartScheduleDto? r)
    {
        if (r is null)
        {
            return null;
        }

        if (!TimeOnly.TryParseExact(r.Time ?? "", ["HH:mm", "H:mm"], CultureInfo.InvariantCulture, DateTimeStyles.None, out var time))
        {
            throw AppException.BadRequest("restartSchedule.time must be a time in HH:mm format.", "validation_failed");
        }

        return new RestartScheduleSettings
        {
            Enabled = r.Enabled,
            Days = (r.Days ?? []).Distinct().Order().ToList(),
            Time = time,
            Condition = r.Condition,
            Mode = r.Mode,
            CountdownMinutes = r.CountdownMinutes,
            DeadlineMinutes = r.DeadlineMinutes,
            ExpiryMinutes = r.ExpiryMinutes,
        };
    }
}

/// <summary>Per-organization endpoint aggregates for list and dashboard views.</summary>
internal static class OrganizationStats
{
    internal sealed record Row(Guid OrganizationId, int Endpoints, int Online, int Compliant, int MissingRequired, int Failed, int Reboot,
        DateTimeOffset? LastActivity, int Sites);

    public static async Task<Dictionary<Guid, Row>> LoadAsync(EasyPatchDbContext db, IReadOnlyCollection<Guid> organizationIds, CancellationToken ct)
    {
        var rows = await db.Endpoints.AsNoTracking()
            .Where(e => organizationIds.Contains(e.OrganizationId) && e.Status == EndpointStatus.Active)
            .GroupBy(e => e.OrganizationId)
            .Select(g => new
            {
                g.Key,
                Endpoints = g.Count(),
                Online = g.Count(e => e.IsOnline),
                Compliant = g.Count(e => e.ComplianceStatus == ComplianceStatus.Compliant),
                MissingRequired = g.Sum(e => e.MissingRequiredCount),
                Failed = g.Count(e => e.ComplianceStatus == ComplianceStatus.FailedUpdates),
                Reboot = g.Count(e => e.RebootPending),
                LastActivity = g.Max(e => e.LastCheckInAt),
            }).ToListAsync(ct);
        var sites = await db.Sites.AsNoTracking().Where(s => organizationIds.Contains(s.OrganizationId) && s.IsActive)
            .GroupBy(s => s.OrganizationId).Select(g => new { g.Key, Count = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.Count, ct);
        var result = rows.ToDictionary(r => r.Key, r => new Row(r.Key, r.Endpoints, r.Online, r.Compliant, r.MissingRequired, r.Failed, r.Reboot,
            r.LastActivity, sites.GetValueOrDefault(r.Key)));
        foreach (var (orgId, count) in sites)
        {
            result.TryAdd(orgId, new Row(orgId, 0, 0, 0, 0, 0, 0, null, count));
        }

        return result;
    }

    public static OrganizationSummaryDto ToSummary(Organization org, IReadOnlyDictionary<Guid, Row> stats)
    {
        var s = stats.GetValueOrDefault(org.Id) ?? new Row(org.Id, 0, 0, 0, 0, 0, 0, null, 0);
        return new OrganizationSummaryDto(org.Id, org.Name, org.Description, org.TimeZone, org.IsActive, s.Sites, s.Endpoints, s.Online,
            s.Endpoints - s.Online, s.Compliant, s.Endpoints - s.Compliant, s.MissingRequired, s.Failed, s.Reboot,
            ComplianceCalculator.Percentage(s.Compliant, s.Endpoints), s.LastActivity, org.CreatedAt);
    }
}
