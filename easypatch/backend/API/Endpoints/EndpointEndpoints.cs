using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using EasyPatch.Contracts.Policy;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using EndpointEntity = EasyPatch.Core.Entities.Endpoint;

namespace EasyPatch.Api.Endpoints;

public sealed record EndpointListQuery(
    Guid? OrganizationId, Guid? SiteId, string? Search, ComplianceStatus? Compliance, bool? Online, string? Os, bool? RebootPending, bool? OutdatedAgent,
    EndpointStatus? Status, string? Sort, string? Dir, int? Page, int? PageSize, Guid? TagId = null, bool? KnownExploited = null);

public static class EndpointEndpoints
{
    public static void MapEndpointEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/api/v1/endpoints").WithTags("Endpoints").RequireAuthorization(Policies.Viewer);

        g.MapGet("/", async ([AsParameters] EndpointListQuery query, EasyPatchDbContext db, ITenantContext tenant, AgentPackageService packages,
            CancellationToken ct) => TypedResults.Ok(await ListAsync(query, db, tenant, packages, ct)));

        app.MapGet("/api/v1/organizations/{id:guid}/endpoints", async (Guid id, [AsParameters] EndpointListQuery query, EasyPatchDbContext db,
                ITenantContext tenant, AgentPackageService packages, CancellationToken ct) =>
            {
                tenant.EnsureAccess(id);
                return TypedResults.Ok(await ListAsync(query with { OrganizationId = id }, db, tenant, packages, ct));
            })
            .WithTags("Endpoints").RequireAuthorization(Policies.Viewer);

        g.MapGet("/{id:guid}", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, AgentPackageService packages, PolicyService policies,
                CancellationToken ct) =>
            TypedResults.Ok(await LoadDetailAsync(id, db, tenant, packages, policies, ct)));

        g.MapPut("/{id:guid}", async (Guid id, UpdateEndpointRequest request, EasyPatchDbContext db, ITenantContext tenant, AuditService audit,
            ComplianceService compliance, AgentPackageService packages, PolicyService policies, TimeProvider clock, CancellationToken ct) =>
        {
            var endpoint = await LoadForUpdateAsync(db, tenant, id, ct);
            new Validator().Optional("notes", request.Notes, 4000).ThrowIfInvalid();
            if (request.SiteId is { } siteId && !await db.Sites.AnyAsync(s => s.Id == siteId && s.OrganizationId == endpoint.OrganizationId, ct))
            {
                throw AppException.BadRequest("The site does not belong to this endpoint's organization.", "validation_failed");
            }

            var siteChanged = endpoint.SiteId != request.SiteId;
            var esuChanged = request.EsuOverride is { } esu && esu != endpoint.EsuOverride;
            endpoint.SiteId = request.SiteId;
            endpoint.Notes = Validator.Clean(request.Notes);
            endpoint.EsuOverride = request.EsuOverride ?? endpoint.EsuOverride;
            endpoint.UpdatedAt = clock.GetUtcNow();
            audit.Record("endpoint.update", "Endpoint", id.ToString(), endpoint.OrganizationId, id, request);
            await db.SaveChangesAsync(ct);
            if (siteChanged || esuChanged)
            {
                await compliance.RecomputeAsync([id], ct);
            }

            return TypedResults.Ok(await LoadDetailAsync(id, db, tenant, packages, policies, ct));
        }).RequireAuthorization(Policies.Operator);

        g.MapDelete("/{id:guid}", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, EnrollmentService enrollment, AuditService audit,
            CancellationToken ct) =>
        {
            var endpoint = await LoadForUpdateAsync(db, tenant, id, ct);
            if (endpoint.Status == EndpointStatus.Active)
            {
                await enrollment.RevokeEndpointAsync(id, "Endpoint deleted by administrator", EndpointStatus.Decommissioned, ct);
            }

            db.ChangeTracker.Clear();
            await db.Endpoints.Where(e => e.Id == id).ExecuteDeleteAsync(ct);
            audit.Record("endpoint.delete", "Endpoint", id.ToString(), endpoint.OrganizationId, null, new { endpoint.Hostname });
            await db.SaveChangesAsync(ct);
            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Operator);

        g.MapPost("/{id:guid}/revoke", async (Guid id, RevokeEndpointRequest? request, EasyPatchDbContext db, ITenantContext tenant,
            EnrollmentService enrollment, AgentPackageService packages, PolicyService policies, CancellationToken ct) =>
        {
            await LoadForUpdateAsync(db, tenant, id, ct);
            await enrollment.RevokeEndpointAsync(id, Validator.Clean(request?.Reason) ?? "Revoked by administrator", EndpointStatus.Revoked, ct);
            return TypedResults.Ok(await LoadDetailAsync(id, db, tenant, packages, policies, ct));
        }).RequireAuthorization(Policies.Operator);

        g.MapGet("/{id:guid}/updates", async (Guid id, EndpointUpdateState? state, UpdateCategory? category, bool? requiredOnly, EasyPatchDbContext db,
            ITenantContext tenant, UpdateHoldService holdService, CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var orgId = await db.Endpoints.AsNoTracking().Where(e => e.Id == id).Select(e => e.OrganizationId).FirstAsync(ct);
            var holds = await holdService.ActiveForAsync(orgId, ct);
            var query = db.EndpointUpdates.AsNoTracking().Where(u => u.EndpointId == id);
            query = state is { } s
                ? query.Where(u => u.State == s)
                : query.Where(u => u.State == EndpointUpdateState.Missing || u.State == EndpointUpdateState.Failed ||
                                   u.State == EndpointUpdateState.PendingReboot || u.State == EndpointUpdateState.PendingVerification ||
                                   u.State == EndpointUpdateState.Reoffered || u.State == EndpointUpdateState.Excluded);
            if (category is { } c)
            {
                query = query.Where(u => u.Update!.Category == c);
            }

            if (requiredOnly == true)
            {
                query = query.Where(u => u.IsRequired);
            }

            var rows = await query.Select(u => new { Row = u, u.Update }).ToListAsync(ct);
            var overlay = await LiveOverlayAsync(db, id, ct);
            var result = rows
                .OrderBy(r => r.Row.State switch
                {
                    EndpointUpdateState.Failed => 0,
                    EndpointUpdateState.Missing => 1,
                    EndpointUpdateState.PendingReboot => 2,
                    EndpointUpdateState.PendingVerification => 3,
                    EndpointUpdateState.Reoffered => 4,
                    _ => 5,
                })
                .ThenByDescending(r => r.Row.KnownExploited)
                .ThenByDescending(r => r.Row.IsRequired)
                .ThenByDescending(r => r.Update!.ReleaseDate)
                .Select(r => ToUpdateDto(r.Row, r.Update!, overlay.GetValueOrDefault(r.Row.UpdateGuid)) with
                {
                    HoldReason = r.Row.State is EndpointUpdateState.Missing or EndpointUpdateState.Failed && holds.TryGetValue(r.Row.UpdateGuid, out var hold)
                        ? hold.Reason
                        : null,
                })
                .ToList();
            return TypedResults.Ok(result);
        });

        g.MapGet("/{id:guid}/installed-updates", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var rows = await db.EndpointUpdates.AsNoTracking().Where(u => u.EndpointId == id && u.State == EndpointUpdateState.Installed)
                .Select(u => new { Row = u, u.Update }).ToListAsync(ct);
            var overlay = await LiveOverlayAsync(db, id, ct);
            return TypedResults.Ok(rows.OrderByDescending(r => r.Row.InstalledAt ?? r.Row.StateChangedAt)
                .Select(r => ToUpdateDto(r.Row, r.Update!, overlay.GetValueOrDefault(r.Row.UpdateGuid))).ToList());
        });

        g.MapGet("/{id:guid}/update-history", async (Guid id, string? search, int? page, int? pageSize, EasyPatchDbContext db, ITenantContext tenant,
            CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var query = db.UpdateHistoryEntries.AsNoTracking().Where(h => h.EndpointId == id);
            if (Validator.Clean(search) is { } s)
            {
                var pattern = "%" + OrganizationEndpoints.EscapeLike(s) + "%";
                query = query.Where(h => EF.Functions.ILike(h.Title, pattern) || (h.KbNumber != null && EF.Functions.ILike(h.KbNumber, pattern)));
            }

            var paged = await query.OrderByDescending(h => h.Date).ToPagedAsync(PageRequest.From(page, pageSize), ct);
            return TypedResults.Ok(new PagedResult<UpdateHistoryDto>(paged.Items.Select(Mapping.History).ToList(), paged.Page, paged.PageSize, paged.TotalCount));
        });

        g.MapGet("/{id:guid}/events", async (Guid id, EventSeverity? severity, int? page, int? pageSize, EasyPatchDbContext db, ITenantContext tenant,
            CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var query = db.EndpointEvents.AsNoTracking().Where(e => e.EndpointId == id);
            if (severity is { } sev)
            {
                query = query.Where(e => e.Severity == sev);
            }

            return TypedResults.Ok(await query.OrderByDescending(e => e.Id).Select(Mapping.Event).ToPagedAsync(PageRequest.From(page, pageSize), ct));
        });

        g.MapGet("/{id:guid}/jobs", async (Guid id, int? page, int? pageSize, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            return TypedResults.Ok(await db.Jobs.AsNoTracking().Where(j => j.EndpointId == id).OrderByDescending(j => j.CreatedAt)
                .Select(Mapping.JobSummary).ToPagedAsync(PageRequest.From(page, pageSize), ct));
        });

        g.MapGet("/{id:guid}/effective-policy", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, PolicyService policies, CancellationToken ct) =>
        {
            var endpoint = await db.Endpoints.AsNoTracking().Include(e => e.Site).Include(e => e.Organization)
                .FirstOrDefaultAsync(e => e.Id == id, ct) ?? throw AppException.NotFound("Endpoint");
            tenant.EnsureAccess(endpoint.OrganizationId);
            var p = await policies.ResolveAsync(endpoint, ct);
            var window = p.MaintenanceWindow;
            var registry = Enum.GetValues<WindowsUpdatePolicyGroup>()
                .SelectMany(g => (WindowsUpdatePolicyRegistry.DesiredValues(p.WindowsUpdate, g) ?? [])
                    .Select(v => new PolicyRegistryValueDto(g, @"HKLM\" + v.Path, v.Name, v.Display)))
                .ToList();
            return TypedResults.Ok(new EffectivePolicyDto(
                p.CheckInIntervalSeconds, p.ScanIntervalMinutes, p.InventoryIntervalMinutes, p.JitterPercent, p.AllowedCategories, p.IncludeOptional,
                p.ExcludedKbs, p.AcceptEulas, p.AutoInstallEnabled, window?.Days.Select(d => (int)d).ToList(),
                window?.Start.ToString("HH:mm", CultureInfo.InvariantCulture), window?.DurationMinutes,
                endpoint.Site?.TimeZone ?? endpoint.Organization!.TimeZone, p.ScanStaleAfterHours, p.MaxConcurrentInstallsPerSite, p.Sources,
                p.TrayIconEnabled, p.InstallNotificationsEnabled, OrganizationEndpoints.ToDto(p.RestartSchedule), p.WindowsUpdate, registry,
                p.AgentAutoUpdateEnabled, p.InstallDelayDays, p.SecurityInstallDelayDays, p.SourceTags, p.KnownExploitedSkipsDelay,
                p.ApplicationUpdates, p.PreDownloadHours));
        });

        // Per-endpoint policy overrides (the most specific layer).
        g.MapGet("/{id:guid}/policy", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, PolicyService policies, CancellationToken ct) =>
        {
            var endpoint = await db.Endpoints.AsNoTracking().FirstOrDefaultAsync(e => e.Id == id, ct) ?? throw AppException.NotFound("Endpoint");
            tenant.EnsureAccess(endpoint.OrganizationId);
            var policy = await policies.GetEndpointPolicyAsync(id, ct);
            return TypedResults.Ok(policy is null
                ? OrganizationEndpoints.EmptyPolicy(PolicyScope.Endpoint, endpoint.OrganizationId, endpoint.SiteId, id)
                : OrganizationEndpoints.ToDto(policy));
        });

        g.MapPut("/{id:guid}/policy", async (Guid id, PolicyRequest request, EasyPatchDbContext db, ITenantContext tenant, PolicyService policies,
            ComplianceService compliance, AuditService audit, ClaimsPrincipal user, CancellationToken ct) =>
        {
            var endpoint = await db.Endpoints.AsNoTracking().FirstOrDefaultAsync(e => e.Id == id, ct) ?? throw AppException.NotFound("Endpoint");
            tenant.EnsureAccess(endpoint.OrganizationId);
            var stored = await policies.UpsertAsync(PolicyScope.Endpoint, endpoint.OrganizationId, null, id, OrganizationEndpoints.FromRequest(request),
                user.FindUserId(), ct);
            audit.Record("policy.update", "Policy", stored.Id.ToString(), endpoint.OrganizationId, id, request);
            await db.SaveChangesAsync(ct);
            await compliance.RecomputeAsync([id], ct);
            return TypedResults.Ok(OrganizationEndpoints.ToDto(stored));
        }).RequireAuthorization(Policies.Operator);

        g.MapDelete("/{id:guid}/policy", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, PolicyService policies,
            ComplianceService compliance, AuditService audit, CancellationToken ct) =>
        {
            var endpoint = await db.Endpoints.AsNoTracking().FirstOrDefaultAsync(e => e.Id == id, ct) ?? throw AppException.NotFound("Endpoint");
            tenant.EnsureAccess(endpoint.OrganizationId);
            if (await policies.DeleteAsync(PolicyScope.Endpoint, id, ct))
            {
                audit.Record("policy.delete", "Policy", null, endpoint.OrganizationId, id);
                await db.SaveChangesAsync(ct);
                await compliance.RecomputeAsync([id], ct);
            }

            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Operator);

        g.MapGet("/{id:guid}/install-preview", async (Guid id, string? mode, string? updateGuids, EasyPatchDbContext db, ITenantContext tenant,
            InstallPreviewService previews, CancellationToken ct) =>
        {
            var endpoint = await db.Endpoints.AsNoTracking().FirstOrDefaultAsync(e => e.Id == id, ct) ?? throw AppException.NotFound("Endpoint");
            tenant.EnsureAccess(endpoint.OrganizationId);
            var installMode = string.Equals(mode, "selected", StringComparison.OrdinalIgnoreCase) || string.Equals(mode, nameof(InstallMode.Selected), StringComparison.Ordinal)
                ? InstallMode.Selected
                : InstallMode.AllEligible;
            var selected = ParseGuids(updateGuids);
            return TypedResults.Ok(await previews.BuildAsync(endpoint, installMode, selected, ct));
        });

        g.MapPost("/{id:guid}/install-updates", async (Guid id, InstallUpdatesRequest request, EasyPatchDbContext db, ITenantContext tenant, JobService jobs,
            CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var job = await jobs.CreateAsync(new CreateJobRequest(id, JobType.InstallUpdates, request.Mode, request.UpdateGuids, request.Force), ct);
            return TypedResults.Accepted($"/api/v1/jobs/{job.Id}", await JobEndpoints.LoadSummaryAsync(db, job.Id, ct));
        }).RequireAuthorization(Policies.Operator);

        g.MapPost("/{id:guid}/scan", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var job = await jobs.CreateAsync(new CreateJobRequest(id, JobType.UpdateScan), ct);
            return TypedResults.Accepted($"/api/v1/jobs/{job.Id}", await JobEndpoints.LoadSummaryAsync(db, job.Id, ct));
        }).RequireAuthorization(Policies.Operator);

        g.MapPost("/{id:guid}/inventory-refresh", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var job = await jobs.CreateAsync(new CreateJobRequest(id, JobType.InventoryRefresh), ct);
            return TypedResults.Accepted($"/api/v1/jobs/{job.Id}", await JobEndpoints.LoadSummaryAsync(db, job.Id, ct));
        }).RequireAuthorization(Policies.Operator);

        // Rolling back an update: the agent removes only that update (Windows Update or DISM) and never restarts the computer.
        g.MapPost("/{id:guid}/updates/{updateGuid:guid}/uninstall", async (Guid id, Guid updateGuid, UninstallUpdateRequest request, EasyPatchDbContext db,
            ITenantContext tenant, UpdateRemovalService removals, CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            new Validator().Optional("reason", request.Reason, 500).ThrowIfInvalid();
            var job = await removals.RemoveAsync(id, updateGuid, request.Block, Validator.Clean(request.Reason), ct);
            return TypedResults.Accepted($"/api/v1/jobs/{job.Id}", await JobEndpoints.LoadSummaryAsync(db, job.Id, ct));
        }).RequireAuthorization(Policies.Operator);

        g.MapPost("/{id:guid}/exclusions", async (Guid id, ExclusionRequest request, EasyPatchDbContext db, ITenantContext tenant, AuditService audit,
            ComplianceService compliance, ClaimsPrincipal user, TimeProvider clock, CancellationToken ct) =>
        {
            var endpoint = await LoadForUpdateAsync(db, tenant, id, ct);
            new Validator().Optional("reason", request.Reason, 500).Check(request.UpdateGuid != Guid.Empty, "updateGuid", "Required.").ThrowIfInvalid();
            if (!await db.UpdateExclusions.AnyAsync(x => x.EndpointId == id && x.UpdateGuid == request.UpdateGuid, ct))
            {
                db.UpdateExclusions.Add(new UpdateExclusion
                {
                    Id = Guid.CreateVersion7(), EndpointId = id, UpdateGuid = request.UpdateGuid, Reason = Validator.Clean(request.Reason),
                    CreatedAt = clock.GetUtcNow(), CreatedByUserId = user.GetUserId(),
                });
                audit.Record("endpoint.update_excluded", "Endpoint", id.ToString(), endpoint.OrganizationId, id, new { request.UpdateGuid, request.Reason });
                await db.SaveChangesAsync(ct);
                await compliance.RecomputeAsync([id], ct);
            }

            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Operator);

        g.MapDelete("/{id:guid}/exclusions/{updateGuid:guid}", async (Guid id, Guid updateGuid, EasyPatchDbContext db, ITenantContext tenant,
            AuditService audit, ComplianceService compliance, CancellationToken ct) =>
        {
            var endpoint = await LoadForUpdateAsync(db, tenant, id, ct);
            var removed = await db.UpdateExclusions.Where(x => x.EndpointId == id && x.UpdateGuid == updateGuid).ExecuteDeleteAsync(ct);
            if (removed > 0)
            {
                audit.Record("endpoint.update_included", "Endpoint", id.ToString(), endpoint.OrganizationId, id, new { updateGuid });
                await db.SaveChangesAsync(ct);
                await compliance.RecomputeAsync([id], ct);
            }

            return TypedResults.NoContent();
        }).RequireAuthorization(Policies.Operator);

        g.MapPost("/bulk/scan", (BulkEndpointsRequest request, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, CancellationToken ct) =>
            BulkAsync(request, db, tenant, jobs, id => new CreateJobRequest(id, JobType.UpdateScan, Force: false), ct)).RequireAuthorization(Policies.Operator);

        g.MapPost("/bulk/install-updates", (BulkEndpointsRequest request, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, CancellationToken ct) =>
            BulkAsync(request, db, tenant, jobs, id => new CreateJobRequest(id, JobType.InstallUpdates, InstallMode.AllEligible, Force: request.Force), ct))
            .RequireAuthorization(Policies.Operator);

        // Restarts are always an explicit administrator action (or an administrator-configured schedule).
        g.MapPost("/{id:guid}/restart", async (Guid id, RestartRequest request, EasyPatchDbContext db, ITenantContext tenant, JobService jobs,
            TimeProvider clock, CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var job = await jobs.CreateAsync(RestartJob(id, request, clock.GetUtcNow()), ct);
            return TypedResults.Accepted($"/api/v1/jobs/{job.Id}", await JobEndpoints.LoadSummaryAsync(db, job.Id, ct));
        }).RequireAuthorization(Policies.Operator);

        g.MapPost("/{id:guid}/notify", async (Guid id, NotifyRequest request, EasyPatchDbContext db, ITenantContext tenant, JobService jobs,
            CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var job = await jobs.CreateAsync(NotifyJob(id, request), ct);
            return TypedResults.Accepted($"/api/v1/jobs/{job.Id}", await JobEndpoints.LoadSummaryAsync(db, job.Id, ct));
        }).RequireAuthorization(Policies.Operator);

        g.MapPost("/bulk/restart", (BulkRestartRequest request, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, TimeProvider clock,
                CancellationToken ct) =>
            BulkAsync(new BulkEndpointsRequest(request.EndpointIds, request.Restart.Force), db, tenant, jobs,
                id => RestartJob(id, request.Restart, clock.GetUtcNow()), ct))
            .RequireAuthorization(Policies.Operator);

        g.MapPost("/bulk/notify", (BulkNotifyRequest request, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, CancellationToken ct) =>
            BulkAsync(new BulkEndpointsRequest(request.EndpointIds, false), db, tenant, jobs, id => NotifyJob(id, request.Message), ct))
            .RequireAuthorization(Policies.Operator);

        // Agent updates install only packages whose release signature the agent verifies against its built-in key.
        g.MapPost("/{id:guid}/agent-update", async (Guid id, AgentUpdateRequest request, EasyPatchDbContext db, ITenantContext tenant, JobService jobs,
            CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var job = await jobs.CreateAsync(new CreateJobRequest(id, JobType.AgentUpdate, AgentVersion: Validator.Clean(request.Version)), ct);
            return TypedResults.Accepted($"/api/v1/jobs/{job.Id}", await JobEndpoints.LoadSummaryAsync(db, job.Id, ct));
        }).RequireAuthorization(Policies.Operator);

        // Removes the EasyPatch agent package from the endpoint (nothing else). The job completes when the agent unenrolls as
        // part of the removal; the endpoint is then decommissioned.
        g.MapPost("/{id:guid}/uninstall-agent", async (Guid id, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, CancellationToken ct) =>
        {
            await EnsureEndpointAccessAsync(db, tenant, id, ct);
            var job = await jobs.CreateAsync(new CreateJobRequest(id, JobType.UninstallAgent), ct);
            return TypedResults.Accepted($"/api/v1/jobs/{job.Id}", await JobEndpoints.LoadSummaryAsync(db, job.Id, ct));
        }).RequireAuthorization(Policies.Operator);

        g.MapPost("/bulk/agent-update", (BulkAgentUpdateRequest request, EasyPatchDbContext db, ITenantContext tenant, JobService jobs, CancellationToken ct) =>
            BulkAsync(new BulkEndpointsRequest(request.EndpointIds, false), db, tenant, jobs,
                id => new CreateJobRequest(id, JobType.AgentUpdate, AgentVersion: Validator.Clean(request.Version)), ct))
            .RequireAuthorization(Policies.Operator);

        app.MapGet("/api/v1/user-messages", () => TypedResults.Ok(Enum.GetValues<UserMessagePreset>()
                .Select(p => new UserMessagePresetDto(p, UserMessages.Title(p), UserMessages.Body(p, p == UserMessagePreset.RestartScheduled ? "{time}" : null),
                    p == UserMessagePreset.RestartScheduled))
                .ToList()))
            .WithTags("Endpoints").RequireAuthorization(Policies.Viewer);
    }

    internal static CreateJobRequest RestartJob(Guid id, RestartRequest request, DateTimeOffset now)
    {
        var expiresAfter = request.ExpiresAfterMinutes ?? 120;
        if (expiresAfter is < 15 or > 1440)
        {
            throw AppException.BadRequest("A restart can wait 15 minutes to 24 hours for an offline computer.", "validation_failed");
        }

        var payload = new RestartPayload
        {
            Mode = request.Mode,
            Condition = request.Condition,
            CountdownMinutes = request.CountdownMinutes ?? 5,
            DeadlineMinutes = request.DeadlineMinutes ?? 240,
        };
        var start = request.ScheduledAt is { } at && at > now ? at : now;
        return new CreateJobRequest(id, JobType.Restart, Force: request.Force, Restart: payload, NotBefore: request.ScheduledAt,
            ExpiresAt: start.AddMinutes(expiresAfter));
    }

    private static CreateJobRequest NotifyJob(Guid id, NotifyRequest request) =>
        new(id, JobType.NotifyUser, Notify: new NotifyUserPayload { Preset = request.Preset, ScheduledAt = request.RestartAt });

    internal static async Task<PagedResult<EndpointSummaryDto>> ListAsync(EndpointListQuery q, EasyPatchDbContext db, ITenantContext tenant,
        AgentPackageService packages, CancellationToken ct)
    {
        var query = db.Endpoints.AsNoTracking().ForTenant(tenant, e => e.OrganizationId);
        query = q.Status is { } status ? query.Where(e => e.Status == status) : query.Where(e => e.Status == EndpointStatus.Active);
        if (q.OrganizationId is { } orgId)
        {
            query = query.Where(e => e.OrganizationId == orgId);
        }

        if (q.SiteId is { } siteId)
        {
            query = query.Where(e => e.SiteId == siteId);
        }

        if (Validator.Clean(q.Search) is { } search)
        {
            var pattern = "%" + OrganizationEndpoints.EscapeLike(search) + "%";
            query = query.Where(e => EF.Functions.ILike(e.Hostname, pattern) || (e.SerialNumber != null && EF.Functions.ILike(e.SerialNumber, pattern)) ||
                                     (e.LastSeenIp != null && EF.Functions.ILike(e.LastSeenIp, pattern)) ||
                                     EF.Functions.ILike(e.Organization!.Name, pattern));
        }

        if (q.Compliance is { } compliance)
        {
            query = query.Where(e => e.ComplianceStatus == compliance);
        }

        if (q.Online is { } online)
        {
            query = query.Where(e => e.IsOnline == online);
        }

        if (Validator.Clean(q.Os) is { } os)
        {
            var pattern = "%" + OrganizationEndpoints.EscapeLike(os) + "%";
            query = query.Where(e => e.OperatingSystem != null && EF.Functions.ILike(e.OperatingSystem, pattern));
        }

        if (q.RebootPending is { } reboot)
        {
            query = query.Where(e => e.RebootPending == reboot);
        }

        if (q.TagId is { } tagId)
        {
            query = query.WithTag(db, tagId);
        }

        if (q.KnownExploited is { } exploited)
        {
            query = exploited ? query.Where(e => e.KnownExploitedMissingCount > 0) : query.Where(e => e.KnownExploitedMissingCount == 0);
        }

        var latest = Mapping.LatestAgentVersions.From(packages);

        var desc = PagingExtensions.IsDescending(q.Dir);
        query = (q.Sort?.ToLowerInvariant()) switch
        {
            "organization" => desc ? query.OrderByDescending(e => e.Organization!.Name).ThenBy(e => e.Hostname) : query.OrderBy(e => e.Organization!.Name).ThenBy(e => e.Hostname),
            "site" => desc ? query.OrderByDescending(e => e.Site!.Name).ThenBy(e => e.Hostname) : query.OrderBy(e => e.Site!.Name).ThenBy(e => e.Hostname),
            "os" => desc ? query.OrderByDescending(e => e.OsBuildNumber).ThenBy(e => e.Hostname) : query.OrderBy(e => e.OsBuildNumber).ThenBy(e => e.Hostname),
            "missing" => desc ? query.OrderByDescending(e => e.MissingRequiredCount).ThenBy(e => e.Hostname) : query.OrderBy(e => e.MissingRequiredCount).ThenBy(e => e.Hostname),
            "knownexploited" => desc ? query.OrderByDescending(e => e.KnownExploitedMissingCount).ThenBy(e => e.Hostname) : query.OrderBy(e => e.KnownExploitedMissingCount).ThenBy(e => e.Hostname),
            "lastcheckin" => desc ? query.OrderByDescending(e => e.LastCheckInAt).ThenBy(e => e.Hostname) : query.OrderBy(e => e.LastCheckInAt).ThenBy(e => e.Hostname),
            "compliance" => desc ? query.OrderByDescending(e => e.ComplianceStatus).ThenBy(e => e.Hostname) : query.OrderBy(e => e.ComplianceStatus).ThenBy(e => e.Hostname),
            "agentversion" => desc ? query.OrderByDescending(e => e.AgentVersion).ThenBy(e => e.Hostname) : query.OrderBy(e => e.AgentVersion).ThenBy(e => e.Hostname),
            _ => desc ? query.OrderByDescending(e => e.Hostname) : query.OrderBy(e => e.Hostname),
        };

        var page = PageRequest.From(q.Page, q.PageSize);
        if (q.OutdatedAgent == true && latest.Any)
        {
            // Version comparison happens in memory (per package format).
            var all = (await query.Select(Mapping.EndpointRowProjection).ToListAsync(ct))
                .Where(r => latest.IsOutdated(r.AgentVersion, r.AgentPackageFormat)).ToList();
            var pageRows = all.Skip(page.Skip).Take(page.PageSize).ToList();
            var pageTags = await Mapping.LoadTagsAsync(db, pageRows.Select(r => r.Id).ToList(), ct);
            return new PagedResult<EndpointSummaryDto>(pageRows.Select(r => Mapping.ToSummary(r, latest, pageTags.GetValueOrDefault(r.Id))).ToList(),
                page.Page, page.PageSize, all.Count);
        }

        var paged = await query.Select(Mapping.EndpointRowProjection).ToPagedAsync(page, ct);
        var tags = await Mapping.LoadTagsAsync(db, paged.Items.Select(r => r.Id).ToList(), ct);
        return new PagedResult<EndpointSummaryDto>(paged.Items.Select(r => Mapping.ToSummary(r, latest, tags.GetValueOrDefault(r.Id))).ToList(),
            paged.Page, paged.PageSize, paged.TotalCount);
    }

    private static async Task<EndpointDetailDto> LoadDetailAsync(Guid id, EasyPatchDbContext db, ITenantContext tenant, AgentPackageService packages,
        PolicyService policies, CancellationToken ct)
    {
        var e = await db.Endpoints.AsNoTracking().Include(x => x.Organization).Include(x => x.Site).FirstOrDefaultAsync(x => x.Id == id, ct)
                ?? throw AppException.NotFound("Endpoint");
        tenant.EnsureAccess(e.OrganizationId);
        var latest = Mapping.LatestAgentVersions.From(packages);
        var row = new Mapping.EndpointRow(e.Id, e.Hostname, e.OrganizationId, e.Organization!.Name, e.SiteId, e.Site?.Name, e.Status, e.OperatingSystem,
            e.OsVersion, e.OsBuild, e.OsBuildNumber, e.OsProductType, e.Architecture, e.AgentVersion, e.IsOnline, e.LastCheckInAt, e.LastScanAt,
            e.ComplianceStatus, e.MissingRequiredCount, e.MissingTotalCount, e.FailedCount, e.RebootPending, e.OsSupportStatus, e.CurrentActivity, e.LastSeenIp,
            e.Platform, e.AgentPackageFormat, e.MissingDeferredCount, e.KnownExploitedMissingCount);
        var endpointTags = await Mapping.LoadTagsAsync(db, [id], ct);
        var credentials = await db.AgentCredentials.AsNoTracking().Where(c => c.EndpointId == id).OrderByDescending(c => c.CreatedAt).Take(10)
            .Select(c => new CredentialDto(c.CredentialId, c.KeyFingerprint, c.CreatedAt, c.ExpiresAt, c.RevokedAt, c.RevokedReason, c.LastUsedAt))
            .ToListAsync(ct);
        var activeJob = await db.Jobs.AsNoTracking()
            .Where(j => j.EndpointId == id && (j.Status == JobStatus.Queued || j.Status == JobStatus.Delivered || j.Status == JobStatus.Acknowledged ||
                                               j.Status == JobStatus.Running || j.Status == JobStatus.WaitingForReboot))
            .OrderByDescending(j => j.Status == JobStatus.Running).ThenByDescending(j => j.CreatedAt)
            .Select(Mapping.JobSummary).FirstOrDefaultAsync(ct);
        return new EndpointDetailDto(Mapping.ToSummary(row, latest, endpointTags.GetValueOrDefault(id)), e.DnsDomain, e.DomainJoined, e.OsEdition, e.OsProductType, e.OsInstallDate,
            e.SerialNumber, e.Manufacturer, e.Model, e.ProcessorName, e.TotalMemoryBytes, e.SystemDriveTotalBytes, e.SystemDriveFreeBytes,
            e.IsVirtualMachine, e.TimeZoneId, e.LastBootAt, e.AgentInstalledAt, e.EnrolledAt, e.LastInventoryAt, e.LastScanAttemptAt, e.LastScanError,
            e.RebootReasons, e.RebootPendingSince, e.UpdateSourceType, e.UpdateSourceServer, e.MicrosoftUpdateRegistered, e.WufbPoliciesConfigured,
            e.DeferQualityUpdatesDays, e.DeferFeatureUpdatesDays, e.TargetReleaseVersion, e.AutomaticUpdatesMode, e.ManagedByMdm,
            e.WindowsUpdateServiceStartMode, e.WindowsUpdateServiceState, e.OsEndOfServicing, e.EsuLicenseDetected, e.EsuOverride, e.InstalledCount,
            e.PendingRebootUpdateCount, e.ComplianceEvaluatedAt, e.Notes, credentials, activeJob, e.AgentCapabilities, e.SignedInUsers,
            e.TrayConnectedSessions,
            e.WindowsUpdatePolicyStatus is null ? null : JsonSerializer.Deserialize<WindowsUpdatePolicyReport>(e.WindowsUpdatePolicyStatus, ContractJson.Options),
            e.WindowsUpdatePolicyReportedAt,
            await db.Policies.AnyAsync(p => p.Scope == PolicyScope.Endpoint && p.EndpointId == id, ct),
            await AgentUpdateInfoAsync(e, packages, policies, ct),
            e.Platform == AgentPlatforms.Linux ? new LinuxDetailsDto(e.OsId, e.OsVersion, e.KernelVersion, e.PackageManager, e.KeyProtection) : null,
            e.Platform == AgentPlatforms.Windows ? await ApplicationStatusAsync(e, policies, db, ct) : null,
            await RestartDetailsAsync(e, db, ct),
            e.Platform == AgentPlatforms.MacOS
                ? new MacOSDetailsDto(e.OsId, e.OsVersion, e.OsBuild, e.KernelVersion, e.PackageManager, e.KeyProtection)
                : null);
    }

    /// <summary>Agents that report what Windows has queued for a restart (<see cref="RebootDetails"/>).</summary>
    private static readonly Version RestartDetailsVersion = new(1, 5, 3);

    private static async Task<RestartDetailsDto?> RestartDetailsAsync(Core.Entities.Endpoint e, EasyPatchDbContext db, CancellationToken ct)
    {
        if (!e.RebootPending && e.PendingRebootUpdateCount == 0)
        {
            return null;
        }

        var updates = await db.EndpointUpdates.AsNoTracking()
            .Where(u => u.EndpointId == e.Id && u.State == EndpointUpdateState.PendingReboot)
            .OrderBy(u => u.Update!.Title)
            .Select(u => new RestartUpdateDto(u.UpdateGuid, u.Update!.Title, u.Update.KbNumbers, "Installed", u.InstalledAt ?? u.StateChangedAt))
            .ToListAsync(ct);
        var details = ScanIngestionService.ReadRebootDetails(e.RebootDetails);
        var supported = e.Platform == AgentPlatforms.Windows && Mapping.ParseVersion(e.AgentVersion) is { } version && version >= RestartDetailsVersion;
        if (details is null)
        {
            return new RestartDetailsDto(updates, [], [], 0, supported);
        }

        // Updates Windows Update lists as waiting for the restart, named from the catalog where it knows them.
        var listed = updates.Select(u => u.UpdateGuid).OfType<Guid>().ToHashSet();
        var ids = details.WindowsUpdateIds.Where(id => !listed.Contains(id)).ToList();
        if (ids.Count > 0)
        {
            var known = (await db.Updates.AsNoTracking().Where(u => ids.Contains(u.UpdateGuid))
                    .Select(u => new { u.UpdateGuid, u.RevisionNumber, u.Title, u.KbNumbers }).ToListAsync(ct))
                .GroupBy(u => u.UpdateGuid).ToDictionary(g => g.Key, g => g.MaxBy(u => u.RevisionNumber)!);
            updates.AddRange(ids.Select(id => known.TryGetValue(id, out var u)
                ? new RestartUpdateDto(id, u.Title, u.KbNumbers, "WindowsUpdate", null)
                : new RestartUpdateDto(id, $"Windows Update {id}", [], "WindowsUpdate", null)));
        }

        // KBs named by pending servicing packages, named from this endpoint's updates where possible.
        var covered = updates.SelectMany(u => u.KbNumbers).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var kbs = details.ServicingKbNumbers().Where(kb => !covered.Contains(kb)).ToList();
        if (kbs.Count > 0)
        {
            var mine = await db.EndpointUpdates.AsNoTracking().Where(u => u.EndpointId == e.Id)
                .Select(u => new { u.UpdateGuid, u.Update!.Title, u.Update.KbNumbers }).ToListAsync(ct);
            foreach (var kb in kbs)
            {
                var match = mine.FirstOrDefault(u => u.KbNumbers.Contains(kb, StringComparer.OrdinalIgnoreCase));
                updates.Add(match is null
                    ? new RestartUpdateDto(null, kb, [kb], "Servicing", null)
                    : new RestartUpdateDto(match.UpdateGuid, match.Title, match.KbNumbers, "Servicing", null));
            }
        }

        var otherPackages = details.ServicingPackages.Where(p => !RebootDetails.NamesKb(p)).ToList();
        return new RestartDetailsDto(updates.DistinctBy(u => (u.UpdateGuid, u.Title)).ToList(), otherPackages, details.FileOperations,
            details.FileOperationCount, supported);
    }

    private static async Task<ApplicationUpdatesStatusDto> ApplicationStatusAsync(Core.Entities.Endpoint e, PolicyService policies, EasyPatchDbContext db,
        CancellationToken ct)
    {
        var apps = (await policies.ResolveAsync(e, ct)).ApplicationUpdates;
        // When the agent could not install winget, the server's own copy may be what is missing.
        var serverCopyError = e.WingetSetupError is null
            ? null
            : await db.MirrorStates.AsNoTracking().Where(m => m.Name == Mirrors.Winget).Select(m => m.LastError).FirstOrDefaultAsync(ct);
        return new ApplicationUpdatesStatusDto(apps.IsActive, e.AgentCapabilities.Contains(AgentCapabilities.ApplicationUpdates), apps.ApprovedApps.Count,
            e.WingetVersion, e.ApplicationScanAt, e.ApplicationScanError, e.WingetSetupError, serverCopyError);
    }

    private static async Task<AgentUpdateInfoDto> AgentUpdateInfoAsync(EasyPatch.Core.Entities.Endpoint e, AgentPackageService packages, PolicyService policies, CancellationToken ct)
    {
        var target = AgentUpdatePlanner.Resolve(e, packages);
        var automatic = (await policies.ResolveAsync(e, ct)).AgentAutoUpdateEnabled;
        return new AgentUpdateInfoDto(e.AgentCapabilities.Contains(AgentCapabilities.SelfUpdate), e.AgentArchitecture, e.AgentReleaseKeyIds, automatic,
            target.Package?.Version, target.ErrorCode, target.Message, e.AgentPackageFormat);
    }

    internal static async Task EnsureEndpointAccessAsync(EasyPatchDbContext db, ITenantContext tenant, Guid id, CancellationToken ct)
    {
        var orgId = await db.Endpoints.AsNoTracking().Where(e => e.Id == id).Select(e => (Guid?)e.OrganizationId).FirstOrDefaultAsync(ct)
                    ?? throw AppException.NotFound("Endpoint");
        tenant.EnsureAccess(orgId);
    }

    private static async Task<EndpointEntity> LoadForUpdateAsync(EasyPatchDbContext db, ITenantContext tenant, Guid id, CancellationToken ct)
    {
        var endpoint = await db.Endpoints.FirstOrDefaultAsync(e => e.Id == id, ct) ?? throw AppException.NotFound("Endpoint");
        tenant.EnsureAccess(endpoint.OrganizationId);
        return endpoint;
    }

    /// <summary>Per-update state of the endpoint's in-flight install job and update removals, for the live overlay in the update tables.</summary>
    private static async Task<Dictionary<Guid, JobOverlayDto>> LiveOverlayAsync(EasyPatchDbContext db, Guid endpointId, CancellationToken ct)
    {
        var jobs = await db.Jobs.AsNoTracking()
            .Where(j => j.EndpointId == endpointId && (j.Type == JobType.InstallUpdates || j.Type == JobType.UninstallUpdate) &&
                        (j.Status == JobStatus.Queued || j.Status == JobStatus.Delivered || j.Status == JobStatus.Acknowledged || j.Status == JobStatus.Running))
            .OrderByDescending(j => j.CreatedAt)
            .Take(50)
            .Select(j => new { j.Id, j.Type, j.Status, Items = j.Updates.Select(u => new { u.UpdateGuid, u.Status, u.DownloadPercent, u.InstallPercent }).ToList() })
            .ToListAsync(ct);
        var overlay = new Dictionary<Guid, JobOverlayDto>();
        var installSeen = false;
        foreach (var job in jobs)
        {
            if (job.Type == JobType.InstallUpdates)
            {
                if (installSeen)
                {
                    continue; // only the newest install job
                }

                installSeen = true;
            }

            foreach (var item in job.Items)
            {
                overlay.TryAdd(item.UpdateGuid, new JobOverlayDto(job.Id, job.Status, item.Status, item.DownloadPercent, item.InstallPercent, job.Type));
            }
        }

        return overlay;
    }

    private static EndpointUpdateDto ToUpdateDto(EndpointUpdate row, Update update, JobOverlayDto? overlay) => new(
        row.UpdateGuid, update.RevisionNumber, update.Title, update.Description, update.PrimaryKb, update.KbNumbers, update.Category, update.MsClassification,
        update.MsrcSeverity, update.ReleaseDate, update.MaxDownloadSizeBytes, update.RebootBehavior is > 0, update.SupportUrl, row.State, row.IsRequired,
        row.IsExcluded, row.FirstDetectedAt, row.StateChangedAt, row.InstalledAt, row.FailedAttempts, row.ErrorCode, row.ErrorMessage, overlay,
        Mapping.Package(update, row.InstalledVersion), row.DeferredUntil, row.CveIds, row.KnownExploited, row.KevDueDate);

    internal static List<Guid> ParseGuids(string? csv) =>
        string.IsNullOrWhiteSpace(csv)
            ? []
            : csv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(s => Guid.TryParse(s, out var g) ? g : throw AppException.BadRequest($"'{s}' is not a valid update GUID.", "validation_failed"))
                .Distinct().Take(500).ToList();

    private static async Task<BulkResultDto> BulkAsync(BulkEndpointsRequest request, EasyPatchDbContext db, ITenantContext tenant, JobService jobs,
        Func<Guid, CreateJobRequest> factory, CancellationToken ct)
    {
        var ids = (request.EndpointIds ?? []).Distinct().ToList();
        if (ids.Count is 0 or > 1000)
        {
            throw AppException.BadRequest("Select between 1 and 1000 endpoints.", "validation_failed");
        }

        var endpoints = await db.Endpoints.AsNoTracking().Where(e => ids.Contains(e.Id)).Select(e => new { e.Id, e.Hostname, e.OrganizationId })
            .ToDictionaryAsync(e => e.Id, ct);
        var results = new List<BulkItemResult>();
        foreach (var id in ids)
        {
            if (!endpoints.TryGetValue(id, out var e) || !tenant.CanAccess(e.OrganizationId))
            {
                results.Add(new BulkItemResult(id, null, false, null, "not_found", "Endpoint not found."));
                continue;
            }

            try
            {
                var job = await jobs.CreateAsync(factory(id), ct);
                results.Add(new BulkItemResult(id, e.Hostname, true, job.Id, null, null));
            }
            catch (AppException ex)
            {
                db.ChangeTracker.Clear();
                var existing = ex.Extensions.TryGetValue("existingJobId", out var value) ? value as Guid? : null;
                results.Add(new BulkItemResult(id, e.Hostname, false, existing, ex.Code, ex.Message));
            }
        }

        return new BulkResultDto(results.Count(r => r.Success), results.Count(r => !r.Success), results);
    }
}
