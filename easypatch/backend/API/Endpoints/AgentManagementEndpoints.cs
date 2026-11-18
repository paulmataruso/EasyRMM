using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Api.Security;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace EasyPatch.Api.Endpoints;

public static class AgentManagementEndpoints
{
    public static void MapAgentManagementEndpoints(this IEndpointRouteBuilder app)
    {
        // ---------------------------------------------------------------- enrollment tokens
        var tokens = app.MapGroup("/api/v1/enrollment-tokens").WithTags("Agent management").RequireAuthorization(Policies.Operator);

        tokens.MapGet("/", async (Guid? organizationId, bool? includeInactive, EasyPatchDbContext db, ITenantContext tenant, TimeProvider clock,
            CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            var query = db.EnrollmentTokens.AsNoTracking().ForTenant(tenant, t => t.OrganizationId);
            if (organizationId is { } orgId)
            {
                query = query.Where(t => t.OrganizationId == orgId);
            }

            if (includeInactive != true)
            {
                query = query.Where(t => t.RevokedAt == null && t.ExpiresAt > now && t.UseCount < t.MaxUses);
            }

            var rows = await TokenQuery(db, query.OrderByDescending(t => t.CreatedAt).Take(1000)).ToListAsync(ct);
            return TypedResults.Ok(rows.OrderByDescending(r => r.CreatedAt).Select(r => r with { State = TokenState(r, now) }).ToList());
        });

        tokens.MapPost("/", async (CreateTokensRequest request, EnrollmentService enrollment, EasyPatchDbContext db, ITenantContext tenant,
            IOptions<EasyPatchOptions> options, AgentPackageService packages, TimeProvider clock, CancellationToken ct) =>
        {
            tenant.EnsureAccess(request.OrganizationId);
            new Validator().Optional("description", request.Description, 500).ThrowIfInvalid();
            var created = await enrollment.CreateTokensAsync(request.OrganizationId, request.SiteId, Validator.Clean(request.Description),
                request.ExpiresInHours, request.MaxUses, request.Count, ct);
            var ids = created.Select(c => c.Token.Id).ToList();
            var now = clock.GetUtcNow();
            var dtos = await TokenQuery(db, db.EnrollmentTokens.AsNoTracking().Where(t => ids.Contains(t.Id))).ToDictionaryAsync(t => t.Id, ct);
            var fileName = packages.GetLatest()?.FileName;
            // The experimental macOS agent is only offered once the server has a macOS package.
            var mac = MacInstallScriptBuilder.Newest(packages.List()).Count > 0;
            return TypedResults.Ok(created.Select(c => new CreatedTokenDto(dtos[c.Token.Id] with { State = TokenState(dtos[c.Token.Id], now) },
                c.PlaintextToken, InstallScriptBuilder.MsiExecCommand(options.Value.PublicUrl, c.PlaintextToken, fileName),
                LinuxInstallScriptBuilder.TokenEnrollCommand(options.Value.PublicUrl, c.PlaintextToken),
                mac ? MacInstallScriptBuilder.TokenEnrollCommand(options.Value.PublicUrl, c.PlaintextToken) : null)).ToList());
        });

        tokens.MapPost("/{id:guid}/revoke", async (Guid id, EnrollmentService enrollment, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var orgId = await db.EnrollmentTokens.Where(t => t.Id == id).Select(t => (Guid?)t.OrganizationId).FirstOrDefaultAsync(ct)
                        ?? throw AppException.NotFound("Enrollment token");
            tenant.EnsureAccess(orgId);
            await enrollment.RevokeTokenAsync(id, ct);
            return TypedResults.NoContent();
        });

        // ---------------------------------------------------------------- deployment codes (tokenless RMM install)
        var codes = app.MapGroup("/api/v1/deployment-codes").WithTags("Agent management").RequireAuthorization(Policies.Operator);

        codes.MapGet("/", async (Guid? organizationId, bool? includeInactive, EasyPatchDbContext db, ITenantContext tenant, IOptions<EasyPatchOptions> options,
            AgentPackageService packages, TimeProvider clock, CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            var query = db.DeploymentCodes.AsNoTracking().ForTenant(tenant, c => c.OrganizationId);
            if (organizationId is { } orgId)
            {
                query = query.Where(c => c.OrganizationId == orgId);
            }

            if (includeInactive != true)
            {
                query = query.Where(c => c.RevokedAt == null && (c.ExpiresAt == null || c.ExpiresAt > now));
            }

            return TypedResults.Ok(await LoadCodesAsync(db, query, options.Value.PublicUrl, packages, now, ct));
        });

        codes.MapPost("/", async (CreateDeploymentCodeRequest request, EnrollmentService enrollment, EasyPatchDbContext db, ITenantContext tenant,
            IOptions<EasyPatchOptions> options, AgentPackageService packages, TimeProvider clock, CancellationToken ct) =>
        {
            tenant.EnsureAccess(request.OrganizationId);
            new Validator().Required("name", request.Name, 200).ThrowIfInvalid();
            var code = await enrollment.CreateDeploymentCodeAsync(request.OrganizationId, request.SiteId, request.Name.Trim(), request.ExpiresInDays,
                request.AllowedSourceCidrs ?? [], request.MaxPendingRequests ?? 500, ct);
            var dto = (await LoadCodesAsync(db, db.DeploymentCodes.AsNoTracking().Where(c => c.Id == code.Id), options.Value.PublicUrl, packages,
                clock.GetUtcNow(), ct))[0];
            return TypedResults.Created($"/api/v1/deployment-codes/{code.Id}", dto);
        });

        codes.MapPost("/{id:guid}/revoke", async (Guid id, EnrollmentService enrollment, EasyPatchDbContext db, ITenantContext tenant, CancellationToken ct) =>
        {
            var orgId = await db.DeploymentCodes.Where(c => c.Id == id).Select(c => (Guid?)c.OrganizationId).FirstOrDefaultAsync(ct)
                        ?? throw AppException.NotFound("Deployment code");
            tenant.EnsureAccess(orgId);
            await enrollment.RevokeDeploymentCodeAsync(id, ct);
            return TypedResults.NoContent();
        });

        codes.MapGet("/{id:guid}/install-script", async (Guid id, string? package, bool? requireSignature, bool? skipCertificateCheck, string? platform, EasyPatchDbContext db,
            ITenantContext tenant, AgentPackageService packages, IOptions<EasyPatchOptions> options, TimeProvider clock, CancellationToken ct) =>
        {
            var code = await db.DeploymentCodes.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct) ?? throw AppException.NotFound("Deployment code");
            tenant.EnsureAccess(code.OrganizationId);
            if (string.Equals(platform, AgentPlatforms.Linux, StringComparison.OrdinalIgnoreCase))
            {
                var linux = LinuxInstallScriptBuilder.Newest(packages.List());
                if (linux.Count == 0)
                {
                    throw AppException.Conflict("No Linux agent package is available. Copy the EasyPatchAgent .deb and .rpm packages into the agent packages directory.",
                        "no_agent_package");
                }

                var serverUrl = options.Value.PublicUrl.TrimEnd('/');
                var linuxScript = LinuxInstallScriptBuilder.Build(serverUrl, linux, code.Code, code.Name, clock.GetUtcNow());
                return TypedResults.Ok(new InstallScriptResponse(linuxScript, LinuxInstallScriptBuilder.OneLiner(serverUrl, code.Code),
                    $"{serverUrl}/downloads/install/{code.Code}.sh", string.Join(", ", linux.Select(p => p.FileName)), linux[0].Version,
                    string.Join(", ", linux.Select(p => p.Sha256)), false, AgentPlatforms.Linux));
            }

            if (string.Equals(platform, AgentPlatforms.MacOS, StringComparison.OrdinalIgnoreCase))
            {
                var mac = MacInstallScriptBuilder.Newest(packages.List());
                if (mac.Count == 0)
                {
                    throw AppException.Conflict("No macOS agent package is available. Copy the EasyPatchAgent .pkg packages into the agent packages directory.",
                        "no_agent_package");
                }

                var serverUrl = options.Value.PublicUrl.TrimEnd('/');
                var macScript = MacInstallScriptBuilder.Build(serverUrl, mac, code.Code, code.Name, clock.GetUtcNow());
                return TypedResults.Ok(new InstallScriptResponse(macScript, MacInstallScriptBuilder.OneLiner(serverUrl, code.Code),
                    MacInstallScriptBuilder.ScriptUrl(serverUrl, code.Code), string.Join(", ", mac.Select(p => p.FileName)), mac[0].Version,
                    string.Join(", ", mac.Select(p => p.Sha256)), false, AgentPlatforms.MacOS));
            }

            var pkg = (package is null ? packages.GetLatest() : packages.Find(package) is { Format: AgentRelease.FormatMsi } chosen ? chosen : null)
                      ?? throw AppException.Conflict("No agent package is available. Copy a signed EasyPatchAgent MSI into the agent packages directory.",
                          "no_agent_package");
            var url = options.Value.PublicUrl.TrimEnd('/');
            var signature = requireSignature ?? false;
            var skipCheck = skipCertificateCheck ?? false;
            var script = InstallScriptBuilder.Build(url, pkg, code.Code, code.Name, signature, clock.GetUtcNow(), skipCheck);
            return TypedResults.Ok(new InstallScriptResponse(script, InstallScriptBuilder.OneLiner(url, code.Code, signature, skipCheck),
                InstallScriptBuilder.ScriptUrl(url, code.Code, signature, skipCheck), pkg.FileName, pkg.Version, pkg.Sha256, signature,
                SkipCertificateCheck: skipCheck));
        });

        // ---------------------------------------------------------------- enrollment requests (pending approvals)
        var requests = app.MapGroup("/api/v1/enrollment-requests").WithTags("Agent management").RequireAuthorization(Policies.Operator);

        requests.MapGet("/", async (EnrollmentRequestStatus? status, Guid? organizationId, int? page, int? pageSize, EasyPatchDbContext db,
            ITenantContext tenant, CancellationToken ct) =>
        {
            var query = db.EnrollmentRequests.AsNoTracking().ForTenant(tenant, r => r.OrganizationId);
            query = query.Where(r => r.Status == (status ?? EnrollmentRequestStatus.Pending));
            if (organizationId is { } orgId)
            {
                query = query.Where(r => r.OrganizationId == orgId);
            }

            var paged = await query.OrderByDescending(r => r.CreatedAt).ToPagedAsync(PageRequest.From(page, pageSize), ct);
            return TypedResults.Ok(new PagedResult<EnrollmentRequestDto>(await ToRequestDtosAsync(db, paged.Items, ct), paged.Page, paged.PageSize, paged.TotalCount));
        });

        requests.MapPost("/{id:guid}/approve", async (Guid id, ApproveRequest? request, EnrollmentService enrollment, EasyPatchDbContext db,
            ITenantContext tenant, CancellationToken ct) =>
        {
            await EnsureRequestAccessAsync(db, tenant, id, ct);
            if (request?.OrganizationId is { } target)
            {
                tenant.EnsureAccess(target);
            }

            var endpoint = await enrollment.ApproveAsync(id, request?.OrganizationId, request?.SiteId, ct);
            return TypedResults.Ok(new { endpointId = endpoint.Id });
        });

        requests.MapPost("/{id:guid}/reject", async (Guid id, RejectRequest? request, EnrollmentService enrollment, EasyPatchDbContext db,
            ITenantContext tenant, CancellationToken ct) =>
        {
            await EnsureRequestAccessAsync(db, tenant, id, ct);
            await enrollment.RejectAsync(id, Validator.Clean(request?.Reason), ct);
            return TypedResults.NoContent();
        });

        requests.MapPost("/bulk-approve", async (BulkApproveRequest request, EnrollmentService enrollment, EasyPatchDbContext db, ITenantContext tenant,
            CancellationToken ct) =>
        {
            var ids = (request.Ids ?? []).Distinct().Take(500).ToList();
            var orgs = await db.EnrollmentRequests.AsNoTracking().Where(r => ids.Contains(r.Id))
                .Select(r => new { r.Id, r.OrganizationId, r.Hostname }).ToDictionaryAsync(r => r.Id, ct);
            var results = new List<BulkItemResult>();
            foreach (var id in ids)
            {
                if (!orgs.TryGetValue(id, out var r) || !tenant.CanAccess(r.OrganizationId))
                {
                    results.Add(new BulkItemResult(id, null, false, null, "not_found", "Enrollment request not found."));
                    continue;
                }

                try
                {
                    var endpoint = await enrollment.ApproveAsync(id, null, null, ct);
                    results.Add(new BulkItemResult(endpoint.Id, r.Hostname, true, null, null, null));
                }
                catch (AppException ex)
                {
                    db.ChangeTracker.Clear();
                    results.Add(new BulkItemResult(id, r.Hostname, false, null, ex.Code, ex.Message));
                }
            }

            return TypedResults.Ok(new BulkResultDto(results.Count(x => x.Success), results.Count(x => !x.Success), results));
        });

        // ---------------------------------------------------------------- packages and versions
        app.MapGet("/api/v1/agent-packages", (AgentPackageService packages) =>
        {
            var list = packages.List();
            var latest = list.GroupBy(p => (p.Architecture, p.Format))
                .Select(g => g.OrderByDescending(p => Mapping.ParseVersion(p.Version)).First().FileName).ToHashSet();
            return TypedResults.Ok(list.OrderByDescending(p => Mapping.ParseVersion(p.Version)).ThenBy(p => p.Format).ThenBy(p => p.Architecture)
                .Select(p => new AgentPackageDto(p.FileName, p.Version, p.Architecture, p.SizeBytes, p.Sha256, p.ModifiedAt,
                    "/downloads/agent/" + Uri.EscapeDataString(p.FileName), latest.Contains(p.FileName), p.Release?.KeyId, p.SignatureProblem,
                    p.Format)).ToList());
        }).WithTags("Agent management").RequireAuthorization(Policies.Viewer);

        app.MapGet("/api/v1/agent-versions", async (Guid? organizationId, EasyPatchDbContext db, ITenantContext tenant, AgentPackageService packages,
            CancellationToken ct) =>
        {
            var query = db.Endpoints.AsNoTracking().ForTenant(tenant, e => e.OrganizationId).Where(e => e.Status == EndpointStatus.Active);
            if (organizationId is { } orgId)
            {
                query = query.Where(e => e.OrganizationId == orgId);
            }

            var rows = await query.GroupBy(e => e.AgentVersion).Select(g => new { Version = g.Key, Count = g.Count() }).ToListAsync(ct);
            var latest = AgentRelease.PackageFormats.Select(f => packages.GetLatestVersion(f)).OfType<string>().ToHashSet();
            return TypedResults.Ok(rows.OrderByDescending(r => Mapping.ParseVersion(r.Version))
                .Select(r => new AgentVersionCountDto(r.Version ?? "unknown", r.Count, r.Version is not null && latest.Contains(r.Version))).ToList());
        }).WithTags("Agent management").RequireAuthorization(Policies.Viewer);
    }

    private static IQueryable<EnrollmentTokenDto> TokenQuery(EasyPatchDbContext db, IQueryable<EnrollmentToken> query) =>
        query.Join(db.Organizations, t => t.OrganizationId, o => o.Id, (t, o) => new { t, OrgName = o.Name })
            .Select(x => new EnrollmentTokenDto(x.t.Id, x.t.OrganizationId, x.OrgName, x.t.SiteId,
                db.Sites.Where(s => s.Id == x.t.SiteId).Select(s => s.Name).FirstOrDefault(),
                x.t.TokenPrefix, x.t.Description, x.t.MaxUses, x.t.UseCount, x.t.CreatedAt, x.t.ExpiresAt, x.t.LastUsedAt, x.t.RevokedAt, string.Empty));

    private static string TokenState(EnrollmentTokenDto t, DateTimeOffset now) =>
        t.RevokedAt is not null ? "Revoked" : t.ExpiresAt <= now ? "Expired" : t.UseCount >= t.MaxUses ? "Exhausted" : "Active";

    private static async Task<List<DeploymentCodeDto>> LoadCodesAsync(EasyPatchDbContext db, IQueryable<DeploymentCode> query, string publicUrl,
        AgentPackageService packages, DateTimeOffset now, CancellationToken ct)
    {
        var rows = await query.OrderByDescending(c => c.CreatedAt)
            .Select(c => new
            {
                Code = c,
                OrgName = db.Organizations.Where(o => o.Id == c.OrganizationId).Select(o => o.Name).First(),
                SiteName = db.Sites.Where(s => s.Id == c.SiteId).Select(s => s.Name).FirstOrDefault(),
                Pending = db.EnrollmentRequests.Count(r => r.DeploymentCodeId == c.Id && r.Status == EnrollmentRequestStatus.Pending),
                Approved = db.EnrollmentRequests.Count(r => r.DeploymentCodeId == c.Id && r.Status == EnrollmentRequestStatus.Approved),
            }).Take(1000).ToListAsync(ct);
        var url = publicUrl.TrimEnd('/');
        // The experimental macOS agent is only offered once the server has a macOS package.
        var mac = MacInstallScriptBuilder.Newest(packages.List()).Count > 0;
        return rows.Select(r => new DeploymentCodeDto(r.Code.Id, r.Code.Code, r.Code.Name, r.Code.OrganizationId, r.OrgName, r.Code.SiteId, r.SiteName,
            r.Code.MaxPendingRequests, r.Code.AllowedSourceCidrs, r.Code.CreatedAt, r.Code.ExpiresAt, r.Code.RevokedAt, r.Pending, r.Approved,
            r.Code.RevokedAt is not null ? "Revoked" : r.Code.ExpiresAt is { } exp && exp <= now ? "Expired" : "Active",
            InstallScriptBuilder.OneLiner(url, r.Code.Code), InstallScriptBuilder.ScriptUrl(url, r.Code.Code),
            LinuxInstallScriptBuilder.OneLiner(url, r.Code.Code), $"{url}/downloads/install/{r.Code.Code}.sh",
            mac ? MacInstallScriptBuilder.OneLiner(url, r.Code.Code) : null, mac ? MacInstallScriptBuilder.ScriptUrl(url, r.Code.Code) : null)).ToList();
    }

    private static async Task EnsureRequestAccessAsync(EasyPatchDbContext db, ITenantContext tenant, Guid id, CancellationToken ct)
    {
        var orgId = await db.EnrollmentRequests.AsNoTracking().Where(r => r.Id == id).Select(r => (Guid?)r.OrganizationId).FirstOrDefaultAsync(ct)
                    ?? throw AppException.NotFound("Enrollment request");
        tenant.EnsureAccess(orgId);
    }

    private static async Task<List<EnrollmentRequestDto>> ToRequestDtosAsync(EasyPatchDbContext db, IReadOnlyList<EnrollmentRequest> rows, CancellationToken ct)
    {
        var orgIds = rows.Select(r => r.OrganizationId).Distinct().ToList();
        var siteIds = rows.Where(r => r.SiteId != null).Select(r => r.SiteId!.Value).Distinct().ToList();
        var codeIds = rows.Select(r => r.DeploymentCodeId).Distinct().ToList();
        var orgNames = await db.Organizations.AsNoTracking().Where(o => orgIds.Contains(o.Id)).ToDictionaryAsync(o => o.Id, o => o.Name, ct);
        var siteNames = await db.Sites.AsNoTracking().Where(s => siteIds.Contains(s.Id)).ToDictionaryAsync(s => s.Id, s => s.Name, ct);
        var codeNames = await db.DeploymentCodes.AsNoTracking().Where(c => codeIds.Contains(c.Id)).ToDictionaryAsync(c => c.Id, c => c.Name, ct);
        var hostnames = rows.Select(r => r.Hostname).Distinct().ToList();
        var existing = await db.Endpoints.AsNoTracking().Where(e => orgIds.Contains(e.OrganizationId) && hostnames.Contains(e.Hostname))
            .Select(e => new { e.Id, e.OrganizationId, e.Hostname }).ToListAsync(ct);
        return rows.Select(r =>
        {
            DeviceIdentity? device = null;
            try
            {
                device = JsonSerializer.Deserialize<DeviceIdentity>(r.DeviceJson, ContractJson.Options);
            }
            catch (JsonException)
            {
                // Device details are informational only.
            }

            var duplicate = existing.FirstOrDefault(e => e.OrganizationId == r.OrganizationId &&
                                                         string.Equals(e.Hostname, r.Hostname, StringComparison.OrdinalIgnoreCase) && e.Id != r.EndpointId);
            return new EnrollmentRequestDto(r.Id, r.RequestId, r.Hostname, r.KeyFingerprint, r.SerialNumber, device?.Manufacturer, device?.Model,
                r.OsCaption, r.AgentVersion, r.SourceIp, r.Status, r.OrganizationId, orgNames.GetValueOrDefault(r.OrganizationId, "?"), r.SiteId,
                r.SiteId is { } sid ? siteNames.GetValueOrDefault(sid) : null, codeNames.GetValueOrDefault(r.DeploymentCodeId, "?"), r.CreatedAt,
                r.LastSeenAt, r.ExpiresAt, r.DecidedAt, r.RejectReason, r.EndpointId, duplicate?.Id);
        }).ToList();
    }
}

/// <summary>Anonymous downloads used by installers: agent packages and the tokenless PowerShell and shell (Linux and macOS) install scripts.</summary>
public static class DownloadEndpoints
{
    public static void MapDownloadEndpoints(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("/downloads").WithTags("Downloads").AllowAnonymous().RequireRateLimiting(RateLimits.Downloads);

        g.MapGet("/agent/{fileName}", (string fileName, AgentPackageService packages) =>
        {
            var path = packages.GetPath(fileName);
            var contentType = AgentRelease.FormatOf(path is null ? null : Path.GetFileName(path)) switch
            {
                AgentRelease.FormatDeb => "application/vnd.debian.binary-package",
                AgentRelease.FormatRpm => "application/x-rpm",
                AgentRelease.FormatPkg => "application/octet-stream",
                _ => "application/x-msi",
            };
            return path is null
                ? Results.NotFound()
                : Results.File(path, contentType, Path.GetFileName(path), enableRangeProcessing: true);
        });

        // The pinned winget release, for Windows agents that cannot reach GitHub (they verify the SHA-256 themselves too).
        // A file the server does not have yet is requested from the worker, which downloads the release from GitHub.
        g.MapGet("/winget/{fileName}", async (string fileName, WingetMirrorService mirror, EasyPatchDbContext db, TimeProvider clock,
            HttpContext http, CancellationToken ct) =>
        {
            if (mirror.Find(fileName) is not { } file)
            {
                return Results.NotFound();
            }

            if (mirror.GetPath(file) is { } path)
            {
                var contentType = file.Name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ? "application/xml" : "application/octet-stream";
                return Results.File(path, contentType, file.Name, enableRangeProcessing: true);
            }

            await WingetMirrorService.RequestAsync(db, clock.GetUtcNow(), ct);
            http.Response.Headers.RetryAfter = "900";
            return Results.Problem(statusCode: StatusCodes.Status503ServiceUnavailable, title: "winget is not available yet",
                detail: "The server is downloading winget from GitHub. Try again later.",
                extensions: new Dictionary<string, object?> { ["code"] = "winget_not_ready" });
        });

        g.MapGet("/install/{code}.sh", async (string code, EasyPatchDbContext db, AgentPackageService packages, IOptions<EasyPatchOptions> options,
            TimeProvider clock, HttpContext http, CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            if (code.Length > 64)
            {
                return Results.NotFound();
            }

            var deployment = await db.DeploymentCodes.AsNoTracking()
                .FirstOrDefaultAsync(c => c.Code == code && c.RevokedAt == null && (c.ExpiresAt == null || c.ExpiresAt > now), ct);
            if (deployment is null)
            {
                return Results.Text("echo 'easypatch: this deployment code is unknown, revoked or expired.' >&2; exit 1\n", "text/plain; charset=utf-8",
                    statusCode: StatusCodes.Status404NotFound);
            }

            var linux = LinuxInstallScriptBuilder.Newest(packages.List());
            if (linux.Count == 0)
            {
                return Results.Text("echo 'easypatch: no Linux agent package is available on the server.' >&2; exit 1\n", "text/plain; charset=utf-8",
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            http.Response.Headers.CacheControl = "no-store";
            return Results.Text(LinuxInstallScriptBuilder.Build(options.Value.PublicUrl, linux, deployment.Code, deployment.Name, now),
                "text/plain; charset=utf-8");
        });

        // The experimental macOS agent: same rules as the Linux script above.
        g.MapGet("/install/macos/{code}.sh", async (string code, EasyPatchDbContext db, AgentPackageService packages, IOptions<EasyPatchOptions> options,
            TimeProvider clock, HttpContext http, CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            if (code.Length > 64)
            {
                return Results.NotFound();
            }

            var deployment = await db.DeploymentCodes.AsNoTracking()
                .FirstOrDefaultAsync(c => c.Code == code && c.RevokedAt == null && (c.ExpiresAt == null || c.ExpiresAt > now), ct);
            if (deployment is null)
            {
                return Results.Text("echo 'easypatch: this deployment code is unknown, revoked or expired.' >&2; exit 1\n", "text/plain; charset=utf-8",
                    statusCode: StatusCodes.Status404NotFound);
            }

            var mac = MacInstallScriptBuilder.Newest(packages.List());
            if (mac.Count == 0)
            {
                return Results.Text("echo 'easypatch: no macOS agent package is available on the server.' >&2; exit 1\n", "text/plain; charset=utf-8",
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            http.Response.Headers.CacheControl = "no-store";
            return Results.Text(MacInstallScriptBuilder.Build(options.Value.PublicUrl, mac, deployment.Code, deployment.Name, now),
                "text/plain; charset=utf-8");
        });

        g.MapGet("/install/{code}.ps1", async (string code, bool? requireSignature, bool? skipCertificateCheck, EasyPatchDbContext db, AgentPackageService packages,
            IOptions<EasyPatchOptions> options, TimeProvider clock, HttpContext http, CancellationToken ct) =>
        {
            var now = clock.GetUtcNow();
            if (code.Length > 64)
            {
                return Results.NotFound();
            }

            var deployment = await db.DeploymentCodes.AsNoTracking()
                .FirstOrDefaultAsync(c => c.Code == code && c.RevokedAt == null && (c.ExpiresAt == null || c.ExpiresAt > now), ct);
            if (deployment is null)
            {
                return Results.Text("throw 'EasyPatch: this deployment code is unknown, revoked or expired.'\n", "text/plain; charset=utf-8",
                    statusCode: StatusCodes.Status404NotFound);
            }

            var package = packages.GetLatest();
            if (package is null)
            {
                return Results.Text("throw 'EasyPatch: no agent package is available on the server.'\n", "text/plain; charset=utf-8",
                    statusCode: StatusCodes.Status503ServiceUnavailable);
            }

            http.Response.Headers.CacheControl = "no-store";
            var script = InstallScriptBuilder.Build(options.Value.PublicUrl, package, deployment.Code, deployment.Name, requireSignature ?? false, now,
                skipCertificateCheck ?? false);
            return Results.Text(script, "text/plain; charset=utf-8");
        });
    }
}
