using System.Text.Json;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Security;
using EasyPatch.Infrastructure.Vulnerabilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace EasyPatch.Infrastructure.Services;

/// <summary>Ingests agent reports: scan snapshots, update history and inventory.</summary>
public sealed class ScanIngestionService(
    EasyPatchDbContext db,
    PolicyService policies,
    VulnerabilityMatcher vulnerabilities,
    TimeProvider clock,
    ILogger<ScanIngestionService> logger)
{
    public const int MaxUpdatesPerScan = 5000;
    public const int MaxHistoryEntries = 2000;

    public async Task IngestScanAsync(Guid endpointId, ScanResultReport report, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (report.Missing.Count + report.Installed.Count > MaxUpdatesPerScan)
        {
            throw AppException.BadRequest($"A scan may report at most {MaxUpdatesPerScan} updates.", AgentErrorCodes.ValidationFailed);
        }

        if (await db.UpdateScans.AsNoTracking().AnyAsync(s => s.EndpointId == endpointId && s.AgentScanId == report.ScanId, ct))
        {
            return; // idempotent retry
        }

        // Application updates must carry a valid winget ID and version and the GUID derived from them; others are dropped.
        static bool Valid(ReportedUpdate u) => u.Application is not { } app ||
                                               (ApplicationIds.IsValid(app.Id) && ApplicationIds.IsValidVersion(app.Version) &&
                                                u.UpdateGuid == ApplicationIds.UpdateGuidFor(app.Id, app.Version));
        if (report.Missing.Any(u => !Valid(u)) || report.Installed.Any(u => !Valid(u)))
        {
            logger.LogWarning("Scan {ScanId} of endpoint {EndpointId} contained invalid application updates; they were ignored", report.ScanId, endpointId);
            report = report with { Missing = report.Missing.Where(Valid).ToList(), Installed = report.Installed.Where(Valid).ToList() };
        }

        var now = clock.GetUtcNow();
        var catalog = report.Succeeded
            ? await UpsertCatalogAsync(report.Missing.Concat(report.Installed).ToList(), now, ct)
            : new Dictionary<(Guid, int), Update>();

        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var endpoint = await LockEndpointAsync(endpointId, ct);
        if (await db.UpdateScans.AnyAsync(s => s.EndpointId == endpointId && s.AgentScanId == report.ScanId, ct))
        {
            return;
        }

        var completedAt = Clamp(report.CompletedAt, now);
        var scan = new UpdateScan
        {
            Id = Guid.CreateVersion7(now),
            EndpointId = endpointId,
            AgentScanId = report.ScanId,
            JobId = report.JobId,
            Trigger = report.Trigger,
            Status = report.Succeeded ? ScanStatus.Succeeded : ScanStatus.Failed,
            StartedAt = Clamp(report.StartedAt, now),
            CompletedAt = completedAt,
            ReceivedAt = now,
            ErrorCode = Truncate(report.ErrorCode, 32),
            ErrorMessage = Truncate(report.ErrorMessage, 2000),
            UpdateSource = Truncate(DescribeSource(report.Source), 500),
            TotalMissing = report.Missing.Count(m => !m.RebootRequired),
            TotalInstalled = report.Installed.Count,
        };
        db.UpdateScans.Add(scan);
        endpoint.LastScanAttemptAt = completedAt;
        ApplySource(endpoint, report.Source);
        if (report.Succeeded)
        {
            ApplyApplicationScan(endpoint, report.Applications, completedAt, now, report.JobId);
        }

        if (!report.Succeeded)
        {
            var message = report.ErrorMessage ?? WindowsUpdateErrors.DescribeCode(report.ErrorCode);
            endpoint.LastScanError = Truncate(message, 2000);
            var what = endpoint.Platform switch
            {
                AgentPlatforms.Linux => "Package update scan",
                AgentPlatforms.MacOS => "Software update scan",
                _ => "Windows Update scan",
            };
            EndpointEvents.Add(db, endpoint, "ScanFailed", $"{what} failed: {message}", now, EventSeverity.Warning, report.JobId,
                new { report.ErrorCode });
            await db.SaveChangesAsync(ct);
            await tx.CommitAsync(ct);
            return;
        }

        endpoint.LastScanAt = completedAt;
        endpoint.LastScanError = null;

        var rows = await db.EndpointUpdates.Include(u => u.Update)
            .Where(u => u.EndpointId == endpointId)
            .ToDictionaryAsync(u => u.UpdateGuid, ct);
        var excludedGuids = (await db.UpdateExclusions.AsNoTracking()
            .Where(x => x.EndpointId == endpointId).Select(x => x.UpdateGuid).ToListAsync(ct)).ToHashSet();
        var policy = await policies.ResolveAsync(endpoint, ct);
        var filter = policy.ToFilter(excludedGuids);
        var byId = catalog.Values.ToDictionary(u => u.Id);
        var byGuid = catalog.Values.GroupBy(u => u.UpdateGuid).ToDictionary(g => g.Key, g => g.MaxBy(u => u.RevisionNumber)!);
        var firstSeen = catalog.Values.GroupBy(u => u.UpdateGuid).ToDictionary(g => g.Key, g => g.Min(u => u.CreatedAt));

        ReconcileItem ToItem(ReportedUpdate r)
        {
            var row = catalog[(r.UpdateGuid, r.RevisionNumber)];
            return new ReconcileItem(r.UpdateGuid, row.Id, r.RebootRequired, r.SupersededUpdateGuids,
                firstSeen.GetValueOrDefault(r.UpdateGuid), UpdateRequirement.LineKey(r));
        }

        var result = UpdateReconciler.Reconcile(
            endpointId,
            rows,
            report.Missing.Select(ToItem).ToList(),
            report.Installed.Select(ToItem).ToList(),
            guid => byGuid.TryGetValue(guid, out var u) && InstallFilter.IsExcluded(guid, u.KbNumbers, filter),
            (guid, updateId) => byId.TryGetValue(updateId, out var u) &&
                                InstallFilter.IsRequired(u.Category, u.IsOptional, guid, u.KbNumbers, filter, UpdateRequirement.ApplicationId(u)),
            scan.Id,
            now,
            // A failed application check says nothing about the applications: keep their states until one succeeds.
            report.Applications is { Succeeded: false } ? r => r.Update?.Category == UpdateCategory.Application : null);
        db.EndpointUpdates.AddRange(result.Added);

        // Linux: remember which version each endpoint had installed (the catalog row is shared by every endpoint), and
        // the CVEs the agent read from the dnf advisories (Debian CVEs come from the Debian Security Tracker instead).
        var cveChanges = new HashSet<Guid>();
        foreach (var reported in report.Missing.Concat(report.Installed))
        {
            if (reported.Application is { } application && rows.TryGetValue(reported.UpdateGuid, out var applicationRow))
            {
                applicationRow.InstalledVersion = Truncate(application.InstalledVersion, 255);
            }

            if (reported.Package is { } package && rows.TryGetValue(reported.UpdateGuid, out var packageRow))
            {
                packageRow.InstalledVersion = Truncate(package.InstalledVersion, 255);
                var cves = VulnerabilityRules.Normalize(package.Cves);
                if (endpoint.OsId != "debian" && !cves.SequenceEqual(packageRow.CveIds))
                {
                    packageRow.CveIds = cves;
                    cveChanges.Add(packageRow.UpdateId);
                }
            }
        }

        foreach (var row in result.Added)
        {
            row.Update ??= byId.GetValueOrDefault(row.UpdateId);
        }

        // CVE exposure and known-exploited flags first: a known-exploited update can skip the rollout delay.
        cveChanges.UnionWith(await vulnerabilities.ApplyAsync([endpoint], rows.Values.ToLookup(r => r.EndpointId), ct));

        // Requirement flags (policy, exclusions and rollout delay) come from the one shared evaluation.

        ComplianceService.ApplyRequirementFlags(rows.Values, excludedGuids, policy, now);
        var previousMissing = endpoint.MissingRequiredCount;
        ComplianceService.ApplyCounts(endpoint, rows.Values, policy, now);
        EndpointEvents.Add(db, endpoint, "ScanCompleted",
            $"Scan completed: {endpoint.MissingRequiredCount} required update(s) missing, {report.Installed.Count} installed.",
            now, EventSeverity.Info, report.JobId,
            new { scan.TotalMissing, scan.TotalInstalled, required = endpoint.MissingRequiredCount, previousRequired = previousMissing, report.Trigger });

        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        await vulnerabilities.RefreshUpdateSummariesAsync(cveChanges, ct);
        logger.LogInformation("Ingested scan {ScanId} for endpoint {EndpointId}: {Missing} missing / {Installed} installed",
            report.ScanId, endpointId, scan.TotalMissing, scan.TotalInstalled);
    }

    public async Task<int> IngestHistoryAsync(Guid endpointId, HistoryReport report, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (report.Entries.Count > MaxHistoryEntries)
        {
            throw AppException.BadRequest($"At most {MaxHistoryEntries} history entries per request.", AgentErrorCodes.ValidationFailed);
        }

        var now = clock.GetUtcNow();
        var entries = report.Entries
            .Select(e => new UpdateHistoryEntry
            {
                EndpointId = endpointId,
                UpdateGuid = e.UpdateGuid,
                RevisionNumber = e.RevisionNumber,
                Title = Truncate(e.Title, 1000) ?? "(untitled)",
                KbNumber = KbNumber.Normalize(e.KbNumber),
                Operation = Truncate(e.Operation, 32) ?? "Other",
                ResultCode = e.ResultCode,
                HResult = Truncate(e.HResult, 16),
                Date = Clamp(e.Date, now),
                ClientApplicationId = Truncate(e.ClientApplicationId, 200),
                Fingerprint = SecureTokens.Fingerprint(e.UpdateGuid?.ToString(), e.RevisionNumber?.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    e.Date.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture), e.Operation,
                    e.ResultCode.ToString(System.Globalization.CultureInfo.InvariantCulture), e.Title),
            })
            .GroupBy(e => e.Fingerprint).Select(g => g.First())
            .ToList();
        if (entries.Count == 0)
        {
            return 0;
        }

        var fingerprints = entries.Select(e => e.Fingerprint).ToList();
        var existing = (await db.UpdateHistoryEntries.AsNoTracking()
            .Where(h => h.EndpointId == endpointId && fingerprints.Contains(h.Fingerprint))
            .Select(h => h.Fingerprint).ToListAsync(ct)).ToHashSet();
        var fresh = entries.Where(e => !existing.Contains(e.Fingerprint)).ToList();
        db.UpdateHistoryEntries.AddRange(fresh);

        // Backfill installation dates for updates confirmed installed by scans.
        var successes = fresh.Where(e => e.UpdateGuid is not null && e.Operation == "Installation" && e.ResultCode is 2 or 3)
            .GroupBy(e => e.UpdateGuid!.Value).ToDictionary(g => g.Key, g => g.Max(e => e.Date));
        if (successes.Count > 0)
        {
            var guids = successes.Keys.ToList();
            var rows = await db.EndpointUpdates.Where(u => u.EndpointId == endpointId && guids.Contains(u.UpdateGuid)).ToListAsync(ct);
            foreach (var row in rows)
            {
                row.InstalledAt = successes[row.UpdateGuid];
            }
        }

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            // A concurrent retry inserted the same entries; treat as success.
            db.ChangeTracker.Clear();
        }

        return fresh.Count;
    }

    public async Task IngestInventoryAsync(Guid endpointId, InventoryReport report, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        var now = clock.GetUtcNow();
        var endpoint = await db.Endpoints.FirstOrDefaultAsync(e => e.Id == endpointId, ct)
                       ?? throw AppException.NotFound("Endpoint");
        var previousOs = endpoint.OsBuild;

        endpoint.Hostname = Truncate(report.Hostname, 255) ?? endpoint.Hostname;
        endpoint.DnsDomain = Truncate(report.DnsDomain, 255);
        endpoint.DomainJoined = report.DomainJoined;
        endpoint.OperatingSystem = Truncate(OsNaming.Describe(report.OsCaption, report.OsBuildNumber, report.OsProductType), 255);
        endpoint.OsEdition = Truncate(report.OsEdition, 255);
        endpoint.OsVersion = Truncate(report.OsDisplayVersion, 255);
        endpoint.OsBuildNumber = report.OsBuildNumber;
        endpoint.OsBuild = report.OsBuildNumber is { } build
            ? (report.OsUbr is { } ubr ? $"{build}.{ubr}" : build.ToString(System.Globalization.CultureInfo.InvariantCulture))
            : null;
        endpoint.OsProductType = Truncate(report.OsProductType, 255);
        endpoint.OsInstallDate = report.OsInstallDate;
        endpoint.Architecture = Truncate(report.Architecture, 255);
        endpoint.Manufacturer = Truncate(report.Manufacturer, 255);
        endpoint.Model = Truncate(report.Model, 255);
        endpoint.SerialNumber = Truncate(report.SerialNumber, 255);
        endpoint.SmbiosUuid = EnrollmentService.NormalizeUuid(report.SmbiosUuid);
        endpoint.ProcessorName = Truncate(report.ProcessorName, 255);
        endpoint.TotalMemoryBytes = report.TotalMemoryBytes;
        endpoint.SystemDriveTotalBytes = report.SystemDriveTotalBytes;
        endpoint.SystemDriveFreeBytes = report.SystemDriveFreeBytes;
        endpoint.IsVirtualMachine = report.IsVirtualMachine;
        endpoint.TimeZoneId = Truncate(report.TimeZoneId, 255);
        endpoint.LastBootAt = report.LastBootAt;
        endpoint.EsuLicenseDetected = report.EsuLicenseDetected ?? false;
        endpoint.WindowsUpdateServiceStartMode = Truncate(report.WindowsUpdateServiceStartMode, 255);
        endpoint.WindowsUpdateServiceState = Truncate(report.WindowsUpdateServiceState, 255);
        endpoint.Platform = AgentPlatforms.Normalize(report.Platform) ?? endpoint.Platform;
        endpoint.OsId = Truncate(report.OsId?.ToLowerInvariant(), 64);
        endpoint.KernelVersion = Truncate(report.KernelVersion, 255);
        endpoint.PackageManager = Truncate(report.PackageManager, 16);
        endpoint.KeyProtection = Truncate(report.KeyProtection, 32);
        if (endpoint.Platform == AgentPlatforms.Linux)
        {
            // There is no build number on Linux: the version is the release ("12.8", "24.04.1 LTS") and the "build" is the
            // running kernel, so OsChanged records kernel changes (normally a restart after a kernel update).
            endpoint.OsVersion = Truncate(report.OsDisplayVersion ?? report.OsVersion, 255);
            endpoint.OsBuild = endpoint.KernelVersion;
        }
        else if (endpoint.Platform == AgentPlatforms.MacOS)
        {
            // macOS: the version is the sw_vers ProductVersion ("15.7.2") and the build its BuildVersion ("24G325"), so
            // OsChanged records macOS updates; the Darwin kernel release is the fallback when the agent sent no build.
            endpoint.OsVersion = Truncate(report.OsVersion ?? report.OsDisplayVersion, 255);
            endpoint.OsBuild = Truncate(report.OsBuildVersion, 255) ?? endpoint.KernelVersion;
        }
        endpoint.AgentVersion = Truncate(report.AgentVersion, 255);
        endpoint.AgentInstalledAt = report.AgentInstalledAt ?? endpoint.AgentInstalledAt;
        endpoint.LastInventoryAt = now;
        ApplySource(endpoint, report.UpdateSource);
        ApplyRebootState(db, endpoint, report.RebootPending, report.RebootReasons, now, report.RebootDetails);

        var lifecycle = await db.OsLifecycleEntries.AsNoTracking().ToListAsync(ct);
        ComplianceService.ApplyLifecycle(endpoint, lifecycle, now);
        var policy = await policies.ResolveAsync(endpoint, ct);
        ComplianceService.ReevaluateStatus(endpoint, policy, now);

        if (previousOs is not null && previousOs != endpoint.OsBuild)
        {
            EndpointEvents.Add(db, endpoint, "OsChanged", endpoint.Platform switch
            {
                AgentPlatforms.Linux => $"Running kernel changed from {previousOs} to {endpoint.OsBuild}.",
                AgentPlatforms.MacOS => $"macOS build changed from {previousOs} to {endpoint.OsBuild}.",
                _ => $"Operating system build changed from {previousOs} to {endpoint.OsBuild}.",
            }, now);
        }

        if (string.Equals(endpoint.WindowsUpdateServiceStartMode, "Disabled", StringComparison.OrdinalIgnoreCase))
        {
            EndpointEvents.Add(db, endpoint, "WindowsUpdateDisabled", "The Windows Update service (wuauserv) is disabled.", now, EventSeverity.Warning);
        }

        endpoint.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Updates reboot flags, emitting an event on change. Returns true if anything changed. <paramref name="details"/>
    /// replaces the stored restart details (null clears them) unless <paramref name="keepDetails"/> is set.</summary>
    public static bool ApplyRebootState(EasyPatchDbContext db, Endpoint endpoint, bool rebootPending, IReadOnlyList<string> reasons, DateTimeOffset now,
        RebootDetails? details = null, bool keepDetails = false)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(reasons);
        var cleanReasons = reasons.Where(r => !string.IsNullOrWhiteSpace(r)).Select(r => Truncate(r, 200)!).Distinct().Take(20).ToList();
        var detailsJson = keepDetails ? SerializeDetails(true, ReadRebootDetails(endpoint.RebootDetails)) : SerializeDetails(rebootPending, details);
        var changed = endpoint.RebootPending != rebootPending || !endpoint.RebootReasons.SequenceEqual(cleanReasons) ||
                      !string.Equals(NormalizeDetails(endpoint.RebootDetails), detailsJson, StringComparison.Ordinal);
        if (!changed)
        {
            return false;
        }

        if (rebootPending && !endpoint.RebootPending)
        {
            endpoint.RebootPendingSince = now;
            EndpointEvents.Add(db, endpoint, "RebootRequired", "A restart is required: " + string.Join(", ", cleanReasons), now, EventSeverity.Warning);
        }
        else if (!rebootPending && endpoint.RebootPending)
        {
            endpoint.RebootPendingSince = null;
            EndpointEvents.Add(db, endpoint, "RebootCleared", "The pending restart was completed.", now);
        }

        endpoint.RebootPending = rebootPending;
        endpoint.RebootReasons = cleanReasons;
        endpoint.RebootDetails = detailsJson;
        return true;
    }

    /// <summary>The stored restart details, read back (null when absent or unreadable).</summary>
    public static RebootDetails? ReadRebootDetails(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<RebootDetails>(json, ContractJson.Options)?.Sanitized();
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? SerializeDetails(bool rebootPending, RebootDetails? details) =>
        rebootPending && details?.Sanitized() is { IsEmpty: false } clean ? JsonSerializer.Serialize(clean, ContractJson.Options) : null;

    // jsonb does not keep the text as written: compare what is stored, read back as it is (not cleaned, so details stored
    // before a cleaning rule existed are rewritten).
    private static string? NormalizeDetails(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<RebootDetails>(json, ContractJson.Options) is { } stored
                ? JsonSerializer.Serialize(stored, ContractJson.Options)
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    internal async Task<Endpoint> LockEndpointAsync(Guid endpointId, CancellationToken ct)
    {
        var endpoint = (await db.Endpoints.FromSql($"SELECT * FROM endpoints WHERE id = {endpointId} FOR UPDATE").ToListAsync(ct)).FirstOrDefault();
        return endpoint ?? throw AppException.NotFound("Endpoint");
    }

    /// <summary>Inserts new catalog revisions and refreshes changed metadata. Runs before the main transaction and
    /// retries on concurrent inserts from other endpoints.</summary>
    private async Task<Dictionary<(Guid, int), Update>> UpsertCatalogAsync(List<ReportedUpdate> reported, DateTimeOffset now, CancellationToken ct)
    {
        var distinct = reported.GroupBy(r => (r.UpdateGuid, r.RevisionNumber)).Select(g => g.First()).ToList();
        for (var attempt = 1; ; attempt++)
        {
            var guids = distinct.Select(r => r.UpdateGuid).Distinct().ToList();
            var existing = new Dictionary<(Guid, int), Update>();
            foreach (var chunk in guids.Chunk(1000))
            {
                var rows = await db.Updates.Where(u => chunk.Contains(u.UpdateGuid)).ToListAsync(ct);
                foreach (var row in rows)
                {
                    existing[(row.UpdateGuid, row.RevisionNumber)] = row;
                }
            }

            foreach (var r in distinct)
            {
                if (existing.TryGetValue((r.UpdateGuid, r.RevisionNumber), out var row))
                {
                    Refresh(row, r, now);
                }
                else
                {
                    row = new Update { Id = Guid.CreateVersion7(now), UpdateGuid = r.UpdateGuid, RevisionNumber = r.RevisionNumber, Title = "", CreatedAt = now };
                    Refresh(row, r, now);
                    db.Updates.Add(row);
                    existing[(r.UpdateGuid, r.RevisionNumber)] = row;
                }
            }

            try
            {
                await db.SaveChangesAsync(ct);
                return existing;
            }
            catch (DbUpdateException ex) when (attempt < 3 && ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
            {
                db.ChangeTracker.Clear();
            }
        }
    }

    private static void Refresh(Update row, ReportedUpdate r, DateTimeOffset now)
    {
        var title = Truncate(r.Title, 1000) ?? "(untitled)";
        var description = Truncate(r.Description, 8000);
        var kbs = r.KbNumbers.Select(KbNumber.Normalize).OfType<string>().Distinct().ToList();
        var category = UpdateClassifier.Classify(r);
        var classification = Truncate(UpdateClassifier.GetMicrosoftClassificationName(r.Categories), 128);
        var products = UpdateClassifier.GetProducts(r.Categories).Select(p => Truncate(p, 200)!).Take(20).ToList();
        var package = r.Package;
        var application = r.Application;
        var packageName = Truncate(application?.Id ?? package?.Name, 255);
        var packageVersion = Truncate(application?.Version ?? package?.Version, 255);
        var packageArch = Truncate(package?.Architecture, 32);
        var repository = application is not null ? ApplicationIds.Source : Truncate(package?.Repository, 255);
        var source = Truncate(package?.SourcePackage?.Trim(), 255);
        var advisories = package?.Advisories.Where(a => !string.IsNullOrWhiteSpace(a)).Select(a => Truncate(a.Trim(), 64)!).Distinct().Take(50).ToList() ?? [];
        var changed = row.Title != title || (description is not null && row.Description != description) ||
                      row.PackageName != packageName || row.PackageVersion != packageVersion || row.PackageArchitecture != packageArch ||
                      row.PackageRepository != repository || row.PackageSource != source || !row.Advisories.SequenceEqual(advisories) ||
                      !row.KbNumbers.SequenceEqual(kbs) || row.Category != category || row.MsClassification != classification ||
                      !row.Products.SequenceEqual(products) || row.MaxDownloadSizeBytes != r.MaxDownloadSize ||
                      row.ReleaseDate != r.LastDeploymentChangeTime || row.IsOptional != r.BrowseOnly ||
                      row.RebootBehavior != r.RebootBehavior || row.IsDriver != r.IsDriver ||
                      !row.SupersededUpdateGuids.SequenceEqual(r.SupersededUpdateGuids);
        if (!changed && row.CreatedAt != now)
        {
            return;
        }

        row.Title = title;
        if (description is not null)
        {
            row.Description = description;
        }

        row.KbNumbers = kbs;
        row.Category = category;
        row.MsClassification = classification;
        row.Products = products;
        row.MsrcSeverity = Truncate(r.MsrcSeverity, 32);
        row.ReleaseDate = r.LastDeploymentChangeTime;
        row.MaxDownloadSizeBytes = r.MaxDownloadSize;
        row.IsDriver = r.IsDriver;
        row.IsOptional = r.BrowseOnly;
        row.IsMandatory = r.IsMandatory;
        row.RebootBehavior = r.RebootBehavior;
        row.SupportUrl = Truncate(r.SupportUrl, 1000);
        row.SupersededUpdateGuids = r.SupersededUpdateGuids.Take(500).ToList();
        row.PackageName = packageName;
        row.PackageVersion = packageVersion;
        row.PackageArchitecture = packageArch;
        row.PackageRepository = repository;
        row.PackageSource = source;
        row.Advisories = advisories;
        row.UpdatedAt = now;
    }

    /// <summary>Records the outcome of the application (winget) check. Null: application updates are off for this endpoint.</summary>
    private void ApplyApplicationScan(Endpoint endpoint, ApplicationScanReport? applications, DateTimeOffset completedAt, DateTimeOffset now, Guid? jobId)
    {
        if (applications is null)
        {
            endpoint.ApplicationScanError = null;
            return;
        }

        endpoint.ApplicationScanAt = completedAt;
        endpoint.WingetVersion = Truncate(applications.WingetVersion?.Trim(), 32);
        var error = applications.Succeeded
            ? null
            : Truncate(applications.ErrorMessage ?? applications.ErrorCode ?? "The application check failed.", 1000);
        if (error is not null && error != endpoint.ApplicationScanError)
        {
            EndpointEvents.Add(db, endpoint, "ApplicationScanFailed", $"Application update check failed: {error}", now, EventSeverity.Warning, jobId,
                new { applications.ErrorCode });
        }

        endpoint.ApplicationScanError = error;
    }

    private static void ApplySource(Endpoint endpoint, UpdateSourceInfo? source)
    {
        if (source is null)
        {
            return;
        }

        endpoint.UpdateSourceType = source.Type.ToString();
        endpoint.UpdateSourceServer = Truncate(source.WsusServer, 255);
        endpoint.MicrosoftUpdateRegistered = source.MicrosoftUpdateRegistered;
        endpoint.WufbPoliciesConfigured = source.WufbPoliciesConfigured;
        endpoint.DeferQualityUpdatesDays = source.DeferQualityUpdatesDays;
        endpoint.DeferFeatureUpdatesDays = source.DeferFeatureUpdatesDays;
        endpoint.TargetReleaseVersion = Truncate(source.TargetReleaseVersion, 255);
        endpoint.AutomaticUpdatesMode = Truncate(source.AutomaticUpdatesMode, 255);
        endpoint.ManagedByMdm = source.ManagedByMdm;
    }

    private static string? DescribeSource(UpdateSourceInfo? source) => source?.Type switch
    {
        null => null,
        UpdateSourceType.Wsus => $"WSUS ({source.WsusServer})",
        UpdateSourceType.PackageRepositories => "Package repositories",
        UpdateSourceType.AppleSoftwareUpdate => "Apple software update",
        var type => type.ToString(),
    };

    private static DateTimeOffset Clamp(DateTimeOffset value, DateTimeOffset now) =>
        value == default || value > now.AddMinutes(10) ? now : value.ToUniversalTime();

    internal static string? Truncate(string? value, int max) =>
        value is null ? null : value.Length <= max ? value : value[..max];
}
