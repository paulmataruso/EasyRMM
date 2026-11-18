using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EasyPatch.Infrastructure.Maintenance;

/// <summary>A periodic background task executed by the worker. Each run is guarded by a PostgreSQL advisory lock so
/// multiple worker replicas never run the same task concurrently.</summary>
public interface IMaintenanceTask
{
    string Name { get; }
    long LockKey { get; }
    TimeSpan Interval { get; }
    Task RunOnceAsync(CancellationToken ct);
}

/// <summary>Job lease recovery, expiry and timeouts.</summary>
public sealed class JobMaintenanceTask(EasyPatchDbContext db, SettingsService settingsService, TimeProvider clock, ILogger<JobMaintenanceTask> logger)
    : IMaintenanceTask
{
    public string Name => "job-maintenance";
    public long LockKey => 0x4550_0001;
    public TimeSpan Interval => TimeSpan.FromSeconds(30);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var settings = await settingsService.GetAsync(ct);

        // 1. Expire queued jobs past their deadline.
        var expiredQueued = await db.Jobs.Include(j => j.Updates).Include(j => j.Endpoint)
            .Where(j => j.Status == JobStatus.Queued && j.ExpiresAt <= now).OrderBy(j => j.Id).Take(500).ToListAsync(ct);
        foreach (var job in expiredQueued)
        {
            JobService.Finish(job, JobStatus.Expired, now, "The endpoint did not pick up the job before it expired.");
            EndpointEvents.Add(db, job.Endpoint!, "JobExpired", $"{JobService.Describe(job.Type)} expired before the endpoint picked it up.", now,
                EventSeverity.Warning, job.Id);
        }

        // 2. Delivered but never acknowledged: return to the queue (or fail after too many attempts).
        var staleLeases = await db.Jobs.Include(j => j.Updates)
            .Where(j => j.Status == JobStatus.Delivered && j.LeaseExpiresAt != null && j.LeaseExpiresAt <= now).OrderBy(j => j.Id).Take(500).ToListAsync(ct);
        foreach (var job in staleLeases)
        {
            if (job.DeliveryCount >= settings.MaxDeliveryAttempts)
            {
                JobService.Finish(job, JobStatus.Failed, now, $"The agent did not acknowledge the job after {job.DeliveryCount} deliveries.");
            }
            else if (job.ExpiresAt <= now)
            {
                JobService.Finish(job, JobStatus.Expired, now, "The job expired before the agent acknowledged it.");
            }
            else
            {
                job.Status = JobStatus.Queued;
                job.LeaseExpiresAt = null;
                job.UpdatedAt = now;
            }
        }

        // 3. Running/acknowledged jobs with no progress for too long: mark failed (timed out). A late genuine result still wins.
        var runningCutoff = now.AddHours(-settings.RunningJobTimeoutHours);
        var stuck = await db.Jobs.Include(j => j.Updates).Include(j => j.Endpoint)
            .Where(j => (j.Status == JobStatus.Running || j.Status == JobStatus.Acknowledged) &&
                        (j.LastProgressAt ?? j.AcknowledgedAt ?? j.DeliveredAt) <= runningCutoff)
            .OrderBy(j => j.Id).Take(500).ToListAsync(ct);
        foreach (var job in stuck)
        {
            JobService.Finish(job, JobStatus.Failed, now,
                $"The agent stopped reporting progress for more than {settings.RunningJobTimeoutHours} hours. If the agent reports a result later, it will replace this outcome.",
                timedOut: true);
            EndpointEvents.Add(db, job.Endpoint!, "JobTimedOut", $"{JobService.Describe(job.Type)} timed out waiting for the agent.", now, EventSeverity.Error, job.Id);
        }

        // 4. Waiting for a reboot that never happens.
        var rebootCutoff = now.AddDays(-settings.WaitingForRebootExpiryDays);
        var parked = await db.Jobs.Include(j => j.Updates)
            .Where(j => j.Status == JobStatus.WaitingForReboot && (j.LastProgressAt ?? j.CreatedAt) <= rebootCutoff).OrderBy(j => j.Id).Take(500).ToListAsync(ct);
        foreach (var job in parked)
        {
            JobService.Finish(job, JobStatus.Expired, now, $"The endpoint was not restarted within {settings.WaitingForRebootExpiryDays} days.");
        }

        if (db.ChangeTracker.HasChanges())
        {
            await db.SaveChangesAsync(ct);
            logger.LogInformation("Job maintenance: {Expired} expired, {Leases} lease(s) recovered, {Stuck} timed out, {Parked} reboot waits expired",
                expiredQueued.Count, staleLeases.Count, stuck.Count, parked.Count);
        }
    }
}

/// <summary>Online/offline transitions (with activity events) and time-based compliance re-evaluation (stale scans).</summary>
public sealed class PresenceMonitorTask(EasyPatchDbContext db, SettingsService settingsService, PolicyService policies, TimeProvider clock,
    ILogger<PresenceMonitorTask> logger) : IMaintenanceTask
{
    public string Name => "presence-monitor";
    public long LockKey => 0x4550_0002;
    public TimeSpan Interval => TimeSpan.FromSeconds(60);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var settings = await settingsService.GetAsync(ct);
        var cutoff = now.AddMinutes(-settings.OfflineThresholdMinutes);

        var wentOffline = await db.Endpoints.Where(e => e.IsOnline && (e.LastCheckInAt == null || e.LastCheckInAt < cutoff)).ToListAsync(ct);
        var cameOnline = await db.Endpoints.Where(e => !e.IsOnline && e.Status == EndpointStatus.Active && e.LastCheckInAt >= cutoff).ToListAsync(ct);
        foreach (var e in wentOffline)
        {
            e.IsOnline = false;
            EndpointEvents.Add(db, e, "Offline", $"No check-in since {e.LastCheckInAt:u}.", now, EventSeverity.Warning);
        }

        foreach (var e in cameOnline)
        {
            e.IsOnline = true;
            EndpointEvents.Add(db, e, "Online", "The agent is checking in.", now);
        }

        // Staleness changes with time, not with events: re-evaluate status for active endpoints whose status may have drifted.
        var resolver = await policies.CreateResolverAsync(ct);
        var candidates = await db.Endpoints
            .Where(e => e.Status == EndpointStatus.Active && e.LastScanAt != null && e.ComplianceStatus != ComplianceStatus.ScanStale)
            .ToListAsync(ct);
        var staled = 0;
        foreach (var e in candidates)
        {
            var policy = resolver(e.OrganizationId, e.SiteId, e.Id);
            if (now - e.LastScanAt!.Value > TimeSpan.FromHours(policy.ScanStaleAfterHours))
            {
                ComplianceService.ReevaluateStatus(e, policy, now);
                staled++;
            }
        }

        if (db.ChangeTracker.HasChanges())
        {
            await db.SaveChangesAsync(ct);
            logger.LogInformation("Presence: {Offline} offline, {Online} online, {Stale} became scan-stale", wentOffline.Count, cameOnline.Count, staled);
        }
    }
}

/// <summary>Creates automatic installation jobs for endpoints whose policy enables auto-install and whose maintenance
/// window is currently open.</summary>
public sealed class ScheduledInstallTask(
    EasyPatchDbContext db,
    PolicyService policies,
    JobService jobs,
    SettingsService settingsService,
    UpdateHoldService holds,
    TimeProvider clock,
    ILogger<ScheduledInstallTask> logger) : IMaintenanceTask
{
    public string Name => "scheduled-installs";
    public long LockKey => 0x4550_0003;
    public TimeSpan Interval => TimeSpan.FromMinutes(2);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var resolver = await policies.CreateResolverAsync(ct);
        var settings = await settingsService.GetAsync(ct);
        var candidates = await db.Endpoints.AsNoTracking()
            .Where(e => e.Status == EndpointStatus.Active && e.MissingRequiredCount > 0 && e.Organization!.IsActive)
            .Select(e => new { e.Id, e.OrganizationId, e.SiteId, SiteTz = e.Site != null ? e.Site.TimeZone : null, OrgTz = e.Organization!.TimeZone })
            .ToListAsync(ct);

        var created = 0;
        var heldByOrg = new Dictionary<Guid, IReadOnlyCollection<Guid>>();
        foreach (var e in candidates)
        {
            var policy = resolver(e.OrganizationId, e.SiteId, e.Id);
            if (!policy.AutoInstallEnabled || policy.MaintenanceWindow is null)
            {
                continue;
            }

            var window = MaintenanceWindow.FindOpenWindow(policy.MaintenanceWindow, e.SiteTz ?? e.OrgTz, now);
            if (window is not { } open || open.End - now < TimeSpan.FromMinutes(15))
            {
                continue; // closed, or too little time left to start safely
            }

            var hasActiveInstall = await db.Jobs.AnyAsync(j => j.EndpointId == e.Id && j.Type == JobType.InstallUpdates &&
                                                               JobTransitions.DedupeStatuses.Contains(j.Status), ct);
            if (hasActiveInstall)
            {
                continue;
            }

            // Without a rollout delay the agent installs everything policy allows (as before). With a delay only the
            // server knows which updates are due, so the job lists them explicitly. Updates on hold are never due; an
            // endpoint that only misses held updates gets no job.
            if (!heldByOrg.TryGetValue(e.OrganizationId, out var held))
            {
                held = (await holds.ActiveForAsync(e.OrganizationId, ct)).Keys.ToHashSet();
                heldByOrg[e.OrganizationId] = held;
            }

            var mode = InstallMode.AllEligible;
            IReadOnlyList<Guid>? selected = null;
            if (policy.HasInstallDelay || held.Count > 0)
            {
                var due = await DueUpdatesAsync(db, e.Id, held, ct);
                if (due.Count == 0)
                {
                    continue;
                }

                if (policy.HasInstallDelay)
                {
                    mode = InstallMode.Selected;
                    selected = due;
                }
            }

            try
            {
                await jobs.CreateAsync(new CreateJobRequest(e.Id, JobType.InstallUpdates, mode, selected,
                    Trigger: JobTrigger.Scheduled, ExpiresAt: open.End, NotAfter: open.End,
                    DedupeSuffix: "window:" + open.Start.UtcDateTime.ToString("yyyyMMddHHmm", System.Globalization.CultureInfo.InvariantCulture)), ct);
                created++;
            }
            catch (AppException ex) when (ex.Code is "duplicate_job" or "endpoint_not_active" or "nothing_to_install" or "validation_failed")
            {
                // One endpoint's problem must not stop the others.
                db.ChangeTracker.Clear();
                if (ex.Code is "nothing_to_install" or "validation_failed")
                {
                    logger.LogInformation("No scheduled installation for endpoint {EndpointId}: {Reason}", e.Id, ex.Message);
                }
            }
        }

        if (created > 0)
        {
            logger.LogInformation("Scheduled {Count} maintenance-window installation job(s) (global limit {Limit})", created, settings.GlobalMaxConcurrentInstalls);
        }
    }

    /// <summary>Required (and therefore due) updates still outstanding on the endpoint and not on hold, security first, at most 500.</summary>
    internal static async Task<IReadOnlyList<Guid>> DueUpdatesAsync(EasyPatchDbContext db, Guid endpointId, IReadOnlyCollection<Guid> held,
        CancellationToken ct)
    {
        var rows = await db.EndpointUpdates.AsNoTracking()
            .Where(u => u.EndpointId == endpointId && u.IsRequired && !u.IsExcluded &&
                        (u.State == EndpointUpdateState.Missing || u.State == EndpointUpdateState.Failed))
            .Select(u => new { u.UpdateGuid, u.Update!.Category, u.Update.MsClassification, u.FirstDetectedAt })
            .ToListAsync(ct);
        return rows
            .Where(r => !held.Contains(r.UpdateGuid))
            .OrderByDescending(r => r.Category == UpdateCategory.Security ||
                                    string.Equals(r.MsClassification, UpdateRequirement.SecurityClassification, StringComparison.OrdinalIgnoreCase))
            .ThenBy(r => r.FirstDetectedAt)
            .Select(r => r.UpdateGuid)
            .Take(500)
            .ToList();
    }
}

/// <summary>
/// Downloads updates ahead of the maintenance window (policy <see cref="EffectivePolicy.PreDownloadHours"/>, with automatic
/// installation): when the next window opens within that many hours, Windows endpoints whose agent can download without
/// installing get a download job for the updates the window would install. The job must start before the window opens
/// (<c>NotAfter</c> and expiry are the window's start), so the installation in the window finds the downloads done.
/// </summary>
public sealed class PreDownloadTask(
    EasyPatchDbContext db,
    PolicyService policies,
    JobService jobs,
    UpdateHoldService holds,
    TimeProvider clock,
    ILogger<PreDownloadTask> logger) : IMaintenanceTask
{
    /// <summary>Closer to the window than this, the installation downloads the updates itself.</summary>
    public static readonly TimeSpan MinimumLead = TimeSpan.FromMinutes(15);

    public string Name => "pre-downloads";
    public long LockKey => 0x4550_000F;
    public TimeSpan Interval => TimeSpan.FromMinutes(10);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var resolver = await policies.CreateResolverAsync(ct);
        var candidates = await db.Endpoints.AsNoTracking()
            .Where(e => e.Status == EndpointStatus.Active && e.MissingRequiredCount > 0 && e.Organization!.IsActive &&
                        e.Platform == AgentPlatforms.Windows && e.AgentCapabilities.Contains(AgentCapabilities.DownloadUpdates))
            .Select(e => new { e.Id, e.OrganizationId, e.SiteId, SiteTz = e.Site != null ? e.Site.TimeZone : null, OrgTz = e.Organization!.TimeZone })
            .ToListAsync(ct);

        var created = 0;
        var heldByOrg = new Dictionary<Guid, IReadOnlyCollection<Guid>>();
        foreach (var e in candidates)
        {
            var policy = resolver(e.OrganizationId, e.SiteId, e.Id);
            if (!policy.AutoInstallEnabled || policy.MaintenanceWindow is not { } settings || policy.PreDownloadHours <= 0)
            {
                continue;
            }

            var tz = e.SiteTz ?? e.OrgTz;
            if (MaintenanceWindow.FindOpenWindow(settings, tz, now) is not null ||
                MaintenanceWindow.FindNextWindow(settings, tz, now) is not { } next ||
                next.Start - now > TimeSpan.FromHours(policy.PreDownloadHours) || next.Start - now < MinimumLead)
            {
                continue; // the window is open (the installation runs), or the next one is too far away or too close
            }

            if (!heldByOrg.TryGetValue(e.OrganizationId, out var held))
            {
                held = (await holds.ActiveForAsync(e.OrganizationId, ct)).Keys.ToHashSet();
                heldByOrg[e.OrganizationId] = held;
            }

            // The same updates the window's installation would install (see ScheduledInstallTask), as far as they are due now.
            var due = await ScheduledInstallTask.DueUpdatesAsync(db, e.Id, held, ct);
            if (due.Count == 0)
            {
                continue;
            }

            try
            {
                await jobs.CreateAsync(new CreateJobRequest(e.Id, JobType.DownloadUpdates,
                    policy.HasInstallDelay ? InstallMode.Selected : InstallMode.AllEligible, policy.HasInstallDelay ? due : null,
                    Trigger: JobTrigger.Scheduled, ExpiresAt: next.Start, NotAfter: next.Start,
                    DedupeSuffix: "window:" + next.Start.UtcDateTime.ToString("yyyyMMddHHmm", System.Globalization.CultureInfo.InvariantCulture)), ct);
                created++;
            }
            catch (AppException ex) when (ex.Code is "duplicate_job" or "endpoint_not_active" or "nothing_to_install" or "validation_failed" or
                                              "agent_upgrade_required" or "not_supported_on_linux")
            {
                db.ChangeTracker.Clear();
            }
        }

        if (created > 0)
        {
            logger.LogInformation("Queued {Count} download job(s) ahead of maintenance windows", created);
        }
    }
}

/// <summary>Recomputes endpoints whose updates have just come out of their rollout delay, so they become required (and
/// scheduled) without waiting for the next scan.</summary>
public sealed class DeferralExpiryTask(EasyPatchDbContext db, ComplianceService compliance, TimeProvider clock, ILogger<DeferralExpiryTask> logger)
    : IMaintenanceTask
{
    public string Name => "deferral-expiry";
    public long LockKey => 0x4550_0008;
    public TimeSpan Interval => TimeSpan.FromMinutes(10);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var ids = await db.EndpointUpdates.AsNoTracking()
            .Where(u => u.DeferredUntil != null && u.DeferredUntil <= now &&
                        (u.State == EndpointUpdateState.Missing || u.State == EndpointUpdateState.Failed))
            .Select(u => u.EndpointId).Distinct().OrderBy(id => id).Take(2000).ToListAsync(ct);
        if (ids.Count == 0)
        {
            return;
        }

        await compliance.RecomputeAsync(ids, ct);
        await db.SaveChangesAsync(ct);
        logger.LogInformation("Rollout delay ended for updates on {Count} endpoint(s)", ids.Count);
    }
}

/// <summary>Creates restart jobs for endpoints whose policy has a recurring restart schedule. Each occurrence is
/// created at most once; with <see cref="RestartCondition.OnlyIfPending"/> only endpoints reporting a pending restart
/// are included (the agent checks again before restarting).</summary>
public sealed class ScheduledRestartTask(
    EasyPatchDbContext db,
    PolicyService policies,
    JobService jobs,
    TimeProvider clock,
    ILogger<ScheduledRestartTask> logger) : IMaintenanceTask
{
    public string Name => "scheduled-restarts";
    public long LockKey => 0x4550_0006;
    public TimeSpan Interval => TimeSpan.FromMinutes(2);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var resolver = await policies.CreateResolverAsync(ct);
        var candidates = await db.Endpoints.AsNoTracking()
            .Where(e => e.Status == EndpointStatus.Active && e.Organization!.IsActive && e.AgentCapabilities.Contains(AgentCapabilities.Restart))
            .Select(e => new
            {
                e.Id, e.OrganizationId, e.SiteId, e.RebootPending, SiteTz = e.Site != null ? e.Site.TimeZone : null, OrgTz = e.Organization!.TimeZone,
            })
            .ToListAsync(ct);

        var created = 0;
        foreach (var e in candidates)
        {
            if (resolver(e.OrganizationId, e.SiteId, e.Id).RestartSchedule is not { } schedule)
            {
                continue;
            }

            if (schedule.Condition == RestartCondition.OnlyIfPending && !e.RebootPending)
            {
                continue;
            }

            // The occurrence stays open for the expiry period, so a worker restart does not lose it.
            var occurrence = MaintenanceWindow.FindOpenWindow(
                new MaintenanceWindowSettings(schedule.Days.Select(d => (DayOfWeek)d).ToArray(), schedule.Time, schedule.ExpiryMinutes),
                e.SiteTz ?? e.OrgTz, now);
            if (occurrence is not { } open || open.End - now < TimeSpan.FromMinutes(5))
            {
                continue;
            }

            var suffix = "schedule:" + open.Start.UtcDateTime.ToString("yyyyMMddHHmm", System.Globalization.CultureInfo.InvariantCulture);
            var key = "restart:" + suffix;
            var exists = await db.Jobs.AnyAsync(j => j.EndpointId == e.Id && j.Type == JobType.Restart &&
                                                     (j.DedupeKey == key || JobTransitions.DedupeStatuses.Contains(j.Status)), ct);
            if (exists)
            {
                continue; // already created for this occurrence, or another restart is pending
            }

            try
            {
                // The occurrence is already open, so the job is deliverable at once and expires when the occurrence closes.
                await jobs.CreateAsync(new CreateJobRequest(e.Id, JobType.Restart, Trigger: JobTrigger.Scheduled, ExpiresAt: open.End,
                    DedupeSuffix: suffix, Restart: schedule.ToPayload()), ct);
                created++;
            }
            catch (AppException ex) when (ex.Code is "duplicate_job" or "endpoint_not_active" or "agent_upgrade_required")
            {
                db.ChangeTracker.Clear();
            }
        }

        if (created > 0)
        {
            logger.LogInformation("Scheduled {Count} restart job(s) from restart schedules", created);
        }
    }
}

/// <summary>
/// Automatic agent updates: queues an agent update for online endpoints whose policy has <c>AgentAutoUpdateEnabled</c>
/// and whose agent can update to a newer signed package. At most <see cref="EasyPatchOptions.AutomaticAgentUpdateConcurrency"/>
/// run at once, so a new package reaches the fleet in waves instead of every agent downloading it in the same minute.
/// </summary>
public sealed class AgentUpdateTask(
    EasyPatchDbContext db,
    PolicyService policies,
    JobService jobs,
    AgentPackageService packages,
    IOptions<EasyPatchOptions> options,
    TimeProvider clock,
    ILogger<AgentUpdateTask> logger) : IMaintenanceTask
{
    /// <summary>After a failed or cancelled update the same version is not tried again for this long.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromHours(6);

    /// <summary>A version that failed this many times is only installed when an administrator asks.</summary>
    public const int MaxFailuresPerVersion = 3;

    public string Name => "agent-updates";
    public long LockKey => 0x4550_0007;
    public TimeSpan Interval => TimeSpan.FromMinutes(2);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        if (!packages.List().Any(p => p.Release is not null))
        {
            return; // nothing is signed, so nothing can be offered
        }

        var active = await db.Jobs.CountAsync(j => j.Type == JobType.AgentUpdate && JobTransitions.DedupeStatuses.Contains(j.Status), ct);
        var slots = options.Value.AutomaticAgentUpdateConcurrency - active;
        if (slots <= 0)
        {
            return;
        }

        var now = clock.GetUtcNow();
        var resolver = await policies.CreateResolverAsync(ct);
        var candidates = await db.Endpoints.AsNoTracking()
            .Where(e => e.Status == EndpointStatus.Active && e.Organization!.IsActive && e.IsOnline &&
                        e.AgentCapabilities.Contains(AgentCapabilities.SelfUpdate) &&
                        !db.Jobs.Any(j => j.EndpointId == e.Id && j.Type == JobType.AgentUpdate && JobTransitions.DedupeStatuses.Contains(j.Status)))
            .OrderBy(e => e.LastCheckInAt)
            .ToListAsync(ct);

        var created = 0;
        foreach (var endpoint in candidates)
        {
            if (created >= slots)
            {
                break;
            }

            if (!resolver(endpoint.OrganizationId, endpoint.SiteId, endpoint.Id).AgentAutoUpdateEnabled ||
                AgentUpdatePlanner.Resolve(endpoint, packages).Package is not { } package)
            {
                continue;
            }

            var key = "agent-update:" + package.Version;
            var previous = await db.Jobs.AsNoTracking()
                .Where(j => j.EndpointId == endpoint.Id && j.Type == JobType.AgentUpdate && j.DedupeKey == key &&
                            (j.Status == JobStatus.Failed || j.Status == JobStatus.Cancelled))
                .Select(j => new { j.Status, j.CompletedAt })
                .ToListAsync(ct);
            if (previous.Count(p => p.Status == JobStatus.Failed) >= MaxFailuresPerVersion ||
                previous.Exists(p => p.CompletedAt > now - RetryAfter))
            {
                continue;
            }

            try
            {
                await jobs.CreateAsync(new CreateJobRequest(endpoint.Id, JobType.AgentUpdate, Trigger: JobTrigger.System,
                    ExpiresAt: now.AddHours(24), AgentVersion: package.Version), ct);
                created++;
            }
            catch (AppException ex) when (ex.Code is "duplicate_job" or "endpoint_not_active" or AgentUpdateTarget.UpgradeRequired or
                                              AgentUpdateTarget.UpToDate or AgentUpdateTarget.NoPackage or AgentUpdateTarget.NotSigned or
                                              AgentUpdateTarget.KeyNotTrusted)
            {
                db.ChangeTracker.Clear();
            }
        }

        if (created > 0)
        {
            logger.LogInformation("Queued {Count} automatic agent update(s)", created);
        }
    }
}

/// <summary>Daily per-organization compliance counters for trend reporting.</summary>
public sealed class ComplianceSnapshotTask(EasyPatchDbContext db, TimeProvider clock) : IMaintenanceTask
{
    public string Name => "compliance-snapshots";
    public long LockKey => 0x4550_0004;
    public TimeSpan Interval => TimeSpan.FromMinutes(30);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var today = DateOnly.FromDateTime(now.UtcDateTime);
        var rows = await db.Endpoints.AsNoTracking().Where(e => e.Status == EndpointStatus.Active)
            .GroupBy(e => e.OrganizationId)
            .Select(g => new
            {
                OrganizationId = g.Key,
                Total = g.Count(),
                Compliant = g.Count(e => e.ComplianceStatus == ComplianceStatus.Compliant),
                Missing = g.Count(e => e.ComplianceStatus == ComplianceStatus.MissingUpdates),
                Failed = g.Count(e => e.ComplianceStatus == ComplianceStatus.FailedUpdates),
                Reboot = g.Count(e => e.ComplianceStatus == ComplianceStatus.RebootRequired),
                Stale = g.Count(e => e.ComplianceStatus == ComplianceStatus.ScanStale),
                Never = g.Count(e => e.ComplianceStatus == ComplianceStatus.NeverScanned),
                Offline = g.Count(e => !e.IsOnline),
                MissingUpdates = g.Sum(e => e.MissingRequiredCount),
            }).ToListAsync(ct);
        var existing = await db.ComplianceSnapshots.Where(s => s.Date == today).ToDictionaryAsync(s => s.OrganizationId, ct);
        foreach (var r in rows)
        {
            if (!existing.TryGetValue(r.OrganizationId, out var snapshot))
            {
                snapshot = new ComplianceSnapshot { Date = today, OrganizationId = r.OrganizationId };
                db.ComplianceSnapshots.Add(snapshot);
            }

            snapshot.TotalEndpoints = r.Total;
            snapshot.Compliant = r.Compliant;
            snapshot.MissingUpdates = r.Missing;
            snapshot.FailedUpdates = r.Failed;
            snapshot.RebootRequired = r.Reboot;
            snapshot.ScanStale = r.Stale;
            snapshot.NeverScanned = r.Never;
            snapshot.Offline = r.Offline;
            snapshot.MissingRequiredUpdates = r.MissingUpdates;
        }

        await db.SaveChangesAsync(ct);
    }
}

/// <summary>Retention: deletes old events, audit records, finished jobs, scans, history and expired auth artifacts.</summary>
public sealed class RetentionTask(EasyPatchDbContext db, SettingsService settingsService, TimeProvider clock, ILogger<RetentionTask> logger) : IMaintenanceTask
{
    public string Name => "retention";
    public long LockKey => 0x4550_0005;
    public TimeSpan Interval => TimeSpan.FromHours(6);

    public async Task RunOnceAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var s = await settingsService.GetAsync(ct);
        var events = await db.EndpointEvents.Where(e => e.CreatedAt < now.AddDays(-s.RetentionEventsDays)).ExecuteDeleteAsync(ct);
        var auditRows = await db.AuditLogs.Where(a => a.CreatedAt < now.AddDays(-s.RetentionAuditDays)).ExecuteDeleteAsync(ct);
        var jobRows = await db.Jobs.Where(j => j.CompletedAt != null && j.CompletedAt < now.AddDays(-s.RetentionJobsDays)).ExecuteDeleteAsync(ct);
        var scans = await db.UpdateScans.Where(x => x.ReceivedAt < now.AddDays(-s.RetentionScansDays)).ExecuteDeleteAsync(ct);
        var history = await db.UpdateHistoryEntries.Where(h => h.Date < now.AddDays(-s.RetentionHistoryDays)).ExecuteDeleteAsync(ct);
        var sessions = await db.UserSessions.Where(x => x.ExpiresAt < now.AddDays(-7) || (x.RevokedAt != null && x.RevokedAt < now.AddDays(-7))).ExecuteDeleteAsync(ct);
        var resets = await db.PasswordResetTokens.Where(x => x.ExpiresAt < now.AddDays(-7)).ExecuteDeleteAsync(ct);
        var requests = await db.EnrollmentRequests
            .Where(r => r.Status == EnrollmentRequestStatus.Pending && r.ExpiresAt < now)
            .ExecuteUpdateAsync(x => x.SetProperty(r => r.Status, EnrollmentRequestStatus.Expired), ct);
        var oldRequests = await db.EnrollmentRequests.Where(r => r.Status != EnrollmentRequestStatus.Pending && r.CreatedAt < now.AddDays(-90)).ExecuteDeleteAsync(ct);
        var obsolete = await db.EndpointUpdates
            .Where(u => (u.State == EndpointUpdateState.NotApplicable || u.State == EndpointUpdateState.Superseded) && u.StateChangedAt < now.AddDays(-90))
            .ExecuteDeleteAsync(ct);
        var snapshots = await db.ComplianceSnapshots.Where(x => x.Date < DateOnly.FromDateTime(now.UtcDateTime.AddDays(-s.RetentionAuditDays))).ExecuteDeleteAsync(ct);
        var alerts = await db.Alerts.Where(a => a.Status == AlertStatus.Resolved && a.ResolvedAt < now.AddDays(-s.RetentionEventsDays)).ExecuteDeleteAsync(ct);
        var deliveries = await db.NotificationDeliveries
            .Where(d => d.Status != DeliveryStatus.Pending && d.CreatedAt < now.AddDays(-s.RetentionEventsDays)).ExecuteDeleteAsync(ct);
        var reports = await db.GeneratedReports.Where(r => r.GeneratedAt < now.AddMonths(-s.RetentionReportsMonths)).ExecuteDeleteAsync(ct);
        logger.LogInformation(
            "Retention: deleted {Events} events, {Audit} audit records, {Jobs} jobs, {Scans} scans, {History} history entries, {Sessions} sessions, " +
            "{Resets} reset tokens, {Old} old enrollment requests, {Obsolete} obsolete update states, {Snapshots} snapshots, {Alerts} resolved alerts, " +
            "{Deliveries} notifications, {Reports} monthly reports; expired {Requests} requests",
            events, auditRows, jobRows, scans, history, sessions, resets, oldRequests, obsolete, snapshots, alerts, deliveries, reports, requests);
    }
}
