using System.Globalization;
using EasyPatch.Contracts;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EasyPatch.Infrastructure.Notifications;

/// <summary>A subject that matches a rule in this evaluation.</summary>
/// <param name="Offline">The endpoint is offline: other rules do not open new alerts for it (the offline rule covers it).</param>
public sealed record AlertMatch(Guid OrganizationId, Guid? EndpointId, string Title, string? Details, bool Offline = false);

public sealed record AlertRunResult(int Opened, int Resolved, int Reopened, int Deliveries);

/// <summary>
/// Evaluates alert rules (worker task "alerts", every 2 minutes):
/// * an alert opens when a subject (endpoint, or organization for enrollment requests) matches an enabled rule;
/// * it resolves after <see cref="ResolveAfterClearEvaluations"/> consecutive evaluations without a match (no flapping);
/// * a subject that matches again within <see cref="ReopenWindow"/> of resolving reopens the same alert without a new
///   notification; offline endpoints only get offline alerts;
/// * alerts of disabled or deleted rules, archived organizations and removed endpoints resolve silently;
/// * notifications are one digest per channel and kind per run, with at most <see cref="MaxItemsPerMessage"/> lines.
/// </summary>
public sealed class AlertEngine(
    EasyPatchDbContext db,
    PolicyService policies,
    IOptions<EasyPatchOptions> options,
    TimeProvider clock,
    ILogger<AlertEngine> logger)
{
    public const int ResolveAfterClearEvaluations = 2;
    public const int MaxItemsPerMessage = 25;
    public static readonly TimeSpan ReopenWindow = TimeSpan.FromHours(1);

    public async Task<AlertRunResult> EvaluateAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow();
        var silent = await db.Alerts
            .Where(a => a.Status != AlertStatus.Resolved &&
                        (a.RuleId == null ||
                         !db.AlertRules.Any(r => r.Id == a.RuleId && r.Enabled) ||
                         !db.Organizations.Any(o => o.Id == a.OrganizationId && o.IsActive) ||
                         (a.EndpointId != null && !db.Endpoints.Any(e => e.Id == a.EndpointId && e.Status == EndpointStatus.Active))))
            .ExecuteUpdateAsync(x => x.SetProperty(a => a.Status, AlertStatus.Resolved).SetProperty(a => a.ResolvedAt, now), ct);

        var rules = await db.AlertRules.Where(r => r.Enabled).OrderBy(r => r.Name).ToListAsync(ct);
        var channels = await db.NotificationChannels.AsNoTracking().Where(c => c.Enabled).Select(c => c.Id).ToListAsync(ct);
        var orgNames = await db.Organizations.AsNoTracking().ToDictionaryAsync(o => o.Id, o => o.Name, ct);
        var outbox = new Dictionary<(Guid Channel, NotificationKind Kind), List<Alert>>();
        int opened = 0, resolved = 0, reopened = 0;

        foreach (var rule in rules)
        {
            List<AlertMatch> matches;
            try
            {
                matches = await MatchAsync(rule, now, ct);
            }
            catch (Exception ex) when (ex is InvalidOperationException or DbUpdateException or Npgsql.NpgsqlException)
            {
                logger.LogError(ex, "Alert rule {Rule} ({Type}) could not be evaluated", rule.Name, rule.Type);
                continue;
            }

            var unresolved = await db.Alerts.Where(a => a.RuleId == rule.Id && a.Status != AlertStatus.Resolved).ToListAsync(ct);
            var byKey = unresolved.ToDictionary(a => a.DedupeKey);
            var since = now - ReopenWindow;
            var recent = (await db.Alerts.Where(a => a.RuleId == rule.Id && a.Status == AlertStatus.Resolved && a.ResolvedAt >= since).ToListAsync(ct))
                .GroupBy(a => a.DedupeKey).ToDictionary(g => g.Key, g => g.OrderByDescending(a => a.ResolvedAt).First());
            var seen = new HashSet<string>();
            var ruleOpened = new List<Alert>();
            var ruleResolved = new List<Alert>();

            foreach (var match in matches)
            {
                var key = DedupeKey(rule, match);
                if (!seen.Add(key))
                {
                    continue;
                }

                if (byKey.TryGetValue(key, out var alert))
                {
                    alert.LastSeenAt = now;
                    alert.ClearCount = 0;
                    alert.Title = Clip(match.Title, 300);
                    alert.Details = match.Details is null ? null : Clip(match.Details, 2000);
                    alert.Severity = rule.Severity;
                    continue;
                }

                if (match.Offline && rule.Type != AlertRuleType.EndpointOffline)
                {
                    continue;
                }

                if (recent.TryGetValue(key, out var previous))
                {
                    previous.Status = AlertStatus.Open;
                    previous.ResolvedAt = null;
                    previous.AcknowledgedAt = null;
                    previous.AcknowledgedBy = null;
                    previous.LastSeenAt = now;
                    previous.ClearCount = 0;
                    previous.Title = Clip(match.Title, 300);
                    previous.Details = match.Details is null ? null : Clip(match.Details, 2000);
                    previous.Severity = rule.Severity;
                    reopened++;
                    continue;
                }

                var created = new Alert
                {
                    Id = Guid.CreateVersion7(now),
                    RuleId = rule.Id,
                    RuleType = rule.Type,
                    OrganizationId = match.OrganizationId,
                    EndpointId = match.EndpointId,
                    DedupeKey = key,
                    Status = AlertStatus.Open,
                    Severity = rule.Severity,
                    Title = Clip(match.Title, 300),
                    Details = match.Details is null ? null : Clip(match.Details, 2000),
                    OpenedAt = now,
                    LastSeenAt = now,
                };
                db.Alerts.Add(created);
                ruleOpened.Add(created);
                opened++;
            }

            foreach (var alert in unresolved.Where(a => !seen.Contains(a.DedupeKey)))
            {
                alert.ClearCount++;
                if (alert.ClearCount >= ResolveAfterClearEvaluations)
                {
                    alert.Status = AlertStatus.Resolved;
                    alert.ResolvedAt = now;
                    ruleResolved.Add(alert);
                    resolved++;
                }
            }

            var reminders = rule.RenotifyHours > 0
                ? unresolved.Where(a => a.Status == AlertStatus.Open && seen.Contains(a.DedupeKey) &&
                                        (a.LastNotifiedAt ?? a.OpenedAt) <= now.AddHours(-rule.RenotifyHours)).ToList()
                : [];

            var targets = rule.ChannelIds.Where(channels.Contains).Distinct().ToList();
            if (targets.Count == 0)
            {
                continue;
            }

            foreach (var channel in targets)
            {
                Add(outbox, channel, NotificationKind.AlertsOpened, ruleOpened);
                Add(outbox, channel, NotificationKind.AlertsReminder, reminders);
                if (rule.NotifyOnResolve)
                {
                    Add(outbox, channel, NotificationKind.AlertsResolved, ruleResolved);
                }
            }

            foreach (var alert in ruleOpened.Concat(reminders))
            {
                alert.LastNotifiedAt = now;
            }
        }

        var deliveries = 0;
        foreach (var ((channel, kind), alerts) in outbox)
        {
            if (alerts.Count == 0)
            {
                continue;
            }

            var message = BuildMessage(kind, alerts, orgNames, options.Value.PublicUrl);
            db.NotificationDeliveries.Add(new NotificationDelivery
            {
                Id = Guid.CreateVersion7(now),
                ChannelId = channel,
                Kind = kind,
                AlertIds = alerts.Take(MaxItemsPerMessage).Select(a => a.Id).ToList(),
                Subject = Clip(message.Subject, 300),
                Payload = NotificationRenderer.Serialize(message),
                Status = DeliveryStatus.Pending,
                NextAttemptAt = now,
                CreatedAt = now,
            });
            deliveries++;
        }

        await db.SaveChangesAsync(ct);
        if (opened + resolved + reopened + silent > 0)
        {
            logger.LogInformation("Alerts: {Opened} opened, {Resolved} resolved, {Reopened} reopened, {Silent} closed (rule or subject removed), {Deliveries} notifications queued",
                opened, resolved, reopened, silent, deliveries);
        }

        return new AlertRunResult(opened, resolved + silent, reopened, deliveries);
    }

    public static string DedupeKey(AlertRule rule, AlertMatch match)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(match);
        return match.EndpointId is { } endpoint ? $"{rule.Id:N}:{endpoint:N}" : $"{rule.Id:N}:org:{match.OrganizationId:N}";
    }

    public static NotificationMessage BuildMessage(NotificationKind kind, IReadOnlyList<Alert> alerts, IReadOnlyDictionary<Guid, string> orgNames, string publicUrl)
    {
        ArgumentNullException.ThrowIfNull(alerts);
        ArgumentNullException.ThrowIfNull(orgNames);
        var baseUrl = (publicUrl ?? string.Empty).TrimEnd('/');
        var ordered = alerts.OrderByDescending(a => a.Severity).ThenBy(a => a.Title, StringComparer.OrdinalIgnoreCase).ToList();
        var items = ordered.Take(MaxItemsPerMessage).Select(a => new NotificationItem(
            a.Id, a.Severity, a.Title, orgNames.GetValueOrDefault(a.OrganizationId), a.Details,
            a.EndpointId is { } e ? $"{baseUrl}/endpoints/{e}" : $"{baseUrl}/alerts?organizationId={a.OrganizationId}",
            kind == NotificationKind.AlertsResolved ? a.ResolvedAt ?? a.LastSeenAt : a.OpenedAt)).ToList();
        var n = alerts.Count;
        var single = n == 1 ? ordered[0] : null;
        var (subject, intro) = kind switch
        {
            NotificationKind.AlertsOpened when single is not null => ($"[EasyPatch] {single.Severity}: {single.Title}", "A new alert was opened."),
            NotificationKind.AlertsOpened => ($"[EasyPatch] {n} new alerts", $"{n} new alerts were opened."),
            NotificationKind.AlertsResolved when single is not null => ($"[EasyPatch] Resolved: {single.Title}", "This alert was resolved."),
            NotificationKind.AlertsResolved => ($"[EasyPatch] {n} alerts resolved", $"{n} alerts were resolved."),
            NotificationKind.AlertsReminder when single is not null => ($"[EasyPatch] Still open: {single.Title}", "This alert is still open."),
            _ => ($"[EasyPatch] {n} alerts still open", $"{n} alerts are still open and not acknowledged."),
        };
        return new NotificationMessage(kind, subject, intro, items, Math.Max(0, n - items.Count), $"{baseUrl}/alerts");
    }

    public static NotificationMessage TestMessage(string channelName, string publicUrl)
    {
        var baseUrl = (publicUrl ?? string.Empty).TrimEnd('/');
        return new NotificationMessage(NotificationKind.Test, "[EasyPatch] Test notification",
            $"This is a test of the notification channel \"{channelName}\". If you can read this, the channel works.", [], 0, $"{baseUrl}/alerts");
    }

    private async Task<List<AlertMatch>> MatchAsync(AlertRule rule, DateTimeOffset now, CancellationToken ct)
    {
        if (rule.Type == AlertRuleType.EnrollmentPending)
        {
            var requests = db.EnrollmentRequests.AsNoTracking()
                .Where(r => r.Status == EnrollmentRequestStatus.Pending && r.ExpiresAt > now)
                .Where(r => db.Organizations.Any(o => o.Id == r.OrganizationId && o.IsActive));
            if (rule.OrganizationId is { } org)
            {
                requests = requests.Where(r => r.OrganizationId == org);
            }

            var counts = await requests.GroupBy(r => r.OrganizationId).Select(g => new { g.Key, Count = g.Count() }).ToListAsync(ct);
            var names = await db.Organizations.AsNoTracking().Where(o => counts.Select(c => c.Key).Contains(o.Id)).ToDictionaryAsync(o => o.Id, o => o.Name, ct);
            return counts.Select(c => new AlertMatch(c.Key, null,
                $"{names.GetValueOrDefault(c.Key, "Organization")}: {Plural(c.Count, "computer")} waiting for enrollment approval",
                "Approve or reject the requests under Pending Approvals.")).ToList();
        }

        if (rule.Type == AlertRuleType.UpdateHeld)
        {
            return await UpdateHeldAsync(rule.OrganizationId, ct);
        }

        var endpoints = db.Endpoints.AsNoTracking()
            .Where(e => e.Status == EndpointStatus.Active && db.Organizations.Any(o => o.Id == e.OrganizationId && o.IsActive));
        if (rule.OrganizationId is { } organization)
        {
            endpoints = endpoints.Where(e => e.OrganizationId == organization);
        }

        if (rule.TagId is { } tag)
        {
            endpoints = endpoints.WithTag(db, tag); // its own tag, or its site's or organization's
        }

        var threshold = rule.Threshold ?? AlertRuleCatalog.Threshold(rule.Type)?.Default ?? 0;
        switch (rule.Type)
        {
            case AlertRuleType.EndpointOffline:
            {
                var cutoff = now.AddHours(-threshold);
                var rows = await endpoints.Where(e => !e.IsOnline && e.LastCheckInAt != null && e.LastCheckInAt <= cutoff)
                    .Select(e => new { e.Id, e.OrganizationId, e.Hostname, e.LastCheckInAt }).ToListAsync(ct);
                return rows.Select(r => new AlertMatch(r.OrganizationId, r.Id, $"{r.Hostname} has been offline for over {Plural(threshold, "hour")}",
                    $"Last check-in {Format(r.LastCheckInAt)}.", Offline: true)).ToList();
            }

            case AlertRuleType.InstallFailed:
            {
                var rows = await endpoints.Where(e => e.FailedCount > 0)
                    .Select(e => new { e.Id, e.OrganizationId, e.Hostname, e.FailedCount, e.IsOnline }).ToListAsync(ct);
                return rows.Select(r => new AlertMatch(r.OrganizationId, r.Id, $"{r.Hostname}: {Plural(r.FailedCount, "update")} failed to install",
                    null, !r.IsOnline)).ToList();
            }

            case AlertRuleType.SecurityUpdateMissing:
                return await SecurityUpdateMissingAsync(endpoints, threshold, now, ct);

            case AlertRuleType.ScanStale:
            {
                var rows = await endpoints.Where(e => e.ComplianceStatus == ComplianceStatus.ScanStale)
                    .Select(e => new { e.Id, e.OrganizationId, e.Hostname, e.LastScanAt, e.IsOnline }).ToListAsync(ct);
                return rows.Select(r => new AlertMatch(r.OrganizationId, r.Id, $"{r.Hostname}: no successful update scan since {Format(r.LastScanAt)}",
                    null, !r.IsOnline)).ToList();
            }

            case AlertRuleType.RestartPending:
            {
                var cutoff = now.AddDays(-threshold);
                var rows = await endpoints.Where(e => e.RebootPending && e.RebootPendingSince != null && e.RebootPendingSince <= cutoff)
                    .Select(e => new { e.Id, e.OrganizationId, e.Hostname, e.RebootPendingSince, e.IsOnline }).ToListAsync(ct);
                return rows.Select(r => new AlertMatch(r.OrganizationId, r.Id, $"{r.Hostname}: restart pending for over {Plural(threshold, "day")}",
                    $"Pending since {Format(r.RebootPendingSince)}. EasyPatch restarts endpoints only when asked or on a restart schedule.", !r.IsOnline)).ToList();
            }

            case AlertRuleType.KnownExploitedMissing:
            {
                var rows = await endpoints.Where(e => e.KnownExploitedMissingCount > 0)
                    .Select(e => new { e.Id, e.OrganizationId, e.Hostname, e.KnownExploitedMissingCount, e.IsOnline }).ToListAsync(ct);
                return rows.Select(r => new AlertMatch(r.OrganizationId, r.Id,
                    $"{r.Hostname}: {Plural(r.KnownExploitedMissingCount, "update")} fixing known-exploited vulnerabilities missing",
                    "The CISA Known Exploited Vulnerabilities catalog lists vulnerabilities these updates fix as exploited in the wild. Install them first.",
                    !r.IsOnline)).ToList();
            }

            case AlertRuleType.OsUnsupported:
            {
                var today = DateOnly.FromDateTime(now.UtcDateTime);
                var soon = today.AddDays(threshold);
                var rows = await endpoints
                    .Where(e => e.OsSupportStatus == OsSupportStatus.Unsupported ||
                                (e.OsEndOfServicing != null && e.OsEndOfServicing >= today && e.OsEndOfServicing <= soon))
                    .Select(e => new { e.Id, e.OrganizationId, e.Hostname, e.OperatingSystem, e.OsSupportStatus, e.OsEndOfServicing, e.IsOnline })
                    .ToListAsync(ct);
                return rows.Select(r => new AlertMatch(r.OrganizationId, r.Id,
                    r.OsSupportStatus == OsSupportStatus.Unsupported
                        ? $"{r.Hostname}: {r.OperatingSystem ?? "the operating system"} no longer receives security updates"
                        : $"{r.Hostname}: {r.OperatingSystem ?? "the operating system"} support ends on {r.OsEndOfServicing:yyyy-MM-dd}",
                    null, !r.IsOnline)).ToList();
            }

            default:
                return [];
        }
    }

    /// <summary>Required security updates missing for more than N days after they became required (after the rollout
    /// delay, which is resolved per endpoint).</summary>
    private async Task<List<AlertMatch>> SecurityUpdateMissingAsync(IQueryable<Endpoint> endpoints, int days, DateTimeOffset now, CancellationToken ct)
    {
        var cutoff = now.AddDays(-days);
        var rows = await (from u in db.EndpointUpdates.AsNoTracking()
                          join e in endpoints on u.EndpointId equals e.Id
                          where u.IsRequired && !u.IsExcluded &&
                                (u.State == EndpointUpdateState.Missing || u.State == EndpointUpdateState.Failed ||
                                 u.State == EndpointUpdateState.PendingVerification) &&
                                u.FirstDetectedAt <= cutoff &&
                                (u.Update!.Category == UpdateCategory.Security || u.Update.MsClassification == UpdateRequirement.SecurityClassification)
                          select new
                          {
                              e.Id, e.OrganizationId, e.SiteId, e.Hostname, e.IsOnline, u.FirstDetectedAt, u.DelayBasisAt, u.KnownExploited,
                              u.Update!.Title,
                          }).ToListAsync(ct);
        if (rows.Count == 0)
        {
            return [];
        }

        var resolver = await policies.CreateResolverAsync(ct);
        var result = new List<AlertMatch>();
        foreach (var g in rows.GroupBy(r => r.Id))
        {
            var first = g.First();
            var policy = resolver(first.OrganizationId, first.SiteId, first.Id);
            var overdue = g.Where(r =>
            {
                var delay = r.KnownExploited && policy.KnownExploitedSkipsDelay ? 0 : policy.SecurityInstallDelayDays;
                var requiredSince = (r.DelayBasisAt ?? r.FirstDetectedAt).AddDays(delay);
                return (requiredSince > r.FirstDetectedAt ? requiredSince : r.FirstDetectedAt) <= cutoff;
            }).ToList();
            if (overdue.Count == 0)
            {
                continue;
            }

            var titles = string.Join("; ", overdue.Take(3).Select(r => r.Title)) + (overdue.Count > 3 ? $"; and {overdue.Count - 3} more" : string.Empty);
            result.Add(new AlertMatch(first.OrganizationId, first.Id,
                $"{first.Hostname}: {Plural(overdue.Count, "security update")} missing for over {Plural(days, "day")}", titles, !first.IsOnline));
        }

        return result;
    }

    /// <summary>One alert per organization that has active endpoints still needing an update on hold for it (a hold for
    /// every organization or its own).</summary>
    private async Task<List<AlertMatch>> UpdateHeldAsync(Guid? organizationId, CancellationToken ct)
    {
        var holds = await db.UpdateHolds.AsNoTracking().Where(h => h.ReleasedAt == null)
            .Where(h => organizationId == null || h.OrganizationId == null || h.OrganizationId == organizationId)
            .ToListAsync(ct);
        if (holds.Count == 0)
        {
            return [];
        }

        var guids = holds.Select(h => h.UpdateGuid).Distinct().ToList();
        var needed = (from u in db.EndpointUpdates.AsNoTracking()
                      join e in db.Endpoints.AsNoTracking() on u.EndpointId equals e.Id
                      where guids.Contains(u.UpdateGuid) && e.Status == EndpointStatus.Active &&
                            (u.State == EndpointUpdateState.Missing || u.State == EndpointUpdateState.Failed) &&
                            db.Organizations.Any(o => o.Id == e.OrganizationId && o.IsActive)
                      select new { e.OrganizationId, u.UpdateGuid, Title = u.Update!.Title });
        if (organizationId is { } org)
        {
            needed = needed.Where(r => r.OrganizationId == org);
        }

        var rows = await needed.Distinct().ToListAsync(ct);
        var names = await db.Organizations.AsNoTracking().Where(o => rows.Select(r => r.OrganizationId).Contains(o.Id))
            .ToDictionaryAsync(o => o.Id, o => o.Name, ct);
        var result = new List<AlertMatch>();
        foreach (var g in rows.GroupBy(r => r.OrganizationId))
        {
            var held = g.Where(r => holds.Exists(h => h.UpdateGuid == r.UpdateGuid && (h.OrganizationId is null || h.OrganizationId == g.Key)))
                .GroupBy(r => r.UpdateGuid).Select(u => u.First()).OrderBy(r => r.Title, StringComparer.OrdinalIgnoreCase).ToList();
            if (held.Count == 0)
            {
                continue;
            }

            var name = names.GetValueOrDefault(g.Key, "Organization");
            var title = held.Count == 1 ? $"{name}: {held[0].Title} is on hold" : $"{name}: {Plural(held.Count, "update")} on hold";
            var details = string.Join("; ", held.Take(3).Select(r =>
            {
                var hold = holds.Where(h => h.UpdateGuid == r.UpdateGuid && (h.OrganizationId is null || h.OrganizationId == g.Key))
                    .OrderBy(h => h.OrganizationId is null).First();
                return held.Count == 1 ? $"{hold.CreatedBy}: {hold.Reason}" : $"{r.Title} ({hold.CreatedBy}: {hold.Reason})";
            })) + (held.Count > 3 ? $"; and {held.Count - 3} more" : string.Empty) +
                ". EasyPatch does not install it automatically until the hold is released on the update's page.";
            result.Add(new AlertMatch(g.Key, null, title, details));
        }

        return result;
    }

    private static void Add(Dictionary<(Guid, NotificationKind), List<Alert>> outbox, Guid channel, NotificationKind kind, IEnumerable<Alert> alerts)
    {
        if (!outbox.TryGetValue((channel, kind), out var list))
        {
            list = [];
            outbox[(channel, kind)] = list;
        }

        foreach (var alert in alerts)
        {
            if (!list.Contains(alert))
            {
                list.Add(alert);
            }
        }
    }

    private static string Plural(int n, string noun) => n == 1 ? $"1 {noun}" : $"{n.ToString(CultureInfo.InvariantCulture)} {noun}s";

    private static string Format(DateTimeOffset? at) =>
        at is { } t ? t.UtcDateTime.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture) : "never";

    private static string Clip(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";
}
