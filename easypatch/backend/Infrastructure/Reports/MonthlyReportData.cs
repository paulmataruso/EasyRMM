using EasyPatch.Contracts;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace EasyPatch.Infrastructure.Reports;

/// <summary>Everything a monthly report shows. "Current" values are taken when the report is generated; the others
/// cover the reporting period.</summary>
public sealed record MonthlyReportData(
    string OrganizationName,
    string? BrandName,
    ReportPeriod Period,
    DateTimeOffset GeneratedAt,
    ReportSummary Summary,
    IReadOnlyList<ReportTrendPoint> Trend,
    IReadOnlyList<ReportSiteRow> Sites,
    IReadOnlyList<ReportMissingUpdateRow> TopMissing,
    IReadOnlyList<ReportOsRow> OperatingSystems,
    IReadOnlyList<ReportEndpointRow>? Endpoints);

/// <summary>A calendar month in UTC dates. <see cref="MonthToDate"/>: the month has not ended yet.</summary>
public sealed record ReportPeriod(DateOnly Start, DateOnly End, bool MonthToDate)
{
    public string Label => Start.ToString("MMMM yyyy", System.Globalization.CultureInfo.InvariantCulture) +
                           (MonthToDate ? $" (to {End.ToString("d MMMM", System.Globalization.CultureInfo.InvariantCulture)})" : "");

    public DateTimeOffset StartUtc => new(Start.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero);
    public DateTimeOffset EndExclusiveUtc => new(End.AddDays(1).ToDateTime(TimeOnly.MinValue), TimeSpan.Zero);

    /// <summary>The month <paramref name="year"/>-<paramref name="month"/>, ending at <paramref name="today"/> when that is
    /// within the month. Null for months that have not started or are more than 10 years old.</summary>
    public static ReportPeriod? For(int year, int month, DateOnly today)
    {
        if (year < 2000 || year > 9999 || month < 1 || month > 12)
        {
            return null;
        }

        var start = new DateOnly(year, month, 1);
        var last = start.AddMonths(1).AddDays(-1);
        if (start > today || start < today.AddYears(-10))
        {
            return null;
        }

        return last < today ? new ReportPeriod(start, last, false) : new ReportPeriod(start, today, true);
    }
}

public sealed record ReportSummary(
    int Endpoints,
    int Compliant,
    double CompliancePercent,
    double? ComplianceAtStart,
    double? ComplianceAtEnd,
    int UpdatesInstalled,
    int EndpointsUpdated,
    int FailedInstallations,
    int MissingRequiredUpdates,
    int KnownExploitedEndpoints,
    int RebootPending,
    int UnsupportedOs,
    int OfflineOver7Days);

public sealed record ReportTrendPoint(DateOnly Date, int Total, int Compliant)
{
    public double Percent => ComplianceCalculator.Percentage(Compliant, Total);
}

public sealed record ReportSiteRow(string Name, int Endpoints, int Compliant, int MissingRequired, int Failed, int RebootPending, int KnownExploited)
{
    public double Percent => ComplianceCalculator.Percentage(Compliant, Endpoints);
}

public sealed record ReportMissingUpdateRow(string Title, string? Kb, string? Severity, bool KnownExploited, int CveCount, int Endpoints);

public sealed record ReportOsRow(string OperatingSystem, OsSupportStatus Support, int Endpoints);

public sealed record ReportEndpointRow(
    string Hostname, string? Site, string? OperatingSystem, ComplianceStatus Status, int MissingRequired, int Failed, int KnownExploited,
    DateTimeOffset? LastCheckIn, DateTimeOffset? LastScan);

/// <summary>Collects the data of a monthly report for one organization (read-only queries).</summary>
public sealed class MonthlyReportDataBuilder(EasyPatchDbContext db)
{
    public const int MaxEndpointRows = 5000;
    public const int TopMissingRows = 15;

    public async Task<MonthlyReportData> BuildAsync(Organization org, ReportPeriod period, bool includeEndpoints, string? brandName,
        DateTimeOffset now, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(org);
        ArgumentNullException.ThrowIfNull(period);
        var endpoints = await db.Endpoints.AsNoTracking()
            .Where(e => e.OrganizationId == org.Id && e.Status == EndpointStatus.Active)
            .Select(e => new
            {
                e.Id, e.Hostname, SiteName = e.Site != null ? e.Site.Name : null, e.OperatingSystem, e.OsBuildNumber, e.OsProductType, e.ComplianceStatus,
                e.MissingRequiredCount, e.FailedCount, e.KnownExploitedMissingCount, e.RebootPending, e.OsSupportStatus, e.LastCheckInAt, e.LastScanAt,
            })
            .ToListAsync(ct);

        // Period values.
        var start = period.StartUtc;
        var end = period.EndExclusiveUtc;
        var installed = await db.EndpointUpdates.AsNoTracking()
            .Where(u => u.State == EndpointUpdateState.Installed && u.InstalledAt >= start && u.InstalledAt < end &&
                        db.Endpoints.Any(e => e.Id == u.EndpointId && e.OrganizationId == org.Id))
            .GroupBy(u => 1).Select(g => new { Updates = g.Count(), Endpoints = g.Select(u => u.EndpointId).Distinct().Count() })
            .FirstOrDefaultAsync(ct);
        var failed = await db.JobUpdates.AsNoTracking()
            .Where(ju => ju.Status == JobItemStatus.Failed && ju.CompletedAt >= start && ju.CompletedAt < end &&
                         db.Jobs.Any(j => j.Id == ju.JobId && j.OrganizationId == org.Id))
            .CountAsync(ct);
        var snapshots = await db.ComplianceSnapshots.AsNoTracking()
            .Where(s => s.OrganizationId == org.Id && s.Date >= period.Start && s.Date <= period.End)
            .OrderBy(s => s.Date)
            .Select(s => new ReportTrendPoint(s.Date, s.TotalEndpoints, s.Compliant))
            .ToListAsync(ct);

        // Current values.
        var compliant = endpoints.Count(e => e.ComplianceStatus == ComplianceStatus.Compliant);
        var summary = new ReportSummary(
            endpoints.Count,
            compliant,
            ComplianceCalculator.Percentage(compliant, endpoints.Count),
            snapshots.Count > 0 ? snapshots[0].Percent : null,
            snapshots.Count > 0 ? snapshots[^1].Percent : null,
            installed?.Updates ?? 0,
            installed?.Endpoints ?? 0,
            failed,
            endpoints.Sum(e => e.MissingRequiredCount),
            endpoints.Count(e => e.KnownExploitedMissingCount > 0),
            endpoints.Count(e => e.RebootPending),
            endpoints.Count(e => e.OsSupportStatus == OsSupportStatus.Unsupported),
            endpoints.Count(e => e.LastCheckInAt is null || e.LastCheckInAt < now.AddDays(-7)));

        var sites = endpoints.GroupBy(e => e.SiteName ?? "(no site)")
            .Select(g => new ReportSiteRow(g.Key, g.Count(), g.Count(e => e.ComplianceStatus == ComplianceStatus.Compliant), g.Sum(e => e.MissingRequiredCount),
                g.Sum(e => e.FailedCount), g.Count(e => e.RebootPending), g.Count(e => e.KnownExploitedMissingCount > 0)))
            .OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var missing = await db.EndpointUpdates.AsNoTracking()
            .Where(u => u.IsRequired && (u.State == EndpointUpdateState.Missing || u.State == EndpointUpdateState.Failed ||
                                         u.State == EndpointUpdateState.PendingVerification) &&
                        db.Endpoints.Any(e => e.Id == u.EndpointId && e.OrganizationId == org.Id && e.Status == EndpointStatus.Active))
            .GroupBy(u => u.UpdateId)
            .Select(g => new { UpdateId = g.Key, Endpoints = g.Count(), KnownExploited = g.Count(u => u.KnownExploited) })
            .OrderByDescending(x => x.KnownExploited > 0).ThenByDescending(x => x.Endpoints)
            .Take(TopMissingRows)
            .ToListAsync(ct);
        var updateIds = missing.Select(m => m.UpdateId).ToList();
        var catalog = await db.Updates.AsNoTracking().Where(u => updateIds.Contains(u.Id))
            .Select(u => new { u.Id, u.Title, u.KbNumbers, u.PackageName, u.MsrcSeverity, CveCount = u.CveIds.Count })
            .ToDictionaryAsync(u => u.Id, ct);
        var topMissing = missing.Where(m => catalog.ContainsKey(m.UpdateId)).Select(m =>
        {
            var u = catalog[m.UpdateId];
            return new ReportMissingUpdateRow(u.Title, u.KbNumbers.Count > 0 ? u.KbNumbers[0] : u.PackageName, u.MsrcSeverity, m.KnownExploited > 0, u.CveCount,
                m.Endpoints);
        }).ToList();

        var os = endpoints
            .GroupBy(e => (Name: OsNaming.Describe(e.OperatingSystem, e.OsBuildNumber, e.OsProductType) ?? "Unknown", e.OsSupportStatus))
            .Select(g => new ReportOsRow(g.Key.Name, g.Key.OsSupportStatus, g.Count()))
            .OrderByDescending(r => r.Endpoints).ThenBy(r => r.OperatingSystem, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var endpointRows = includeEndpoints
            ? endpoints.OrderBy(e => e.SiteName ?? "", StringComparer.OrdinalIgnoreCase).ThenBy(e => e.Hostname, StringComparer.OrdinalIgnoreCase)
                .Take(MaxEndpointRows)
                .Select(e => new ReportEndpointRow(e.Hostname, e.SiteName, OsNaming.Describe(e.OperatingSystem, e.OsBuildNumber, e.OsProductType),
                    e.ComplianceStatus, e.MissingRequiredCount, e.FailedCount, e.KnownExploitedMissingCount, e.LastCheckInAt, e.LastScanAt))
                .ToList()
            : null;

        return new MonthlyReportData(org.Name, brandName, period, now, summary, snapshots, sites, topMissing, os, endpointRows);
    }
}
