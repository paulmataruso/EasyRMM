using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;

namespace EasyPatch.Api.Endpoints;

internal static class Mapping
{
    public static readonly Expression<Func<Job, JobSummaryDto>> JobSummary = j => new JobSummaryDto(
        j.Id, j.EndpointId, j.Endpoint!.Hostname, j.OrganizationId, j.Endpoint.Organization!.Name, j.Type, j.Status, j.Trigger, j.RequestedBy,
        j.CreatedAt, j.StartedAt, j.CompletedAt, j.ExpiresAt, j.ProgressPercent, j.Phase, j.ProgressMessage, j.ErrorCode, j.ErrorMessage,
        j.RebootRequired, j.TimedOut, j.CancelRequestedAt != null,
        j.Updates.Count,
        j.Updates.Count(u => u.Status == JobItemStatus.Succeeded),
        j.Updates.Count(u => u.Status == JobItemStatus.Failed));

    public static readonly Expression<Func<EndpointEvent, EndpointEventDto>> Event = e => new EndpointEventDto(
        e.Id, e.EndpointId, null, e.Type, e.Severity, e.Message, e.JobId, e.CreatedAt);

    public static readonly Expression<Func<JobUpdate, JobItemDto>> JobItem = u => new JobItemDto(
        u.UpdateGuid, u.Title, u.KbNumber, u.Category, u.Status, u.SkipReason, u.ResultCode, u.ErrorCode, u.ErrorMessage, u.RebootRequired,
        u.DownloadPercent, u.InstallPercent, u.StartedAt, u.CompletedAt);

    public static string HistoryResult(int resultCode) => resultCode switch
    {
        0 => "NotStarted",
        1 => "InProgress",
        2 => "Succeeded",
        3 => "SucceededWithErrors",
        4 => "Failed",
        5 => "Aborted",
        _ => "Unknown",
    };

    public static UpdateHistoryDto History(UpdateHistoryEntry h) => new(
        h.Id, h.UpdateGuid, h.Title, h.KbNumber, h.Operation, h.ResultCode, HistoryResult(h.ResultCode), h.HResult,
        h.HResult is { Length: > 0 } code && code != "0x00000000" ? WindowsUpdateErrors.DescribeCode(code) : null, h.Date);

    /// <summary>Intermediate row loaded from SQL; mapped to <see cref="EndpointSummaryDto"/> in memory (OS naming, agent outdated).</summary>
    public sealed record EndpointRow(
        Guid Id, string Hostname, Guid OrganizationId, string OrganizationName, Guid? SiteId, string? SiteName, EndpointStatus Status,
        string? OperatingSystem, string? OsVersion, string? OsBuild, int? OsBuildNumber, string? OsProductType, string? Architecture, string? AgentVersion,
        bool IsOnline, DateTimeOffset? LastCheckInAt, DateTimeOffset? LastScanAt, ComplianceStatus ComplianceStatus, int MissingRequiredCount,
        int MissingTotalCount, int FailedCount, bool RebootPending, OsSupportStatus OsSupportStatus, string? CurrentActivity, string? LastSeenIp,
        string Platform, string? AgentPackageFormat, int MissingDeferredCount = 0, int KnownExploitedMissingCount = 0);

    public static readonly Expression<Func<EasyPatch.Core.Entities.Endpoint, EndpointRow>> EndpointRowProjection = e => new EndpointRow(
        e.Id, e.Hostname, e.OrganizationId, e.Organization!.Name, e.SiteId, e.Site != null ? e.Site.Name : null, e.Status, e.OperatingSystem,
        e.OsVersion, e.OsBuild, e.OsBuildNumber, e.OsProductType, e.Architecture, e.AgentVersion, e.IsOnline, e.LastCheckInAt, e.LastScanAt,
        e.ComplianceStatus, e.MissingRequiredCount, e.MissingTotalCount, e.FailedCount, e.RebootPending, e.OsSupportStatus, e.CurrentActivity,
        e.LastSeenIp, e.Platform, e.AgentPackageFormat, e.MissingDeferredCount, e.KnownExploitedMissingCount);

    public static EndpointSummaryDto ToSummary(EndpointRow r, LatestAgentVersions latest, IReadOnlyList<TagRefDto>? tags = null) => new(
        r.Id, r.Hostname, r.OrganizationId, r.OrganizationName, r.SiteId, r.SiteName, r.Status,
        OsNaming.Describe(r.OperatingSystem, r.OsBuildNumber, r.OsProductType), r.OsVersion, r.OsBuild, r.Architecture, r.AgentVersion,
        latest.IsOutdated(r.AgentVersion, r.AgentPackageFormat), r.IsOnline, r.LastCheckInAt, r.LastScanAt, r.ComplianceStatus, r.MissingRequiredCount,
        r.MissingTotalCount, r.FailedCount, r.RebootPending, r.OsSupportStatus, r.CurrentActivity, r.LastSeenIp, r.Platform, r.MissingDeferredCount,
        tags ?? [], r.KnownExploitedMissingCount);

    /// <summary>Tags of the given endpoints (for list and detail views): their own tags first, then those they have through
    /// their site or organization, each group by name.</summary>
    public static async Task<Dictionary<Guid, List<TagRefDto>>> LoadTagsAsync(EasyPatch.Infrastructure.Data.EasyPatchDbContext db,
        IReadOnlyCollection<Guid> endpointIds, CancellationToken ct)
    {
        var links = await EffectiveTags.ForEndpointsAsync(db, endpointIds, ct);
        if (links.Count == 0)
        {
            return [];
        }

        var tagIds = links.Select(l => l.TagId).Distinct().ToList();
        var tags = await db.Tags.AsNoTracking().Where(t => tagIds.Contains(t.Id)).ToDictionaryAsync(t => t.Id, ct);
        return links.Where(l => tags.ContainsKey(l.TagId))
            .GroupBy(l => l.EndpointId)
            .ToDictionary(g => g.Key, g => g
                .OrderBy(l => l.Source == TagSource.Endpoint ? 0 : 1)
                .ThenBy(l => tags[l.TagId].Name, StringComparer.OrdinalIgnoreCase)
                .Select(l => ToRef(tags[l.TagId], l.Source))
                .ToList());
    }

    public static TagRefDto ToRef(Tag tag, TagSource source = TagSource.Endpoint)
    {
        ArgumentNullException.ThrowIfNull(tag);
        return new TagRefDto(tag.Id, tag.Name, tag.Color, source == TagSource.Endpoint ? null : source.ToString());
    }

    public static bool IsOutdated(string? agentVersion, Version? latest) =>
        latest is not null && Version.TryParse(agentVersion, out var v) && v < latest;

    /// <summary>The newest agent version per package format (MSI for Windows, deb and rpm for Linux, pkg for macOS): an agent is
    /// outdated only when a newer package exists for the kind of agent it is.</summary>
    public sealed class LatestAgentVersions(IReadOnlyDictionary<string, Version> byFormat)
    {
        public static LatestAgentVersions From(AgentPackageService packages)
        {
            ArgumentNullException.ThrowIfNull(packages);
            var map = new Dictionary<string, Version>(StringComparer.Ordinal);
            foreach (var format in AgentRelease.PackageFormats)
            {
                if (ParseVersion(packages.GetLatestVersion(format)) is { } version)
                {
                    map[format] = version;
                }
            }

            return new LatestAgentVersions(map);
        }

        public bool Any => byFormat.Count > 0;

        public Version? For(string? packageFormat) => byFormat.GetValueOrDefault(packageFormat ?? AgentRelease.FormatMsi);

        public bool IsOutdated(string? agentVersion, string? packageFormat) => Mapping.IsOutdated(agentVersion, For(packageFormat));
    }

    public static Version? ParseVersion(string? value) => Version.TryParse(value, out var v) ? v : null;

    /// <summary>The Linux package behind a catalog update (null for Windows updates).</summary>
    public static PackageInfoDto? Package(Update update, string? installedVersion)
    {
        ArgumentNullException.ThrowIfNull(update);
        return update.PackageName is null
            ? null
            : new PackageInfoDto(update.PackageName, update.PackageArchitecture, update.PackageVersion, installedVersion, update.PackageRepository,
                update.Advisories);
    }
}
