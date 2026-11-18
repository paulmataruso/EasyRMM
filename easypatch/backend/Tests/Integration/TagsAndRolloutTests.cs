using System.Globalization;
using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Maintenance;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Endpoint tags, tag policies and rollout delays (deferral, expiry and scheduled installs).</summary>
public sealed class TagsAndRolloutTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private AdminSession root = null!;
    private OrganizationDto org = null!;
    private SiteDto site = null!;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = await SuperAdminAsync();
        (org, site) = await CreateOrgAsync(root);
    }

    private static PolicyRequest Delays(int? delay, int? securityDelay, bool? autoInstall = null, IReadOnlyList<int>? days = null, string? start = null,
        int? duration = null) =>
        new(null, null, null, null, null, null, null, null, autoInstall, days, start, duration, null, null,
            InstallDelayDays: delay, SecurityInstallDelayDays: securityDelay);

    private static ReportedUpdate NonSecurityUpdate(string kb) => new()
    {
        UpdateGuid = Guid.NewGuid(),
        RevisionNumber = 1,
        Title = $"2026-11 Update for Windows 11 ({kb})",
        KbNumbers = [kb.Replace("KB", string.Empty, StringComparison.Ordinal)],
        Categories = [new UpdateCategoryRef { Id = MicrosoftClassifications.Updates, Name = "Updates", Type = "UpdateClassification" }],
        MaxDownloadSize = 1024,
    };

    private async Task ReportScanAsync(SignedAgent agent, IReadOnlyList<ReportedUpdate> missing)
    {
        var now = Clock.GetUtcNow();
        using var response = await agent.PostAsync(AgentRoutes.ScanResults, new ScanResultReport
        {
            ScanId = Guid.NewGuid(),
            Trigger = ScanTrigger.Scheduled,
            StartedAt = now.AddMinutes(-1),
            CompletedAt = now,
            Succeeded = true,
            Source = new UpdateSourceInfo { Type = UpdateSourceType.WindowsUpdate },
            Missing = missing,
            Installed = [],
        });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
    }

    private Task<TagDto> CreateTagAsync(string name, int priority = 0) =>
        root.SendAsync<TagDto>(HttpMethod.Post, "/api/v1/tags", new TagRequest(name, "blue", null, priority), HttpStatusCode.OK);

    [Fact]
    public async Task Tags_are_managed_by_super_admins_and_assigned_by_unrestricted_admins()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-TAGS");
        var other = await EnrollAgentAsync(root, org.Id, site.Id, "PC-UNTAGGED");
        var pilot = await CreateTagAsync("Pilot");
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/tags", new TagRequest("pilot", "blue", null, 0), HttpStatusCode.Conflict, "tag_exists");
        await root.ExpectAsync(HttpMethod.Post, "/api/v1/tags", new TagRequest("x", "orange", null, 0), HttpStatusCode.BadRequest);

        var admin = await CreateAndLoginAsync("admin", UserRole.Admin);
        await admin.ExpectAsync(HttpMethod.Post, "/api/v1/tags", new TagRequest("Servers", "red", null, 0), HttpStatusCode.Forbidden);
        await admin.ExpectAsync(HttpMethod.Put, $"/api/v1/tags/{pilot.Id}/policy", Delays(1, 1), HttpStatusCode.Forbidden);
        await admin.ExpectAsync(HttpMethod.Put, $"/api/v1/endpoints/{agent.EndpointId}/tags", new EndpointTagsRequest([pilot.Id]), HttpStatusCode.NoContent);

        var list = await root.GetAsync<PagedResult<EndpointSummaryDto>>($"/api/v1/endpoints?tagId={pilot.Id}");
        var tagged = Assert.Single(list.Items);
        Assert.Equal(agent.EndpointId, tagged.Id);
        Assert.Equal("Pilot", Assert.Single(tagged.Tags!).Name);
        Assert.Equal(1, Assert.Single(await root.GetAsync<List<TagDto>>("/api/v1/tags")).EndpointCount);

        // Organization-restricted admins can see the tags on their endpoints but not change them.
        var otherOrg = await CreateOrgAsync(root, "Fabrikam");
        var restricted = await CreateAndLoginAsync("restricted", UserRole.Admin, otherOrg.Org.Id);
        Assert.Empty(await restricted.GetAsync<List<TagDto>>("/api/v1/tags"));
        await restricted.ExpectAsync(HttpMethod.Put, $"/api/v1/endpoints/{agent.EndpointId}/tags", new EndpointTagsRequest([]), HttpStatusCode.Forbidden);
        var scoped = await CreateAndLoginAsync("scoped", UserRole.Admin, org.Id);
        Assert.Equal("Pilot", Assert.Single(await scoped.GetAsync<List<TagDto>>("/api/v1/tags")).Name);

        var bulk = await root.SendAsync<BulkEndpointTagsResult>(HttpMethod.Post, "/api/v1/endpoints/tags/bulk",
            new BulkEndpointTagsRequest([agent.EndpointId, other.EndpointId], [pilot.Id], null), HttpStatusCode.OK);
        Assert.Equal(1, bulk.Changed); // the first endpoint already had the tag
        bulk = await root.SendAsync<BulkEndpointTagsResult>(HttpMethod.Post, "/api/v1/endpoints/tags/bulk",
            new BulkEndpointTagsRequest([agent.EndpointId, other.EndpointId], null, [pilot.Id]), HttpStatusCode.OK);
        Assert.Equal(2, bulk.Changed);

        await root.ExpectAsync(HttpMethod.Delete, $"/api/v1/tags/{pilot.Id}", null, HttpStatusCode.NoContent);
        Assert.Empty(await root.GetAsync<List<TagDto>>("/api/v1/tags"));
        Assert.Contains(await WithDbAsync(db => db.AuditLogs.Select(a => a.Action).ToListAsync()), a => a == "endpoint.tags_bulk_update");
    }

    [Fact]
    public async Task A_pilot_tag_on_a_site_or_organization_applies_to_every_endpoint_in_it()
    {
        var pilotSite = await root.SendAsync<SiteDto>(HttpMethod.Post, $"/api/v1/organizations/{org.Id}/sites", new SiteRequest("Pilot office", null, null, null),
            HttpStatusCode.Created);
        var early = await EnrollAgentAsync(root, org.Id, pilotSite.Id, "PC-EARLY");
        var late = await EnrollAgentAsync(root, org.Id, site.Id, "PC-LATE");
        var (otherOrg, otherSite) = await CreateOrgAsync(root, "Fabrikam");
        var elsewhere = await EnrollAgentAsync(root, otherOrg.Id, otherSite.Id, "PC-ELSEWHERE");

        // Everyone waits a week, except the pilot ring.
        await root.SendAsync<PolicyDto>(HttpMethod.Put, "/api/v1/policies/global", Delays(7, 7), HttpStatusCode.OK);
        var pilot = await CreateTagAsync("Pilot", priority: 10);
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/tags/{pilot.Id}/policy", Delays(0, 0), HttpStatusCode.OK);
        ReportedUpdate[] missing = [JobQueueTests.SecurityUpdate("KB5046617")];
        foreach (var agent in new[] { early, late, elsewhere })
        {
            await ReportScanAsync(agent, missing);
        }

        async Task<EndpointSummaryDto> SummaryAsync(SignedAgent agent) => (await root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}")).Summary;
        Assert.Equal(1, (await SummaryAsync(early)).MissingDeferredCount);

        // Tagging the site puts its endpoints in the pilot ring at once.
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/sites/{pilotSite.Id}/tags", new TagAssignmentRequest([pilot.Id]), HttpStatusCode.NoContent);
        var summary = await SummaryAsync(early);
        Assert.Equal(1, summary.MissingRequiredCount);
        Assert.Equal(0, summary.MissingDeferredCount);
        var inherited = Assert.Single(summary.Tags!);
        Assert.Equal(("Pilot", "Site"), (inherited.Name, inherited.InheritedFrom));
        Assert.Equal(1, (await SummaryAsync(late)).MissingDeferredCount);
        var layer = Assert.Single(await root.GetAsync<List<TagPolicyLayerDto>>($"/api/v1/endpoints/{early.EndpointId}/tag-policies"));
        Assert.Equal("Pilot", layer.Tag.Name);
        Assert.Equal("Pilot", (await root.GetAsync<EffectivePolicyDto>($"/api/v1/endpoints/{early.EndpointId}/effective-policy")).SourceTags!["InstallDelayDays"]);
        Assert.Equal([early.EndpointId], (await root.GetAsync<PagedResult<EndpointSummaryDto>>($"/api/v1/endpoints?tagId={pilot.Id}")).Items.Select(e => e.Id));
        var listed = Assert.Single(await root.GetAsync<List<TagDto>>("/api/v1/tags"));
        Assert.Equal((1, 1, 0), (listed.EndpointCount, listed.SiteCount, listed.OrganizationCount));
        Assert.Equal("Pilot", Assert.Single((await root.GetAsync<SiteDto>($"/api/v1/sites/{pilotSite.Id}")).Tags!).Name);

        // Tagging the organization covers all of its sites; an endpoint's own tag is listed once, as its own.
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/tags", new TagAssignmentRequest([pilot.Id]), HttpStatusCode.NoContent);
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/endpoints/{early.EndpointId}/tags", new EndpointTagsRequest([pilot.Id]), HttpStatusCode.NoContent);
        Assert.Equal(1, (await SummaryAsync(late)).MissingRequiredCount);
        Assert.Equal("Organization", Assert.Single((await SummaryAsync(late)).Tags!).InheritedFrom);
        Assert.Null(Assert.Single((await SummaryAsync(early)).Tags!).InheritedFrom);
        Assert.Equal(1, (await SummaryAsync(elsewhere)).MissingDeferredCount);
        Assert.Equal(2, (await root.GetAsync<PagedResult<EndpointSummaryDto>>($"/api/v1/endpoints?tagId={pilot.Id}")).TotalCount);
        Assert.Equal("Pilot", Assert.Single((await root.GetAsync<OrganizationDto>($"/api/v1/organizations/{org.Id}")).Tags!).Name);

        // Only administrators without organization restrictions assign tags; restricted ones see the tags of their organization.
        var restricted = await CreateAndLoginAsync("restricted", UserRole.Admin, org.Id);
        await restricted.ExpectAsync(HttpMethod.Put, $"/api/v1/sites/{pilotSite.Id}/tags", new TagAssignmentRequest([]), HttpStatusCode.Forbidden);
        await restricted.ExpectAsync(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/tags", new TagAssignmentRequest([]), HttpStatusCode.Forbidden);
        Assert.Equal("Pilot", Assert.Single(await restricted.GetAsync<List<TagDto>>("/api/v1/tags")).Name);
        var outsider = await CreateAndLoginAsync("outsider", UserRole.Admin, otherOrg.Id);
        Assert.Empty(await outsider.GetAsync<List<TagDto>>("/api/v1/tags"));

        // Untagging puts the endpoints back on the normal delay.
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/tags", new TagAssignmentRequest([]), HttpStatusCode.NoContent);
        Assert.Equal(1, (await SummaryAsync(late)).MissingDeferredCount);
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/sites/{pilotSite.Id}/tags", new TagAssignmentRequest([Guid.NewGuid()]), HttpStatusCode.NotFound);
        await root.ExpectAsync(HttpMethod.Delete, $"/api/v1/tags/{pilot.Id}", null, HttpStatusCode.NoContent);
        Assert.Equal(0, await WithDbAsync(db => db.SiteTags.CountAsync()));
        Assert.Equal(1, (await SummaryAsync(early)).MissingDeferredCount);
        var actions = await WithDbAsync(db => db.AuditLogs.Select(a => a.Action).ToListAsync());
        Assert.Contains("site.tags_update", actions);
        Assert.Contains("organization.tags_update", actions);
    }

    [Fact]
    public async Task Tag_rollout_delay_defers_updates_until_the_delay_ends()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-RING2");
        var ring = await CreateTagAsync("Ring 2", priority: 5);
        var url = $"/api/v1/endpoints/{agent.EndpointId}";
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/tags/{ring.Id}/policy", Delays(7, 3), HttpStatusCode.OK);
        await root.ExpectAsync(HttpMethod.Put, url + "/tags", new EndpointTagsRequest([ring.Id]), HttpStatusCode.NoContent);
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/tags/{ring.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, MaxConcurrentInstallsPerSite: 3),
            HttpStatusCode.BadRequest); // a site-wide setting cannot be set on a tag

        var layer = Assert.Single(await root.GetAsync<List<TagPolicyLayerDto>>(url + "/tag-policies"));
        Assert.Equal("Ring 2", layer.Tag.Name);
        Assert.Equal(7, layer.Policy.InstallDelayDays);

        var effective = await root.GetAsync<EffectivePolicyDto>(url + "/effective-policy");
        Assert.Equal(7, effective.InstallDelayDays);
        Assert.Equal(PolicyScope.Tag, effective.Sources["InstallDelayDays"]);
        Assert.Equal("Ring 2", effective.SourceTags!["InstallDelayDays"]);

        ReportedUpdate[] missing = [JobQueueTests.SecurityUpdate("KB5046617"), NonSecurityUpdate("KB5046700")];
        await ReportScanAsync(agent, missing);
        var detail = await root.GetAsync<EndpointDetailDto>(url);
        Assert.Equal(0, detail.Summary.MissingRequiredCount);
        Assert.Equal(2, detail.Summary.MissingDeferredCount);
        Assert.Equal(ComplianceStatus.Compliant, detail.Summary.ComplianceStatus);

        // A later scan does not restart the delay.
        Clock.Advance(TimeSpan.FromDays(2));
        await ReportScanAsync(agent, missing);
        var updates = await WithDbAsync(db => db.EndpointUpdates.AsNoTracking().Where(u => u.EndpointId == agent.EndpointId).ToListAsync());
        Assert.All(updates, u => Assert.True(u.DeferredUntil <= Clock.GetUtcNow().AddDays(5)));

        Clock.Advance(TimeSpan.FromDays(1).Add(TimeSpan.FromMinutes(1)));
        await RunMaintenanceAsync<DeferralExpiryTask>();
        root = await LoginAsync("root", DefaultPassword, root.MfaSecret); // the session expired while time moved on
        detail = await root.GetAsync<EndpointDetailDto>(url);
        Assert.Equal(1, detail.Summary.MissingRequiredCount); // the security update's 3-day delay ended
        Assert.Equal(1, detail.Summary.MissingDeferredCount);
        Assert.Equal(ComplianceStatus.MissingUpdates, detail.Summary.ComplianceStatus);

        // Removing the tag removes its delay.
        await root.ExpectAsync(HttpMethod.Put, url + "/tags", new EndpointTagsRequest([]), HttpStatusCode.NoContent);
        detail = await root.GetAsync<EndpointDetailDto>(url);
        Assert.Equal(2, detail.Summary.MissingRequiredCount);
        Assert.Equal(0, detail.Summary.MissingDeferredCount);
    }

    [Fact]
    public async Task Scheduled_installs_only_include_updates_whose_delay_has_ended()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-SCHED");
        var start = Clock.GetUtcNow().AddMinutes(-10).ToString("HH:mm", CultureInfo.InvariantCulture);
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/policy",
            Delays(14, 0, autoInstall: true, days: [0, 1, 2, 3, 4, 5, 6], start: start, duration: 120), HttpStatusCode.OK);
        var security = JobQueueTests.SecurityUpdate("KB5046617");
        await ReportScanAsync(agent, [security, NonSecurityUpdate("KB5046700")]);

        await RunMaintenanceAsync<ScheduledInstallTask>();
        var delivered = Assert.Single((await agent.CheckInAsync()).Jobs);
        Assert.Equal(InstallMode.Selected, delivered.Install!.Mode);
        Assert.Equal([security.UpdateGuid], delivered.Install.SelectedUpdateGuids);
    }

    [Fact]
    public async Task Policy_changes_are_saved_to_endpoint_compliance()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-RECOMPUTE");
        await ReportScanAsync(agent, [NonSecurityUpdate("KB5046700")]);
        var url = $"/api/v1/endpoints/{agent.EndpointId}";
        Assert.Equal(1, (await root.GetAsync<EndpointDetailDto>(url)).Summary.MissingRequiredCount);

        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/policy", Delays(30, null), HttpStatusCode.OK);
        var summary = (await root.GetAsync<EndpointDetailDto>(url)).Summary;
        Assert.Equal(0, summary.MissingRequiredCount);
        Assert.Equal(1, summary.MissingDeferredCount);

        var row = await WithDbAsync(db => db.EndpointUpdates.AsNoTracking().SingleAsync(u => u.EndpointId == agent.EndpointId));
        Assert.Equal(row.FirstDetectedAt.AddDays(30), row.DeferredUntil);
        var dto = Assert.Single(await root.GetAsync<List<EndpointUpdateDto>>(url + "/updates")).DeferredUntil;
        Assert.NotNull(dto);
    }
}
