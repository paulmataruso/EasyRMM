using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Third-party application updates (winget): policy, agent configuration, scan ingestion and install jobs.</summary>
public sealed class ApplicationUpdateTests(PostgresFixture postgres) : IntegrationTest(postgres)
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

    private static PolicyRequest Apps(bool enabled, params string[] approved) =>
        new(null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            ApplicationUpdates: new ApplicationUpdateSettings { Enabled = enabled, ApprovedApps = approved });

    private static ReportedUpdate App(string id, string version, string installedVersion, bool installed = false) => new()
    {
        UpdateGuid = ApplicationIds.UpdateGuidFor(id, version),
        Title = $"{id} {version}",
        IsInstalled = installed,
        IsDownloaded = true,
        Application = new ApplicationUpdateInfo { Id = id, Version = version, InstalledVersion = installedVersion },
    };

    private static CheckInRequest CapableCheckIn() => new()
    {
        AgentVersion = "1.4.0",
        ActiveJobIds = [],
        Capabilities = AgentCapabilities.All,
    };

    private async Task ReportScanAsync(SignedAgent agent, IReadOnlyList<ReportedUpdate> missing, IReadOnlyList<ReportedUpdate> installed,
        ApplicationScanReport? applications)
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
            Installed = installed,
            Applications = applications,
        });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
    }

    private static ApplicationScanReport Checked(int count) => new() { Succeeded = true, WingetVersion = "1.9.25200", Checked = count };

    [Fact]
    public async Task Policy_validates_and_normalizes_the_approved_applications()
    {
        var url = $"/api/v1/organizations/{org.Id}/policy";
        await root.ExpectAsync(HttpMethod.Put, url, Apps(true, "Mozilla.Firefox", "Firefox; calc"), HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Put, url, Apps(true, "Mozilla.Firefox --force"), HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Put, url, Apps(true, [.. Enumerable.Range(0, 101).Select(i => $"Vendor.App{i}")]), HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Put, url,
            new PolicyRequest(null, null, null, null, ["Security", "Application"], null, null, null, null, null, null, null, null, null),
            HttpStatusCode.BadRequest); // application updates are approved per application, never by category

        var saved = await root.SendAsync<PolicyDto>(HttpMethod.Put, url, Apps(true, " Mozilla.Firefox ", "mozilla.firefox", "7zip.7zip"), HttpStatusCode.OK);
        Assert.Equal(["Mozilla.Firefox", "7zip.7zip"], saved.ApplicationUpdates!.ApprovedApps);

        // A site can switch the inherited setting off as a unit.
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/sites/{site.Id}/policy", Apps(false), HttpStatusCode.OK);
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-SITE-OFF");
        var effective = await root.GetAsync<EffectivePolicyDto>($"/api/v1/endpoints/{agent.EndpointId}/effective-policy");
        Assert.False(effective.ApplicationUpdates!.Enabled);
        Assert.Null((await agent.CheckInAsync(CapableCheckIn())).Config.Applications);
    }

    [Fact]
    public async Task Approved_application_updates_are_required_installed_through_jobs_and_confirmed_by_the_next_scan()
    {
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/policy", Apps(true, "Mozilla.Firefox", "7zip.7zip"),
            HttpStatusCode.OK);
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-APPS");
        var config = (await agent.CheckInAsync(CapableCheckIn())).Config.Applications;
        Assert.True(config!.Enabled);
        Assert.Equal(["Mozilla.Firefox", "7zip.7zip"], config.ApprovedApps);

        var firefox = App("Mozilla.Firefox", "133.0", "132.0.1");
        var vlc = App("VideoLAN.VLC", "3.0.21", "3.0.20"); // reported although not approved (e.g. an old configuration)
        var forged = App("Mozilla.Firefox", "134.0", "132.0.1") with { UpdateGuid = Guid.NewGuid() };
        var badVersion = App("Mozilla.Firefox", "135.0", "132.0.1") with { Application = firefox.Application! with { Version = "135.0 --force" } };
        await ReportScanAsync(agent, [firefox, vlc, forged, badVersion, JobQueueTests.SecurityUpdate("KB5046617")],
            [App("Mozilla.Firefox", "132.0.1", "132.0.1", installed: true), App("7zip.7zip", "24.08", "24.08", installed: true)], Checked(2));

        var url = $"/api/v1/endpoints/{agent.EndpointId}";
        var apps = await root.GetAsync<List<EndpointUpdateDto>>(url + "/updates?category=Application");
        Assert.Equal(2, apps.Count); // the forged GUID and the invalid version were dropped
        var row = apps.Single(a => a.UpdateGuid == firefox.UpdateGuid);
        Assert.True(row.IsRequired);
        Assert.Equal(("Mozilla.Firefox", "133.0", "132.0.1", "winget"), (row.Package!.Name, row.Package.Version, row.Package.InstalledVersion, row.Package.Repository));
        Assert.False(apps.Single(a => a.UpdateGuid == vlc.UpdateGuid).IsRequired);

        var status = (await root.GetAsync<EndpointDetailDto>(url)).Applications!;
        Assert.Equal((true, true, 2, "1.9.25200", (string?)null), (status.Enabled, status.Supported, status.ApprovedApps, status.WingetVersion, status.LastError));
        Assert.NotNull(status.LastCheckAt);

        // The install job carries the approved list: the agent installs application updates only when they are on it.
        var job = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, url + "/install-updates",
            new InstallUpdatesRequest(InstallMode.Selected, [firefox.UpdateGuid], false), HttpStatusCode.Accepted);
        var delivered = Assert.Single((await agent.CheckInAsync(CapableCheckIn() with { ActiveJobIds = [] })).Jobs);
        Assert.Equal(job.Id, delivered.JobId);
        Assert.Equal(["Mozilla.Firefox", "7zip.7zip"], delivered.Install!.Filter.ApprovedApplications);
        Assert.DoesNotContain(UpdateCategory.Application, delivered.Install.Filter.Categories);
        await root.ExpectAsync(HttpMethod.Post, url + "/install-updates", new InstallUpdatesRequest(InstallMode.Selected, [vlc.UpdateGuid], true),
            HttpStatusCode.Conflict, "nothing_to_install");

        // The next scan lists 133.0 as installed: the update row becomes Installed (same GUID).
        Clock.Advance(TimeSpan.FromMinutes(30));
        await ReportScanAsync(agent, [], [App("Mozilla.Firefox", "133.0", "133.0", installed: true), App("7zip.7zip", "24.08", "24.08", installed: true)],
            Checked(2));
        Assert.Equal(EndpointUpdateState.Installed, await WithDbAsync(db =>
            db.EndpointUpdates.Where(u => u.EndpointId == agent.EndpointId && u.UpdateGuid == firefox.UpdateGuid).Select(u => u.State).FirstAsync()));
    }

    [Fact]
    public async Task A_failed_application_check_keeps_the_application_rows_and_switching_off_retires_them()
    {
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/policy", Apps(true, "Mozilla.Firefox"), HttpStatusCode.OK);
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-WINGET-FAIL");
        await agent.CheckInAsync(CapableCheckIn());
        var firefox = App("Mozilla.Firefox", "133.0", "132.0.1");
        await ReportScanAsync(agent, [firefox], [], Checked(1));

        Clock.Advance(TimeSpan.FromHours(4));
        var failed = new ApplicationScanReport { Succeeded = false, ErrorCode = "winget_list_failed", ErrorMessage = "Mozilla.Firefox: winget exited with 0x8A15000F." };
        await ReportScanAsync(agent, [], [], failed);
        await ReportScanAsync(agent, [], [], failed); // the same error is recorded once
        Task<EndpointUpdateState> StateAsync() => WithDbAsync(db =>
            db.EndpointUpdates.Where(u => u.EndpointId == agent.EndpointId && u.UpdateGuid == firefox.UpdateGuid).Select(u => u.State).FirstAsync());
        Assert.Equal(EndpointUpdateState.Missing, await StateAsync());
        root = await LoginAsync("root", DefaultPassword, root.MfaSecret);
        var status = (await root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}")).Applications!;
        Assert.Contains("0x8A15000F", status.LastError, StringComparison.Ordinal);
        Assert.Equal(1, await WithDbAsync(db => db.EndpointEvents.CountAsync(e => e.EndpointId == agent.EndpointId && e.Type == "ApplicationScanFailed")));

        // Switched off: the agent stops checking applications and their rows stop counting.
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/policy", Apps(false, "Mozilla.Firefox"), HttpStatusCode.OK);
        Assert.Null((await agent.CheckInAsync(CapableCheckIn())).Config.Applications);
        await ReportScanAsync(agent, [], [], applications: null);
        Assert.Equal(EndpointUpdateState.NotApplicable, await StateAsync());
        status = (await root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}")).Applications!;
        Assert.Equal((false, (string?)null), (status.Enabled, status.LastError));
    }
}
