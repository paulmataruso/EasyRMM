using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Maintenance;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Update holds: the rollout guard holds an update that failed on too many endpoints, and administrators hold and
/// release updates. Held updates are left out of automatic and "install all" installations, but can still be selected.</summary>
public sealed class RolloutGuardTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private AdminSession root = null!;
    private OrganizationDto org = null!;
    private SiteDto site = null!;
    private readonly ReportedUpdate bad = JobQueueTests.SecurityUpdate("KB5050001");
    private readonly ReportedUpdate good = JobQueueTests.SecurityUpdate("KB5050002");

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = await SuperAdminAsync();
        (org, site) = await CreateOrgAsync(root);
    }

    private async Task<SignedAgent> EndpointMissingBothAsync(Guid orgId, Guid? siteId, string hostname)
    {
        var agent = await EnrollAgentAsync(root, orgId, siteId, hostname);
        var now = Clock.GetUtcNow();
        using var response = await agent.PostAsync(AgentRoutes.ScanResults, new ScanResultReport
        {
            ScanId = Guid.NewGuid(),
            Trigger = ScanTrigger.Scheduled,
            StartedAt = now.AddMinutes(-1),
            CompletedAt = now,
            Succeeded = true,
            Source = new UpdateSourceInfo { Type = UpdateSourceType.WindowsUpdate },
            Missing = [bad, good],
            Installed = [],
        });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
        return agent;
    }

    private Task<JobSummaryDto> InstallAsync(SignedAgent agent, InstallMode mode, params Guid[] guids) =>
        root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/install-updates",
            new InstallUpdatesRequest(mode, guids.Length == 0 ? null : guids, false), HttpStatusCode.Accepted);

    private static async Task ReportAsync(SignedAgent agent, Guid jobId, JobStatus status, IReadOnlyList<JobItemReport> items)
    {
        using (var ack = await agent.PostAsync($"api/v1/agents/jobs/{jobId}/ack", new { }))
        {
            await AdminSession.EnsureAsync(ack, HttpStatusCode.OK);
        }

        using var response = await agent.PostAsync($"api/v1/agents/jobs/{jobId}/status", new JobStatusReport
        {
            Sequence = 1,
            Status = status,
            Phase = status.ToString(),
            Items = items,
        });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
    }

    private JobItemReport Item(ReportedUpdate update, JobItemStatus status, string? skipReason = null) => new()
    {
        UpdateGuid = update.UpdateGuid,
        RevisionNumber = update.RevisionNumber,
        Title = update.Title,
        KbNumber = "KB" + update.KbNumbers[0],
        Category = UpdateCategory.Security,
        Status = status,
        SkipReason = skipReason,
        ErrorCode = status == JobItemStatus.Failed ? "0x80070002" : null,
    };

    /// <summary>Installs the bad update on the endpoint; the agent reports the given outcome.</summary>
    private async Task InstallBadAsync(SignedAgent agent, JobItemStatus outcome)
    {
        var job = await InstallAsync(agent, InstallMode.Selected, bad.UpdateGuid);
        Assert.Equal(job.Id, Assert.Single((await agent.CheckInAsync()).Jobs).JobId);
        await ReportAsync(agent, job.Id, JobStatus.Completed, [Item(bad, outcome)]);
    }

    private Task<List<UpdateHoldDto>> HoldsAsync(AdminSession session, string query = "") => session.GetAsync<List<UpdateHoldDto>>("/api/v1/update-holds" + query);

    [Fact]
    public async Task An_update_that_fails_on_too_many_endpoints_is_held_for_every_organization_until_released()
    {
        var agents = new List<SignedAgent>();
        for (var i = 1; i <= 5; i++)
        {
            agents.Add(await EndpointMissingBothAsync(org.Id, site.Id, $"PC-{i}"));
        }

        var (other, _) = await CreateOrgAsync(root, "Fabrikam");
        var elsewhere = await EndpointMissingBothAsync(other.Id, null, "FAB-1");

        // Two failures are not enough (at least 3 endpoints by default).
        await InstallBadAsync(agents[0], JobItemStatus.Failed);
        await InstallBadAsync(agents[1], JobItemStatus.Failed);
        await RunMaintenanceAsync<RolloutGuardTask>();
        Assert.Empty(await HoldsAsync(root));

        await InstallBadAsync(agents[2], JobItemStatus.Failed);
        await InstallBadAsync(agents[3], JobItemStatus.Succeeded);
        await RunMaintenanceAsync<RolloutGuardTask>();
        await RunMaintenanceAsync<RolloutGuardTask>(); // one hold, not one per run
        var hold = Assert.Single(await HoldsAsync(root));
        Assert.Equal((bad.UpdateGuid, (Guid?)null, UpdateHoldSource.Automatic, "Rollout guard", 3, 4, true),
            (hold.UpdateGuid, hold.OrganizationId, hold.Source, hold.CreatedBy, hold.FailedEndpoints, hold.AttemptedEndpoints, hold.CanRelease));
        Assert.Equal("Installation failed on 3 of 4 endpoints (75%) in the last 7 days.", hold.Reason);

        // "Install all" leaves it out, in every organization; selecting it installs it with a warning.
        foreach (var agent in new[] { agents[4], elsewhere })
        {
            var all = await root.GetAsync<InstallPreview>($"/api/v1/endpoints/{agent.EndpointId}/install-preview?mode=all");
            Assert.Equal([good.UpdateGuid], all.Items.Select(i => i.UpdateGuid));
            Assert.Equal(SkipReasons.Held, Assert.Single(all.Skipped, s => s.UpdateGuid == bad.UpdateGuid).Reason);
            Assert.Contains(bad.UpdateGuid, all.Filter.ExcludedUpdateGuids);
        }

        var selected = await root.GetAsync<InstallPreview>($"/api/v1/endpoints/{agents[4].EndpointId}/install-preview?mode=selected&updateGuids={bad.UpdateGuid}");
        Assert.Equal([bad.UpdateGuid], selected.Items.Select(i => i.UpdateGuid));
        Assert.DoesNotContain(bad.UpdateGuid, selected.Filter.ExcludedUpdateGuids);
        Assert.Contains(selected.Warnings, w => w.StartsWith("1 of these update(s) are on hold (Installation failed on 3 of 4", StringComparison.Ordinal));

        // Shown on the endpoint, in the fleet list and on the update's page.
        var rows = await root.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{agents[4].EndpointId}/updates");
        Assert.Equal(hold.Reason, rows.Single(r => r.UpdateGuid == bad.UpdateGuid).HoldReason);
        Assert.Null(rows.Single(r => r.UpdateGuid == good.UpdateGuid).HoldReason);
        var fleet = await root.GetAsync<PagedResult<FleetUpdateDto>>("/api/v1/updates");
        Assert.True(fleet.Items.Single(u => u.UpdateGuid == bad.UpdateGuid).OnHold);
        Assert.False(fleet.Items.Single(u => u.UpdateGuid == good.UpdateGuid).OnHold);
        var detail = await root.GetAsync<FleetUpdateDetailDto>($"/api/v1/updates/{bad.UpdateGuid}");
        Assert.Equal(hold.Id, Assert.Single(detail.Holds!).Id);

        // One alert per organization that still needs it.
        await RunMaintenanceAsync<AlertEvaluationTask>();
        var alerts = (await root.GetAsync<PagedResult<AlertDto>>("/api/v1/alerts?ruleType=UpdateHeld")).Items;
        Assert.Equal(new[] { org.Id, other.Id }.Order(), alerts.Select(a => a.OrganizationId).Order());
        Assert.All(alerts, a => Assert.Null(a.EndpointId));
        Assert.Equal($"{org.Name}: {bad.Title} is on hold", alerts.Single(a => a.OrganizationId == org.Id).Title);

        // An organization administrator cannot release a hold for every organization.
        var admin = await CreateAndLoginAsync("admin", UserRole.Admin, org.Id);
        Assert.False(Assert.Single(await HoldsAsync(admin)).CanRelease);
        await admin.ExpectAsync(HttpMethod.Post, $"/api/v1/update-holds/{hold.Id}/release", null, HttpStatusCode.Forbidden, "forbidden");

        var released = await root.SendAsync<UpdateHoldDto>(HttpMethod.Post, $"/api/v1/update-holds/{hold.Id}/release", null, HttpStatusCode.OK);
        Assert.NotNull(released.ReleasedAt);
        Assert.Empty(await HoldsAsync(root));
        Assert.Single(await HoldsAsync(root, "?active=false"));

        // Failures from before the release do not hold it again.
        await RunMaintenanceAsync<RolloutGuardTask>();
        Assert.Empty(await HoldsAsync(root));
        var actions = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.TargetId == bad.UpdateGuid.ToString()).Select(a => a.Action).ToListAsync());
        Assert.Equal(["update.hold", "update.hold_released"], actions.Order());
    }

    [Fact]
    public async Task Queued_automatic_jobs_leave_out_updates_held_after_they_were_queued_but_hand_picked_updates_stay()
    {
        var all = await EndpointMissingBothAsync(org.Id, site.Id, "PC-ALL");
        var picked = await EndpointMissingBothAsync(org.Id, site.Id, "PC-PICKED");
        var scheduled = await EndpointMissingBothAsync(org.Id, site.Id, "PC-SCHEDULED");
        var installAll = await InstallAsync(all, InstallMode.AllEligible);
        var handPicked = await InstallAsync(picked, InstallMode.Selected, bad.UpdateGuid);
        var automatic = await InstallAsync(scheduled, InstallMode.Selected, bad.UpdateGuid);
        await WithDbAsync(db => db.Jobs.Where(j => j.Id == automatic.Id).ExecuteUpdateAsync(x => x.SetProperty(j => j.Trigger, JobTrigger.Scheduled)));

        await root.SendAsync<UpdateHoldDto>(HttpMethod.Post, $"/api/v1/updates/{bad.UpdateGuid}/holds",
            new CreateUpdateHoldRequest(null, "Breaks printing"), HttpStatusCode.Created);

        // "Install all": the held update is excluded and its planned item skipped.
        var delivered = Assert.Single((await all.CheckInAsync()).Jobs);
        Assert.Contains(bad.UpdateGuid, delivered.Install!.Filter.ExcludedUpdateGuids);
        var items = (await root.GetAsync<JobDetailDto>($"/api/v1/jobs/{installAll.Id}")).Items;
        Assert.Equal((JobItemStatus.Skipped, SkipReasons.Held), (items.Single(i => i.UpdateGuid == bad.UpdateGuid).Status, items.Single(i => i.UpdateGuid == bad.UpdateGuid).SkipReason));
        Assert.Equal(JobItemStatus.Pending, items.Single(i => i.UpdateGuid == good.UpdateGuid).Status);

        // The agent reports it as excluded by the job's filter: shown as held.
        await ReportAsync(all, installAll.Id, JobStatus.Completed, [Item(good, JobItemStatus.Succeeded), Item(bad, JobItemStatus.Skipped, SkipReasons.Excluded)]);
        items = (await root.GetAsync<JobDetailDto>($"/api/v1/jobs/{installAll.Id}")).Items;
        Assert.Equal(SkipReasons.Held, items.Single(i => i.UpdateGuid == bad.UpdateGuid).SkipReason);

        // An automatic job with only held updates is cancelled instead of delivered.
        Assert.Empty((await scheduled.CheckInAsync()).Jobs);
        var cancelled = await root.GetAsync<JobDetailDto>($"/api/v1/jobs/{automatic.Id}");
        Assert.Equal(JobStatus.Cancelled, cancelled.Summary.Status);
        Assert.Equal(SkipReasons.Held, Assert.Single(cancelled.Items).SkipReason);

        // Updates an administrator selected by hand are installed as selected.
        var kept = Assert.Single((await picked.CheckInAsync()).Jobs);
        Assert.Equal(handPicked.Id, kept.JobId);
        Assert.Equal([bad.UpdateGuid], kept.Install!.SelectedUpdateGuids);
    }

    [Fact]
    public async Task Organization_administrators_hold_updates_for_their_organization_only()
    {
        var (other, _) = await CreateOrgAsync(root, "Fabrikam");
        var mine = await EndpointMissingBothAsync(org.Id, site.Id, "PC-MINE");
        var theirs = await EndpointMissingBothAsync(other.Id, null, "FAB-1");
        var admin = await CreateAndLoginAsync("admin", UserRole.Admin, org.Id);
        var outsider = await CreateAndLoginAsync("outsider", UserRole.Admin, other.Id);
        var viewer = await CreateAndLoginAsync("viewer", UserRole.ReadOnly, org.Id);
        var url = $"/api/v1/updates/{bad.UpdateGuid}/holds";

        await admin.ExpectAsync(HttpMethod.Post, url, new CreateUpdateHoldRequest(null, "x"), HttpStatusCode.Forbidden, "forbidden");
        await admin.ExpectAsync(HttpMethod.Post, url, new CreateUpdateHoldRequest(other.Id, "x"), HttpStatusCode.NotFound);
        await admin.ExpectAsync(HttpMethod.Post, url, new CreateUpdateHoldRequest(org.Id, " "), HttpStatusCode.BadRequest);
        await admin.ExpectAsync(HttpMethod.Post, $"/api/v1/updates/{Guid.NewGuid()}/holds", new CreateUpdateHoldRequest(org.Id, "x"), HttpStatusCode.NotFound);
        await viewer.ExpectAsync(HttpMethod.Post, url, new CreateUpdateHoldRequest(org.Id, "x"), HttpStatusCode.Forbidden);
        var hold = await admin.SendAsync<UpdateHoldDto>(HttpMethod.Post, url, new CreateUpdateHoldRequest(org.Id, "Wait for the vendor fix"), HttpStatusCode.Created);
        Assert.Equal((org.Id, org.Name, UpdateHoldSource.Manual, "admin", true), (hold.OrganizationId, hold.OrganizationName, hold.Source, hold.CreatedBy, hold.CanRelease));
        await admin.ExpectAsync(HttpMethod.Post, url, new CreateUpdateHoldRequest(org.Id, "again"), HttpStatusCode.Conflict, "already_held");

        // Held in its organization only.
        var held = await root.GetAsync<InstallPreview>($"/api/v1/endpoints/{mine.EndpointId}/install-preview?mode=all");
        Assert.Equal([good.UpdateGuid], held.Items.Select(i => i.UpdateGuid));
        var free = await root.GetAsync<InstallPreview>($"/api/v1/endpoints/{theirs.EndpointId}/install-preview?mode=all");
        Assert.Equal(new[] { bad.UpdateGuid, good.UpdateGuid }.Order(), free.Items.Select(i => i.UpdateGuid).Order());
        Assert.Empty(await HoldsAsync(outsider));
        await outsider.ExpectAsync(HttpMethod.Post, $"/api/v1/update-holds/{hold.Id}/release", null, HttpStatusCode.NotFound);
        Assert.False(Assert.Single(await HoldsAsync(viewer)).CanRelease);

        await admin.SendAsync<UpdateHoldDto>(HttpMethod.Post, $"/api/v1/update-holds/{hold.Id}/release", null, HttpStatusCode.OK);
        Assert.Empty(await HoldsAsync(admin));

        // Removing an update from the fleet can hold it for the organization, even where nothing had it installed.
        var result = await admin.SendAsync<BulkResultDto>(HttpMethod.Post, $"/api/v1/updates/{bad.UpdateGuid}/uninstall",
            new FleetUninstallRequest(org.Id, null, null, Block: true, Reason: "Bad update", Hold: true), HttpStatusCode.OK);
        Assert.Equal(0, result.Succeeded + result.Failed);
        var again = Assert.Single(await HoldsAsync(admin));
        Assert.Equal((org.Id, "Bad update"), (again.OrganizationId, again.Reason));
        await admin.ExpectAsync(HttpMethod.Post, $"/api/v1/updates/{bad.UpdateGuid}/uninstall",
            new FleetUninstallRequest(null, null, null, Hold: true), HttpStatusCode.Forbidden, "forbidden");
    }
}
