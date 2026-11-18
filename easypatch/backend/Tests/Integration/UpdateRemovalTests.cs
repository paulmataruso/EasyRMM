using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Rolling back an installed Windows update: one uninstall-update job per endpoint (agent 1.8.0 and later), optionally
/// excluding the update so EasyPatch does not install it again. The server changes nothing until a scan reports the result.</summary>
public sealed class UpdateRemovalTests(PostgresFixture postgres) : IntegrationTest(postgres)
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

    private static ReportedUpdate Cumulative() => JobQueueTests.SecurityUpdate("KB5046617") with
    {
        Title = "2024-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617) (26100.2314)",
    };

    private static Task<CheckInResponse> CheckInAsync(SignedAgent agent, string version = "1.8.0") => agent.CheckInAsync(new CheckInRequest
    {
        AgentVersion = version,
        ActiveJobIds = [],
        Capabilities = version == "1.8.0" ? [AgentCapabilities.Restart, AgentCapabilities.UninstallUpdates] : [AgentCapabilities.Restart],
    });

    private async Task ReportScanAsync(SignedAgent agent, IReadOnlyList<ReportedUpdate> missing, IReadOnlyList<ReportedUpdate> installed)
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
        });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
    }

    private static async Task ReportAsync(SignedAgent agent, Guid jobId, long sequence, JobStatus status, IReadOnlyList<JobItemReport> items,
        bool rebootRequired = false, string? message = null)
    {
        using var response = await agent.PostAsync($"api/v1/agents/jobs/{jobId}/status", new JobStatusReport
        {
            Sequence = sequence,
            Status = status,
            Phase = status.ToString(),
            Message = message,
            Items = items,
            RebootRequired = rebootRequired,
        });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
    }

    [Fact]
    public async Task An_installed_update_is_removed_by_a_job_and_excluded_so_EasyPatch_does_not_install_it_again()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-ROLLBACK");
        await CheckInAsync(agent);
        var lcu = Cumulative();
        var other = JobQueueTests.SecurityUpdate("KB5046618");
        await ReportScanAsync(agent, [other], [lcu]);
        var installedUrl = $"/api/v1/endpoints/{agent.EndpointId}/installed-updates";
        var before = Assert.Single(await root.GetAsync<List<EndpointUpdateDto>>(installedUrl));
        Assert.Equal((lcu.UpdateGuid, EndpointUpdateState.Installed), (before.UpdateGuid, before.State));

        var url = $"/api/v1/endpoints/{agent.EndpointId}/updates/{lcu.UpdateGuid}/uninstall";
        var job = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, url, new UninstallUpdateRequest(Block: true, Reason: "Breaks printing"),
            HttpStatusCode.Accepted);
        Assert.Equal(JobType.UninstallUpdate, job.Type);
        await root.ExpectAsync(HttpMethod.Post, url, new UninstallUpdateRequest(), HttpStatusCode.Conflict, "duplicate_job");

        // Excluded on this endpoint, and shown as being removed.
        var exclusion = await WithDbAsync(db => db.UpdateExclusions.AsNoTracking().SingleAsync(x => x.EndpointId == agent.EndpointId));
        Assert.Equal((lcu.UpdateGuid, "Breaks printing"), (exclusion.UpdateGuid, exclusion.Reason));
        var removing = Assert.Single(await root.GetAsync<List<EndpointUpdateDto>>(installedUrl));
        Assert.Equal((job.Id, JobType.UninstallUpdate, JobItemStatus.Pending), (removing.ActiveJob!.JobId, removing.ActiveJob.JobType, removing.ActiveJob.ItemStatus));
        Assert.True(removing.IsExcluded);

        // The agent receives exactly one update to remove.
        var delivered = Assert.Single((await CheckInAsync(agent)).Jobs);
        Assert.Equal((job.Id, JobType.UninstallUpdate, null), (delivered.JobId, delivered.Type, delivered.Install));
        Assert.Equal(new UninstallUpdatePayload { UpdateGuid = lcu.UpdateGuid, Title = lcu.Title, KbNumber = "5046617", Category = UpdateCategory.Cumulative },
            delivered.UninstallUpdate);
        using (var ack = await agent.PostAsync($"api/v1/agents/jobs/{job.Id}/ack", new { }))
        {
            await AdminSession.EnsureAsync(ack, HttpStatusCode.OK);
        }

        var item = new JobItemReport { UpdateGuid = lcu.UpdateGuid, Title = lcu.Title, KbNumber = "KB5046617", Category = UpdateCategory.Cumulative, Status = JobItemStatus.Installing };
        await ReportAsync(agent, job.Id, 1, JobStatus.Running, [item]);
        await ReportAsync(agent, job.Id, 2, JobStatus.Completed, [item with { Status = JobItemStatus.Succeeded, RebootRequired = true }], rebootRequired: true,
            message: "Removed KB5046617 with DISM. Restart the computer to finish removing it.");

        var done = await root.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}");
        Assert.Equal((JobStatus.Completed, true), (done.Summary.Status, done.Summary.RebootRequired));
        Assert.Equal((JobItemStatus.Succeeded, UpdateCategory.Cumulative), (Assert.Single(done.Items).Status, done.Items[0].Category));
        var endpoint = await root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");
        Assert.Contains("An update removed by EasyPatch requires a restart", endpoint.RebootReasons);
        Assert.DoesNotContain("Updates installed by EasyPatch require a restart", endpoint.RebootReasons);

        // A removal does not change the update's state: only a scan does. Until the restart Windows still lists it.
        var row = await WithDbAsync(db => db.EndpointUpdates.AsNoTracking().SingleAsync(u => u.EndpointId == agent.EndpointId && u.UpdateGuid == lcu.UpdateGuid));
        Assert.Equal((EndpointUpdateState.Installed, 0), (row.State, row.FailedAttempts));
        var events = await WithDbAsync(db => db.EndpointEvents.AsNoTracking().Where(e => e.JobId == job.Id).Select(e => e.Message).ToListAsync());
        Assert.Contains(events, m => m.StartsWith("Update removal completed: Removed KB5046617", StringComparison.Ordinal));

        // After the restart the scan reports it missing again; it is excluded, so installing everything leaves it alone.
        await ReportScanAsync(agent, [other, lcu], []);
        var preview = await root.GetAsync<InstallPreview>($"/api/v1/endpoints/{agent.EndpointId}/install-preview?mode=all");
        Assert.Equal([other.UpdateGuid], preview.Items.Select(i => i.UpdateGuid));
        Assert.Contains(lcu.UpdateGuid, preview.Filter.ExcludedUpdateGuids);

        var audit = await WithDbAsync(db => db.AuditLogs.AsNoTracking().Where(a => a.EndpointId == agent.EndpointId).Select(a => a.Action).ToListAsync());
        Assert.Contains("endpoint.update_removal", audit);
        Assert.Contains("endpoint.update_excluded", audit);
    }

    [Fact]
    public async Task Only_updates_a_capable_agent_reports_installed_can_be_removed()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-OLD");
        var lcu = Cumulative();
        var missing = JobQueueTests.SecurityUpdate("KB5046618");
        await ReportScanAsync(agent, [missing], [lcu]);

        // An agent older than 1.8.0 cannot remove updates.
        await CheckInAsync(agent, "1.7.1");
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/updates/{lcu.UpdateGuid}/uninstall", new UninstallUpdateRequest(),
            HttpStatusCode.Conflict, "agent_upgrade_required");

        await CheckInAsync(agent);
        foreach (var guid in new[] { missing.UpdateGuid, Guid.NewGuid() })
        {
            await root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/updates/{guid}/uninstall", new UninstallUpdateRequest(),
                HttpStatusCode.Conflict, "update_not_installed");
        }

        // Without blocking, nothing is excluded; a retry queues the same removal again.
        var job = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/updates/{lcu.UpdateGuid}/uninstall",
            new UninstallUpdateRequest(Block: false), HttpStatusCode.Accepted);
        Assert.False(await WithDbAsync(db => db.UpdateExclusions.AnyAsync()));
        await root.SendAsync<JobDetailDto>(HttpMethod.Post, $"/api/v1/jobs/{job.Id}/cancel", null, HttpStatusCode.OK);
        var retry = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/jobs/{job.Id}/retry", null, HttpStatusCode.Accepted);
        var payload = Assert.Single((await CheckInAsync(agent)).Jobs);
        Assert.Equal((retry.Id, lcu.UpdateGuid), (payload.JobId, payload.UninstallUpdate!.UpdateGuid));
    }

    [Fact]
    public async Task Removing_an_update_from_the_fleet_targets_only_endpoints_that_have_it_installed()
    {
        var lcu = Cumulative();
        var a = await EnrollAgentAsync(root, org.Id, site.Id, "PC-A");
        var b = await EnrollAgentAsync(root, org.Id, site.Id, "PC-B");
        var old = await EnrollAgentAsync(root, org.Id, site.Id, "PC-OLD");
        var without = await EnrollAgentAsync(root, org.Id, site.Id, "PC-MISSING");
        foreach (var agent in new[] { a, b })
        {
            await CheckInAsync(agent);
            await ReportScanAsync(agent, [], [lcu]);
        }

        await CheckInAsync(old, "1.7.1");
        await ReportScanAsync(old, [], [lcu]);
        await CheckInAsync(without);
        await ReportScanAsync(without, [lcu], []);

        var result = await root.SendAsync<BulkResultDto>(HttpMethod.Post, $"/api/v1/updates/{lcu.UpdateGuid}/uninstall",
            new FleetUninstallRequest(org.Id, null, null, Block: true), HttpStatusCode.OK);

        Assert.Equal((2, 1), (result.Succeeded, result.Failed));
        Assert.Equal(["PC-A", "PC-B", "PC-OLD"], result.Results.Select(r => r.Hostname));
        Assert.Equal("agent_upgrade_required", result.Results.Single(r => r.Hostname == "PC-OLD").ErrorCode);
        var excluded = await WithDbAsync(db => db.UpdateExclusions.AsNoTracking().Select(x => x.EndpointId).ToListAsync());
        Assert.Equal(new[] { a.EndpointId, b.EndpointId }.Order(), excluded.Order());
    }
}
