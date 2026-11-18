using System.Globalization;
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

/// <summary>Downloading updates ahead of the maintenance window (policy "download before the window", Windows agents 1.8.0+).</summary>
public sealed class PreDownloadTests(PostgresFixture postgres) : IntegrationTest(postgres)
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

    private static Task<CheckInResponse> CheckInAsync(SignedAgent agent, bool capable) => agent.CheckInAsync(new CheckInRequest
    {
        AgentVersion = capable ? "1.8.0" : "1.7.1",
        ActiveJobIds = [],
        Capabilities = capable ? [AgentCapabilities.Restart, AgentCapabilities.DownloadUpdates] : [AgentCapabilities.Restart],
    });

    private async Task<SignedAgent> EndpointMissingAsync(string hostname, bool capable, ReportedUpdate update)
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, hostname);
        await CheckInAsync(agent, capable);
        var now = Clock.GetUtcNow();
        using var response = await agent.PostAsync(AgentRoutes.ScanResults, new ScanResultReport
        {
            ScanId = Guid.NewGuid(),
            Trigger = ScanTrigger.Scheduled,
            StartedAt = now.AddMinutes(-1),
            CompletedAt = now,
            Succeeded = true,
            Source = new UpdateSourceInfo { Type = UpdateSourceType.WindowsUpdate },
            Missing = [update],
            Installed = [],
        });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
        return agent;
    }

    private Task SetPolicyAsync(string start, int? preDownloadHours) =>
        root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, AutoInstallEnabled: true, MaintenanceDays: [0, 1, 2, 3, 4, 5, 6],
                MaintenanceStart: start, MaintenanceDurationMinutes: 120, null, null, PreDownloadHours: preDownloadHours), HttpStatusCode.OK);

    [Fact]
    public async Task Updates_are_downloaded_ahead_of_the_window_by_agents_that_can()
    {
        var update = JobQueueTests.SecurityUpdate("KB5060001");
        var agent = await EndpointMissingAsync("PC-NEW", capable: true, update);
        var old = await EndpointMissingAsync("PC-OLD", capable: false, update);
        var windowStart = Clock.GetUtcNow().AddHours(3);
        var start = windowStart.ToString("HH:mm", CultureInfo.InvariantCulture);

        // Off by default, and the window is further away than two hours.
        await SetPolicyAsync(start, null);
        await RunMaintenanceAsync<PreDownloadTask>();
        await SetPolicyAsync(start, 2);
        await RunMaintenanceAsync<PreDownloadTask>();
        Assert.False(await WithDbAsync(db => db.Jobs.AnyAsync(j => j.Type == JobType.DownloadUpdates)));
        await root.ExpectAsync(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, null, PreDownloadHours: 25), HttpStatusCode.BadRequest);

        await SetPolicyAsync(start, 4);
        await RunMaintenanceAsync<PreDownloadTask>();
        await RunMaintenanceAsync<PreDownloadTask>(); // one job per window
        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.Type == JobType.DownloadUpdates));
        Assert.Equal((agent.EndpointId, JobTrigger.Scheduled, "Download before maintenance window"), (job.EndpointId, job.Trigger, job.RequestedBy));
        var expectedStart = new DateTimeOffset(windowStart.Year, windowStart.Month, windowStart.Day, windowStart.Hour, windowStart.Minute, 0, TimeSpan.Zero);
        Assert.Equal(expectedStart, job.ExpiresAt);

        // Delivered with the install payload; downloads are not installations and change nothing on the server.
        var delivered = Assert.Single((await CheckInAsync(agent, true)).Jobs);
        Assert.Equal((job.Id, JobType.DownloadUpdates, InstallMode.AllEligible, expectedStart), (delivered.JobId, delivered.Type, delivered.Install!.Mode, delivered.Install.NotAfter));
        Assert.Empty((await CheckInAsync(old, false)).Jobs);
        using (var ack = await agent.PostAsync($"api/v1/agents/jobs/{job.Id}/ack", new { }))
        {
            await AdminSession.EnsureAsync(ack, HttpStatusCode.OK);
        }

        using (var report = await agent.PostAsync($"api/v1/agents/jobs/{job.Id}/status", new JobStatusReport
        {
            Sequence = 1,
            Status = JobStatus.Completed,
            Phase = "Completed",
            Items = [new JobItemReport
            {
                UpdateGuid = update.UpdateGuid, RevisionNumber = update.RevisionNumber, Title = update.Title, KbNumber = "KB5060001",
                Category = UpdateCategory.Security, Status = JobItemStatus.Downloaded, DownloadPercent = 100,
            }],
            Result = new JobResultSummary { Planned = 1, Succeeded = 1 },
        }))
        {
            await AdminSession.EnsureAsync(report, HttpStatusCode.NoContent);
        }

        var detail = await root.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}");
        Assert.Equal((JobStatus.Completed, JobItemStatus.Downloaded), (detail.Summary.Status, Assert.Single(detail.Items).Status));
        var row = await WithDbAsync(db => db.EndpointUpdates.AsNoTracking().SingleAsync(u => u.EndpointId == agent.EndpointId));
        Assert.Equal(EndpointUpdateState.Missing, row.State);
        var events = await WithDbAsync(db => db.EndpointEvents.AsNoTracking().Where(e => e.JobId == job.Id).Select(e => e.Message).ToListAsync());
        Assert.Contains("Download before the maintenance window completed: 1 downloaded.", events);
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/jobs/{job.Id}/retry", null, HttpStatusCode.Conflict, "not_retryable");
    }

    [Fact]
    public async Task No_download_job_while_the_window_is_open_or_when_everything_is_on_hold()
    {
        var update = JobQueueTests.SecurityUpdate("KB5060002");
        await EndpointMissingAsync("PC-1", capable: true, update);

        await SetPolicyAsync(Clock.GetUtcNow().AddMinutes(-10).ToString("HH:mm", CultureInfo.InvariantCulture), 4);
        await RunMaintenanceAsync<PreDownloadTask>();
        Assert.False(await WithDbAsync(db => db.Jobs.AnyAsync(j => j.Type == JobType.DownloadUpdates)));

        await SetPolicyAsync(Clock.GetUtcNow().AddHours(2).ToString("HH:mm", CultureInfo.InvariantCulture), 4);
        await root.SendAsync<UpdateHoldDto>(HttpMethod.Post, $"/api/v1/updates/{update.UpdateGuid}/holds", new CreateUpdateHoldRequest(org.Id, "Testing"),
            HttpStatusCode.Created);
        await RunMaintenanceAsync<PreDownloadTask>();
        Assert.False(await WithDbAsync(db => db.Jobs.AnyAsync(j => j.Type == JobType.DownloadUpdates)));
    }
}
