using System.Globalization;
using System.Net;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Maintenance;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace EasyPatch.Tests.Integration;

public sealed class JobQueueTests(PostgresFixture postgres) : IntegrationTest(postgres)
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

    internal static ReportedUpdate SecurityUpdate(string kb) => new()
    {
        UpdateGuid = Guid.NewGuid(),
        RevisionNumber = 201,
        Title = $"2026-11 Security Update for Windows 11 ({kb})",
        KbNumbers = [kb.Replace("KB", string.Empty, StringComparison.Ordinal)],
        Categories = [new UpdateCategoryRef { Id = MicrosoftClassifications.SecurityUpdates, Name = "Security Updates", Type = "UpdateClassification" }],
        RebootBehavior = 1,
        MsrcSeverity = "Critical",
        MaxDownloadSize = 1024 * 1024,
    };

    private async Task ReportScanAsync(SignedAgent agent, IReadOnlyList<ReportedUpdate> missing, IReadOnlyList<ReportedUpdate>? installed = null)
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
            Installed = installed ?? [],
        });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
    }

    private async Task ReportAsync(SignedAgent agent, Guid jobId, long sequence, JobStatus status, HttpStatusCode expected = HttpStatusCode.NoContent,
        IReadOnlyList<JobItemReport>? items = null, bool rebootRequired = false)
    {
        using var response = await agent.PostAsync($"api/v1/agents/jobs/{jobId}/status", new JobStatusReport
        {
            Sequence = sequence,
            Status = status,
            Phase = status.ToString(),
            Items = items ?? [],
            RebootRequired = rebootRequired,
        });
        await AdminSession.EnsureAsync(response, expected);
    }

    private async Task AckAsync(SignedAgent agent, Guid jobId)
    {
        using var response = await agent.PostAsync($"api/v1/agents/jobs/{jobId}/ack", new { });
        await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
    }

    private Task<JobDetailDto> JobAsync(Guid id) => root.GetAsync<JobDetailDto>($"/api/v1/jobs/{id}");

    private Task<JobStatus> JobStatusInDbAsync(Guid id) => WithDbAsync(db => db.Jobs.Where(j => j.Id == id).Select(j => j.Status).FirstAsync());

    private Task<JobSummaryDto> InstallAllAsync(Guid endpointId, bool force = false) =>
        root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{endpointId}/install-updates",
            new InstallUpdatesRequest(InstallMode.AllEligible, null, force), HttpStatusCode.Accepted);

    [Fact]
    public async Task An_update_Windows_offers_again_after_installing_is_not_failed_and_not_installed_again_automatically()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-REOFFER");
        var platform = SecurityUpdate("KB5007651") with
        {
            Title = "Update for Windows Security platform - KB5007651 (Version 10.0.29628.1000)",
            RevisionNumber = 204,
            RebootBehavior = 0,
            Categories = [new UpdateCategoryRef { Id = MicrosoftClassifications.DefinitionUpdates, Name = "Definition Updates", Type = "UpdateClassification" }],
            MsrcSeverity = null,
        };
        var cumulative = SecurityUpdate("KB5046617");
        await ReportScanAsync(agent, [platform, cumulative]);

        // Windows reports the installation as successful...
        var job = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/install-updates",
            new InstallUpdatesRequest(InstallMode.Selected, [platform.UpdateGuid], false), HttpStatusCode.Accepted);
        Assert.Equal(job.Id, Assert.Single((await agent.CheckInAsync()).Jobs).JobId);
        await AckAsync(agent, job.Id);
        await ReportAsync(agent, job.Id, 1, JobStatus.Completed, items:
        [
            new JobItemReport { UpdateGuid = platform.UpdateGuid, RevisionNumber = 204, Title = platform.Title, Status = JobItemStatus.Succeeded, ResultCode = 2 },
        ]);

        // ...but the next scan still offers it.
        await ReportScanAsync(agent, [platform, cumulative]);
        var updates = await root.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{agent.EndpointId}/updates");
        var row = updates.Single(u => u.UpdateGuid == platform.UpdateGuid);
        Assert.Equal(EndpointUpdateState.Reoffered, row.State);
        Assert.Contains("still offers this update", row.ErrorMessage, StringComparison.Ordinal);
        var summary = (await root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}")).Summary;
        Assert.Equal((1, 0, ComplianceStatus.MissingUpdates), (summary.MissingRequiredCount, summary.FailedCount, summary.ComplianceStatus)); // only the cumulative update

        // Installing everything skips it, and tells the agent to skip it too.
        var all = await root.GetAsync<InstallPreview>($"/api/v1/endpoints/{agent.EndpointId}/install-preview?mode=all");
        Assert.Equal([cumulative.UpdateGuid], all.Items.Select(i => i.UpdateGuid));
        Assert.Equal(SkipReasons.Reoffered, all.Skipped.Single(x => x.UpdateGuid == platform.UpdateGuid).Reason);
        Assert.Contains(platform.UpdateGuid, all.Filter.ExcludedUpdateGuids);
        var installAll = await InstallAllAsync(agent.EndpointId);
        var payload = Assert.Single((await agent.CheckInAsync()).Jobs);
        Assert.Equal(installAll.Id, payload.JobId);
        Assert.Contains(platform.UpdateGuid, payload.Install!.Filter.ExcludedUpdateGuids);
        await AckAsync(agent, installAll.Id);
        await ReportAsync(agent, installAll.Id, 1, JobStatus.Completed);

        // An administrator can still choose to install it.
        var chosen = await root.GetAsync<InstallPreview>($"/api/v1/endpoints/{agent.EndpointId}/install-preview?mode=selected&updateGuids={platform.UpdateGuid}");
        Assert.Equal([platform.UpdateGuid], chosen.Items.Select(i => i.UpdateGuid));
        Assert.DoesNotContain(platform.UpdateGuid, chosen.Filter.ExcludedUpdateGuids);

        // A new revision is missing again and installed normally.
        await ReportScanAsync(agent, [platform with { RevisionNumber = 205 }, cumulative]);
        updates = await root.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{agent.EndpointId}/updates");
        Assert.Equal(EndpointUpdateState.Missing, updates.Single(u => u.UpdateGuid == platform.UpdateGuid).State);
    }

    [Fact]
    public async Task Duplicate_requests_return_the_existing_job_unless_forced()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-1");
        await ReportScanAsync(agent, [SecurityUpdate("KB5046617")]);

        var first = await InstallAllAsync(agent.EndpointId);
        using (var duplicate = await root.SendAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/install-updates",
                   new InstallUpdatesRequest(InstallMode.AllEligible, null, false)))
        {
            Assert.Equal(HttpStatusCode.Conflict, duplicate.StatusCode);
            using var problem = JsonDocument.Parse(await duplicate.Content.ReadAsStringAsync());
            Assert.Equal("duplicate_job", problem.RootElement.GetProperty("code").GetString());
            Assert.Equal(first.Id, problem.RootElement.GetProperty("existingJobId").GetGuid());
        }

        var forced = await InstallAllAsync(agent.EndpointId, force: true);
        Assert.NotEqual(first.Id, forced.Id);

        // Selecting only updates that are not offered is refused instead of creating an empty job.
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/install-updates",
            new InstallUpdatesRequest(InstallMode.Selected, [Guid.NewGuid()], false), HttpStatusCode.Conflict, "nothing_to_install");
    }

    [Fact]
    public async Task Jobs_wait_for_offline_endpoints_and_are_delivered_when_they_return()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "LAPTOP-1");
        await agent.CheckInAsync();
        await FlushPresenceAsync();

        Clock.Advance(TimeSpan.FromMinutes(20));
        await RunMaintenanceAsync<PresenceMonitorTask>();
        Assert.Equal(EndpointStatus.Active, await WithDbAsync(db => db.Endpoints.Select(e => e.Status).FirstAsync()));
        root = await LoginAsync("root", DefaultPassword, root.MfaSecret);
        Assert.False((await root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}")).Summary.IsOnline);

        var scan = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/scan", null, HttpStatusCode.Accepted);
        Clock.Advance(TimeSpan.FromHours(30)); // a long weekend
        await RunMaintenanceAsync<JobMaintenanceTask>();
        Assert.Equal(JobStatus.Queued, await JobStatusInDbAsync(scan.Id));

        var checkIn = await agent.CheckInAsync();
        Assert.Equal(scan.Id, Assert.Single(checkIn.Jobs).JobId);
        await FlushPresenceAsync();
        Assert.Equal(JobStatus.Delivered, await JobStatusInDbAsync(scan.Id));
    }

    [Fact]
    public async Task Queued_jobs_expire_at_their_deadline()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-EXPIRE");
        var scan = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/scan", null, HttpStatusCode.Accepted);
        Clock.Advance(TimeSpan.FromHours(169));
        await RunMaintenanceAsync<JobMaintenanceTask>();
        Assert.Equal(JobStatus.Expired, await JobStatusInDbAsync(scan.Id));
        Assert.Empty((await agent.CheckInAsync()).Jobs);
    }

    [Fact]
    public async Task Unacknowledged_deliveries_are_retried_and_eventually_failed()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-FLAKY");
        var scan = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/scan", null, HttpStatusCode.Accepted);

        // Delivered, but the agent never acknowledged it and went silent: the lease expires and the job is queued again.
        Assert.Single((await agent.CheckInAsync()).Jobs);
        Clock.Advance(TimeSpan.FromMinutes(11));
        await RunMaintenanceAsync<JobMaintenanceTask>();
        Assert.Equal(JobStatus.Queued, await JobStatusInDbAsync(scan.Id));

        // An agent that keeps losing the job (check-ins without listing it) gets it again, up to the attempt limit.
        for (var delivery = 2; delivery <= 5; delivery++)
        {
            Assert.Equal(scan.Id, Assert.Single((await agent.CheckInAsync()).Jobs).JobId);
        }

        Assert.Empty((await agent.CheckInAsync()).Jobs);
        var detail = await WithDbAsync(db => db.Jobs.AsNoTracking().FirstAsync(j => j.Id == scan.Id));
        Assert.Equal(JobStatus.Failed, detail.Status);
        Assert.Equal(5, detail.DeliveryCount);
    }

    [Fact]
    public async Task Stalled_jobs_time_out_but_a_late_result_is_still_recorded()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-SLOW");
        var scan = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/scan", null, HttpStatusCode.Accepted);
        await agent.CheckInAsync();
        await AckAsync(agent, scan.Id);
        await ReportAsync(agent, scan.Id, 1, JobStatus.Running);

        Clock.Advance(TimeSpan.FromHours(13));
        await RunMaintenanceAsync<JobMaintenanceTask>();
        var timedOut = await WithDbAsync(db => db.Jobs.AsNoTracking().FirstAsync(j => j.Id == scan.Id));
        Assert.Equal(JobStatus.Failed, timedOut.Status);
        Assert.True(timedOut.TimedOut);

        // The agent was just slow: its final report replaces the timeout instead of being discarded.
        await ReportAsync(agent, scan.Id, 2, JobStatus.Completed);
        Assert.Equal(JobStatus.Completed, await JobStatusInDbAsync(scan.Id));

        // Stale and duplicate reports are ignored.
        await ReportAsync(agent, scan.Id, 1, JobStatus.Running);
        Assert.Equal(JobStatus.Completed, await JobStatusInDbAsync(scan.Id));
    }

    [Fact]
    public async Task Download_and_install_percentages_of_each_update_are_shown_while_the_job_runs()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-PROGRESS");
        var downloading = SecurityUpdate("KB5046631");
        var installing = SecurityUpdate("KB5046632");
        await ReportScanAsync(agent, [downloading, installing]);
        var install = await InstallAllAsync(agent.EndpointId);
        Assert.Equal(install.Id, Assert.Single((await agent.CheckInAsync()).Jobs).JobId);
        await AckAsync(agent, install.Id);

        JobItemReport Item(ReportedUpdate update, JobItemStatus status, int? downloaded, int? installed) => new()
        {
            UpdateGuid = update.UpdateGuid,
            Title = update.Title,
            KbNumber = "KB" + update.KbNumbers[0],
            Status = status,
            DownloadPercent = downloaded,
            InstallPercent = installed,
        };
        await ReportAsync(agent, install.Id, 1, JobStatus.Running, items:
        [
            Item(downloading, JobItemStatus.Downloading, 140, null), // out of range: stored as 100
            Item(installing, JobItemStatus.Installing, 100, 45),
        ]);

        var items = (await JobAsync(install.Id)).Items.ToDictionary(i => i.UpdateGuid);
        Assert.Equal((100, (int?)null), (items[downloading.UpdateGuid].DownloadPercent, items[downloading.UpdateGuid].InstallPercent));
        Assert.Equal((100, 45), (items[installing.UpdateGuid].DownloadPercent, items[installing.UpdateGuid].InstallPercent));

        var overlay = (await root.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{agent.EndpointId}/updates"))
            .Single(u => u.UpdateGuid == installing.UpdateGuid).ActiveJob;
        Assert.NotNull(overlay);
        Assert.Equal(JobItemStatus.Installing, overlay.ItemStatus);
        Assert.Equal(45, overlay.InstallPercent);
    }

    [Fact]
    public async Task Cancellation_is_immediate_when_queued_and_cooperative_when_running()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-CANCEL");
        var queued = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/scan", null, HttpStatusCode.Accepted);
        var cancelled = await root.SendAsync<JobDetailDto>(HttpMethod.Post, $"/api/v1/jobs/{queued.Id}/cancel", null, HttpStatusCode.OK);
        Assert.Equal(JobStatus.Cancelled, cancelled.Summary.Status);
        Assert.Empty((await agent.CheckInAsync()).Jobs);
        await root.ExpectAsync(HttpMethod.Post, $"/api/v1/jobs/{queued.Id}/cancel", null, HttpStatusCode.Conflict, "invalid_state");

        await ReportScanAsync(agent, [SecurityUpdate("KB5046617"), SecurityUpdate("KB5046618")]);
        var install = await InstallAllAsync(agent.EndpointId);
        var delivered = await agent.CheckInAsync();
        Assert.Equal(install.Id, Assert.Single(delivered.Jobs).JobId);
        await AckAsync(agent, install.Id);
        await ReportAsync(agent, install.Id, 1, JobStatus.Running);

        var requested = await root.SendAsync<JobDetailDto>(HttpMethod.Delete, $"/api/v1/jobs/{install.Id}", null, HttpStatusCode.OK);
        Assert.Equal(JobStatus.Running, requested.Summary.Status);
        Assert.True(requested.Summary.CancelRequested);

        var next = await agent.CheckInAsync([install.Id]);
        Assert.Contains(install.Id, next.CancelJobIds);
        await ReportAsync(agent, install.Id, 2, JobStatus.Cancelled);
        Assert.Equal(JobStatus.Cancelled, (await JobAsync(install.Id)).Summary.Status);

        // A finished job can be retried as a new job.
        var retry = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/jobs/{install.Id}/retry", null, HttpStatusCode.Accepted);
        Assert.Equal(install.Id, (await JobAsync(retry.Id)).RetryOfJobId);
    }

    [Fact]
    public async Task Site_concurrency_limit_staggers_installs()
    {
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/sites/{site.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, MaxConcurrentInstallsPerSite: 1), HttpStatusCode.OK);
        var a = await EnrollAgentAsync(root, org.Id, site.Id, "PC-A");
        var b = await EnrollAgentAsync(root, org.Id, site.Id, "PC-B");
        await ReportScanAsync(a, [SecurityUpdate("KB5046617")]);
        await ReportScanAsync(b, [SecurityUpdate("KB5046617")]);
        var jobA = await InstallAllAsync(a.EndpointId);
        var jobB = await InstallAllAsync(b.EndpointId);

        Assert.Single((await a.CheckInAsync()).Jobs);
        Assert.Empty((await b.CheckInAsync()).Jobs); // site slot taken
        await AckAsync(a, jobA.Id);
        await ReportAsync(a, jobA.Id, 1, JobStatus.Running);
        Assert.Empty((await b.CheckInAsync()).Jobs);

        await ReportAsync(a, jobA.Id, 2, JobStatus.Completed);
        Assert.Equal(jobB.Id, Assert.Single((await b.CheckInAsync()).Jobs).JobId);
    }

    [Fact]
    public async Task Scans_still_run_while_an_install_waits_for_a_restart_but_installs_do_not()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-REBOOT");
        await ReportScanAsync(agent, [SecurityUpdate("KB5046617")]);
        var install = await InstallAllAsync(agent.EndpointId);
        await agent.CheckInAsync();
        await AckAsync(agent, install.Id);
        await ReportAsync(agent, install.Id, 1, JobStatus.WaitingForReboot, rebootRequired: true);

        var forced = await InstallAllAsync(agent.EndpointId, force: true);
        var scan = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/scan", null, HttpStatusCode.Accepted);
        var checkIn = await agent.CheckInAsync([install.Id]);
        Assert.Equal(scan.Id, Assert.Single(checkIn.Jobs).JobId);
        await AckAsync(agent, scan.Id);
        await ReportAsync(agent, scan.Id, 1, JobStatus.Completed);
        Assert.Empty((await agent.CheckInAsync([install.Id])).Jobs);
        Assert.Equal(JobStatus.Queued, await JobStatusInDbAsync(forced.Id));

        // The administrator restarts the computer; the parked job completes and the next install is delivered.
        await ReportAsync(agent, install.Id, 2, JobStatus.Completed);
        Assert.Equal(forced.Id, Assert.Single((await agent.CheckInAsync()).Jobs).JobId);
    }

    [Fact]
    public async Task Maintenance_windows_schedule_installs_only_when_enabled()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-WINDOW");
        await ReportScanAsync(agent, [SecurityUpdate("KB5046617")]);

        await RunMaintenanceAsync<ScheduledInstallTask>();
        Assert.Equal(0, await WithDbAsync(db => db.Jobs.CountAsync(j => j.Type == JobType.InstallUpdates))); // off by default

        var start = Clock.GetUtcNow().AddMinutes(-10).ToString("HH:mm", CultureInfo.InvariantCulture);
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, AutoInstallEnabled: true, MaintenanceDays: [0, 1, 2, 3, 4, 5, 6],
                MaintenanceStart: start, MaintenanceDurationMinutes: 120, null, null), HttpStatusCode.OK);

        await RunMaintenanceAsync<ScheduledInstallTask>();
        await RunMaintenanceAsync<ScheduledInstallTask>(); // idempotent within one window
        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.Type == JobType.InstallUpdates));
        Assert.Equal(JobTrigger.Scheduled, job.Trigger);
        Assert.True(job.ExpiresAt <= Clock.GetUtcNow().AddMinutes(111));

        var delivered = Assert.Single((await agent.CheckInAsync()).Jobs);
        Assert.NotNull(delivered.Install!.NotAfter); // the agent will not start new updates after the window closes
    }

    [Fact]
    public async Task Maintenance_tasks_are_skipped_while_another_worker_holds_the_lock()
    {
        await using var other = new Npgsql.NpgsqlConnection(Factory.ConnectionString);
        await other.OpenAsync();
        await using (var take = new Npgsql.NpgsqlCommand("SELECT pg_advisory_lock(0x45500005)", other))
        {
            await take.ExecuteNonQueryAsync();
        }

        Assert.False(await MaintenanceExecutor.RunExclusiveAsync<RetentionTask>(Factory.Services, CancellationToken.None));

        await using (var release = new Npgsql.NpgsqlCommand("SELECT pg_advisory_unlock(0x45500005)", other))
        {
            await release.ExecuteNonQueryAsync();
        }

        Assert.True(await MaintenanceExecutor.RunExclusiveAsync<RetentionTask>(Factory.Services, CancellationToken.None));
    }
    [Fact]
    public async Task The_endpoint_shows_which_updates_and_files_a_pending_restart_is_for()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-RESTART");
        var installed = SecurityUpdate("KB5000001") with { RebootRequired = true };
        var listed = SecurityUpdate("KB5000002");
        var servicing = SecurityUpdate("KB5000003");
        await ReportScanAsync(agent, [installed, listed, servicing]);

        var unknown = Guid.NewGuid();
        var request = new CheckInRequest
        {
            AgentVersion = "1.5.3",
            RebootPending = true,
            RebootReasons = ["Windows Update (RebootRequired)", "Component Based Servicing (PackagesPending)", "Pending file rename operations"],
            RebootDetails = new RebootDetails
            {
                WindowsUpdateIds = [listed.UpdateGuid, unknown, installed.UpdateGuid],
                ServicingPackages =
                [
                    "Package_for_KB5000003~31bf3856ad364e35~amd64~~26100.1.1.0",
                    "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.2.1.0",
                    "Package_for_KB5000001~31bf3856ad364e35~amd64~~26100.3.1.0",
                    "Package_for_KB5999999~31bf3856ad364e35~amd64~~26100.4.1.0",
                ],
                FileOperations = [new PendingFileOperation { Action = PendingFileOperation.Replace, Path = @"C:\Program Files\Contoso\contoso.dll" }],
                FileOperationCount = 30,
            },
        };
        await agent.CheckInAsync(request);
        await agent.CheckInAsync(request);

        var detail = await root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");
        var restart = detail.Restart!;
        Assert.True(restart.DetailsSupported);
        Assert.Equal(
        [
            (installed.UpdateGuid, "Installed", "KB5000001"),
            (listed.UpdateGuid, "WindowsUpdate", "KB5000002"),
            (unknown, "WindowsUpdate", ""),
            (servicing.UpdateGuid, "Servicing", "KB5000003"),
            ((Guid?)null, "Servicing", "KB5999999"),
        ], restart.Updates.Select(u => (u.UpdateGuid, u.Source, (u.KbNumbers.Count > 0 ? u.KbNumbers[0] : ""))).ToList());
        Assert.Equal(servicing.Title, restart.Updates[3].Title);
        Assert.Equal("KB5999999", restart.Updates[4].Title);
        Assert.Equal(["Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.2.1.0"], restart.ServicingPackages);
        Assert.Equal(@"C:\Program Files\Contoso\contoso.dll", Assert.Single(restart.FileOperations).Path);
        Assert.Equal(30, restart.FileOperationCount);

        // The same report again records no new event.
        await using (var scope = Factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<EasyPatch.Infrastructure.Data.EasyPatchDbContext>();
            Assert.Equal(1, await db.EndpointEvents.CountAsync(x => x.EndpointId == agent.EndpointId && x.Type == "RebootRequired",
                TestContext.Current.CancellationToken));
        }

        // Details stored before a cleaning rule existed are cleaned at the next report.
        await using (var scope = Factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<EasyPatch.Infrastructure.Data.EasyPatchDbContext>();
            var endpoint = await db.Endpoints.SingleAsync(x => x.Id == agent.EndpointId, TestContext.Current.CancellationToken);
            endpoint.RebootDetails = """{"isEmpty":false,"fileOperations":[{"path":"*1\\??\\C:\\Users\\erin\\AppData\\Local\\Temp\\x.tmp","action":"Delete"}],"fileOperationCount":1}""";
            await db.SaveChangesAsync(TestContext.Current.CancellationToken);
        }

        var raw = request with
        {
            RebootDetails = new RebootDetails
            {
                FileOperations = [new PendingFileOperation { Action = "Delete", Path = @"*1\??\C:\Users\erin\AppData\Local\Temp\x.tmp" }],
            },
        };
        await agent.CheckInAsync(raw);
        await using (var scope = Factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<EasyPatch.Infrastructure.Data.EasyPatchDbContext>();
            var stored = await db.Endpoints.Where(x => x.Id == agent.EndpointId).Select(x => x.RebootDetails).SingleAsync(TestContext.Current.CancellationToken);
            Assert.Contains(@"C:\\Users\\*\\AppData", stored, StringComparison.Ordinal);
            Assert.DoesNotContain("erin", stored, StringComparison.Ordinal);
            Assert.DoesNotContain("isEmpty", stored, StringComparison.Ordinal);
        }

        // An agent that does not report details: only the installed update is known.
        await agent.CheckInAsync(request with { AgentVersion = "1.5.0", RebootDetails = null });
        restart = (await root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}")).Restart!;
        Assert.False(restart.DetailsSupported);
        Assert.Equal([installed.UpdateGuid], restart.Updates.Select(u => u.UpdateGuid));
        Assert.Empty(restart.FileOperations);
    }
}
