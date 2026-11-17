using System.Net;
using EasyPatch.Agent.Core;
using EasyPatch.Agent.Core.Abstractions;
using EasyPatch.Agent.Core.Enrollment;
using EasyPatch.Agent.Core.Runtime;
using EasyPatch.Agent.Tests.Infrastructure;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Updates;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>
/// The Definition-of-Done workflow end to end: the real agent runtime (with a Windows Update test double in place of
/// the WUA COM API) talks to the real API over HTTP, signed exactly as on a Windows endpoint.
/// </summary>
public sealed class AgentLifecycleTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private sealed class TestAgent : IDisposable
    {
        private readonly HttpClient http;
        private readonly TimeProvider clock;

        public TestAgent(HttpClient http, TimeProvider clock)
        {
            this.http = http;
            this.clock = clock;
            BootTime = new FakeBootTime(clock.GetUtcNow().AddHours(-3));
            Platform = new AgentPlatform(WindowsUpdate, Inventory, RebootDetector, new FakeUpdateSource(), Protector, Bootstrap, BootTime)
            {
                AgentUninstaller = Uninstaller,
            };
            Runtime = Create();
        }

        public string DataDirectory { get; } = Directory.CreateTempSubdirectory("easypatch-agent-").FullName;
        public FakeWindowsUpdate WindowsUpdate { get; } = new();
        public FakeInventory Inventory { get; } = new();
        public FakeRebootDetector RebootDetector { get; } = new();
        public TestSecretProtector Protector { get; } = new();
        public FakeAgentUninstaller Uninstaller { get; } = new();
        public InMemoryBootstrap Bootstrap { get; } = new() { ServerUrl = EasyPatchApiFactory.PublicUrl };
        public FakeBootTime BootTime { get; }
        public AgentPlatform Platform { get; }
        public AgentRuntime Runtime { get; private set; }

        /// <summary>An administrator restarted the computer: updates finish and the service starts again.</summary>
        public void Restart()
        {
            WindowsUpdate.SimulateReboot();
            RebootDetector.Status = RebootStatus.None;
            BootTime.Boot = clock.GetUtcNow().AddMinutes(-1);
            Runtime.Dispose();
            Runtime = Create();
        }

        public async Task RunJobsAsync()
        {
            while (await Runtime.ProcessNextJobAsync())
            {
            }

            Assert.True(await Runtime.FlushOutboxAsync());
        }

        private AgentRuntime Create() =>
            new(new AgentRuntimeOptions { DataDirectory = DataDirectory, AgentVersion = "1.0.0" }, Platform, http, loggerFactory: null, timeProvider: clock);

        public void Dispose()
        {
            Runtime.Dispose();
            try
            {
                Directory.Delete(DataDirectory, true);
            }
            catch (IOException)
            {
            }
        }
    }

    [Fact]
    public async Task Enroll_scan_install_all_missing_restart_and_report_compliance()
    {
        // 1-3. An administrator signs in (password + MFA), creates the customer and site, and issues an enrollment token.
        var admin = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(admin, "Northwind Traders");
        var token = await CreateTokenAsync(admin, org.Id, site.Id, maxUses: 1);

        // 4. The MSI installs the agent with the token; the agent enrolls with its own device key and forgets the token.
        using var agent = new TestAgent(NewHttpClient(), Clock);
        agent.Bootstrap.EnrollmentToken = token;
        Assert.Equal(EnrollmentOutcome.Active, await agent.Runtime.EnsureEnrolledAsync());
        Assert.Null(agent.Bootstrap.EnrollmentToken);
        Assert.True(agent.Protector.ProtectCalls > 0); // the private key is stored protected (DPAPI on Windows)
        var endpointId = agent.Runtime.State.Read(s => s.EndpointId)!.Value;

        // 5-6. Windows Update reports a mix of updates; inventory and the scan reach the server; the endpoint is online.
        var securityUpdate = agent.WindowsUpdate.Add("2026-11 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5046617)",
            MicrosoftClassifications.SecurityUpdates, "5046617", requiresReboot: true);
        var edgeUpdate = agent.WindowsUpdate.Add("Security Update for Microsoft Edge (KB5046700)", MicrosoftClassifications.SecurityUpdates, "5046700");
        var definitions = agent.WindowsUpdate.Add("Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.421.1)",
            MicrosoftClassifications.DefinitionUpdates, "2267602");
        var driver = agent.WindowsUpdate.Add("Intel Corporation - Display - 31.0.101.5590", MicrosoftClassifications.Drivers, isDriver: true);
        var preview = agent.WindowsUpdate.Add("2026-11 Cumulative Update Preview for .NET Framework (KB5046800)", MicrosoftClassifications.Updates,
            "5046800", browseOnly: true);
        var alreadyInstalled = agent.WindowsUpdate.Add("2026-10 Servicing Stack Update (KB5044000)", MicrosoftClassifications.SecurityUpdates, "5044000",
            installed: true);

        await agent.Runtime.SendInventoryAsync();
        Assert.NotNull(await agent.Runtime.RunScanAsync(ScanTrigger.Startup));
        Assert.NotNull(await agent.Runtime.CheckInOnceAsync());
        Assert.True(await agent.Runtime.FlushOutboxAsync());
        await FlushPresenceAsync();

        var detail = await admin.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{endpointId}");
        Assert.True(detail.Summary.IsOnline);
        Assert.Equal("TEST-PC", detail.Summary.Hostname);
        Assert.Equal(site.Id, detail.Summary.SiteId);
        Assert.Equal("1.0.0", detail.Summary.AgentVersion);
        Assert.Equal(ComplianceStatus.MissingUpdates, detail.Summary.ComplianceStatus);
        Assert.Equal(3, detail.Summary.MissingRequiredCount); // cumulative, Edge, Defender; not the driver or the optional preview

        var missing = await admin.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{endpointId}/updates");
        Assert.Contains(missing, u => u.UpdateGuid == securityUpdate.Guid && u.State == EndpointUpdateState.Missing && u.IsRequired);
        Assert.Contains(missing, u => u.UpdateGuid == driver.Guid && !u.IsRequired);
        Assert.Contains(await admin.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{endpointId}/installed-updates"),
            u => u.UpdateGuid == alreadyInstalled.Guid);

        // 7. The confirmation dialog shows exactly what the agent will install.
        var installPreview = await admin.GetAsync<InstallPreview>($"/api/v1/endpoints/{endpointId}/install-preview?mode=all");
        Assert.Equal(new[] { securityUpdate.Guid, edgeUpdate.Guid, definitions.Guid }.Order(), installPreview.Items.Select(i => i.UpdateGuid).Order());
        Assert.True(installPreview.RebootLikelyCount >= 1); // the cumulative update needs a restart

        // 8. "Install All Missing Updates".
        var job = await admin.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{endpointId}/install-updates",
            new InstallUpdatesRequest(InstallMode.AllEligible, null, false), HttpStatusCode.Accepted);
        Assert.Equal(JobStatus.Queued, job.Status);

        // 9. The agent picks the job up on its next check-in and acknowledges it.
        var checkIn = await agent.Runtime.CheckInOnceAsync();
        Assert.Equal(job.Id, Assert.Single(checkIn!.Jobs).JobId);
        Assert.Equal(JobStatus.Acknowledged, (await admin.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}")).Summary.Status);

        // 10-12. It downloads and installs through Windows Update, reports progress and runs a verification scan.
        agent.RebootDetector.Status = new RebootStatus(true, ["WindowsUpdate"]);
        await agent.RunJobsAsync();
        Assert.Equal(1, agent.WindowsUpdate.InstallCount(securityUpdate.Guid));
        Assert.Equal(1, agent.WindowsUpdate.InstallCount(edgeUpdate.Guid));
        Assert.Equal(1, agent.WindowsUpdate.InstallCount(definitions.Guid));
        Assert.Equal(0, agent.WindowsUpdate.InstallCount(driver.Guid));
        Assert.Equal(0, agent.WindowsUpdate.InstallCount(preview.Guid));
        await agent.Runtime.CheckInOnceAsync();

        var finished = await admin.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}");
        Assert.Equal(JobStatus.Completed, finished.Summary.Status);
        Assert.True(finished.Summary.RebootRequired);
        Assert.Equal(3, finished.Summary.SucceededCount);
        Assert.All(finished.Items, i => Assert.Equal(JobItemStatus.Succeeded, i.Status));
        Assert.Contains(finished.Events, e => e.Type == "JobStarted");

        // 13-14. The restart-pending update is not reported as installed until a scan confirms it; nothing restarts the computer.
        var afterInstall = await admin.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{endpointId}/updates");
        Assert.Equal(EndpointUpdateState.PendingReboot, afterInstall.Single(u => u.UpdateGuid == securityUpdate.Guid).State);
        Assert.DoesNotContain(afterInstall, u => u.UpdateGuid == edgeUpdate.Guid); // confirmed installed by the verification scan
        detail = await admin.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{endpointId}");
        Assert.True(detail.Summary.RebootPending);
        Assert.Equal(ComplianceStatus.RebootRequired, detail.Summary.ComplianceStatus);
        Assert.All(agent.WindowsUpdate.Operations, op => Assert.Matches("^(download|install):", op));

        for (var i = 0; i < 3; i++)
        {
            Clock.Advance(TimeSpan.FromMinutes(1));
            await agent.Runtime.CheckInOnceAsync();
            Assert.False(await agent.Runtime.ProcessNextJobAsync());
        }

        Assert.True((await admin.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{endpointId}")).Summary.RebootPending);

        // 15-17. The administrator restarts the computer; the agent reports the new boot and rescans.
        Clock.Advance(TimeSpan.FromMinutes(5));
        agent.Restart();
        Assert.Equal(EnrollmentOutcome.Active, await agent.Runtime.EnsureEnrolledAsync()); // identity survives the restart
        await agent.Runtime.CheckInOnceAsync();
        Assert.NotNull(await agent.Runtime.RunScanAsync(ScanTrigger.PostReboot));
        Assert.True(await agent.Runtime.FlushOutboxAsync());

        // 18. Compliance is now green, and the update is recorded as installed (with history).
        detail = await admin.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{endpointId}");
        Assert.False(detail.Summary.RebootPending);
        Assert.Equal(ComplianceStatus.Compliant, detail.Summary.ComplianceStatus);
        Assert.Equal(0, detail.Summary.MissingRequiredCount);
        var installed = await admin.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{endpointId}/installed-updates");
        Assert.Contains(installed, u => u.UpdateGuid == securityUpdate.Guid && u.InstalledAt is not null);
        var history = await admin.GetAsync<PagedResult<UpdateHistoryDto>>($"/api/v1/endpoints/{endpointId}/update-history");
        Assert.Contains(history.Items, h => h.UpdateGuid == securityUpdate.Guid && h.Result == "Succeeded");

        // 19. Reports and the dashboard reflect it.
        var compliance = await admin.GetAsync<ComplianceReportDto>("/api/v1/reports/compliance");
        Assert.Equal(1, compliance.Total);
        Assert.Equal(100, compliance.CompliancePercent);
        var installations = await admin.GetAsync<PagedResult<InstallationReportRow>>("/api/v1/reports/installations");
        Assert.Equal(3, installations.Items.Count(r => r.JobId == job.Id && r.Status == JobItemStatus.Succeeded));
        using (var csv = await admin.SendAsync(HttpMethod.Get, "/api/v1/reports/compliance.csv"))
        {
            Assert.Equal(HttpStatusCode.OK, csv.StatusCode);
            Assert.Equal("text/csv", csv.Content.Headers.ContentType?.MediaType);
            Assert.Contains("TEST-PC", await csv.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }

        var dashboard = await admin.GetAsync<DashboardSummaryDto>("/api/v1/dashboard/summary");
        Assert.Equal(1, dashboard.Endpoints);
        Assert.Equal(1, dashboard.Compliant);

        // 20. Every administrative action is in the audit log; no secret appears anywhere in it.
        var audit = await admin.GetAsync<PagedResult<AuditLogDto>>("/api/v1/audit-logs?pageSize=200");
        var actions = audit.Items.Select(a => a.Action).ToHashSet();
        Assert.Contains("auth.login", actions);
        Assert.Contains("organization.create", actions);
        Assert.Contains("enrollment_token.create", actions);
        Assert.Contains("job.create", actions);
        Assert.DoesNotContain(audit.Items, a => (a.Details ?? string.Empty).Contains(token, StringComparison.Ordinal));
        Assert.DoesNotContain(token, await WithDbAsync(db => db.EndpointEvents.Select(e => e.Message).ToListAsync()));
    }

    [Fact]
    public async Task Failed_updates_are_reported_with_the_windows_update_error()
    {
        var admin = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(admin);
        using var agent = new TestAgent(NewHttpClient(), Clock);
        agent.Bootstrap.EnrollmentToken = await CreateTokenAsync(admin, org.Id, site.Id);
        await agent.Runtime.EnsureEnrolledAsync();
        var endpointId = agent.Runtime.State.Read(s => s.EndpointId)!.Value;

        var good = agent.WindowsUpdate.Add("Security Update for Microsoft Edge (KB5046700)", MicrosoftClassifications.SecurityUpdates, "5046700");
        var bad = agent.WindowsUpdate.Add("2026-11 Security Update for Windows (KB5046999)", MicrosoftClassifications.SecurityUpdates, "5046999");
        bad.InstallHResult = unchecked((int)0x80073712); // ERROR_SXS_COMPONENT_STORE_CORRUPT
        await agent.Runtime.RunScanAsync(ScanTrigger.Startup);
        await agent.Runtime.CheckInOnceAsync();

        var job = await admin.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{endpointId}/install-updates",
            new InstallUpdatesRequest(InstallMode.AllEligible, null, false), HttpStatusCode.Accepted);
        await agent.Runtime.CheckInOnceAsync();
        await agent.RunJobsAsync();

        var finished = await admin.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}");
        Assert.Equal(JobStatus.Completed, finished.Summary.Status); // partial success
        Assert.Equal(1, finished.Summary.FailedCount);
        var failedItem = finished.Items.Single(i => i.UpdateGuid == bad.Guid);
        Assert.Equal(JobItemStatus.Failed, failedItem.Status);
        Assert.Equal("0x80073712", failedItem.ErrorCode);
        Assert.Equal(JobItemStatus.Succeeded, finished.Items.Single(i => i.UpdateGuid == good.Guid).Status);

        var updates = await admin.GetAsync<List<EndpointUpdateDto>>($"/api/v1/endpoints/{endpointId}/updates");
        var failedUpdate = updates.Single(u => u.UpdateGuid == bad.Guid);
        Assert.Equal(EndpointUpdateState.Failed, failedUpdate.State);
        Assert.Equal(1, failedUpdate.FailedAttempts);
        var summary = (await admin.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{endpointId}")).Summary;
        Assert.Equal(ComplianceStatus.FailedUpdates, summary.ComplianceStatus);
    }

    [Fact]
    public async Task Rmm_install_with_a_deployment_code_activates_after_approval()
    {
        var admin = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(admin);
        var code = await admin.SendAsync<DeploymentCodeDto>(HttpMethod.Post, "/api/v1/deployment-codes",
            new CreateDeploymentCodeRequest(org.Id, site.Id, "RMM", 30, null, null), HttpStatusCode.Created);

        using var agent = new TestAgent(NewHttpClient(), Clock);
        agent.Bootstrap.DeploymentCode = code.Code;
        Assert.Equal(EnrollmentOutcome.PendingApproval, await agent.Runtime.EnsureEnrolledAsync());
        Assert.Null(await agent.Runtime.CheckInOnceAsync()); // nothing is sent before approval
        Assert.Equal(EnrollmentOutcome.PendingApproval, await agent.Runtime.EnsureEnrolledAsync());

        var request = (await admin.GetAsync<PagedResult<EnrollmentRequestDto>>("/api/v1/enrollment-requests")).Items.Single();
        await admin.SendAsync<object>(HttpMethod.Post, $"/api/v1/enrollment-requests/{request.Id}/approve", new ApproveRequest(null, null), HttpStatusCode.OK);

        Clock.Advance(TimeSpan.FromMinutes(2));
        Assert.Equal(EnrollmentOutcome.Active, await agent.Runtime.EnsureEnrolledAsync());
        Assert.NotNull(await agent.Runtime.CheckInOnceAsync());
        var endpointId = agent.Runtime.State.Read(s => s.EndpointId)!.Value;
        Assert.Equal(site.Id, (await admin.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{endpointId}")).Summary.SiteId);
    }

    [Fact]
    public async Task Agent_rotates_its_key_and_unenrolls_on_uninstall()
    {
        var admin = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(admin);
        using var agent = new TestAgent(NewHttpClient(), Clock);
        agent.Bootstrap.EnrollmentToken = await CreateTokenAsync(admin, org.Id, site.Id);
        await agent.Runtime.EnsureEnrolledAsync();
        var endpointId = agent.Runtime.State.Read(s => s.EndpointId)!.Value;
        var firstCredential = agent.Runtime.State.Read(s => s.CredentialId);

        await agent.Runtime.RotateCredentialAsync();
        var secondCredential = agent.Runtime.State.Read(s => s.CredentialId);
        Assert.NotEqual(firstCredential, secondCredential);
        Assert.NotNull(await agent.Runtime.CheckInOnceAsync()); // signed with the new key

        var credentials = (await admin.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{endpointId}")).Credentials;
        Assert.Equal(2, credentials.Count);
        Assert.Contains(credentials, c => c.CredentialId == secondCredential && c.RevokedAt is null);

        // MSI uninstall: the server is told, the endpoint is decommissioned and the local identity is erased.
        await agent.Runtime.UnenrollAsync("Uninstalled by test");
        var detail = await admin.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{endpointId}");
        Assert.Equal(EndpointStatus.Decommissioned, detail.Summary.Status);
        Assert.Null(agent.Runtime.State.Read(s => s.CredentialId));
        Assert.Null(await agent.Runtime.CheckInOnceAsync());
    }

    [Fact]
    public async Task An_administrator_uninstalls_the_agent_and_the_job_completes_when_the_agent_unenrolls()
    {
        var admin = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(admin);
        using var agent = new TestAgent(NewHttpClient(), Clock);
        agent.Bootstrap.EnrollmentToken = await CreateTokenAsync(admin, org.Id, site.Id);
        await agent.Runtime.EnsureEnrolledAsync();
        var endpointId = agent.Runtime.State.Read(s => s.EndpointId)!.Value;
        await agent.Runtime.CheckInOnceAsync();

        var scan = await admin.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{endpointId}/scan", null, HttpStatusCode.Accepted);
        var job = await admin.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{endpointId}/uninstall-agent", null, HttpStatusCode.Accepted);
        Assert.Equal(JobType.UninstallAgent, job.Type);
        await admin.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{endpointId}/uninstall-agent", null, HttpStatusCode.Conflict, "duplicate_job");

        // The uninstall goes before the scan that was queued first. Starting the removal stops the service.
        await agent.Runtime.CheckInOnceAsync();
        using (var stopping = new CancellationTokenSource())
        {
            agent.Uninstaller.ServiceStopping = stopping;
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => agent.Runtime.ProcessNextJobAsync(stopping.Token));
        }

        Assert.Single(agent.Uninstaller.Started);
        Assert.True(await agent.Runtime.FlushOutboxAsync());
        var running = await admin.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}");
        Assert.Equal(JobStatus.Running, running.Summary.Status);
        Assert.Equal("Uninstalling", running.Summary.Phase);

        // The package's uninstall step (msiexec runs "EasyPatch.Agent.exe unenroll") tells the server.
        await agent.Runtime.UnenrollAsync("Agent uninstalled");

        var done = await admin.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}");
        Assert.Equal(JobStatus.Completed, done.Summary.Status);
        Assert.Equal(100, done.Summary.ProgressPercent);
        Assert.Equal("The agent was removed and unenrolled from the server.", done.Summary.ProgressMessage);
        var cancelled = await admin.GetAsync<JobDetailDto>($"/api/v1/jobs/{scan.Id}");
        Assert.Equal(JobStatus.Cancelled, cancelled.Summary.Status);
        Assert.Equal("The agent was uninstalled.", cancelled.Summary.ErrorMessage);
        var detail = await admin.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{endpointId}");
        Assert.Equal(EndpointStatus.Decommissioned, detail.Summary.Status);
        await WithDbAsync(async db =>
        {
            Assert.True(await db.AuditLogs.AnyAsync(a => a.Action == "job.create" && a.TargetId == job.Id.ToString()));
            Assert.True(await db.EndpointEvents.AnyAsync(e => e.EndpointId == endpointId && e.Type == "Decommissioned" && e.Message == "Agent uninstalled."));
        });

        // A decommissioned endpoint gets no more jobs.
        await admin.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{endpointId}/uninstall-agent", null, HttpStatusCode.Conflict, "endpoint_not_active");
    }

    [Fact]
    public async Task Agents_that_cannot_remove_themselves_are_not_sent_an_uninstall()
    {
        var root = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(root);
        using var agent = await EnrollAgentAsync(root, org.Id, site.Id, "WS-OLD");
        await agent.CheckInAsync(new EasyPatch.Contracts.Agent.CheckInRequest { AgentVersion = "1.5.3", Capabilities = [EasyPatch.Contracts.Agent.AgentCapabilities.Restart] });

        using var response = await root.SendAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/uninstall-agent");
        await AdminSession.EnsureAsync(response, HttpStatusCode.Conflict);
        Assert.Equal("agent_upgrade_required", await AdminSession.ProblemCodeAsync(response));
    }

    [Fact]
    public async Task An_update_check_a_user_asked_for_from_the_tray_is_recorded_as_such()
    {
        var admin = await SuperAdminAsync();
        var (org, site) = await CreateOrgAsync(admin);
        using var agent = new TestAgent(NewHttpClient(), Clock);
        agent.Bootstrap.EnrollmentToken = await CreateTokenAsync(admin, org.Id, site.Id);
        await agent.Runtime.EnsureEnrolledAsync();
        agent.WindowsUpdate.Add("Security Update for Microsoft Edge (KB5046700)", MicrosoftClassifications.SecurityUpdates, "5046700");

        Assert.True(agent.Runtime.HandleUserRequest(UserRequestKind.CheckForUpdates, sessionId: 2).Accepted);
        var scanId = await agent.Runtime.RunRequestedUpdateCheckAsync();
        Assert.NotNull(scanId);
        Assert.True(await agent.Runtime.FlushOutboxAsync());

        var scan = await WithDbAsync(db => db.UpdateScans.AsNoTracking().SingleAsync(s => s.AgentScanId == scanId));
        Assert.Equal(ScanTrigger.User, scan.Trigger);
        Assert.Equal(ScanStatus.Succeeded, scan.Status);
    }
}
