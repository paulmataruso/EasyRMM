using System.Globalization;
using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Policy;
using EasyPatch.Core.Domain;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Maintenance;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Restart jobs, user messages, restart schedules, per-endpoint policy and Windows Update policy status.</summary>
public sealed class UserExperienceTests(PostgresFixture postgres) : IntegrationTest(postgres)
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

    private static CheckInRequest CapableCheckIn(IReadOnlyList<Guid>? active = null, bool rebootPending = false, WindowsUpdatePolicyReport? report = null) => new()
    {
        AgentVersion = "1.1.0",
        RebootPending = rebootPending,
        ActiveJobIds = active ?? [],
        Capabilities = AgentCapabilities.All,
        Sessions = new UserSessionInfo { SignedInUsers = 2, TrayConnected = 1 },
        WindowsUpdatePolicy = report,
    };

    private async Task AckAsync(SignedAgent agent, Guid jobId)
    {
        using var response = await agent.PostAsync($"api/v1/agents/jobs/{jobId}/ack", new { });
        await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
    }

    private static async Task ReportAsync(SignedAgent agent, Guid jobId, long sequence, JobStatus status)
    {
        using var response = await agent.PostAsync($"api/v1/agents/jobs/{jobId}/status", new JobStatusReport { Sequence = sequence, Status = status, Phase = status.ToString() });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
    }

    private static RestartRequest Restart(RestartMode mode = RestartMode.PromptWithDeadline, int? deadline = 60, DateTimeOffset? at = null) =>
        new(mode, RestartCondition.Always, null, deadline, at, null, false);

    [Fact]
    public async Task Restarts_and_messages_need_a_capable_agent_and_messages_do_not_wait_for_other_jobs()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-UX");
        await agent.CheckInAsync(); // a 1.0.0 agent: no capabilities

        var url = $"/api/v1/endpoints/{agent.EndpointId}";
        await root.ExpectAsync(HttpMethod.Post, url + "/restart", Restart(), HttpStatusCode.Conflict, "agent_upgrade_required");
        await root.ExpectAsync(HttpMethod.Post, url + "/notify", new NotifyRequest(UserMessagePreset.SaveYourWork, null), HttpStatusCode.Conflict,
            "agent_upgrade_required");

        await agent.CheckInAsync(CapableCheckIn());
        var detail = await root.GetAsync<EndpointDetailDto>(url);
        Assert.Equal(AgentCapabilities.All.Order(StringComparer.Ordinal), detail.AgentCapabilities);
        Assert.Equal(2, detail.SignedInUsers);
        Assert.Equal(1, detail.TrayConnectedSessions);

        // Invalid requests are refused.
        await root.ExpectAsync(HttpMethod.Post, url + "/restart", Restart(deadline: 5), HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Post, url + "/notify", new NotifyRequest(UserMessagePreset.RestartScheduled, null), HttpStatusCode.BadRequest);

        // A running scan keeps the endpoint busy...
        var scan = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, url + "/scan", null, HttpStatusCode.Accepted);
        Assert.Equal(scan.Id, Assert.Single((await agent.CheckInAsync(CapableCheckIn())).Jobs).JobId);
        await AckAsync(agent, scan.Id);
        await ReportAsync(agent, scan.Id, 1, JobStatus.Running);

        var restart = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, url + "/restart", Restart(), HttpStatusCode.Accepted);
        await root.ExpectAsync(HttpMethod.Post, url + "/restart", Restart(), HttpStatusCode.Conflict, "duplicate_job");
        var at = Clock.GetUtcNow().AddHours(3);
        var message = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, url + "/notify", new NotifyRequest(UserMessagePreset.RestartScheduled, at),
            HttpStatusCode.Accepted);

        // ...but the message is delivered at once, while the restart waits.
        var delivered = Assert.Single((await agent.CheckInAsync(CapableCheckIn([scan.Id]))).Jobs);
        Assert.Equal(message.Id, delivered.JobId);
        Assert.Equal(JobType.NotifyUser, delivered.Type);
        Assert.Equal(UserMessagePreset.RestartScheduled, delivered.Notify!.Preset);
        Assert.Equal(at, delivered.Notify.ScheduledAt);

        await ReportAsync(agent, scan.Id, 2, JobStatus.Completed);
        var next = Assert.Single((await agent.CheckInAsync(CapableCheckIn([message.Id]))).Jobs);
        Assert.Equal(restart.Id, next.JobId);
        Assert.Equal(RestartMode.PromptWithDeadline, next.Restart!.Mode);
        Assert.Equal(60, next.Restart.DeadlineMinutes);

        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.Id == restart.Id));
        Assert.Equal(JobTrigger.Manual, job.Trigger);
        Assert.True(job.ExpiresAt <= Clock.GetUtcNow().AddMinutes(121));
    }

    [Fact]
    public async Task One_off_restarts_can_be_scheduled_and_are_not_delivered_early()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-LATER");
        await agent.CheckInAsync(CapableCheckIn());
        var url = $"/api/v1/endpoints/{agent.EndpointId}/restart";
        await root.ExpectAsync(HttpMethod.Post, url, Restart(at: Clock.GetUtcNow().AddDays(40)), HttpStatusCode.BadRequest);

        var at = Clock.GetUtcNow().AddHours(2);
        var restart = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, url, Restart(RestartMode.Countdown, null, at) with { CountdownMinutes = 10 },
            HttpStatusCode.Accepted);
        Assert.Empty((await agent.CheckInAsync(CapableCheckIn())).Jobs);

        Clock.Advance(TimeSpan.FromHours(2));
        var delivered = Assert.Single((await agent.CheckInAsync(CapableCheckIn())).Jobs);
        Assert.Equal(restart.Id, delivered.JobId);
        Assert.Equal(10, delivered.Restart!.CountdownMinutes);
    }

    [Fact]
    public async Task Restart_schedules_create_one_job_per_occurrence_for_endpoints_that_need_a_restart()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-SCHEDULE");
        var legacy = await EnrollAgentAsync(root, org.Id, site.Id, "PC-OLD-AGENT");
        await legacy.CheckInAsync(rebootPending: true);
        await agent.CheckInAsync(CapableCheckIn());

        var start = Clock.GetUtcNow().AddMinutes(-10);
        var schedule = new RestartScheduleDto(true, [0, 1, 2, 3, 4, 5, 6], start.ToString("HH:mm", CultureInfo.InvariantCulture),
            RestartCondition.OnlyIfPending, RestartMode.Countdown, 10, 240, 120);
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, null, RestartSchedule: schedule), HttpStatusCode.OK);

        await RunMaintenanceAsync<ScheduledRestartTask>();
        Assert.Equal(0, await WithDbAsync(db => db.Jobs.CountAsync(j => j.Type == JobType.Restart))); // nothing pending, old agent skipped

        await agent.CheckInAsync(CapableCheckIn(rebootPending: true));
        await RunMaintenanceAsync<ScheduledRestartTask>();
        await RunMaintenanceAsync<ScheduledRestartTask>(); // idempotent within one occurrence
        var job = await WithDbAsync(db => db.Jobs.AsNoTracking().SingleAsync(j => j.Type == JobType.Restart));
        Assert.Equal(agent.EndpointId, job.EndpointId);
        Assert.Equal(JobTrigger.Scheduled, job.Trigger);
        Assert.Equal("Restart schedule", job.RequestedBy);
        Assert.Null(job.NotBefore);
        Assert.InRange(job.ExpiresAt, Clock.GetUtcNow().AddMinutes(109), Clock.GetUtcNow().AddMinutes(111)); // 120-minute occurrence opened 10 minutes ago

        var delivered = Assert.Single((await agent.CheckInAsync(CapableCheckIn(rebootPending: true))).Jobs);
        Assert.Equal(RestartMode.Countdown, delivered.Restart!.Mode);
        Assert.Equal(RestartCondition.OnlyIfPending, delivered.Restart.Condition);

        // The job finishes; the same occurrence is not scheduled again.
        await AckAsync(agent, job.Id);
        await ReportAsync(agent, job.Id, 1, JobStatus.Completed);
        await RunMaintenanceAsync<ScheduledRestartTask>();
        Assert.Equal(1, await WithDbAsync(db => db.Jobs.CountAsync(j => j.Type == JobType.Restart)));

        // A site can switch the inherited schedule off.
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/sites/{site.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, null,
                RestartSchedule: schedule with { Enabled = false }), HttpStatusCode.OK);
        var effective = await root.GetAsync<EffectivePolicyDto>($"/api/v1/endpoints/{agent.EndpointId}/effective-policy");
        Assert.Null(effective.RestartSchedule);
    }

    [Fact]
    public async Task Endpoint_policy_overrides_reach_the_agent_and_windows_update_status_is_recorded()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-POLICY");
        await agent.CheckInAsync(CapableCheckIn());
        var url = $"/api/v1/endpoints/{agent.EndpointId}";

        var orgWu = new PolicyWindowsUpdate
        {
            AutomaticUpdates = new PolicyGroupSetting<AutomaticUpdatesSettings>
            {
                Managed = true,
                Value = new AutomaticUpdatesSettings { Mode = AutoUpdateMode.AutoDownloadNotifyInstall },
            },
            RestartBehavior = new PolicyGroupSetting<RestartBehaviorSettings>
            {
                Managed = true,
                Value = new RestartBehaviorSettings { NoAutoRestartWithSignedInUsers = true },
            },
        };
        await root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/organizations/{org.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, null, WindowsUpdate: orgWu), HttpStatusCode.OK);

        Assert.Null((await root.GetAsync<PolicyDto>(url + "/policy")).Id);
        var endpointWu = new PolicyWindowsUpdate
        {
            RestartBehavior = new PolicyGroupSetting<RestartBehaviorSettings> { Managed = false },
            QualityUpdates = new PolicyGroupSetting<QualityUpdateSettings> { Managed = true, Value = new QualityUpdateSettings { DeferDays = 7, DisablePause = true } },
        };
        var saved = await root.SendAsync<PolicyDto>(HttpMethod.Put, url + "/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, null, TrayIconEnabled: false, WindowsUpdate: endpointWu),
            HttpStatusCode.OK);
        Assert.Equal(PolicyScope.Endpoint, saved.Scope);
        Assert.Equal(agent.EndpointId, saved.EndpointId);
        Assert.True((await root.GetAsync<EndpointDetailDto>(url)).HasOwnPolicy);

        // Invalid settings are refused.
        var badPin = new PolicyWindowsUpdate
        {
            FeatureUpdates = new PolicyGroupSetting<FeatureUpdateSettings>
            {
                Managed = true,
                Value = new FeatureUpdateSettings { TargetProductVersion = "Windows 11", TargetReleaseVersion = "2024" },
            },
        };
        await root.ExpectAsync(HttpMethod.Put, url + "/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, null, WindowsUpdate: badPin), HttpStatusCode.BadRequest);
        await root.ExpectAsync(HttpMethod.Put, url + "/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, MaxConcurrentInstallsPerSite: 3),
            HttpStatusCode.BadRequest);

        var effective = await root.GetAsync<EffectivePolicyDto>(url + "/effective-policy");
        Assert.False(effective.TrayIconEnabled);
        Assert.True(effective.InstallNotificationsEnabled);
        Assert.Equal(PolicyScope.Endpoint, effective.Sources["TrayIconEnabled"]);
        Assert.NotNull(effective.WindowsUpdate!.AutomaticUpdates);
        Assert.Null(effective.WindowsUpdate.RestartBehavior); // the endpoint stopped managing it
        Assert.Equal(7, effective.WindowsUpdate.QualityUpdates!.DeferDays);
        Assert.Equal(PolicyScope.Endpoint, effective.Sources["WindowsUpdate.QualityUpdates"]);
        Assert.Contains(effective.WindowsUpdateValues!, v => v.Name == "DeferQualityUpdatesPeriodInDays" && v.Value == "7");
        Assert.Contains(effective.WindowsUpdateValues!, v => v.Name == "AUOptions" && v.Value == "3" && v.Path.EndsWith(@"WindowsUpdate\AU", StringComparison.Ordinal));
        Assert.DoesNotContain(effective.WindowsUpdateValues!, v => v.Name is "WUServer" or "UseWUServer");

        var config = (await agent.CheckInAsync(CapableCheckIn())).Config;
        Assert.False(config.UserExperience.TrayIcon);
        Assert.Equal(AutoUpdateMode.AutoDownloadNotifyInstall, config.WindowsUpdate!.AutomaticUpdates!.Mode);
        Assert.True(config.WindowsUpdate.QualityUpdates!.DisablePause);
        Assert.Null(config.WindowsUpdate.FeatureUpdates);

        // The agent reports a conflict: stored, and one warning event (not one per check-in).
        var report = new WindowsUpdatePolicyReport
        {
            Groups =
            [
                new WindowsUpdatePolicyGroupStatus { Group = WindowsUpdatePolicyGroup.AutomaticUpdates, State = WindowsUpdatePolicyState.Applied },
                new WindowsUpdatePolicyGroupStatus
                {
                    Group = WindowsUpdatePolicyGroup.QualityUpdates,
                    State = WindowsUpdatePolicyState.Conflict,
                    Message = "Changed by another policy source.",
                    ConflictingValues = ["DeferQualityUpdatesPeriodInDays = 14 (EasyPatch: 7)"],
                },
            ],
        };
        await agent.CheckInAsync(CapableCheckIn(report: report));
        Clock.Advance(TimeSpan.FromMinutes(1));
        await agent.CheckInAsync(CapableCheckIn(report: report));
        var detail = await root.GetAsync<EndpointDetailDto>(url);
        Assert.Equal(WindowsUpdatePolicyState.Conflict, detail.WindowsUpdatePolicy!.Groups.Single(g => g.Group == WindowsUpdatePolicyGroup.QualityUpdates).State);
        Assert.Equal(1, await WithDbAsync(db => db.EndpointEvents.CountAsync(e => e.EndpointId == agent.EndpointId && e.Type == "WindowsUpdatePolicyConflict")));

        // Removing the endpoint layer brings back the inherited values.
        await root.ExpectAsync(HttpMethod.Delete, url + "/policy", null, HttpStatusCode.NoContent);
        effective = await root.GetAsync<EffectivePolicyDto>(url + "/effective-policy");
        Assert.True(effective.TrayIconEnabled);
        Assert.NotNull(effective.WindowsUpdate!.RestartBehavior);
        Assert.False((await root.GetAsync<EndpointDetailDto>(url)).HasOwnPolicy);
    }

    [Fact]
    public async Task Read_only_users_cannot_restart_message_or_change_endpoint_policy()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-RO");
        await agent.CheckInAsync(CapableCheckIn());
        var viewer = await CreateAndLoginAsync("viewer", UserRole.ReadOnly);
        var url = $"/api/v1/endpoints/{agent.EndpointId}";
        await viewer.ExpectAsync(HttpMethod.Post, url + "/restart", Restart(), HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Post, url + "/notify", new NotifyRequest(UserMessagePreset.SaveYourWork, null), HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Put, url + "/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, null, TrayIconEnabled: false), HttpStatusCode.Forbidden);
        var presets = await viewer.GetAsync<List<UserMessagePresetDto>>("/api/v1/user-messages");
        Assert.Equal(Enum.GetValues<UserMessagePreset>().Length, presets.Count);
        Assert.Contains("{time}", presets.Single(p => p.NeedsRestartTime).Body, StringComparison.Ordinal);
        Assert.Equal(0, await WithDbAsync(db => db.Jobs.CountAsync()));
    }
}
