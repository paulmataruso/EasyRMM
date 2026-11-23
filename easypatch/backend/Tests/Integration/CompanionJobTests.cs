using System.Net;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Infrastructure.Maintenance;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>ADR-0069: the engine's RepairCompanion and CollectLogs jobs. They go only to agents that declare the capability, name a
/// fixed target and step (never a command), and return diagnostics apart from the message, capped and kept 14 days.</summary>
public sealed class CompanionJobTests(PostgresFixture postgres) : IntegrationTest(postgres)
{
    private const string Sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private AdminClient root = null!;
    private OrganizationDto org = null!;
    private SiteDto site = null!;

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        root = SuperAdmin();
        (org, site) = await CreateOrgAsync(root);
    }

    private static Task<CheckInResponse> CheckInAsync(SignedAgent agent, bool capable = true) => agent.CheckInAsync(new CheckInRequest
    {
        AgentVersion = capable ? "1.9.0" : "1.8.0",
        ActiveJobIds = [],
        Capabilities = capable ? [AgentCapabilities.Restart, AgentCapabilities.RepairCompanion, AgentCapabilities.CollectLogs] : [AgentCapabilities.Restart],
    });

    private string Repair(SignedAgent agent) => $"/api/v1/endpoints/{agent.EndpointId}/companion/repair";

    private string Collect(SignedAgent agent) => $"/api/v1/endpoints/{agent.EndpointId}/collect-logs";

    [Fact]
    public async Task Only_agents_that_declare_the_capability_are_sent_these_jobs()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-OLD");
        await CheckInAsync(agent, capable: false);
        await root.ExpectAsync(HttpMethod.Post, Repair(agent), new RepairCompanionRequest("meshagent", "restart"), HttpStatusCode.Conflict, "agent_upgrade_required");
        await root.ExpectAsync(HttpMethod.Post, Collect(agent), null, HttpStatusCode.Conflict, "agent_upgrade_required");
        Assert.False(await WithDbAsync(db => db.Jobs.AnyAsync(j => j.Type == JobType.RepairCompanion || j.Type == JobType.CollectLogs)));

        await CheckInAsync(agent);
        var job = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, Collect(agent), null, HttpStatusCode.Accepted);
        Assert.Equal(JobType.CollectLogs, job.Type);
    }

    [Fact]
    public async Task A_repair_names_a_fixed_target_and_step_and_nothing_else_is_accepted()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-FIXED");
        await CheckInAsync(agent);
        var bad = new RepairCompanionRequest[]
        {
            new("powershell", "restart"),
            new("easyrmm-agent", "reinstall"),
            new("easyrmm-agent", "repair"), // no hash
            new("easyrmm-agent", "repair", "NOT-A-HASH"),
            new("easyrmm-agent", "repair", Sha.ToUpperInvariant()),
            new("easyrmm-agent", "restart", Sha), // a restart carries no hash
            new("meshagent", "repair", Sha), // MeshAgent is restarted, never repaired, through patching
            new("meshagent", "repair"),
            new("", ""),
        };
        foreach (var request in bad)
        {
            await root.ExpectAsync(HttpMethod.Post, Repair(agent), request, HttpStatusCode.BadRequest, "validation_failed");
        }

        Assert.False(await WithDbAsync(db => db.Jobs.AnyAsync(j => j.Type == JobType.RepairCompanion)));
    }

    [Fact]
    public async Task A_repair_reaches_the_agent_with_its_payload_ahead_of_other_work_and_a_second_one_is_refused_while_it_waits()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-REPAIR");
        await CheckInAsync(agent);
        var job = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, Repair(agent), new RepairCompanionRequest("easyrmm-agent", "repair", Sha),
            HttpStatusCode.Accepted);
        Assert.Equal(JobType.RepairCompanion, job.Type);
        await root.ExpectAsync(HttpMethod.Post, Repair(agent), new RepairCompanionRequest("easyrmm-agent", "repair", Sha), HttpStatusCode.Conflict, "duplicate_job");
        // The other step is another job.
        await root.SendAsync<JobSummaryDto>(HttpMethod.Post, Repair(agent), new RepairCompanionRequest("meshagent", "restart"), HttpStatusCode.Accepted);

        var delivered = Assert.Single((await CheckInAsync(agent)).Jobs);
        Assert.Equal((job.Id, JobType.RepairCompanion), (delivered.JobId, delivered.Type));
        Assert.Equal(new RepairCompanionPayload { Target = "easyrmm-agent", Step = "repair", ExpectedSha256 = Sha }, delivered.RepairCompanion);
        Assert.Null(delivered.Install);
        // These jobs expire quickly: a repair that waits hours is not the repair that was asked for.
        Assert.True(delivered.ExpiresAt - Clock.GetUtcNow() <= TimeSpan.FromMinutes(31));
    }

    [Fact]
    public async Task Diagnostics_are_kept_apart_from_the_message_and_the_engine_refuses_more_than_256_KiB()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-DIAG");
        await CheckInAsync(agent);
        var job = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, Collect(agent), null, HttpStatusCode.Accepted);
        Assert.Single((await CheckInAsync(agent)).Jobs);
        using (var ack = await agent.PostAsync($"api/v1/agents/jobs/{job.Id}/ack", new { }))
        {
            await AdminClient.EnsureAsync(ack, HttpStatusCode.OK);
        }

        var tooLong = new string('x', JobDiagnostics.MaxBytes + 1);
        using (var refused = await agent.PostAsync($"api/v1/agents/jobs/{job.Id}/status",
                   new JobStatusReport { Sequence = 1, Status = JobStatus.Completed, Phase = "Completed", Message = "Collected.", Diagnostics = tooLong }))
        {
            await AdminClient.EnsureAsync(refused, HttpStatusCode.BadRequest);
        }

        // Exactly the cap, in multi-byte characters, is accepted.
        var atCap = new string('é', JobDiagnostics.MaxBytes / 2);
        using (var accepted = await agent.PostAsync($"api/v1/agents/jobs/{job.Id}/status",
                   new JobStatusReport { Sequence = 1, Status = JobStatus.Completed, Phase = "Completed", Message = "Collected.", Diagnostics = atCap }))
        {
            await AdminClient.EnsureAsync(accepted, HttpStatusCode.NoContent);
        }

        var done = await root.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}");
        Assert.Equal(JobStatus.Completed, done.Summary.Status);
        Assert.Equal(atCap, done.Diagnostics);
        Assert.Equal("Collected.", done.Summary.ProgressMessage);
    }

    [Fact]
    public async Task Diagnostics_are_removed_14_days_after_the_job_finished_and_the_job_stays()
    {
        var agent = await EnrollAgentAsync(root, org.Id, site.Id, "PC-KEEP");
        await CheckInAsync(agent);
        var job = await root.SendAsync<JobSummaryDto>(HttpMethod.Post, Repair(agent), new RepairCompanionRequest("meshagent", "restart"), HttpStatusCode.Accepted);
        Assert.Single((await CheckInAsync(agent)).Jobs);
        using (var ack = await agent.PostAsync($"api/v1/agents/jobs/{job.Id}/ack", new { }))
        {
            await AdminClient.EnsureAsync(ack, HttpStatusCode.OK);
        }

        using (var done = await agent.PostAsync($"api/v1/agents/jobs/{job.Id}/status",
                   new JobStatusReport { Sequence = 1, Status = JobStatus.Completed, Phase = "Completed", Message = "Restarted.", Diagnostics = "meshagent: running" }))
        {
            await AdminClient.EnsureAsync(done, HttpStatusCode.NoContent);
        }

        Clock.Advance(TimeSpan.FromDays(13));
        await RunMaintenanceAsync<JobMaintenanceTask>();
        Assert.Equal("meshagent: running", (await root.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}")).Diagnostics);

        Clock.Advance(TimeSpan.FromDays(2));
        await RunMaintenanceAsync<JobMaintenanceTask>();
        var after = await root.GetAsync<JobDetailDto>($"/api/v1/jobs/{job.Id}");
        Assert.Null(after.Diagnostics);
        Assert.Equal(JobStatus.Completed, after.Summary.Status);
    }
}
