using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using EasyPatch.Api.Contracts;
using EasyPatch.Contracts;
using EasyPatch.Contracts.Agent;
using EasyPatch.Contracts.Json;
using EasyPatch.Core.Entities;
using EasyPatch.Infrastructure.Maintenance;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace EasyPatch.Tests.Integration;

/// <summary>Helpers for agent update tests: a release key, signed packages and agents that can update themselves.</summary>
public abstract class AgentUpdateTestBase(PostgresFixture postgres) : IntegrationTest(postgres)
{
    protected static readonly ECDsa ReleaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    protected AdminSession Root { get; private set; } = null!;
    protected OrganizationDto Org { get; private set; } = null!;
    protected SiteDto Site { get; private set; } = null!;

    protected static string KeyId => AgentRelease.KeyId(ReleaseKey);

    public override async ValueTask InitializeAsync()
    {
        await base.InitializeAsync();
        Root = await SuperAdminAsync();
        (Org, Site) = await CreateOrgAsync(Root);
    }

    /// <summary>Copies a package (and, when signed, its .sig file) into the server's package folder.</summary>
    protected string Publish(string version, ECDsa? key = null, bool signed = true, string architecture = "x64")
    {
        var path = Path.Combine(Factory.PackagesPath, $"EasyPatchAgent-{version}-{architecture}.msi");
        File.WriteAllBytes(path, RandomNumberGenerator.GetBytes(2048));
        if (signed)
        {
            key ??= ReleaseKey;
            var manifest = AgentRelease.Describe(path);
            var signature = new AgentReleaseSignature { KeyId = AgentRelease.KeyId(key), Manifest = manifest, Signature = AgentRelease.Sign(manifest, key) };
            File.WriteAllText(path + AgentRelease.SignatureExtension, JsonSerializer.Serialize(signature, ContractJson.Options));
        }

        Clock.Advance(TimeSpan.FromSeconds(61)); // the package list is cached for a minute
        return path;
    }

    protected static CheckInRequest UpdatableCheckIn(string version = "1.2.0", IReadOnlyList<Guid>? active = null, IReadOnlyList<string>? keys = null,
        string? architecture = "x64") => new()
    {
        AgentVersion = version,
        ActiveJobIds = active ?? [],
        Capabilities = AgentCapabilities.All,
        AgentArchitecture = architecture,
        ReleaseKeyIds = keys ?? [KeyId],
    };

    protected async Task<SignedAgent> UpdatableAgentAsync(string hostname, Guid? siteId = null)
    {
        var agent = await EnrollAgentAsync(Root, Org.Id, siteId ?? Site.Id, hostname);
        await agent.CheckInAsync(UpdatableCheckIn());
        return agent;
    }

    protected static async Task ReportAsync(SignedAgent agent, Guid jobId, long sequence, JobStatus status, string? errorCode = null)
    {
        using var response = await agent.PostAsync($"api/v1/agents/jobs/{jobId}/status",
            new JobStatusReport { Sequence = sequence, Status = status, Phase = status.ToString(), ErrorCode = errorCode, ErrorMessage = errorCode });
        await AdminSession.EnsureAsync(response, HttpStatusCode.NoContent);
    }

    protected static async Task AckAsync(SignedAgent agent, Guid jobId)
    {
        using var response = await agent.PostAsync($"api/v1/agents/jobs/{jobId}/ack", new { });
        await AdminSession.EnsureAsync(response, HttpStatusCode.OK);
    }

    protected Task<List<Job>> AgentUpdateJobsAsync() =>
        WithDbAsync(db => db.Jobs.AsNoTracking().Where(j => j.Type == JobType.AgentUpdate).OrderBy(j => j.CreatedAt).ToListAsync());

    protected static readonly AgentUpdateRequest Newest = new(null);
}

/// <summary>Agent self-update: signed packages, manual and bulk updates, and the "Agent updates" policy.</summary>
public sealed class AgentUpdateTests(PostgresFixture postgres) : AgentUpdateTestBase(postgres)
{
    private static readonly ECDsa OtherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task An_administrator_can_update_an_agent_to_the_newest_signed_package()
    {
        var agent = await UpdatableAgentAsync("PC-UPD");
        Publish("1.2.0");
        Publish("1.3.0");
        var url = $"/api/v1/endpoints/{agent.EndpointId}";

        var detail = await Root.GetAsync<EndpointDetailDto>(url);
        Assert.True(detail.AgentUpdate!.Supported);
        Assert.Equal("x64", detail.AgentUpdate.Architecture);
        Assert.Equal([KeyId], detail.AgentUpdate.ReleaseKeyIds);
        Assert.True(detail.AgentUpdate.AutomaticUpdates);
        Assert.Equal("1.3.0", detail.AgentUpdate.AvailableVersion);
        Assert.Null(detail.AgentUpdate.Code);

        var packages = await Root.GetAsync<List<AgentPackageDto>>("/api/v1/agent-packages");
        Assert.All(packages, p => Assert.Equal(KeyId, p.ReleaseKeyId));

        var job = await Root.SendAsync<JobSummaryDto>(HttpMethod.Post, url + "/agent-update", Newest, HttpStatusCode.Accepted);
        Assert.Equal(JobType.AgentUpdate, job.Type);
        Assert.Equal("root", job.RequestedBy);
        await Root.ExpectAsync(HttpMethod.Post, url + "/agent-update", Newest, HttpStatusCode.Conflict, "duplicate_job");

        // The agent receives the package description and the release signature, which it verifies itself.
        var delivered = Assert.Single((await agent.CheckInAsync(UpdatableCheckIn())).Jobs);
        Assert.Equal(job.Id, delivered.JobId);
        var payload = delivered.AgentUpdate!;
        Assert.Equal("EasyPatchAgent-1.3.0-x64.msi", payload.Package.FileName);
        Assert.Equal("1.3.0", payload.Package.Version);
        Assert.Equal(KeyId, payload.KeyId);
        Assert.True(AgentRelease.Verify(payload.Package, payload.Signature, ReleaseKey));
        Assert.Equal(AgentRelease.Describe(Path.Combine(Factory.PackagesPath, "EasyPatchAgent-1.3.0-x64.msi")), payload.Package);

        // ...and downloads it anonymously from the server.
        using var download = await NewHttpClient().GetAsync("/downloads/agent/" + payload.Package.FileName, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal(payload.Package.SizeBytes, (await download.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken)).Length);
    }

    [Fact]
    public async Task A_package_copied_in_after_the_last_scan_can_be_downloaded_at_once()
    {
        var ct = TestContext.Current.CancellationToken;
        Publish("1.2.0");
        Assert.Single(await Root.GetAsync<List<AgentPackageDto>>("/api/v1/agent-packages")); // the API caches this list for a minute

        // The worker keeps its own list and may offer a new package to agents before the API's list is refreshed.
        var bytes = RandomNumberGenerator.GetBytes(2048);
        await File.WriteAllBytesAsync(Path.Combine(Factory.PackagesPath, "EasyPatchAgent-1.3.0-x64.msi"), bytes, ct);
        await File.WriteAllBytesAsync(Path.Combine(Factory.PackagesPath, "notes.msi"), bytes, ct);
        Clock.Advance(TimeSpan.FromSeconds(2));

        var http = NewHttpClient();
        Assert.Equal(bytes, await http.GetByteArrayAsync("/downloads/agent/EasyPatchAgent-1.3.0-x64.msi", ct));
        foreach (var name in new[] { "notes.msi", "EasyPatchAgent-1.4.0-x64.msi", "EasyPatchAgent-1.2.0-x64.msi.sig" })
        {
            using var missing = await http.GetAsync("/downloads/agent/" + name, ct);
            Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        }
    }

    [Fact]
    public async Task A_specific_version_can_be_requested_but_never_a_downgrade()
    {
        var agent = await UpdatableAgentAsync("PC-VER");
        Publish("1.1.0");
        Publish("1.2.5");
        Publish("1.3.0");
        var url = $"/api/v1/endpoints/{agent.EndpointId}/agent-update";

        await Root.ExpectAsync(HttpMethod.Post, url, new AgentUpdateRequest("1.1.0"), HttpStatusCode.Conflict, "agent_up_to_date");
        await Root.ExpectAsync(HttpMethod.Post, url, new AgentUpdateRequest("1.9.0"), HttpStatusCode.Conflict, "no_agent_package");
        await Root.ExpectAsync(HttpMethod.Post, url, new AgentUpdateRequest("latest; rm -rf"), HttpStatusCode.Conflict, "no_agent_package");

        await Root.SendAsync<JobSummaryDto>(HttpMethod.Post, url, new AgentUpdateRequest("1.2.5"), HttpStatusCode.Accepted);

        var delivered = Assert.Single((await agent.CheckInAsync(UpdatableCheckIn())).Jobs);
        Assert.Equal("1.2.5", delivered.AgentUpdate!.Package.Version);
    }

    [Fact]
    public async Task Updates_are_refused_with_the_reason_when_they_cannot_work()
    {
        var old = await EnrollAgentAsync(Root, Org.Id, Site.Id, "PC-OLD");
        await old.CheckInAsync(new CheckInRequest { AgentVersion = "1.1.1", Capabilities = [AgentCapabilities.Restart, AgentCapabilities.Tray] });
        var agent = await UpdatableAgentAsync("PC-NEW");
        var url = $"/api/v1/endpoints/{agent.EndpointId}/agent-update";

        await Root.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{old.EndpointId}/agent-update", Newest, HttpStatusCode.Conflict, "agent_upgrade_required");
        await Root.ExpectAsync(HttpMethod.Post, url, Newest, HttpStatusCode.Conflict, "no_agent_package");

        Publish("1.2.0");
        await Root.ExpectAsync(HttpMethod.Post, url, Newest, HttpStatusCode.Conflict, "agent_up_to_date");

        Publish("1.3.0", signed: false);
        await Root.ExpectAsync(HttpMethod.Post, url, Newest, HttpStatusCode.Conflict, "package_not_signed");

        Publish("1.4.0", key: OtherKey);
        await Root.ExpectAsync(HttpMethod.Post, url, Newest, HttpStatusCode.Conflict, "release_key_not_trusted");
        var detail = await Root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");
        Assert.Equal("release_key_not_trusted", detail.AgentUpdate!.Code);
        Assert.Null(detail.AgentUpdate.AvailableVersion);

        // A package changed after it was signed is treated as unsigned, and the package list says why.
        var rebuilt = Publish("1.5.0");
        await File.WriteAllBytesAsync(rebuilt, RandomNumberGenerator.GetBytes(2048), TestContext.Current.CancellationToken);
        Clock.Advance(TimeSpan.FromSeconds(61));
        await Root.ExpectAsync(HttpMethod.Post, url, Newest, HttpStatusCode.Conflict, "package_not_signed");
        var package = (await Root.GetAsync<List<AgentPackageDto>>("/api/v1/agent-packages")).Single(p => p.Version == "1.5.0");
        Assert.Null(package.ReleaseKeyId);
        Assert.Contains("does not match its signature", package.SignatureProblem, StringComparison.Ordinal);

        Assert.Empty(await AgentUpdateJobsAsync());
    }

    [Fact]
    public async Task An_agent_update_is_only_delivered_while_the_agent_can_update_itself()
    {
        var agent = await UpdatableAgentAsync("PC-CAP");
        Publish("1.3.0");
        await Root.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/agent-update", Newest, HttpStatusCode.Accepted);

        // e.g. someone installed a build without a release key in the meantime
        var response = await agent.CheckInAsync(new CheckInRequest { AgentVersion = "1.2.0", Capabilities = [AgentCapabilities.Restart] });
        Assert.Empty(response.Jobs);

        Assert.Single((await agent.CheckInAsync(UpdatableCheckIn())).Jobs);
    }

    [Fact]
    public async Task Bulk_updates_report_each_computer()
    {
        var agent = await UpdatableAgentAsync("PC-B1");
        var old = await EnrollAgentAsync(Root, Org.Id, Site.Id, "PC-B2");
        await old.CheckInAsync();
        Publish("1.3.0");

        var result = await Root.SendAsync<BulkResultDto>(HttpMethod.Post, "/api/v1/endpoints/bulk/agent-update",
            new BulkAgentUpdateRequest([agent.EndpointId, old.EndpointId], null), HttpStatusCode.OK);

        Assert.Equal(1, result.Succeeded);
        Assert.Equal(1, result.Failed);
        Assert.Equal("agent_upgrade_required", result.Results.Single(r => r.EndpointId == old.EndpointId).ErrorCode);
        Assert.Equal(agent.EndpointId, Assert.Single(await AgentUpdateJobsAsync()).EndpointId);
    }

    [Fact]
    public async Task Read_only_users_cannot_update_agents()
    {
        var agent = await UpdatableAgentAsync("PC-RO");
        Publish("1.3.0");
        var viewer = await CreateAndLoginAsync("viewer", UserRole.ReadOnly);

        await viewer.ExpectAsync(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/agent-update", Newest, HttpStatusCode.Forbidden);
        await viewer.ExpectAsync(HttpMethod.Post, "/api/v1/endpoints/bulk/agent-update", new BulkAgentUpdateRequest([agent.EndpointId], null),
            HttpStatusCode.Forbidden);
        Assert.Empty(await AgentUpdateJobsAsync());
    }

    [Fact]
    public async Task Check_ins_store_only_known_architectures_and_well_formed_key_ids()
    {
        var agent = await EnrollAgentAsync(Root, Org.Id, Site.Id, "PC-KEYS");
        await agent.CheckInAsync(UpdatableCheckIn(keys: [KeyId, "NOT-A-KEY", KeyId, "0123456789abcdef"], architecture: "mips"));

        var endpoint = await WithDbAsync(db => db.Endpoints.AsNoTracking().SingleAsync(e => e.Id == agent.EndpointId));
        Assert.Null(endpoint.AgentArchitecture);
        Assert.Equal(new[] { KeyId, "0123456789abcdef" }.Order(StringComparer.Ordinal), endpoint.AgentReleaseKeyIds);
    }

    [Fact]
    public async Task Automatic_updates_follow_the_policy_and_only_reach_online_computers()
    {
        var manualSite = await Root.SendAsync<SiteDto>(HttpMethod.Post, $"/api/v1/organizations/{Org.Id}/sites",
            new SiteRequest("Servers", null, null, null), HttpStatusCode.Created);
        await Root.SendAsync<PolicyDto>(HttpMethod.Put, $"/api/v1/sites/{manualSite.Id}/policy",
            new PolicyRequest(null, null, null, null, null, null, null, null, null, null, null, null, null, null, AgentAutoUpdateEnabled: false),
            HttpStatusCode.OK);
        var automatic = await UpdatableAgentAsync("PC-AUTO");
        var manual = await UpdatableAgentAsync("SRV-MANUAL", manualSite.Id);
        var offline = await UpdatableAgentAsync("PC-OFFLINE");
        await WithDbAsync(db => db.Endpoints.Where(e => e.Id == offline.EndpointId).ExecuteUpdateAsync(s => s.SetProperty(e => e.IsOnline, false)));

        var effective = await Root.GetAsync<EffectivePolicyDto>($"/api/v1/endpoints/{manual.EndpointId}/effective-policy");
        Assert.False(effective.AgentAutoUpdateEnabled);
        Assert.Equal(PolicyScope.Site, effective.Sources["AgentAutoUpdateEnabled"]);
        Assert.False((await Root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{manual.EndpointId}")).AgentUpdate!.AutomaticUpdates);

        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Empty(await AgentUpdateJobsAsync()); // nothing is signed yet

        Publish("1.3.0");
        await RunMaintenanceAsync<AgentUpdateTask>();
        await RunMaintenanceAsync<AgentUpdateTask>();

        var job = Assert.Single(await AgentUpdateJobsAsync());
        Assert.Equal(automatic.EndpointId, job.EndpointId);
        Assert.Equal(JobTrigger.System, job.Trigger);
        Assert.Equal("Automatic agent updates", job.RequestedBy);
        Assert.Equal("agent-update:1.3.0", job.DedupeKey);
    }

    [Fact]
    public async Task A_failed_automatic_update_waits_and_stops_after_three_failures()
    {
        var agent = await UpdatableAgentAsync("PC-RETRY");
        Publish("1.3.0");

        for (var attempt = 1; attempt <= AgentUpdateTask.MaxFailuresPerVersion; attempt++)
        {
            await RunMaintenanceAsync<AgentUpdateTask>();
            var job = (await AgentUpdateJobsAsync()).Last();
            Assert.Equal(attempt, (await AgentUpdateJobsAsync()).Count);
            Assert.Single((await agent.CheckInAsync(UpdatableCheckIn())).Jobs);
            await AckAsync(agent, job.Id);
            await ReportAsync(agent, job.Id, 1, JobStatus.Failed, "update_install_failed");

            await RunMaintenanceAsync<AgentUpdateTask>();
            Assert.Equal(attempt, (await AgentUpdateJobsAsync()).Count); // not straight away

            Clock.Advance(AgentUpdateTask.RetryAfter + TimeSpan.FromMinutes(1));
            await agent.CheckInAsync(UpdatableCheckIn());
        }

        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Equal(AgentUpdateTask.MaxFailuresPerVersion, (await AgentUpdateJobsAsync()).Count);

        // An administrator can still ask for it (signing in again after the simulated 18 hours).
        var admin = await LoginAsync(Root.Username, Root.Password, Root.MfaSecret);
        await admin.SendAsync<JobSummaryDto>(HttpMethod.Post, $"/api/v1/endpoints/{agent.EndpointId}/agent-update", Newest, HttpStatusCode.Accepted);
    }

    [Fact]
    public async Task An_updated_agent_is_not_offered_the_same_version_again()
    {
        var agent = await UpdatableAgentAsync("PC-DONE");
        Publish("1.3.0");
        await RunMaintenanceAsync<AgentUpdateTask>();
        var job = Assert.Single(await AgentUpdateJobsAsync());
        Assert.Single((await agent.CheckInAsync(UpdatableCheckIn())).Jobs);
        await AckAsync(agent, job.Id);
        await ReportAsync(agent, job.Id, 1, JobStatus.Running);

        // The new version checks in and finishes the job.
        await agent.CheckInAsync(UpdatableCheckIn("1.3.0", active: [job.Id]));
        await ReportAsync(agent, job.Id, 2, JobStatus.Completed);
        await RunMaintenanceAsync<AgentUpdateTask>();

        Assert.Single(await AgentUpdateJobsAsync());
        var detail = await Root.GetAsync<EndpointDetailDto>($"/api/v1/endpoints/{agent.EndpointId}");
        Assert.Equal("1.3.0", detail.Summary.AgentVersion);
        Assert.Equal("agent_up_to_date", detail.AgentUpdate!.Code);
    }

    [Fact]
    public async Task The_windows_install_script_can_skip_the_certificate_check()
    {
        Publish("1.3.0");
        var code = await Root.SendAsync<DeploymentCodeDto>(HttpMethod.Post, "/api/v1/deployment-codes",
            new CreateDeploymentCodeRequest(Org.Id, Site.Id, "Lab servers", 30, null, null), HttpStatusCode.Created);

        var plain = await Root.GetAsync<InstallScriptResponse>($"/api/v1/deployment-codes/{code.Id}/install-script");
        Assert.False(plain.SkipCertificateCheck);
        Assert.Equal(code.OneLiner, plain.OneLiner);
        Assert.DoesNotContain("ServerCertificateValidationCallback", plain.OneLiner, StringComparison.Ordinal);
        Assert.Contains("$SkipCertificateCheck = $false", plain.Script, StringComparison.Ordinal);

        var skip = await Root.GetAsync<InstallScriptResponse>($"/api/v1/deployment-codes/{code.Id}/install-script?skipCertificateCheck=true&requireSignature=true");
        Assert.True(skip.SkipCertificateCheck);
        Assert.True(skip.RequireSignature);
        Assert.EndsWith($"/downloads/install/{code.Code}.ps1?requireSignature=true&skipCertificateCheck=true", skip.ScriptUrl, StringComparison.Ordinal);
        Assert.Contains("ServerCertificateValidationCallback={[bool]1}", skip.OneLiner, StringComparison.Ordinal);
        Assert.Contains(skip.ScriptUrl, skip.OneLiner, StringComparison.Ordinal);

        // The URL in the one-liner serves the same script.
        using var client = NewHttpClient();
        var served = await client.GetStringAsync(new Uri(skip.ScriptUrl).PathAndQuery, TestContext.Current.CancellationToken);
        Assert.Contains("$SkipCertificateCheck = $true", served, StringComparison.Ordinal);
        Assert.Contains("$RequireSignature = $true", served, StringComparison.Ordinal);
        Assert.Contains("SERVERCACERT=$serverCa", served, StringComparison.Ordinal);
    }
}

/// <summary>The number of automatic agent updates running at once is limited.</summary>
public sealed class AgentUpdateConcurrencyTests(PostgresFixture postgres) : AgentUpdateTestBase(postgres)
{
    protected override IReadOnlyDictionary<string, string?>? Settings => new Dictionary<string, string?>
    {
        ["EasyPatch:AutomaticAgentUpdateConcurrency"] = "2",
    };

    [Fact]
    public async Task Automatic_updates_are_rolled_out_a_few_at_a_time()
    {
        var agents = new List<SignedAgent>();
        for (var i = 0; i < 5; i++)
        {
            agents.Add(await UpdatableAgentAsync($"PC-{i}"));
        }

        Publish("1.3.0");
        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Equal(2, (await AgentUpdateJobsAsync()).Count);

        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Equal(2, (await AgentUpdateJobsAsync()).Count); // both still running

        var first = (await AgentUpdateJobsAsync())[0];
        var owner = agents.Single(a => a.EndpointId == first.EndpointId);
        await owner.CheckInAsync(UpdatableCheckIn());
        await AckAsync(owner, first.Id);
        await ReportAsync(owner, first.Id, 1, JobStatus.Completed);

        await RunMaintenanceAsync<AgentUpdateTask>();
        Assert.Equal(3, (await AgentUpdateJobsAsync()).Count);
    }
}
